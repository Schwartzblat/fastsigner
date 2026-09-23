//! APK Signature Scheme v2/v3 content digest: 1 MiB chunks over
//! [zip entries (+padding), central directory, EOCD], hashed in parallel.
//!
//!   chunk digest = H(0xa5 || u32le(chunk_len) || chunk)
//!   top digest   = H(0x5a || u32le(chunk_count) || chunk digests...)
//!
//! The chunks are read straight out of the mapped APK. With SHA-256 (every key except RSA above
//! 3072 bits) and SHA-NI, each worker keeps two chunks in flight and feeds them to the core's SHA
//! unit together, refilling a lane as soon as its chunk ends; otherwise ring hashes one chunk at a
//! time.

use std::sync::atomic::{AtomicUsize, Ordering};

use ring::digest::{Algorithm, Context, SHA256};

use crate::sha256::{self, Sha256, ShaNi};

pub const CHUNK_SIZE: u64 = 1 << 20;

/// One digested section: `data` followed by `tail` (the zero padding that apksig appends to the
/// entries section). `file_off` is where `data` starts in the APK when it is a view of the mapped
/// file, so that the zipalign inspector sees file offsets; `None` for in-memory sections.
pub struct Source<'a> {
    pub file_off: Option<u64>,
    pub data: &'a [u8],
    pub tail: &'a [u8],
}

impl<'a> Source<'a> {
    pub fn file(off: u64, data: &'a [u8], tail: &'a [u8]) -> Self {
        Source { file_off: Some(off), data, tail }
    }
    pub fn bytes(b: &'a [u8]) -> Self {
        Source { file_off: None, data: b, tail: &[] }
    }
    pub fn len(&self) -> u64 {
        (self.data.len() + self.tail.len()) as u64
    }
    pub fn chunk_count(&self) -> u64 {
        (self.len() + CHUNK_SIZE - 1) / CHUNK_SIZE
    }

    /// Chunk `k` of this source: its part of `data`, then its part of `tail`.
    fn chunk(&self, k: u64) -> [&'a [u8]; 2] {
        let start = (k * CHUNK_SIZE) as usize;
        let end = (k * CHUNK_SIZE + CHUNK_SIZE).min(self.len()) as usize;
        let d = self.data.len();
        [&self.data[start.min(d)..end.min(d)], &self.tail[start.saturating_sub(d)..end.saturating_sub(d)]]
    }
}

/// Digest of one chunk: `H(0xa5 || u32le(len) || parts...)`.
pub fn hash_chunk(alg: &'static Algorithm, parts: &[&[u8]]) -> ring::digest::Digest {
    let len: usize = parts.iter().map(|p| p.len()).sum();
    let mut ctx = Context::new(alg);
    let mut prefix = [0xa5u8, 0, 0, 0, 0];
    prefix[1..].copy_from_slice(&(len as u32).to_le_bytes());
    ctx.update(&prefix);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish()
}

/// Chunk digests of an in-memory section, concatenated, plus the chunk count.
pub fn chunk_digests_of(alg: &'static Algorithm, data: &[u8]) -> (usize, Vec<u8>) {
    let mut out = Vec::with_capacity(((data.len() >> 20) + 1) * alg.output_len());
    let mut n = 0;
    for c in data.chunks(CHUNK_SIZE as usize) {
        out.extend_from_slice(hash_chunk(alg, &[c]).as_ref());
        n += 1;
    }
    (n, out)
}

/// Top-level digest: `H(0x5a || u32le(count) || chunk digests)`. `parts` are concatenated
/// chunk-digest runs (e.g. entries section, central directory, EOCD).
pub fn top_digest(alg: &'static Algorithm, count: usize, parts: &[&[u8]]) -> Vec<u8> {
    let mut ctx = Context::new(alg);
    let mut prefix = [0x5au8, 0, 0, 0, 0];
    prefix[1..].copy_from_slice(&(count as u32).to_le_bytes());
    ctx.update(&prefix);
    for p in parts {
        ctx.update(p);
    }
    ctx.finish().as_ref().to_vec()
}

/// A claimed chunk: global index, its bytes, and the file-backed part of them (for `release`).
type Claimed<'a> = (usize, [&'a [u8]; 2], &'a [u8]);

/// A chunk being hashed on SHA-NI: the hasher and the bytes it has not absorbed yet.
struct Lane<'a> {
    k: usize,
    h: Sha256,
    parts: [&'a [u8]; 2],
    file_part: &'a [u8],
}

impl<'a> Lane<'a> {
    fn new(ni: ShaNi, (k, parts, file_part): Claimed<'a>) -> Self {
        let mut h = Sha256::new(ni);
        let mut prefix = [0xa5u8, 0, 0, 0, 0];
        prefix[1..].copy_from_slice(&((parts[0].len() + parts[1].len()) as u32).to_le_bytes());
        h.update(&prefix);
        Lane { k, h, parts, file_part }
    }

    /// Absorb bytes through the hasher's buffer until whole blocks are next (the 5-byte prefix
    /// and part boundaries leave a partial block). Returns how many whole blocks can go to the
    /// 2-way kernel, or 0 once everything is absorbed.
    fn settle(&mut self) -> usize {
        loop {
            let p = self.parts[0];
            if p.is_empty() {
                if self.parts[1].is_empty() {
                    return 0;
                }
                self.parts = [self.parts[1], &[]];
                continue;
            }
            let take = match self.h.gap() {
                0 if p.len() >= 64 => return p.len() / 64,
                0 => p.len(),
                gap => gap.min(p.len()),
            };
            self.h.update(&p[..take]);
            self.parts[0] = &p[take..];
        }
    }

    fn take_blocks(&mut self, n: usize) -> &'a [u8] {
        let (blocks, rest) = self.parts[0].split_at(n * 64);
        self.parts[0] = rest;
        blocks
    }
}

/// Callbacks on the file-backed part of every chunk.
#[derive(Default, Clone, Copy)]
pub struct Observers<'a> {
    /// `(file offset, bytes)` just before the chunk is hashed: the zipalign check, which thereby
    /// costs no extra pass over the file on the aligned-input fast path.
    pub inspect: Option<&'a (dyn Fn(u64, &[u8]) + Sync)>,
    /// The bytes once hashed, never to be read again (`Mmap::release`).
    pub release: Option<&'a (dyn Fn(&[u8]) + Sync)>,
}

/// Compute the content digest of `sources` with `alg` on up to `threads()` threads (only asked
/// when there is more than one thread's worth of work).
pub fn content_digest(sources: &[Source], alg: &'static Algorithm, threads: &dyn Fn() -> usize, obs: Observers) -> Vec<u8> {
    let counts: Vec<u64> = sources.iter().map(|s| s.chunk_count()).collect();
    let total = counts.iter().sum::<u64>() as usize;
    let ol = alg.output_len();
    let next = AtomicUsize::new(0);

    // Hand out chunks one at a time from a shared counter, so a slow thread (page-cache miss, a
    // busy sibling) never holds a fixed share of the work hostage.
    let claim = || -> Option<Claimed> {
        let k = next.fetch_add(1, Ordering::Relaxed);
        if k >= total {
            return None;
        }
        let (mut idx, mut si) = (k as u64, 0usize);
        while idx >= counts[si] {
            idx -= counts[si];
            si += 1;
        }
        let src = &sources[si];
        let parts = src.chunk(idx);
        let Some(off) = src.file_off else { return Some((k, parts, &[])) };
        if let Some(f) = obs.inspect {
            if !parts[0].is_empty() {
                f(off + idx * CHUNK_SIZE, parts[0]);
            }
        }
        Some((k, parts, parts[0]))
    };
    let release = |file_part: &[u8]| {
        if let Some(f) = obs.release {
            if !file_part.is_empty() {
                f(file_part);
            }
        }
    };

    // Spawning a thread costs ~50 µs; below ~512 KiB per thread it is not worth it.
    let total_len: u64 = sources.iter().map(|s| s.len()).sum();
    let useful = (total_len.div_ceil(512 << 10) as usize).min(total).max(1);
    let threads = if useful > 1 { threads().clamp(1, useful) } else { 1 };
    let ni = if *alg == SHA256 { ShaNi::detect() } else { None };

    let worker = || -> Vec<(usize, [u8; 64])> {
        let mut out = Vec::new();
        let mut record = |k: usize, d: &[u8]| {
            let mut a = [0u8; 64];
            a[..d.len()].copy_from_slice(d);
            out.push((k, a));
        };
        let Some(ni) = ni else {
            while let Some((k, parts, file_part)) = claim() {
                record(k, hash_chunk(alg, &parts).as_ref());
                release(file_part);
            }
            return out;
        };
        let mut lanes: [Option<Lane>; 2] = [None, None];
        loop {
            for i in 0..2 {
                loop {
                    if lanes[i].is_none() {
                        // A second chunk only while every thread can still get one of its own:
                        // one chunk per core beats two on one core when chunks run short.
                        if lanes[1 - i].is_some() && total.saturating_sub(next.load(Ordering::Relaxed)) < threads {
                            break;
                        }
                        let Some(c) = claim() else { break };
                        lanes[i] = Some(Lane::new(ni, c));
                    }
                    let lane = lanes[i].as_mut().unwrap();
                    if lane.settle() > 0 {
                        break;
                    }
                    let done = lanes[i].take().unwrap();
                    record(done.k, &done.h.finish());
                    release(done.file_part);
                }
            }
            match &mut lanes {
                [Some(a), Some(b)] => {
                    let n = (a.parts[0].len() / 64).min(b.parts[0].len() / 64);
                    let (da, db) = (a.take_blocks(n), b.take_blocks(n));
                    sha256::update2(&mut a.h, &mut b.h, da, db);
                }
                [Some(a), None] | [None, Some(a)] => {
                    let n = a.parts[0].len() / 64;
                    let d = a.take_blocks(n);
                    a.h.update(d);
                }
                [None, None] => return out,
            }
        }
    };

    let mut all: Vec<(usize, [u8; 64])> = Vec::with_capacity(total);
    if threads <= 1 {
        all = worker();
    } else {
        let worker = &worker;
        std::thread::scope(|s| {
            let handles: Vec<_> = (1..threads).map(|_| s.spawn(worker)).collect();
            all.extend(worker());
            for h in handles {
                all.extend(h.join().expect("digest worker panicked"));
            }
        });
    }
    debug_assert_eq!(all.len(), total);
    let mut concat = vec![0u8; total * ol];
    for (k, d) in &all {
        concat[k * ol..(k + 1) * ol].copy_from_slice(&d[..ol]);
    }
    top_digest(alg, total, &[&concat])
}

/// Number of physical cores: available parallelism divided by the SMT width of cpu0
/// (`thread_siblings_list`, one ~10 µs sysfs read). SMT siblings share the SHA unit that each
/// worker already feeds two streams: they gain a few percent on one big APK and lose more than
/// that on a batch of small ones (KNOWLEDGE.md §4.1, §10.7). Falls back to available parallelism.
pub fn physical_cores() -> usize {
    let avail = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let smt = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list")
        .ok()
        .map(|s| cpu_list_len(s.trim()))
        .filter(|&n| n >= 1)
        .unwrap_or(1);
    (avail / smt).max(1)
}

/// Length of a Linux CPU list such as "0,16" or "0-3,8-11".
fn cpu_list_len(s: &str) -> usize {
    s.split(',')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('-') {
            Some((a, b)) => match (a.parse::<usize>(), b.parse::<usize>()) {
                (Ok(a), Ok(b)) if b >= a => b - a + 1,
                _ => 1,
            },
            None => 1,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::SHA512;

    /// Straightforward single-threaded reference implementation of the spec, on ring.
    fn reference(alg: &'static Algorithm, sections: &[Vec<u8>]) -> Vec<u8> {
        let mut chunks = Vec::new();
        for s in sections {
            for c in s.chunks(CHUNK_SIZE as usize) {
                let mut ctx = Context::new(alg);
                ctx.update(&[0xa5]);
                ctx.update(&(c.len() as u32).to_le_bytes());
                ctx.update(c);
                chunks.push(ctx.finish().as_ref().to_vec());
            }
            // zero-length sections contribute zero chunks
        }
        let mut top = vec![0x5a];
        top.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
        for c in &chunks {
            top.extend_from_slice(c);
        }
        ring::digest::digest(alg, &top).as_ref().to_vec()
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
    }

    #[test]
    fn matches_reference_across_chunk_boundaries_and_thread_counts() {
        // entries: 2.5 MiB from "file" + 1000 bytes of zero padding tail; CD: 70 KiB; EOCD: 22 B
        let file = pattern((2 << 20) + (1 << 19), 7);
        let pad = vec![0u8; 1000];
        let cd = pattern(70 * 1024, 3);
        let eocd = pattern(22, 9);

        let mut entries = file.clone();
        entries.extend_from_slice(&pad);
        let expect = reference(&SHA256, &[entries, cd.clone(), eocd.clone()]);

        for threads in [1usize, 2, 3, 16] {
            let sources = [Source::file(0, &file, &pad), Source::bytes(&cd), Source::bytes(&eocd)];
            assert_eq!(content_digest(&sources, &SHA256, &|| threads, Observers::default()), expect, "threads={threads}");
        }
    }

    #[test]
    fn many_chunks_and_odd_sizes_on_every_path() {
        // 9.3 MiB of file with a 4095-byte padding tail that straddles the last chunk boundary,
        // plus sections shorter than one block: every lane refill, part switch and short chunk.
        let file = pattern(9 * (1 << 20) + 300_000, 5);
        let pad = vec![0u8; 4095];
        let small = pattern(58, 1);
        let one = pattern(1, 2);
        let mut entries = file.clone();
        entries.extend_from_slice(&pad);
        for alg in [&SHA256, &SHA512] {
            let expect = reference(alg, &[entries.clone(), small.clone(), vec![], one.clone()]);
            for threads in [1usize, 2, 3, 4, 7, 32] {
                let sources = [Source::file(0, &file, &pad), Source::bytes(&small), Source::bytes(&[]), Source::bytes(&one)];
                assert_eq!(content_digest(&sources, alg, &|| threads, Observers::default()), expect, "threads={threads}");
            }
        }
    }

    #[test]
    fn exact_multiple_of_the_chunk_size() {
        let file = pattern(3 << 20, 1);
        let sec = &file[12345..12345 + (2 << 20)];
        let expect = reference(&SHA256, &[sec.to_vec()]);
        assert_eq!(content_digest(&[Source::file(12345, sec, &[])], &SHA256, &|| 4, Observers::default()), expect);
        // A padding tail after an exact multiple is a chunk of its own, with no file bytes.
        let pad = vec![0u8; 100];
        let mut padded = sec.to_vec();
        padded.extend_from_slice(&pad);
        let expect = reference(&SHA256, &[padded]);
        for threads in [1usize, 3] {
            assert_eq!(content_digest(&[Source::file(12345, sec, &pad)], &SHA256, &|| threads, Observers::default()), expect);
        }
    }

    #[test]
    fn pieces_compose_to_the_same_digest() {
        let a = pattern((1 << 20) + 5000, 1);
        let b = pattern(70_000, 2);
        let c = pattern(22, 3);
        let whole = content_digest(&[Source::bytes(&a), Source::bytes(&b), Source::bytes(&c)], &SHA256, &|| 3, Observers::default());
        let (na, da) = chunk_digests_of(&SHA256, &a);
        let (nb, db) = chunk_digests_of(&SHA256, &b);
        let (nc, dc) = chunk_digests_of(&SHA256, &c);
        assert_eq!((na, nb, nc), (2, 1, 1));
        assert_eq!(top_digest(&SHA256, na + nb + nc, &[&da, &db, &dc]), whole);
        // hash_chunk over split parts equals over the concatenation
        assert_eq!(hash_chunk(&SHA256, &[&a[..100], &a[100..2000]]).as_ref(), hash_chunk(&SHA256, &[&a[..2000]]).as_ref());
    }

    #[test]
    fn inspect_sees_every_file_byte_once_with_offsets() {
        use std::sync::Mutex;
        let file = pattern((2 << 20) + 777, 5);
        let pad = vec![0u8; 3000];
        let seen = Mutex::new(Vec::new());
        let sources = [Source::file(100, &file[100..], &pad), Source::bytes(&pad)];
        let released = Mutex::new(Vec::new());
        let inspect = |off: u64, b: &[u8]| seen.lock().unwrap().push((off, b.to_vec()));
        let release = |b: &[u8]| released.lock().unwrap().push((b.as_ptr() as usize - file.as_ptr() as usize, b.len()));
        content_digest(&sources, &SHA256, &|| 3, Observers { inspect: Some(&inspect), release: Some(&release) });
        let mut seen = seen.into_inner().unwrap();
        let mut released = released.into_inner().unwrap();
        released.sort();
        let file_backed: Vec<(usize, usize)> = seen.iter().map(|(o, b)| (*o as usize, b.len())).collect::<Vec<_>>();
        assert_eq!(released, { let mut f = file_backed; f.sort(); f }, "every file-backed chunk is released once, after hashing");
        seen.sort_by_key(|(o, _)| *o);
        let mut rebuilt = Vec::new();
        let mut expect_off = 100u64;
        for (off, b) in &seen {
            assert_eq!(*off, expect_off);
            expect_off += b.len() as u64;
            rebuilt.extend_from_slice(b);
        }
        assert_eq!(rebuilt, &file[100..], "inspector must see exactly the file-backed bytes, not the padding tail");
    }

    #[test]
    fn cpu_list_parsing() {
        assert_eq!(cpu_list_len("0"), 1);
        assert_eq!(cpu_list_len("0,16"), 2);
        assert_eq!(cpu_list_len("0-3"), 4);
        assert_eq!(cpu_list_len("0-3,8-11"), 8);
        assert_eq!(cpu_list_len(""), 0);
    }

    #[test]
    fn physical_cores_is_sane() {
        let n = physical_cores();
        assert!(n >= 1);
        assert!(n <= std::thread::available_parallelism().map(|x| x.get()).unwrap_or(usize::MAX));
    }
}
