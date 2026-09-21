//! APK Signature Scheme v2/v3 content digest: 1 MiB chunks over
//! [zip entries (+padding), central directory, EOCD], hashed in parallel.
//!
//!   chunk digest = H(0xa5 || u32le(chunk_len) || chunk)
//!   top digest   = H(0x5a || u32le(chunk_count) || chunk digests...)

use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

use ring::digest::{Algorithm, Context};

use crate::zip::ReadAt;

pub const CHUNK_SIZE: u64 = 1 << 20;

/// One digested section. Bytes come from `file[file_off .. file_off+file_len]` followed by
/// `tail` (used for the zero padding that apksig appends to the entries section, and for
/// in-memory CD / EOCD sections).
pub struct Source<'a> {
    pub file_off: u64,
    pub file_len: u64,
    pub tail: &'a [u8],
}

impl<'a> Source<'a> {
    pub fn file(off: u64, len: u64, tail: &'a [u8]) -> Self {
        Source { file_off: off, file_len: len, tail }
    }
    pub fn bytes(b: &'a [u8]) -> Self {
        Source { file_off: 0, file_len: 0, tail: b }
    }
    pub fn len(&self) -> u64 {
        self.file_len + self.tail.len() as u64
    }
    pub fn chunk_count(&self) -> u64 {
        (self.len() + CHUNK_SIZE - 1) / CHUNK_SIZE
    }

    /// Copy chunk `k` of this source into `buf`; returns the chunk length.
    fn read_chunk(&self, k: u64, file: &(impl ReadAt + ?Sized), buf: &mut [u8]) -> io::Result<usize> {
        let start = k * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(self.len());
        let n = (end - start) as usize;
        let mut filled = 0usize;
        if start < self.file_len {
            let file_end = end.min(self.file_len);
            filled = (file_end - start) as usize;
            file.read_exact_at(&mut buf[..filled], self.file_off + start)?;
        }
        if end > self.file_len {
            let t0 = start.saturating_sub(self.file_len) as usize;
            let t1 = (end - self.file_len) as usize;
            buf[filled..n].copy_from_slice(&self.tail[t0..t1]);
        }
        Ok(n)
    }
}

/// Compute the content digest for every algorithm in `algs`, in one pass over the data.
/// Returns one digest per algorithm, in order.
pub fn content_digests(
    file: &(impl ReadAt + Sync + ?Sized),
    sources: &[Source],
    algs: &[&'static Algorithm],
    threads: usize,
) -> io::Result<Vec<Vec<u8>>> {
    let counts: Vec<u64> = sources.iter().map(|s| s.chunk_count()).collect();
    let total = counts.iter().sum::<u64>() as usize;
    let per_chunk_out: usize = algs.iter().map(|a| a.output_len()).sum();
    let next = AtomicUsize::new(0);

    // Dynamic scheduling: every thread grabs the next chunk index from a shared counter, so a
    // straggler (page-cache miss, SMT sibling contention) never holds a fixed slice hostage.
    let worker = |out: &mut Vec<(usize, Vec<u8>)>| -> io::Result<()> {
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        let mut prefix = [0xa5u8, 0, 0, 0, 0];
        loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            if k >= total {
                return Ok(());
            }
            let mut idx = k as u64;
            let mut si = 0usize;
            while idx >= counts[si] {
                idx -= counts[si];
                si += 1;
            }
            let n = sources[si].read_chunk(idx, file, &mut buf)?;
            prefix[1..].copy_from_slice(&(n as u32).to_le_bytes());
            let mut d = Vec::with_capacity(per_chunk_out);
            for alg in algs {
                let mut ctx = Context::new(alg);
                ctx.update(&prefix);
                ctx.update(&buf[..n]);
                d.extend_from_slice(ctx.finish().as_ref());
            }
            out.push((k, d));
        }
    };

    // Spawning a thread costs ~50 µs; below ~512 KiB per thread it is not worth it.
    let total_len: u64 = sources.iter().map(|s| s.len()).sum();
    let useful = ((total_len + (512 << 10) - 1) / (512 << 10)) as usize;
    let threads = threads.max(1).min(total.max(1)).min(useful.max(1));
    let mut all: Vec<(usize, Vec<u8>)> = Vec::with_capacity(total);
    if threads <= 1 {
        worker(&mut all)?;
    } else {
        let worker = &worker;
        std::thread::scope(|s| -> io::Result<()> {
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    s.spawn(move || {
                        let mut r = Vec::new();
                        worker(&mut r).map(|_| r)
                    })
                })
                .collect();
            for h in handles {
                all.extend(h.join().expect("digest worker panicked")?);
            }
            Ok(())
        })?;
    }

    let mut result = Vec::with_capacity(algs.len());
    let mut off = 0usize;
    for alg in algs {
        let ol = alg.output_len();
        let mut concat = vec![0u8; 5 + total * ol];
        concat[0] = 0x5a;
        concat[1..5].copy_from_slice(&(total as u32).to_le_bytes());
        for (k, d) in &all {
            concat[5 + k * ol..5 + (k + 1) * ol].copy_from_slice(&d[off..off + ol]);
        }
        result.push(ring::digest::digest(alg, &concat).as_ref().to_vec());
        off += ol;
    }
    Ok(result)
}

/// Number of physical cores: available parallelism divided by the SMT width of cpu0
/// (`thread_siblings_list`, one ~10 µs sysfs read). SHA-NI saturates a core's crypto unit, so SMT
/// siblings only add contention (KNOWLEDGE.md §4.1). Falls back to available parallelism.
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
    use ring::digest::SHA256;

    /// Straightforward single-threaded reference implementation of the spec.
    fn reference(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut chunks = Vec::new();
        for s in sections {
            for c in s.chunks(CHUNK_SIZE as usize) {
                let mut ctx = Context::new(&SHA256);
                ctx.update(&[0xa5]);
                ctx.update(&(c.len() as u32).to_le_bytes());
                ctx.update(c);
                chunks.push(ctx.finish().as_ref().to_vec());
            }
            if s.is_empty() {
                // zero-length sections contribute zero chunks
            }
        }
        let mut top = vec![0x5a];
        top.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
        for c in &chunks {
            top.extend_from_slice(c);
        }
        ring::digest::digest(&SHA256, &top).as_ref().to_vec()
    }

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
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
        let expect = reference(&[entries, cd.clone(), eocd.clone()]);

        for threads in [1usize, 2, 3, 16] {
            let sources = [
                Source::file(0, file.len() as u64, &pad),
                Source::bytes(&cd),
                Source::bytes(&eocd),
            ];
            let got = content_digests(file.as_slice(), &sources, &[&SHA256], threads).unwrap();
            assert_eq!(got[0], expect, "threads={threads}");
        }
    }

    #[test]
    fn file_subrange_and_exact_multiple() {
        // Source that starts at an offset and is exactly 2 chunks with no tail.
        let file = pattern(3 << 20, 1);
        let off = 12345u64;
        let len = 2u64 << 20;
        let sec = file[off as usize..(off + len) as usize].to_vec();
        let expect = reference(&[sec]);
        let got = content_digests(file.as_slice(), &[Source::file(off, len, &[])], &[&SHA256], 4).unwrap();
        assert_eq!(got[0], expect);
    }

    #[test]
    fn two_algorithms_in_one_pass() {
        use ring::digest::SHA512;
        let data = pattern(1500, 4);
        let got = content_digests(data.as_slice(), &[Source::bytes(&data)], &[&SHA256, &SHA512], 2).unwrap();
        assert_eq!(got[0].len(), 32);
        assert_eq!(got[1].len(), 64);
        assert_eq!(got[0], reference(&[data.clone()]));
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
