//! zipalign: check that uncompressed entries' data is aligned (4 bytes, a page for `.so`), and
//! rewrite the entries section when it is not.
//!
//! The check piggybacks on the digest pass, which already streams every byte of the file: the
//! `LfhInspector` picks the local file headers out of each chunk while it is in memory, so an
//! already-aligned APK (the normal case) pays no extra I/O. The rewrite follows apksig's
//! `ApkSigner.sign` byte for byte: every stored entry gets a `0xd935` alignment extra field (old
//! ones and zipalign's raw zero padding are removed), compressed entries are copied verbatim,
//! dropped entries disappear, and unprocessed bytes between records are copied as they are.
//!
//! The rewrite is planned first (every output offset is known before a byte is copied), then
//! workers materialise the output in 1 MiB chunks — which are exactly the v2/v3 digest chunks —
//! so each chunk is written and hashed in the same pass and no second read of the file is needed.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Mutex;
use std::time::Instant;


use ring::digest::Algorithm;

use crate::digest::{self, CHUNK_SIZE};
use crate::zip::{self, CdEntry, EntryPolicy, ReadAt, DATA_DESCRIPTOR_SIG, LFH_LEN, LFH_SIG};

pub const ALIGNMENT_EXTRA_ID: u16 = 0xd935;
const WINDOW_SIZE: usize = 256 << 10;
/// Largest source span read with one pread while materialising an output chunk.
const SRC_WINDOW: usize = 2 << 20;
/// Producers feeding the single writer thread. The page-cache write of one file is serialised
/// by the kernel at ~9 GB/s and slows down when many other threads compete for memory, so a
/// handful of producers (read + assemble + hash at ~1.5 GB/s each) is the sweet spot.
const MAX_PRODUCERS: usize = 6;

#[derive(Clone, Copy)]
pub struct Policy {
    /// Page size for `.so` entries in bytes; values <= 4 disable page alignment.
    pub lib_page_size: u32,
}

/// (name_len, extra_len) of an entry's local file header.
pub type LfhLens = (u16, u16);

fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}

/// Entry indices sorted by local header offset; validates that headers are distinct, ordered
/// and inside the entries section.
fn file_order(entries: &[CdEntry], entries_end: u64) -> Result<Vec<usize>, String> {
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|&i| entries[i].lfh_off);
    for (k, &i) in order.iter().enumerate() {
        let off = entries[i].lfh_off;
        if off + LFH_LEN as u64 > entries_end {
            return Err(format!("local file header at {off} lies outside the entries section"));
        }
        if k > 0 && entries[order[k - 1]].lfh_off == off {
            return Err(format!("two Central Directory entries share local header offset {off}"));
        }
    }
    Ok(order)
}

/// Collects local-file-header lengths from digest chunks as they stream by.
pub struct LfhInspector {
    offsets: Vec<u64>,
    order: Vec<usize>,
    found: Mutex<Vec<(usize, LfhLens)>>,
    straddlers: Mutex<Vec<usize>>,
    error: Mutex<Option<String>>,
}

impl LfhInspector {
    pub fn new(entries: &[CdEntry], entries_end: u64) -> Result<Self, String> {
        let order = file_order(entries, entries_end)?;
        let offsets = order.iter().map(|&i| entries[i].lfh_off).collect();
        Ok(LfhInspector {
            offsets,
            order,
            found: Mutex::new(Vec::with_capacity(entries.len())),
            straddlers: Mutex::new(Vec::new()),
            error: Mutex::new(None),
        })
    }

    /// Called with every file-backed digest chunk.
    pub fn inspect(&self, file_off: u64, buf: &[u8]) {
        let end = file_off + buf.len() as u64;
        let lo = self.offsets.partition_point(|&o| o < file_off);
        let hi = self.offsets.partition_point(|&o| o < end);
        if lo == hi {
            return;
        }
        let mut found = Vec::with_capacity(hi - lo);
        let mut straddlers = Vec::new();
        for k in lo..hi {
            let rel = (self.offsets[k] - file_off) as usize;
            if rel + LFH_LEN <= buf.len() {
                let h = &buf[rel..rel + LFH_LEN];
                if h[..4] != LFH_SIG {
                    *self.error.lock().unwrap() = Some(format!("no local file header at offset {}", self.offsets[k]));
                    return;
                }
                found.push((self.order[k], (u16le(h, 26), u16le(h, 28))));
            } else {
                straddlers.push(self.order[k]);
            }
        }
        self.found.lock().unwrap().extend(found);
        if !straddlers.is_empty() {
            self.straddlers.lock().unwrap().extend(straddlers);
        }
    }

    /// Per-entry (name_len, extra_len), reading the few headers that straddled chunk boundaries.
    pub fn finish(self, file: &(impl ReadAt + ?Sized), entries: &[CdEntry]) -> Result<Vec<LfhLens>, String> {
        if let Some(e) = self.error.into_inner().unwrap() {
            return Err(e);
        }
        let mut lens: Vec<Option<LfhLens>> = vec![None; entries.len()];
        for (i, l) in self.found.into_inner().unwrap() {
            lens[i] = Some(l);
        }
        for i in self.straddlers.into_inner().unwrap() {
            lens[i] = Some(read_lfh_lens(file, entries[i].lfh_off)?);
        }
        lens.into_iter()
            .enumerate()
            .map(|(i, l)| l.ok_or_else(|| format!("local file header at {} was not seen by the digest pass", entries[i].lfh_off)))
            .collect()
    }
}

fn read_lfh_lens(file: &(impl ReadAt + ?Sized), off: u64) -> Result<LfhLens, String> {
    let mut h = [0u8; LFH_LEN];
    file.read_exact_at(&mut h, off).map_err(|e| format!("read local file header at {off}: {e}"))?;
    if h[..4] != LFH_SIG {
        return Err(format!("no local file header at offset {off}"));
    }
    Ok((u16le(&h, 26), u16le(&h, 28)))
}

/// Cheap early test: read the local headers of the first `sample` stored, non-directory entries
/// (Central Directory order) and report whether any of them is misaligned. A ZIP written
/// without alignment padding fails this almost immediately, which lets the rewrite start without
/// first digesting the old layout. `false` only means "not proven misaligned".
pub fn quick_misaligned(file: &(impl ReadAt + ?Sized), cd: &[u8], entries: &[CdEntry], entries_end: u64, policy: &Policy, sample: usize) -> Result<bool, String> {
    let mut seen = 0usize;
    for e in entries {
        let req = zip::required_alignment(cd, e, policy.lib_page_size);
        if req <= 1 {
            continue;
        }
        if e.lfh_off + LFH_LEN as u64 > entries_end {
            return Err(format!("local file header at {} lies outside the entries section", e.lfh_off));
        }
        let (nl, el) = read_lfh_lens(file, e.lfh_off)?;
        let data_off = e.lfh_off + (LFH_LEN + nl as usize + el as usize) as u64;
        if data_off % req as u64 != 0 {
            return Ok(true);
        }
        seen += 1;
        if seen >= sample {
            break;
        }
    }
    Ok(false)
}

pub struct Misaligned {
    pub name: String,
    pub data_off: u64,
    pub required: u32,
}

/// Which entries violate the alignment policy. Errors if a header overruns the next entry.
pub fn check(cd: &[u8], entries: &[CdEntry], lens: &[LfhLens], entries_end: u64, policy: &Policy) -> Result<Vec<Misaligned>, String> {
    let order = file_order(entries, entries_end)?;
    let mut bad = Vec::new();
    for (k, &i) in order.iter().enumerate() {
        let e = &entries[i];
        let (nl, el) = lens[i];
        let data_off = e.lfh_off + (LFH_LEN + nl as usize + el as usize) as u64;
        let limit = order.get(k + 1).map_or(entries_end, |&j| entries[j].lfh_off);
        if data_off > limit {
            return Err(format!("local file header of {:?} overruns the next entry", String::from_utf8_lossy(e.name(cd))));
        }
        let req = zip::required_alignment(cd, e, policy.lib_page_size);
        if req > 1 && data_off % req as u64 != 0 {
            bad.push(Misaligned { name: String::from_utf8_lossy(e.name(cd)).into_owned(), data_off, required: req });
        }
    }
    Ok(bad)
}

/// Alignment declared by a `0xd935` extra field, if any (apksig's
/// `getInputJarEntryDataAlignmentMultiple`).
pub fn declared_alignment(extra: &[u8]) -> Option<u32> {
    let mut p = 0;
    while extra.len() - p >= 4 {
        let id = u16le(extra, p);
        let size = u16le(extra, p + 2) as usize;
        if size > extra.len() - p - 4 {
            return None;
        }
        if id == ALIGNMENT_EXTRA_ID && size >= 2 {
            return Some(u16le(extra, p + 4) as u32);
        }
        p += 4 + size;
    }
    None
}

/// apksig's `createExtraFieldToAlignData`: keep every well-formed extra field except previous
/// `0xd935` fields and zipalign's raw zero padding, then append a `0xd935` field sized so the
/// entry data (which follows the extra field at `extra_start_off`) lands on `align`.
pub fn aligning_extra(original: &[u8], extra_start_off: u64, align: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(original.len() + 6 + align as usize);
    let mut p = 0;
    while original.len() - p >= 4 {
        let id = u16le(original, p);
        let size = u16le(original, p + 2) as usize;
        if size > original.len() - p - 4 {
            break;
        }
        if !((id == 0 && size == 0) || id == ALIGNMENT_EXTRA_ID) {
            out.extend_from_slice(&original[p..p + 4 + size]);
        }
        p += 4 + size;
    }
    let data_min_start = extra_start_off + out.len() as u64 + 6;
    let pad = ((align as u64 - data_min_start % align as u64) % align as u64) as usize;
    out.extend_from_slice(&ALIGNMENT_EXTRA_ID.to_le_bytes());
    out.extend_from_slice(&((2 + pad) as u16).to_le_bytes());
    out.extend_from_slice(&(align as u16).to_le_bytes());
    out.resize(out.len() + pad, 0);
    out
}

pub struct Rewritten {
    pub cd: Vec<u8>,
    pub entries_end: u64,
    pub entries: u64,
    pub dropped: usize,
    /// Zero padding that follows the entries (`sigblock::padding_before_block(entries_end)`);
    /// it is part of the digested contents and is covered by `chunk_digests`.
    pub pad: u64,
    /// Number of 1 MiB chunks in `[0, entries_end + pad)` and their concatenated digests.
    pub chunk_count: usize,
    pub chunk_digests: Vec<u8>,
    /// Per-phase timing summary for `--timing`.
    pub stats: String,
}

struct Plan {
    /// Index into `entries` for an output record; `None` for a verbatim gap copy.
    idx: Option<usize>,
    src_off: u64,
    src_len: u64,
    new_off: u64,
    /// Rebuilt local header (30 bytes + name + new extra); empty for a gap.
    hdr: Vec<u8>,
}

impl Plan {
    fn out_len(&self) -> u64 {
        self.hdr.len() as u64 + self.src_len
    }
    fn out_end(&self) -> u64 {
        self.new_off + self.out_len()
    }
}

/// Sliding-window reader for local headers: runs of small entries cost one pread.
struct HeaderReader<'a, R: ReadAt + ?Sized> {
    input: &'a R,
    entries_end: u64,
    window: Vec<u8>,
    win_off: u64,
    win_len: usize,
}

impl<'a, R: ReadAt + ?Sized> HeaderReader<'a, R> {
    fn ensure(&mut self, off: u64, need: usize) -> Result<usize, String> {
        if off < self.win_off || off + need as u64 > self.win_off + self.win_len as u64 {
            self.win_off = off;
            self.win_len = (self.entries_end - off).min(WINDOW_SIZE as u64) as usize;
            if need > self.win_len {
                return Err(format!("local file header at {off} overruns the entries section"));
            }
            self.input.read_exact_at(&mut self.window[..self.win_len], off).map_err(|e| format!("read local headers: {e}"))?;
        }
        Ok((off - self.win_off) as usize)
    }
    /// The full local header prefix (30 bytes + name + extra) at `off`.
    fn prefix(&mut self, off: u64) -> Result<Vec<u8>, String> {
        let rel = self.ensure(off, LFH_LEN)?;
        let h = &self.window[rel..rel + LFH_LEN];
        if h[..4] != LFH_SIG {
            return Err(format!("no local file header at offset {off}"));
        }
        let need = LFH_LEN + u16le(h, 26) as usize + u16le(h, 28) as usize;
        let rel = self.ensure(off, need)?;
        Ok(self.window[rel..rel + need].to_vec())
    }
}

/// Copy the entries section of `input` into `out` (from offset 0) with aligned local headers,
/// applying each entry's `EntryPolicy`, and digest the result (including the zero padding that
/// precedes the signing block) with `alg` while writing it. Returns the new Central Directory
/// (original order, `Output` entries only, offsets patched), the new entries end and the chunk
/// digests of the new contents section.
pub fn rewrite(
    input: &(impl ReadAt + Sync + ?Sized),
    cd: &[u8],
    entries: &[CdEntry],
    policies: &[EntryPolicy],
    entries_end: u64,
    out: &File,
    policy: &Policy,
    threads: usize,
    alg: &'static Algorithm,
) -> Result<Rewritten, String> {
    let order = file_order(entries, entries_end)?;
    let mut hdrs = HeaderReader { input, entries_end, window: vec![0u8; WINDOW_SIZE], win_off: 0, win_len: 0 };

    let mut plans: Vec<Plan> = Vec::with_capacity(entries.len());
    let mut cursor = 0u64; // output
    let mut consumed = 0u64; // input bytes processed so far
    let mut dropped = 0usize;
    for &i in &order {
        let e = &entries[i];
        if policies[i] == EntryPolicy::Gap {
            dropped += 1;
            continue; // its record stays unprocessed and travels with the next gap
        }
        if e.lfh_off < consumed {
            return Err(format!("entry {:?} overlaps the previous record", String::from_utf8_lossy(e.name(cd))));
        }
        if e.lfh_off > consumed {
            let len = e.lfh_off - consumed;
            plans.push(Plan { idx: None, src_off: consumed, src_len: len, new_off: cursor, hdr: Vec::new() });
            cursor += len;
        }
        let prefix = hdrs.prefix(e.lfh_off)?;
        let nl = u16le(&prefix, 26) as usize;
        let src_data_off = e.lfh_off + prefix.len() as u64;
        let mut data_len = e.compressed_size;
        if e.has_data_descriptor() {
            let mut sig = [0u8; 4];
            let at = src_data_off + data_len;
            data_len += if at + 4 <= entries_end && input.read_exact_at(&mut sig, at).is_ok() && u32::from_le_bytes(sig) == DATA_DESCRIPTOR_SIG { 16 } else { 12 };
        }
        if src_data_off + data_len > entries_end {
            return Err(format!("entry {:?} overruns the entries section", String::from_utf8_lossy(e.name(cd))));
        }
        consumed = src_data_off + data_len;
        if policies[i] == EntryPolicy::Skip {
            dropped += 1;
            continue;
        }
        let old_extra = &prefix[LFH_LEN + nl..];
        let rule = zip::required_alignment(cd, e, policy.lib_page_size);
        let mut hdr = Vec::with_capacity(prefix.len() + 64);
        hdr.extend_from_slice(&prefix[..LFH_LEN + nl]);
        if rule > 1 {
            let align = rule.max(declared_alignment(old_extra).unwrap_or(0));
            let extra = aligning_extra(old_extra, cursor + (LFH_LEN + nl) as u64, align);
            if extra.len() > u16::MAX as usize {
                return Err(format!("extra field of {:?} would exceed 64 KiB", String::from_utf8_lossy(e.name(cd))));
            }
            hdr[28..30].copy_from_slice(&(extra.len() as u16).to_le_bytes());
            hdr.extend_from_slice(&extra);
        } else {
            hdr.extend_from_slice(old_extra);
        }
        let total = hdr.len() as u64 + data_len;
        plans.push(Plan { idx: Some(i), src_off: src_data_off, src_len: data_len, new_off: cursor, hdr });
        cursor += total;
    }
    // apksig copies whatever unprocessed bytes remain after the last record (e.g. a dropped
    // source stamp entry, or zero padding left before a previous signing block) verbatim.
    if consumed < entries_end {
        let len = entries_end - consumed;
        plans.push(Plan { idx: None, src_off: consumed, src_len: len, new_off: cursor, hdr: Vec::new() });
        cursor += len;
    }
    let new_end = cursor;

    // Materialise + digest the output in 1 MiB chunks. The digested contents section is the
    // entries plus the zero padding before the signing block.
    let pad = crate::sigblock::padding_before_block(new_end);
    let stats = RewriteStats::default();
    let chunk_count = ((new_end + pad + CHUNK_SIZE - 1) / CHUNK_SIZE) as usize;
    let ol = alg.output_len();
    out.set_len(new_end).map_err(|e| format!("rewrite: {e}"))?;
    let chunker = Chunker { plans: &plans, new_end, padded_end: new_end + pad, stats: &stats };
    let producers = threads.saturating_sub(1).clamp(1, MAX_PRODUCERS).min(chunk_count.max(1));
    stats.producers.store(producers as u64, Ordering::Relaxed);
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<Job>();

    // Producers: grab the next chunk, assemble + hash it into one of two private buffers, hand
    // it to the writer; the writer returns buffers through a per-producer channel.
    let produce = |tx: Sender<Job>| -> io::Result<Vec<(usize, Vec<u8>)>> {
        let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>();
        let mut spare: Option<Vec<u8>> = Some(vec![0u8; CHUNK_SIZE as usize]);
        back_tx.send(vec![0u8; CHUNK_SIZE as usize]).expect("own channel");
        let mut src_buf = vec![0u8; SRC_WINDOW];
        let mut acc = Vec::new();
        loop {
            let k = next.fetch_add(1, Ordering::Relaxed);
            if k >= chunk_count {
                return Ok(acc);
            }
            let mut buf = match spare.take() {
                Some(b) => b,
                None => {
                    let t = Instant::now();
                    let b = back_rx.recv().map_err(|_| io::Error::other("writer thread stopped"))?;
                    stats.wait_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    b
                }
            };
            let (real, d) = chunker.assemble_and_hash(k as u64, input, &mut buf, &mut src_buf, alg)?;
            acc.push((k, d));
            if real > 0 {
                tx.send(Job { off: k as u64 * CHUNK_SIZE, len: real, buf, back: back_tx.clone() })
                    .map_err(|_| io::Error::other("writer thread stopped"))?;
            } else {
                spare = Some(buf);
            }
        }
    };
    // Writer: the only thread that touches the output, so the kernel's per-inode write lock is
    // never contended. It never stops early: buffers always go back so producers cannot hang.
    let stats_ref = &stats;
    let write_all = move || -> io::Result<()> {
        let stats = stats_ref;
        let mut first_err = None;
        for job in rx {
            if first_err.is_none() {
                let t = Instant::now();
                if let Err(e) = out.write_all_at(&job.buf[..job.len], job.off) {
                    first_err = Some(e);
                }
                stats.write_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }
            let _ = job.back.send(job.buf);
        }
        first_err.map_or(Ok(()), Err)
    };

    let mut all: Vec<(usize, Vec<u8>)> = Vec::with_capacity(chunk_count);
    let copy_result = std::thread::scope(|s| -> io::Result<()> {
        let writer = s.spawn(write_all);
        let produce = &produce;
        let handles: Vec<_> = (0..producers)
            .map(|_| {
                let tx = tx.clone();
                s.spawn(move || produce(tx))
            })
            .collect();
        drop(tx);
        let mut first_err = None;
        for h in handles {
            match h.join().expect("rewrite producer panicked") {
                Ok(r) => all.extend(r),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        let w = writer.join().expect("rewrite writer panicked");
        match (first_err, w) {
            (Some(e), _) => Err(e),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Ok(()),
        }
    });
    copy_result.map_err(|e| format!("rewrite: {e}"))?;
    let mut chunk_digests = vec![0u8; chunk_count * ol];
    for (k, d) in &all {
        chunk_digests[k * ol..(k + 1) * ol].copy_from_slice(d);
    }

    // New Central Directory in the original order, output entries only.
    let mut new_off: Vec<Option<u64>> = vec![None; entries.len()];
    for p in &plans {
        if let Some(i) = p.idx {
            new_off[i] = Some(p.new_off);
        }
    }
    let mut new_cd = Vec::with_capacity(cd.len());
    let mut count = 0u64;
    for (i, e) in entries.iter().enumerate() {
        let Some(off) = new_off[i] else { continue };
        let start = new_cd.len();
        new_cd.extend_from_slice(&cd[e.record.clone()]);
        new_cd[start + 42..start + 46].copy_from_slice(&(off as u32).to_le_bytes());
        count += 1;
    }
    Ok(Rewritten { cd: new_cd, entries_end: new_end, entries: count, dropped, pad, chunk_count, chunk_digests, stats: stats.render() })
}

/// Thread-summed nanoseconds per phase of the rewrite, for `--timing`.
#[derive(Default)]
pub struct RewriteStats {
    pub read_ns: AtomicU64,
    pub assemble_ns: AtomicU64,
    pub write_ns: AtomicU64,
    pub wait_ns: AtomicU64,
    pub hash_ns: AtomicU64,
    pub direct_reads: AtomicU64,
    pub producers: AtomicU64,
}

impl RewriteStats {
    pub fn render(&self) -> String {
        let ms = |a: &AtomicU64| a.load(Ordering::Relaxed) as f64 / 1e6;
        format!(
            "{} producers + 1 writer, thread-summed: read {:.1} ms, assemble {:.1} ms, hash {:.1} ms, buffer wait {:.1} ms; writer {:.1} ms; direct reads {}",
            self.producers.load(Ordering::Relaxed),
            ms(&self.read_ns),
            ms(&self.assemble_ns),
            ms(&self.hash_ns),
            ms(&self.wait_ns),
            ms(&self.write_ns),
            self.direct_reads.load(Ordering::Relaxed)
        )
    }
}

struct Chunker<'a> {
    plans: &'a [Plan],
    new_end: u64,
    padded_end: u64,
    stats: &'a RewriteStats,
}

/// A finished output chunk on its way to the writer thread.
struct Job {
    off: u64,
    len: usize,
    buf: Vec<u8>,
    back: Sender<Vec<u8>>,
}

impl Chunker<'_> {
    /// Build output chunk `k` in `buf` and return (bytes to write, digest); the digest also
    /// covers the zero padding beyond `new_end`.
    fn assemble_and_hash(
        &self,
        k: u64,
        input: &(impl ReadAt + ?Sized),
        buf: &mut [u8],
        src_buf: &mut [u8],
        alg: &'static Algorithm,
    ) -> io::Result<(usize, Vec<u8>)> {
        let cs = k * CHUNK_SIZE;
        let ce = (cs + CHUNK_SIZE).min(self.padded_end);
        let real_end = ce.min(self.new_end);
        let real = real_end.saturating_sub(cs) as usize;
        let zeros = (ce - cs) as usize - real;
        static ZEROS: [u8; 4096] = [0u8; 4096];
        debug_assert!(zeros <= ZEROS.len());

        if real == 0 {
            return Ok((0, digest::hash_chunk(alg, &[&ZEROS[..zeros]]).as_ref().to_vec()));
        }

        // Plans overlapping [cs, real_end): the first is the one whose end is past cs.
        let first = self.plans.partition_point(|p| p.out_end() <= cs);
        let overlapping = &self.plans[first..];
        let overlapping = &overlapping[..overlapping.partition_point(|p| p.new_off < real_end)];

        // Source span needed for this chunk; one pread if it is compact.
        let t = Instant::now();
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for p in overlapping {
            let data_start = p.new_off + p.hdr.len() as u64;
            let a = data_start.max(cs);
            let b = (data_start + p.src_len).min(real_end);
            if a < b {
                lo = lo.min(p.src_off + (a - data_start));
                hi = hi.max(p.src_off + (b - data_start));
            }
        }
        let window = if lo < hi && (hi - lo) as usize <= src_buf.len() {
            input.read_exact_at(&mut src_buf[..(hi - lo) as usize], lo)?;
            Some(lo)
        } else {
            None
        };
        self.stats.read_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);

        let t = Instant::now();
        let target: &mut [u8] = &mut buf[..real];
        for p in overlapping {
            // header part
            let h0 = p.new_off;
            let h1 = h0 + p.hdr.len() as u64;
            let (a, b) = (h0.max(cs), h1.min(real_end));
            if a < b {
                target[(a - cs) as usize..(b - cs) as usize].copy_from_slice(&p.hdr[(a - h0) as usize..(b - h0) as usize]);
            }
            // data part
            let d0 = h1;
            let d1 = d0 + p.src_len;
            let (a, b) = (d0.max(cs), d1.min(real_end));
            if a < b {
                let src = p.src_off + (a - d0);
                let dst = &mut target[(a - cs) as usize..(b - cs) as usize];
                match window {
                    Some(w) => dst.copy_from_slice(&src_buf[(src - w) as usize..(src - w) as usize + dst.len()]),
                    None => {
                        self.stats.direct_reads.fetch_add(1, Ordering::Relaxed);
                        input.read_exact_at(dst, src)?
                    }
                }
            }
        }
        self.stats.assemble_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);

        let t = Instant::now();
        let d = digest::hash_chunk(alg, &[&target[..real], &ZEROS[..zeros]]).as_ref().to_vec();
        self.stats.hash_ns.fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
        Ok((real, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligning_extra_matches_apksig_rules() {
        // No original extra, extra starts at 41: the 6-byte field ends at 47, one pad byte → 48.
        let e = aligning_extra(&[], 41, 4);
        assert_eq!(e, [0x35, 0xd9, 3, 0, 4, 0, 0]);
        assert_eq!((41 + e.len() as u64) % 4, 0);
        // Already aligned: still gets a minimal 6-byte field... which shifts data by 6 → pad 2.
        let e = aligning_extra(&[], 40, 4);
        assert_eq!(e.len(), 8);
        assert_eq!((40 + e.len() as u64) % 4, 0);
        // Old 0xd935 field and zipalign zero padding are dropped; a foreign field is kept.
        let original = [0x35, 0xd9, 4, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x99, 2, 0, 0xAA, 0xBB, 0, 0];
        let e = aligning_extra(&original, 100, 4096);
        assert_eq!(&e[..6], &[0x01, 0x99, 2, 0, 0xAA, 0xBB]);
        assert_eq!(u16le(&e, 6), ALIGNMENT_EXTRA_ID);
        assert_eq!(u16le(&e, 10), 4096);
        assert_eq!((100 + e.len() as u64) % 4096, 0);
        assert_eq!(declared_alignment(&e), Some(4096));
        assert_eq!(declared_alignment(&original), Some(4));
        assert_eq!(declared_alignment(&[0, 0, 0, 0]), None);
        assert_eq!(declared_alignment(&[0x35, 0xd9, 9, 0, 1]), None, "overrunning field is ignored");
        // A truncated trailing field is dropped, like apksig.
        let e = aligning_extra(&[0x01, 0x99, 9, 0, 1, 2], 0, 4);
        assert_eq!(u16le(&e, 0), ALIGNMENT_EXTRA_ID);
    }

    #[test]
    fn inspector_check_and_rewrite_on_synthetic_zip() {
        use crate::zip::tests::synth_zip;
        use ring::digest::SHA256;
        // synth_zip stores entries with no padding: data offsets are 30+name_len, misaligned
        // for most names.
        let names = ["a.txt", "lib/x/liby.so", "dir/", "bb.bin", "ccc.bin", "stamp-cert-sha256"];
        let z = synth_zip(&names, None, b"");
        let secs = zip::parse(z.as_slice()).unwrap();
        let cd = z[secs.cd_off as usize..(secs.cd_off + secs.cd_size) as usize].to_vec();
        let entries = zip::parse_cd_entries(&cd).unwrap();
        let policy = Policy { lib_page_size: 4096 };

        let insp = LfhInspector::new(&entries, secs.entries_end).unwrap();
        let src = [crate::digest::Source::file(0, secs.entries_end, &[])];
        let f = |o: u64, b: &[u8]| insp.inspect(o, b);
        crate::digest::content_digests(z.as_slice(), &src, &[&SHA256], 2, Some(&f)).unwrap();
        let lens = insp.finish(z.as_slice(), &entries).unwrap();
        assert!(lens.iter().all(|&(nl, el)| el == 0 && nl > 0));

        let bad = check(&cd, &entries, &lens, secs.entries_end, &policy).unwrap();
        // (the check in main runs on Output entries only; here the dir entry is simply not stored-aligned-checked)
        let bad_names: Vec<_> = bad.iter().map(|m| m.name.as_str()).collect();
        assert!(bad_names.contains(&"lib/x/liby.so"));
        assert!(!bad_names.contains(&"dir/"));
        assert_eq!(bad.iter().find(|m| m.name == "lib/x/liby.so").unwrap().required, 4096);

        let tmp = std::env::temp_dir().join(format!("fastsigner-align-test-{}", std::process::id()));
        let out = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&tmp).unwrap();
        let policies: Vec<_> = entries.iter().map(|e| zip::entry_policy(e.name(&cd))).collect();
        let rw = rewrite(z.as_slice(), &cd, &entries, &policies, secs.entries_end, &out, &policy, 3, &SHA256).unwrap();
        assert_eq!(rw.dropped, 2, "directory entry skipped, stamp entry treated as a gap");
        assert_eq!(rw.entries, 4);
        let mut body = vec![0u8; rw.entries_end as usize];
        ReadAt::read_exact_at(&out, &mut body, 0).unwrap();
        std::fs::remove_file(&tmp).ok();
        // The trailing stamp record is copied verbatim as unprocessed bytes, like apksig does.
        let stamp = entries.iter().find(|e| e.name(&cd) == b"stamp-cert-sha256").unwrap();
        let stamp_rec = &z[stamp.lfh_off as usize..secs.entries_end as usize];
        assert!(body.ends_with(stamp_rec));
        // Digests produced while writing must equal the reference engine's over the written
        // bytes plus the zero padding.
        let zeros = vec![0u8; rw.pad as usize];
        let reference = crate::digest::content_digests(body.as_slice(), &[crate::digest::Source::file(0, body.len() as u64, &zeros)], &[&SHA256], 2, None).unwrap();
        assert_eq!(crate::digest::top_digest(&SHA256, rw.chunk_count, &[&rw.chunk_digests]), reference[0]);
        assert_eq!(rw.pad, crate::sigblock::padding_before_block(rw.entries_end));

        // Every surviving entry: header intact, data aligned, data bytes identical to the input.
        let new_entries = zip::parse_cd_entries(&rw.cd).unwrap();
        assert_eq!(new_entries.len(), 4);
        for e in &new_entries {
            let off = e.lfh_off as usize;
            assert_eq!(&body[off..off + 4], &LFH_SIG);
            let nl = u16le(&body, off + 26) as usize;
            let el = u16le(&body, off + 28) as usize;
            let name = &body[off + 30..off + 30 + nl];
            assert_eq!(name, e.name(&rw.cd));
            let data_off = off + 30 + nl + el;
            let req = zip::required_alignment(&rw.cd, e, policy.lib_page_size);
            assert_eq!(data_off % req as usize, 0, "{}", String::from_utf8_lossy(name));
            assert_eq!(declared_alignment(&body[off + 30 + nl..data_off]), Some(req));
            assert_eq!(&body[data_off..data_off + e.compressed_size as usize], name, "synth entries contain their own name");
        }
        // Re-checking the rewritten section finds nothing.
        let lens2: Vec<LfhLens> = new_entries.iter().map(|e| read_lfh_lens(body.as_slice(), e.lfh_off).unwrap()).collect();
        assert!(check(&rw.cd, &new_entries, &lens2, rw.entries_end, &policy).unwrap().is_empty());
    }
}
