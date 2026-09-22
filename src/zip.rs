//! ZIP structure discovery: End of Central Directory, Central Directory, and the
//! APK Signing Block. Only the pieces a v2/v3 signer needs; entry contents are never parsed.

use std::fs::File;
use std::io;

pub const SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const EOCD_SIG: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
const ZIP64_LOCATOR_SIG: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
const CD_ENTRY_SIG: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
pub const LFH_SIG: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
pub const LFH_LEN: usize = 30;
pub const DATA_DESCRIPTOR_SIG: u32 = 0x0807_4b50;
pub const METHOD_STORED: u16 = 0;
pub const FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
const EOCD_MIN_LEN: usize = 22;
const MAX_COMMENT_LEN: usize = 0xffff;

/// Positioned reads. Implemented for `File` (pread) and `[u8]` (tests, in-memory data).
pub trait ReadAt {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<()>;
    fn len(&self) -> io::Result<u64>;
}

impl ReadAt for File {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, off)
    }
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<()> {
        let start = off as usize;
        let end = start.saturating_add(buf.len());
        if end > <[u8]>::len(self) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end of buffer"));
        }
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }
    fn len(&self) -> io::Result<u64> {
        Ok(<[u8]>::len(self) as u64)
    }
}

pub fn u16le(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
pub fn u32le(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}
pub fn u64le(b: &[u8], i: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(a)
}

#[derive(Debug, Clone)]
pub struct ZipSections {
    pub file_len: u64,
    /// End of the ZIP entries section: start of the existing APK Signing Block if there is
    /// one, otherwise the Central Directory offset.
    pub entries_end: u64,
    /// Existing APK Signing Block as (start, total length including both size fields + magic).
    pub sig_block: Option<(u64, u64)>,
    pub cd_off: u64,
    pub cd_size: u64,
    #[allow(dead_code)]
    pub eocd_off: u64,
    /// Full EOCD record including the comment.
    pub eocd: Vec<u8>,
}

/// Find the EOCD record in `tail` (the last bytes of the file). Returns its offset in `tail`.
/// Scans backwards and requires the comment-length field to match the remaining bytes, which
/// is what apksig/libziparchive do.
pub fn find_eocd(tail: &[u8]) -> Option<usize> {
    if tail.len() < EOCD_MIN_LEN {
        return None;
    }
    let max_comment = (tail.len() - EOCD_MIN_LEN).min(MAX_COMMENT_LEN);
    for comment_len in 0..=max_comment {
        let i = tail.len() - EOCD_MIN_LEN - comment_len;
        if tail[i..i + 4] == EOCD_SIG && u16le(tail, i + 20) as usize == comment_len {
            return Some(i);
        }
    }
    None
}

pub fn parse(f: &(impl ReadAt + ?Sized)) -> Result<ZipSections, String> {
    let file_len = f.len().map_err(|e| format!("stat: {e}"))?;
    if file_len < EOCD_MIN_LEN as u64 {
        return Err("file too small to be a ZIP".into());
    }
    let tail_len = file_len.min((EOCD_MIN_LEN + MAX_COMMENT_LEN) as u64);
    let mut tail = vec![0u8; tail_len as usize];
    f.read_exact_at(&mut tail, file_len - tail_len).map_err(|e| format!("read tail: {e}"))?;
    let rel = find_eocd(&tail).ok_or("ZIP End of Central Directory record not found")?;
    let eocd = tail[rel..].to_vec();
    let eocd_off = file_len - tail_len + rel as u64;

    let disk = u16le(&eocd, 4);
    let cd_disk = u16le(&eocd, 6);
    let entries_disk = u16le(&eocd, 8);
    let entries_total = u16le(&eocd, 10);
    let cd_size = u32le(&eocd, 12) as u64;
    let cd_off = u32le(&eocd, 16) as u64;

    if disk != 0 || cd_disk != 0 || entries_disk != entries_total {
        return Err("multi-disk ZIP archives are not supported".into());
    }
    if entries_total == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
        return Err("Zip64 archives are not supported".into());
    }
    if rel >= 20 && tail[rel - 20..rel - 16] == ZIP64_LOCATOR_SIG {
        return Err("Zip64 archives are not supported (zip64 locator present)".into());
    }
    if cd_off + cd_size != eocd_off {
        return Err(format!(
            "ZIP Central Directory is not immediately followed by the EOCD \
             (cd_off={cd_off} cd_size={cd_size} eocd_off={eocd_off})"
        ));
    }

    // Existing APK Signing Block: sits immediately before the CD, ends with u64 size + magic.
    let mut sig_block = None;
    let mut entries_end = cd_off;
    if cd_off >= 32 {
        let mut footer = [0u8; 24];
        f.read_exact_at(&mut footer, cd_off - 24).map_err(|e| format!("read sig block footer: {e}"))?;
        if &footer[8..24] == SIG_BLOCK_MAGIC {
            let size = u64le(&footer, 0);
            if size >= 24 && size + 8 <= cd_off {
                let start = cd_off - size - 8;
                let mut head = [0u8; 8];
                f.read_exact_at(&mut head, start).map_err(|e| format!("read sig block head: {e}"))?;
                if u64le(&head, 0) == size {
                    sig_block = Some((start, size + 8));
                    entries_end = start;
                }
            }
        }
    }

    Ok(ZipSections { file_len, entries_end, sig_block, cd_off, cd_size, eocd_off, eocd })
}

pub fn set_eocd_cd_offset(eocd: &mut [u8], off: u32) {
    eocd[16..20].copy_from_slice(&off.to_le_bytes());
}
pub fn set_eocd_cd_size(eocd: &mut [u8], size: u32) {
    eocd[12..16].copy_from_slice(&size.to_le_bytes());
}
pub fn set_eocd_entry_count(eocd: &mut [u8], n: u16) {
    eocd[8..10].copy_from_slice(&n.to_le_bytes());
    eocd[10..12].copy_from_slice(&n.to_le_bytes());
}

/// v1 (JAR) signature files directly under `META-INF/`, case-insensitive file name (apksig's
/// `isJarEntryDigestNeededInManifest == false` for non-directories).
pub fn is_v1_signature_entry(name: &[u8]) -> bool {
    let Some(rest) = name.strip_prefix(b"META-INF/") else { return false };
    if rest.contains(&b'/') {
        return false;
    }
    let lower: Vec<u8> = rest.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower == b"manifest.mf"
        || lower.ends_with(b".sf")
        || lower.ends_with(b".rsa")
        || lower.ends_with(b".dsa")
        || lower.ends_with(b".ec")
        || lower.starts_with(b"sig-")
}

/// One Central Directory record, referenced by byte ranges into the CD buffer.
#[derive(Debug, Clone)]
pub struct CdEntry {
    pub record: std::ops::Range<usize>,
    pub name: std::ops::Range<usize>,
    pub lfh_off: u64,
    pub method: u16,
    pub flags: u16,
    pub compressed_size: u64,
}

impl CdEntry {
    pub fn name<'a>(&self, cd: &'a [u8]) -> &'a [u8] {
        &cd[self.name.clone()]
    }
    pub fn is_dir(&self, cd: &[u8]) -> bool {
        self.name(cd).ends_with(b"/")
    }
    pub fn is_stored(&self) -> bool {
        self.method == METHOD_STORED
    }
    pub fn has_data_descriptor(&self) -> bool {
        self.flags & FLAG_DATA_DESCRIPTOR != 0
    }
}

pub fn parse_cd_entries(cd: &[u8]) -> Result<Vec<CdEntry>, String> {
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < cd.len() {
        if p + 46 > cd.len() || cd[p..p + 4] != CD_ENTRY_SIG {
            return Err(format!("malformed Central Directory entry at offset {p}"));
        }
        let name_len = u16le(cd, p + 28) as usize;
        let extra_len = u16le(cd, p + 30) as usize;
        let comment_len = u16le(cd, p + 32) as usize;
        let total = 46 + name_len + extra_len + comment_len;
        if p + total > cd.len() {
            return Err(format!("Central Directory entry at offset {p} overruns the directory"));
        }
        out.push(CdEntry {
            record: p..p + total,
            name: p + 46..p + 46 + name_len,
            lfh_off: u32le(cd, p + 42) as u64,
            method: u16le(cd, p + 10),
            flags: u16le(cd, p + 8),
            compressed_size: u32le(cd, p + 20) as u64,
        });
        p += total;
    }
    Ok(out)
}

/// zipalign's rule: uncompressed non-directory entries need 4-byte aligned data, and `.so`
/// files a page (`lib_page_size` bytes, 0 disables). Returns 1 when no alignment applies.
pub fn required_alignment(cd: &[u8], e: &CdEntry, lib_page_size: u32) -> u32 {
    if !e.is_stored() || e.is_dir(cd) {
        return 1;
    }
    if lib_page_size > 4 && e.name(cd).ends_with(b".so") {
        lib_page_size
    } else {
        4
    }
}

/// What apksigner does with an input entry when re-signing (`ApkSigner.sign`, step 3):
/// `Output` is copied (re-aligned if stored), `Skip` is dropped (v1 signature files and
/// directory entries), `Gap` is dropped from the Central Directory but its local record is left
/// where it was, as unprocessed bytes (the source stamp hash and the pin list, which apksig
/// regenerates rather than copies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPolicy {
    Output,
    Skip,
    Gap,
}

pub fn entry_policy(name: &[u8]) -> EntryPolicy {
    if name == b"stamp-cert-sha256" || name == b"pinlist.meta" {
        EntryPolicy::Gap
    } else if name.ends_with(b"/") || is_v1_signature_entry(name) {
        EntryPolicy::Skip
    } else {
        EntryPolicy::Output
    }
}

pub struct FilteredCd {
    /// Central Directory holding only `Output` entries.
    pub bytes: Vec<u8>,
    pub entries: u64,
    pub removed: Vec<String>,
    /// Every record of the original Central Directory, with its policy.
    pub all: Vec<CdEntry>,
    pub policies: Vec<EntryPolicy>,
}

/// Apply `entry_policy` to a Central Directory. The local file data of dropped entries is
/// left in place (orphaned) unless the entries section is rewritten for alignment — readers
/// only follow the Central Directory, and apksigner leaves such orphans too.
pub fn filter_cd(cd: &[u8]) -> Result<FilteredCd, String> {
    let all = parse_cd_entries(cd)?;
    let mut out = Vec::with_capacity(cd.len());
    let mut removed = Vec::new();
    let mut entries = 0u64;
    let mut policies = Vec::with_capacity(all.len());
    for e in &all {
        let name = e.name(cd);
        let policy = entry_policy(name);
        policies.push(policy);
        if policy == EntryPolicy::Output {
            out.extend_from_slice(&cd[e.record.clone()]);
            entries += 1;
        } else {
            removed.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    Ok(FilteredCd { bytes: out, entries, removed, all, policies })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a minimal valid ZIP: stored entries, optional APK signing block, optional comment.
    pub fn synth_zip(names: &[&str], sig_block: Option<&[u8]>, comment: &[u8]) -> Vec<u8> {
        let mut z = Vec::new();
        let mut cd = Vec::new();
        for name in names {
            let data = name.as_bytes();
            let lho = z.len() as u32;
            z.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
            z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method, time, date
            z.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked here)
            z.extend_from_slice(&(data.len() as u32).to_le_bytes());
            z.extend_from_slice(&(data.len() as u32).to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(name.as_bytes());
            z.extend_from_slice(data);

            cd.extend_from_slice(&CD_ENTRY_SIG);
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            cd.extend_from_slice(&0u32.to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // extra, comment, disk, int attrs
            cd.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
            cd.extend_from_slice(&lho.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        if let Some(b) = sig_block {
            z.extend_from_slice(b);
        }
        let cd_off = z.len() as u32;
        z.extend_from_slice(&cd);
        z.extend_from_slice(&EOCD_SIG);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&(names.len() as u16).to_le_bytes());
        z.extend_from_slice(&(names.len() as u16).to_le_bytes());
        z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        z.extend_from_slice(comment);
        z
    }

    pub fn fake_sig_block(payload_len: usize) -> Vec<u8> {
        let size = (payload_len + 8 + 16) as u64;
        let mut b = Vec::new();
        b.extend_from_slice(&size.to_le_bytes());
        b.extend(std::iter::repeat(0xEEu8).take(payload_len));
        b.extend_from_slice(&size.to_le_bytes());
        b.extend_from_slice(SIG_BLOCK_MAGIC);
        b
    }

    #[test]
    fn finds_eocd_without_comment() {
        let z = synth_zip(&["a.txt"], None, b"");
        let s = parse(z.as_slice()).unwrap();
        assert_eq!(s.eocd_off, z.len() as u64 - 22);
        assert_eq!(s.cd_off + s.cd_size, s.eocd_off);
        assert_eq!(s.entries_end, s.cd_off);
        assert!(s.sig_block.is_none());
        assert_eq!(s.eocd.len(), 22);
    }

    #[test]
    fn finds_eocd_with_comment_containing_fake_signature() {
        // Comment contains bytes that look like an EOCD signature; the comment-length check
        // must reject the decoy.
        let mut comment = b"hello PK\x05\x06 world".to_vec();
        comment.extend_from_slice(&[0u8; 30]);
        let z = synth_zip(&["a.txt", "b/c.txt"], None, &comment);
        let s = parse(z.as_slice()).unwrap();
        assert_eq!(s.eocd.len(), 22 + comment.len());
        assert_eq!(s.cd_off + s.cd_size, s.eocd_off);
    }

    #[test]
    fn detects_existing_signing_block() {
        let blk = fake_sig_block(100);
        let z = synth_zip(&["a.txt"], Some(&blk), b"");
        let s = parse(z.as_slice()).unwrap();
        let (start, len) = s.sig_block.expect("sig block");
        assert_eq!(len, blk.len() as u64);
        assert_eq!(start + len, s.cd_off);
        assert_eq!(s.entries_end, start);
    }

    #[test]
    fn rejects_truncated_and_zip64() {
        assert!(parse(&b"PK"[..]).is_err());
        let mut z = synth_zip(&["a.txt"], None, b"");
        let n = z.len();
        z[n - 22 + 16..n - 22 + 20].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(parse(z.as_slice()).unwrap_err().contains("Zip64"));
    }

    #[test]
    fn v1_entry_classification() {
        assert!(is_v1_signature_entry(b"META-INF/MANIFEST.MF"));
        assert!(is_v1_signature_entry(b"META-INF/CERT.SF"));
        assert!(is_v1_signature_entry(b"META-INF/cert.rsa"));
        assert!(is_v1_signature_entry(b"META-INF/KEY.DSA"));
        assert!(is_v1_signature_entry(b"META-INF/KEY.EC"));
        assert!(is_v1_signature_entry(b"META-INF/SIG-FOO"));
        assert!(!is_v1_signature_entry(b"stamp-cert-sha256"));
        assert_eq!(entry_policy(b"stamp-cert-sha256"), EntryPolicy::Gap);
        assert_eq!(entry_policy(b"pinlist.meta"), EntryPolicy::Gap);
        assert_eq!(entry_policy(b"META-INF/stamp-cert-sha256"), EntryPolicy::Output);
        assert_eq!(entry_policy(b"assets/"), EntryPolicy::Skip);
        assert_eq!(entry_policy(b"META-INF/CERT.RSA"), EntryPolicy::Skip);
        assert_eq!(entry_policy(b"classes.dex"), EntryPolicy::Output);
        assert!(!is_v1_signature_entry(b"META-INF/services/x"));
        assert!(!is_v1_signature_entry(b"META-INF/com/android/build/gradle/app-metadata.properties"));
        assert!(!is_v1_signature_entry(b"META-INF/version-control-info.textproto"));
        assert!(!is_v1_signature_entry(b"classes.dex"));
        assert!(!is_v1_signature_entry(b"meta-inf/MANIFEST.MF"));
    }

    #[test]
    fn cd_entries_and_alignment_rule() {
        let z = synth_zip(&["classes.dex", "lib/arm64-v8a/libx.so", "assets/", "res/a.png"], None, b"");
        let s = parse(z.as_slice()).unwrap();
        let cd = &z[s.cd_off as usize..(s.cd_off + s.cd_size) as usize];
        let es = parse_cd_entries(cd).unwrap();
        assert_eq!(es.len(), 4);
        assert_eq!(es[0].name(cd), b"classes.dex");
        assert!(es[0].is_stored() && !es[0].has_data_descriptor());
        assert_eq!(es[0].lfh_off, 0);
        assert!(es[1].lfh_off > 0);
        assert!(es[2].is_dir(cd));
        assert_eq!(required_alignment(cd, &es[0], 16384), 4);
        assert_eq!(required_alignment(cd, &es[1], 16384), 16384);
        assert_eq!(required_alignment(cd, &es[1], 4096), 4096);
        assert_eq!(required_alignment(cd, &es[1], 0), 4);
        assert_eq!(required_alignment(cd, &es[2], 16384), 1, "directories are never aligned");
        let mut compressed = es[3].clone();
        compressed.method = 8;
        assert_eq!(required_alignment(cd, &compressed, 16384), 1);
        assert!(parse_cd_entries(&cd[..cd.len() - 1]).is_err());
    }

    #[test]
    fn filters_cd_like_apksigner() {
        let z = synth_zip(&["classes.dex", "META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA", "res/", "stamp-cert-sha256", "res/x"], None, b"");
        let s = parse(z.as_slice()).unwrap();
        let cd = &z[s.cd_off as usize..(s.cd_off + s.cd_size) as usize];
        let f = filter_cd(cd).unwrap();
        assert_eq!(f.entries, 2);
        assert_eq!(f.removed, vec!["META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA", "res/", "stamp-cert-sha256"]);
        assert_eq!(f.all.len(), 7);
        assert_eq!(f.policies, [EntryPolicy::Output, EntryPolicy::Skip, EntryPolicy::Skip, EntryPolicy::Skip, EntryPolicy::Skip, EntryPolicy::Gap, EntryPolicy::Output]);
        // The filtered CD must itself parse cleanly and keep the survivors in order.
        let g = filter_cd(&f.bytes).unwrap();
        assert_eq!(g.entries, 2);
        assert!(g.removed.is_empty());
        assert_eq!(g.bytes, f.bytes);
    }
}
