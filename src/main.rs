//! fastsigner — a fast native `apksigner sign` replacement for APK Signature Scheme v2 + v3.
//!
//! Per APK: locate ZIP sections → strip stale v1 entries from the CD → pad entries to 4 KiB →
//! parallel chunked digest → build v2/v3 blocks → APK Signing Block → splice the tail.
//! Several APKs can be signed concurrently with one shared key.

mod align;
mod digest;
mod jks;
mod keys;
mod pkcs12;
mod sigblock;
mod zip;

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, Write};
use std::os::raw::{c_char, c_int, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use digest::Source;
use keys::Signer;
use sigblock::{SignerInput, V2_BLOCK_ID, V3_BLOCK_ID, V3_MAX_SDK, V3_MIN_SDK};

const USAGE: &str = "\
fastsigner — fast APK signer (APK Signature Scheme v2 + v3)

USAGE:
    fastsigner [sign] (--key <key> --cert <cert> | --ks <keystore> --ks-pass <src>) [OPTIONS] <apk>...

KEY MATERIAL:
    --key <file>                  Private key: PKCS#8 DER/PEM (RSA or EC P-256), PKCS#1 RSA, SEC1 EC
    --cert <file>                 X.509 certificate (chain), PEM or DER
    --ks <file>                   Keystore: JKS, or PKCS#12 with PBES2/AES (JDK 12+ keytool, OpenSSL 3)
    --ks-pass <src>               Keystore password: pass:<pw> | env:<VAR> | file:<path> | stdin
    --ks-key-alias <alias>        Key alias (optional when the store has exactly one key)
    --key-pass <src>              Key password (default: same as --ks-pass)
    --ks-type <type>              JKS or PKCS12 (the format is detected from the file either way)

OUTPUT:
    (none)                        Sign every input in place (only the tail of the file is rewritten)
    --out <file>                  Write the signed APK here (single input only)
    --out-dir <dir>               Write <dir>/<input file name> for every input

OPTIONS:
    --zipalign [true|false|always] Default true: check 4-byte alignment of stored entries and page
                                  alignment of .so files; rewrite the entries only if misaligned.
                                  `always` rewrites unconditionally (apksigner-style normalisation)
    --lib-page-size <KiB>         Page size for .so alignment, default 16 (zipalign -P 16); 0 = off
    --v2-signing-enabled [bool]   Default true
    --v3-signing-enabled [bool]   Default true
    --v1-signing-enabled [bool]   Default false. `true` is NOT IMPLEMENTED and exits with an error
    --min-sdk-version <n>         Accepted for apksigner compatibility; unused by v2/v3 signing
    --jobs <n>, -j <n>            APKs signed concurrently (default: min(inputs, physical cores))
    --threads <n>                 Digest threads per APK (default: physical cores / jobs)
    --timing                      Print per-phase timings to stderr
    -h, --help                    This text
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum ZipAlign {
    Off,
    Check,
    Always,
}

#[derive(Clone, Copy)]
struct Opts {
    v2: bool,
    v3: bool,
    timing: bool,
    zipalign: ZipAlign,
    lib_page_size: u32,
}

enum KeySource {
    Files { key: PathBuf, cert: PathBuf },
    Keystore { ks: PathBuf, ks_pass: Option<String>, alias: Option<String>, key_pass: Option<String> },
}

struct Args {
    inputs: Vec<PathBuf>,
    out: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    keysrc: KeySource,
    v1: bool,
    jobs: Option<usize>,
    threads: Option<usize>,
    opts: Opts,
}

fn parse_bool(next: Option<&String>) -> (bool, bool) {
    match next.map(|s| s.as_str()) {
        Some("true") => (true, true),
        Some("false") => (false, true),
        _ => (true, false),
    }
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut inputs = Vec::new();
    let (mut out, mut out_dir, mut key, mut cert, mut ks) = (None, None, None, None, None);
    let (mut ks_pass, mut alias, mut key_pass) = (None, None, None);
    let (mut v1, mut v2, mut v3) = (false, true, true);
    let (mut jobs, mut threads) = (None, None);
    let mut timing = false;
    let mut zipalign = ZipAlign::Check;
    let mut lib_page_size: u32 = 16 << 10;
    let mut i = 0;
    let value = |i: &mut usize, name: &str| -> Result<String, String> {
        *i += 1;
        argv.get(*i).cloned().ok_or_else(|| format!("{name} requires a value"))
    };
    let num = |s: String, name: &str| -> Result<usize, String> {
        s.parse::<usize>().ok().filter(|&n| n > 0).ok_or_else(|| format!("{name} must be a positive number"))
    };
    while i < argv.len() {
        let a = argv[i].as_str();
        match a {
            "sign" if i == 0 => {}
            "-h" | "--help" => {
                print!("{USAGE}");
                exit(0);
            }
            "--key" => key = Some(PathBuf::from(value(&mut i, a)?)),
            "--cert" => cert = Some(PathBuf::from(value(&mut i, a)?)),
            "--ks" => ks = Some(PathBuf::from(value(&mut i, a)?)),
            "--ks-pass" => ks_pass = Some(value(&mut i, a)?),
            "--ks-key-alias" => alias = Some(value(&mut i, a)?),
            "--key-pass" => key_pass = Some(value(&mut i, a)?),
            "--ks-type" => {
                let t = value(&mut i, a)?;
                if !t.eq_ignore_ascii_case("jks") && !t.eq_ignore_ascii_case("pkcs12") {
                    return Err(format!("--ks-type {t}: only JKS and PKCS12 keystores are supported"));
                }
            }
            "--out" => out = Some(PathBuf::from(value(&mut i, a)?)),
            "--out-dir" => out_dir = Some(PathBuf::from(value(&mut i, a)?)),
            "--jobs" | "-j" => jobs = Some(num(value(&mut i, a)?, a)?),
            "--threads" => threads = Some(num(value(&mut i, a)?, a)?),
            "--min-sdk-version" => {
                value(&mut i, a)?.parse::<u32>().map_err(|_| "--min-sdk-version must be a number")?;
            }
            "--timing" => timing = true,
            "--zipalign" => {
                if argv.get(i + 1).map(|s| s.as_str()) == Some("always") {
                    i += 1;
                    zipalign = ZipAlign::Always;
                } else {
                    let (b, consumed) = parse_bool(argv.get(i + 1));
                    if consumed {
                        i += 1;
                    }
                    zipalign = if b { ZipAlign::Check } else { ZipAlign::Off };
                }
            }
            "--lib-page-size" => {
                let kib: u32 = value(&mut i, a)?.parse().map_err(|_| "--lib-page-size must be a number of KiB (0, 4, 16, 64)")?;
                if kib != 0 && !kib.is_power_of_two() || kib > 64 {
                    return Err("--lib-page-size must be 0 or a power of two up to 64 (KiB)".into());
                }
                lib_page_size = kib << 10;
            }
            "--v1-signing-enabled" | "--v2-signing-enabled" | "--v3-signing-enabled" => {
                let (b, consumed) = parse_bool(argv.get(i + 1));
                if consumed {
                    i += 1;
                }
                match a {
                    "--v1-signing-enabled" => v1 = b,
                    "--v2-signing-enabled" => v2 = b,
                    _ => v3 = b,
                }
            }
            _ if a.starts_with('-') => return Err(format!("unknown option {a}\n\n{USAGE}")),
            _ => inputs.push(PathBuf::from(a)),
        }
        i += 1;
    }
    if inputs.is_empty() {
        return Err(format!("missing input APK\n\n{USAGE}"));
    }
    let keysrc = match (key, cert, ks) {
        (Some(key), Some(cert), None) => KeySource::Files { key, cert },
        (None, None, Some(ks)) => KeySource::Keystore { ks, ks_pass, alias, key_pass },
        (None, None, None) => return Err("key material required: --key <file> --cert <file>, or --ks <keystore>".into()),
        (Some(_), None, None) | (None, Some(_), None) => return Err("--key and --cert must be given together".into()),
        _ => return Err("use either --key/--cert or --ks, not both".into()),
    };
    if out.is_some() && inputs.len() > 1 {
        return Err("--out works with a single input; use --out-dir for several APKs".into());
    }
    if out.is_some() && out_dir.is_some() {
        return Err("--out and --out-dir are mutually exclusive".into());
    }
    Ok(Args { inputs, out, out_dir, keysrc, v1, jobs, threads, opts: Opts { v2, v3, timing, zipalign, lib_page_size } })
}

/// apksigner password sources: pass:<pw>, env:<VAR>, file:<path> (first line), stdin.
fn resolve_password(spec: &str, what: &str) -> Result<String, String> {
    if let Some(p) = spec.strip_prefix("pass:") {
        Ok(p.to_string())
    } else if let Some(var) = spec.strip_prefix("env:") {
        std::env::var(var).map_err(|_| format!("{what}: environment variable {var} is not set"))
    } else if let Some(path) = spec.strip_prefix("file:") {
        let f = File::open(path).map_err(|e| format!("{what}: {path}: {e}"))?;
        let mut line = String::new();
        io::BufReader::new(f).read_line(&mut line).map_err(|e| format!("{what}: {path}: {e}"))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    } else if spec == "stdin" {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).map_err(|e| format!("{what}: stdin: {e}"))?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    } else {
        Err(format!("{what}: expected pass:<password>, env:<VAR>, file:<path> or stdin"))
    }
}

fn load_signer(src: &KeySource) -> Result<Signer, String> {
    match src {
        KeySource::Files { key, cert } => Signer::load_files(key, cert),
        KeySource::Keystore { ks, ks_pass, alias, key_pass } => {
            let store_pw = match ks_pass {
                Some(s) => resolve_password(s, "--ks-pass")?,
                None => return Err("--ks-pass is required with --ks (pass:<pw>, env:<VAR>, file:<path> or stdin)".into()),
            };
            let key_pw = match key_pass {
                Some(s) => resolve_password(s, "--key-pass")?,
                None => store_pw.clone(),
            };
            Signer::load_keystore(ks, &store_pw, alias.as_deref(), &key_pw)
        }
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Output path for every input: `None` means in place.
fn plan_outputs(args: &Args) -> Result<Vec<Option<PathBuf>>, String> {
    if let Some(out) = &args.out {
        return Ok(vec![Some(out.clone()).filter(|o| !same_file(o, &args.inputs[0]))]);
    }
    let Some(dir) = &args.out_dir else {
        return Ok(vec![None; args.inputs.len()]);
    };
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut outs = Vec::with_capacity(args.inputs.len());
    let mut seen: Vec<PathBuf> = Vec::new();
    for input in &args.inputs {
        let name = input.file_name().ok_or_else(|| format!("{}: not a file name", input.display()))?;
        let out = dir.join(name);
        if seen.contains(&out) {
            return Err(format!("two inputs would both be written to {}", out.display()));
        }
        seen.push(out.clone());
        outs.push(Some(out).filter(|o| !same_file(o, input)));
    }
    Ok(outs)
}

struct Timings {
    t0: Instant,
    marks: Vec<(&'static str, Instant)>,
}

impl Timings {
    fn mark(&mut self, name: &'static str) {
        self.marks.push((name, Instant::now()));
    }
    fn render(&self) -> String {
        let mut s = String::new();
        let mut prev = self.t0;
        for (name, t) in &self.marks {
            s += &format!("  {name:<10} {:8.3} ms\n", (*t - prev).as_secs_f64() * 1e3);
            prev = *t;
        }
        s + &format!("  {:<10} {:8.3} ms\n", "total", (prev - self.t0).as_secs_f64() * 1e3)
    }
}

/// A file created for output that is removed on drop unless committed.
struct TempFile {
    path: Option<PathBuf>,
}

extern "C" {
    fn renameat2(olddirfd: c_int, oldpath: *const c_char, newdirfd: c_int, newpath: *const c_char, flags: c_uint) -> c_int;
}
const AT_FDCWD: c_int = -100;
const RENAME_EXCHANGE: c_uint = 2;

/// Replace `dest` with `temp`. Swapping the two names atomically and unlinking the old content
/// avoids ext4's replace-via-rename data flush (`auto_da_alloc`), which costs ~30 ms for a
/// freshly written 145 MB file; a plain rename is the fallback.
fn replace_file(temp: &Path, dest: &Path) -> io::Result<()> {
    let (a, b) = (CString::new(temp.as_os_str().as_bytes())?, CString::new(dest.as_os_str().as_bytes())?);
    // SAFETY: both pointers are valid NUL-terminated paths for the duration of the call.
    if unsafe { renameat2(AT_FDCWD, a.as_ptr(), AT_FDCWD, b.as_ptr(), RENAME_EXCHANGE) } == 0 {
        std::fs::remove_file(temp)
    } else {
        std::fs::rename(temp, dest)
    }
}

impl TempFile {
    fn commit(mut self, dest: &Path) -> Result<(), String> {
        let p = self.path.take().unwrap();
        replace_file(&p, dest).map_err(|e| {
            std::fs::remove_file(&p).ok();
            format!("replace {} with {}: {e}", dest.display(), p.display())
        })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(p) = &self.path {
            std::fs::remove_file(p).ok();
        }
    }
}

fn open_rw_truncate(path: &Path) -> Result<File, String> {
    OpenOptions::new().read(true).write(true).create(true).truncate(true).open(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// EOCD with entry count / CD size patched (CD offset still to be set), the EOCD variant used
/// for digesting (CD offset = signing block start), the padding before the block and the block
/// start, for a given entries section length.
fn layout(entries_end: u64, cd_len: usize, eocd_template: &[u8], entry_count: u64) -> (Vec<u8>, Vec<u8>, u64, u64) {
    let pad = sigblock::padding_before_block(entries_end);
    let block_start = entries_end + pad;
    let mut eocd = eocd_template.to_vec();
    zip::set_eocd_entry_count(&mut eocd, entry_count as u16);
    zip::set_eocd_cd_size(&mut eocd, cd_len as u32);
    let mut eocd_for_digest = eocd.clone();
    zip::set_eocd_cd_offset(&mut eocd_for_digest, block_start as u32);
    (eocd, eocd_for_digest, pad, block_start)
}

/// Fast path: digest the APK as it would look with the signing block spliced in, straight from
/// the input file. Returns (content digest, patched EOCD, padding, block start).
fn digest_layout(
    file: &File,
    entries_end: u64,
    cd: &[u8],
    eocd_template: &[u8],
    entry_count: u64,
    signer: &Signer,
    threads: usize,
    inspect: Option<&(dyn Fn(u64, &[u8]) + Sync)>,
) -> Result<(Vec<u8>, Vec<u8>, u64, u64), String> {
    let (eocd, eocd_for_digest, pad, block_start) = layout(entries_end, cd.len(), eocd_template, entry_count);
    let zeros = vec![0u8; pad as usize];
    let sources = [Source::file(0, entries_end, &zeros), Source::bytes(cd), Source::bytes(&eocd_for_digest)];
    let digests = digest::content_digests(file, &sources, &[signer.content_digest], threads, inspect).map_err(|e| format!("digest: {e}"))?;
    Ok((digests.into_iter().next().unwrap(), eocd, pad, block_start))
}

/// Rewrite path: the entries section was digested while it was written; only the (in-memory)
/// central directory and EOCD chunks remain.
fn finish_rewritten_digest(rw: &align::Rewritten, eocd_template: &[u8], signer: &Signer) -> (Vec<u8>, Vec<u8>, u64, u64) {
    let (eocd, eocd_for_digest, pad, block_start) = layout(rw.entries_end, rw.cd.len(), eocd_template, rw.entries);
    debug_assert_eq!(pad, rw.pad);
    let alg = signer.content_digest;
    let (n_cd, d_cd) = digest::chunk_digests_of(alg, &rw.cd);
    let (n_eocd, d_eocd) = digest::chunk_digests_of(alg, &eocd_for_digest);
    let digest = digest::top_digest(alg, rw.chunk_count + n_cd + n_eocd, &[&rw.chunk_digests, &d_cd, &d_eocd]);
    (digest, eocd, pad, block_start)
}

/// Sign one APK. Returns the `--timing` report (empty unless enabled).
fn sign_one(input: &Path, output: Option<&Path>, signer: &Signer, threads: usize, opts: Opts) -> Result<String, String> {
    let mut tm = Timings { t0: Instant::now(), marks: Vec::new() };
    let in_place = output.is_none();
    let file = if in_place {
        OpenOptions::new().read(true).write(true).open(input)
    } else {
        File::open(input)
    }
    .map_err(|e| e.to_string())?;

    // --- ZIP structure ---------------------------------------------------------------------
    let sections = zip::parse(&file)?;
    let mut cd_full = vec![0u8; sections.cd_size as usize];
    file.read_exact_at(&mut cd_full, sections.cd_off).map_err(|e| format!("read central directory: {e}"))?;
    let filtered = zip::filter_cd(&cd_full)?;
    let mut cd = filtered.bytes;
    let mut entry_count = filtered.entries;
    let mut entries_end = sections.entries_end;
    let policy = align::Policy { lib_page_size: opts.lib_page_size };
    let entries = if opts.zipalign == ZipAlign::Check { Some(zip::parse_cd_entries(&cd)?) } else { None };
    let inspector = match &entries {
        Some(es) => Some(align::LfhInspector::new(es, entries_end)?),
        None => None,
    };
    tm.mark("parse");

    // Output file for a rewritten entries section: the --out path, or a temp swapped in later.
    let open_dest = || -> Result<(File, Option<TempFile>), String> {
        match output {
            Some(p) => Ok((open_rw_truncate(p)?, None)),
            None => {
                let name = input.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let tmp_path = input.with_file_name(format!(".{name}.fastsigner-tmp"));
                let f = open_rw_truncate(&tmp_path)?;
                Ok((f, Some(TempFile { path: Some(tmp_path) })))
            }
        }
    };
    let mut rewritten: Option<(File, Option<TempFile>)> = None;
    let mut align_note = match opts.zipalign {
        ZipAlign::Off => "not checked".to_string(),
        ZipAlign::Check => "aligned".to_string(),
        ZipAlign::Always => String::new(),
    };

    // --- content digest (pass 1, with the alignment inspector riding along) ---------------
    let (mut content_digest, mut eocd, mut pad, mut block_start);
    if opts.zipalign == ZipAlign::Always {
        let (dest, temp) = open_dest()?;
        let rw = align::rewrite(&file, &cd_full, &filtered.all, &filtered.policies, entries_end, &dest, &policy, threads, signer.content_digest)?;
        (content_digest, eocd, pad, block_start) = finish_rewritten_digest(&rw, &sections.eocd, signer);
        cd = rw.cd;
        entry_count = rw.entries;
        entries_end = rw.entries_end;
        align_note = format!("rewritten unconditionally ({} entries dropped; {})", rw.dropped, rw.stats);
        rewritten = Some((dest, temp));
        tm.mark("digest");
    } else if entries.as_ref().map_or(Ok(false), |es| align::quick_misaligned(&file, &cd, es, entries_end, &policy, 16))? {
        // Proven misaligned by a handful of header reads: skip digesting the old layout.
        drop(inspector);
        let (dest, temp) = open_dest()?;
        let rw = align::rewrite(&file, &cd_full, &filtered.all, &filtered.policies, entries_end, &dest, &policy, threads, signer.content_digest)?;
        (content_digest, eocd, pad, block_start) = finish_rewritten_digest(&rw, &sections.eocd, signer);
        cd = rw.cd;
        entry_count = rw.entries;
        entries_end = rw.entries_end;
        align_note = format!("realigned (misaligned within the first stored entries; {} entries dropped; {})", rw.dropped, rw.stats);
        rewritten = Some((dest, temp));
        tm.mark("digest");
    } else {
        let inspect_fn = inspector.as_ref().map(|i| move |o: u64, b: &[u8]| i.inspect(o, b));
        (content_digest, eocd, pad, block_start) = digest_layout(
            &file,
            entries_end,
            &cd,
            &sections.eocd,
            entry_count,
            signer,
            threads,
            inspect_fn.as_ref().map(|f| f as &(dyn Fn(u64, &[u8]) + Sync)),
        )?;
        tm.mark("digest");

        // --- zipalign: check, and rewrite + re-digest only when needed ----------------------
        if let (Some(es), Some(insp)) = (&entries, inspector) {
            let lens = insp.finish(&file, es)?;
            let bad = align::check(&cd, es, &lens, entries_end, &policy)?;
            if !bad.is_empty() {
                let (dest, temp) = open_dest()?;
                let rw = align::rewrite(&file, &cd_full, &filtered.all, &filtered.policies, entries_end, &dest, &policy, threads, signer.content_digest)?;
                (content_digest, eocd, pad, block_start) = finish_rewritten_digest(&rw, &sections.eocd, signer);
                cd = rw.cd;
                entry_count = rw.entries;
                entries_end = rw.entries_end;
                align_note = format!(
                    "realigned ({} misaligned, e.g. {:?} data at {} needs {}; {} entries dropped; {})",
                    bad.len(),
                    bad[0].name,
                    bad[0].data_off,
                    bad[0].required,
                    rw.dropped,
                    rw.stats
                );
                rewritten = Some((dest, temp));
            }
        }
    }
    tm.mark("align");

    // --- signature blocks ------------------------------------------------------------------
    let inp = SignerInput { alg_id: signer.alg_id, digest: &content_digest, certs: &signer.certs, spki: &signer.spki };
    // v2 and v3 are independent signatures (each ~0.35 ms for RSA-2048); overlap them.
    let (v2_block, v3_block) = std::thread::scope(|s| {
        let v3 = opts.v3.then(|| s.spawn(|| sigblock::v3_signer(&inp, V3_MIN_SDK, V3_MAX_SDK, |d| signer.sign(d))));
        let v2 = opts.v2.then(|| sigblock::v2_signer(&inp, opts.v3, |d| signer.sign(d)));
        (v2, v3.map(|h| h.join().expect("v3 signer panicked")))
    });
    let mut pairs: Vec<(u32, Vec<u8>)> = Vec::new();
    if let Some(b) = v2_block {
        pairs.push((V2_BLOCK_ID, sigblock::scheme_block(&[b?])));
    }
    if let Some(b) = v3_block {
        pairs.push((V3_BLOCK_ID, sigblock::scheme_block(&[b?])));
    }
    let block = sigblock::apk_signing_block(&pairs);
    let new_cd_off = block_start + block.len() as u64;
    if new_cd_off > u32::MAX as u64 {
        return Err("output would exceed 4 GiB (Zip64 not supported)".into());
    }
    zip::set_eocd_cd_offset(&mut eocd, new_cd_off as u32);
    tm.mark("sign");

    // --- write -----------------------------------------------------------------------------
    let mut tail = Vec::with_capacity(pad as usize + block.len() + cd.len() + eocd.len());
    tail.resize(pad as usize, 0);
    tail.extend_from_slice(&block);
    tail.extend_from_slice(&cd);
    tail.extend_from_slice(&eocd);
    let new_len = entries_end + tail.len() as u64;

    match (&rewritten, output) {
        (Some((dest, _)), _) => {
            dest.write_all_at(&tail, entries_end).map_err(|e| format!("write: {e}"))?;
            dest.set_len(new_len).map_err(|e| format!("truncate: {e}"))?;
        }
        (None, None) => {
            file.write_all_at(&tail, entries_end).map_err(|e| format!("write: {e}"))?;
            file.set_len(new_len).map_err(|e| format!("truncate: {e}"))?;
        }
        (None, Some(out_path)) => {
            let mut out = File::create(out_path).map_err(|e| format!("{}: {e}", out_path.display()))?;
            let mut head = (&file).take(entries_end);
            let copied = io::copy(&mut head, &mut out).map_err(|e| format!("copy: {e}"))?;
            if copied != entries_end {
                return Err(format!("short copy: {copied} of {entries_end} bytes"));
            }
            out.seek(io::SeekFrom::Start(entries_end)).map_err(|e| e.to_string())?;
            out.write_all(&tail).map_err(|e| format!("write: {e}"))?;
        }
    }
    if let Some((dest, Some(temp))) = rewritten {
        drop(dest);
        temp.commit(input)?;
    }
    tm.mark("write");

    if !opts.timing {
        return Ok(String::new());
    }
    Ok(format!(
        "fastsigner: {} ({} B{}) | {} | entries_end={} pad={} block={} B cd={} B ({} entries, {} stale entries removed) | zipalign: {} | {} threads | wrote {} B{}\n{}",
        input.display(),
        sections.file_len,
        match sections.sig_block {
            Some((s, l)) => format!(", old signing block {l} B @ {s}"),
            None => String::new(),
        },
        signer.description,
        entries_end,
        pad,
        block.len(),
        cd.len(),
        entry_count,
        filtered.removed.len(),
        align_note,
        threads,
        tail.len(),
        match output {
            None => " in place".to_string(),
            Some(o) => format!(" to {}", o.display()),
        },
        tm.render(),
    ))
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let t0 = Instant::now();
    if args.v1 {
        return Err("v1 (JAR) signing is not implemented. Run with --v1-signing-enabled false \
                    (the default). v1 is only consulted by devices below API 24; see KNOWLEDGE.md §6.1"
            .into());
    }
    if !args.opts.v2 && !args.opts.v3 {
        return Err("nothing to do: both --v2-signing-enabled and --v3-signing-enabled are false".into());
    }

    let outputs = plan_outputs(&args)?;
    let signer = load_signer(&args.keysrc)?;
    let t_keys = t0.elapsed();

    let n = args.inputs.len();
    let cores = digest::physical_cores();
    let jobs = args.jobs.unwrap_or(cores).min(n).max(1);
    let threads = args.threads.unwrap_or_else(|| (cores / jobs).max(1));

    let results: Mutex<Vec<(usize, Result<String, String>)>> = Mutex::new(Vec::with_capacity(n));
    let work = |idx: usize| {
        let r = sign_one(&args.inputs[idx], outputs[idx].as_deref(), &signer, threads, args.opts);
        results.lock().unwrap().push((idx, r));
    };
    if jobs == 1 {
        (0..n).for_each(work);
    } else {
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..jobs {
                s.spawn(|| loop {
                    let idx = next.fetch_add(1, Ordering::Relaxed);
                    if idx >= n {
                        break;
                    }
                    work(idx);
                });
            }
        });
    }

    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    let mut failed = 0usize;
    let stderr = io::stderr();
    let mut err = stderr.lock();
    for (idx, r) in &results {
        match r {
            Ok(report) => {
                let _ = err.write_all(report.as_bytes());
            }
            Err(e) => {
                failed += 1;
                let _ = writeln!(err, "fastsigner: error: {}: {e}", args.inputs[*idx].display());
            }
        }
    }
    if args.opts.timing {
        let _ = writeln!(
            err,
            "fastsigner: {} APK(s), {} failed | keys {:.3} ms | {} job(s) × {} thread(s) | wall {:.3} ms",
            n,
            failed,
            t_keys.as_secs_f64() * 1e3,
            jobs,
            threads,
            t0.elapsed().as_secs_f64() * 1e3
        );
    }
    if failed > 0 {
        return Err(format!("{failed} of {n} APK(s) failed"));
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("fastsigner: error: {e}");
        exit(1);
    }
}
