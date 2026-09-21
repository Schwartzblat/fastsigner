//! fastsigner — a fast native `apksigner sign` replacement for APK Signature Scheme v2 + v3.
//!
//! Per APK: locate ZIP sections → strip stale v1 entries from the CD → pad entries to 4 KiB →
//! parallel chunked digest → build v2/v3 blocks → APK Signing Block → splice the tail.
//! Several APKs can be signed concurrently with one shared key.

mod digest;
mod jks;
mod keys;
mod sigblock;
mod zip;

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Read, Seek, Write};
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
    --ks <file>                   Java KeyStore (JKS). PKCS#12/JCEKS are detected and rejected
    --ks-pass <src>               Keystore password: pass:<pw> | env:<VAR> | file:<path> | stdin
    --ks-key-alias <alias>        Key alias (optional when the store has exactly one key)
    --key-pass <src>              Key password (default: same as --ks-pass)
    --ks-type <type>              Only JKS is accepted

OUTPUT:
    (none)                        Sign every input in place (only the tail of the file is rewritten)
    --out <file>                  Write the signed APK here (single input only)
    --out-dir <dir>               Write <dir>/<input file name> for every input

OPTIONS:
    --v2-signing-enabled [bool]   Default true
    --v3-signing-enabled [bool]   Default true
    --v1-signing-enabled [bool]   Default false. `true` is NOT IMPLEMENTED and exits with an error
    --min-sdk-version <n>         Accepted for apksigner compatibility; unused by v2/v3 signing
    --jobs <n>, -j <n>            APKs signed concurrently (default: min(inputs, physical cores))
    --threads <n>                 Digest threads per APK (default: physical cores / jobs)
    --timing                      Print per-phase timings to stderr
    -h, --help                    This text
";

#[derive(Clone, Copy)]
struct Opts {
    v2: bool,
    v3: bool,
    timing: bool,
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
                if !t.eq_ignore_ascii_case("jks") {
                    return Err(format!("--ks-type {t}: only JKS keystores are supported"));
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
    Ok(Args { inputs, out, out_dir, keysrc, v1, jobs, threads, opts: Opts { v2, v3, timing } })
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
    let mut cd = vec![0u8; sections.cd_size as usize];
    file.read_exact_at(&mut cd, sections.cd_off).map_err(|e| format!("read central directory: {e}"))?;
    let filtered = zip::strip_v1_signature_entries(&cd)?;
    let cd = filtered.bytes;
    if filtered.entries > u16::MAX as u64 {
        return Err("too many entries for a non-Zip64 archive".into());
    }

    let entries_end = sections.entries_end;
    let pad = sigblock::padding_before_block(entries_end);
    let block_start = entries_end + pad;
    let zeros = vec![0u8; pad as usize];

    let mut eocd = sections.eocd.clone();
    zip::set_eocd_entry_count(&mut eocd, filtered.entries as u16);
    zip::set_eocd_cd_size(&mut eocd, cd.len() as u32);
    // For digesting, the EOCD's CD-offset field points at the signing block start.
    let mut eocd_for_digest = eocd.clone();
    zip::set_eocd_cd_offset(&mut eocd_for_digest, block_start as u32);
    tm.mark("parse");

    // --- content digest --------------------------------------------------------------------
    let sources = [Source::file(0, entries_end, &zeros), Source::bytes(&cd), Source::bytes(&eocd_for_digest)];
    let digests = digest::content_digests(&file, &sources, &[signer.content_digest], threads).map_err(|e| format!("digest: {e}"))?;
    let content_digest = &digests[0];
    tm.mark("digest");

    // --- signature blocks ------------------------------------------------------------------
    let inp = SignerInput { alg_id: signer.alg_id, digest: content_digest, certs: &signer.certs, spki: &signer.spki };
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
    let mut tail = Vec::with_capacity(zeros.len() + block.len() + cd.len() + eocd.len());
    tail.extend_from_slice(&zeros);
    tail.extend_from_slice(&block);
    tail.extend_from_slice(&cd);
    tail.extend_from_slice(&eocd);
    let new_len = entries_end + tail.len() as u64;

    match output {
        None => {
            file.write_all_at(&tail, entries_end).map_err(|e| format!("write: {e}"))?;
            file.set_len(new_len).map_err(|e| format!("truncate: {e}"))?;
        }
        Some(out_path) => {
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
    tm.mark("write");

    if !opts.timing {
        return Ok(String::new());
    }
    Ok(format!(
        "fastsigner: {} ({} B{}) | {} | entries_end={} pad={} block={} B cd={} B ({} entries, {} v1 entries stripped) | {} threads | wrote {} B{}\n{}",
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
        filtered.entries,
        filtered.removed.len(),
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
