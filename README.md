# fastsigner

A native Rust replacement for `zipalign` + `apksigner sign` that implements APK Signature Scheme
**v2 and v3** and skips everything that makes apksigner slow: JVM/JCA warm-up, rewriting the
whole APK, and under-using the CPU's SHA-256 units. See `KNOWLEDGE.md` for the research that
motivated it.

**Status: proof of concept.** Output is byte-for-byte identical to apksigner 37.0.0 for RSA keys
(RSA PKCS#1 v1.5 is deterministic) — both for already-aligned inputs and for unaligned inputs
that go through the zipalign rewrite (100 of 100 local corpus APKs, `tests/corpus_identity.sh`).
Every signed APK passes `apksigner verify` and `zipalign -c -P 16 4`.

## Measured (Ryzen 9 9950X, ext4, warm page cache, wall-clock from spawn to exit, median)

| APK | bytes | fastsigner (in place) | with a PKCS#12 store | apksigner (`--out`, v2+v3) | speedup |
|---|---:|---:|---:|---:|---:|
| tiny (manifest only) | 2.3 KB | **0.63 ms** | 1.35 ms | 128 ms | 200× |
| small (2048 game) | 3.3 MB | **1.17 ms** | 1.40 ms | 160 ms | 136× |
| med (Bumble) | 62.6 MB | **2.96 ms** | 3.02 ms | 302 ms | 102× |
| big (WhatsApp) | 145.4 MB | **5.03 ms** | 5.18 ms | 447 ms | 89× |

`bench/bench_fastsigner.sh` reproduces the table (it times with `bench/runbench.c`; earlier
versions of this table used `date` and included ~1.5 ms of shell overhead per run). On the tiny
APK, 0.35 ms of the 0.63 ms is the RSA-2048 signature (v2 and v3 are signed side by side), and
a PKCS#12 store adds ~0.7 ms of key derivation, which bigger APKs hide behind their digest.
Digest phase on `big.apk`: 40 ms on 1 thread, 3.6 ms on 16 (physical cores), 3.2 ms on 32.
KNOWLEDGE.md §10.7 has the measurements behind the current design.

## Usage

```
fastsigner [sign] (--key key.pk8 --cert cert.pem | --ks store.jks --ks-pass pass:pw) [OPTIONS] in.apk...

key material
    --key <file> --cert <file>          PKCS#8/PKCS#1/SEC1 key + PEM/DER certificate chain
    --ks <file>                         JKS or PKCS#12 (PBES2/AES; detected from content); JCEKS rejected
    --ks-pass <src>                     pass:<pw> | env:<VAR> | file:<path> | stdin
    --ks-key-alias <alias>              optional when the store holds exactly one key
    --key-pass <src>                    defaults to the store password
output
    (none)                              sign every input in place
    --out <file>                        single input only
    --out-dir <dir>                     <dir>/<input file name> for each input
options
    --zipalign [true|false|always]      default true: check alignment, rewrite entries only if needed;
                                        always = unconditional apksigner-style rewrite (drops orphans)
    --lib-page-size <KiB>               .so page alignment, default 16 (zipalign -P 16); 4 = zipalign -p; 0 = off
    --v2-signing-enabled [true|false]   default true
    --v3-signing-enabled [true|false]   default true
    --v1-signing-enabled [true|false]   default false; `true` exits with "not implemented"
    --min-sdk-version N                 accepted for apksigner compatibility, unused
    --jobs N, -j N                      APKs signed concurrently (default: min(inputs, physical cores))
    --threads N                         digest threads per APK (default: physical cores / jobs)
    --timing                            per-phase timings on stderr
```

Without `--out`/`--out-dir` the APK is signed **in place**: only the tail (padding + signing block +
central directory + EOCD, ~0.6% of `big.apk`) is rewritten; the entries section is never touched.
Re-signing an APK whose central directory does not change writes the signing block alone (4 KB).
Existing signing blocks and stale `META-INF/` v1 signature entries are removed, like apksigner.
With `--out`/`--out-dir`, the unchanged head of the APK is copied (`copy_file_range`) while the
digest runs, into a temp file next to the destination that is swapped in at the end: a failed run
leaves an existing output untouched.

**Batch mode.** Any number of APKs can be given; the key is loaded once and the APKs are signed
concurrently, each with a share of the physical cores so the machine is never oversubscribed.
A failing input is reported and does not stop the others; the exit code is 1 if any failed.

| batch | `--jobs 1` | default jobs | |
|---|---:|---:|---|
| 8 × small (3.3 MB) | 7.3 ms | **2.0 ms** | serial phases overlap |
| 3 × big (145 MB) | 14.1 ms | **12.6 ms** | digest is CPU-bound either way |

**zipalign.** On by default. Uncompressed entries must have 4-byte aligned data and `.so`
files page-aligned data (16 KiB by default, what Android 15+ and `zipalign -P 16` want). The
check rides on the digest pass, which already streams every byte, so an aligned APK — anything
built by Gradle or previously signed — costs nothing extra and keeps the splice fast path. A
misaligned APK (for example one rebuilt by a patcher with Python's `zipfile`) gets its entries
section rewritten exactly the way apksigner does it: a `0xd935` alignment extra field per stored
entry, stale `0xd935` fields and zipalign's raw zero padding removed, compressed entries and
inter-record bytes copied verbatim, directory entries dropped. Misalignment is usually proven by
a 16-header sample before anything else is read, so the old layout is never digested. The
rewrite is planned first (every output offset known up front), then a few producer threads
assemble 1 MiB output chunks — exactly the v2/v3 digest chunks — and hash them on the way to a
single writer thread, so the new file is digested while it is written rather than read back.
In place it goes through a temp file swapped in with `renameat2(RENAME_EXCHANGE)`, which avoids
ext4's replace-via-rename flush (3 ms instead of 30 ms on `big.apk`). `--zipalign always` forces
the rewrite even for aligned inputs, which is exactly what apksigner does to every APK: use it to
drop orphaned records left by earlier tools.

| unaligned input | fastsigner (in place) | `zipalign` + `apksigner` |
|---|---:|---:|
| small (3.3 MB) | 1.9 ms | ~180 ms |
| big (145 MB) | 28 ms | ~600 ms |

On `big.apk` the floor is the kernel: ext4 serialises buffered writes to one file at ~7 GB/s,
so ~21 of those 28 ms are the write itself; reading, assembling and hashing hide behind it.

Keys: unencrypted PKCS#8 (DER `.pk8` or PEM), PKCS#1 RSA or SEC1 EC, 2048–8192-bit RSA and EC P-256.
Certificates: PEM or DER, chain allowed. Keystores: JKS as written by `keytool -storetype JKS` or
Android Studio, and PKCS#12 as written by JDK 12+ `keytool` (its default, even for `.jks` names)
or OpenSSL 3: PBES2 with PBKDF2-HMAC-SHA1/256/384/512 and AES-128/192/256-CBC, HMAC-SHA1/256/384/512
MAC. The format is detected from the file, and aliases match case-insensitively as in Java. Legacy PKCS#12
(3DES/RC2 from JDK 8–11 or `openssl -legacy`) is refused with a conversion hint:
`keytool -importkeystore -srckeystore old.p12 -destkeystore new.p12 -deststoretype PKCS12` on a
JDK 12+ re-encrypts it. Opening a keytool PKCS#12 store takes 3 × 10 000 PBKDF2/KDF iterations
(MAC, certificates, key); they run in parallel on SHA-NI (~0.7 ms), on their own thread while the
first APK is parsed and digested. Generate a test pair with:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out k.pem
openssl pkcs8 -topk8 -nocrypt -in k.pem -outform DER -out key.pk8
openssl req -new -x509 -key k.pem -days 3650 -subj "/CN=test" -out cert.pem
```

Verify with the reference tool (v2/v3-only APKs need the min-SDK override, see KNOWLEDGE.md §6.3):

```
apksigner verify --verbose --min-sdk-version 24 out.apk
```

## Build & test

```
cargo build --release          # binary: target/release/fastsigner (glibc linked statically, .cargo/config.toml)
cargo test --release           # unit tests (synthetic zips, encoders, digest vs reference impl)
testdata/setup.sh              # symlink corpus APKs, generate keys, apksigner reference outputs
tests/differential.sh          # byte-identity + apksigner verify + zipalign -c on the corpus
tests/corpus_identity.sh       # unaligned rebuild of every local APK: fastsigner must equal apksigner byte for byte
bench/bench_fastsigner.sh      # the table above
```

## Third-party dependencies

| crate | purpose | why this one |
|---|---|---|
| [`ring`](https://crates.io/crates/ring) 0.17 | SHA-256/512, SHA-1 (JKS, PKCS#12 MAC), HMAC, PBKDF2, RSA PKCS#1 v1.5, ECDSA P-256, PKCS#8 parsing, RNG | one crate covers all crypto; BoringSSL assembly with SHA-NI; no system library. Needs a C compiler at build time. |
| [`aes`](https://crates.io/crates/aes) 0.9 | AES block cipher for PKCS#12 key/cert decryption | `ring` has no raw AES or CBC mode. RustCrypto's crate is pure Rust and constant-time (AES-NI when available). Pulls in `cipher`, `crypto-common`, `hybrid-array`, `typenum`, `inout`, `cpufeatures`, `cpubits`. |
| [`cbc`](https://crates.io/crates/cbc) 0.2 | CBC mode on top of `aes` | built with `default-features = false`, which drops `block-padding`: PKCS#7 unpadding is checked by hand. Hand-writing AES was considered and rejected, because it would be security-sensitive code to maintain for a once-per-run operation. |

Everything else is hand-written on `std`: CLI parsing, base64/PEM, a minimal DER walker (to pull
the SubjectPublicKeyInfo out of the certificate and the scalar out of EC keys), the JKS reader and
key protector, the PKCS#12 container parser and its RFC 7292 KDF, ZIP/EOCD/central-directory handling, the scoped-thread work pools (chunks within an
APK, APKs within a batch), and physical-core detection. So is SHA-256 on the x86 SHA extensions
(`src/sha256.rs`, ~300 lines of `core::arch` intrinsics plus tests): ring's is as fast for one message, but
the digest and the PKCS#12 key derivations need two messages interleaved per core and fixed-size
iteration loops, which ring's API cannot express. It is checked against ring in the unit tests,
and ring remains the fallback for CPUs without SHA-NI and for SHA-512. The input is mapped with
`mmap`/`madvise` called directly (`src/mmap.rs`). `memmap2`, `rayon` and `clap` were considered
and deliberately left out.

## Not implemented (yet)

- v1 / JAR signing (`--v1-signing-enabled true` errors out; only devices below API 24 need it)
- JCEKS keystores, legacy PKCS#12 encryption (3DES/RC2/RC4), PKCS#12 PBMAC1 and public-key modes
- v3.1 lineage / key rotation, v4 `.idsig`, source stamps, multiple signers
- Zip64 archives, DSA and P-384 keys
- per-chunk digest caching for re-sign-after-patch (KNOWLEDGE.md §8, "novel optimisation")
- `pinlist.meta` regeneration (apksigner rewrites it for system APKs; fastsigner drops it)

## Layout

| path | role |
|---|---|
| `src/zip.rs` | EOCD / central directory / existing signing block discovery, entry policy (what apksigner keeps, drops, or leaves as a gap) |
| `src/digest.rs` | parallel 1 MiB chunked content digest (two chunks per thread on SHA-NI), physical-core count |
| `src/sha256.rs` | SHA-256 on the SHA extensions: 1- and 2-way block functions, PBKDF2-HMAC-SHA256 |
| `src/mmap.rs` | read-only file mapping; pages are unmapped by the digest threads as they finish |
| `src/align.rs` | zipalign check (piggybacks on the digest pass) and apksig-identical entries rewrite |
| `src/keys.rs` | PEM/DER key + cert loading, keystore entry selection, SPKI extraction, sign-then-verify |
| `src/jks.rs` | Java KeyStore reader: integrity check, entry parsing, key decryption |
| `src/sigblock.rs` | v2/v3 signer block and APK Signing Block encoders (pure functions) |
| `src/main.rs` | CLI, per-APK pipeline, batch scheduling, in-place / `--out` / `--out-dir` writing |
| `docs/superpowers/specs/` | design spec |
| `poc/`, `bench/` | the C/Python research PoCs and apksigner baselines from KNOWLEDGE.md; `bench/runbench.c` times a command from spawn to exit |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution intentionally submitted for inclusion in this work shall be dual licensed as
above, without any additional terms or conditions.
