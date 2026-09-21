# fastsigner

A native Rust replacement for `apksigner sign` that implements APK Signature Scheme **v2 and v3**
and skips everything that makes apksigner slow: JVM/JCA warm-up, rewriting the whole APK, and
under-using the CPU's SHA-256 units. See `KNOWLEDGE.md` for the research that motivated it.

**Status: proof of concept.** Output is byte-for-byte identical to apksigner 37.0.0 for RSA keys
(RSA PKCS#1 v1.5 is deterministic), and every signed APK in the test corpus passes
`apksigner verify`.

## Measured (Ryzen 9 9950X, warm page cache, wall-clock incl. process start)

| APK | bytes | fastsigner (in place) | apksigner (`--out`, v2+v3) | speedup |
|---|---:|---:|---:|---:|
| tiny (manifest only) | 2.3 KB | **2.1 ms** | 132 ms | 63× |
| small (2048 game) | 3.3 MB | **3.0 ms** | 157 ms | 53× |
| med (Bumble) | 62.6 MB | **5.6 ms** | 308 ms | 55× |
| big (WhatsApp) | 145.4 MB | **8.2 ms** | 443 ms | 54× |

Wall numbers include ~1.5 ms of fork/exec + shell measurement overhead; in-process time on the
tiny APK is 0.5 ms, of which 0.4 ms is two RSA-2048 signatures. `bench/bench_fastsigner.sh`
reproduces the table. Digest phase on `big.apk`: 59 ms on 1 thread, 5.6 ms on 16 (physical
cores), 6.9 ms on 32 (SMT hurts, as predicted in KNOWLEDGE.md §4.1).

## Usage

```
fastsigner [sign] (--key key.pk8 --cert cert.pem | --ks store.jks --ks-pass pass:pw) [OPTIONS] in.apk...

key material
    --key <file> --cert <file>          PKCS#8/PKCS#1/SEC1 key + PEM/DER certificate chain
    --ks <file>                         Java KeyStore (JKS); PKCS#12 and JCEKS are detected and rejected
    --ks-pass <src>                     pass:<pw> | env:<VAR> | file:<path> | stdin
    --ks-key-alias <alias>              optional when the store holds exactly one key
    --key-pass <src>                    defaults to the store password
output
    (none)                              sign every input in place
    --out <file>                        single input only
    --out-dir <dir>                     <dir>/<input file name> for each input
options
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
Existing signing blocks and stale `META-INF/` v1 signature entries are removed, like apksigner.

**Batch mode.** Any number of APKs can be given; the key is loaded once and the APKs are signed
concurrently, each with a share of the physical cores so the machine is never oversubscribed.
A failing input is reported and does not stop the others; the exit code is 1 if any failed.

| batch | `--jobs 1` | default jobs | |
|---|---:|---:|---|
| 8 × small (3.3 MB) | 8.6 ms | **2.6 ms** | serial phases overlap |
| 3 × big (145 MB) | 18.5 ms | **16.6 ms** | digest is CPU-bound either way |

Keys: unencrypted PKCS#8 (DER `.pk8` or PEM), PKCS#1 RSA or SEC1 EC, 2048–8192-bit RSA and EC P-256.
Certificates: PEM or DER, chain allowed. JKS stores as written by `keytool -storetype JKS` or
Android Studio; note that JDK 9+ `keytool` writes **PKCS#12** by default even for `.jks` names, and
fastsigner tells you so rather than misreading the file. Generate a test pair with:

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
cargo build --release          # binary: target/release/fastsigner
cargo test --release           # unit tests (synthetic zips, encoders, digest vs reference impl)
testdata/setup.sh              # symlink corpus APKs, generate keys, apksigner reference outputs
tests/differential.sh          # byte-identity + apksigner verify on the corpus
bench/bench_fastsigner.sh      # the table above
```

## Third-party dependencies

| crate | purpose | why this one |
|---|---|---|
| [`ring`](https://crates.io/crates/ring) 0.17 | SHA-256/512, SHA-1 (JKS only), RSA PKCS#1 v1.5, ECDSA P-256, PKCS#8 parsing, RNG | one crate covers all crypto; BoringSSL assembly with SHA-NI; no system library. Needs a C compiler at build time. |

Everything else is hand-written on `std`: CLI parsing, base64/PEM, a minimal DER walker (to pull
the SubjectPublicKeyInfo out of the certificate and the scalar out of EC keys), the JKS reader and
key protector, ZIP/EOCD/central-directory handling, the scoped-thread work pools (chunks within an
APK, APKs within a batch), and physical-core detection. `memmap2`, `rayon` and `clap` were
considered and deliberately left out; `pread` into a per-thread 1 MiB buffer already reaches
the SHA-NI limit.

## Not implemented (yet)

- v1 / JAR signing (`--v1-signing-enabled true` errors out; only devices below API 24 need it)
- PKCS#12 and JCEKS keystores (would need AES-CBC / 3DES, i.e. the `aes`+`cbc` or `openssl` crates)
- v3.1 lineage / key rotation, v4 `.idsig`, source stamps, multiple signers
- Zip64 archives, DSA and P-384 keys
- per-chunk digest caching for re-sign-after-patch (KNOWLEDGE.md §8, "novel optimisation")

## Layout

| path | role |
|---|---|
| `src/zip.rs` | EOCD / central directory / existing signing block discovery, v1 entry stripping |
| `src/digest.rs` | parallel 1 MiB chunked content digest, physical-core count |
| `src/keys.rs` | PEM/DER key + cert loading, keystore entry selection, SPKI extraction, sign-then-verify |
| `src/jks.rs` | Java KeyStore reader: integrity check, entry parsing, key decryption |
| `src/sigblock.rs` | v2/v3 signer block and APK Signing Block encoders (pure functions) |
| `src/main.rs` | CLI, per-APK pipeline, batch scheduling, in-place / `--out` / `--out-dir` writing |
| `docs/superpowers/specs/` | design spec |
| `poc/`, `bench/` | the C/Python research PoCs and apksigner baselines from KNOWLEDGE.md |
