# fastsigner PoC — design (2026-09-21)

Native Rust replacement for `apksigner sign`, v2 + v3 only. Targets the numbers in
KNOWLEDGE.md §5 (~13 ms on `big.apk` vs apksigner's 410 ms).

## Scope

- **In:** APK Signature Scheme v2 and v3 (single signer), RSA (PKCS#1 v1.5, SHA-256 for
  ≤3072-bit keys, SHA-512 above) and ECDSA P-256 keys, raw `pk8`/`pem` key + `pem` cert,
  JKS keystores (`--ks`, `--ks-pass`, `--ks-key-alias`, `--key-pass`; added later the same day),
  batch signing of many APKs with `--jobs` concurrency and `--out-dir`,
  in-place splice write, parallel chunk digest on physical cores, stripping of stale
  `META-INF/` v1 signature entries from the central directory.
- **Flagged out:** `--v1-signing-enabled true` exits with "not implemented" (KNOWLEDGE §6.1).
- **Out (later):** PKCS#12/JCEKS keystores, v3.1 lineage/rotation, v4 `.idsig`, source stamps,
  Zip64, DSA, P-384, multiple signers, verity digests, per-chunk digest cache.

## CLI

Mirrors apksigner so bench scripts can swap binaries:

```
fastsigner sign --key k.pk8 --cert c.pem [--out out.apk] [--v2-signing-enabled true|false]
                [--v3-signing-enabled true|false] [--v1-signing-enabled false] [--min-sdk-version N]
                [--threads N] [--timing] in.apk
```

No `--out` = sign in place (only the tail of the file is rewritten).

## Pipeline

1. `zip::parse` — locate EOCD (backward scan, comment-tolerant), CD offset/size, existing
   APK Signing Block (magic at `cd_off-16`, size fields must agree). Reject Zip64.
2. Read CD into memory, drop v1 signature entries (`META-INF/MANIFEST.MF`, `*.SF/RSA/DSA/EC`,
   `SIG-*`, direct children only, case-insensitive — same rule as apksig's
   `isJarEntryDigestNeededInManifest`). Patch entry counts / cd size in the EOCD.
3. `entries_end` = signing block start (if present) else `cd_off`. Zero-pad to a 4096 multiple
   (apksig `generateApkSigningBlockPadding`). The padding **is part of the digested contents**.
4. `digest::content_digests` — 1 MiB chunks over [contents+pad, CD, EOCD-with-cd_off=block_start],
   `SHA(0xa5 ‖ len ‖ chunk)` per chunk, `SHA(0x5a ‖ count ‖ digests)` on top. Dynamic
   work-stealing over an atomic counter, one 1 MiB buffer per thread, `pread` (no mmap in v0).
5. `sigblock` — v2 signer block (with 0xbeeff00d stripping-protection attr when v3 is on, plus
   the empty 4th element apksig emits), v3 signer block (minSdk 24, maxSdk 0x7fffffff), APK
   Signing Block with verity padding pair so the block is a 4096 multiple. Byte layout verified
   against apksigner 37.0.0 output.
6. Sign with `ring`, verify the signature against the cert's public key (apksig does the same).
7. Write: in place → `pwrite` tail at `entries_end` then `ftruncate`; `--out` → `copy_file_range`
   of the head then the tail.

## Modules

| file | responsibility | depends on |
|---|---|---|
| `zip.rs` | EOCD/CD/sig-block discovery, `ReadAt` trait, CD filtering, EOCD patching | std |
| `digest.rs` | parallel chunked content digest, physical core count | ring, zip::ReadAt |
| `keys.rs` | PEM/DER loading, keystore entry selection, key type detection (with EC scalar fallback), SPKI extraction, sign+verify | ring, jks |
| `jks.rs` | JKS reader: magic sniffing, integrity hash, entry parsing, KeyProtector decryption | ring (SHA-1) |
| `sigblock.rs` | v2/v3/APK-signing-block encoders (pure functions over bytes) | — |
| `main.rs` | CLI, per-APK pipeline, batch scheduler (atomic queue over scoped threads, `cores/jobs` digest threads each), output writing, `--timing` | all |

## Third-party crates

| crate | why | alternative considered |
|---|---|---|
| `ring` 0.17 | SHA-256/512 (BoringSSL asm, SHA-NI), RSA PKCS#1 v1.5, ECDSA P-256, PKCS#8 parsing, RNG — one crate for all crypto | RustCrypto (`sha2`+`rsa`+`p256`+`pkcs8`, ~30 transitive crates, `rsa` has an open timing advisory); `openssl` (system lib) |

Everything else (CLI parsing, base64/PEM, minimal DER walk, ZIP, threading, core detection) is
hand-written on std. `memmap2`/`rayon`/`clap` deliberately not used; can be added if measured.

## Testing

- Unit tests per module (synthetic zips, encoders, padding arithmetic).
- Digest test: recompute the digest embedded in `testdata/ref_small_rsa.apk` (apksigner output).
- **Byte-identity test:** RSA PKCS#1 v1.5 is deterministic, so re-signing an apksigner-signed APK
  with the same key must reproduce the file byte for byte (`cmp`).
- Differential test: sign small/med/big with RSA and EC keys →
  `apksigner verify --verbose --min-sdk-version 24` must report v2 and v3 `true`.
- Bench: `bench/bench_fastsigner.sh` vs the apksigner numbers in KNOWLEDGE.md §2.
