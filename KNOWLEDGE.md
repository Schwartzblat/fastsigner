# fastsigner — Knowledge Base

Feasibility research for a native (Rust/C/C++) replacement for Android's `apksigner`.

**Status:** research complete, nothing built. Verdict: **highly feasible, ~30–70× achievable.**
**Date:** 2026-09-20

---

## 1. Test environment

All numbers below were measured on this machine. They are not estimates unless explicitly labelled as such.

| | |
|---|---|
| CPU | AMD Ryzen 9 9950X, 16 cores / 32 threads |
| Relevant ISA | `sha_ni`, `avx2`, `aes` |
| JDK | OpenJDK 21.0.12 (Ubuntu 26.04) |
| apksigner | Android build-tools **37.0.0** (`~/Android/Sdk/build-tools/37.0.0/apksigner`) |
| OS | Linux 7.0.0-31-generic |
| Test device | Pixel 9a, **API 36**, adb `54251JEBF05850` |
| AVDs available | `a12_api31_x86_64`, `ci_repro_33_x86_64`, `ci_repro_36_x86_64` |

`apksigner` is a bash script ending in `exec java $javaOpts -jar apksigner.jar "$@"`, default heap `-Xmx1024M`.

### Test corpus

| alias | source | bytes | MiB | entries | uncompressed |
|---|---|---|---|---|---|
| `small.apk` | 2048 game | 3,321,628 | 3.17 | 352 | 7.8 MiB |
| `med.apk` | Bumble 5.362.0 | 62,592,233 | 59.7 | 4,390 | 106.9 MiB |
| `big.apk` | WhatsApp 2.26.36.71 | 145,376,445 | 138.6 | 14,889 | 201.1 MiB |

Keystore used: 2048-bit RSA self-signed, `keytool -genkeypair`, alias `test`, pass `android`.
Also derived a raw `key.pk8` (PKCS#8 DER) + `cert.pem` pair to isolate keystore cost.

---

## 2. Baseline — what apksigner actually costs

Warm page cache, best of 2 runs, wall time.

| APK | v2+v3 | v1+v2+v3 | v1 only | v2 only |
|---|---|---|---|---|
| **111 B** (1 entry) | **0.13–0.18 s** | — | — | — |
| small (3.17 MiB) | 0.20 s | 0.24 s | 0.20 s | 0.18 s |
| med (59.7 MiB) | 0.28 s | 0.68 s | 0.58 s | 0.27 s |
| big (138.6 MiB) | 0.41 s | 1.04 s | 0.91 s | 0.36 s |

CPU utilisation was 250–530%, so **apksig already multithreads** — it is just far from the hardware limit.
Peak RSS reached **1.28 GB** on `big.apk` with the default scheme set.

### 2.1 The single most important finding

**A 111-byte APK takes 130–180 ms.** That is pure fixed overhead, before any real work.

Breakdown of that floor:

| component | cost |
|---|---|
| JVM startup (`java -version`, CDS enabled) | ~13 ms |
| `apksigner --help` (JVM + jar load, no work) | ~29 ms |
| tiny APK, **raw `pk8`+`pem`** key | **0.13–0.14 s** |
| tiny APK, **JKS keystore** | **0.17–0.18 s** |

Conclusions:
- JVM startup is **not** the main cost — it is ~10% of the floor.
- The floor is JCA provider init + apksig object-graph construction + keystore parsing.
- **JKS costs ~40 ms extra** vs a raw key, because of PBKDF2-style key derivation.
- For any APK under ~50 MiB, **most of apksigner's runtime is warm-up, not work.**

A native binary's equivalent floor is ~1 ms.

### 2.2 In-place mode is not faster

| mode | big.apk, v2+v3 |
|---|---|
| in-place (no `--out`) | 0.44 s / 0.43 s |
| `--out` (fresh file) | 0.40 s / 0.42 s |

apksigner **rewrites the entire file either way**. "In-place" writes a temp file and renames. This is a
major, unexploited optimisation opportunity — see §4.3.

---

## 3. APK Signature Scheme v2 — verified format notes

> Reference: <https://source.android.com/docs/security/features/apksigning/v2>

### 3.1 Block layout

The APK Signing Block is inserted **immediately before the ZIP Central Directory**. All fields little-endian.

```
uint64  block size (excluding this field)
  repeated: uint64 pair-length, uint32 ID, <value bytes>
uint64  block size (repeated — allows locating the block from either end)
16 B    magic "APK Sig Block 42"
```

Known pair IDs observed in the wild:

| ID | meaning |
|---|---|
| `0x7109871a` | APK Signature Scheme **v2** block |
| `0xf05368c0` | APK Signature Scheme **v3** block |
| `0x1b93ad61` | APK Signature Scheme **v3.1** block |
| `0x42726577` | **verity padding block** (pads the signing block to a 4096 boundary) |

### 3.2 Digest computation (confirmed byte-exact)

Three sections are digested:

1. **Contents** — `[0, signing_block_start)`
2. **Central Directory** — `[cd_off, cd_off + cd_size)`
3. **EOCD** — with its *central-directory-offset field (offset +16) overwritten with the signing block's
   start offset*. This is the subtle part; get it wrong and nothing verifies.

Each section is split into **1 MiB (2^20) chunks**, chunks flattened across all three sections in order:

```
chunk digest = SHA-256( 0xa5 || uint32le(chunk_len) || chunk_bytes )
top digest   = SHA-256( 0x5a || uint32le(chunk_count) || concat(chunk_digests) )
```

### 3.3 Signed-data structure

Everything is uint32-length-prefixed:

```
v2 block
 └─ signers (lp)
     └─ signer (lp)
         ├─ signed data (lp)
         │   ├─ digests (lp)         → repeated lp{ uint32 algId, lp digest }
         │   ├─ certificates (lp)    → DER X.509 chain
         │   └─ additional attrs (lp)
         ├─ signatures (lp)          → repeated { uint32 algId, lp signature }
         └─ public key (lp)          → SubjectPublicKeyInfo, ASN.1 DER
```

Signature algorithm IDs seen: `0x0103` = RSASSA-PKCS1-v1_5 + SHA-256 (what our RSA-2048 key produced).
The digest list and signature list must cover the same algorithms — this is the anti-stripping defence.

### 3.4 Live verification (the key result)

Signed `big.apk` with real apksigner (v2 only), parsed the resulting block, recomputed the digest
independently, compared:

```
signing block: start=143380480 size=4088 cd_off=143384576 cd_size=865248
  pair id=0x7109871a len=1362
  pair id=0x42726577 len=2686
  embedded digest alg=0x0103 -> aac92ddebb1f3811b6c108faf3fc15d1580be3f806dae740445d789574f87759
  recomputed             -> aac92ddebb1f3811b6c108faf3fc15d1580be3f806dae740445d789574f87759
  MATCH
```

Byte-exact on the first attempt, in ~40 lines of Python (`poc/verify_v2_digest.py`).
Note `143380480 % 4096 == 0` — the verity padding block did its job.

**Takeaway: the format is small, well-specified, and reproducible in an afternoon.**

---

## 4. Native performance floor (measured)

Proof-of-concept C programs, `gcc -O2 -fopenmp`, OpenSSL EVP, mmap'd input, warm page cache.

### 4.1 v2/v3 content digest — `poc/v2digest.c`

| APK | 1 thread | 16 threads | 32 threads |
|---|---|---|---|
| small | 2.4 ms (1.32 GB/s) | 2.1 ms | 4.0 ms |
| med | 27.0 ms (2.16 GB/s) | 6.8 ms (8.5 GB/s) | 9.0 ms |
| big | 60.0 ms (2.26 GB/s) | **9.0 ms (15.1 GB/s)** | 16.2 ms |

- **16 threads is the sweet spot** (physical cores). 32 threads (SMT) is *slower* — SHA-NI saturates the
  core's crypto unit, so hyperthreads just add contention. Pin the pool to physical cores.
- Single-core SHA-256 with `sha_ni` is ~2.3 GB/s (OpenSSL `speed` reports 2.7 GB/s at 16 KiB blocks).
- For reference, coreutils `sha256sum big.apk` takes 0.25 s (~580 MB/s) — **do not benchmark against
  `sha256sum`**, its implementation is far off the hardware peak.
- Full process wall time (startup + mmap + digest) on `big.apk`: **10 ms**.

### 4.2 v1/JAR digest — `poc/v1digest.c`

Inflate every entry (zlib, raw `-15`) and SHA-256 the uncompressed bytes.

| APK | 1 thread | 16 threads | 32 threads |
|---|---|---|---|
| med (106.9 MiB uncompressed) | 248.1 ms | **31.4 ms** | 43.7 ms |
| big (201.1 MiB uncompressed) | 351.6 ms | **34–43 ms** | 47.7 ms |

#### Cost decomposition (big.apk, 16 threads)

| phase | time | share |
|---|---|---|
| inflate only | 25.7 ms | 75% |
| SHA-256 only (per-entry, over compressed bytes) | 13.9 ms | — |
| **inflate + SHA-256** | **34.2 ms** | 100% |

**Inflate is ~75% of v1's cost.** See §6.0 for the full "why v1 is slow" analysis.

#### ⚠ Scheduling is worth 4.8× — the biggest single tuning lever found

The first version of this PoC used `schedule(dynamic,8)` and measured **157.8 ms**. Changing the chunk
size to 1 dropped it to **33.1 ms**:

| OpenMP schedule | big.apk, 16 threads |
|---|---|
| `dynamic,8` (zip order) | 157.8 ms |
| `guided` (zip order) | 300.3 ms |
| **`dynamic,1`** (zip order) | **33.1 ms** |
| `dynamic,1` + largest-entry-first | 37.6 ms |

Why: the `classes*.dex` files are **adjacent in zip order**, so a chunk of 8 hands one thread eight
consecutive multi-MiB dex files (~25 ms each) while 15 threads idle on 4 KiB XML files. `guided` is worse
still — it issues the largest chunks first. Sorting largest-first did *not* help here (37.6 ms); plain
`dynamic,1` is already at the floor, and the sort adds its own cost.

**Any reimplementation must schedule entries one at a time, not in blocks.** This applies to `rayon`
too — use `par_iter()` over individual entries, and avoid `with_min_len`.

#### Hard floor (Amdahl tail), measured — `poc/inflate_tail.c`

```
  slowest single deflated entry : 24.3 ms  (classes11.dex)
  sum of all inflate time       : 259.7 ms  (serial total)
  => perfect-parallel lower bound = max(259.7/16, 24.3) = 24.3 ms
```

A DEFLATE stream is a serial bit-stream — **a single entry cannot be split across cores.** So the floor
is the *slowest individual entry*, not total-bytes/cores. At 25.7 ms measured for inflate-only, the
PoC is within 6% of that bound and is effectively optimal. Adding cores past 16 cannot help.

`libdeflate` (~2× on raw throughput) would lower the tail itself and is the only remaining lever.

### 4.3 I/O — the other big lever

apksigner rewrites the whole file. A splicing signer does not:

```
APK total             : 137.6 MB
central directory     :   0.83 MB (14,887 entries)
in-place signer WRITES:   0.83 MB  (0.60% of the file)
re-sign, same key+alg :   4.00 KB  (0.0028% of the file)
```

Two tiers of optimisation:
1. **Signing an unsigned APK:** write signing block + CD + EOCD. The first ~137 MB is never touched.
2. **Re-signing with the same key+algorithm:** the block is padded to 4096 bytes, so the new block is
   *identical in size*. Overwrite **4 KB** and stop. Nothing moves, CD offsets stay valid.

### 4.4 Asymmetric signing cost — negligible

| operation | cost |
|---|---|
| ECDSA P-256 sign | 0.01 ms (98,983/s measured) |
| RSA-2048 sign | ~1 ms |
| PKCS#8 DER key parse | microseconds |

---

## 5. Projected native performance

Digest figures are measured; the rest are the small measured/known constants from §4.3–4.4.

| workload | apksigner | native target | speedup |
|---|---|---|---|
| tiny APK (fixed overhead) | 130–180 ms | ~1 ms | **>100×** |
| small, v2+v3 | 200 ms | ~3 ms | **~60×** |
| med, v2+v3 | 280 ms | ~8 ms | **~35×** |
| big, v2+v3 | 410 ms | ~13 ms | **~30×** |
| big, v1+v2+v3 | 1040 ms | ~50 ms | **~20×** |

The v1 row assumes ~34 ms v1 digest overlapped with the 9 ms v2 digest, plus manifest generation.
**Manifest text generation is not measured** and is the main uncertainty in that row — 2.4 MiB of
line-wrapped text plus ~15k extra small SHA operations (§6.0). Treat ~20× as optimistic until measured.

Where the ~13 ms for `big` comes from: 9 ms digest + ~1 ms RSA + ~1 ms splice write + ~2 ms process/parse.

**The win is three separate things, in order of importance for typical APKs:**
1. Eliminating 130–180 ms of fixed warm-up — free, you get it just by being native.
2. Splicing instead of copying the file.
3. Saturating SHA-NI across physical cores.

---

## 6. Gotchas and risks

### 6.0 Why v1 is slow — four independent reasons

Measured on `big.apk`. v2 digests 138.6 MiB in 9 ms; v1 digests the *same APK* in 34 ms, and apksigner
takes 0.91 s for v1-only. The gap has four separate causes.

**1. It digests *uncompressed* bytes, so everything must be inflated.**
v2 hashes the raw file as it sits on disk. v1 (JAR signing) hashes each entry's *decompressed* content,
so 105 MiB of deflated data must be reconstructed first.

| | entries | uncompressed |
|---|---|---|
| DEFLATED (must inflate) | 9,434 | 105.0 MiB |
| STORED (memcpy only) | 5,455 | 96.1 MiB |

Note modern APKs store native libs uncompressed (`extractNativeLibs=false` + 16 KiB page alignment), so
the 17.3 MiB `lib/x86/libs.so` is free — the cost is concentrated in the `classes*.dex` files.

**2. DEFLATE is ~6× slower than SHA-256 and has no hardware acceleration.**
Measured single-core on real dex data: **0.32–0.39 GB/s inflate** vs **2.3 GB/s SHA-256** with `sha_ni`.
Inflate is a serial bit-stream decode with unpredictable branches and byte-granular LZ77 back-references.
There is no `sha_ni` equivalent for it. This is why v1 is *algorithmically* expensive and v2 is not.

**3. A single entry can't be parallelised, so there's a hard Amdahl tail.**
`classes11.dex` alone takes 24.3 ms to inflate and cannot be split across cores. Total serial inflate is
259.7 ms; 16 cores would ideally give 16.2 ms, but the floor is 24.3 ms. **More cores stop helping.**
v2 has no such limit — its 1 MiB chunks are independent, which is why it hits 15.1 GB/s.

**4. Per-entry fragmentation wrecks SHA throughput too.**
v1 needs one SHA context *per entry*; v2 hashes 1 MiB chunks. On nearly identical byte volume
(137.1 MiB vs 138.6 MiB), per-entry SHA costs **13.9 ms vs v2's 9.0 ms**. The entry sizes explain it:

| size range | entries | % of entries | % of bytes |
|---|---|---|---|
| < 4 KiB | 13,974 | **93.8%** | **6.4%** |
| > 1 MiB | 20 | 0.1% | 82.2% |

OpenSSL SHA-256 runs at 249 MB/s on 16-byte inputs but 2,731 MB/s at 16 KiB — an **11× penalty** for
small blocks. 93.8% of entries land in the slow regime.

**Plus, for apksigner specifically: the manifest text.** v1-signing `big.apk` produces
`MANIFEST.MF` = **1.19 MiB / 14,887 sections** and `KEY.SF` = **1.19 MiB / 14,887 sections**. KEY.SF holds
a `SHA-256-Digest-Manifest` of the whole manifest *plus a digest of every individual manifest section* —
so ~15k more tiny SHA operations, on top of generating and parsing 2.4 MiB of line-wrapped text. This is
serial string work that our 34 ms digest floor does not include.

### 6.1 Do you actually need v1? — corpus study

Short answer for a patching workflow: **almost certainly not.**

#### Rule of thumb everyone gets wrong

`minSdk < 24` means the APK *claims* to support old devices. It does **not** mean v1 is needed to install
it. **Android verifies with the highest scheme the device supports** — if v2 is present, an API 24+
device never looks at v1 at all. v1 matters only if the APK will land on **Android 6.0 or older**
(API < 24), which in 2026 is a rounding error.

It also cuts the other way: [Android 11+ *rejects* v1-only APKs](https://developer.android.com/about/versions/11/behavior-changes-11)
when `targetSdk >= 30` — *"Target SDK version 30 requires a minimum of signature scheme v2; the APK is
not signed with this or a later signature scheme."* **v1-only is no longer a viable configuration.**
v1 is strictly a legacy *add-on*, never a standalone choice.

#### What the local corpus actually ships (`bench/scan_corpus_schemes.sh`, 29 APKs)

| | count | schemes shipped |
|---|---|---|
| minSdk < 24 | 22 (76%) | mostly `v1 v2 v3` |
| minSdk ≥ 24 | 7 (24%) | **no v1 at all** |

The minSdk ≥ 24 group is the existence proof — real shipping apps with no v1:

| APK | minSdk | target | schemes |
|---|---|---|---|
| **Etsy 6.80 / 6.81** (4 copies) | 28 | 34 | **`v3` only** |
| ItsOnFire | 30 | 32 | `v2` only |
| WonderSMS | 24 | 34 | `v2` only |
| Jetpack Joyride | 24 | 33 | `v2 v3` |

Etsy is the strongest data point: a major production Play app shipping **v3 alone** — no v1, no v2.

Notable legacy counter-examples in the corpus (`v1` only): `UnCrackable-Level3.apk` (minSdk 19) and
`Defender II` (minSdk 14) — both old, both targetSdk 28, i.e. predating the Android 11 rule.

#### Why this is the highest-leverage decision in the project

Dropping v1 wins on *both* axes at once, which is unusual:

- **Speed:** v1 costs 34 ms of digest vs v2's 9 ms (§4.2), *plus* 2.4 MiB of MANIFEST.MF/KEY.SF text
  generation and ~15k extra small SHA operations (§6.0). It is most of the gap between ~20× and ~30×.
- **Complexity:** v1 is where all the format pain lives — 72-byte line wrapping, section ordering,
  PKCS#7/CMS DER. It is the difference between a weekend and a month.

**Decision: build v2+v3 only. Treat v1 as an opt-in `--v1` flag that may never be implemented.**

#### Not yet verified empirically

A v2+v3-only, `minSdk=14` APK (`2048_v2v3only.apk`) was produced and passes
`apksigner verify --min-sdk-version 24`, but **has not been installed on a real device.**
`adb install --dry-run` is **not supported** on the Pixel 9a (API 36) — it fails with
`IllegalArgumentException: Unknown option --dry-run`, so there is no non-committing install check.
The open test: boot the `ci_repro_36_x86_64` AVD and `adb install` it. Expected to succeed.

### 6.2 v1/JAR signing is the whole difficulty
Not the digest — the *serialisation*. MANIFEST.MF / CERT.SF text quirks, 72-byte line wrapping (note
KEY.SF wraps mid-token: `...builtins.Buil\n t`), entry ordering, and a PKCS#7/CMS DER blob for the
`.RSA` file. It is also the only algorithmically expensive scheme.

**v1 is only required below API 24.** Scoping it out is the biggest single decision available and turns
this project from weeks into a weekend.

### 6.3 minSdk drives verification (hit live)
A v2-only APK reports:
```
DOES NOT VERIFY
ERROR: Missing META-INF/MANIFEST.MF
```
…unless `--min-sdk-version 24` is passed, at which point it reports `Verifies`.

**This is a tooling default, not a device rule** (§6.1) — apksigner is being conservative on the app's
behalf. The APK itself is fine. fastsigner needs the same escape hatch, and should arguably default the
*other* way, since it signs for a known target device rather than for Play distribution.

The signer must read minSdk out of the **binary** AndroidManifest.xml, exactly as apksigner does
(`ApkSigner.getMinSdkVersionFromApk`), or demand it on the command line. Note `aapt2 dump badging` does
not always print `sdkVersion` — WhatsApp's output omitted it.

### 6.4 Other
- **Keystores.** JKS is proprietary-but-documented; PKCS#12 is more work. Supporting raw `pk8`+`pem`
  first is nearly free and skips the PBKDF2 cost entirely.
- **Alignment.** 4-byte entry alignment, plus **16 KiB page alignment for `.so` on Android 15+**. If
  signing freshly-patched APKs this must be integrated, not shelled out to `zipalign`.
- **Untrusted ZIP parsing.** Attacker-influenced offsets and lengths. Main argument for Rust over C.
- **Zip64.** The PoCs read 32-bit EOCD fields only. Real APKs >4 GiB or >65535 entries need Zip64.
- **Skippable for an MVP:** v3.1 / SigningCertificateLineage / key rotation; v4 (`.idsig`, fs-verity
  Merkle tree) which only matters for `adb install --incremental`; source stamps.

---

## 7. Prior art

| project | language | what it is | relevance |
|---|---|---|---|
| [apksig](https://android.googlesource.com/platform/tools/apksig/) | Java | the official library | ground truth |
| [apksig-go](https://github.com/agusibrahim/apksig-go) | Go | clean-room port, v1/v2/v3/v3.1/v4/v4.1 | **proof it's doable** |
| [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) | Java | CLI wrapping official apksig + bundled zipalign | not a speed competitor |
| [`apksig`](https://docs.rs/apksig/latest/apksig/) | Rust | parses signing blocks | parse only |
| [`apk-info`](https://crates.io/crates/apk-info) | Rust | parses v2/v3/v3.1 | parse only |
| `droidsaw_apk` | Rust | static analysis, verification | parse/verify only |
| [`apk`](https://docs.rs/apk/latest/apk/struct.Signer.html) | Rust | has a `Signer` | limited |

**apksig-go** is the strongest evidence: "accepted byte-for-byte by Google's upstream `apksigner`",
cross-validated on 100+ real APKs. It documents the exact gotchas a port hits — non-standard JAR
manifest continuation lines, negative certificate serial numbers (Huawei), lenient DER parsing that
preserves original bytes for digest matching. It deliberately omits JCEKS keystores and source-stamp
signing. **It publishes no benchmarks** — it ports the algorithms, it does not optimise them.

**The Rust gap is real: every Rust crate parses; none is a fast, complete signer.**

### apksig source size (cloned, counted)
```
181 .java files, 47,442 lines total, 34,317 excluding tests
  ApkVerifier.java                3,671
  DefaultApkSignerEngine.java     2,301
  ApkSigner.java                  1,851
  SigningCertificateLineage.java  1,338
  SourceStampVerifier.java        1,012
  internal/ (all)                18,518
```
The v2/v3 **signing** core is a small fraction of that — verification, lineage and source stamps
dominate the line count and are all optional for an MVP.

---

## 8. Recommendation

**Language: Rust.** Memory safety on untrusted ZIP parsing matters, and the ASN.1/certificate work is
dramatically less painful than in C.

Suggested crates: `memmap2`, `rayon`, `sha2` (asm feature) or `openssl`, `rsa`, `p256`, `der`,
`x509-cert`, `cms`, and `libdeflater` bindings for the v1 path if needed.

### MVP scope (~1–2k lines, targets 30–70×)
- v2 + v3 signing only
- In-place splice, never a full copy
- `pk8`/`pem` keys first, then PKCS#12, then JKS
- **No v1** — opt-in `--v1` flag at most (§6.1). Biggest single scope win.
- Default to verifying at the *device's* API level, not the manifest's minSdk (§6.3)
- Thread pool pinned to **physical** cores, not SMT threads

### Testing strategy
Differential-test against apksigner: sign with ours, `apksigner verify --min-sdk-version N` it. This is
minutes of work and catches essentially everything — it caught the format details in §3.4 immediately.

### Novel optimisation worth building in
**Per-chunk digest caching.** v2 digests raw file bytes in *independent* 1 MiB chunks. After patching a
single dex in a 138 MiB APK, recompute one chunk digest and reuse the other 139. Combined with the 4 KB
same-size re-sign from §4.3, re-sign-after-patch becomes sub-millisecond. apksigner cannot do this.
Directly relevant to the local patching workflows (`ApkProjects`, `UltimatePatcher`, ASC).

---

## 9. Artifacts in this repo

| path | what |
|---|---|
| `poc/v2digest.c` | v2/v3 content digest, mmap + OpenMP + OpenSSL. Build: `gcc -O2 -fopenmp -o v2digest poc/v2digest.c -lcrypto` |
| `poc/v1digest.c` | v1 JAR digest floor, parallel inflate + SHA. Build: add `-lz` |
| `poc/v1split.c` | decomposes v1 into inflate-only / sha-only / both; `OMP_SCHEDULE` configurable |
| `poc/inflate_tail.c` | measures the serial Amdahl tail (slowest single deflated entry) |
| `poc/verify_v2_digest.py` | parses a signed APK's signing block and proves the recomputed digest matches |
| `bench/bench_apksigner.sh` | apksigner baseline across sizes × schemes |
| `bench/bench_fixed_overhead.sh` | isolates the fixed-overhead floor (JKS vs raw key) |
| `bench/bench_inplace_vs_out.sh` | in-place vs `--out` comparison |
| `bench/scan_corpus_schemes.sh` | scans a tree of APKs for minSdk / targetSdk / schemes actually present |

Bench scripts expect `small.apk` / `med.apk` / `big.apk`, `test.jks`, `key.pk8`, `cert.pem` in CWD.
**Note:** the bench scripts are bash, not zsh — unquoted array expansion silently breaks under zsh
(zsh does not word-split), which produced a run of bogus 0.04 s "results" during this research.

---

## 10. Rust PoC — built and measured (2026-09-21)

The recommendation in §8 was implemented as a Rust crate in this repo (`src/`, one third-party
crate: `ring`). All numbers below are measured, same machine as §1, warm page cache.

### 10.1 Correctness

- **Byte-identical to apksigner 37.0.0.** Re-signing apksigner's own RSA output with fastsigner
  reproduces the file exactly (`cmp` clean, v2+v3 and v2-only). Possible because RSA PKCS#1 v1.5
  is deterministic; it proves every byte of the v2/v3/signing-block encoding, padding and EOCD
  patching, not just "verifies".
- small/med/big × RSA-2048 and EC P-256 all pass `apksigner verify --min-sdk-version 24`
  (v2 true, v3 true), via `--out` and in place, and after a second in-place re-sign.
- Encoding details that had to be confirmed from apksig source + real output (the spec page does
  not mention them): v2 signed-data carries an **empty 4th length-prefixed element** (4 zero
  bytes) after the additional attributes; v2 gets the stripping-protection attribute
  `0xbeeff00d = 3` when v3 is present; v3 signer minSdk is **24** (the algorithm's own min SDK,
  not 28) and maxSdk `0x7fffffff`, both inside and outside the signed data; pair order is v2, v3,
  verity padding. The zero padding before the signing block **is part of the digested contents**.
- minSdk from the binary manifest (§6.3) turned out to be unnecessary for v2/v3 signing: it only
  influences v1 and apksigner's own verify defaults. No manifest parsing, no inflate needed.

### 10.2 Speed (wall-clock, includes process start and ~1.5 ms of shell measurement overhead)

| APK | fastsigner in-place | apksigner `--out` v2+v3 | speedup | §5 target |
|---|---:|---:|---:|---|
| tiny (2.3 KB) | **2.1 ms** | 132 ms | **63×** | >100× (≈1 ms) |
| small | **3.0 ms** | 157 ms | **53×** | ~60× (≈3 ms) |
| med | **5.6 ms** | 308 ms | **55×** | ~35× (≈8 ms) |
| big | **8.2 ms** | 443 ms | **54×** | ~30× (≈13 ms) |

In-process phases on `big.apk` (`--timing`): parse 0.36 ms, keys 0.03 ms, digest 5.6 ms,
sign 0.4 ms (v2 and v3 RSA signatures run on two threads), write 0.2 ms (869 KB in place).
`--out` instead of in place costs +15 ms on `big.apk` for the `copy_file_range` of the head.

Thread scaling on `big.apk`, digest phase, best of 5: 1 → 59.4 ms, 4 → 15.7, 8 → 8.4,
**16 → 5.6**, 24 → 4.9, 32 → 6.9. Physical cores (from `thread_siblings_list`) is the default.

### 10.3 Things learned building it

- **Fixed overhead hunting matters below 1 ms.** Reading `/proc/cpuinfo` to count physical cores
  cost 0.23 ms — a third of the tiny-APK runtime; a sysfs read is 0.03 ms. An apksig-style
  "sign once to check key/cert" cost another 0.35 ms and was redundant because every real
  signature is verified against the certificate anyway. Thread spawn is ~50 µs, so inputs under
  512 KiB/thread run inline.
- `pread` into a per-thread 1 MiB buffer reaches the SHA-NI limit; mmap was not needed.
- `ring` was the right call: SHA-256/512, RSA, ECDSA, PKCS#8 and RNG in one crate, BoringSSL
  assembly, and its RSA/ECDSA verification API accepts the raw SubjectPublicKey bits straight out
  of the certificate. Limitations hit: no SEC1 `EC PRIVATE KEY` parsing (needs PKCS#8), no P-384
  with SHA-512, RSA keys must be ≥2048 bits.
- `RsaKeyPair::from_pkcs8` is 0.03 ms; RSA-2048 signing is ~0.35 ms each and is now the floor
  for the tiny-APK case. EC P-256 keys bring the in-process total down to ~0.15 ms.

### 10.4 JKS keystores and batch signing (same day, later)

- **JKS is small.** OpenJDK's `JavaKeyStore` format plus the `KeyProtector` SHA-1 keystream cipher
  is ~150 lines on top of `ring`'s legacy SHA-1; no new crate. Validated empirically: apksigner
  signing with `--ks rsa.jks` and fastsigner signing with the same store produce **identical
  files**. Store password (integrity hash) and key password (key decryption) are handled
  separately, aliases are matched lower-cased as Java does, entries come out in Hashtable order.
- **Gotcha: JDK 9+ `keytool` writes PKCS#12 by default**, even when the file is called `.jks`.
  The `test.jks` from the §1 baseline was in fact PKCS#12. fastsigner sniffs the magic
  (`FEEDFEED` JKS, `CECECECE` JCEKS, `30 82` PKCS#12) and refuses non-JKS stores with a
  conversion hint instead of misreading them.
- **PKCS#12 (added 2026-09-23).** `src/pkcs12.rs`, ~450 lines incl. tests, on `ring` (HMAC,
  PBKDF2, digests) + RustCrypto `aes`/`cbc` (no default features; PKCS#7 unpadding by hand).
  Scope: PBES2/PBKDF2/AES-CBC, i.e. JDK 12+ keytool and OpenSSL 3 defaults; legacy PBE
  (3DES/RC2/RC4) is refused by name. Findings: the MAC key is the RFC 7292 B.2 KDF over the
  BMPString password *with* its trailing 00 00, while PBKDF2 takes plain UTF-8. `openssl kdf
  PKCS12KDF` takes raw bytes, so its vectors check the KDF core only (`hexpass:` reproduces the
  RFC "smeg" vector). keytool encrypts the cert bag too, so a wrong store password with no MAC
  shows up as a padding failure. Keys pair with certs by `localKeyId`, and chains are rebuilt
  leaf-first by issuer → subject. Output is byte-identical to `apksigner --ks` for keytool,
  OpenSSL and CA-chain stores. Cost: +2.5 ms per process (0.8 → 3.3 ms on tiny) for 3 × 10 000
  KDF iterations; the binary grows ~80 KB.
- **Java's EC keys omit the public key** from the PKCS#8 `ECPrivateKey`, which `ring`'s parser
  requires. Fix: pull the scalar out of the DER and rebuild the pair with the certificate's public
  point (`from_private_key_and_public_key`). The same path makes SEC1 `EC PRIVATE KEY` PEMs work.
- **Batch mode.** N inputs, `--jobs` concurrent APKs (default min(N, physical cores)), each with
  `cores/jobs` digest threads, one shared key. Wall time, best of 5:

  | batch | `--jobs 1` | default | why |
  |---|---:|---:|---|
  | 8 × small | 8.6 ms | **2.6 ms** | per-APK serial phases (parse, sign, write, spawn) overlap |
  | 3 × big | 18.5 ms | **16.6 ms** | already CPU-bound on SHA; only the serial parts overlap |

  Small APKs are latency-bound, so this is where batch mode pays; big ones are throughput-bound and
  gain little. `--out` is single-input, `--out-dir` maps by file name, in place is the default.

### 10.5 zipalign (2026-09-22)

- **The check is free.** Alignment needs every stored entry's local-header lengths, i.e. ~15k
  30-byte reads spread over 145 MB — 10+ ms of `pread`s or a new `mmap` dependency if done
  separately. Instead the digest workers hand each 1 MiB chunk to an inspector that binary-
  searches the sorted header offsets and parses the headers inside the chunk (headers straddling
  a chunk boundary are re-read afterwards; there are at most a handful). Measured fast-path cost:
  +0.1–0.6 ms across tiny…big. Every APK in the local corpus is already aligned (16 KiB `.so`
  in WhatsApp), so this is the path that runs in practice.
- **Rewrite = apksig, byte for byte.** apksigner already re-aligns when it rewrites an APK, so
  its output is the oracle for ours. Mirroring `ApkSigner.sign` step 3 exactly — `0xd935`
  alignment field per stored entry (`createExtraFieldToAlignData`, dropping old `0xd935`
  fields and zipalign's `id=0,size=0` zero padding), directory entries and v1 files dropped,
  `stamp-cert-sha256` / `pinlist.meta` left as unprocessed bytes, unprocessed gaps *and the
  bytes after the last record* copied verbatim — makes fastsigner's output identical to
  apksigner's on all 100 local corpus APKs rebuilt unaligned with Python's `zipfile`
  (`tests/corpus_identity.sh`; 8 tiny language splits came out aligned by chance and were
  forced through the rewrite with `--zipalign always`, which is apksigner's default behaviour). Two quirks had to be copied to get there: apksig keeps the
  orphaned local record of a dropped source-stamp entry, and copies whatever trails the last
  record. Directory entries are now dropped on the fast path too, so both paths produce
  apksigner's entry set.
- **Rule differences, on purpose:** the *check* uses zipalign's rule (4 / page size by
  extension) so `zipalign -c -P 16 4` passes; the *rewrite* uses
  `max(rule, declared 0xd935 alignment)` where apksig uses the declared value alone. A `.so`
  declared 4096 is therefore re-aligned to 16 KiB by us and kept at 4096 by apksigner.
- **ext4 replace-via-rename costs 30 ms.** Writing the rewritten APK to a temp file and
  `rename()`-ing it over the original triggers `auto_da_alloc`, which flushes the new file's
  delayed-allocation blocks: 28.6 ms for 145 MB, ~10 ms floor even for 3 MB.
  `renameat2(RENAME_EXCHANGE)` + unlink is 3.2 ms and still atomic. glibc exports it, no crate.
- **Rewrite-path cost:** unaligned small 3.4 ms, unaligned big 34 ms in place (parallel copy
  ~18 ms + second digest 6 ms), vs ~600 ms for `zipalign` + `apksigner`. A patch → sign loop
  that rebuilds the ZIP with an unaligned writer lands here every time, so it matters.
  Improved to **1.9 ms / 28 ms** the next day, see §10.6.

### 10.6 Digest-during-rewrite, and what the kernel allows (2026-09-22)

Goal: fold the second digest pass (6 ms on big) into the rewrite copy. The output offsets are
known before any byte is copied, so a worker can materialise output chunk *k* = `[k MiB,
(k+1) MiB)` from the plan, write it, and hash it — the output chunks are exactly the v2/v3
digest chunks. Straightforward; the surprises were all in the write path.

| variant (big, unaligned, in place) | rewrite+digest | why |
|---|---:|---|
| before: group copy, then re-read + digest | 26 ms | 20 ms copy + 6 ms digest |
| fused, 16 threads, dynamic chunks | 29–32 ms | slower! |
| fused, static per-thread ranges + pre-sized file | 29–35 ms | no help |
| fused, output via `mmap(MAP_SHARED)` + `MADV_POPULATE_WRITE` | 34–38 ms | worse |
| fused, userspace mutex around `pwrite` | 29–32 ms | writer slowed by 15 competing threads |
| **fused, 1 writer thread + 6 producers over a channel** | **~26 ms** (total 28) | writer-bound |

What the per-phase counters showed (`--timing` prints them, thread-summed):
- **ext4 serialises buffered writes to one inode** (`i_rwsem`). One thread writes 145 MB into a
  fresh file in 15.6 ms; 16 threads spend 250–340 ms *combined* in `pwrite` — all but one are
  waiting, and kernel rwsem waiters *spin*, stealing the CPU the hashing needs. That is why the
  fused pass lost to the old two-pass version.
- **mmap does not escape it**: page-cache population through write faults (`page_mkwrite`, block
  reservation per page) serialises just the same, 300+ ms thread-summed.
- A userspace mutex makes waiters sleep, but the in-lock write time itself grows from 16.5 ms
  (2 threads) to 27 ms (16 threads): memory contention from the other threads slows the single
  writer. Fewer, busier threads are better here — the opposite of the digest engine.
- **Dedicated writer + few producers** is the design that fits: the writer streams at its
  ~7 GB/s limit undisturbed (20–23 ms for 145 MB, independent of 3–6 producers), producers
  (read window + assemble + hash ≈ 0.6 ms per chunk) hide behind it. Buffers travel over
  channels, two per producer, so nothing is ever copied twice.
- **Do not digest what you are about to throw away.** In the check path the input was digested
  (6 ms) only to discover it was misaligned. A 16-entry header sample (≤16 `pread`s, ~30 µs)
  proves misalignment for any ZIP written without padding and lets the rewrite start at once.
  A sample that passes falls back to the full inspector-on-digest check, so nothing is lost.

Net: unaligned big 33.6 → **27.5 ms** in place, unaligned small 3.4 → **1.9 ms**; fast path and
byte identity with apksigner unchanged (100/100 corpus). The remaining 21 ms on big is the
kernel's page-cache write; only larger folios in ext4 or a different filesystem move it.

### 10.7 Speed pass (2026-09-23)

Profiled a fresh process per run (that is how the tool is used), on ext4, warm page cache,
timing spawn to exit with `bench/runbench.c` (`date` in a shell adds ~1.5 ms, more than a small
APK takes). Before → after, median, RSA-2048:

| | tiny | small | med | big |
|---|---:|---:|---:|---:|
| in place, pk8 key | 0.75 → **0.63** | 1.71 → **1.17** | 4.46 → **2.96** | 7.67 → **5.03** ms |
| in place, PKCS#12 (keytool) | 3.01 → **1.35** | 3.98 → **1.40** | 6.95 → **3.02** | 10.09 → **5.18** ms |
| `--out`, output exists | 0.81 → **0.66** | 2.13 → **1.30** | 23.6 → **11.0** | 50.7 → **25.4** ms |
| batch, default jobs | | 8 × small 3.2 → **2.0** | | 3 × big 17.5 → **12.6** ms |

Where the time went on `big.apk` before: parse 0.7 ms, digest 6.0 ms, sign 0.4 ms, write 0.2 ms.

**SHA-256, two messages per core.** `sha256rnds2` has ~4 cycles of latency, and one message is a
single chain of 32 of them per block: 2.8 GB/s per core, ring and a hand-written SHA-NI loop
alike. Interleaving two independent messages in one thread (the kernel's `sha256_ni_finup2x`
idea) gives 4.1 GB/s on one core and 55.8 GB/s on 16 (in cache; 32.6 GB/s one stream each).
The v2 digest is made of independent 1 MiB chunks, so each worker keeps two in flight
("lanes") and refills a lane from the shared counter as soon as its chunk ends. It takes a
second chunk only while at least `threads` chunks remain; when chunks run short, one chunk per
core at 1-way speed beats two on one core (small APKs have 4–6 chunks). Single-thread digest of
`big.apk`: 57 → 40 ms.

**The fresh-process tax was bigger than the hashing.** The same pread design measured 4.2 ms in a
warm loop but 5.5–6.5 ms in a new process: workers started 430 µs late (130 µs when warm),
most likely because each one mapped and faulted in a fresh 1 MiB buffer while the main thread
was still mapping thread stacks, all of which takes `mmap_lock`. Hashing straight out of an `mmap` of the APK
removes the buffers and the copy (`src/mmap.rs`, two libc calls, no crate).

**…but `munmap` of a fully faulted 145 MB mapping costs 0.4–0.7 ms on ext4 and 1.1–3.2 ms on
tmpfs**, serially, at the end (per-page rmap work; tmpfs has 4 KiB pages here, ext4 is cheaper,
presumably thanks to large folios). Fix: each worker `madvise(MADV_DONTNEED)`s its chunk after hashing it, which
spreads the teardown over the threads while they run; the final `munmap` is ~free. Fresh-process
digest of `big.apk` (ext4): pread + ring 5.3–5.6 ms → mmap + lanes 4.0–4.2 → + DONTNEED
**3.5 ms**. `pread` into two 64 KiB windows per lane is within 5% (64 KiB beat 16–256 KiB);
mmap won because the parse can then borrow the central directory instead of copying it.

**Floors.** Page cache → user memory tops out at ~67 GB/s here (4 threads of `pread`), so
reading 145 MB costs ≥2.2 ms; we are at 3.5 ms including thread start-up (~12 µs per spawn on
the spawning thread, ~50 µs before the first one runs) and the 1-way tail. Cold cache: ~26 ms for
`big.apk` before and after — the NVMe (~5 GB/s for one sequential reader) is the limit.

**Parse: 0.7 → 0.25 ms.** `filter_cd` took 0.5 ms for 15k entries, nearly all of it faulting in
fresh ~1 MB vectors (entry list grown without a size hint, a filtered copy of the CD, a second
parse for the zipalign check). Now the entry vector is reserved (`cd.len() / 46`), the CD is
borrowed from the mapping when nothing is dropped, and the kept entries come out of the single
parse. The rewrite path re-parses the full CD itself; it is 20+ ms anyway.

**Writing.** In place, re-signing an already signed APK usually leaves the CD and EOCD where and
as they were: compare, and write only the padded block (4 KB instead of 869 KB). One bug on the
way, caught by `differential.sh` and now a unit test: with the CD borrowed from the mapping, the
new block can land on the old CD, which then has to be copied out *before* the block is written.
For `--out`, the head (all of the entries) is copied with `copy_file_range` on its own thread while
the digest runs — 17 ms for 145 MB on ext4; writing from the mapping was slower (22 ms), and
tmpfs does ~4.5 GB/s either way — into a temp file that is swapped in with
`renameat2(RENAME_EXCHANGE)` (§10.5). The old code copied after the digest, and truncating and
rewriting an existing 145 MB output cost it ~25 ms more than a fresh one: 50.7 → 25.4 ms.

**PKCS#12: 2.5 → ~0.7 ms, and mostly hidden.** Per 10 000 iterations: PBKDF2-HMAC-SHA256 0.91 ms
in ring, 0.67 ms with the pads absorbed once and two compressions per iteration on SHA-NI; the
RFC 7292 MAC KDF 0.33 ms. The MAC, each encrypted SafeContents and each key the request can
select are independent, so they run on their own threads (the MAC first, and its verdict is
still reported first). The whole key load then runs on a thread of its own while the first APK
is parsed and digested; the digest assumes SHA-256 (every key but RSA > 3072 bits) and is redone
once if the key says SHA-512 (checked: RSA-4096 store, byte-identical to apksigner). Key files
and JKS stores still load inline: ~40 µs, less than starting a thread.

**Process start.** Static glibc (`.cargo/config.toml`) saves 0.12 ms of dynamic loading per
run (binary 1 → 2 MB). `available_parallelism()` reads ~6 cgroup files (~30 µs) and the sysfs
SMT width another ~6 µs; both are now only read when an APK has more than one chunk's worth of
work.

**Tried, no gain:**
- More threads than cores: 24 digest threads are 6–8% faster than 16 on one med/big APK (the
  1-way tail is shared with SMT siblings), 32 in between; but 8 × small in a batch gets 10%
  slower. Default left at physical cores; `--threads` is there.
- Starting the v3 signer thread before the digest (so its start-up overlaps): waking it from
  its channel costs what spawning it did. Reverted.
- `MADV_HUGEPAGE` on the mapping (no PMD mappings of ext4 page cache here), `MAP_POPULATE`
  (serial, slower), a single malloc arena (`glibc.malloc.arena_max=1`, within noise).
- Remaining big item not done: RSA-2048 signing is 330 µs in ring vs 159 µs in OpenSSL 3.5
  (AVX-512 IFMA, `openssl speed rsa2048`), i.e. half of the tiny-APK time. Closing it means a
  heavyweight dependency (aws-lc-rs) or hand-written constant-time IFMA Montgomery arithmetic.

### 10.8 Open items (in the order worth doing)

1. Install a fastsigner-signed, v2+v3-only, minSdk<24 APK on the API 36 AVD (§6.1 open test).
2. ~~PKCS#12 keystores~~ — done 2026-09-23 (modern PBES2 only; legacy 3DES/RC2 refused).
3. Per-chunk digest cache for the patch → re-sign loop (§8) — 3.5 ms → sub-millisecond on big
   (fast path only; the rewrite path is write-bound, see §10.6). Only same-size patches keep the
   chunk boundaries: any size change shifts every later 1 MiB chunk.
4. Faster RSA-2048 signing (§10.7): the floor for small APKs.
5. v3.1 / lineage if rotation is ever needed; Zip64; v4 `.idsig` for `adb install --incremental`.
