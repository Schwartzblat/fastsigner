//! SHA-256 on the x86 SHA extensions, for the two places where fastsigner hashes in bulk: the
//! v2/v3 content digest (many independent 1 MiB chunks) and PKCS#12 key derivation (tens of
//! thousands of one-block hashes).
//!
//! ring's SHA-256 (BoringSSL assembly) already uses SHA-NI, but one message at a time, and that is
//! bound by the latency of `sha256rnds2` rather than by the SHA unit's throughput. Two independent
//! messages interleaved in one thread (`compress2`) fill the gaps: on a Ryzen 9 9950X one core does
//! 2.8 GB/s for one stream and 4.1 GB/s for two. The idea is the kernel's `sha256_ni_finup2x`.
//!
//! Callers get a `ShaNi` token only when the CPU has the extensions; everything else falls back
//! to ring. Every entry point is checked against ring in the tests below.

/// Initial hash value (FIPS 180-4 §5.3.3).
pub const H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// Proof that the CPU supports SHA-NI (plus the SSE levels the kernels use).
#[derive(Clone, Copy)]
pub struct ShaNi(());

impl ShaNi {
    pub fn detect() -> Option<ShaNi> {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("sse4.1") && std::is_x86_feature_detected!("ssse3") {
            return Some(ShaNi(()));
        }
        None
    }

    /// Absorb whole 64-byte blocks.
    pub fn compress(self, state: &mut [u32; 8], blocks: &[u8]) {
        assert_eq!(blocks.len() % 64, 0);
        // SAFETY: `self` exists only if the CPU has SHA-NI, SSSE3 and SSE4.1; the pointer covers
        // `blocks.len() / 64` whole blocks.
        unsafe { x86::compress1(state, blocks.as_ptr(), blocks.len() / 64) }
    }

    /// Absorb the same number of whole blocks into two independent states, interleaved.
    pub fn compress2(self, a: &mut [u32; 8], b: &mut [u32; 8], da: &[u8], db: &[u8]) {
        assert!(da.len() == db.len() && da.len() % 64 == 0);
        // SAFETY: as in `compress`, for both inputs.
        unsafe { x86::compress2(a, b, da.as_ptr(), db.as_ptr(), da.len() / 64) }
    }

    /// `H^n(x)` for a 32-byte `x`: every step is a single block (RFC 7292 KDF iterations).
    pub fn iterate(self, mut x: [u8; 32], n: u32) -> [u8; 32] {
        let mut block = [0u8; 64];
        block[32] = 0x80;
        block[62..].copy_from_slice(&256u16.to_be_bytes());
        for _ in 0..n {
            block[..32].copy_from_slice(&x);
            let mut s = H0;
            self.compress(&mut s, &block);
            x = state_bytes(&s);
        }
        x
    }

    /// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2). With the HMAC pads absorbed once, each iteration is
    /// exactly two compressions.
    pub fn pbkdf2_hmac_sha256(self, password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        let mut key = [0u8; 64];
        if password.len() > 64 {
            key[..32].copy_from_slice(&Sha256::digest(self, password));
        } else {
            key[..password.len()].copy_from_slice(password);
        }
        let (mut inner, mut outer) = (H0, H0);
        self.compress(&mut inner, &key.map(|b| b ^ 0x36));
        self.compress(&mut outer, &key.map(|b| b ^ 0x5c));
        // U_j = HMAC(U_{j-1}): 32 message bytes after the 64-byte pad block, so 768 bits in all.
        let mut block = [0u8; 64];
        block[32] = 0x80;
        block[62..].copy_from_slice(&768u16.to_be_bytes());
        for (i, t_out) in out.chunks_mut(32).enumerate() {
            let mut h = Sha256 { state: inner, buf: [0; 64], buf_len: 0, len: 64, shani: self };
            h.update(salt);
            h.update(&(i as u32 + 1).to_be_bytes());
            let mut h2 = Sha256 { state: outer, buf: [0; 64], buf_len: 0, len: 64, shani: self };
            h2.update(&h.finish());
            let mut u = h2.finish();
            let mut t = u;
            for _ in 1..iterations {
                block[..32].copy_from_slice(&u);
                let mut s = inner;
                self.compress(&mut s, &block);
                block[..32].copy_from_slice(&state_bytes(&s));
                let mut s = outer;
                self.compress(&mut s, &block);
                u = state_bytes(&s);
                t.iter_mut().zip(u).for_each(|(t, u)| *t ^= u);
            }
            t_out.copy_from_slice(&t[..t_out.len()]);
        }
    }
}

fn state_bytes(s: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, w) in out.chunks_exact_mut(4).zip(s) {
        o.copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// Streaming SHA-256 on SHA-NI.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    len: u64,
    shani: ShaNi,
}

impl Sha256 {
    pub fn new(shani: ShaNi) -> Sha256 {
        Sha256 { state: H0, buf: [0; 64], buf_len: 0, len: 0, shani }
    }

    pub fn digest(shani: ShaNi, data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new(shani);
        h.update(data);
        h.finish()
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            self.shani.compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        let whole = data.len() & !63;
        self.shani.compress(&mut self.state, &data[..whole]);
        self.buf[..data.len() - whole].copy_from_slice(&data[whole..]);
        self.buf_len = data.len() - whole;
    }

    /// Bytes still needed to complete the buffered partial block; 0 at a block boundary, where
    /// whole blocks may go straight to `update2`.
    pub fn gap(&self) -> usize {
        (64 - self.buf_len) % 64
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len * 8;
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let zeros = (55usize.wrapping_sub(self.buf_len)) % 64;
        pad[1 + zeros..9 + zeros].copy_from_slice(&bits.to_be_bytes());
        self.update(&pad[..9 + zeros]);
        debug_assert_eq!(self.buf_len, 0);
        state_bytes(&self.state)
    }
}

/// Absorb `da` and `db` (equal length, whole blocks) into two hashers that are both at a block
/// boundary, two blocks at a time.
pub fn update2(a: &mut Sha256, b: &mut Sha256, da: &[u8], db: &[u8]) {
    debug_assert!(a.gap() == 0 && b.gap() == 0);
    a.shani.compress2(&mut a.state, &mut b.state, da, db);
    a.len += da.len() as u64;
    b.len += db.len() as u64;
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::arch::x86_64::*;

    #[rustfmt::skip]
    static K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    /// Round constants for quad-round `i`.
    #[inline(always)]
    unsafe fn k(i: usize) -> __m128i {
        _mm_loadu_si128(K.as_ptr().add(4 * i) as *const __m128i)
    }

    /// Message words 4i..4i+4 of the block at `p`, big-endian.
    #[inline(always)]
    unsafe fn load(p: *const u8, i: usize) -> __m128i {
        let bswap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b, 0x0405_0607_0001_0203);
        _mm_shuffle_epi8(_mm_loadu_si128(p.add(16 * i) as *const __m128i), bswap)
    }

    /// The state in the ABEF / CDGH register layout `sha256rnds2` works on.
    #[inline(always)]
    unsafe fn to_regs(s: &[u32; 8]) -> (__m128i, __m128i) {
        let dcba = _mm_loadu_si128(s.as_ptr() as *const __m128i);
        let hgfe = _mm_loadu_si128(s.as_ptr().add(4) as *const __m128i);
        let cdab = _mm_shuffle_epi32(dcba, 0xb1);
        let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
        (_mm_alignr_epi8(cdab, efgh, 8), _mm_blend_epi16(efgh, cdab, 0xf0))
    }

    #[inline(always)]
    unsafe fn from_regs(abef: __m128i, cdgh: __m128i, s: &mut [u32; 8]) {
        let feba = _mm_shuffle_epi32(abef, 0x1b);
        let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
        _mm_storeu_si128(s.as_mut_ptr() as *mut __m128i, _mm_blend_epi16(feba, dchg, 0xf0));
        _mm_storeu_si128(s.as_mut_ptr().add(4) as *mut __m128i, _mm_alignr_epi8(dchg, feba, 8));
    }

    /// Four rounds with message words `w` (+ constants of quad-round `i`).
    macro_rules! rounds4 {
        ($abef:ident, $cdgh:ident, $w:expr, $i:expr) => {{
            let t = _mm_add_epi32($w, k($i));
            $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t);
            $abef = _mm_sha256rnds2_epu32($abef, $cdgh, _mm_shuffle_epi32(t, 0x0e));
        }};
    }

    /// The next four message words from the previous sixteen.
    macro_rules! schedule {
        ($w0:expr, $w1:expr, $w2:expr, $w3:expr) => {
            _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32($w0, $w1), _mm_alignr_epi8($w3, $w2, 4)), $w3)
        };
    }

    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress1(state: &mut [u32; 8], mut p: *const u8, blocks: usize) {
        let (mut abef, mut cdgh) = to_regs(state);
        for _ in 0..blocks {
            let (abef0, cdgh0) = (abef, cdgh);
            let (mut w0, mut w1, mut w2, mut w3) = (load(p, 0), load(p, 1), load(p, 2), load(p, 3));
            rounds4!(abef, cdgh, w0, 0);
            rounds4!(abef, cdgh, w1, 1);
            rounds4!(abef, cdgh, w2, 2);
            rounds4!(abef, cdgh, w3, 3);
            for i in (4..16).step_by(4) {
                w0 = schedule!(w0, w1, w2, w3);
                rounds4!(abef, cdgh, w0, i);
                w1 = schedule!(w1, w2, w3, w0);
                rounds4!(abef, cdgh, w1, i + 1);
                w2 = schedule!(w2, w3, w0, w1);
                rounds4!(abef, cdgh, w2, i + 2);
                w3 = schedule!(w3, w0, w1, w2);
                rounds4!(abef, cdgh, w3, i + 3);
            }
            abef = _mm_add_epi32(abef, abef0);
            cdgh = _mm_add_epi32(cdgh, cdgh0);
            p = p.add(64);
        }
        from_regs(abef, cdgh, state);
    }

    /// `compress1` for two independent streams, every step issued for both.
    #[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
    pub unsafe fn compress2(sa: &mut [u32; 8], sb: &mut [u32; 8], mut pa: *const u8, mut pb: *const u8, blocks: usize) {
        let (mut abef_a, mut cdgh_a) = to_regs(sa);
        let (mut abef_b, mut cdgh_b) = to_regs(sb);
        for _ in 0..blocks {
            let (abef_a0, cdgh_a0, abef_b0, cdgh_b0) = (abef_a, cdgh_a, abef_b, cdgh_b);
            let (mut a0, mut a1, mut a2, mut a3) = (load(pa, 0), load(pa, 1), load(pa, 2), load(pa, 3));
            let (mut b0, mut b1, mut b2, mut b3) = (load(pb, 0), load(pb, 1), load(pb, 2), load(pb, 3));
            rounds4!(abef_a, cdgh_a, a0, 0);
            rounds4!(abef_b, cdgh_b, b0, 0);
            rounds4!(abef_a, cdgh_a, a1, 1);
            rounds4!(abef_b, cdgh_b, b1, 1);
            rounds4!(abef_a, cdgh_a, a2, 2);
            rounds4!(abef_b, cdgh_b, b2, 2);
            rounds4!(abef_a, cdgh_a, a3, 3);
            rounds4!(abef_b, cdgh_b, b3, 3);
            for i in (4..16).step_by(4) {
                a0 = schedule!(a0, a1, a2, a3);
                b0 = schedule!(b0, b1, b2, b3);
                rounds4!(abef_a, cdgh_a, a0, i);
                rounds4!(abef_b, cdgh_b, b0, i);
                a1 = schedule!(a1, a2, a3, a0);
                b1 = schedule!(b1, b2, b3, b0);
                rounds4!(abef_a, cdgh_a, a1, i + 1);
                rounds4!(abef_b, cdgh_b, b1, i + 1);
                a2 = schedule!(a2, a3, a0, a1);
                b2 = schedule!(b2, b3, b0, b1);
                rounds4!(abef_a, cdgh_a, a2, i + 2);
                rounds4!(abef_b, cdgh_b, b2, i + 2);
                a3 = schedule!(a3, a0, a1, a2);
                b3 = schedule!(b3, b0, b1, b2);
                rounds4!(abef_a, cdgh_a, a3, i + 3);
                rounds4!(abef_b, cdgh_b, b3, i + 3);
            }
            abef_a = _mm_add_epi32(abef_a, abef_a0);
            cdgh_a = _mm_add_epi32(cdgh_a, cdgh_a0);
            abef_b = _mm_add_epi32(abef_b, abef_b0);
            cdgh_b = _mm_add_epi32(cdgh_b, cdgh_b0);
            pa = pa.add(64);
            pb = pb.add(64);
        }
        from_regs(abef_a, cdgh_a, sa);
        from_regs(abef_b, cdgh_b, sb);
    }
}

/// `ShaNi::detect` never succeeds elsewhere, so these are unreachable.
#[cfg(not(target_arch = "x86_64"))]
mod x86 {
    pub unsafe fn compress1(_: &mut [u32; 8], _: *const u8, _: usize) {
        unreachable!()
    }
    pub unsafe fn compress2(_: &mut [u32; 8], _: &mut [u32; 8], _: *const u8, _: *const u8, _: usize) {
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::digest::{digest, SHA256};

    fn pattern(n: usize, seed: u32) -> Vec<u8> {
        (0..n as u32).map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 13) as u8).collect()
    }

    #[test]
    fn streaming_matches_ring_at_every_boundary() {
        let Some(ni) = ShaNi::detect() else { return };
        let data = pattern(70_000, 1);
        for len in (0..300).chain([1000, 4095, 4096, 4097, 65_535, 65_536, 70_000]) {
            let d = &data[..len];
            assert_eq!(Sha256::digest(ni, d), digest(&SHA256, d).as_ref(), "len {len}");
            // odd split points exercise the partial-block buffer
            for split in [0, 1, 5, 63, 64, 65, len / 2] {
                let split = split.min(len);
                let mut h = Sha256::new(ni);
                h.update(&d[..split]);
                h.update(&d[split..]);
                assert_eq!(h.finish(), digest(&SHA256, d).as_ref(), "len {len} split {split}");
            }
        }
    }

    #[test]
    fn two_way_matches_one_way() {
        let Some(ni) = ShaNi::detect() else { return };
        let a = pattern(64 * 300 + 17, 2);
        let b = pattern(64 * 300 + 40, 3);
        let (mut ha, mut hb) = (Sha256::new(ni), Sha256::new(ni));
        ha.update(&a[..3]);
        hb.update(&b[..3]);
        ha.update(&a[3..64]);
        hb.update(&b[3..64]);
        update2(&mut ha, &mut hb, &a[64..64 * 257], &b[64..64 * 257]);
        ha.update(&a[64 * 257..]);
        hb.update(&b[64 * 257..]);
        assert_eq!(ha.finish(), digest(&SHA256, &a).as_ref());
        assert_eq!(hb.finish(), digest(&SHA256, &b).as_ref());
    }

    #[test]
    fn iterate_matches_repeated_ring_digests() {
        let Some(ni) = ShaNi::detect() else { return };
        let mut want: [u8; 32] = digest(&SHA256, b"seed").as_ref().try_into().unwrap();
        let start = want;
        for _ in 0..1000 {
            want = digest(&SHA256, &want).as_ref().try_into().unwrap();
        }
        assert_eq!(ni.iterate(start, 1000), want);
        assert_eq!(ni.iterate(start, 0), start);
    }

    #[test]
    fn pbkdf2_matches_ring() {
        let Some(ni) = ShaNi::detect() else { return };
        let long_pw = pattern(100, 4);
        for (pw, salt, iters, len) in [
            (&b"android"[..], &b"saltsalt"[..], 1u32, 32usize),
            (b"android", b"0123456789abcdef", 10_000, 32),
            (b"", b"s", 2, 16),
            (b"p", &[0u8; 70][..], 3, 24),
            (&long_pw[..], b"salt", 5, 70), // hashed HMAC key, multi-block output
        ] {
            let mut want = vec![0u8; len];
            ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, iters.try_into().unwrap(), salt, pw, &mut want);
            let mut got = vec![0u8; len];
            ni.pbkdf2_hmac_sha256(pw, salt, iters, &mut got);
            assert_eq!(got, want, "pw len {} iters {iters} len {len}", pw.len());
        }
    }
}
