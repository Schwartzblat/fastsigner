//! Byte-level encoders for the APK Signature Scheme v2 / v3 blocks and the APK Signing Block.
//! Layouts are taken from apksig's V2SchemeSigner / V3SchemeSigner / ApkSigningBlockUtils and
//! were checked against apksigner 37.0.0 output (see KNOWLEDGE.md §3 and the design spec).

pub const V2_BLOCK_ID: u32 = 0x7109871a;
pub const V3_BLOCK_ID: u32 = 0xf05368c0;
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x42726577;
pub const STRIPPING_PROTECTION_ATTR_ID: u32 = 0xbeeff00d;
pub const SCHEME_V3_VERSION: u32 = 3;
pub const PAGE_ALIGNMENT: u64 = 4096;
pub const APK_SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// v3 signer SDK range. apksig uses the signature algorithm's own min SDK (N = 24 for every
/// non-verity algorithm) and Integer.MAX_VALUE.
pub const V3_MIN_SDK: u32 = 24;
pub const V3_MAX_SDK: u32 = 0x7fff_ffff;

pub struct SignerInput<'a> {
    pub alg_id: u32,
    pub digest: &'a [u8],
    pub certs: &'a [Vec<u8>],
    pub spki: &'a [u8],
}

fn put_u32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn put_lp(v: &mut Vec<u8>, b: &[u8]) {
    put_u32(v, b.len() as u32);
    v.extend_from_slice(b);
}

/// apksig `encodeAsSequenceOfLengthPrefixedElements`.
fn seq_lp<'a>(items: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut v = Vec::new();
    for it in items {
        put_lp(&mut v, it);
    }
    v
}

/// apksig `encodeAsSequenceOfLengthPrefixedPairsOfIntAndLengthPrefixedBytes`:
/// repeated { u32 len; u32 id; u32 value_len; value }.
fn seq_lp_pairs<'a>(pairs: impl IntoIterator<Item = (u32, &'a [u8])>) -> Vec<u8> {
    let mut v = Vec::new();
    for (id, b) in pairs {
        put_u32(&mut v, 8 + b.len() as u32);
        put_u32(&mut v, id);
        put_lp(&mut v, b);
    }
    v
}

/// v2 additional attributes: the stripping-protection attribute when v3 is also present.
fn v2_additional_attributes(v3_enabled: bool) -> Vec<u8> {
    if !v3_enabled {
        return Vec::new();
    }
    let mut v = Vec::with_capacity(12);
    put_u32(&mut v, 8);
    put_u32(&mut v, STRIPPING_PROTECTION_ATTR_ID);
    put_u32(&mut v, SCHEME_V3_VERSION);
    v
}

/// One v2 signer: lp(signed data) || lp(signatures) || lp(public key).
pub fn v2_signer(
    inp: &SignerInput,
    v3_enabled: bool,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let digests = seq_lp_pairs([(inp.alg_id, inp.digest)]);
    let certs = seq_lp(inp.certs.iter().map(|c| c.as_slice()));
    let attrs = v2_additional_attributes(v3_enabled);
    // apksig appends an empty fourth element; verifiers ignore it but we reproduce it exactly.
    let signed_data = seq_lp([digests.as_slice(), certs.as_slice(), attrs.as_slice(), &[]]);
    let signature = sign(&signed_data)?;
    let signatures = seq_lp_pairs([(inp.alg_id, signature.as_slice())]);
    Ok(seq_lp([signed_data.as_slice(), signatures.as_slice(), inp.spki]))
}

/// One v3 signer:
/// lp(signed data) || u32 minSdk || u32 maxSdk || lp(signatures) || lp(public key)
/// where signed data = lp(digests) || lp(certs) || u32 minSdk || u32 maxSdk || lp(attrs).
pub fn v3_signer(
    inp: &SignerInput,
    min_sdk: u32,
    max_sdk: u32,
    sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let digests = seq_lp_pairs([(inp.alg_id, inp.digest)]);
    let certs = seq_lp(inp.certs.iter().map(|c| c.as_slice()));
    let attrs: Vec<u8> = Vec::new(); // no lineage / rotation attributes in the PoC
    let mut signed_data = Vec::new();
    put_lp(&mut signed_data, &digests);
    put_lp(&mut signed_data, &certs);
    put_u32(&mut signed_data, min_sdk);
    put_u32(&mut signed_data, max_sdk);
    put_lp(&mut signed_data, &attrs);

    let signature = sign(&signed_data)?;
    let signatures = seq_lp_pairs([(inp.alg_id, signature.as_slice())]);

    let mut out = Vec::new();
    put_lp(&mut out, &signed_data);
    put_u32(&mut out, min_sdk);
    put_u32(&mut out, max_sdk);
    put_lp(&mut out, &signatures);
    put_lp(&mut out, inp.spki);
    Ok(out)
}

/// Scheme block value (v2 or v3): lp( lp(signer)... ).
pub fn scheme_block(signers: &[Vec<u8>]) -> Vec<u8> {
    let inner = seq_lp(signers.iter().map(|s| s.as_slice()));
    seq_lp([inner.as_slice()])
}

/// Size the APK Signing Block will have for the given (id, value) pairs, including the verity
/// padding pair that makes the total a multiple of 4096.
pub fn signing_block_size(pairs: &[(u32, Vec<u8>)]) -> u64 {
    let mut size: u64 = 8 + 8 + 16;
    for (_, v) in pairs {
        size += 8 + 4 + v.len() as u64;
    }
    if size % PAGE_ALIGNMENT != 0 {
        let mut pad = PAGE_ALIGNMENT - size % PAGE_ALIGNMENT;
        if pad < 12 {
            pad += PAGE_ALIGNMENT;
        }
        size += pad;
    }
    size
}

/// APK Signing Block:
/// u64 size || { u64 len, u32 id, value }... || [verity padding pair] || u64 size || magic
pub fn apk_signing_block(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let total = signing_block_size(pairs) as usize;
    let mut v = Vec::with_capacity(total);
    let size_field = (total - 8) as u64;
    v.extend_from_slice(&size_field.to_le_bytes());
    for (id, val) in pairs {
        v.extend_from_slice(&(4 + val.len() as u64).to_le_bytes());
        put_u32(&mut v, *id);
        v.extend_from_slice(val);
    }
    let used = v.len() + 8 + 16;
    if used < total {
        let pad = total - used;
        debug_assert!(pad >= 12);
        v.extend_from_slice(&((pad - 8) as u64).to_le_bytes());
        put_u32(&mut v, VERITY_PADDING_BLOCK_ID);
        v.resize(v.len() + pad - 12, 0);
    }
    v.extend_from_slice(&size_field.to_le_bytes());
    v.extend_from_slice(APK_SIGNING_BLOCK_MAGIC);
    debug_assert_eq!(v.len(), total);
    v
}

/// Zero padding apksig inserts before the signing block so it starts on a 4096 boundary.
pub fn padding_before_block(entries_end: u64) -> u64 {
    (PAGE_ALIGNMENT - entries_end % PAGE_ALIGNMENT) % PAGE_ALIGNMENT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lp_at(b: &[u8], p: usize) -> (&[u8], usize) {
        let n = u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) as usize;
        (&b[p + 4..p + 4 + n], p + 4 + n)
    }

    #[test]
    fn v2_signer_layout_matches_apksigner() {
        let digest = [0x11u8; 32];
        let certs = vec![vec![0x30, 0x03, 0x02, 0x01, 0x05]];
        let spki = [0x30u8, 0x00];
        let inp = SignerInput { alg_id: 0x0103, digest: &digest, certs: &certs, spki: &spki };
        let mut seen = Vec::new();
        let out = v2_signer(&inp, true, |d| {
            seen = d.to_vec();
            Ok(vec![0xAB; 256])
        })
        .unwrap();

        let (signed, p) = lp_at(&out, 0);
        assert_eq!(signed, seen.as_slice(), "signature must be over the signed-data bytes");
        let (sigs, p) = lp_at(&out, p);
        let (pk, p) = lp_at(&out, p);
        assert_eq!(p, out.len());
        assert_eq!(pk, &spki);
        // signatures: one pair { len=8+256, id, lp(sig) }
        assert_eq!(&sigs[..4], &(264u32).to_le_bytes());
        assert_eq!(&sigs[4..8], &0x0103u32.to_le_bytes());
        assert_eq!(&sigs[8..12], &256u32.to_le_bytes());
        assert_eq!(sigs.len(), 12 + 256);

        // signed data: lp(digests) lp(certs) lp(attrs) lp(empty)
        let (digests, q) = lp_at(signed, 0);
        assert_eq!(digests, [&(40u32).to_le_bytes()[..], &0x0103u32.to_le_bytes(), &32u32.to_le_bytes(), &digest].concat());
        let (cs, q) = lp_at(signed, q);
        assert_eq!(cs, [&5u32.to_le_bytes()[..], &certs[0]].concat());
        let (attrs, q) = lp_at(signed, q);
        assert_eq!(attrs, hex("080000000df0efbe03000000"));
        let (empty, q) = lp_at(signed, q);
        assert!(empty.is_empty());
        assert_eq!(q, signed.len(), "exactly four elements, the last one empty");
    }

    #[test]
    fn v2_without_v3_has_empty_attributes() {
        let digest = [0u8; 32];
        let certs = vec![vec![1, 2, 3]];
        let inp = SignerInput { alg_id: 0x0201, digest: &digest, certs: &certs, spki: &[9] };
        let out = v2_signer(&inp, false, |_| Ok(vec![1])).unwrap();
        let (signed, _) = lp_at(&out, 0);
        let (_, q) = lp_at(signed, 0);
        let (_, q) = lp_at(signed, q);
        let (attrs, q) = lp_at(signed, q);
        assert!(attrs.is_empty());
        let (empty, q) = lp_at(signed, q);
        assert!(empty.is_empty());
        assert_eq!(q, signed.len());
    }

    #[test]
    fn v3_signer_layout_matches_apksigner() {
        let digest = [0x22u8; 32];
        let certs = vec![vec![0xAA; 10], vec![0xBB; 3]];
        let spki = [0x30u8, 0x01, 0x00];
        let inp = SignerInput { alg_id: 0x0103, digest: &digest, certs: &certs, spki: &spki };
        let mut seen = Vec::new();
        let out = v3_signer(&inp, V3_MIN_SDK, V3_MAX_SDK, |d| {
            seen = d.to_vec();
            Ok(vec![0xCD; 256])
        })
        .unwrap();

        let (signed, p) = lp_at(&out, 0);
        assert_eq!(signed, seen.as_slice());
        assert_eq!(&out[p..p + 4], &24u32.to_le_bytes());
        assert_eq!(&out[p + 4..p + 8], &0x7fff_ffffu32.to_le_bytes());
        let (sigs, p) = lp_at(&out, p + 8);
        assert_eq!(sigs.len(), 12 + 256);
        let (pk, p) = lp_at(&out, p);
        assert_eq!(pk, &spki);
        assert_eq!(p, out.len());

        let (_digests, q) = lp_at(signed, 0);
        let (cs, q) = lp_at(signed, q);
        assert_eq!(cs.len(), 4 + 10 + 4 + 3);
        assert_eq!(&signed[q..q + 4], &24u32.to_le_bytes());
        assert_eq!(&signed[q + 4..q + 8], &0x7fff_ffffu32.to_le_bytes());
        let (attrs, q) = lp_at(signed, q + 8);
        assert!(attrs.is_empty());
        assert_eq!(q, signed.len());
    }

    #[test]
    fn signing_block_is_page_multiple_with_padding_pair() {
        for len in [0usize, 1, 100, 1463, 4000, 4056, 4060, 4064, 4065, 4096, 9000] {
            let pairs = vec![(V2_BLOCK_ID, vec![0x55; len])];
            let b = apk_signing_block(&pairs);
            assert_eq!(b.len() % 4096, 0, "len={len}");
            assert_eq!(b.len() as u64, signing_block_size(&pairs));
            let size = u64::from_le_bytes(b[..8].try_into().unwrap());
            assert_eq!(size as usize, b.len() - 8);
            assert_eq!(&b[b.len() - 24..b.len() - 16], &b[..8]);
            assert_eq!(&b[b.len() - 16..], APK_SIGNING_BLOCK_MAGIC);
            // walk pairs
            let mut p = 8;
            let end = b.len() - 24;
            let mut ids = Vec::new();
            while p < end {
                let plen = u64::from_le_bytes(b[p..p + 8].try_into().unwrap()) as usize;
                let id = u32::from_le_bytes(b[p + 8..p + 12].try_into().unwrap());
                ids.push((id, plen));
                p += 8 + plen;
            }
            assert_eq!(p, end);
            assert_eq!(ids[0], (V2_BLOCK_ID, 4 + len));
            if ids.len() == 2 {
                assert_eq!(ids[1].0, VERITY_PADDING_BLOCK_ID);
                assert!(ids[1].1 >= 4);
            }
        }
    }

    #[test]
    fn apksigner_reference_sizes() {
        // From testdata/ref_small_rsa.apk: v2 pair len 1463, v3 pair len 1463, pad 1114 → 4096.
        let pairs = vec![(V2_BLOCK_ID, vec![0; 1463 - 4]), (V3_BLOCK_ID, vec![0; 1463 - 4])];
        let b = apk_signing_block(&pairs);
        assert_eq!(b.len(), 4096);
        let pad_pair_off = 8 + (8 + 1463) * 2;
        let pad_len = u64::from_le_bytes(b[pad_pair_off..pad_pair_off + 8].try_into().unwrap());
        assert_eq!(pad_len, 1114);
    }

    #[test]
    fn padding_before_block_math() {
        assert_eq!(padding_before_block(0), 0);
        assert_eq!(padding_before_block(4096), 0);
        assert_eq!(padding_before_block(1), 4095);
        assert_eq!(padding_before_block(4095), 1);
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
