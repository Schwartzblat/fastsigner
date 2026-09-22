//! PKCS#12 (PFX, RFC 7292) keystore reader, limited to what JDK 12+ `keytool` and OpenSSL 3 write
//! by default: PBES2 (PBKDF2 + AES-CBC) shrouded keys and encrypted certificate bags, checked by
//! the PKCS#12-KDF HMAC over the AuthenticatedSafe.
//!
//! ```text
//! PFX ::= SEQUENCE { version 3, authSafe ContentInfo(data), macData MacData OPTIONAL }
//! AuthenticatedSafe ::= SEQUENCE OF ContentInfo           -- data | encryptedData
//! SafeContents ::= SEQUENCE OF SafeBag { bagId, [0] bagValue, SET OF Attribute OPTIONAL }
//! ```
//!
//! Keys pair with certificates by `localKeyId`; the alias is the `friendlyName`, lower-cased as
//! OpenJDK's `PKCS12KeyStore` does. Legacy PKCS#12 PBE (3DES, RC2, RC4) is rejected by name.

use aes::cipher::consts::U16;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use ring::{digest, hmac, pbkdf2};
use std::num::NonZeroU32;

use crate::jks::KeyEntry;
use crate::keys::{cert_issuer_subject, der_header};

const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
const OID_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
const OID_BAG_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01];
const BAG_KEY: u8 = 1;
const BAG_SHROUDED_KEY: u8 = 2;
const BAG_CERT: u8 = 3;
const BAG_SAFE_CONTENTS: u8 = 6;
const OID_LEGACY_PBE_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01];
const OID_X509_CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x16, 0x01];
const OID_FRIENDLY_NAME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x14];
const OID_LOCAL_KEY_ID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x15];
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_PBMAC1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0e];
const OID_HMAC_PREFIX: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02]; // + 7 SHA1, 9 SHA256, 10 SHA384, 11 SHA512
const OID_AES_CBC_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01]; // + 2, 22, 42
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA2_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02]; // + 1 SHA256, 2 SHA384, 3 SHA512
const MAX_NESTING: u32 = 4;

pub struct Pkcs12 {
    pub keys: Vec<KeyEntry>,
}

/// A DER element: tag, contents, and the whole encoding (header included).
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    body: &'a [u8],
    raw: &'a [u8],
}

fn tlv(b: &[u8], p: usize) -> Result<(Tlv<'_>, usize), String> {
    let (tag, s, l) = der_header(b, p)?;
    Ok((Tlv { tag, body: &b[s..s + l], raw: &b[p..s + l] }, s + l))
}

/// The single element `b` must consist of.
fn one<'a>(b: &'a [u8], tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    let (t, _) = tlv(b, 0)?;
    expect_tag(t, tag, what)
}

fn expect_tag<'a>(t: Tlv<'a>, tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    if t.tag != tag {
        return Err(format!("malformed PKCS#12 {what}: expected DER tag {tag:#04x}, found {:#04x}", t.tag));
    }
    Ok(t)
}

fn children(b: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut v = Vec::new();
    let mut p = 0;
    while p < b.len() {
        let (t, next) = tlv(b, p)?;
        v.push(t);
        p = next;
    }
    Ok(v)
}

/// Child `i` of a constructed element, with its expected tag.
fn child<'a>(c: &[Tlv<'a>], i: usize, tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    let t = *c.get(i).ok_or_else(|| format!("malformed PKCS#12 {what}: missing field"))?;
    expect_tag(t, tag, what)
}

/// OCTET STRING contents, also accepting the BER constructed form (a sequence of chunks).
fn octets(t: Tlv) -> Result<Vec<u8>, String> {
    if t.tag & 0x20 == 0 {
        return Ok(t.body.to_vec());
    }
    let mut out = Vec::new();
    for c in children(t.body)? {
        out.extend(octets(c)?);
    }
    Ok(out)
}

fn uint(t: Tlv, what: &str) -> Result<u32, String> {
    let t = expect_tag(t, 0x02, what)?;
    if t.body.first().map_or(true, |&b| b & 0x80 != 0) {
        return Err(format!("malformed PKCS#12 {what}: not a positive INTEGER"));
    }
    let v = t.body.iter().try_fold(0u64, |acc, &b| (acc >> 32 == 0).then_some(acc << 8 | b as u64));
    v.and_then(|v| u32::try_from(v).ok()).ok_or_else(|| format!("PKCS#12 {what} too large"))
}

fn bmp_password(pw: &str) -> Vec<u8> {
    pw.encode_utf16().chain([0]).flat_map(|u| u.to_be_bytes()).collect()
}

/// RFC 7292 Appendix B.2 key derivation. `pass` is already BMPString-encoded (NUL-terminated).
fn pkcs12_kdf(alg: &'static digest::Algorithm, pass: &[u8], salt: &[u8], id: u8, iterations: u32, n: usize) -> Vec<u8> {
    let (u, v) = (alg.output_len(), alg.block_len());
    let fill = |s: &[u8]| -> Vec<u8> { (0..v * s.len().div_ceil(v)).map(|i| s[i % s.len()]).collect() };
    let mut i_buf = fill(salt);
    i_buf.extend(fill(pass));
    let d = vec![id; v];
    let mut out = Vec::with_capacity(n);
    loop {
        let mut ctx = digest::Context::new(alg);
        ctx.update(&d);
        ctx.update(&i_buf);
        let mut a = ctx.finish();
        for _ in 1..iterations {
            a = digest::digest(alg, a.as_ref());
        }
        let a = a.as_ref();
        out.extend_from_slice(&a[..u.min(n - out.len())]);
        if out.len() == n {
            return out;
        }
        // I_j = (I_j + B + 1) mod 2^(8v), with B = A repeated to v bytes.
        for block in i_buf.chunks_exact_mut(v) {
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let s = block[k] as u16 + a[k % u] as u16 + carry;
                block[k] = s as u8;
                carry = s >> 8;
            }
        }
    }
}

fn integrity_error() -> String {
    "keystore integrity check failed: wrong keystore password, or the file was tampered with".into()
}

/// MacData ::= SEQUENCE { DigestInfo { AlgorithmIdentifier, digest }, macSalt, iterations DEFAULT 1 }
fn verify_mac(mac_data: Tlv, auth_safe: &[u8], password: &str) -> Result<(), String> {
    let m = children(mac_data.body)?;
    let di = children(child(&m, 0, 0x30, "MacData")?.body)?;
    let alg = children(child(&di, 0, 0x30, "MAC algorithm")?.body)?;
    let oid = child(&alg, 0, 0x06, "MAC algorithm")?.body;
    let expected = child(&di, 1, 0x04, "MAC digest")?.body;
    let salt = child(&m, 1, 0x04, "MAC salt")?.body;
    let iterations = match m.get(2) {
        Some(&t) => uint(t, "MAC iteration count")?,
        None => 1,
    };
    let (d, h) = if oid == OID_SHA1 {
        (&digest::SHA1_FOR_LEGACY_USE_ONLY, hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY)
    } else if oid.len() == OID_SHA2_PREFIX.len() + 1 && oid.starts_with(OID_SHA2_PREFIX) {
        match oid[OID_SHA2_PREFIX.len()] {
            1 => (&digest::SHA256, hmac::HMAC_SHA256),
            2 => (&digest::SHA384, hmac::HMAC_SHA384),
            3 => (&digest::SHA512, hmac::HMAC_SHA512),
            _ => return Err("unsupported PKCS#12 MAC digest (SHA-224 / SHA-512/t)".into()),
        }
    } else if oid == OID_PBMAC1 {
        return Err("PKCS#12 PBMAC1 integrity protection is not supported".into());
    } else {
        return Err("unsupported PKCS#12 MAC algorithm".into());
    };
    if iterations == 0 {
        return Err("malformed PKCS#12 MAC iteration count".into());
    }
    let key = pkcs12_kdf(d, &bmp_password(password), salt, 3, iterations, d.output_len());
    hmac::verify(&hmac::Key::new(h, &key), auth_safe, expected).map_err(|_| integrity_error())
}

fn legacy_pbe_name(oid: &[u8]) -> Option<&'static str> {
    if oid.len() != OID_LEGACY_PBE_PREFIX.len() + 1 || !oid.starts_with(OID_LEGACY_PBE_PREFIX) {
        return None;
    }
    Some(match oid[OID_LEGACY_PBE_PREFIX.len()] {
        1 => "pbeWithSHAAnd128BitRC4",
        2 => "pbeWithSHAAnd40BitRC4",
        3 => "pbeWithSHAAnd3-KeyTripleDES-CBC",
        4 => "pbeWithSHAAnd2-KeyTripleDES-CBC",
        5 => "pbeWithSHAAnd128BitRC2-CBC",
        6 => "pbeWithSHAAnd40BitRC2-CBC",
        _ => "unknown PKCS#12 PBE",
    })
}

fn cbc_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), String> {
    fn run<D: KeyIvInit + BlockModeDecrypt<BlockSize = U16>>(key: &[u8], iv: &[u8], data: &mut [u8]) -> Result<(), String> {
        let mut dec = D::new_from_slices(key, iv).map_err(|_| "malformed PKCS#12: bad AES IV length".to_string())?;
        for chunk in data.chunks_exact_mut(16) {
            dec.decrypt_block(chunk.try_into().expect("16-byte chunk"));
        }
        Ok(())
    }
    match key.len() {
        16 => run::<cbc::Decryptor<aes::Aes128>>(key, iv, data),
        24 => run::<cbc::Decryptor<aes::Aes192>>(key, iv, data),
        _ => run::<cbc::Decryptor<aes::Aes256>>(key, iv, data),
    }
}

/// Decrypt `data` per the PBES2 AlgorithmIdentifier `alg`. `Ok(None)` means the password did not
/// produce valid padding; `Err` is a malformed or unsupported algorithm.
fn pbes2_decrypt(alg: Tlv, data: &[u8], password: &str) -> Result<Option<Vec<u8>>, String> {
    let a = children(alg.body)?;
    let oid = child(&a, 0, 0x06, "encryption algorithm")?.body;
    if let Some(name) = legacy_pbe_name(oid) {
        return Err(format!(
            "legacy PKCS#12 encryption ({name}) is not supported; re-encrypt with a modern tool, e.g. \
             keytool -importkeystore -srckeystore <in> -destkeystore <out.p12> -deststoretype PKCS12 (JDK 12+)"
        ));
    }
    if oid != OID_PBES2 {
        return Err("unsupported PKCS#12 encryption algorithm (only PBES2 is supported)".into());
    }
    let params = children(child(&a, 1, 0x30, "PBES2 parameters")?.body)?;
    let kdf = children(child(&params, 0, 0x30, "PBES2 key derivation")?.body)?;
    if child(&kdf, 0, 0x06, "PBES2 key derivation")?.body != OID_PBKDF2 {
        return Err("unsupported PBES2 key derivation function (only PBKDF2 is supported)".into());
    }
    let kp = children(child(&kdf, 1, 0x30, "PBKDF2 parameters")?.body)?;
    let salt = child(&kp, 0, 0x04, "PBKDF2 salt")?.body;
    let iterations = NonZeroU32::new(uint(*kp.get(1).ok_or("malformed PKCS#12: PBKDF2 iteration count missing")?, "PBKDF2 iteration count")?)
        .ok_or("malformed PKCS#12: PBKDF2 iteration count is 0")?;
    let mut key_length = None;
    let mut prf = pbkdf2::PBKDF2_HMAC_SHA1;
    for &t in &kp[2..] {
        match t.tag {
            0x02 => key_length = Some(uint(t, "PBKDF2 key length")? as usize),
            0x30 => {
                let p = children(t.body)?;
                let oid = child(&p, 0, 0x06, "PBKDF2 PRF")?.body;
                let sub = if oid.len() == OID_HMAC_PREFIX.len() + 1 && oid.starts_with(OID_HMAC_PREFIX) { oid[OID_HMAC_PREFIX.len()] } else { 0 };
                prf = match sub {
                    7 => pbkdf2::PBKDF2_HMAC_SHA1,
                    9 => pbkdf2::PBKDF2_HMAC_SHA256,
                    10 => pbkdf2::PBKDF2_HMAC_SHA384,
                    11 => pbkdf2::PBKDF2_HMAC_SHA512,
                    _ => return Err("unsupported PBKDF2 PRF (supported: HMAC-SHA1/256/384/512)".into()),
                };
            }
            _ => return Err("malformed PKCS#12 PBKDF2 parameters".into()),
        }
    }
    let enc = children(child(&params, 1, 0x30, "PBES2 encryption scheme")?.body)?;
    let eoid = child(&enc, 0, 0x06, "PBES2 encryption scheme")?.body;
    let key_len = match (eoid.len() == OID_AES_CBC_PREFIX.len() + 1 && eoid.starts_with(OID_AES_CBC_PREFIX)).then(|| eoid[OID_AES_CBC_PREFIX.len()]) {
        Some(2) => 16,
        Some(22) => 24,
        Some(42) => 32,
        _ => return Err("unsupported PBES2 cipher (only AES-CBC is supported)".into()),
    };
    if key_length.is_some_and(|l| l != key_len) {
        return Err("malformed PKCS#12: PBKDF2 key length does not match the AES key size".into());
    }
    let iv = child(&enc, 1, 0x04, "AES IV")?.body;
    if data.is_empty() || data.len() % 16 != 0 {
        return Err("malformed PKCS#12: ciphertext is not a whole number of AES blocks".into());
    }
    let mut key = vec![0u8; key_len];
    pbkdf2::derive(prf, iterations, salt, password.as_bytes(), &mut key);
    let mut plain = data.to_vec();
    cbc_decrypt(&key, iv, &mut plain)?;
    let pad = *plain.last().unwrap() as usize;
    if pad == 0 || pad > 16 || !plain[plain.len() - pad..].iter().all(|&b| b as usize == pad) {
        return Ok(None);
    }
    plain.truncate(plain.len() - pad);
    Ok(Some(plain))
}

/// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
fn content_info(t: Tlv<'_>) -> Result<(&[u8], Tlv<'_>), String> {
    let c = children(expect_tag(t, 0x30, "ContentInfo")?.body)?;
    let oid = child(&c, 0, 0x06, "ContentInfo")?.body;
    Ok((oid, tlv(child(&c, 1, 0xa0, "ContentInfo")?.body, 0)?.0))
}

struct KeyBag {
    der: Vec<u8>,
    name: Option<String>,
    local_id: Option<Vec<u8>>,
}

struct CertBag {
    der: Vec<u8>,
    local_id: Option<Vec<u8>>,
}

#[derive(Default)]
struct Bags {
    keys: Vec<KeyBag>,
    certs: Vec<CertBag>,
}

fn parse_safe_contents(b: &[u8], bags: &mut Bags, depth: u32) -> Result<(), String> {
    if depth > MAX_NESTING {
        return Err("malformed PKCS#12: SafeContents nested too deeply".into());
    }
    for bag in children(one(b, 0x30, "SafeContents")?.body)? {
        let f = children(expect_tag(bag, 0x30, "SafeBag")?.body)?;
        let oid = child(&f, 0, 0x06, "SafeBag")?.body;
        let value = tlv(child(&f, 1, 0xa0, "SafeBag")?.body, 0)?.0;
        let (mut name, mut local_id) = (None, None);
        if let Some(&attrs) = f.get(2) {
            for attr in children(expect_tag(attrs, 0x31, "bag attributes")?.body)? {
                let a = children(expect_tag(attr, 0x30, "bag attribute")?.body)?;
                let aoid = child(&a, 0, 0x06, "bag attribute")?.body;
                let Some(&v) = children(child(&a, 1, 0x31, "bag attribute")?.body)?.first() else { continue };
                if aoid == OID_FRIENDLY_NAME && v.tag == 0x1e {
                    let units: Vec<u16> = v.body.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                    name = Some(String::from_utf16_lossy(&units));
                } else if aoid == OID_LOCAL_KEY_ID && v.tag == 0x04 {
                    local_id = Some(v.body.to_vec());
                }
            }
        }
        if oid.len() != OID_BAG_PREFIX.len() + 1 || !oid.starts_with(OID_BAG_PREFIX) {
            continue;
        }
        match oid[OID_BAG_PREFIX.len()] {
            BAG_KEY | BAG_SHROUDED_KEY => bags.keys.push(KeyBag { der: expect_tag(value, 0x30, "key bag")?.raw.to_vec(), name, local_id }),
            BAG_CERT => {
                let c = children(expect_tag(value, 0x30, "CertBag")?.body)?;
                if child(&c, 0, 0x06, "CertBag")?.body != OID_X509_CERT {
                    continue; // SDSI certificates
                }
                let der = octets(tlv(child(&c, 1, 0xa0, "CertBag")?.body, 0)?.0)?;
                bags.certs.push(CertBag { der, local_id });
            }
            BAG_SAFE_CONTENTS => parse_safe_contents(value.raw, bags, depth + 1)?,
            _ => {} // CRL and secret bags
        }
    }
    Ok(())
}

/// Leaf-first certificate chain, following issuer → subject like `PKCS12KeyStore`.
fn build_chain(certs: &[CertBag], leaf: usize) -> Result<Vec<Vec<u8>>, String> {
    let names: Vec<(&[u8], &[u8])> = certs.iter().map(|c| cert_issuer_subject(&c.der)).collect::<Result<_, _>>()?;
    let mut used = vec![leaf];
    let mut cur = leaf;
    while used.len() < certs.len() && names[cur].0 != names[cur].1 {
        match (0..certs.len()).find(|i| !used.contains(i) && names[*i].1 == names[cur].0) {
            Some(i) => {
                used.push(i);
                cur = i;
            }
            None => break,
        }
    }
    Ok(used.into_iter().map(|i| certs[i].der.clone()).collect())
}

/// Parse a PKCS#12 file, verifying its MAC (when present) with the store password.
pub fn parse(bytes: &[u8], store_password: &str) -> Result<Pkcs12, String> {
    let pfx = one(bytes, 0x30, "PFX")?;
    if pfx.raw.len() != bytes.len() {
        return Err("malformed PKCS#12: trailing data after the PFX".into());
    }
    let f = children(pfx.body)?;
    if uint(child(&f, 0, 0x02, "PFX version")?, "PFX version")? != 3 {
        return Err("unsupported PKCS#12 version".into());
    }
    let (oid, content) = content_info(child(&f, 1, 0x30, "authSafe")?)?;
    if oid != OID_DATA {
        return Err("PKCS#12 files with public-key integrity (signed authSafe) are not supported".into());
    }
    let auth_safe = octets(expect_tag(content, content.tag & 0x20 | 0x04, "authSafe")?)?;
    if let Some(&mac) = f.get(2) {
        verify_mac(expect_tag(mac, 0x30, "MacData")?, &auth_safe, store_password)?;
    }

    let mut bags = Bags::default();
    for ci in children(one(&auth_safe, 0x30, "AuthenticatedSafe")?.body)? {
        let (oid, content) = content_info(ci)?;
        if oid == OID_DATA {
            parse_safe_contents(&octets(expect_tag(content, content.tag & 0x20 | 0x04, "data")?)?, &mut bags, 0)?;
        } else if oid == OID_ENCRYPTED_DATA {
            // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo { type, alg, [0] IMPLICIT data } }
            let ed = children(expect_tag(content, 0x30, "EncryptedData")?.body)?;
            let eci = children(child(&ed, 1, 0x30, "EncryptedContentInfo")?.body)?;
            let alg = child(&eci, 1, 0x30, "EncryptedContentInfo")?;
            let Some(&enc) = eci.get(2) else { continue };
            if enc.tag & !0x20 != 0x80 {
                return Err("malformed PKCS#12 EncryptedContentInfo".into());
            }
            let plain = pbes2_decrypt(alg, &octets(enc)?, store_password)?
                .ok_or("cannot decrypt the keystore's certificates: wrong keystore password?")?;
            parse_safe_contents(&plain, &mut bags, 0)?;
        } else {
            return Err("PKCS#12 public-key privacy mode (envelopedData) is not supported".into());
        }
    }

    let single_key = bags.keys.len() == 1;
    let mut unnamed = 0;
    let mut keys = Vec::with_capacity(bags.keys.len());
    for k in &bags.keys {
        let by_id = k.local_id.as_ref().and_then(|id| bags.certs.iter().position(|c| c.local_id.as_ref() == Some(id)));
        // Without a localKeyId, a lone key takes the one certificate that issued no other.
        let leaf = by_id.or_else(|| {
            if !single_key {
                return None;
            }
            let subjects: Vec<_> = bags.certs.iter().filter_map(|c| cert_issuer_subject(&c.der).ok()).collect();
            let leaves: Vec<usize> = (0..subjects.len())
                .filter(|&i| !subjects.iter().enumerate().any(|(j, s)| j != i && s.0 == subjects[i].1 && s.0 != s.1))
                .collect();
            (leaves.len() == 1).then(|| leaves[0])
        });
        let chain = match leaf {
            Some(i) => build_chain(&bags.certs, i)?,
            None => Vec::new(),
        };
        let alias = match &k.name {
            Some(n) => n.to_lowercase(),
            None => {
                unnamed += 1;
                unnamed.to_string()
            }
        };
        keys.push(KeyEntry { alias, protected_key: k.der.clone(), chain });
    }
    Ok(Pkcs12 { keys })
}

/// Decrypt a PKCS#12 key bag (PBES2 EncryptedPrivateKeyInfo, or a plain PrivateKeyInfo).
/// Returns the PKCS#8 PrivateKeyInfo DER.
pub fn recover_key(protected: &[u8], key_password: &str) -> Result<Vec<u8>, String> {
    let c = children(one(protected, 0x30, "key bag")?.body)?;
    if c.first().is_some_and(|t| t.tag == 0x02) {
        return Ok(protected.to_vec()); // keyBag: unencrypted PrivateKeyInfo
    }
    let alg = child(&c, 0, 0x30, "EncryptedPrivateKeyInfo")?;
    let data = child(&c, 1, 0x04, "EncryptedPrivateKeyInfo")?.body;
    let plain = pbes2_decrypt(alg, data, key_password)?.ok_or("wrong key password")?;
    // Padding matches by chance 1 time in ~256; a well-formed PKCS#8 SEQUENCE settles it.
    match one(&plain, 0x30, "") {
        Ok(t) if t.raw.len() == plain.len() => Ok(plain),
        _ => Err("wrong key password".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> Option<Vec<u8>> {
        std::fs::read(name).ok()
    }

    fn hex(s: &str) -> Vec<u8> {
        s.split(':').map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    /// Vectors from `openssl kdf ... PKCS12KDF` (the first is the classic RFC 7292 "smeg" one).
    #[test]
    fn kdf_known_answers() {
        let smeg = bmp_password("smeg");
        assert_eq!(smeg, hex("00:73:00:6D:00:65:00:67:00:00"));
        assert_eq!(
            pkcs12_kdf(&digest::SHA1_FOR_LEGACY_USE_ONLY, &smeg, &hex("0A:58:CF:64:53:0D:82:3F"), 1, 1, 24),
            hex("8A:AA:E6:29:7B:6C:B0:46:42:AB:5B:07:78:51:28:4E:B7:12:8F:1A:2A:7F:BC:A3")
        );
        assert_eq!(
            pkcs12_kdf(&digest::SHA1_FOR_LEGACY_USE_ONLY, b"smeg", &hex("0A:58:CF:64:53:0D:82:3F"), 1, 1, 24),
            hex("CD:F5:D7:00:BD:B7:14:FD:C9:6A:18:9D:B3:AC:C2:81:BE:29:A3:3E:39:FA:CB:89")
        );
        assert_eq!(
            pkcs12_kdf(&digest::SHA256, b"android", &hex("01:02:03:04:05:06:07:08"), 3, 3, 32),
            hex("0F:1D:B5:BE:29:0B:9E:30:C3:5F:1A:3C:36:A2:92:E6:FF:84:F1:26:95:4C:65:56:13:1A:1F:D0:B0:CC:24:9E")
        );
        // Multi-block output with a 128-byte block size.
        assert_eq!(
            pkcs12_kdf(&digest::SHA512, b"p", &hex("AA"), 3, 2, 70),
            hex("F5:A4:02:B1:8C:6D:E7:99:CB:CF:1F:20:31:11:53:05:A5:D1:D1:80:4C:45:47:2F:FA:CE:08:C6:5E:3A:C7:F5:62:C0:17:83:BA:06:81:5D:07:0D:BD:1F:95:92:07:DB:BA:A5:3B:B7:07:C2:EF:1B:F1:17:26:BE:7A:90:18:93:30:2F:EF:40:15:D2")
        );
    }

    fn check_store(path: &str, pw: &str, aliases: &[&str]) -> Option<Pkcs12> {
        let b = load(path)?;
        let ks = parse(&b, pw).unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut got: Vec<_> = ks.keys.iter().map(|k| k.alias.as_str()).collect();
        got.sort();
        assert_eq!(got, aliases, "{path}");
        for k in &ks.keys {
            assert!(!k.chain.is_empty(), "{path}: {}", k.alias);
            let pkcs8 = recover_key(&k.protected_key, pw).unwrap_or_else(|e| panic!("{path}: {e}"));
            assert_eq!(one(&pkcs8, 0x30, "").unwrap().raw.len(), pkcs8.len());
            assert!(recover_key(&k.protected_key, "wrong").unwrap_err().contains("wrong key password"));
        }
        assert!(parse(&b, "wrong").err().unwrap().contains("integrity"), "{path}");
        for cut in [0usize, 1, 4, 40, b.len() / 2, b.len() - 1] {
            assert!(parse(&b[..cut], pw).is_err(), "{path} cut at {cut}");
        }
        Some(ks)
    }

    #[test]
    fn keytool_stores() {
        check_store("testdata/rsa.p12", "android", &["test"]);
        check_store("testdata/ec.p12", "android", &["eckey"]);
        check_store("testdata/two.p12", "storepw", &["a", "b"]);
    }

    #[test]
    fn openssl_stores() {
        check_store("testdata/ossl.p12", "android", &["ossl"]);
        // AES-128 key, unencrypted cert bag, SHA-1 MAC
        check_store("testdata/ossl_aes128_sha1mac.p12", "android", &["ec"]);
        if let Some(ks) = check_store("testdata/chain.p12", "android", &["leaf"]) {
            let chain = &ks.keys[0].chain;
            assert_eq!(chain.len(), 2);
            let (leaf_issuer, _) = cert_issuer_subject(&chain[0]).unwrap();
            assert_eq!(leaf_issuer, cert_issuer_subject(&chain[1]).unwrap().1, "leaf first, then its issuer");
        }
    }

    #[test]
    fn chain_is_ordered_regardless_of_storage_order() {
        let Some(b) = load("testdata/chain.p12") else { return };
        let ks = parse(&b, "android").unwrap();
        let (leaf, ca) = (ks.keys[0].chain[0].clone(), ks.keys[0].chain[1].clone());
        let certs = vec![CertBag { der: ca.clone(), local_id: None }, CertBag { der: leaf.clone(), local_id: None }];
        assert_eq!(build_chain(&certs, 1).unwrap(), vec![leaf, ca]);
    }

    #[test]
    fn legacy_store_is_rejected_by_name() {
        let Some(b) = load("testdata/ossl_legacy.p12") else { return };
        let e = parse(&b, "android").err().unwrap();
        assert!(e.contains("legacy") && e.contains("RC2"), "{e}");
    }
}
