//! Key material: PEM/DER loading, key type detection, SubjectPublicKeyInfo extraction from the
//! certificate, and sign-then-verify (apksig verifies every signature it produces against the
//! certificate's public key, so a key/cert mismatch is caught before anything is written).

use std::path::Path;

use ring::digest::{Algorithm, SHA256, SHA512};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, RsaKeyPair, UnparsedPublicKey};

pub const ALG_RSA_PKCS1_SHA256: u32 = 0x0103;
pub const ALG_RSA_PKCS1_SHA512: u32 = 0x0104;
pub const ALG_ECDSA_SHA256: u32 = 0x0201;

#[derive(Clone, Copy)]
enum RsaHash {
    Sha256,
    Sha512,
}

enum Key {
    Rsa { pair: RsaKeyPair, hash: RsaHash },
    EcP256(EcdsaKeyPair),
}

pub struct Signer {
    key: Key,
    rng: SystemRandom,
    pub alg_id: u32,
    pub content_digest: &'static Algorithm,
    pub certs: Vec<Vec<u8>>,
    pub spki: Vec<u8>,
    pub description: String,
}

impl Signer {
    /// Raw key + certificate files (`--key` / `--cert`).
    pub fn load_files(key_path: &Path, cert_path: &Path) -> Result<Signer, String> {
        let key_bytes = std::fs::read(key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
        let cert_bytes = std::fs::read(cert_path).map_err(|e| format!("{}: {e}", cert_path.display()))?;
        let key_ders = decode_key_file(&key_bytes).map_err(|e| format!("{}: {e}", key_path.display()))?;
        let certs = decode_cert_file(&cert_bytes).map_err(|e| format!("{}: {e}", cert_path.display()))?;
        if certs.is_empty() {
            return Err(format!("{}: no certificate found", cert_path.display()));
        }
        Signer::from_material(key_ders, certs).map_err(|e| format!("{}: {e}", key_path.display()))
    }

    /// Java KeyStore or PKCS#12 (`--ks`), told apart by content. `alias == None` is accepted when
    /// the store has exactly one key.
    pub fn load_keystore(ks_path: &Path, store_password: &str, alias: Option<&str>, key_password: &str) -> Result<Signer, String> {
        let bytes = std::fs::read(ks_path).map_err(|e| format!("{}: {e}", ks_path.display()))?;
        let (keys, recover): (_, fn(&[u8], &str) -> Result<Vec<u8>, String>) = match crate::jks::detect(&bytes) {
            crate::jks::StoreKind::Pkcs12 => {
                let request = crate::pkcs12::KeyRequest { alias, password: key_password };
                (crate::pkcs12::parse(&bytes, store_password, Some(request)).map(|s| s.keys), crate::pkcs12::recover_key)
            }
            _ => (crate::jks::parse(&bytes, store_password).map(|s| s.keys), crate::jks::recover_key),
        };
        let keys = keys.map_err(|e| format!("{}: {e}", ks_path.display()))?;
        let available = || keys.iter().map(|k| k.alias.as_str()).collect::<Vec<_>>().join(", ");
        let entry = match alias {
            Some(a) => {
                let want = a.to_lowercase();
                keys.iter().find(|k| k.alias == want).ok_or_else(|| {
                    format!("{}: key alias {a:?} not found (available: {})", ks_path.display(), available())
                })?
            }
            None => match keys.len() {
                1 => &keys[0],
                0 => return Err(format!("{}: keystore contains no key entries", ks_path.display())),
                n => return Err(format!("{}: keystore has {n} key entries, --ks-key-alias is required (available: {})", ks_path.display(), available())),
            },
        };
        let pkcs8 = match &entry.recovered {
            Some(r) => r.clone(),
            None => recover(&entry.protected_key, key_password),
        }
        .map_err(|e| format!("{}: alias {:?}: {e}", ks_path.display(), entry.alias))?;
        if entry.chain.is_empty() {
            return Err(format!("{}: alias {:?} has no certificate chain", ks_path.display(), entry.alias));
        }
        Signer::from_material(vec![(Some("PRIVATE KEY".into()), pkcs8)], entry.chain.clone())
            .map_err(|e| format!("{}: alias {:?}: {e}", ks_path.display(), entry.alias))
    }

    /// Build a signer from candidate private-key DER blobs and a certificate chain.
    pub fn from_material(key_ders: Vec<(Option<String>, Vec<u8>)>, certs: Vec<Vec<u8>>) -> Result<Signer, String> {
        let rng = SystemRandom::new();
        let spki = spki_from_cert(&certs[0]).map_err(|e| format!("cannot locate SubjectPublicKeyInfo in certificate: {e}"))?.to_vec();
        let pubkey_bits = spki_public_key_bits(&spki)?.to_vec();

        let mut last_err = String::from("no key found");
        for (label, der) in &key_ders {
            match parse_key(der, label.as_deref(), &pubkey_bits, &rng) {
                Ok(key) => {
                    let (alg_id, content_digest, description) = match &key {
                        Key::Rsa { pair, hash } => {
                            let bits = pair.public().modulus_len() * 8;
                            match hash {
                                RsaHash::Sha256 => (ALG_RSA_PKCS1_SHA256, &SHA256, format!("RSA-{bits} / PKCS#1 v1.5 / SHA-256")),
                                RsaHash::Sha512 => (ALG_RSA_PKCS1_SHA512, &SHA512, format!("RSA-{bits} / PKCS#1 v1.5 / SHA-512")),
                            }
                        }
                        Key::EcP256(_) => (ALG_ECDSA_SHA256, &SHA256, "ECDSA P-256 / SHA-256".to_string()),
                    };
                    // A key/certificate mismatch is caught by the verify step inside `sign`.
                    return Ok(Signer { key, rng, alg_id, content_digest, certs, spki, description });
                }
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Sign `data`, then verify the signature with the certificate's public key.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let key_bits = spki_public_key_bits(&self.spki)?;
        match &self.key {
            Key::Rsa { pair, hash } => {
                let (encoding, verify): (&'static dyn signature::RsaEncoding, &'static signature::RsaParameters) = match hash {
                    RsaHash::Sha256 => (&signature::RSA_PKCS1_SHA256, &signature::RSA_PKCS1_2048_8192_SHA256),
                    RsaHash::Sha512 => (&signature::RSA_PKCS1_SHA512, &signature::RSA_PKCS1_2048_8192_SHA512),
                };
                let mut sig = vec![0u8; pair.public().modulus_len()];
                pair.sign(encoding, &self.rng, data, &mut sig).map_err(|_| "RSA signing failed".to_string())?;
                UnparsedPublicKey::new(verify, key_bits)
                    .verify(data, &sig)
                    .map_err(|_| "generated RSA signature does not verify with the certificate's public key (key/cert mismatch?)".to_string())?;
                Ok(sig)
            }
            Key::EcP256(pair) => {
                let sig = pair.sign(&self.rng, data).map_err(|_| "ECDSA signing failed".to_string())?;
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key_bits)
                    .verify(data, sig.as_ref())
                    .map_err(|_| "generated ECDSA signature does not verify with the certificate's public key (key/cert mismatch?)".to_string())?;
                Ok(sig.as_ref().to_vec())
            }
        }
    }
}

fn parse_key(der: &[u8], label: Option<&str>, cert_pubkey_bits: &[u8], rng: &SystemRandom) -> Result<Key, String> {
    if let Ok(pair) = RsaKeyPair::from_pkcs8(der) {
        return Ok(rsa(pair));
    }
    if let Ok(pair) = RsaKeyPair::from_der(der) {
        return Ok(rsa(pair));
    }
    if let Ok(pair) = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, der, rng) {
        return Ok(Key::EcP256(pair));
    }
    // Java (JKS, keytool) and SEC1 files omit the public key from the ECPrivateKey structure,
    // which ring's PKCS#8 parser requires. Recover it from the certificate instead.
    if let Some(scalar) = ec_private_scalar(der) {
        return EcdsaKeyPair::from_private_key_and_public_key(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &scalar, cert_pubkey_bits, rng)
            .map(Key::EcP256)
            .map_err(|_| "EC private key does not match the certificate's public key, or is not P-256".to_string());
    }
    match label {
        Some("ENCRYPTED PRIVATE KEY") => Err("encrypted PKCS#8 keys are not supported; decrypt with \
             `openssl pkcs8 -in key.pem -out key.pk8 -nocrypt`"
            .into()),
        _ => Err("unsupported private key: expected unencrypted PKCS#8 (or PKCS#1) RSA 2048..8192-bit, \
             or PKCS#8 / SEC1 EC P-256"
            .into()),
    }
}

fn rsa(pair: RsaKeyPair) -> Key {
    let hash = if pair.public().modulus_len() * 8 <= 3072 { RsaHash::Sha256 } else { RsaHash::Sha512 };
    Key::Rsa { pair, hash }
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The private scalar (left-padded to 32 bytes) from a PKCS#8 or SEC1 EC private key,
/// if it is (or may be) a P-256 key. `None` if the structure is not an EC key at all.
fn ec_private_scalar(der: &[u8]) -> Option<Vec<u8>> {
    let (p, _) = der_expect(der, 0, 0x30).ok()?;
    let (_, vs, vl) = der_header(der, p).ok()?; // INTEGER version
    let next = vs + vl;
    let (tag, s, l) = der_header(der, next).ok()?;
    let ec_private_key: &[u8] = if tag == 0x30 {
        // PKCS#8: AlgorithmIdentifier { ecPublicKey, namedCurve }, then OCTET STRING { ECPrivateKey }
        let (os, ol) = der_expect(der, s, 0x06).ok()?;
        if &der[os..os + ol] != OID_EC_PUBLIC_KEY {
            return None;
        }
        if let Ok((0x06, cs, cl)) = der_header(der, os + ol) {
            if &der[cs..cs + cl] != OID_PRIME256V1 {
                return None;
            }
        }
        let (ks, kl) = der_expect(der, s + l, 0x04).ok()?;
        &der[ks..ks + kl]
    } else if tag == 0x04 {
        der // SEC1 ECPrivateKey at top level
    } else {
        return None;
    };
    // ECPrivateKey ::= SEQUENCE { version INTEGER, privateKey OCTET STRING, [0] params, [1] pubkey }
    let (p, _) = der_expect(ec_private_key, 0, 0x30).ok()?;
    let (_, vs, vl) = der_header(ec_private_key, p).ok()?;
    let (ks, kl) = der_expect(ec_private_key, vs + vl, 0x04).ok()?;
    let mut scalar = ec_private_key[ks..ks + kl].to_vec();
    while scalar.len() > 32 && scalar[0] == 0 {
        scalar.remove(0);
    }
    if scalar.len() > 32 {
        return None;
    }
    let mut padded = vec![0u8; 32 - scalar.len()];
    padded.extend_from_slice(&scalar);
    Some(padded)
}

// ---------------------------------------------------------------------------------------------
// PEM / base64

fn is_pem(bytes: &[u8]) -> bool {
    bytes.iter().position(|b| !b.is_ascii_whitespace()).map_or(false, |i| bytes[i..].starts_with(b"-----BEGIN"))
}

/// All `-----BEGIN label-----` blocks in a PEM file, as (label, DER).
pub fn pem_blocks(text: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    let text = std::str::from_utf8(text).map_err(|_| "PEM file is not valid UTF-8".to_string())?;
    let mut out = Vec::new();
    let mut label: Option<String> = None;
    let mut b64 = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            label = Some(rest.trim_end_matches('-').trim().to_string());
            b64.clear();
        } else if line.starts_with("-----END ") {
            let l = label.take().ok_or("PEM END without BEGIN")?;
            out.push((l, base64_decode(&b64)?));
        } else if label.is_some() && !line.is_empty() && !line.contains(':') {
            b64.push_str(line);
        }
    }
    Ok(out)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return Err(format!("invalid base64 character {:?}", c as char)),
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn decode_key_file(bytes: &[u8]) -> Result<Vec<(Option<String>, Vec<u8>)>, String> {
    if is_pem(bytes) {
        let blocks = pem_blocks(bytes)?;
        let keys: Vec<_> = blocks
            .into_iter()
            .filter(|(l, _)| l.ends_with("PRIVATE KEY"))
            .map(|(l, d)| (Some(l), d))
            .collect();
        if keys.is_empty() {
            return Err("no PRIVATE KEY block in PEM file".into());
        }
        Ok(keys)
    } else {
        Ok(vec![(None, bytes.to_vec())])
    }
}

fn decode_cert_file(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if is_pem(bytes) {
        Ok(pem_blocks(bytes)?.into_iter().filter(|(l, _)| l == "CERTIFICATE").map(|(_, d)| d).collect())
    } else {
        // Raw DER; accept a concatenation of certificates.
        let mut certs = Vec::new();
        let mut p = 0;
        while p < bytes.len() {
            let (tag, start, len) = der_header(bytes, p)?;
            if tag != 0x30 {
                return Err("certificate file is neither PEM nor DER".into());
            }
            certs.push(bytes[p..start + len].to_vec());
            p = start + len;
        }
        Ok(certs)
    }
}

// ---------------------------------------------------------------------------------------------
// Minimal DER walking (only what is needed to pull the SPKI out of an X.509 certificate).

/// Returns (tag, content_start, content_len) for the TLV at `p`.
pub fn der_header(b: &[u8], p: usize) -> Result<(u8, usize, usize), String> {
    let err = || "truncated or malformed DER".to_string();
    let tag = *b.get(p).ok_or_else(err)?;
    if tag & 0x1f == 0x1f {
        return Err("multi-byte DER tags are not supported".into());
    }
    let first = *b.get(p + 1).ok_or_else(err)?;
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("unsupported DER length encoding".into());
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(p + 2 + i).ok_or_else(err)? as usize;
        }
        (len, 2 + n)
    };
    let start = p + hdr;
    if start + len > b.len() {
        return Err(err());
    }
    Ok((tag, start, len))
}

fn der_skip(b: &[u8], p: usize) -> Result<usize, String> {
    let (_, s, l) = der_header(b, p)?;
    Ok(s + l)
}

pub(crate) fn der_expect(b: &[u8], p: usize, tag: u8) -> Result<(usize, usize), String> {
    let (t, s, l) = der_header(b, p)?;
    if t != tag {
        return Err(format!("expected DER tag {tag:#04x}, found {t:#04x} at offset {p}"));
    }
    Ok((s, l))
}

/// The DER-encoded SubjectPublicKeyInfo of an X.509 certificate, byte-for-byte as it appears
/// in the certificate (this is what apksig embeds as the signer's public key).
pub fn spki_from_cert(cert: &[u8]) -> Result<&[u8], String> {
    let (tbs_pos, _) = der_expect(cert, 0, 0x30)?; // Certificate
    let (mut p, _) = der_expect(cert, tbs_pos, 0x30)?; // TBSCertificate
    if let (0xa0, _, _) = der_header(cert, p)? {
        p = der_skip(cert, p)?; // [0] EXPLICIT version
    }
    p = der_skip(cert, p)?; // serialNumber
    p = der_skip(cert, p)?; // signature AlgorithmIdentifier
    p = der_skip(cert, p)?; // issuer
    p = der_skip(cert, p)?; // validity
    p = der_skip(cert, p)?; // subject
    let (s, l) = der_expect(cert, p, 0x30)?; // subjectPublicKeyInfo
    Ok(&cert[p..s + l])
}

/// Raw DER (issuer, subject) Names of an X.509 certificate.
pub fn cert_issuer_subject(cert: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let (tbs_pos, _) = der_expect(cert, 0, 0x30)?; // Certificate
    let (mut p, _) = der_expect(cert, tbs_pos, 0x30)?; // TBSCertificate
    if let (0xa0, _, _) = der_header(cert, p)? {
        p = der_skip(cert, p)?; // [0] EXPLICIT version
    }
    p = der_skip(cert, p)?; // serialNumber
    p = der_skip(cert, p)?; // signature AlgorithmIdentifier
    let issuer_end = der_skip(cert, p)?;
    let subject_start = der_skip(cert, issuer_end)?; // skip validity
    let subject_end = der_skip(cert, subject_start)?;
    Ok((&cert[p..issuer_end], &cert[subject_start..subject_end]))
}

/// Contents of the BIT STRING inside a SubjectPublicKeyInfo (RSAPublicKey DER for RSA,
/// uncompressed EC point for EC) — the form ring's verification API wants.
pub fn spki_public_key_bits(spki: &[u8]) -> Result<&[u8], String> {
    let (p, _) = der_expect(spki, 0, 0x30)?;
    let p = der_skip(spki, p)?; // AlgorithmIdentifier
    let (s, l) = der_expect(spki, p, 0x03)?; // BIT STRING
    if l == 0 || spki[s] != 0 {
        return Err("unexpected BIT STRING padding in SubjectPublicKeyInfo".into());
    }
    Ok(&spki[s + 1..s + l])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_basics() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        assert!(base64_decode("Zm9v*").is_err());
    }

    #[test]
    fn pem_blocks_parse_labels_and_skip_headers() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n\
                   -----BEGIN PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAwQ=\n-----END PRIVATE KEY-----\n";
        let b = pem_blocks(pem.as_bytes()).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0], ("CERTIFICATE".to_string(), vec![0, 1, 2]));
        assert_eq!(b[1], ("PRIVATE KEY".to_string(), vec![3, 4]));
    }

    #[test]
    fn der_header_short_and_long_forms() {
        assert_eq!(der_header(&[0x30, 0x02, 1, 2], 0).unwrap(), (0x30, 2, 2));
        let mut v = vec![0x30, 0x82, 0x01, 0x00];
        v.extend(std::iter::repeat(0).take(256));
        assert_eq!(der_header(&v, 0).unwrap(), (0x30, 4, 256));
        assert!(der_header(&[0x30, 0x05, 1], 0).is_err());
    }

    /// Uses the real test certificates when present (generated by testdata setup).
    #[test]
    fn spki_extraction_from_test_certs() {
        for (name, expect_len) in [("testdata/rsa.cert.pem", 294usize), ("testdata/ec.cert.pem", 91)] {
            let Ok(pem) = std::fs::read(name) else { continue };
            let certs = decode_cert_file(&pem).unwrap();
            let spki = spki_from_cert(&certs[0]).unwrap();
            assert_eq!(spki.len(), expect_len, "{name}");
            assert_eq!(spki[0], 0x30);
            let bits = spki_public_key_bits(spki).unwrap();
            assert!(!bits.is_empty());
        }
    }

    #[test]
    fn load_and_sign_with_test_keys() {
        for (k, c, alg) in [
            ("testdata/rsa.pk8", "testdata/rsa.cert.pem", ALG_RSA_PKCS1_SHA256),
            ("testdata/rsa.key.pem", "testdata/rsa.cert.pem", ALG_RSA_PKCS1_SHA256),
            ("testdata/ec.pk8", "testdata/ec.cert.pem", ALG_ECDSA_SHA256),
            ("testdata/ec.key.pem", "testdata/ec.cert.pem", ALG_ECDSA_SHA256), // SEC1, via scalar fallback
        ] {
            if !Path::new(k).exists() {
                continue;
            }
            let s = Signer::load_files(Path::new(k), Path::new(c)).unwrap();
            assert_eq!(s.alg_id, alg, "{k}");
            let sig = s.sign(b"hello").unwrap();
            assert!(!sig.is_empty());
        }
        // Mismatched key/cert must be rejected.
        if Path::new("testdata/rsa.pk8").exists() && Path::new("testdata/ec.cert.pem").exists() {
            let s = Signer::load_files(Path::new("testdata/rsa.pk8"), Path::new("testdata/ec.cert.pem")).unwrap();
            assert!(s.sign(b"x").unwrap_err().contains("mismatch"));
        }
    }

    #[test]
    fn load_from_jks_keystores() {
        if !Path::new("testdata/rsa.jks").exists() {
            return;
        }
        let s = Signer::load_keystore(Path::new("testdata/rsa.jks"), "android", None, "android").unwrap();
        assert_eq!(s.alg_id, ALG_RSA_PKCS1_SHA256);
        assert!(s.sign(b"x").is_ok());
        let s = Signer::load_keystore(Path::new("testdata/ec.jks"), "android", Some("ECKEY"), "android").unwrap();
        assert_eq!(s.alg_id, ALG_ECDSA_SHA256, "Java EC keys lack the public key in PKCS#8; scalar fallback");
        assert!(s.sign(b"x").is_ok());
        // two keys: alias required, per-key passwords
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "storepw", None, "keypw22").err().unwrap().contains("--ks-key-alias"));
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "storepw", Some("a"), "keypw22").is_ok());
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "storepw", Some("b"), "keypw2b").unwrap().sign(b"x").is_ok());
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "storepw", Some("b"), "keypw22").err().unwrap().contains("wrong key password"));
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "nope", Some("a"), "keypw22").err().unwrap().contains("integrity"));
        assert!(Signer::load_keystore(Path::new("testdata/two.jks"), "storepw", Some("zzz"), "x").err().unwrap().contains("not found"));
    }

    #[test]
    fn load_from_pkcs12_keystores() {
        if !Path::new("testdata/rsa.p12").exists() {
            return;
        }
        let s = Signer::load_keystore(Path::new("testdata/rsa.p12"), "android", None, "android").unwrap();
        assert_eq!(s.alg_id, ALG_RSA_PKCS1_SHA256);
        assert!(s.sign(b"x").is_ok());
        let s = Signer::load_keystore(Path::new("testdata/ec.p12"), "android", Some("ECKey"), "android").unwrap();
        assert_eq!(s.alg_id, ALG_ECDSA_SHA256);
        assert!(s.sign(b"x").is_ok());
        assert!(Signer::load_keystore(Path::new("testdata/two.p12"), "storepw", None, "storepw").err().unwrap().contains("--ks-key-alias"));
        assert!(Signer::load_keystore(Path::new("testdata/two.p12"), "storepw", Some("b"), "storepw").unwrap().sign(b"x").is_ok());
        assert!(Signer::load_keystore(Path::new("testdata/two.p12"), "nope", Some("a"), "storepw").err().unwrap().contains("integrity"));
        assert!(Signer::load_keystore(Path::new("testdata/two.p12"), "storepw", Some("a"), "nope").err().unwrap().contains("wrong key password"));
        let s = Signer::load_keystore(Path::new("testdata/chain.p12"), "android", None, "android").unwrap();
        assert!(s.sign(b"x").is_ok());
        // One flipped byte inside the MAC-protected content must fail the integrity check.
        let mut b = std::fs::read("testdata/rsa.p12").unwrap();
        let n = b.len();
        b[n / 2] ^= 1;
        let tampered = std::env::temp_dir().join(format!("fastsigner-tampered-{}.p12", std::process::id()));
        std::fs::write(&tampered, &b).unwrap();
        let e = Signer::load_keystore(&tampered, "android", None, "android").err().unwrap();
        let _ = std::fs::remove_file(&tampered);
        assert!(e.contains("integrity") || e.contains("malformed"), "{e}");
    }
}
