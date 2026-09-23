//! Java KeyStore (JKS) reader. Format and key protection follow OpenJDK's
//! `sun.security.provider.JavaKeyStore` / `KeyProtector`:
//!
//! ```text
//! u32 magic 0xFEEDFEED, u32 version (1|2), u32 count,
//! entries: u32 tag (1=key, 2=trusted cert), UTF alias, u64 date,
//!   key:  u32 len, EncryptedPrivateKeyInfo, u32 chain len, { [v2: UTF "X.509"] u32 len, DER }...
//!   cert: [v2: UTF type] u32 len, DER
//! SHA-1( UTF-16BE(store password) || "Mighty Aphrodite" || everything above )
//! ```
//!
//! Key protection (OID 1.3.6.1.4.1.42.2.17.1.1): data = salt[20] || encrypted || check[20];
//! keystream block i = SHA-1(UTF-16BE(password) || previous block), block 0 uses the salt;
//! check = SHA-1(password || plaintext PKCS#8).

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1};

use crate::keys::der_expect;

const MAGIC_JKS: u32 = 0xfeed_feed;
const MAGIC_JCEKS: u32 = 0xcece_cece;
const KEY_PROTECTOR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];
const SALT_LEN: usize = 20;
const DIGEST_LEN: usize = 20;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StoreKind {
    Jks,
    Jceks,
    Pkcs12,
    Unknown,
}

pub fn detect(bytes: &[u8]) -> StoreKind {
    if bytes.len() < 4 {
        return StoreKind::Unknown;
    }
    match u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) {
        MAGIC_JKS => StoreKind::Jks,
        MAGIC_JCEKS => StoreKind::Jceks,
        _ if bytes[0] == 0x30 => StoreKind::Pkcs12,
        _ => StoreKind::Unknown,
    }
}

pub struct KeyEntry {
    pub alias: String,
    /// EncryptedPrivateKeyInfo DER, see `recover_key`.
    pub protected_key: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    /// `recover_key`'s result when the reader already ran it (the PKCS#12 reader decrypts the
    /// keys a request can select alongside its other key derivations).
    pub recovered: Option<Result<Vec<u8>, String>>,
}

pub struct Jks {
    pub keys: Vec<KeyEntry>,
    #[allow(dead_code)]
    pub trusted_certs: usize,
}

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.p.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("truncated keystore")?;
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
    /// `DataInput.readUTF`: u16 length + (modified) UTF-8. Aliases are ASCII in practice.
    fn utf(&mut self) -> Result<String, String> {
        let s = self.take(2)?;
        let n = u16::from_be_bytes([s[0], s[1]]) as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
}

fn password_bytes(pw: &str) -> Vec<u8> {
    pw.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

/// Parse a JKS file and verify its integrity hash with the store password.
pub fn parse(bytes: &[u8], store_password: &str) -> Result<Jks, String> {
    match detect(bytes) {
        StoreKind::Jks => {}
        StoreKind::Jceks => return Err("JCEKS keystores are not supported (convert with keytool -importkeystore -deststoretype JKS)".into()),
        StoreKind::Pkcs12 => return Err("not a JKS keystore (PKCS#12, see the pkcs12 module)".into()),
        StoreKind::Unknown => return Err("not a JKS keystore".into()),
    }
    let mut c = Cursor { b: bytes, p: 4 };
    let version = c.u32()?;
    if version != 1 && version != 2 {
        return Err(format!("unsupported JKS version {version}"));
    }
    let count = c.u32()?;
    let mut keys = Vec::new();
    let mut trusted_certs = 0usize;
    for _ in 0..count {
        let tag = c.u32()?;
        let alias = c.utf()?;
        let _date_ms = c.u64()?;
        match tag {
            1 => {
                let n = c.u32()? as usize;
                let protected_key = c.take(n)?.to_vec();
                let chain_len = c.u32()?;
                let mut chain = Vec::with_capacity(chain_len as usize);
                for _ in 0..chain_len {
                    if version == 2 {
                        let t = c.utf()?;
                        if t != "X.509" {
                            return Err(format!("unsupported certificate type {t:?} in keystore"));
                        }
                    }
                    let n = c.u32()? as usize;
                    chain.push(c.take(n)?.to_vec());
                }
                keys.push(KeyEntry { alias, protected_key, chain, recovered: None });
            }
            2 => {
                if version == 2 {
                    c.utf()?;
                }
                let n = c.u32()? as usize;
                c.take(n)?;
                trusted_certs += 1;
            }
            _ => return Err(format!("unknown JKS entry tag {tag}")),
        }
    }
    let data_end = c.p;
    let stored = c.take(DIGEST_LEN)?;
    let mut ctx = Context::new(&SHA1);
    ctx.update(&password_bytes(store_password));
    ctx.update(b"Mighty Aphrodite");
    ctx.update(&bytes[..data_end]);
    if ctx.finish().as_ref() != stored {
        return Err("keystore integrity check failed: wrong keystore password, or the file was tampered with".into());
    }
    Ok(Jks { keys, trusted_certs })
}

/// Decrypt a JKS-protected key. Returns the plaintext PKCS#8 PrivateKeyInfo DER.
pub fn recover_key(protected: &[u8], key_password: &str) -> Result<Vec<u8>, String> {
    let (p, _) = der_expect(protected, 0, 0x30)?; // EncryptedPrivateKeyInfo
    let (alg_start, alg_len) = der_expect(protected, p, 0x30)?; // AlgorithmIdentifier
    let (oid_start, oid_len) = der_expect(protected, alg_start, 0x06)?;
    if &protected[oid_start..oid_start + oid_len] != KEY_PROTECTOR_OID {
        return Err("key is not protected with the JKS algorithm (JCEKS or PKCS#12 entry?)".into());
    }
    let (d_start, d_len) = der_expect(protected, alg_start + alg_len, 0x04)?; // encryptedData
    let data = &protected[d_start..d_start + d_len];
    if data.len() < SALT_LEN + DIGEST_LEN + 1 {
        return Err("protected key too short".into());
    }
    let salt = &data[..SALT_LEN];
    let encrypted = &data[SALT_LEN..data.len() - DIGEST_LEN];
    let check = &data[data.len() - DIGEST_LEN..];

    let pw = password_bytes(key_password);
    let mut plain = Vec::with_capacity(encrypted.len());
    let mut block: Vec<u8> = salt.to_vec();
    while plain.len() < encrypted.len() {
        let mut ctx = Context::new(&SHA1);
        ctx.update(&pw);
        ctx.update(&block);
        block = ctx.finish().as_ref().to_vec();
        let off = plain.len();
        let n = (encrypted.len() - off).min(DIGEST_LEN);
        plain.extend(encrypted[off..off + n].iter().zip(&block).map(|(a, b)| a ^ b));
    }
    let mut ctx = Context::new(&SHA1);
    ctx.update(&pw);
    ctx.update(&plain);
    if ctx.finish().as_ref() != check {
        return Err("wrong key password".into());
    }
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(name: &str) -> Option<Vec<u8>> {
        std::fs::read(name).ok()
    }

    #[test]
    fn detect_kinds() {
        assert_eq!(detect(&[0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2]), StoreKind::Jks);
        assert_eq!(detect(&[0xce, 0xce, 0xce, 0xce]), StoreKind::Jceks);
        assert_eq!(detect(&[0x30, 0x82, 0x0a, 0x00]), StoreKind::Pkcs12);
        assert_eq!(detect(b"PK"), StoreKind::Unknown);
        assert!(parse(&[0x30, 0x82, 0x0a, 0x00, 0, 0, 0, 0], "x").err().unwrap().contains("PKCS#12"));
    }

    #[test]
    fn parses_keytool_rsa_store_and_recovers_key() {
        let Some(b) = load("testdata/rsa.jks") else { return };
        let ks = parse(&b, "android").unwrap();
        assert_eq!(ks.keys.len(), 1);
        assert_eq!(ks.keys[0].alias, "test");
        assert_eq!(ks.keys[0].chain.len(), 1);
        assert_eq!(ks.keys[0].chain[0][0], 0x30);
        let pkcs8 = recover_key(&ks.keys[0].protected_key, "android").unwrap();
        assert!(ring::signature::RsaKeyPair::from_pkcs8(&pkcs8).is_ok(), "recovered key must be a valid PKCS#8 RSA key");
        assert!(recover_key(&ks.keys[0].protected_key, "wrong").unwrap_err().contains("wrong key password"));
        assert!(parse(&b, "wrong").err().unwrap().contains("integrity"));
        // truncation must not panic
        for cut in [4usize, 8, 12, 40, b.len() - 21, b.len() - 1] {
            assert!(parse(&b[..cut], "android").is_err());
        }
    }

    #[test]
    fn two_key_store_with_distinct_passwords() {
        let Some(b) = load("testdata/two.jks") else { return };
        let ks = parse(&b, "storepw").unwrap();
        // JKS writes entries in Hashtable order, so do not assume insertion order.
        let mut aliases: Vec<_> = ks.keys.iter().map(|k| k.alias.as_str()).collect();
        aliases.sort();
        assert_eq!(aliases, ["a", "b"], "aliases are stored lower-cased");
        let a = ks.keys.iter().find(|k| k.alias == "a").unwrap();
        let b = ks.keys.iter().find(|k| k.alias == "b").unwrap();
        assert!(recover_key(&a.protected_key, "keypw22").is_ok());
        assert!(recover_key(&a.protected_key, "keypw2b").is_err());
        assert!(recover_key(&b.protected_key, "keypw2b").is_ok());
    }
}
