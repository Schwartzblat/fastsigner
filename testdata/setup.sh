#!/bin/bash
# Populate testdata/: symlink the corpus APKs from KNOWLEDGE.md §1, generate RSA/EC test keys,
# build a tiny manifest-only APK, and produce apksigner reference outputs used by tests/differential.sh.
set -e
cd "$(dirname "$0")"
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
# Point at real small/medium/large APKs on your machine to build the differential-test
# corpus (e.g. FASTSIGNER_SMALL_APK=path/to/a.apk ./setup.sh); skipped if unset.
[ -z "${FASTSIGNER_SMALL_APK:-}" ] || ln -sf "$FASTSIGNER_SMALL_APK" small.apk
[ -z "${FASTSIGNER_MED_APK:-}" ] || ln -sf "$FASTSIGNER_MED_APK" med.apk
[ -z "${FASTSIGNER_BIG_APK:-}" ] || ln -sf "$FASTSIGNER_BIG_APK" big.apk
if [ ! -f rsa.pk8 ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key.pem 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in rsa.key.pem -outform DER -out rsa.pk8
  openssl req -new -x509 -key rsa.key.pem -days 3650 -subj "/CN=fastsigner test RSA" -out rsa.cert.pem 2>/dev/null
fi
if [ ! -f ec.pk8 ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out ec.key.pem
  openssl pkcs8 -topk8 -nocrypt -in ec.key.pem -outform DER -out ec.pk8
  openssl req -new -x509 -key ec.key.pem -days 3650 -subj "/CN=fastsigner test EC" -out ec.cert.pem 2>/dev/null
fi
# Real JKS stores (JDK 9+ keytool writes PKCS#12 unless -storetype JKS is given).
[ -f rsa.jks ] || keytool -genkeypair -storetype JKS -keystore rsa.jks -storepass android -keypass android -alias test \
  -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=fastsigner jks rsa" >/dev/null 2>&1
[ -f ec.jks ] || keytool -genkeypair -storetype JKS -keystore ec.jks -storepass android -keypass android -alias eckey \
  -keyalg EC -groupname secp256r1 -validity 3650 -dname "CN=fastsigner jks ec" >/dev/null 2>&1
if [ ! -f two.jks ]; then  # two keys, store password != key passwords
  keytool -genkeypair -storetype JKS -keystore two.jks -storepass storepw -keypass keypw22 -alias a -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=a" >/dev/null 2>&1
  keytool -genkeypair -storetype JKS -keystore two.jks -storepass storepw -keypass keypw2b -alias B -keyalg EC -groupname secp256r1 -validity 3650 -dname "CN=b" >/dev/null 2>&1
fi
# PKCS#12 stores: JDK 12+ keytool and OpenSSL 3 both default to PBES2 (PBKDF2-HMAC-SHA256 +
# AES-256-CBC) with an HMAC-SHA256 MAC. Variants cover AES-128, SHA-1 MAC and unencrypted cert bags.
[ -f rsa.p12 ] || keytool -genkeypair -storetype PKCS12 -keystore rsa.p12 -storepass android -alias test \
  -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=fastsigner p12 rsa" >/dev/null 2>&1
[ -f ec.p12 ] || keytool -genkeypair -storetype PKCS12 -keystore ec.p12 -storepass android -alias ECKey \
  -keyalg EC -groupname secp256r1 -validity 3650 -dname "CN=fastsigner p12 ec" >/dev/null 2>&1
if [ ! -f two.p12 ]; then
  keytool -genkeypair -storetype PKCS12 -keystore two.p12 -storepass storepw -alias a -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=a" >/dev/null 2>&1
  keytool -genkeypair -storetype PKCS12 -keystore two.p12 -storepass storepw -alias B -keyalg EC -groupname secp256r1 -validity 3650 -dname "CN=b" >/dev/null 2>&1
fi
[ -f ossl.p12 ] || openssl pkcs12 -export -inkey rsa.key.pem -in rsa.cert.pem -name ossl -passout pass:android -out ossl.p12
[ -f ossl_aes128_sha1mac.p12 ] || openssl pkcs12 -export -inkey ec.key.pem -in ec.cert.pem -name ec -passout pass:android \
  -keypbe AES-128-CBC -certpbe NONE -macalg sha1 -out ossl_aes128_sha1mac.p12
if [ ! -f chain.p12 ]; then  # CA-signed leaf; CA cert stored before the leaf to exercise chain ordering
  openssl req -new -x509 -newkey rsa:2048 -nodes -keyout ca.key.pem -days 3650 -subj "/CN=fastsigner test CA" -out ca.cert.pem 2>/dev/null
  openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key.pem -subj "/CN=fastsigner test leaf" -out leaf.csr 2>/dev/null
  openssl x509 -req -in leaf.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -days 3650 -out leaf.cert.pem 2>/dev/null
  cat ca.cert.pem leaf.cert.pem > chain.pem
  openssl pkcs12 -export -inkey leaf.key.pem -in chain.pem -name leaf -passout pass:android -out chain.p12
  rm -f leaf.csr ca.cert.srl chain.pem
fi
[ -f ossl_legacy.p12 ] || openssl pkcs12 -export -legacy -inkey rsa.key.pem -in rsa.cert.pem -name old -passout pass:android -out ossl_legacy.p12 2>/dev/null || true
if [ ! -f rsa4096.p12 ]; then  # RSA above 3072 bits: apksig switches the content digest to SHA-512
  openssl req -new -x509 -newkey rsa:4096 -nodes -keyout rsa4096.key.pem -days 3650 -subj "/CN=fastsigner test RSA-4096" -out rsa4096.cert.pem 2>/dev/null
  openssl pkcs12 -export -inkey rsa4096.key.pem -in rsa4096.cert.pem -name big -passout pass:android -out rsa4096.p12
fi
python3 - <<'PY'
import zipfile
man = zipfile.ZipFile('small.apk').read('AndroidManifest.xml')
with zipfile.ZipFile('tiny.apk', 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('AndroidManifest.xml', man)
PY
$AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out ref_small_rsa.apk small.apk
$AS sign --key ec.pk8 --cert ec.cert.pem --v1-signing-enabled false --out ref_small_ec.apk small.apk
$AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --v3-signing-enabled false --out ref_small_rsa_v2only.apk small.apk
$AS sign --ks rsa.jks --ks-pass pass:android --ks-key-alias test --v1-signing-enabled false --out ref_small_jks.apk small.apk
$AS sign --ks rsa.p12 --ks-pass pass:android --v1-signing-enabled false --out ref_small_p12.apk small.apk
$AS sign --ks ossl.p12 --ks-pass pass:android --v1-signing-enabled false --out ref_small_ossl_p12.apk small.apk
$AS sign --ks chain.p12 --ks-pass pass:android --v1-signing-enabled false --out ref_small_chain_p12.apk small.apk
$AS sign --ks rsa4096.p12 --ks-pass pass:android --v1-signing-enabled false --out ref_small_rsa4096_p12.apk small.apk
# Unaligned copies (Python's zipfile writes no alignment padding) + apksigner's output for them:
# the zipalign rewrite path must reproduce apksigner byte for byte.
python3 - <<'PY'
import zipfile
for src, dst in [('small.apk', 'ua_small.apk'), ('big.apk', 'ua_big.apk')]:
    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, 'w') as zo:
        for i in zi.infolist():
            zo.writestr(i, zi.read(i.filename), compress_type=i.compress_type)
PY
$AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out ref_ua_small.apk ua_small.apk
$AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out ref_ua_big.apk ua_big.apk
rm -f *.idsig
ls -la
