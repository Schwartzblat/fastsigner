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
