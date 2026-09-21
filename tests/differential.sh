#!/bin/bash
# End-to-end checks against the reference implementation.
#   1. byte identity: re-signing apksigner's RSA output must reproduce it exactly
#   2. every corpus APK × key signs (--out and in place) and passes `apksigner verify`
#   3. --v1-signing-enabled true is refused
# Requires testdata/setup.sh to have run and target/release/fastsigner to be built.
cd "$(dirname "$0")/../testdata" || exit 1
FS=../target/release/fastsigner
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
fail=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; fail=1; }
verify() { $AS verify --verbose --min-sdk-version 24 "$1" 2>/dev/null | grep -q "^Verified using v2 .*true" && $AS verify --verbose --min-sdk-version 24 "$1" 2>/dev/null | grep -q "^Verified using v3 .*true"; }

echo "== byte identity with apksigner 37.0.0 (RSA is deterministic) =="
cp -f ref_small_rsa.apk t_id.apk && $FS sign --key rsa.pk8 --cert rsa.cert.pem t_id.apk && cmp -s ref_small_rsa.apk t_id.apk && ok "v2+v3 identical" || bad "v2+v3 identical"
cp -f ref_small_rsa_v2only.apk t_id2.apk && $FS sign --key rsa.pk8 --cert rsa.cert.pem --v3-signing-enabled false t_id2.apk && cmp -s ref_small_rsa_v2only.apk t_id2.apk && ok "v2-only identical" || bad "v2-only identical"

echo "== sign + apksigner verify =="
for apk in tiny small med big; do
  [ -e "$apk.apk" ] || { echo "  SKIP  $apk.apk missing"; continue; }
  for key in rsa ec; do
    $FS sign --key $key.pk8 --cert $key.cert.pem --out t_${apk}_$key.apk $apk.apk && verify t_${apk}_$key.apk && ok "$apk $key --out" || bad "$apk $key --out"
  done
  cp -f "$apk.apk" t_${apk}_inplace.apk
  $FS sign --key ec.pk8 --cert ec.cert.pem t_${apk}_inplace.apk && verify t_${apk}_inplace.apk && ok "$apk ec in-place" || bad "$apk ec in-place"
  $FS sign --key rsa.pk8 --cert rsa.cert.pem t_${apk}_inplace.apk && verify t_${apk}_inplace.apk && ok "$apk rsa re-sign in-place" || bad "$apk rsa re-sign in-place"
done

echo "== JKS keystores =="
cp -f ref_small_jks.apk t_jks.apk && $FS sign --ks rsa.jks --ks-pass pass:android --ks-key-alias test t_jks.apk && cmp -s ref_small_jks.apk t_jks.apk && ok "JKS RSA identical to apksigner --ks output" || bad "JKS RSA identical"
$FS sign --ks rsa.jks --ks-pass pass:android --out t_jks2.apk small.apk && verify t_jks2.apk && ok "JKS single key, alias omitted" || bad "JKS alias omitted"
$FS sign --ks ec.jks --ks-pass pass:android --ks-key-alias ECKEY --out t_jks3.apk small.apk && verify t_jks3.apk && ok "JKS EC key (public key recovered from cert)" || bad "JKS EC"
echo storepw > t_pw.txt; KP=keypw2b $FS sign --ks two.jks --ks-pass file:t_pw.txt --ks-key-alias b --key-pass env:KP --out t_jks4.apk small.apk && verify t_jks4.apk && ok "JKS alias b, key-pass env:, ks-pass file:" || bad "JKS two.jks"
echo android | $FS sign --ks rsa.jks --ks-pass stdin --out t_jks5.apk small.apk && verify t_jks5.apk && ok "JKS ks-pass stdin" || bad "JKS stdin"
$FS sign --ks two.jks --ks-pass pass:storepw --out t_x.apk small.apk 2>/dev/null && bad "alias required with 2 keys" || ok "alias required with 2 keys"
$FS sign --ks two.jks --ks-pass pass:wrong --ks-key-alias a --out t_x.apk small.apk 2>/dev/null && bad "wrong store password refused" || ok "wrong store password refused"
$FS sign --ks two.jks --ks-pass pass:storepw --ks-key-alias b --key-pass pass:keypw22 --out t_x.apk small.apk 2>/dev/null && bad "wrong key password refused" || ok "wrong key password refused"

echo "== batch mode =="
rm -rf t_out && $FS sign --key rsa.pk8 --cert rsa.cert.pem --out-dir t_out tiny.apk small.apk med.apk big.apk && verify t_out/tiny.apk && verify t_out/small.apk && verify t_out/med.apk && verify t_out/big.apk && ok "--out-dir 4 APKs" || bad "--out-dir 4 APKs"
for i in 1 2 3 4 5 6; do cp -f small.apk t_b$i.apk; done
$FS sign --ks ec.jks --ks-pass pass:android --jobs 3 t_b?.apk && for i in 1 2 3 4 5 6; do verify t_b$i.apk || exit 1; done && ok "in-place batch, 6 APKs, --jobs 3" || bad "in-place batch"
echo notazip > t_bad.apk; cp -f small.apk t_g.apk
$FS sign --key ec.pk8 --cert ec.cert.pem t_g.apk t_bad.apk 2>/dev/null; [ $? -eq 1 ] && verify t_g.apk && ok "bad input reported, good input still signed, exit 1" || bad "partial failure handling"
$FS sign --key ec.pk8 --cert ec.cert.pem --out t_x.apk t_g.apk t_b1.apk 2>/dev/null && bad "--out with 2 inputs refused" || ok "--out with 2 inputs refused"
rm -rf t_out t_pw.txt

echo "== flags =="
$FS sign --key ec.pk8 --cert ec.cert.pem --v1-signing-enabled true --out t_v1.apk small.apk 2>/dev/null && bad "--v1 must be refused" || ok "--v1-signing-enabled true refused"
$FS sign --key rsa.pk8 --cert ec.cert.pem --out t_mm.apk small.apk 2>/dev/null && bad "key/cert mismatch must be refused" || ok "key/cert mismatch refused"
$FS sign --key rsa.pk8 --cert rsa.cert.pem --v2-signing-enabled false --out t_v3.apk small.apk && $AS verify --verbose --min-sdk-version 28 t_v3.apk 2>/dev/null | grep -q "^Verified using v3 .*true" && ok "v3-only verifies" || bad "v3-only verifies"

rm -rf t_*.apk t_*.idsig t_out t_pw.txt
[ $fail -eq 0 ] && echo "ALL PASS" || { echo "FAILURES"; exit 1; }
