#!/bin/bash
# Rewrite-path oracle: for every APK in the local corpus, build an unaligned copy (Python's
# zipfile writes no alignment padding), sign it with apksigner and with fastsigner using the same
# RSA key, and require byte-identical output. RSA PKCS#1 v1.5 is deterministic, so this checks
# the whole entries rewrite (0xd935 padding, dropped entries, gap copies) plus the signing block.
# Usage: tests/corpus_identity.sh [max_apks=12] [max_mb=200]
cd "$(dirname "$0")/../testdata" || exit 1
FS=../target/release/fastsigner
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
ZA=~/Android/Sdk/build-tools/37.0.0/zipalign
MAX=${1:-12}; MAXMB=${2:-200}
mkdir -p corpus_tmp
n=0; pass=0; fail=0
while IFS= read -r f; do
  [ "$n" -ge "$MAX" ] && break
  sz=$(stat -L -c %s "$f"); [ "$sz" -gt $((MAXMB * 1024 * 1024)) ] && continue
  n=$((n + 1))
  base=$(basename "$f" .apk | tr -c 'A-Za-z0-9._-' '_')
  ua="corpus_tmp/ua_$base.apk"
  python3 - "$f" "$ua" <<'PY'
import sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, 'w') as zo:
    for i in zi.infolist():
        zo.writestr(i, zi.read(i.filename), compress_type=i.compress_type)
PY
  if ! $AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out "corpus_tmp/ref_$base.apk" "$ua" 2>/dev/null; then
    printf "  SKIP  %-50s apksigner cannot sign it\n" "$base"; n=$((n - 1)); continue
  fi
  rm -f corpus_tmp/*.idsig
  cp -f "$ua" "corpus_tmp/fs_$base.apk"
  # A rebuilt APK can be aligned by chance (few, small entries); fastsigner would then take the
  # splice fast path, which keeps orphaned records apksigner drops. Force the rewrite in that case.
  mode="misaligned input"; extra=""
  if $ZA -c -P 16 4 "$ua" >/dev/null 2>&1; then mode="aligned by chance, --zipalign always"; extra="--zipalign always"; fi
  t0=$(date +%s%N)
  $FS sign --key rsa.pk8 --cert rsa.cert.pem $extra "corpus_tmp/fs_$base.apk" 2>"corpus_tmp/err.txt"
  ms=$(( ($(date +%s%N) - t0) / 1000000 ))
  if cmp -s "corpus_tmp/ref_$base.apk" "corpus_tmp/fs_$base.apk" && $ZA -c -P 16 4 "corpus_tmp/fs_$base.apk" >/dev/null 2>&1; then
    printf "  PASS  %-50s %4d ms  %6d KB identical to apksigner, zipalign -c ok (%s)\n" "$base" "$ms" $((sz / 1024)) "$mode"; pass=$((pass + 1))
  else
    printf "  FAIL  %-50s %s\n" "$base" "$(head -c 200 corpus_tmp/err.txt)"; cmp "corpus_tmp/ref_$base.apk" "corpus_tmp/fs_$base.apk" | head -1; fail=$((fail + 1))
  fi
done < <(find /home/alon/ApkProjects /home/alon/tools/ASC /home/alon/Documents/old_pc_user/Downloads /home/alon/workspace/PycharmProjects -maxdepth 3 -name "*.apk" -size +100k 2>/dev/null | sort -u)
rm -rf corpus_tmp
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
