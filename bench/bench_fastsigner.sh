#!/bin/bash
# Wall-clock comparison: fastsigner (in place) vs apksigner (--out), v2+v3, raw pk8/pem key; then
# fastsigner with a PKCS#12 keystore and with --out. Times are spawn to exit (bench/runbench.c,
# built with gcc on first use), so no shell or `date` overhead is included.
# Run from the repo root; expects testdata/{tiny,small,med,big}.apk, testdata/rsa.{pk8,cert.pem,p12}.
# Usage: [FS=path/to/fastsigner] bench/bench_fastsigner.sh [runs=20] [apks="tiny small med big"]
cd "$(dirname "$0")/../testdata" || exit 1
FS=${FS:-../target/release/fastsigner}
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
RB=../target/runbench
RUNS=${1:-20}
APKS=${2:-"tiny small med big"}
[ "$RB" -nt ../bench/runbench.c ] || gcc -O2 -o "$RB" ../bench/runbench.c || exit 1

printf "%-6s %10s  %-44s  %s\n" "apk" "bytes" "fastsigner in place ($RUNS runs)" "apksigner --out (3 runs)"
for f in $APKS; do
  [ -e "$f.apk" ] || { echo "missing $f.apk"; continue; }
  cp -f "$f.apk" "bench_$f.apk"
  $FS sign --key rsa.pk8 --cert rsa.cert.pem "bench_$f.apk" || exit 1   # warm-up + first sign
  fs=$($RB "$RUNS" $FS sign --key rsa.pk8 --cert rsa.cert.pem "bench_$f.apk") || exit 1
  as=$($RB 3 $AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out "bench_${f}_as.apk" "$f.apk") || exit 1
  printf "%-6s %10d  %-44s  %s\n" "$f" "$(stat -L -c %s "$f.apk")" "$fs" "$as"
  $AS verify --min-sdk-version 24 "bench_$f.apk" || echo "  !! fastsigner output does not verify"
done

echo
printf "%-6s  %-44s  %s\n" "apk" "fastsigner, PKCS#12 keystore, in place" "fastsigner --out (existing output)"
for f in $APKS; do
  [ -e "bench_$f.apk" ] || continue
  p12=$($RB "$RUNS" $FS sign --ks rsa.p12 --ks-pass pass:android "bench_$f.apk") || exit 1
  out=$($RB "$RUNS" $FS sign --key rsa.pk8 --cert rsa.cert.pem --out "bench_${f}_out.apk" "bench_$f.apk") || exit 1
  printf "%-6s  %-44s  %s\n" "$f" "$p12" "$out"
done
rm -f bench_*.apk bench_*.idsig

echo
echo "thread scaling on big.apk (in-process digest phase, --timing):"
cp -f big.apk bench_big.apk
for t in 1 4 8 16 24 32; do
  best=$(for i in 1 2 3 4 5; do $FS sign --key rsa.pk8 --cert rsa.cert.pem --threads $t --timing bench_big.apk 2>&1 | awk '/digest/{print $2}'; done | sort -n | head -1)
  printf "  threads=%-3s digest best-of-5 = %s ms\n" "$t" "$best"
done
rm -f bench_big.apk
