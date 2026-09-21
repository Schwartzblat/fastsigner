#!/bin/bash
# Wall-clock comparison: fastsigner (in place) vs apksigner (--out), v2+v3, raw pk8/pem key.
# Run from the repo root; expects testdata/{tiny,small,med,big}.apk and testdata/rsa.{pk8,cert.pem}.
# Usage: bench/bench_fastsigner.sh [runs=20] [apks="tiny small med big"]
cd "$(dirname "$0")/../testdata" || exit 1
FS=../target/release/fastsigner
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
RUNS=${1:-20}
APKS=${2:-"tiny small med big"}
ms_now() { date +%s%N; }
stats() { sort -n | awk '{a[NR]=$1} END{printf "min=%.2f  median=%.2f  max=%.2f ms", a[1]/1e6, a[int((NR+1)/2)]/1e6, a[NR]/1e6}'; }

printf "%-6s %10s  %-46s  %s\n" "apk" "bytes" "fastsigner in-place (wall, $RUNS runs)" "apksigner --out (wall, 3 runs)"
for f in $APKS; do
  [ -e "$f.apk" ] || { echo "missing $f.apk"; continue; }
  cp -f "$f.apk" "bench_$f.apk"
  $FS sign --key rsa.pk8 --cert rsa.cert.pem "bench_$f.apk" || exit 1   # warm-up + first sign
  fs=$(for i in $(seq "$RUNS"); do t0=$(ms_now); $FS sign --key rsa.pk8 --cert rsa.cert.pem "bench_$f.apk" || exit 1; echo $(( $(ms_now) - t0 )); done | stats)
  as=$(for i in 1 2 3; do t0=$(ms_now); $AS sign --key rsa.pk8 --cert rsa.cert.pem --v1-signing-enabled false --out "bench_${f}_as.apk" "$f.apk" || exit 1; echo $(( $(ms_now) - t0 )); done | stats)
  printf "%-6s %10d  %-46s  %s\n" "$f" "$(stat -L -c %s "$f.apk")" "$fs" "$as"
  $AS verify --min-sdk-version 24 "bench_$f.apk" || echo "  !! fastsigner output does not verify"
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
