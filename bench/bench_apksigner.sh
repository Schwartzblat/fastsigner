#!/bin/bash
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
KS=(--ks test.jks --ks-pass pass:android --ks-key-alias test --key-pass pass:android)
run() {
  local label="$1" f="$2"; shift 2
  echo "--- $f.apk | $label ---"
  for i in 1 2; do
    /usr/bin/time -f "  wall=%es user=%Us sys=%Ss cpu=%P maxrss=%MkB" \
      "$AS" sign "${KS[@]}" "$@" --out "out_$f.apk" "$f.apk"
    rc=$?; [ $rc -ne 0 ] && echo "  FAILED rc=$rc"
  done
}
for f in small med big; do
  run "v1+v2+v3 (default)" $f
  run "v2+v3 only"         $f --v1-signing-enabled false
  run "v1 only"            $f --v2-signing-enabled false --v3-signing-enabled false
  run "v2 only"            $f --v1-signing-enabled false --v3-signing-enabled false
done
