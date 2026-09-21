#!/bin/bash
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
K=(--key key.pk8 --cert cert.pem --v1-signing-enabled false)
cp big.apk inplace.apk
echo "--- apksigner in-place (no --out) on 138MB, v2+v3 ---"
for i in 1 2; do /usr/bin/time -f "  in-place wall=%es" "$AS" sign "${K[@]}" inplace.apk 2>&1 | grep wall=; done
echo "--- apksigner with --out (fresh copy) ---"
for i in 1 2; do /usr/bin/time -f "  --out    wall=%es" "$AS" sign "${K[@]}" --out o4.apk big.apk 2>&1 | grep wall=; done
