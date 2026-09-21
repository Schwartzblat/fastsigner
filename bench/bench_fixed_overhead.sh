#!/bin/bash
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
M=(--min-sdk-version 24)
echo "--- tiny.apk (111 bytes, 1 entry) = pure fixed overhead ---"
for i in 1 2 3; do /usr/bin/time -f "  JKS keystore   wall=%es" "$AS" sign "${M[@]}" --ks test.jks --ks-pass pass:android --ks-key-alias test --key-pass pass:android --out o1.apk tiny.apk 2>&1 | grep wall= ; done
for i in 1 2 3; do /usr/bin/time -f "  raw pk8+pem    wall=%es" "$AS" sign "${M[@]}" --key key.pk8 --cert cert.pem --out o2.apk tiny.apk 2>&1 | grep wall=; done
