#!/bin/bash
AAPT=~/Android/Sdk/build-tools/36.0.0/aapt2
AS=~/Android/Sdk/build-tools/37.0.0/apksigner
printf "%-42s %6s %6s  %-5s %s\n" "APK" "minSdk" "target" "v1?" "schemes actually present"
printf "%-42s %6s %6s  %-5s %s\n" "---" "------" "------" "---" "------------------------"
# Directories to scan for a corpus of real APKs; pass your own on the command line.
dirs=("$@"); [ ${#dirs[@]} -eq 0 ] && dirs=("$HOME")
find "${dirs[@]}" -maxdepth 3 -name "*.apk" 2>/dev/null | sort -u | head -30 | while read -r f; do
  b=$("$AAPT" dump badging "$f" 2>/dev/null)
  mn=$(printf '%s' "$b" | sed -n "s/^minSdkVersion:'\([0-9]*\)'.*/\1/p" | head -1)
  tg=$(printf '%s' "$b" | sed -n "s/^targetSdkVersion:'\([0-9]*\)'.*/\1/p" | head -1)
  v=$("$AS" verify --verbose "$f" 2>/dev/null | awk '/^Verified using v/ && /true/ {match($0,/v[0-9.]+/); printf "%s ", substr($0,RSTART,RLENGTH)}')
  [ -z "$v" ] && v="(verify failed)"
  need="no"; [ -n "$mn" ] && [ "$mn" -lt 24 ] 2>/dev/null && need="YES"
  printf "%-42s %6s %6s  %-5s %s\n" "$(basename "$f" | cut -c1-41)" "${mn:-?}" "${tg:-?}" "$need" "$v"
done
