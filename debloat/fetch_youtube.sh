#!/bin/sh
set -eu

version=25.30.r1.v162.0
version_code=325311620
name=YouTube-FireTV-$version.apk
expected=0f8ad0f9a0b2b77444cf0a13397de7abcaa3f482f908163448967b0f899931cc
output=${1:-$name}
url=https://pool.apk.aptoide.com/nelcas/com-amazon-firetv-youtube-$version_code-75052314-f8a25a7054ada80b34d3b963b52c4baa.apk

curl -fL "$url" -o "$output"
actual=$(sha256sum "$output" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  echo "Unexpected Fire TV YouTube SHA-256: $actual" >&2
  exit 1
fi
printf '%s  %s\n' "$actual" "$output"
