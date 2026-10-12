#!/bin/sh
set -eu

version=v2026.10.03
name=LTvLauncher-armeabi-v7a-release.apk
expected=ec77396eb05acbf22c59b27e121f59073e1da397404d0cd6a26f4f1c5eaa8221
output=${1:-$name}
url=https://github.com/leanbitlab-org/LtvLauncher/releases/download/$version/$name

curl -fL "$url" -o "$output"
actual=$(sha256sum "$output" | awk '{print $1}')
if [ "$actual" != "$expected" ]; then
  echo "Unexpected LTvLauncher SHA-256: $actual" >&2
  exit 1
fi
printf '%s  %s\n' "$actual" "$output"
