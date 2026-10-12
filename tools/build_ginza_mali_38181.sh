#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
output=${1:-ginza_mali_38181}
zig=${ZIG:-zig}

exec "$zig" cc \
  -target arm-linux-musleabi \
  -O2 \
  -static \
  -Wall \
  -Wextra \
  -Wpedantic \
  -Werror \
  -pthread \
  "$script_dir/ginza_mali_38181.c" \
  -o "$output"
