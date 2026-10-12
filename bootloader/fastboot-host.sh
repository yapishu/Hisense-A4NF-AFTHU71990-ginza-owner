#!/bin/sh
set -eu

root=${GINZA_FASTBOOT_ROOT:-"$HOME/.cache/ginza-fastboot-host/root"}
binary="$root/usr/bin/fastboot"
library="$root/usr/lib/x86_64-linux-gnu/android"

[ -x "$binary" ] || {
  echo "fastboot is unavailable at $binary" >&2
  exit 1
}

LD_LIBRARY_PATH="$library${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  exec "$binary" "$@"
