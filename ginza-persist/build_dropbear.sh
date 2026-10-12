#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
output=${1:?usage: build_dropbear.sh OUTPUT}
sdk_root=${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT to an Android SDK directory}
ndk_root=${ANDROID_NDK_ROOT:-$sdk_root/ndk/27.0.12077973}
toolchain=$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin
tag=DROPBEAR_2026.94
archive=${DROPBEAR_ARCHIVE:-${TMPDIR:-/tmp}/dropbear-$tag.tar.gz}
archive_sha256=827d3f6e510e7554ee18d5c6a00dfee1a6a555559495e65e2e8f8d41c79eed84

for tool in curl make patch sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing $tool" >&2
    exit 1
  fi
done
for tool in armv7a-linux-androideabi30-clang llvm-ar llvm-ranlib llvm-strip; do
  if [ ! -x "$toolchain/$tool" ]; then
    echo "Missing $toolchain/$tool" >&2
    exit 1
  fi
done

if [ ! -f "$archive" ] ||
   ! printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c - >/dev/null 2>&1; then
  curl -L --fail --silent --show-error \
    "https://github.com/mkj/dropbear/archive/refs/tags/$tag.tar.gz" \
    -o "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c - >/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
tar -xzf "$archive" -C "$work"
source_dir=$work/dropbear-$tag
build_dir=$work/build
mkdir "$build_dir"
cp "$script_dir/dropbear/localoptions.h" "$build_dir/localoptions.h"
patch -d "$source_dir" -p1 < "$script_dir/dropbear/authorized-keys-dir.patch"

(
  cd "$build_dir"
  CC="$toolchain/armv7a-linux-androideabi30-clang" \
  AR="$toolchain/llvm-ar" \
  RANLIB="$toolchain/llvm-ranlib" \
  STRIP="$toolchain/llvm-strip" \
  CFLAGS='-O2 -fPIE -Wno-strict-prototypes -Wno-declaration-after-statement' \
  LDFLAGS='-pie' \
    "$source_dir/configure" \
      --host=arm-linux-androideabi \
      --disable-zlib \
      --disable-syslog \
      --disable-shadow \
      --disable-lastlog \
      --disable-utmp \
      --disable-utmpx \
      --disable-wtmp \
      --disable-wtmpx \
      --disable-loginfunc \
      --disable-pututline \
      --disable-pututxline >/dev/null
  make -s -j"${GINZA_BUILD_JOBS:-4}" NO_ADDTL_WARNINGS=1 \
    PROGRAMS='dropbear dropbearkey' MULTI=1
)

cp "$build_dir/dropbearmulti" "$output"
"$toolchain/llvm-strip" "$output"
chmod 755 "$output"
