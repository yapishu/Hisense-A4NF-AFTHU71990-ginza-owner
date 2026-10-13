#!/bin/sh
# shellcheck disable=SC2016
set -eu

platform_tools_url=https://dl.google.com/android/repository/platform-tools-latest-darwin.zip
tools_root=${GINZA_MAC_PLATFORM_TOOLS_ROOT:-$HOME/Library/Caches/ginza-platform-tools}
cached_tools=$tools_root/platform-tools
adb_serial=${ADB_SERIAL:-10.10.8.53:5555}
probe_sha256=ce7fb1c5c7d3c48f9338a3ede7b75ad269b53b208debf543e78ec750c6c62a7f
mboot_sha256=f95082e5eb03bd813ba1b82d824c59693e22c5bc60fad309c8dc3a7cabebee11

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<EOF
usage: $0 setup
       $0 preflight
       $0 enter-stock-fastboot
       $0 probe-stock-fastboot PROOF_DIRECTORY
       $0 devices
       $0 verify-bundle FASTBOOT_BUNDLE
       $0 prove-unlocked FASTBOOT_BUNDLE
       $0 restore-stock FASTBOOT_BUNDLE
EOF
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

select_tool() {
  name=$1
  override=$2
  if [ -n "$override" ]; then
    [ -x "$override" ] || die "$name override is not executable: $override"
    printf '%s\n' "$override"
  elif [ -x "$cached_tools/$name" ]; then
    printf '%s\n' "$cached_tools/$name"
  elif command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
  else
    die "$name is unavailable; run '$0 setup' first"
  fi
}

adb_path() {
  select_tool adb "${GINZA_ADB_BIN:-}"
}

fastboot_path() {
  select_tool fastboot "${GINZA_FASTBOOT_BIN:-}"
}

file_sha() {
  shasum -a 256 "$1" | awk '{print $1}'
}

file_size() {
  case $(uname -s) in
    Darwin) stat -f %z "$1" ;;
    *) stat -c %s "$1" ;;
  esac
}

json_value() {
  manifest=$1
  key=$2
  if [ -x /usr/bin/plutil ]; then
    /usr/bin/plutil -extract "$key" raw -o - "$manifest"
  elif command -v python3 >/dev/null 2>&1; then
    python3 - "$manifest" "$key" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for component in sys.argv[2].split("."):
    value = value[component]
print(value)
PY
  else
    die "bundle verification requires macOS plutil or python3"
  fi
}

require_fastboot() {
  require_command awk
  require_command shasum
  fastboot=$(fastboot_path)
  "$fastboot" --version >/dev/null
}

fastboot_serial() {
  devices=$($fastboot devices)
  count=$(printf '%s\n' "$devices" | awk 'NF { count++ } END { print count + 0 }')
  [ "$count" -eq 1 ] || die "expected one Fastboot device, found $count"
  protocol=$(printf '%s\n' "$devices" | awk 'NF { print $2 }')
  [ "$protocol" = fastboot ] || die "USB device does not report Fastboot"
  printf '%s\n' "$devices" | awk 'NF { print $1 }'
}

setup_tools() {
  [ "$(uname -s)" = Darwin ] || die "setup downloads the macOS Platform Tools build"
  require_command curl
  require_command ditto
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/ginza-platform-tools.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM
  curl --fail --location --proto '=https' --tlsv1.2 \
    "$platform_tools_url" -o "$tmp/platform-tools.zip"
  ditto -x -k "$tmp/platform-tools.zip" "$tmp/unpacked"
  [ -x "$tmp/unpacked/platform-tools/adb" ] || die "download lacks adb"
  [ -x "$tmp/unpacked/platform-tools/fastboot" ] || die "download lacks fastboot"
  mkdir -p "$tools_root"
  rm -rf "$cached_tools"
  mv "$tmp/unpacked/platform-tools" "$cached_tools"
  trap - EXIT HUP INT TERM
  rm -rf "$tmp"
  "$cached_tools/adb" --version
  "$cached_tools/fastboot" --version
  printf 'Platform Tools installed under %s\n' "$cached_tools"
}

require_exact_android() {
  adb=$(adb_path)
  "$adb" connect "$adb_serial" >/dev/null
  [ "$("$adb" -s "$adb_serial" get-state 2>/dev/null)" = device ] || \
    die "ADB target $adb_serial is unavailable"
  identity=$("$adb" -s "$adb_serial" shell '
    printf "%s\n" \
      "$(getprop ro.product.model)" \
      "$(getprop ro.product.device)" \
      "$(getprop ro.boot.slot_suffix)" \
      "$(getprop ro.build.version.incremental)"
  ' | tr -d '\r')
  expected=$(printf '%s\n' AFTHU71990 ginza _b 0032280318340)
  [ "$identity" = "$expected" ] || {
    printf 'Android target identity is:\n%s\n' "$identity" >&2
    die "ADB target does not match the exact Ginza TV"
  }
}

preflight() {
  require_fastboot
  require_exact_android
  [ -z "$($fastboot devices)" ] || die "disconnect the TV USB cable before preflight"
  printf '%s\n' \
    'Exact AFTHU71990 Ginza Android target verified.' \
    'No Fastboot USB device is connected.'
}

enter_stock_fastboot() {
  preflight
  adb=$(adb_path)
  "$adb" -s "$adb_serial" reboot bootloader
  printf '%s\n' \
    'Stock Fastboot entry requested.' \
    'Wait for the TV to reach Fastboot, connect the USB data cable, then run:' \
    "  $0 probe-stock-fastboot \"$HOME/Desktop/ginza-stock-fastboot-proof\""
}

probe_stock_fastboot() {
  [ "$#" -eq 1 ] || usage
  output=$1
  require_fastboot
  [ ! -e "$output" ] || die "proof directory already exists: $output"
  serial=$(fastboot_serial)
  tmp="$output.tmp.$$"
  mkdir -p "$tmp"
  log=$tmp/stock-fastboot.log
  {
    printf 'fastboot_serial=%s\n' "$serial"
    "$fastboot" --version
  } >"$log"
  if ! "$fastboot" getvar all >>"$log" 2>&1; then
    cat "$log" >&2
    rm -rf "$tmp"
    die "stock Fastboot getvar probe failed"
  fi
  digest=$(file_sha "$log")
  {
    printf 'format=1\n'
    printf 'serial=%s\n' "$serial"
    printf 'log_sha256=%s\n' "$digest"
  } >"$tmp/stock-fastboot-proof.env"
  mv "$tmp" "$output"
  cat "$output/stock-fastboot.log"
  printf '%s\n' \
    "Stock Fastboot transport verified for $serial." \
    "Proof record: $output" \
    'Disconnect the USB cable and power-cycle the TV. Do not use a Fastboot reboot command.'
}

verify_host_bundle() {
  [ "$#" -eq 1 ] || usage
  bundle=$1
  require_command shasum
  manifest=$bundle/manifest.json
  probe=$bundle/fastboot-unlock-probe-mscript.img
  restore=$bundle/uenv-restore-mscript.img
  [ -f "$manifest" ] || die "bundle manifest is missing: $manifest"
  [ -f "$probe" ] || die "unlock probe is missing: $probe"
  [ -f "$restore" ] || die "stock restore is missing: $restore"
  [ "$(json_value "$manifest" format)" = 2 ] || die "unsupported bundle format"
  [ "$(json_value "$manifest" target.model)" = AFTHU71990 ] || \
    die "bundle targets another model"
  [ "$(json_value "$manifest" target.device)" = ginza ] || \
    die "bundle targets another device"
  [ "$(json_value "$manifest" target.mboot_sha256)" = "$mboot_sha256" ] || \
    die "bundle targets another mboot image"
  [ "$(json_value "$manifest" files.probe.path)" = "$(basename "$probe")" ] || \
    die "bundle names another unlock probe"
  [ "$(json_value "$manifest" files.restore.path)" = "$(basename "$restore")" ] || \
    die "bundle names another stock restore"
  [ "$(file_size "$probe")" -eq 164 ] || die "unlock probe has the wrong size"
  [ "$(file_sha "$probe")" = "$probe_sha256" ] || \
    die "unlock probe has the wrong SHA-256"
  [ "$(json_value "$manifest" files.probe.sha256)" = "$probe_sha256" ] || \
    die "manifest names another unlock probe"
  [ "$(file_size "$restore")" -eq 33554432 ] || \
    die "stock restore has the wrong size"
  [ "$(file_sha "$restore")" = "$(json_value "$manifest" files.restore.sha256)" ] || \
    die "stock restore has the wrong SHA-256"
  printf 'Exact Fastboot proof and stock-restore payloads verified: %s\n' "$bundle"
}

prove_unlocked() {
  [ "$#" -eq 1 ] || usage
  bundle=$1
  verify_host_bundle "$bundle"
  require_fastboot
  serial=$(fastboot_serial)
  log=$bundle/fastboot-unlock-proof.log
  marker=$bundle/unlocked
  [ ! -e "$marker" ] || die "bundle already has a successful unlock proof"
  tmp=$bundle/.fastboot-unlock-proof.$$
  printf 'fastboot_serial=%s\n' "$serial" >"$tmp"
  if ! "$fastboot" getvar all >>"$tmp" 2>&1 || \
     ! "$fastboot" flash mscript \
       "$bundle/fastboot-unlock-probe-mscript.img" >>"$tmp" 2>&1; then
    cat "$tmp" >&2
    mv "$tmp" "$bundle/fastboot-unlock-proof.failed.log"
    die "unlocked Fastboot proof failed; leave the TV powered on in Fastboot"
  fi
  mv "$tmp" "$log"
  cat "$log"
  printf 'proof_sha256=%s\n' "$(file_sha "$log")" >"$marker"
  printf '%s\n' \
    'Unlocked Fastboot accepted the RAM-only mscript proof.' \
    'Leave the TV in Fastboot and run:' \
    "  $0 restore-stock \"$bundle\""
}

restore_stock() {
  [ "$#" -eq 1 ] || usage
  bundle=$1
  verify_host_bundle "$bundle"
  require_fastboot
  serial=$(fastboot_serial)
  [ -s "$bundle/unlocked" ] || die "successful unlock proof marker is missing"
  log=$bundle/fastboot-stock-restore.log
  marker=$bundle/restored
  [ ! -e "$marker" ] || die "bundle already has a successful stock restore"
  tmp=$bundle/.fastboot-stock-restore.$$
  printf 'fastboot_serial=%s\n' "$serial" >"$tmp"
  if ! "$fastboot" flash mscript \
    "$bundle/uenv-restore-mscript.img" >>"$tmp" 2>&1; then
    cat "$tmp" >&2
    mv "$tmp" "$bundle/fastboot-stock-restore.failed.log"
    die "verified stock restore failed; leave the TV powered on in Fastboot"
  fi
  mv "$tmp" "$log"
  cat "$log"
  printf 'proof_sha256=%s\n' "$(file_sha "$log")" >"$marker"
  printf '%s\n' \
    'The bootloader restored and compared the complete stock uenv partition.' \
    'Disconnect the USB cable and power-cycle the TV. Do not use a Fastboot reboot command.'
}

[ "$#" -ge 1 ] || usage
action=$1
shift
case "$action" in
  setup) [ "$#" -eq 0 ] || usage; setup_tools ;;
  preflight) [ "$#" -eq 0 ] || usage; preflight ;;
  enter-stock-fastboot) [ "$#" -eq 0 ] || usage; enter_stock_fastboot ;;
  probe-stock-fastboot) probe_stock_fastboot "$@" ;;
  devices) [ "$#" -eq 0 ] || usage; require_fastboot; "$fastboot" devices ;;
  verify-bundle) verify_host_bundle "$@" ;;
  prove-unlocked) prove_unlocked "$@" ;;
  restore-stock) restore_stock "$@" ;;
  *) usage ;;
esac
