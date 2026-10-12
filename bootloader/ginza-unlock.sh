#!/bin/sh
# shellcheck disable=SC2016
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")"/.. && pwd)
builder="$project_dir/bootloader/ginza_uenv.py"
fastboot="$project_dir/bootloader/fastboot-host.sh"

adb_bin=${ADB:-adb}
adb_serial=${ADB_SERIAL:-10.10.8.53:5555}
ssh_host=${GINZA_SSH_HOST:-10.10.8.53}
ssh_port=${GINZA_SSH_PORT:-2222}
ssh_key=${GINZA_SSH_KEY:-$HOME/.ssh/ginza_bot_ed25519}
known_hosts=${GINZA_KNOWN_HOSTS:-$HOME/.ssh/ginza_known_hosts}
state_dir=${GINZA_UNLOCK_STATE_DIR:-$HOME/.cache/ginza-bootloader-unlock}

target="root@$ssh_host"
uenv_device=/dev/block/by-name/uenv
mboot_device=/dev/block/by-name/mboot_b
uenv_mount=/mnt/vendor/uenv
remote_candidate=/data/local/tmp/ginza-uenv-fastboot.img
remote_stock=/data/local/tmp/ginza-uenv-stock.img
remote_state=/data/local/tmp/ginza-uenv-state

mboot_size=10485760
uenv_size=16777216
mboot_sha=f95082e5eb03bd813ba1b82d824c59693e22c5bc60fad309c8dc3a7cabebee11

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<EOF
usage: $0 preflight
       $0 enter-stock-fastboot
       $0 probe-stock-fastboot
       $0 prepare RUN_DIRECTORY
       $0 boot-prepared RUN_DIRECTORY
       $0 prove-unlocked RUN_DIRECTORY
       $0 restore-stock RUN_DIRECTORY
       $0 abort-prepared RUN_DIRECTORY
EOF
  exit 2
}

run_adb() {
  "$adb_bin" -s "$adb_serial" "$@"
}

run_ssh() {
  ssh \
    -i "$ssh_key" \
    -p "$ssh_port" \
    -o BatchMode=yes \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile="$known_hosts" \
    "$target" "$@"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

file_size() {
  stat -c %s "$1"
}

file_sha() {
  sha256sum "$1" | awk '{print $1}'
}

require_host_tools() {
  for command in "$adb_bin" ssh python3 sha256sum stat sed e2fsck debugfs; do
    require_command "$command"
  done
  [ -x "$builder" ] || die "bundle builder is unavailable: $builder"
  [ -x "$fastboot" ] || die "Fastboot wrapper is unavailable: $fastboot"
  [ -f "$ssh_key" ] || die "SSH key is unavailable: $ssh_key"
  [ -f "$known_hosts" ] || die "SSH known-hosts file is unavailable: $known_hosts"
  "$fastboot" --version >/dev/null
}

require_android_target() {
  [ "$(run_adb get-state 2>/dev/null)" = device ] || \
    die "ADB target $adb_serial is unavailable"

  identity=$(run_ssh '
    set -eu
    printf "%s\n" \
      "$(getprop ro.product.model)" \
      "$(getprop ro.product.device)" \
      "$(getprop ro.boot.slot_suffix)" \
      "$(getprop ro.build.version.incremental)" \
      "$(blockdev --getsize64 /dev/block/by-name/mboot_b)" \
      "$(blockdev --getsize64 /dev/block/by-name/uenv)" \
      "$(sha256sum /dev/block/by-name/mboot_b | awk '\''{print $1}'\'')" \
      "$(cat /proc/sys/kernel/random/boot_id)"
  ')
  expected=$(printf '%s\n' \
    AFTHU71990 \
    ginza \
    _b \
    0032280318340 \
    "$mboot_size" \
    "$uenv_size" \
    "$mboot_sha")
  actual=$(printf '%s\n' "$identity" | sed '$d')
  [ "$actual" = "$expected" ] || {
    printf 'Target identity is:\n%s\n' "$identity" >&2
    die "the connected Android target does not match the exact Ginza target"
  }
  boot_id=$(printf '%s\n' "$identity" | tail -1)
  [ -n "$boot_id" ] || die "the target boot ID is empty"
}

require_stock_mounted() {
  run_ssh '
    set -eu
    awk '\''
      $1 == "/dev/block/by-name/uenv" &&
      $2 == "/mnt/vendor/uenv" &&
      $3 == "ext4" { found = 1 }
      END { exit !found }
    '\'' /proc/mounts
    digest=$(sha256sum /mnt/vendor/uenv/uboot.env)
    [ "${digest%% *}" = "ed362a2f4ce8b15955e67e6e050f0e913c997e5becf404af040ce7f986de081f" ]
  ' || die "the mounted uenv partition does not contain the exact stock environment"
}

preflight() {
  require_host_tools
  require_android_target
  require_stock_mounted
  printf 'Exact target verified: AFTHU71990 ginza slot _b, boot %s\n' "$boot_id"
  printf 'Active mboot verified: %s\n' "$mboot_sha"
  printf 'Stock uenv and its environment file are mounted and verified.\n'
}

fastboot_serial() {
  devices=$($fastboot devices)
  count=$(printf '%s\n' "$devices" | awk 'NF { count++ } END { print count + 0 }')
  [ "$count" -eq 1 ] || die "expected one Fastboot device, found $count"
  protocol=$(printf '%s\n' "$devices" | awk 'NF { print $2 }')
  [ "$protocol" = fastboot ] || die "USB device does not report the Fastboot protocol"
  printf '%s\n' "$devices" | awk 'NF { print $1 }'
}

enter_stock_fastboot() {
  preflight
  [ -z "$($fastboot devices)" ] || die "a Fastboot device is already connected"
  run_adb reboot bootloader
  printf '%s\n' \
    'Stock bootloader entry requested.' \
    'Connect the USB data cable only after the TV reaches Fastboot, then run:' \
    "  $0 probe-stock-fastboot"
}

probe_stock_fastboot() {
  require_host_tools
  serial=$(fastboot_serial)
  mkdir -p "$state_dir"
  log=$(mktemp "$state_dir/stock-fastboot.XXXXXX")
  if ! "$fastboot" getvar all >"$log" 2>&1; then
    cat "$log" >&2
    rm -f "$log"
    die "the stock Fastboot getvar probe failed"
  fi
  cat "$log"
  digest=$(file_sha "$log")
  marker="$state_dir/stock-fastboot-proven"
  {
    printf 'serial=%s\n' "$serial"
    printf 'probe_sha256=%s\n' "$digest"
    printf 'probe_log=%s\n' "$log"
  } >"$marker.tmp"
  mv "$marker.tmp" "$marker"
  printf 'Stock Fastboot transport verified for %s.\n' "$serial"
  printf '%s\n' \
    'Leave the TV in Fastboot, disconnect the USB data cable, and power-cycle the TV.' \
    'Wait for Android and persistent root to return before preparing the candidate.'
}

require_fastboot_proof() {
  marker="$state_dir/stock-fastboot-proven"
  [ -s "$marker" ] || die "the stock Fastboot transport has not been proven"
  probe_digest=$(sed -n 's/^probe_sha256=//p' "$marker")
  probe_log=$(sed -n 's/^probe_log=//p' "$marker")
  if [ -z "$probe_digest" ] || [ ! -f "$probe_log" ]; then
    die "the stock Fastboot proof record is incomplete"
  fi
  [ "$(file_sha "$probe_log")" = "$probe_digest" ] || \
    die "the stock Fastboot proof log does not match its record"
}

mount_stock_uenv() {
  run_ssh '
    if ! awk '\''$2 == "/mnt/vendor/uenv" { found = 1 } END { exit !found }'\'' /proc/mounts; then
      mount -t ext4 -o noatime,nosuid,nodev,noexec \
        /dev/block/by-name/uenv /mnt/vendor/uenv
    fi
  '
}

remote_uenv_sha() {
  run_ssh 'sha256sum /dev/block/by-name/uenv' | awk '{print $1}'
}

verify_bundle() {
  run_dir=$1
  [ -f "$run_dir/mboot_b.img" ] || die "mboot capture is missing from $run_dir"
  [ -f "$run_dir/uenv-stock.img" ] || die "stock uenv capture is missing from $run_dir"
  [ -d "$run_dir/bundle" ] || die "bundle is missing from $run_dir"
  python3 "$builder" verify \
    "$run_dir/mboot_b.img" "$run_dir/bundle" --stock "$run_dir/uenv-stock.img"
}

prepare_candidate() {
  [ "$#" -eq 1 ] || usage
  run_dir=$1
  require_fastboot_proof
  preflight
  [ ! -e "$run_dir" ] || die "run directory already exists: $run_dir"

  umask 077
  mkdir -p "$run_dir"
  phase=mounted
  stock_digest=
  cleanup_prepare() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ] && [ "$phase" != 'done' ]; then
      echo "Preparation failed during phase: $phase" >&2
      remote_phase=$(run_ssh "cat $remote_state 2>/dev/null || true" 2>/dev/null || true)
      case "$remote_phase" in
        write-started|candidate-written)
          echo "Restoring the staged stock image before remounting uenv." >&2
          if [ -n "$stock_digest" ] && \
             [ "$(run_ssh "sha256sum $remote_stock" 2>/dev/null | awk '{print $1}')" = "$stock_digest" ] && \
             run_ssh "
               set -eu
               if awk '\$2 == \"$uenv_mount\" { found = 1 } END { exit !found }' /proc/mounts; then
                 umount $uenv_mount
               fi
               dd if=$remote_stock of=$uenv_device bs=1048576 count=16 conv=fsync status=none
               sync
             " && \
             [ "$(remote_uenv_sha 2>/dev/null)" = "$stock_digest" ]; then
            mount_stock_uenv || true
            echo "The complete stock uenv image was restored and verified." >&2
          else
            echo "AUTOMATIC STOCK RESTORE FAILED; keep the TV powered on and uenv unmounted." >&2
          fi
          ;;
        *)
          mount_stock_uenv || true
          ;;
      esac
    fi
    exit "$status"
  }
  trap cleanup_prepare EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM

  run_ssh "rm -f $remote_state $remote_candidate $remote_stock"
  run_ssh "dd if=$mboot_device bs=1048576 count=10 status=none" >"$run_dir/mboot_b.img"
  [ "$(file_size "$run_dir/mboot_b.img")" -eq "$mboot_size" ] || \
    die "active mboot capture has the wrong size"
  [ "$(file_sha "$run_dir/mboot_b.img")" = "$mboot_sha" ] || \
    die "active mboot capture has the wrong SHA-256"

  run_ssh '
    set -eu
    sync
    umount /mnt/vendor/uenv
    if awk '\''$2 == "/mnt/vendor/uenv" { found = 1 } END { exit !found }'\'' /proc/mounts; then
      echo "uenv remained mounted" >&2
      exit 1
    fi
  '
  phase=unmounted

  run_ssh "dd if=$uenv_device bs=1048576 count=16 status=none" >"$run_dir/uenv-stock.img"
  [ "$(file_size "$run_dir/uenv-stock.img")" -eq "$uenv_size" ] || \
    die "stock uenv capture has the wrong size"
  stock_digest=$(file_sha "$run_dir/uenv-stock.img")

  python3 "$builder" build \
    "$run_dir/mboot_b.img" "$run_dir/uenv-stock.img" "$run_dir/bundle"
  verify_bundle "$run_dir"
  candidate="$run_dir/bundle/uenv-fastboot.img"
  candidate_digest=$(file_sha "$candidate")

  run_ssh "cat >$remote_stock" <"$run_dir/uenv-stock.img"
  run_ssh "cat >$remote_candidate" <"$candidate"
  remote_stock_digest=$(run_ssh "sha256sum $remote_stock" | awk '{print $1}')
  remote_candidate_digest=$(run_ssh "sha256sum $remote_candidate" | awk '{print $1}')
  [ "$remote_stock_digest" = "$stock_digest" ] || die "staged stock image hash mismatch"
  [ "$remote_candidate_digest" = "$candidate_digest" ] || \
    die "staged candidate image hash mismatch"
  run_ssh "printf '%s\n' staged >$remote_state"

  run_ssh "
    set -eu
    if awk '\$2 == \"$uenv_mount\" { found = 1 } END { exit !found }' /proc/mounts; then
      echo 'uenv was remounted before the candidate write' >&2
      exit 1
    fi
    [ \"\$(blockdev --getsize64 $uenv_device)\" = $uenv_size ]
    printf '%s\n' write-started >$remote_state
    dd if=$remote_candidate of=$uenv_device bs=1048576 count=16 conv=fsync status=none
    sync
    printf '%s\n' candidate-written >$remote_state
  "
  phase='candidate-written'
  readback_digest=$(remote_uenv_sha)
  [ "$readback_digest" = "$candidate_digest" ] || die "candidate readback hash mismatch"

  {
    printf 'boot_id=%s\n' "$boot_id"
    printf 'stock_sha256=%s\n' "$stock_digest"
    printf 'candidate_sha256=%s\n' "$candidate_digest"
    printf 'mboot_sha256=%s\n' "$mboot_sha"
  } >"$run_dir/prepared"
  phase='done'
  trap - EXIT HUP INT TERM

  printf 'Candidate written and fully read back: %s\n' "$candidate_digest"
  printf 'Stock rollback image retained locally and on the TV: %s\n' "$stock_digest"
  printf '%s\n' \
    'The TV remains in Android with uenv unmounted. Do not power-cycle it yet.' \
    'When the USB data cable is disconnected and ready, run:' \
    "  $0 boot-prepared $run_dir"
}

boot_prepared() {
  [ "$#" -eq 1 ] || usage
  run_dir=$1
  require_fastboot_proof
  require_host_tools
  require_android_target
  verify_bundle "$run_dir"
  [ -s "$run_dir/prepared" ] || die "prepared marker is missing from $run_dir"
  candidate_digest=$(file_sha "$run_dir/bundle/uenv-fastboot.img")
  [ "$(remote_uenv_sha)" = "$candidate_digest" ] || \
    die "live uenv does not match the verified candidate"
  if run_ssh "awk '\$2 == \"$uenv_mount\" { found = 1 } END { exit !found }' /proc/mounts"; then
    die "candidate uenv is mounted; refusing to reboot"
  fi
  [ -z "$($fastboot devices)" ] || die "disconnect the USB data cable before rebooting"
  reboot_log=$(mktemp)
  run_ssh 'sync; echo GINZA-CANDIDATE-REBOOT; reboot' >"$reboot_log" 2>&1 || true
  if ! grep -qx GINZA-CANDIDATE-REBOOT "$reboot_log"; then
    cat "$reboot_log" >&2
    die "the reboot command did not reach the TV"
  fi
  printf '%s\n' \
    'Candidate boot requested.' \
    'Connect the USB data cable only after the TV reaches Fastboot, then run:' \
    "  $0 prove-unlocked $run_dir"
}

prove_unlocked() {
  [ "$#" -eq 1 ] || usage
  run_dir=$1
  require_host_tools
  verify_bundle "$run_dir"
  serial=$(fastboot_serial)
  log="$run_dir/fastboot-unlock-proof.log"
  marker="$run_dir/unlocked"
  [ ! -e "$marker" ] || die "this run already has a successful unlock proof"
  log_tmp="$run_dir/.fastboot-unlock-proof.$$"
  printf 'fastboot_serial=%s\n' "$serial" >"$log_tmp"
  if ! "$fastboot" getvar all >>"$log_tmp" 2>&1; then
    cat "$log_tmp" >&2
    mv "$log_tmp" "$run_dir/fastboot-unlock-proof.failed.log"
    die "the Fastboot getvar probe failed"
  fi
  if ! "$fastboot" flash mscript \
      "$run_dir/bundle/fastboot-unlock-probe-mscript.img" >>"$log_tmp" 2>&1; then
    cat "$log_tmp" >&2
    mv "$log_tmp" "$run_dir/fastboot-unlock-proof.failed.log"
    die "Fastboot rejected the RAM-only unlock probe"
  fi
  mv "$log_tmp" "$log"
  cat "$log"
  printf 'proof_sha256=%s\n' "$(file_sha "$log")" >"$marker"
  printf '%s\n' \
    'Unlocked Fastboot accepted and completed the scratch-RAM mscript probe.' \
    'No storage was written. Leave the TV in Fastboot and run:' \
    "  $0 restore-stock $run_dir"
}

restore_stock() {
  [ "$#" -eq 1 ] || usage
  run_dir=$1
  require_host_tools
  verify_bundle "$run_dir"
  serial=$(fastboot_serial)
  log="$run_dir/fastboot-stock-restore.log"
  marker="$run_dir/restored"
  [ ! -e "$marker" ] || die "this run already has a successful stock restore"
  log_tmp="$run_dir/.fastboot-stock-restore.$$"
  printf 'fastboot_serial=%s\n' "$serial" >"$log_tmp"
  if ! "$fastboot" flash mscript \
      "$run_dir/bundle/uenv-restore-mscript.img" >>"$log_tmp" 2>&1; then
    cat "$log_tmp" >&2
    mv "$log_tmp" "$run_dir/fastboot-stock-restore.failed.log"
    die "Fastboot did not complete the verified stock restore"
  fi
  mv "$log_tmp" "$log"
  cat "$log"
  printf 'proof_sha256=%s\n' "$(file_sha "$log")" >"$marker"
  printf '%s\n' \
    'The Fastboot script restored and compared the complete stock uenv partition.' \
    'Leave the TV in Fastboot, disconnect the USB data cable, and power-cycle the TV.'
}

abort_prepared() {
  [ "$#" -eq 1 ] || usage
  run_dir=$1
  require_host_tools
  require_android_target
  verify_bundle "$run_dir"
  stock_digest=$(file_sha "$run_dir/uenv-stock.img")
  remote_digest=$(run_ssh "sha256sum $remote_stock 2>/dev/null" | awk '{print $1}' || true)
  if [ "$remote_digest" != "$stock_digest" ]; then
    run_ssh "cat >$remote_stock" <"$run_dir/uenv-stock.img"
    remote_digest=$(run_ssh "sha256sum $remote_stock" | awk '{print $1}')
  fi
  [ "$remote_digest" = "$stock_digest" ] || die "staged stock image hash mismatch"
  if run_ssh "awk '\$2 == \"$uenv_mount\" { found = 1 } END { exit !found }' /proc/mounts"; then
    die "uenv is mounted; refusing a raw restore"
  fi
  run_ssh "dd if=$remote_stock of=$uenv_device bs=1048576 count=16 conv=fsync status=none && sync"
  [ "$(remote_uenv_sha)" = "$stock_digest" ] || die "stock restore readback hash mismatch"
  mount_stock_uenv
  run_ssh "rm -f $remote_candidate $remote_stock $remote_state"
  printf 'Stock uenv restored, fully read back, and mounted: %s\n' "$stock_digest"
}

[ "$#" -ge 1 ] || usage
action=$1
shift
case "$action" in
  preflight)
    [ "$#" -eq 0 ] || usage
    preflight
    ;;
  enter-stock-fastboot)
    [ "$#" -eq 0 ] || usage
    enter_stock_fastboot
    ;;
  probe-stock-fastboot)
    [ "$#" -eq 0 ] || usage
    probe_stock_fastboot
    ;;
  prepare) prepare_candidate "$@" ;;
  boot-prepared) boot_prepared "$@" ;;
  prove-unlocked) prove_unlocked "$@" ;;
  restore-stock) restore_stock "$@" ;;
  abort-prepared) abort_prepared "$@" ;;
  *) usage ;;
esac
