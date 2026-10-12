#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 APK AUTHORIZED_KEYS [ADB_SERIAL]" >&2
  exit 2
fi

apk=$1
keys=$2
serial=${3:-}
adb_bin=${ADB:-adb}
package=io.github.ginzaroot.autostart
component=$package/.RootService

run_adb() {
  if [ -n "$serial" ]; then
    "$adb_bin" -s "$serial" "$@"
  else
    "$adb_bin" "$@"
  fi
}

if [ ! -f "$apk" ]; then
  echo "APK not found: $apk" >&2
  exit 1
fi
if [ ! -s "$keys" ]; then
  echo "Authorized-key file is missing or empty: $keys" >&2
  exit 1
fi

key_count=$(awk '
  /^[[:space:]]*($|#)/ { next }
  $1 != "ssh-ed25519" && $1 != "ssh-rsa" { exit 2 }
  { count++ }
  END { print count + 0 }
' "$keys") || {
  echo "Authorized-key file contains an unsupported entry" >&2
  exit 1
}
if [ "$key_count" -lt 1 ] || [ "$key_count" -gt 16 ]; then
  echo "Authorized-key file must contain between 1 and 16 keys" >&2
  exit 1
fi

encoded=$(base64 "$keys" | tr -d '\n')
digest=$(sha256sum "$keys" | awk '{print $1}')

run_adb install -r "$apk"
run_adb shell am start-foreground-service \
  -n "$component" \
  --es mode provision-keys \
  --es authorizedKeys "$encoded" \
  --ez immediate true
sleep 2
run_adb shell "logcat -d -v brief -s GinzaRoot | grep 'Provisioned authorized_keys' | tail -1" || true
printf 'authorized_keys: %s (%s keys)\n' "$digest" "$key_count"
printf 'Reboot the TV to start the guarded boot-time root attempt.\n'
