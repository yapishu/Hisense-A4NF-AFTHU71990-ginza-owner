#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
policy=${GINZA_DEBLOAT_POLICY:-$project_dir/packages.txt}
uninstall_policy=${GINZA_UNINSTALL_POLICY:-$project_dir/uninstall-packages.txt}
adb_bin=${ADB:-adb}
adb_server_port=${ADB_SERVER_PORT:-5037}
adb_serial=${ADB_SERIAL:-10.10.8.53:5555}
ssh_host=${GINZA_SSH_HOST:-10.10.8.53}
ssh_port=${GINZA_SSH_PORT:-2222}
ssh_key=${GINZA_SSH_KEY:-$HOME/.ssh/ginza_bot_ed25519}
known_hosts=${GINZA_KNOWN_HOSTS:-$HOME/.ssh/ginza_known_hosts}
service=io.github.ginzaroot.autostart/.RootService
stock_home=com.amazon.tv.launcher/.ui.HomeActivity_vNext

"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell am start-foreground-service \
  -n "$service" \
  --es mode clear-debloat \
  --ez immediate true

awk '
  { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
  $0 != "" && $0 !~ /^#/ { print }
' "$uninstall_policy" | ssh \
  -i "$ssh_key" \
  -p "$ssh_port" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$known_hosts" \
  "root@$ssh_host" '
    set -eu
    toybox killall -CONT update_engine || true
    while IFS= read -r target; do
      cmd package install-existing --user 0 "$target"
    done
  '

awk '
  { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
  $0 != "" && $0 !~ /^#/ { print }
' "$policy" | ssh \
  -i "$ssh_key" \
  -p "$ssh_port" \
  -o BatchMode=yes \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$known_hosts" \
  "root@$ssh_host" '
    set -eu
    while IFS= read -r target; do
      pm enable --user 0 "$target"
    done
  '

"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell \
  cmd package set-home-activity "$stock_home"
"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell \
  am start -n "$stock_home"
printf 'Restored %s policy entries.\n' "$(awk '$0 !~ /^[[:space:]]*($|#)/ {n++} END {print n+0}' "$policy")"
