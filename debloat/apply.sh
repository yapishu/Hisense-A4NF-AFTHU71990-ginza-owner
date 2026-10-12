#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
policy=${GINZA_DEBLOAT_POLICY:-$project_dir/packages.txt}
uninstall_policy=${GINZA_UNINSTALL_POLICY:-$project_dir/uninstall-packages.txt}
launcher=${GINZA_LAUNCHER_APK:-$project_dir/LTvLauncher-armeabi-v7a-release.apk}
adb_bin=${ADB:-adb}
adb_server_port=${ADB_SERVER_PORT:-5037}
adb_serial=${ADB_SERIAL:-10.10.8.53:5555}
ssh_host=${GINZA_SSH_HOST:-10.10.8.53}
ssh_port=${GINZA_SSH_PORT:-2222}
ssh_key=${GINZA_SSH_KEY:-$HOME/.ssh/ginza_bot_ed25519}
known_hosts=${GINZA_KNOWN_HOSTS:-$HOME/.ssh/ginza_known_hosts}
service=io.github.ginzaroot.autostart/.RootService
launcher_component=com.leanbitlab.ltvL/.MainActivity

for path in "$policy" "$uninstall_policy" "$ssh_key" "$known_hosts"; do
  if [ ! -f "$path" ]; then
    echo "Missing required file: $path" >&2
    exit 1
  fi
done
if [ ! -f "$launcher" ]; then
  "$project_dir/fetch_launcher.sh" "$launcher"
fi

encoded=$(base64 "$policy" | tr -d '\n')
"$adb_bin" -P "$adb_server_port" -s "$adb_serial" install -r "$launcher"
"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell am start-foreground-service \
  -n "$service" \
  --es mode provision-debloat \
  --es debloatPackages "$encoded" \
  --ez immediate true

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
      case "$target" in
        */*) pm disable --user 0 "$target" ;;
        *)
          pm disable-user --user 0 "$target"
          am force-stop --user 0 "$target"
          ;;
      esac
    done
    toybox killall -STOP update_engine
  '

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
    while IFS= read -r target; do
      pm uninstall -k --user 0 "$target"
    done
  '

"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell \
  cmd package set-home-activity "$launcher_component"
"$adb_bin" -P "$adb_server_port" -s "$adb_serial" shell \
  am start -n "$launcher_component"
printf 'Applied %s debloat entries.\n' "$(awk '$0 !~ /^[[:space:]]*($|#)/ {n++} END {print n+0}' "$policy")"
