# Persistent Fire OS debloat policy

The policy keeps the TV's core display, input, network, settings, tuner,
streaming, and root functions while removing the Amazon home screen and its
advertising, recommendations, telemetry, retail, Alexa, and update clients.
LTvLauncher is the HOME activity. The Fire TV YouTube receiver remains
installed so YouTube DIAL/cast requests can launch and play on the TV.

[`packages.txt`](packages.txt) contains 66 package or component targets. The
root app stores a validated copy in device-protected storage and applies it
after every successful boot-time root. Package entries are disabled for user 0,
component entries are disabled directly, and package processes are stopped.
The same step stops `update_engine` with `SIGSTOP`.

The policy keeps `com.amazon.vizzini` and `com.amazon.imp` enabled because the
Fire OS Settings application depends on them.

## Apply

The apply script downloads the pinned ARMv7 LTvLauncher and Fire TV YouTube
builds when needed, verifies their SHA-256 digests, installs them, provisions
the persistent policy, applies the live package state through the root SSH
service, freezes `update_engine`, and selects LTvLauncher as HOME.

The YouTube receiver is `com.amazon.firetv.youtube` version
`25.30.r1.v162.0` (`325311620`). Its APK is ARMv7, has SHA-256
`0f8ad0f9a0b2b77444cf0a13397de7abcaa3f482f908163448967b0f899931cc`,
and carries the Google LLC signing certificate with SHA-256
`21bd252aa5d6f8fa71792a430f7e9c1bf6b71797b8c5a5033f806036f46f0c49`.

The defaults match the deployed TV and local automation key:

```sh
ADB_SERVER_PORT=5038 ./debloat/apply.sh
```

The script accepts these environment variables:

| Variable | Default |
| --- | --- |
| `ADB` | `adb` |
| `ADB_SERVER_PORT` | `5037` |
| `ADB_SERIAL` | `10.10.8.53:5555` |
| `GINZA_SSH_HOST` | `10.10.8.53` |
| `GINZA_SSH_PORT` | `2222` |
| `GINZA_SSH_KEY` | `~/.ssh/ginza_bot_ed25519` |
| `GINZA_KNOWN_HOSTS` | `~/.ssh/ginza_known_hosts` |
| `GINZA_DEBLOAT_POLICY` | `debloat/packages.txt` |
| `GINZA_LAUNCHER_APK` | pinned launcher beside the script |
| `GINZA_YOUTUBE_APK` | pinned Fire TV YouTube APK beside the script |

The configured known-hosts file must contain the TV's persistent Dropbear host
key. The verified Ed25519 fingerprint is:

```text
SHA256:15ikJ0/f24MW2snU68idzvVi6poViC8unCUVrmhfCWU
```

## Restore

The restore script clears the boot-time policy, resumes `update_engine`,
enables every policy entry, and selects Amazon's stock HOME activity:

```sh
ADB_SERVER_PORT=5038 ./debloat/restore.sh
```

Both scripts require the persistent root and SSH service to be ready. Rebooting
releases the active exploit state safely; the root app reapplies the stored
policy during the next boot.
