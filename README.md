# Toshiba 40V35RUF / Hisense A4NF Ginza jailbreak

This repository provides hardware-verified persistent root for the Toshiba
40V35RUF Fire TV (`AFTHU71990`) on the exact `ginza-hh` firmware listed below.
The app runs a Mali CVE-2022-38181 exploit once per boot, starts a key-only
Dropbear SSH server on TCP port 2222, and keeps the required GPU objects alive.

| Field | Required value |
| --- | --- |
| Product model | `AFTHU71990` / Toshiba 40V35RUF |
| Device | `ginza` |
| Variant | `ginza-hh` |
| Fire OS build | `RS8180.3729N` / `0032280318340` |
| Boot image build | `0032280318208` |
| Kernel | `5.15.180-android13-8-g0d8b47e36fe4-dirty` |
| Architecture | ARMv7 (`armv7l`) |
| GPU driver | Mali kbase r39p0, API 11.35 |

The native executable checks the complete system and boot fingerprints, the
variant, incremental build, kernel release, and architecture before it enters
any GPU exploit mode. It refuses other targets.

## Security model

The service patches only a process-private credential. The root server has UID
and GID 0, the kernel's complete 41-capability mask, and the app's existing
SELinux identity. It verifies a permissive SELinux transition and removes the
Android app seccomp filter from a stopped root server child before accepting
connections.

SSH accepts public keys only. Password and PAM authentication are absent from
the Dropbear build. The authorized-key file and persistent Ed25519 host key
live in the app's device-protected private storage.

The root process retains cross-owned GPU objects. Never kill the native root
process, the root server child, or Dropbear. Reboot the TV to release the GPU
state safely. The boot receiver starts a new guarded attempt during each boot.

## Build

The build requires:

- Zig with ARM Linux musl support
- JDK 21
- Android SDK Platform 36 and Build Tools 35.0.0
- Android NDK 27.0.12077973
- `curl`, `make`, `patch`, `tar`, `zip`, and `sha256sum`

Set the tool locations and build the signed APK:

```sh
export JAVA_HOME=/path/to/jdk-21
export ANDROID_SDK_ROOT=/path/to/android-sdk
export ZIG=/path/to/zig
./ginza-persist/build.sh ./ginza-root-autostart.apk
```

The build compiles the exploit as a static ARMv7 library payload. It downloads
the pinned official Dropbear 2026.94 source archive, verifies its SHA-256 hash,
applies the local authorized-key-directory patch, and builds an ARMv7 Bionic
multi-call executable. The APK is signed with `ginza-persist/debug.keystore`;
the build creates that ignored keystore when it does not exist.

The native executable can also be built by itself:

```sh
ZIG=/path/to/zig ./tools/build_ginza_mali_38181.sh ./ginza_mali_38181
```

## Install

Enable ADB debugging and connect to the TV. Put the public keys that may log in
into one file, one OpenSSH public key per line. The installer accepts 1 to 16
Ed25519 or RSA keys. The deployed TV has the owner's Ed25519 and RSA keys plus
a dedicated local automation key:

```sh
cat ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub ~/.ssh/ginza_bot_ed25519.pub \
  > authorized_keys
```

Install the APK and provision the key file:

```sh
./install.sh ./ginza-root-autostart.apk ./authorized_keys 10.10.8.53:5555
```

The installer prints the local key-file SHA-256 digest and the app's matching
provisioning log. It never copies private keys.

Reboot to exercise the persistent path:

```sh
adb -s 10.10.8.53:5555 reboot
```

The direct-boot receiver handles `LOCKED_BOOT_COMPLETED`, then waits 75 seconds
for boot services. Root and SSH normally appear about two minutes after startup.
Check without starting another attempt:

```sh
adb -s 10.10.8.53:5555 shell getenforce
ssh-keyscan -p 2222 10.10.8.53 | ssh-keygen -lf -
```

The tested TV keeps this Ed25519 host-key fingerprint across reboots:

```text
SHA256:15ikJ0/f24MW2snU68idzvVi6poViC8unCUVrmhfCWU
```

Connect with either provisioned private key:

```sh
ssh -p 2222 root@10.10.8.53
```

A root session reports UID/GID 0, seccomp mode 0, and these capability masks:

```text
CapInh: 000001ffffffffff
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 000001ffffffffff
```

## Debloat and update blocking

The deployed TV uses LTvLauncher as HOME and keeps Netflix, Jellyfin, YouTube,
YouTube casting, AirPlay, the tuner/operator app, Files, QuickSettings, and the
root service available.
The persistent policy disables 68 Amazon OTA, launcher, advertising,
recommendation, retail, telemetry, Alexa, smart-home, and synchronization
targets. It also stops `update_engine` at every successful root startup.

`com.amazon.vizzini` and `com.amazon.imp` declare themselves persistent and
restart when merely disabled. The policy removes them for Android user 0 while
leaving their read-only system APKs intact for restoration. The locked AVB boot
chain and system partitions remain unchanged.

The current setup uses the local automation key and a pinned SSH host key:

```sh
ADB_SERVER_PORT=5038 ./debloat/apply.sh
```

Restore the stock packages, resume `update_engine`, and select Amazon's HOME:

```sh
ADB_SERVER_PORT=5038 ./debloat/restore.sh
```

See [`debloat/README.md`](debloat/README.md) for the policy contents,
configuration variables, and recovery details.

## Local recovery shell

The root server also exposes an abstract Unix socket through ADB:

```sh
adb -s 10.10.8.53:5555 forward tcp:4242 localabstract:ginza-root
nc 127.0.0.1 4242
```

This path is useful for verification and recovery when SSH configuration is
unavailable.

## Remove persistent root

Reboot and uninstall the package immediately after ADB reconnects, before the
ordered boot broadcast reaches the app:

```sh
adb -s 10.10.8.53:5555 reboot
adb -s 10.10.8.53:5555 wait-for-device
adb -s 10.10.8.53:5555 uninstall io.github.ginzaroot.autostart
```

A reboot restores the stock credential and SELinux state. Uninstalling removes
the app-private authorized keys and SSH host key.

## Implementation notes

The exploit reclaims the released backing of an evicted Mali JIT allocation as
page tables from a second GPU context. Native G52 jobs provide validated
physical reads and verified 32-bit writes. Every temporary GPU address-table
entry is restored immediately. Exact symbols and structure layouts come from
the running kernel's kallsyms and BTF data.

The locked green AVB 1.1 boot chain remains unchanged. The top-level vbmeta
chains the signed boot image and authenticates `vendor_boot`, `dtbo`, and the
dynamic partitions. Persistence comes from the boot receiver rerunning the
firmware-specific exploit; no boot partition is modified.

[`reference/target.json`](reference/target.json) records the exact target,
kernel symbols, and structure offsets. [`reference/vmlinux.btf`](reference/vmlinux.btf)
and [`reference/kernel.config`](reference/kernel.config) are the exact running
kernel artifacts.
