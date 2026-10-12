# Ginza bootloader entry

The exact `AFTHU71990` Ginza bootloader loads `/uboot.env` from the 16 MiB
`uenv` ext4 partition before verified boot. Its ext4 symlink reader accepts a
wrapped inode size and overflows a zero-size heap allocation. The candidate
image built here uses that path to call an existing command parser with this
command:

```text
mw.b 5fd684d5 e7;go 5fd6ab8c;go 5fd6abfc;fas 0
```

The command changes `is_lockdown()` to return false in relocated RAM, writes
the modified cache line to memory, invalidates the instruction cache, and
starts USB Fastboot. The signed bootloader partition and protected unlock
material remain unchanged. A power cycle reloads the signed bootloader; the
crafted `uenv` filesystem re-applies the RAM change on each boot until the
stock partition image is restored.

This path is exact-target only. `ginza_uenv.py` rejects another mboot hash,
filesystem UUID, block size, environment file, layout, or command-site byte
sequence.

## Build and verify

Capture the complete `uenv` partition while it is unmounted. Keep that image
as the authoritative rollback source. Then build the candidate and rollback
bundle:

```sh
python3 bootloader/ginza_uenv.py build \
  /path/to/mboot_b.img \
  /path/to/uenv-stock.img \
  /path/to/new-bundle
```

The builder replays the stock ext4 journal in a copy, preserves the existing
state files and stock environment backup, creates the cache-warming extent
layout, and emits:

- `uenv-fastboot.img`: the 16 MiB candidate written to `uenv` while unmounted.
- `uenv-restore-mscript.img`: a 32 MiB Fastboot payload containing a script at
  `0x30000000` and the exact stock partition at `0x31000000`.
- `uenv-clean.img` and `uenv-layout.img`: review inputs for byte-level checks.
- `manifest.json`: hashes, filesystem allocation, target addresses, preserved
  file hashes, and the exact command.

Verify the complete bundle again before staging it:

```sh
python3 bootloader/ginza_uenv.py verify \
  /path/to/mboot_b.img /path/to/new-bundle
```

The verifier checks the exact bootloader bytes, ext4 geometry, nested symlink
targets, shared extent leaf, forged allocator metadata, unsafe-unlink targets,
preserved stock inodes and data blocks, rollback script, zero padding, embedded
stock image, sizes, and SHA-256 hashes.

## Hardware workflow

`ginza-unlock.sh` drives the live operation as separate, fail-closed phases.
It uses the pinned SSH host key and automation key, checks the exact model,
firmware, slot, partition sizes, and active mboot hash, and refuses to prepare a
candidate until the unmodified bootloader's USB Fastboot transport has worked:

```sh
bootloader/ginza-unlock.sh preflight
bootloader/ginza-unlock.sh enter-stock-fastboot
```

Connect the USB data cable only after the TV reaches Fastboot. Probe the stock
transport while the partition is still unchanged:

```sh
bootloader/ginza-unlock.sh probe-stock-fastboot
```

The probe leaves the TV in Fastboot. Disconnect the cable, power-cycle the TV,
and wait for Android and the persistent root service. Then capture the cleanly
unmounted live partition, build and verify a fresh bundle, stage both the stock
and candidate images, write the candidate, and compare a complete raw readback:

```sh
bootloader/ginza-unlock.sh prepare bootloader/bundles/first-hardware-run
```

Preparation leaves Android running with `uenv` unmounted. It restores and
remounts the stock image automatically when a failure occurs after a raw write.
Before a reboot, the prepared operation can also be cancelled explicitly:

```sh
bootloader/ginza-unlock.sh abort-prepared \
  bootloader/bundles/first-hardware-run
```

With the cable disconnected, boot the verified candidate:

```sh
bootloader/ginza-unlock.sh boot-prepared \
  bootloader/bundles/first-hardware-run
```

After the TV reaches Fastboot, connect the cable and run the proof. An accepted
`mscript` flash demonstrates that the RAM lockdown patch is active. The script
restores the exact stock image and compares every byte before Fastboot reports
success:

```sh
bootloader/ginza-unlock.sh prove-and-restore \
  bootloader/bundles/first-hardware-run
```

The proof leaves the TV in Fastboot. Disconnect the cable and power-cycle the
TV to load the restored stock filesystem.

## Rollback protocol

The first hardware proof restores the stock partition before rebooting. After
the candidate enters Fastboot, the host sends the rollback payload as the
vendor `mscript` pseudo-partition:

```sh
bootloader/fastboot-host.sh devices
bootloader/fastboot-host.sh getvar all
bootloader/fastboot-host.sh flash mscript \
  /path/to/new-bundle/uenv-restore-mscript.img
```

The embedded script writes all 16 MiB from `0x31000000`, reads the partition
back to `0x32000000`, and runs a byte comparison across the full image. Fastboot
reports success only when every command succeeds. The final line printed by
the bootloader is:

```text
GINZA-UENV-RESTORE-VERIFIED
```

After the successful response, leave the TV in Fastboot, disconnect the USB
data cable, and power-cycle the TV. The next boot reads the restored stock
filesystem.

The candidate never mounts under Linux. The install sequence unmounts
`/mnt/vendor/uenv`, captures and verifies the final raw backup, builds the
bundle from that capture, writes and reads back the candidate, leaves the
partition unmounted, and reboots directly into the bootloader.
