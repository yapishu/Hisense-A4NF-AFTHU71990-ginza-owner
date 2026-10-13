# macOS Fastboot host

The Mac handles the physical USB connection while the Linux workstation keeps
the exact-target image builder, the TV's SSH automation key, and the complete
rollback source. No private key or raw TV partition image belongs in Git.

The live TV remains on its stock `uenv` filesystem until the stock Fastboot
transport test succeeds. Keep the USB cable disconnected while Android is
running and while either computer requests a reboot. Connect it only after the
TV reaches Fastboot device mode.

## Handoff state

The TV matches model `AFTHU71990`, device `ginza`, slot B, and firmware build
`0032280318340`. Its active `mboot_b` SHA-256 is
`f95082e5eb03bd813ba1b82d824c59693e22c5bc60fad309c8dc3a7cabebee11`.
The live `uenv` partition is mounted with the stock environment whose SHA-256
is `ed362a2f4ce8b15955e67e6e050f0e913c997e5becf404af040ce7f986de081f`.
No crafted filesystem is installed. The next hardware action is the stock
Fastboot transport test below.

## Install the host tools

Fetch this branch on the Mac:

```sh
git clone \
  --branch bootloader-macos-handoff \
  https://github.com/yapishu/Hisense-A4NF-AFTHU71990-ginza-owner.git
cd Hisense-A4NF-AFTHU71990-ginza-owner
```

Install Google's current macOS Platform Tools in the user's cache and verify
that the Mac can still reach the exact TV over network ADB:

```sh
./bootloader/macos-fastboot.sh setup
./bootloader/macos-fastboot.sh preflight
```

The helper also accepts existing tools through `GINZA_ADB_BIN` and
`GINZA_FASTBOOT_BIN`. It checks model `AFTHU71990`, device `ginza`, slot B, and
firmware build `0032280318340` before requesting stock Fastboot.

## Prove the stock USB transport

Leave the cable disconnected and run:

```sh
./bootloader/macos-fastboot.sh enter-stock-fastboot
```

Wait for the TV to reach Fastboot. Connect the TV's USB-A port to the Mac with
the data cable and run:

```sh
./bootloader/macos-fastboot.sh probe-stock-fastboot \
  "$HOME/Desktop/ginza-stock-fastboot-proof"
```

Success creates a small proof directory containing the complete `getvar` log
and its SHA-256 metadata. Copy that directory to the Linux workstation. Leave
the TV in Fastboot, disconnect the cable, and power-cycle the TV. The stock
filesystem is unchanged during this test.

On the Linux workstation, import the transferred proof before preparing an
image:

```sh
./bootloader/ginza-unlock.sh import-stock-fastboot-proof \
  /path/to/ginza-stock-fastboot-proof
```

## Transfer the proof and rollback payloads

The Linux workstation captures the live `uenv` partition only after a clean
unmount, builds and verifies the candidate, writes it with a full readback, and
keeps the exact stock image staged on the TV:

```sh
./bootloader/ginza-unlock.sh prepare bootloader/bundles/first-hardware-run
./bootloader/ginza-unlock.sh export-fastboot-bundle \
  bootloader/bundles/first-hardware-run \
  bootloader/runtime/first-hardware-run-mac
```

Transfer the complete exported directory to the Mac. It contains a 164-byte
RAM-only unlock probe, the 32 MiB full-partition rollback payload, and the
manifest that pins both files. It does not contain an SSH key or the crafted
candidate filesystem.

On the Mac, verify the transferred payloads before the TV reboots:

```sh
./bootloader/macos-fastboot.sh verify-bundle \
  /path/to/first-hardware-run-mac
```

## Prove the unlock and restore stock

The Linux workstation verifies the installed candidate and requests the
bootloader reboot with the cable disconnected:

```sh
./bootloader/ginza-unlock.sh boot-prepared \
  bootloader/bundles/first-hardware-run
```

After the TV reaches Fastboot, connect the cable to the Mac. Run the RAM-only
probe, then immediately run the exact stock restore:

```sh
./bootloader/macos-fastboot.sh prove-unlocked \
  /path/to/first-hardware-run-mac
./bootloader/macos-fastboot.sh restore-stock \
  /path/to/first-hardware-run-mac
```

The restore command sends an `mscript` that writes all 16 MiB of the embedded
stock image, reads the partition back, and compares every byte before Fastboot
reports success. After success, leave the TV in Fastboot, disconnect the cable,
and power-cycle it. Do not use `fastboot reboot` while the cable remains
connected.

If either Fastboot command fails, keep the TV powered on in Fastboot and keep
the cable connected. The rollback payload remains available on the Mac for a
retry, and the staged stock image remains on the TV.
