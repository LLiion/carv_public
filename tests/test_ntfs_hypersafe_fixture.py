#!/usr/bin/env python3
"""Exercise the isolated Hypersafe NTFS bootstrap with a tiny synthetic disk."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
CARV = ROOT / "carv"
SECTOR_SIZE = 512
CLUSTER_SIZE = 4096
PARTITION_OFFSET = 1 * 1024 * 1024
SOURCE_SIZE = 64 * 1024 * 1024
MFT_OFFSET = 40 * 1024 * 1024
MFT_MIRROR_OFFSET = 56 * 1024 * 1024
MFT_LCN = (MFT_OFFSET - PARTITION_OFFSET) // CLUSTER_SIZE
MFT_MIRROR_LCN = (MFT_MIRROR_OFFSET - PARTITION_OFFSET) // CLUSTER_SIZE
MFT_DATA_SIZE = 12 * 1024
VOLUME_SERIAL = 0x0123456789ABCDEF
AVI_DATA_OFFSET = 48 * 1024 * 1024
AVI_DATA_LCN = (AVI_DATA_OFFSET - PARTITION_OFFSET) // CLUSTER_SIZE
AVI_DATA = (
    b"RIFF" +
    struct.pack("<I", 1016) +
    b"AVI " +
    bytes(index & 0xFF for index in range(1012))
)
WAV_DATA_OFFSET = 52 * 1024 * 1024
WAV_DATA_LCN = (WAV_DATA_OFFSET - PARTITION_OFFSET) // CLUSTER_SIZE
WAV_DATA = b"RIFF" + struct.pack("<I", 56) + b"WAVE" + bytes(reversed(range(52)))


def _align8(value: int) -> int:
    return (value + 7) & ~7


def _file_name_attribute(name: str, parent: int) -> bytes:
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    struct.pack_into("<Q", value, 0, parent)
    struct.pack_into("<Q", value, 40, 0)
    struct.pack_into("<Q", value, 48, 0)
    struct.pack_into("<I", value, 56, 0x10000000)
    value[64] = len(encoded) // 2
    value[65] = 1
    value[66:] = encoded

    attr_len = _align8(24 + len(value))
    attr = bytearray(attr_len)
    struct.pack_into("<I", attr, 0, 0x30)
    struct.pack_into("<I", attr, 4, attr_len)
    struct.pack_into("<I", attr, 16, len(value))
    struct.pack_into("<H", attr, 20, 24)
    attr[24:24 + len(value)] = value
    return bytes(attr)


def _mft_data_attribute() -> bytes:
    runlist = b"\x21\x20" + struct.pack("<H", MFT_LCN) + b"\x00"
    attr_len = _align8(64 + len(runlist))
    attr = bytearray(attr_len)
    struct.pack_into("<I", attr, 0, 0x80)
    struct.pack_into("<I", attr, 4, attr_len)
    attr[8] = 1
    struct.pack_into("<Q", attr, 16, 0)
    struct.pack_into("<Q", attr, 24, 31)
    struct.pack_into("<H", attr, 32, 64)
    struct.pack_into("<Q", attr, 40, 32 * CLUSTER_SIZE)
    struct.pack_into("<Q", attr, 48, MFT_DATA_SIZE)
    struct.pack_into("<Q", attr, 56, MFT_DATA_SIZE)
    attr[64:64 + len(runlist)] = runlist
    return bytes(attr)


def _nonresident_data_attribute(lcn: int, data_size: int) -> bytes:
    clusters = (data_size + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    if not 0 < clusters < 256 or not 0 <= lcn < 65536:
        raise ValueError("fixture runlist values exceed compact encoding")
    runlist = b"\x21" + bytes([clusters]) + struct.pack("<H", lcn) + b"\x00"
    attr_len = _align8(64 + len(runlist))
    attr = bytearray(attr_len)
    struct.pack_into("<I", attr, 0, 0x80)
    struct.pack_into("<I", attr, 4, attr_len)
    attr[8] = 1
    struct.pack_into("<Q", attr, 16, 0)
    struct.pack_into("<Q", attr, 24, clusters - 1)
    struct.pack_into("<H", attr, 32, 64)
    struct.pack_into("<Q", attr, 40, clusters * CLUSTER_SIZE)
    struct.pack_into("<Q", attr, 48, data_size)
    struct.pack_into("<Q", attr, 56, data_size)
    attr[64:64 + len(runlist)] = runlist
    return bytes(attr)


def _mft_record(record_number: int, *, name: str = "", parent: int = 5,
                directory: bool = False, include_mft_data: bool = False,
                data_lcn: int | None = None, data_size: int = 0) -> bytes:
    record = bytearray(1024)
    record[0:4] = b"FILE"
    struct.pack_into("<H", record, 4, 0x30)
    struct.pack_into("<H", record, 6, 3)
    struct.pack_into("<H", record, 16, 1)
    struct.pack_into("<H", record, 18, 1)
    struct.pack_into("<H", record, 20, 0x38)
    struct.pack_into("<H", record, 22, 3 if directory else 1)
    struct.pack_into("<I", record, 28, len(record))
    struct.pack_into("<I", record, 44, record_number)

    cursor = 0x38
    if name:
        attr = _file_name_attribute(name, parent)
        record[cursor:cursor + len(attr)] = attr
        cursor += len(attr)
    if include_mft_data:
        attr = _mft_data_attribute()
        record[cursor:cursor + len(attr)] = attr
        cursor += len(attr)
    if data_lcn is not None:
        attr = _nonresident_data_attribute(data_lcn, data_size)
        record[cursor:cursor + len(attr)] = attr
        cursor += len(attr)
    struct.pack_into("<I", record, cursor, 0xFFFFFFFF)
    cursor += 4
    struct.pack_into("<I", record, 24, cursor)

    update_sequence = 0xA55A
    struct.pack_into("<H", record, 0x30, update_sequence)
    struct.pack_into("<H", record, 0x32, 0)
    struct.pack_into("<H", record, 0x34, 0)
    struct.pack_into("<H", record, 510, update_sequence)
    struct.pack_into("<H", record, 1022, update_sequence)
    return bytes(record)


def _write_fixture(path: Path) -> None:
    with path.open("wb") as image:
        image.truncate(SOURCE_SIZE)

        mbr = bytearray(SECTOR_SIZE)
        # Give the early-resume identity sample enough real variation to be
        # safer than accepting a generic all-zero partition gap.
        mbr[0:256] = bytes((index * 37 + 11) & 0xFF for index in range(256))
        partition_sectors = (SOURCE_SIZE - PARTITION_OFFSET) // SECTOR_SIZE
        entry = 446
        mbr[entry + 4] = 0x07
        struct.pack_into("<I", mbr, entry + 8, PARTITION_OFFSET // SECTOR_SIZE)
        struct.pack_into("<I", mbr, entry + 12, partition_sectors)
        mbr[510:512] = b"\x55\xaa"
        image.seek(0)
        image.write(mbr)

        boot = bytearray(SECTOR_SIZE)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = b"NTFS    "
        struct.pack_into("<H", boot, 11, SECTOR_SIZE)
        boot[13] = CLUSTER_SIZE // SECTOR_SIZE
        struct.pack_into("<Q", boot, 40, partition_sectors)
        struct.pack_into("<Q", boot, 48, MFT_LCN)
        struct.pack_into("<Q", boot, 56, MFT_MIRROR_LCN)
        boot[64] = 0xF6  # -10: 2**10 byte MFT records
        struct.pack_into("<Q", boot, 72, VOLUME_SERIAL)
        boot[510:512] = b"\x55\xaa"
        image.seek(PARTITION_OFFSET)
        image.write(boot)

        records = {
            0: _mft_record(0, name="$MFT", include_mft_data=True),
            # Record 5 is deliberately absent. Root listing must fall back to
            # the acquired MFT when resident $I30 is not readable.
            6: _mft_record(6, name="Customer videos", directory=True),
            7: _mft_record(7, name="Mobile rescue", directory=True),
            8: _mft_record(8, name="AVI", parent=6, directory=True),
            9: _mft_record(
                9,
                name="family_clip.avi",
                parent=8,
                data_lcn=AVI_DATA_LCN,
                data_size=len(AVI_DATA),
            ),
            10: _mft_record(
                10,
                name="camera_audio.wav",
                parent=8,
                data_lcn=WAV_DATA_LCN,
                data_size=len(WAV_DATA),
            ),
        }
        for number, record in records.items():
            image.seek(MFT_OFFSET + number * 1024)
            image.write(record)
        image.seek(MFT_MIRROR_OFFSET)
        image.write(records[0])
        image.seek(AVI_DATA_OFFSET)
        image.write(AVI_DATA)
        image.seek(WAV_DATA_OFFSET)
        image.write(WAV_DATA)


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


class NtfsHypersafeFixtureTest(unittest.TestCase):
    def setUp(self) -> None:
        if not CARV.is_file():
            self.skipTest("build carv before running the Hypersafe fixture")
        if shutil.which("ddrescue") is None:
            self.skipTest("GNU ddrescue is not installed")
        self.temp = tempfile.TemporaryDirectory(prefix="carv-hypersafe-")
        self.base = Path(self.temp.name)
        self.source = self.base / "source.img"
        self.output = self.base / "out"
        self.output.mkdir()
        _write_fixture(self.source)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _carv(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CARV), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=45,
            check=False,
        )

    def _faulting_ddrescue_environment(self, mode: str) -> tuple[dict[str, str], Path]:
        if mode not in {
            "recover_on_selected_retry",
            "remain_unresolved",
            "disconnect_then_return",
            "disconnect_wrong_source",
            "identity_unreadable_then_return",
            "retry_budget_then_return",
            "operator_continue_partial",
        }:
            raise ValueError(f"unsupported fault mode: {mode}")
        real_ddrescue = shutil.which("ddrescue")
        self.assertIsNotNone(real_ddrescue)
        fake_bin = self.base / f"faulting-ddrescue-{mode}"
        fake_bin.mkdir()
        phase_log = self.base / f"ddrescue-phases-{mode}.log"
        fake_ddrescue = fake_bin / "ddrescue"
        fake_ddrescue.write_text(
            """#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

args = sys.argv[1:]
real_ddrescue = os.environ["CARV_TEST_REAL_DDRESCUE"]
phase_log = Path(os.environ["CARV_TEST_DDRESCUE_PHASE_LOG"])
with phase_log.open("a", encoding="utf-8") as stream:
    stream.write(" ".join(args) + "\\n")

if len(args) < 3:
    raise SystemExit(subprocess.run([real_ddrescue, *args], check=False).returncode)

source_path = Path(args[-3])
image_path = Path(args[-2])
map_path = Path(args[-1])
mode = os.environ["CARV_TEST_DDRESCUE_FAULT_MODE"]
target_start = int(os.environ["CARV_TEST_FAULT_START"])
target_length = int(os.environ["CARV_TEST_FAULT_LENGTH"])
source_size = int(os.environ["CARV_TEST_SOURCE_SIZE"])
is_selected_domain = "-m" in args
is_retry = "-r" in args
is_bootstrap_range = "-i" in args
is_full_image = not is_selected_domain and not is_bootstrap_range
is_identity_probe = ".hypersafe_identity_" in image_path.name

if mode in {
    "disconnect_then_return",
    "disconnect_wrong_source",
    "identity_unreadable_then_return",
}:
    marker = Path(os.environ["CARV_TEST_DISCONNECT_MARKER"])
    if is_selected_domain and not is_retry and not marker.exists():
        marker.write_text("disconnected\\n", encoding="utf-8")
        source_path.rename(source_path.with_name(source_path.name + ".offline"))
        raise SystemExit(1)

if mode == "identity_unreadable_then_return" and is_identity_probe:
    counter_path = Path(os.environ["CARV_TEST_IDENTITY_PROBE_COUNTER"])
    try:
        probe_count = int(counter_path.read_text(encoding="utf-8")) + 1
    except (OSError, ValueError):
        probe_count = 1
    counter_path.write_text(str(probe_count), encoding="utf-8")
    if probe_count <= 3:
        start = int(args[args.index("-i") + 1], 0)
        length = int(args[args.index("-s") + 1], 0)
        with image_path.open("wb") as image:
            image.truncate(start + length)
        map_path.write_text(
            "# Mapfile. Synthetic temporarily unreadable identity fixture\\n"
            "0x00000000  ?\\n"
            f"0x00000000  0x{start:x}  ?\\n"
            f"0x{start:x}  0x{length:x}  -\\n"
            f"0x{start + length:x}  0x{source_size - start - length:x}  ?\\n",
            encoding="utf-8",
        )
        raise SystemExit(0)

if mode == "retry_budget_then_return" and is_full_image and "-n" in args:
    counter_path = Path(os.environ["CARV_TEST_RETRY_BUDGET_COUNTER"])
    try:
        attempt = int(counter_path.read_text(encoding="utf-8")) + 1
    except (OSError, ValueError):
        attempt = 1
    counter_path.write_text(str(attempt), encoding="utf-8")
    if attempt <= 6:
        raise SystemExit(1)

if mode == "operator_continue_partial" and is_full_image and "-n" in args:
    unresolved_length = 4 * 1024 * 1024
    copied_length = source_size - unresolved_length
    with source_path.open("rb") as source, image_path.open("wb") as image:
        remaining = copied_length
        while remaining > 0:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            image.write(chunk)
            remaining -= len(chunk)
    map_path.write_text(
        "# Mapfile. Synthetic operator-continue fixture\\n"
        "0x00000000  ?\\n"
        f"0x00000000  0x{copied_length:x}  +\\n"
        f"0x{copied_length:x}  0x{unresolved_length:x}  ?\\n",
        encoding="utf-8",
    )
    Path(os.environ["CARV_TEST_PARTIAL_IMAGE_READY"]).write_text(
        "ready\\n", encoding="utf-8"
    )

    def stop_cleanly(_signum, _frame):
        raise SystemExit(130)

    signal.signal(signal.SIGINT, stop_cleanly)
    while True:
        time.sleep(0.1)

result = subprocess.run([real_ddrescue, *args], check=False).returncode

force_unresolved = False
if mode == "remain_unresolved":
    force_unresolved = is_selected_domain or is_full_image
elif mode == "recover_on_selected_retry":
    force_unresolved = (
        (is_selected_domain and not is_retry) or
        (is_full_image and "-n" in args)
    )

if force_unresolved and image_path.exists():
    with image_path.open("r+b") as image:
        image.seek(target_start)
        image.write(b"\\0" * target_length)
    after_target = target_start + target_length
    map_path.write_text(
        "# Mapfile. Synthetic Hypersafe unresolved-extent fixture\\n"
        "0x00000000  ?\\n"
        f"0x00000000  0x{target_start:x}  +\\n"
        f"0x{target_start:x}  0x{target_length:x}  ?\\n"
        f"0x{after_target:x}  0x{source_size - after_target:x}  +\\n",
        encoding="utf-8",
    )

raise SystemExit(result)
""",
            encoding="utf-8",
        )
        fake_ddrescue.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
        environment["CARV_TEST_REAL_DDRESCUE"] = str(real_ddrescue)
        environment["CARV_TEST_DDRESCUE_PHASE_LOG"] = str(phase_log)
        environment["CARV_TEST_DDRESCUE_FAULT_MODE"] = mode
        environment["CARV_TEST_FAULT_START"] = str(WAV_DATA_OFFSET)
        environment["CARV_TEST_FAULT_LENGTH"] = str(CLUSTER_SIZE)
        environment["CARV_TEST_SOURCE_SIZE"] = str(SOURCE_SIZE)
        environment["CARV_TEST_DISCONNECT_MARKER"] = str(
            self.base / f"disconnect-{mode}.marker"
        )
        environment["CARV_TEST_IDENTITY_PROBE_COUNTER"] = str(
            self.base / f"identity-probes-{mode}.txt"
        )
        environment["CARV_TEST_RETRY_BUDGET_COUNTER"] = str(
            self.base / f"retry-budget-{mode}.txt"
        )
        environment["CARV_TEST_PARTIAL_IMAGE_READY"] = str(
            self.base / f"partial-image-ready-{mode}.txt"
        )
        wrong_source = self.base / f"wrong-source-{mode}.img"
        shutil.copy2(self.source, wrong_source)
        with wrong_source.open("r+b") as source:
            source.seek(PARTITION_OFFSET + 72)
            source.write(struct.pack("<Q", VOLUME_SERIAL + 1))
        environment["CARV_TEST_WRONG_SOURCE"] = str(wrong_source)
        return environment, phase_log

    def _carv_with_environment(
        self,
        environment: dict[str, str],
        *arguments: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(CARV), *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=45,
            check=False,
        )

    def test_sparse_bootstrap_lazy_children_resume_and_identity_guard(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "fixture",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(result.returncode, 0, result.stdout)

        run = self.output / "fixture"
        status = run / "state" / "hypersafe_bootstrap.txt"
        sparse_image = run / "source_image.img"
        mapfile = run / "source_image.map"
        roots = (run / "state" / "hypersafe_root_folders.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        self.assertEqual(roots, ["Customer videos", "Mobile rescue"])
        status_text = status.read_text(encoding="utf-8")
        self.assertIn("status=ready", status_text)
        self.assertIn(f"volume_serial={VOLUME_SERIAL:016x}", status_text)
        self.assertIn("mft_finished_bytes=12288", status_text)
        self.assertGreater(sparse_image.stat().st_size, MFT_MIRROR_OFFSET)
        self.assertLess(sparse_image.stat().st_blocks * 512, sparse_image.stat().st_size)

        children = self._carv(
            "--src", str(sparse_image),
            "--filesys", "ntfs",
            "--list-folders-under", "Customer videos",
            "--hypersafe-preview-status", str(status),
        )
        self.assertEqual(children.returncode, 0, children.stdout)
        self.assertEqual(children.stdout.splitlines(), ["Customer videos/AVI"])

        original_map = mapfile.read_text(encoding="utf-8")
        mapfile.write_text(
            "# Mapfile. Created for partial-image coverage test\n"
            "0x00000000  ?\n"
            f"0x00000000  0x{32 * 1024 * 1024:x}  +\n"
            f"0x{MFT_OFFSET:x}  0x2000  +\n"
            f"0x{MFT_OFFSET + 8192:x}  0x400  ?\n"
            f"0x{MFT_OFFSET + 9216:x}  0x{1024 * 1024 - 9216:x}  +\n"
            f"0x{MFT_MIRROR_OFFSET:x}  0x{1024 * 1024:x}  +\n",
            encoding="utf-8",
        )
        missing_child = self._carv(
            "--src", str(sparse_image),
            "--filesys", "ntfs",
            "--list-folders-under", "Customer videos",
            "--hypersafe-preview-status", str(status),
        )
        self.assertEqual(missing_child.returncode, 0, missing_child.stdout)
        self.assertEqual(missing_child.stdout, "")
        mapfile.write_text(original_map, encoding="utf-8")

        # Model a kill after the head range became readable but before the
        # NTFS serial reached the atomic state file. Resume must prove the
        # source with already rescued head bytes and continue the same map.
        interrupted_status = status_text.replace(
            "status=ready", "status=acquiring_head"
        ).replace(
            f"volume_serial={VOLUME_SERIAL:016x}", "volume_serial=0000000000000000"
        )
        status.write_text(interrupted_status, encoding="utf-8")
        resumed = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "fixture",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stdout)
        self.assertIn(
            "Checking rescued head bytes",
            resumed.stdout,
        )

        map_digest = _digest(mapfile)
        image_digest = _digest(sparse_image)
        with self.source.open("r+b") as source:
            source.seek(PARTITION_OFFSET + 72)
            source.write(struct.pack("<Q", VOLUME_SERIAL + 1))
        rejected = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "fixture",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertIn("identity does not match", rejected.stdout)
        self.assertEqual(_digest(mapfile), map_digest)
        self.assertEqual(_digest(sparse_image), image_digest)

    def test_linux_wwn_and_ata_identity_are_saved_and_reject_another_disk(self) -> None:
        by_id = self.base / "synthetic-disk-by-id"
        by_id.mkdir()
        (by_id / "wwn-0xfixture-original").symlink_to(self.source)
        (by_id / "ata-FixtureDisk_ORIGINAL123").symlink_to(self.source)
        (by_id / "usb-FixtureBridge_BRIDGE123-0:0").symlink_to(self.source)
        environment = os.environ.copy()
        environment["CARV_TEST_DISK_BY_ID_DIR"] = str(by_id)

        created = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "linux-identity",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(created.returncode, 0, created.stdout)
        run = self.output / "linux-identity"
        status_path = run / "state" / "hypersafe_bootstrap.txt"
        status = status_path.read_text(encoding="utf-8")
        self.assertIn("format_version=2", status)
        self.assertIn("linux_wwn_id=wwn-0xfixture-original", status)
        self.assertIn("linux_ata_id=ata-FixtureDisk_ORIGINAL123", status)
        self.assertIn(
            "linux_usb_id=usb-FixtureBridge_BRIDGE123-0:0",
            status,
        )

        same_disk_resume = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "linux-identity",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(same_disk_resume.returncode, 0, same_disk_resume.stdout)
        self.assertIn(
            "verified the returning source from its saved Linux WWN/ATA identity",
            same_disk_resume.stdout,
        )

        # State created before Linux identifiers were introduced must accept
        # an explicitly selected resume source once, then persist strong IDs
        # so every later reconnect is constrained normally.
        legacy_status = status_path.read_text(encoding="utf-8").replace(
            "format_version=2", "format_version=1"
        )
        legacy_status = "\n".join(
            line
            for line in legacy_status.splitlines()
            if not line.startswith(("linux_wwn_id=", "linux_ata_id=", "linux_usb_id="))
        ) + "\n"
        status_path.write_text(legacy_status, encoding="utf-8")
        legacy_resume = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "linux-identity",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(legacy_resume.returncode, 0, legacy_resume.stdout)
        self.assertIn(
            "accepted the explicitly selected source for legacy resume",
            legacy_resume.stdout,
        )
        migrated_status = status_path.read_text(encoding="utf-8")
        self.assertIn("format_version=2", migrated_status)
        self.assertIn("linux_wwn_id=wwn-0xfixture-original", migrated_status)
        self.assertIn("linux_ata_id=ata-FixtureDisk_ORIGINAL123", migrated_status)

        wrong_source = self.base / "same-size-wrong-source.img"
        shutil.copy2(self.source, wrong_source)
        with wrong_source.open("r+b") as source:
            source.seek(PARTITION_OFFSET + 72)
            source.write(struct.pack("<Q", VOLUME_SERIAL + 1))
        (by_id / "wwn-0xfixture-wrong").symlink_to(wrong_source)
        (by_id / "ata-FixtureDisk_WRONG456").symlink_to(wrong_source)
        image_digest = _digest(run / "source_image.img")
        map_digest = _digest(run / "source_image.map")

        rejected = self._carv_with_environment(
            environment,
            "--src", str(wrong_source),
            "--out", str(self.output),
            "--id", "linux-identity",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertIn("Linux WWN/ATA identity differs", rejected.stdout)
        self.assertEqual(_digest(run / "source_image.img"), image_digest)
        self.assertEqual(_digest(run / "source_image.map"), map_digest)

    def test_sigterm_reaches_ddrescue_child_and_keeps_state(self) -> None:
        fake_bin = self.base / "fake-bin"
        fake_bin.mkdir()
        child_pid_file = self.base / "ddrescue.pid"
        fake_ddrescue = fake_bin / "ddrescue"
        fake_ddrescue.write_text(
            "#!/bin/sh\n"
            "trap 'exit 130' INT\n"
            "trap 'exit 143' TERM\n"
            "map_path=\n"
            "for argument in \"$@\"; do map_path=$argument; done\n"
            "printf '%s\\n' '# Mapfile. Live mirror fixture' "
            "'0x00000000  ?' '0x00000000  0x00001000  +' "
            "'0x00001000  0x00001000  ?' > \"$map_path\"\n"
            "printf '%s\\n' \"$$\" > \"$CARV_TEST_DDRESCUE_PID\"\n"
            "sleep 1\n"
            "printf '%s\\n' '# Mapfile. Live mirror fixture updated' "
            "'0x00001000  +' '0x00000000  0x00002000  +' "
            "> \"$map_path\"\n"
            "while :; do sleep 1; done\n",
            encoding="utf-8",
        )
        fake_ddrescue.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
        environment["CARV_TEST_DDRESCUE_PID"] = str(child_pid_file)
        environment["CARV_TEST_STATE_MAP_MIRROR_INTERVAL_SECONDS"] = "0.1"
        process = subprocess.Popen(
            [
                str(CARV),
                "--src", str(self.source),
                "--out", str(self.output),
                "--id", "stop-fixture",
                "--filesys", "ntfs",
                "--hypersafe-folder-fetch",
            ],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        child_pid = 0
        try:
            deadline = time.monotonic() + 5.0
            while not child_pid_file.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(child_pid_file.is_file(), "fake ddrescue did not start")
            child_pid = int(child_pid_file.read_text(encoding="utf-8").strip())
            live_state_map = (
                self.output /
                "stop-fixture" /
                "state" /
                "source_image.map"
            )
            while not live_state_map.is_file() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertTrue(
                live_state_map.is_file(),
                "ddrescue map was not mirrored while the child was running",
            )
            self.assertIn(
                "Live mirror fixture",
                live_state_map.read_text(encoding="utf-8"),
            )
            while (
                "Live mirror fixture updated"
                not in live_state_map.read_text(encoding="utf-8")
                and time.monotonic() < deadline
            ):
                time.sleep(0.05)
            self.assertIn(
                "Live mirror fixture updated",
                live_state_map.read_text(encoding="utf-8"),
                "state map did not refresh while ddrescue was still running",
            )
            process.terminate()  # Only Carv gets SIGTERM; it must signal its child.
            output, _ = process.communicate(timeout=8)
            self.assertNotEqual(process.returncode, 0, output)
            self.assertIn("asking ddrescue to save its map and exit", output)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            status = self.output / "stop-fixture" / "state" / "hypersafe_bootstrap.txt"
            self.assertTrue(status.is_file())
            self.assertIn("status=failed", status.read_text(encoding="utf-8"))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=3)
            if child_pid:
                try:
                    os.kill(child_pid, 15)
                except ProcessLookupError:
                    pass

    def test_mft_mirror_seed_can_build_preview(self) -> None:
        with self.source.open("r+b") as source:
            source.seek(MFT_OFFSET)
            source.write(b"BAAD")
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "mirror-fixture",
            "--filesys", "ntfs",
            "--hypersafe-folder-fetch",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("using $MFTMirr record 0", result.stdout)
        roots = (
            self.output /
            "mirror-fixture" /
            "state" /
            "hypersafe_root_folders.txt"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(roots, ["Customer videos", "Mobile rescue"])

    def test_plain_folders_recovery_still_handles_riff_formats(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "plain-folders",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        recovered = self.output / "plain-folders" / "recovered" / "Customer videos" / "AVI"
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)

    def test_plain_folders_accepts_partial_folder_name(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "partial-folders",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "customer vid",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "Folder search match for 'customer vid': /customer videos",
            result.stdout,
        )
        recovered = (
            self.output /
            "partial-folders" /
            "recovered" /
            "Customer videos" /
            "AVI"
        )
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)

        reused = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "partial-folders",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "customer vid",
            "--fmt", "avi,wav",
        )
        self.assertEqual(reused.returncode, 0, reused.stdout)
        self.assertIn("Reusing 1 resolved --fold folder path", reused.stdout)
        self.assertEqual(len(list((recovered).glob("*.avi"))), 1)
        self.assertEqual(len(list((recovered).glob("*.wav"))), 1)

    def test_partial_folder_name_with_no_match_fails_closed(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "partial-missing",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "definitely absent",
            "--fmt", "avi",
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "Folder search term did not match any MFT directory",
            result.stdout,
        )

    def test_plain_folders_accepts_explicit_and_expression(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "and-folders",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "customer AND avi,mobile",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "Folder search match for 'customer AND avi': /customer videos/avi",
            result.stdout,
        )
        self.assertIn(
            "Folder search match for 'mobile': /mobile rescue",
            result.stdout,
        )
        recovered = (
            self.output /
            "and-folders" /
            "recovered" /
            "Customer videos" /
            "AVI"
        )
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)
        resolution_state = (
            self.output /
            "and-folders" /
            "state" /
            "folder_scope_resolution.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("query_and_mask=0000000000000001", resolution_state)

        reused = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "and-folders",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "customer AND avi,mobile",
            "--fmt", "avi,wav",
        )
        self.assertEqual(reused.returncode, 0, reused.stdout)
        self.assertIn("Reusing 2 resolved --fold folder paths", reused.stdout)

        missing = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "and-missing",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "mobile AND avi",
            "--fmt", "avi",
        )
        self.assertNotEqual(missing.returncode, 0, missing.stdout)
        self.assertIn(
            "Folder search term did not match any MFT directory",
            missing.stdout,
        )

        encoded_literal = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "encoded-and-literal",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--fold", "@scope-v1:customer%20AND%20avi",
            "--fmt", "avi",
        )
        self.assertNotEqual(encoded_literal.returncode, 0, encoded_literal.stdout)
        self.assertIn(
            "Folder search term did not match any MFT directory",
            encoded_literal.stdout,
        )

    def test_hypersafe_recovery_accepts_case_insensitive_infix_folder_name(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "partial-hypersafe",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "@scope-v1:MER%20VID",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(
            "Folder search match for 'mer vid': /customer videos",
            result.stdout,
        )
        recovered = (
            self.output /
            "partial-hypersafe" /
            "recovered" /
            "Customer videos" /
            "AVI"
        )
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)

    def test_image_immediately_arms_before_source_appears_and_completes_image(self) -> None:
        offline_source = self.source.with_name(self.source.name + ".offline")
        self.source.rename(offline_source)
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "immediate-waiting",
            "--mode", "all",
            "--filesys", "ntfs",
            "--hypersafe", "immediate",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "immediate-waiting" /
            "state" /
            "hypersafe_recovery.txt"
        )
        armed_seen = False
        deadline = time.monotonic() + 10.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file():
                state_now = state_path.read_text(encoding="utf-8")
                if "workflow_status=armed_waiting_for_source" in state_now:
                    armed_seen = True
                    break
            time.sleep(0.05)
        self.assertTrue(armed_seen, "Hypersafe never armed while the source was absent")
        offline_source.rename(self.source)
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Image immediately did not finish after source arrival:\n{output}")
        self.assertEqual(process.returncode, 0, output)
        run = self.output / "immediate-waiting"
        image = run / "source_image.img"
        self.assertTrue(image.is_file(), output)
        self.assertEqual(_digest(image), _digest(self.source))
        state = state_path.read_text(encoding="utf-8")
        self.assertIn("strategy=hypersafe_image_immediately", state)
        self.assertIn("workflow_status=completed", state)
        self.assertIn("source_status=connected", state)
        self.assertIn("image_status=complete", state)
        self.assertIn("quick_image_pass_status=completed", state)
        self.assertIn("selected_retry_status=not_required", state)
        self.assertIn("global_retry_status=not_required", state)
        self.assertIn("full_image_complete=1", state)
        self.assertIn("DONE (Hypersafe immediate full image)", output)
        self.assertFalse(
            (run / "state" / "raw_all_stage.txt").exists(),
            "Image immediately must not be wrapped by the raw-all supervisor",
        )
        self.assertFalse(
            (run / "state" / "raw_all_supervisor_generation.txt").exists(),
            "Hypersafe owns its own ddrescue/reconnect supervision",
        )

        image_digest = _digest(image)
        with self.source.open("r+b") as source:
            source.seek(32)
            source.write(b"different disk")
        rejected = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "immediate-waiting",
            "--mode", "all",
            "--filesys", "ntfs",
            "--hypersafe", "immediate",
        )
        self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
        self.assertIn("identity does not match", rejected.stdout)
        self.assertEqual(_digest(image), image_digest)

    def test_unreadable_mft_falls_back_to_complete_full_image(self) -> None:
        with self.source.open("r+b") as source:
            source.seek(MFT_OFFSET)
            source.write(b"\0" * 1024)
            source.seek(MFT_MIRROR_OFFSET)
            source.write(b"\0" * 1024)

        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "metadata-fallback",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos",
            "--cat", "all",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "metadata-fallback"
        self.assertEqual(_digest(run / "source_image.img"), _digest(self.source))
        state = (run / "state" / "hypersafe_recovery.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_status=completed", state)
        self.assertIn("image_complete=1", state)
        self.assertIn("priority_plan_status=unavailable", state)
        self.assertIn("selected_quick_read_status=not_required", state)
        self.assertIn("selected_retry_status=not_required", state)
        self.assertIn(
            "selected_domain_coverage_stage=metadata_unavailable",
            state,
        )
        self.assertIn(
            "continuing with full-source imaging without folder priority",
            result.stdout,
        )
        self.assertIn(
            "DONE (Hypersafe full image; folder priority unavailable)",
            result.stdout,
        )
        self.assertNotIn("Hypersafe recovery failed", result.stdout)

    def test_image_immediately_detects_only_a_disk_added_after_start(self) -> None:
        block_class = self.base / "synthetic-sys-class-block"
        block_devices = self.base / "synthetic-dev"
        block_class.mkdir()
        block_devices.mkdir()
        environment = os.environ.copy()
        environment["CARV_TEST_BLOCK_CLASS_DIR"] = str(block_class)
        environment["CARV_TEST_BLOCK_DEV_DIR"] = str(block_devices)
        command = [
            str(CARV),
            "--src", "__CARV_WAIT_FOR_NEW_SOURCE__",
            "--out", str(self.output),
            "--id", "immediate-new-disk",
            "--mode", "all",
            "--filesys", "ntfs",
            "--hypersafe", "immediate",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "immediate-new-disk" /
            "state" /
            "hypersafe_recovery.txt"
        )
        deadline = time.monotonic() + 10.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file() and (
                "Waiting for the first new physical disk connected after start"
                in state_path.read_text(encoding="utf-8")
            ):
                break
            time.sleep(0.05)
        else:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe did not enter new-disk waiting mode:\n{output}")

        synthetic_disk = block_devices / "sdb"
        os.link(self.source, synthetic_disk)
        (block_class / "sdb" / "device").mkdir(parents=True)
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe did not image the newly added disk:\n{output}")
        self.assertEqual(process.returncode, 0, output)
        run = self.output / "immediate-new-disk"
        self.assertEqual(_digest(run / "source_image.img"), _digest(self.source))
        state = state_path.read_text(encoding="utf-8")
        self.assertIn(f"source_path={synthetic_disk}", state)
        self.assertIn("workflow_status=completed", state)
        self.assertIn("Hypersafe detected new source", output)

    def test_named_folder_priority_starts_when_new_disk_appears(self) -> None:
        block_class = self.base / "synthetic-sys-class-block"
        block_devices = self.base / "synthetic-dev"
        block_class.mkdir()
        block_devices.mkdir()
        environment = os.environ.copy()
        environment["CARV_TEST_BLOCK_CLASS_DIR"] = str(block_class)
        environment["CARV_TEST_BLOCK_DEV_DIR"] = str(block_devices)
        command = [
            str(CARV),
            "--src", "__CARV_WAIT_FOR_NEW_SOURCE__",
            "--out", str(self.output),
            "--id", "named-priority-new-disk",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "@scope-v1:MER%20VID",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "named-priority-new-disk" /
            "state" /
            "hypersafe_recovery.txt"
        )
        deadline = time.monotonic() + 10.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file() and (
                "Waiting for the first new physical disk connected after start"
                in state_path.read_text(encoding="utf-8")
            ):
                break
            time.sleep(0.05)
        else:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(
                "Named-folder Hypersafe did not enter new-disk waiting mode:\n"
                f"{output}"
            )

        synthetic_disk = block_devices / "sdb"
        os.link(self.source, synthetic_disk)
        (block_class / "sdb" / "device").mkdir(parents=True)
        try:
            output, _ = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(
                "Named-folder Hypersafe did not finish after first contact:\n"
                f"{output}"
            )
        self.assertEqual(process.returncode, 0, output)
        run = self.output / "named-priority-new-disk"
        recovered = run / "recovered" / "Customer videos" / "AVI"
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)
        self.assertEqual(_digest(run / "source_image.img"), _digest(self.source))
        state = state_path.read_text(encoding="utf-8")
        self.assertIn(f"source_path={synthetic_disk}", state)
        self.assertIn("workflow_status=completed", state)
        self.assertIn("Hypersafe detected new source", output)
        self.assertIn(
            "After priority read:",
            output,
        )
        self.assertNotIn(
            "Checking rescued head bytes before resuming an early interrupted preview",
            output,
        )
        self.assertLess(
            output.index("selected folder/file extents"),
            output.index("Ddrescue scope: full source"),
        )

    def test_tree_recovery_waits_for_selected_source_first_contact(self) -> None:
        offline_source = self.source.with_name(self.source.name + ".offline")
        self.source.rename(offline_source)
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "tree-first-contact",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "tree-first-contact" /
            "state" /
            "hypersafe_recovery.txt"
        )
        deadline = time.monotonic() + 10.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file() and (
                "workflow_status=armed_waiting_for_source"
                in state_path.read_text(encoding="utf-8")
            ):
                break
            time.sleep(0.05)
        else:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(
                "Tree Hypersafe did not remain armed for its selected source:\n"
                f"{output}"
            )

        offline_source.rename(self.source)
        try:
            output, _ = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(
                "Tree Hypersafe did not finish after source first contact:\n"
                f"{output}"
            )
        self.assertEqual(process.returncode, 0, output)
        run = self.output / "tree-first-contact"
        recovered = run / "recovered" / "Customer videos" / "AVI"
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)
        self.assertEqual(_digest(run / "source_image.img"), _digest(self.source))
        state = state_path.read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("source_status=connected", state)

    def test_all_selected_file_types_are_recovered_before_full_image_and_resume_is_idempotent(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-fixture",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "selected-fixture"
        recovered = run / "recovered" / "Customer videos" / "AVI" / "family_clip.avi"
        recovered_wav = run / "recovered" / "Customer videos" / "AVI" / "camera_audio.wav"
        self.assertTrue(recovered.is_file(), result.stdout)
        self.assertEqual(recovered.read_bytes(), AVI_DATA)
        self.assertTrue(recovered_wav.is_file(), result.stdout)
        self.assertEqual(recovered_wav.read_bytes(), WAV_DATA)
        state = (run / "state" / "hypersafe_recovery.txt").read_text(encoding="utf-8")
        self.assertIn("status=completed", state)
        self.assertIn("workflow_status=completed", state)
        self.assertIn("image_status=complete", state)
        self.assertIn("strategy=hypersafe_selected_quick_map_retry", state)
        self.assertIn("selected_files=2", state)
        self.assertIn("early_recovered=2", state)
        self.assertIn("early_folders_with_complete_files=1", state)
        self.assertIn("selected_quick_read_status=completed", state)
        self.assertIn("quick_image_pass_status=completed", state)
        self.assertIn("selected_retry_status=not_required", state)
        self.assertIn("selected_retry_forward_status=not_required", state)
        self.assertIn("selected_retry_reverse_status=not_required", state)
        self.assertRegex(state, r"selected_domain_imaged_ranges=[1-9][0-9]*\n")
        self.assertIn("selected_domain_partial_ranges=0", state)
        self.assertIn("selected_domain_unread_ranges=0", state)
        self.assertIn("selected_domain_unresolved_bytes=0", state)
        self.assertIn("selected_domain_coverage_status=available", state)
        self.assertRegex(state, r"selected_quick_new_bytes=[1-9][0-9]*\n")
        self.assertIn("global_retry_status=not_required", state)
        self.assertIn("full_image_complete=1", state)
        self.assertIn("final_waiting=0", state)
        self.assertIn("final_folders_with_complete_files=1", state)
        self.assertIn("final_failed=0", state)
        self.assertIn("final_unaccounted=0", state)
        missing_lines = (
            run / "state" / "hypersafe_selected_missing.tsv"
        ).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(missing_lines), 1)
        self.assertTrue(missing_lines[0].startswith("problem\trecord\tfamily\t"))
        avi_ready = result.stdout.index(f"Hypersafe early file ready: {recovered}")
        selected_domain = result.stdout.index("selected folder/file extents")
        wav_ready = result.stdout.index(f"Hypersafe early file ready: {recovered_wav}")
        full_image = result.stdout.index("Ddrescue scope: full source")
        self.assertLess(selected_domain, avi_ready)
        self.assertLess(selected_domain, wav_ready)
        self.assertLess(avi_ready, full_image)
        self.assertLess(wav_ready, full_image)
        self.assertEqual((run / "source_image.img").stat().st_size, SOURCE_SIZE)

        first_digest = _digest(recovered)
        first_wav_digest = _digest(recovered_wav)
        resumed = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-fixture",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(resumed.returncode, 0, resumed.stdout)
        self.assertEqual(_digest(recovered), first_digest)
        self.assertEqual(_digest(recovered_wav), first_wav_digest)
        self.assertEqual(len(list((run / "recovered").rglob("*.avi"))), 1)
        self.assertEqual(len(list((run / "recovered").rglob("*.wav"))), 1)

    def test_selected_hypersafe_image_only_prioritizes_extents_without_reconstructing_files(self) -> None:
        result = self._carv(
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-image-only",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--image-only",
            "--fold", "Customer videos/AVI",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "selected-image-only"
        self.assertEqual(_digest(run / "source_image.img"), _digest(self.source))
        recovered_root = run / "recovered"
        self.assertFalse(
            any(path.is_file() for path in recovered_root.rglob("*")),
            result.stdout,
        )
        state = (run / "state" / "hypersafe_recovery.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_status=completed", state)
        self.assertIn("image_only=1", state)
        self.assertIn("image_status=complete", state)
        self.assertIn("selected_files=2", state)
        self.assertIn("early_recovered=0", state)
        self.assertIn("quick_image_recovered=0", state)
        self.assertIn("targeted_retry_recovered=0", state)
        self.assertIn("final_recovered=0", state)
        self.assertIn("Hypersafe image-only completed", state)
        self.assertNotIn("Hypersafe early file ready:", result.stdout)

    def test_selected_hypersafe_image_only_still_retries_unresolved_priority_extents(self) -> None:
        environment, phase_log = self._faulting_ddrescue_environment(
            "recover_on_selected_retry"
        )
        result = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-image-only-retry",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--image-only",
            "--fold", "Customer videos/AVI",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "selected-image-only-retry"
        recovered_root = run / "recovered"
        self.assertFalse(
            any(path.is_file() for path in recovered_root.rglob("*")),
            result.stdout,
        )
        state = (run / "state" / "hypersafe_recovery.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("image_only=1", state)
        self.assertIn("selected_retry_status=completed\n", state)
        self.assertIn("selected_retry_forward_status=completed\n", state)
        self.assertIn("selected_retry_reverse_status=completed\n", state)
        self.assertIn(f"selected_retry_forward_new_bytes={CLUSTER_SIZE}", state)
        self.assertIn("selected_domain_unresolved_bytes=0", state)
        phases = phase_log.read_text(encoding="utf-8")
        self.assertIn("-r 2", phases)
        self.assertIn("-R -r 1", phases)

    def test_selected_unresolved_extent_is_recovered_by_targeted_retry(self) -> None:
        environment, phase_log = self._faulting_ddrescue_environment(
            "recover_on_selected_retry"
        )
        result = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-retry-recovers",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "selected-retry-recovers"
        recovered = run / "recovered" / "Customer videos" / "AVI"
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)
        state = (run / "state" / "hypersafe_recovery.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_status=completed", state)
        self.assertIn("image_status=complete", state)
        self.assertIn("quick_image_pass_status=completed", state)
        self.assertIn("selected_retry_status=completed\n", state)
        self.assertIn("selected_retry_forward_status=completed\n", state)
        self.assertIn("selected_retry_reverse_status=completed\n", state)
        self.assertIn(f"selected_retry_forward_new_bytes={CLUSTER_SIZE}", state)
        self.assertIn("selected_retry_forward_new_bytes_known=1", state)
        self.assertIn("selected_retry_reverse_new_bytes_known=1", state)
        self.assertIn("selected_domain_unresolved_bytes=0", state)
        self.assertIn("global_retry_status=not_required", state)
        self.assertIn("early_waiting=1", state)
        self.assertIn("quick_image_waiting=1", state)
        self.assertIn("targeted_retry_waiting=0", state)
        self.assertIn("final_waiting=0", state)
        self.assertIn("final_folders_with_complete_files=1", state)
        phases = phase_log.read_text(encoding="utf-8")
        self.assertIn("-r 2", phases)
        self.assertIn("-R -r 1", phases)

    def test_selected_extent_that_remains_unresolved_is_reported_honestly(self) -> None:
        environment, phase_log = self._faulting_ddrescue_environment(
            "remain_unresolved"
        )
        result = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "selected-retry-unresolved",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        run = self.output / "selected-retry-unresolved"
        recovered = run / "recovered" / "Customer videos" / "AVI"
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertFalse((recovered / "camera_audio.wav").exists())
        state = (run / "state" / "hypersafe_recovery.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_status=completed", state)
        self.assertIn("image_status=unresolved", state)
        self.assertIn("quick_image_pass_status=completed", state)
        self.assertIn(
            "selected_retry_status=completed_with_unresolved\n",
            state,
        )
        self.assertIn(
            "selected_retry_forward_status=completed_with_unresolved\n",
            state,
        )
        self.assertIn(
            "selected_retry_reverse_status=completed_with_unresolved\n",
            state,
        )
        self.assertIn("selected_retry_forward_new_bytes=0", state)
        self.assertIn("selected_retry_reverse_new_bytes=0", state)
        self.assertIn("selected_retry_forward_new_bytes_known=1", state)
        self.assertIn("selected_retry_reverse_new_bytes_known=1", state)
        self.assertIn("global_retry_status=completed", state)
        self.assertIn("final_waiting=1", state)
        self.assertIn("final_folders_with_complete_files=1", state)
        self.assertIn(f"map_unresolved_bytes={CLUSTER_SIZE}", state)
        self.assertIn(f"selected_domain_unresolved_bytes={CLUSTER_SIZE}", state)
        self.assertIn("full_image_complete=0", state)
        missing = (run / "state" / "hypersafe_selected_missing.tsv").read_text(
            encoding="utf-8"
        )
        self.assertIn("camera_audio.wav", missing)
        self.assertIn("one or more file extents are still unresolved", missing)
        phases = phase_log.read_text(encoding="utf-8")
        self.assertIn("-r 2", phases)
        self.assertIn("-R -r 1", phases)
        self.assertIn("-r 3", phases)

    def test_disconnected_source_waits_verifies_and_resumes_same_disk(self) -> None:
        environment, _phase_log = self._faulting_ddrescue_environment(
            "disconnect_then_return"
        )
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "disconnect-returns",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output / "disconnect-returns" / "state" / "hypersafe_recovery.txt"
        )
        waiting_seen = False
        deadline = time.monotonic() + 15.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file():
                state_now = state_path.read_text(encoding="utf-8")
                if "workflow_status=waiting_for_source" in state_now:
                    waiting_seen = True
                    break
            time.sleep(0.05)
        offline_source = self.source.with_name(self.source.name + ".offline")
        self.assertTrue(offline_source.is_file(), "fixture source was not disconnected")
        offline_source.rename(self.source)
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe did not leave waiting_for_source:\n{output}")
        self.assertEqual(process.returncode, 0, output)
        self.assertTrue(waiting_seen, output)
        state = state_path.read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("source_status=connected", state)
        self.assertIn("image_status=complete", state)
        self.assertIn("verified the returning source", output)

    def test_temporarily_unreadable_identity_waits_then_resumes(self) -> None:
        environment, _phase_log = self._faulting_ddrescue_environment(
            "identity_unreadable_then_return"
        )
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "identity-unreadable-returns",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "identity-unreadable-returns" /
            "state" /
            "hypersafe_recovery.txt"
        )
        offline_source = self.source.with_name(self.source.name + ".offline")
        deadline = time.monotonic() + 15.0
        while process.poll() is None and time.monotonic() < deadline:
            if offline_source.is_file():
                break
            time.sleep(0.05)
        self.assertTrue(offline_source.is_file(), "fixture source was not disconnected")
        offline_source.rename(self.source)

        identity_wait_seen = False
        deadline = time.monotonic() + 25.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file():
                state_now = state_path.read_text(encoding="utf-8")
                if "source_status=identity_unavailable" in state_now:
                    identity_wait_seen = True
                    break
            time.sleep(0.05)
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(
                "Hypersafe did not recover from temporarily unreadable identity:\n"
                + output
            )
        self.assertTrue(identity_wait_seen, output)
        self.assertEqual(process.returncode, 0, output)
        self.assertIn("temporarily unreadable", output)
        state = state_path.read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("source_status=connected", state)
        self.assertNotIn("source_status=identity_mismatch", state)
        probe_counter = Path(environment["CARV_TEST_IDENTITY_PROBE_COUNTER"])
        self.assertGreaterEqual(int(probe_counter.read_text(encoding="utf-8")), 4)

    def test_exhausted_retry_batch_waits_then_resumes_without_error(self) -> None:
        environment, _phase_log = self._faulting_ddrescue_environment(
            "retry_budget_then_return"
        )
        environment["CARV_TEST_DDRESCUE_SOURCE_RETRY_DELAY_SECONDS"] = "0"
        result = self._carv_with_environment(
            environment,
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "retry-budget-returns",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Hypersafe source retry batch exhausted", result.stdout)
        self.assertIn("remaining in waiting-for-source", result.stdout)
        counter_path = Path(environment["CARV_TEST_RETRY_BUDGET_COUNTER"])
        self.assertGreaterEqual(
            int(counter_path.read_text(encoding="utf-8")),
            7,
        )
        state = (
            self.output /
            "retry-budget-returns" /
            "state" /
            "hypersafe_recovery.txt"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("quick_image_pass_status=completed", state)
        self.assertNotIn("status=failed", state)

    def test_operator_can_stop_imaging_and_recover_from_partial_image(self) -> None:
        environment, phase_log = self._faulting_ddrescue_environment(
            "operator_continue_partial"
        )
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "operator-continue",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        ready_path = Path(environment["CARV_TEST_PARTIAL_IMAGE_READY"])
        deadline = time.monotonic() + 20.0
        while process.poll() is None and time.monotonic() < deadline:
            if ready_path.is_file():
                break
            time.sleep(0.05)
        if not ready_path.is_file():
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe never reached the full-image pass:\n{output}")

        state_dir = self.output / "operator-continue" / "state"
        supervisor_path = state_dir / "ddrescue_supervisor.txt"
        deadline = time.monotonic() + 5.0
        while process.poll() is None and time.monotonic() < deadline:
            if supervisor_path.is_file():
                supervisor = supervisor_path.read_text(encoding="utf-8")
                if "status=active" in supervisor:
                    break
            time.sleep(0.05)
        else:
            supervisor = ""
        self.assertIn("status=active", supervisor)
        self.assertIn("continue_available=1", supervisor)

        (state_dir / "source_image_continue_requested").write_text(
            "reason=fixture_operator_continue\n",
            encoding="utf-8",
        )
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe did not continue from its partial image:\n{output}")

        self.assertEqual(process.returncode, 0, output)
        self.assertIn("Imaging stopped by operator request", output)
        self.assertIn("selected source retry passes are skipped", output)
        self.assertIn("remaining whole-source retries are skipped", output)

        image_status = (state_dir / "source_image_status.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("status=partial_continue", image_status)
        self.assertIn("continue_requested=1", image_status)

        state = (state_dir / "hypersafe_recovery.txt").read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("quick_image_pass_status=partial_continue", state)
        self.assertIn("selected_retry_status=skipped_operator_continue", state)
        self.assertIn("global_retry_status=skipped_operator_continue", state)
        self.assertIn("full_image_complete=0", state)

        recovered = (
            self.output /
            "operator-continue" /
            "recovered" /
            "Customer videos" /
            "AVI"
        )
        self.assertEqual((recovered / "family_clip.avi").read_bytes(), AVI_DATA)
        self.assertEqual((recovered / "camera_audio.wav").read_bytes(), WAV_DATA)

        phases = phase_log.read_text(encoding="utf-8")
        self.assertNotIn("-r 2", phases)
        self.assertNotIn("-r 3", phases)

    def test_operator_can_finish_immediate_mode_with_partial_image(self) -> None:
        environment, phase_log = self._faulting_ddrescue_environment(
            "operator_continue_partial"
        )
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "immediate-operator-continue",
            "--mode", "all",
            "--filesys", "ntfs",
            "--hypersafe", "immediate",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        ready_path = Path(environment["CARV_TEST_PARTIAL_IMAGE_READY"])
        deadline = time.monotonic() + 20.0
        while process.poll() is None and time.monotonic() < deadline:
            if ready_path.is_file():
                break
            time.sleep(0.05)
        if not ready_path.is_file():
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Immediate Hypersafe never reached full imaging:\n{output}")

        state_dir = self.output / "immediate-operator-continue" / "state"
        (state_dir / "source_image_continue_requested").write_text(
            "reason=fixture_operator_continue\n",
            encoding="utf-8",
        )
        try:
            output, _ = process.communicate(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Immediate Hypersafe did not keep its partial image:\n{output}")

        self.assertEqual(process.returncode, 0, output)
        state = (state_dir / "hypersafe_recovery.txt").read_text(encoding="utf-8")
        self.assertIn("workflow_status=completed", state)
        self.assertIn("quick_image_pass_status=partial_continue", state)
        self.assertIn("global_retry_status=skipped_operator_continue", state)
        self.assertIn("full_image_complete=0", state)
        self.assertIn("remaining source retries are skipped", output)
        phases = phase_log.read_text(encoding="utf-8")
        self.assertNotIn("-r 3", phases)

    def test_disconnected_source_rejects_different_returning_disk(self) -> None:
        environment, _phase_log = self._faulting_ddrescue_environment(
            "disconnect_wrong_source"
        )
        command = [
            str(CARV),
            "--src", str(self.source),
            "--out", str(self.output),
            "--id", "disconnect-wrong-source",
            "--mode", "folders",
            "--filesys", "ntfs",
            "--hypersafe-recover",
            "--fold", "Customer videos/AVI",
            "--fmt", "avi,wav",
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        state_path = (
            self.output /
            "disconnect-wrong-source" /
            "state" /
            "hypersafe_recovery.txt"
        )
        waiting_seen = False
        deadline = time.monotonic() + 15.0
        while process.poll() is None and time.monotonic() < deadline:
            if state_path.is_file():
                state_now = state_path.read_text(encoding="utf-8")
                if "workflow_status=waiting_for_source" in state_now:
                    waiting_seen = True
                    break
            time.sleep(0.05)
        self.assertTrue(waiting_seen, "Hypersafe never entered waiting_for_source")
        self.assertTrue(
            self.source.with_name(self.source.name + ".offline").is_file(),
            "fixture source was not disconnected",
        )
        wrong_source = Path(environment["CARV_TEST_WRONG_SOURCE"])
        shutil.copy2(wrong_source, self.source)
        try:
            output, _ = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate(timeout=5)
            self.fail(f"Hypersafe did not reject the returning wrong source:\n{output}")
        self.assertNotEqual(process.returncode, 0, output)
        state = state_path.read_text(encoding="utf-8")
        self.assertIn("workflow_status=failed", state)
        self.assertIn("source_status=identity_mismatch", state)
        self.assertIn(
            "detail=A source appeared, but its identity does not match the disk bound to this Service ID",
            state,
        )
        self.assertIn("identity does not match", output)
        self.assertIn("Hypersafe rejected the returning source", output)


if __name__ == "__main__":
    unittest.main()
