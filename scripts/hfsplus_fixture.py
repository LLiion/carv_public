#!/usr/bin/env python3
"""Create and verify Carv's small HFS+ truth fixture.

The ordinary tree works on any local filesystem and is used by quick tests.
The macOS image generator uses the same code, then adds fragmentation pressure
before the final truth manifest is written.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unicodedata


MANIFEST_VERSION = "carv-hfsplus-fixture-v1"
FIXTURE_DIRECTORY = "Carv HFS+, facit"
MARKER_NAME = ".carv-hfsplus-fixture-v1"
READ_SIZE = 1024 * 1024
FRAGMENT_SMALL_PATH = Path("Carv HFS+, facit/Fragment/över 8 extents.bin")
FRAGMENT_LARGE_PATH = Path("Carv HFS+, facit/Fragment/över 64 extents.bin")


def write_pattern(path: Path, label: str, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = hashlib.sha256(label.encode("utf-8")).digest()
    block = seed * (READ_SIZE // len(seed))
    remaining = size
    with path.open("wb") as handle:
        while remaining:
            chunk = block[: min(remaining, len(block))]
            handle.write(chunk)
            remaining -= len(chunk)
        handle.flush()
        os.fsync(handle.fileno())


def create_tree(root: Path, include_fragment_payloads: bool = True) -> Path:
    fixture = root / FIXTURE_DIRECTORY
    if fixture.exists():
        raise FileExistsError(f"Fixture root already exists: {fixture}")

    directories = (
        fixture / "Bilder" / "Åsa, BB",
        fixture / "Dokument" / "djupt" / "ännu djupare",
        fixture / "Tom mapp 😴",
        fixture / "Okänt format",
        fixture / "Hardlinks" / "andra platsen",
        fixture / "Scope A, ett" / "vald gren",
        fixture / "Scope B – två" / "vald gren",
        fixture / "Utanför scope",
        fixture / "Fragment",
    )
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
    (root / MARKER_NAME).write_text(MANIFEST_VERSION + "\n", encoding="utf-8")

    files: tuple[tuple[Path, str, int], ...] = (
        (fixture / "Bilder" / "Åsa, BB" / "nyfödd 😄.jpg", "fixture-jpeg", 91_337),
        (fixture / "Dokument" / "räddningsanteckning", "extensionless", 12_345),
        (fixture / "Dokument" / "djupt" / "ännu djupare" / "rapport.txt", "nested", 4_321),
        (fixture / "Okänt format" / "kunddata.weird", "unknown", 23_456),
        (fixture / "Scope A, ett" / "vald gren" / "alpha.bin", "scope-a", 8_193),
        (fixture / "Scope B – två" / "vald gren" / "beta.bin", "scope-b", 16_385),
        (fixture / "Utanför scope" / "ska-inte-följa-med.bin", "outside", 7_777),
    )
    for path, label, size in files:
        write_pattern(path, label, size)

    (fixture / "Dokument" / "nollfil, tom").touch()

    hardlink_source = fixture / "Hardlinks" / "original, ÅÄÖ.bin"
    hardlink_second = fixture / "Hardlinks" / "andra platsen" / "samma data 😄.bin"
    write_pattern(hardlink_source, "hardlink-content", 65_537)
    os.link(hardlink_source, hardlink_second)

    if include_fragment_payloads:
        write_pattern(root / FRAGMENT_SMALL_PATH, "fragment-small", 2 * 1024 * 1024)
        write_pattern(root / FRAGMENT_LARGE_PATH, "fragment-large", 12 * 1024 * 1024)

    return fixture


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def fixture_paths(root: Path) -> list[Path]:
    fixture = root / FIXTURE_DIRECTORY
    if not fixture.is_dir():
        raise ValueError(f"Fixture directory is missing: {fixture}")
    return [fixture, *sorted(fixture.rglob("*"), key=lambda value: value.as_posix())]


def link_groups(root: Path) -> dict[tuple[int, int], str]:
    groups: dict[tuple[int, int], list[Path]] = {}
    for path in fixture_paths(root):
        if path.is_file() and not path.is_symlink():
            stat = path.stat()
            if stat.st_nlink > 1:
                groups.setdefault((stat.st_dev, stat.st_ino), []).append(path)
    result: dict[tuple[int, int], str] = {}
    for index, key in enumerate(sorted(groups, key=lambda item: groups[item][0].as_posix()), 1):
        result[key] = f"hardlink-{index:03d}"
    return result


def build_rows(root: Path) -> list[dict[str, str]]:
    groups = link_groups(root)
    rows: list[dict[str, str]] = []
    for path in fixture_paths(root):
        relpath = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append({
                "kind": "symlink",
                "size": "0",
                "sha256": "-",
                "link_group": "-",
                "link_target": os.readlink(path),
                "min_extents": "0",
                "relpath": relpath,
            })
        elif path.is_dir():
            rows.append({
                "kind": "directory",
                "size": "0",
                "sha256": "-",
                "link_group": "-",
                "link_target": "-",
                "min_extents": "0",
                "relpath": relpath,
            })
        elif path.is_file():
            stat = path.stat()
            key = (stat.st_dev, stat.st_ino)
            min_extents = 0
            normalized_relpath = Path(unicodedata.normalize("NFC", relpath))
            if normalized_relpath == FRAGMENT_SMALL_PATH:
                min_extents = 9
            elif normalized_relpath == FRAGMENT_LARGE_PATH:
                min_extents = 65
            rows.append({
                "kind": "file",
                "size": str(stat.st_size),
                "sha256": sha256_file(path),
                "link_group": groups.get(key, "-"),
                "link_target": "-",
                "min_extents": str(min_extents),
                "relpath": relpath,
            })
    return rows


def write_manifest(root: Path, manifest: Path) -> int:
    rows = build_rows(root)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8", newline="") as handle:
        handle.write(f"# {MANIFEST_VERSION}\n")
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "kind", "size", "sha256", "link_group",
                "link_target", "min_extents", "relpath",
            ),
            delimiter="\t",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def read_manifest(manifest: Path) -> list[dict[str, str]]:
    with manifest.open("r", encoding="utf-8", newline="") as handle:
        version = handle.readline().rstrip("\n")
        if version != f"# {MANIFEST_VERSION}":
            raise ValueError(f"Unsupported fixture manifest: {version}")
        return list(csv.DictReader(handle, delimiter="\t"))


def scope_matches(relpath: str, scopes: list[str]) -> bool:
    if not scopes:
        return True
    normalized_path = unicodedata.normalize("NFC", "/" + relpath.strip("/"))
    for scope in scopes:
        normalized_scope = unicodedata.normalize("NFC", "/" + scope.strip("/"))
        if normalized_path == normalized_scope or normalized_path.startswith(normalized_scope + "/"):
            return True
    return False


def verify(
    root: Path,
    manifest: Path,
    require_hardlinks: bool = False,
    scopes: list[str] | None = None,
) -> list[str]:
    failures: list[str] = []
    hardlink_inodes: dict[str, set[tuple[int, int]]] = {}
    matched_rows = 0
    for row in read_manifest(manifest):
        if not scope_matches(row["relpath"], scopes or []):
            continue
        matched_rows += 1
        path = root / row["relpath"]
        kind = row["kind"]
        if kind == "directory":
            if not path.is_dir():
                failures.append(f"missing directory: {row['relpath']}")
            continue
        if kind == "symlink":
            if not path.is_symlink():
                failures.append(f"missing symlink: {row['relpath']}")
            elif os.readlink(path) != row["link_target"]:
                failures.append(f"wrong symlink target: {row['relpath']}")
            continue
        if not path.is_file():
            failures.append(f"missing file: {row['relpath']}")
            continue
        stat = path.stat()
        if stat.st_size != int(row["size"]):
            failures.append(
                f"wrong size: {row['relpath']} expected={row['size']} actual={stat.st_size}"
            )
            continue
        digest = sha256_file(path)
        if digest != row["sha256"]:
            failures.append(f"wrong SHA-256: {row['relpath']}")
        if row["link_group"] != "-":
            hardlink_inodes.setdefault(row["link_group"], set()).add((stat.st_dev, stat.st_ino))

    if require_hardlinks:
        for group, identities in hardlink_inodes.items():
            if len(identities) != 1:
                failures.append(f"hardlink identity was not preserved: {group}")
    if scopes and matched_rows == 0:
        failures.append("none of the requested scopes exist in the truth manifest")
    return failures


def replace_with_fragmentation_pressure(root: Path) -> None:
    """Try to force two files into holes on a real, nearly-full HFS+ volume."""
    marker = root / MARKER_NAME
    try:
        marker_text = marker.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError(f"Refusing to fill an unmarked volume: {root}") from exc
    if marker_text != MANIFEST_VERSION or not (root / FIXTURE_DIRECTORY).is_dir():
        raise ValueError(f"Refusing to fill an invalid fixture volume: {root}")

    small_path = root / FRAGMENT_SMALL_PATH
    large_path = root / FRAGMENT_LARGE_PATH
    small_path.unlink(missing_ok=True)
    large_path.unlink(missing_ok=True)

    work = root / ".carv-fragment-work"
    work.mkdir()
    free_before = shutil.disk_usage(root).free
    reserve = 24 * 1024 * 1024
    block_size = 128 * 1024
    blocker_count = max(0, (free_before - reserve) // block_size)
    try:
        for index in range(blocker_count):
            write_pattern(work / f"block-{index:05d}.bin", f"block-{index}", block_size)
        # Consume the still-contiguous tail before holes are opened.  The two
        # payloads then have to use the small alternating holes as well.
        write_pattern(work / "tail-guard.bin", "tail-guard", 20 * 1024 * 1024)
        for index in range(0, blocker_count, 2):
            (work / f"block-{index:05d}.bin").unlink()
        write_pattern(root / FRAGMENT_LARGE_PATH, "fragment-large", 12 * 1024 * 1024)
        write_pattern(root / FRAGMENT_SMALL_PATH, "fragment-small", 2 * 1024 * 1024)
        os.sync()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def command_create(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    create_tree(root, include_fragment_payloads=not args.no_fragment_payloads)
    count = write_manifest(root, Path(args.manifest).resolve()) if args.manifest else 0
    print(f"fixture_root\t{root}")
    if args.manifest:
        print(f"manifest\t{Path(args.manifest).resolve()}")
        print(f"manifest_rows\t{count}")
    return 0


def command_manifest(args: argparse.Namespace) -> int:
    count = write_manifest(Path(args.root).resolve(), Path(args.manifest).resolve())
    print(f"manifest_rows\t{count}")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    failures = verify(
        Path(args.root).resolve(),
        Path(args.manifest).resolve(),
        require_hardlinks=args.require_hardlinks,
        scopes=args.scope,
    )
    if failures:
        for failure in failures:
            print(f"FAIL\t{failure}")
        print(f"result\tfailed\nfailures\t{len(failures)}")
        return 1
    print("result\tok\nfailures\t0")
    return 0


def command_fragment(args: argparse.Namespace) -> int:
    replace_with_fragmentation_pressure(Path(args.root).resolve())
    return 0


def command_verify_extents(args: argparse.Namespace) -> int:
    expected = {
        unicodedata.normalize("NFC", "/" + row["relpath"].strip("/")): int(row["min_extents"])
        for row in read_manifest(Path(args.manifest).resolve())
        if int(row["min_extents"]) > 0
    }
    actual: dict[str, int] = {}
    with Path(args.report).resolve().open("r", encoding="utf-8", errors="strict") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            path = unicodedata.normalize("NFC", "/" + row["path"].strip("/"))
            actual[path] = int(row["extent_count"])

    failures = []
    for path, minimum in expected.items():
        found = actual.get(path)
        if found is None:
            failures.append(f"missing extent report row: {path}")
        elif found < minimum:
            failures.append(f"too few extents: {path} expected>={minimum} actual={found}")
        else:
            print(f"EXTENTS\t{found}\tminimum={minimum}\t{path}")
    if failures:
        for failure in failures:
            print(f"FAIL\t{failure}")
        return 1
    print("extent_result\tok")
    return 0


def command_self_test(_args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="carv-hfs-fixture-") as temp_text:
        temp = Path(temp_text)
        source = temp / "source"
        recovered = temp / "recovered"
        manifest = temp / "truth.tsv"
        source.mkdir()
        create_tree(source)
        rows = write_manifest(source, manifest)
        shutil.copytree(source / "Carv HFS+, facit", recovered / "Carv HFS+, facit")
        failures = verify(recovered, manifest)
        if failures:
            raise AssertionError(f"clean copy failed verification: {failures}")
        damaged = recovered / "Carv HFS+, facit" / "Dokument" / "räddningsanteckning"
        damaged.write_bytes(b"damaged")
        if not verify(recovered, manifest):
            raise AssertionError("damaged copy unexpectedly passed verification")
        scopes = [
            f"/{FIXTURE_DIRECTORY}/Scope A, ett",
            f"/{FIXTURE_DIRECTORY}/Scope B – två",
        ]
        if verify(recovered, manifest, scopes=scopes):
            raise AssertionError("scoped verification was affected by an out-of-scope damaged file")
        if not verify(recovered, manifest, scopes=["/finns inte"]):
            raise AssertionError("an unknown scope unexpectedly passed verification")
        print(f"self_test\tok\nmanifest_rows\t{rows}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="Create the deterministic fixture tree.")
    create.add_argument("--root", required=True)
    create.add_argument("--manifest")
    create.add_argument("--no-fragment-payloads", action="store_true")
    create.set_defaults(func=command_create)

    manifest = subparsers.add_parser("manifest", help="Write truth from an existing tree.")
    manifest.add_argument("--root", required=True)
    manifest.add_argument("--manifest", required=True)
    manifest.set_defaults(func=command_manifest)

    verify_parser = subparsers.add_parser("verify", help="Verify recovered output against truth.")
    verify_parser.add_argument("--root", required=True)
    verify_parser.add_argument("--manifest", required=True)
    verify_parser.add_argument("--require-hardlinks", action="store_true")
    verify_parser.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Verify only this path and its descendants; may be repeated.",
    )
    verify_parser.set_defaults(func=command_verify)

    fragment = subparsers.add_parser("fragment", help="Add fragmentation pressure on a real volume.")
    fragment.add_argument("--root", required=True)
    fragment.set_defaults(func=command_fragment)

    extents = subparsers.add_parser(
        "verify-extents",
        help="Compare a compact-index extent report against manifest minima.",
    )
    extents.add_argument("--manifest", required=True)
    extents.add_argument("--report", required=True)
    extents.set_defaults(func=command_verify_extents)

    self_test = subparsers.add_parser("self-test", help="Run a no-disk round-trip test.")
    self_test.set_defaults(func=command_self_test)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(f"ERROR\t{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
