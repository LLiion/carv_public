#!/usr/bin/env python3
"""Install or remove the portable Carv runtime for the current Linux user."""

from __future__ import annotations

import os
from pathlib import Path
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

from manage_linux_desktop_dev import refresh_desktop_caches, write_desktop_entry


ROOT_RUNTIME_FILES = (
    "carv",
    "carv_gui",
    "carv_gui_terminal",
    "install-carv.sh",
    "uninstall-carv.sh",
)
DATA_RUNTIME_FILES = (
    "database.db",
)
SCRIPT_RUNTIME_FILES = (
    "carv_gui_qt.py",
    "carv_gui_askpass.py",
    "combo_down_v.svg",
    "combo_down_v_macos.svg",
    "tree_branch_closed_black.svg",
    "tree_branch_open_black.svg",
    "tree_branch_closed_white.svg",
    "tree_branch_open_white.svg",
    "wrench_button_icon.png",
    "carv_title_logo.png",
    "manage_linux_desktop_dev.py",
    "manage_linux_user_install.py",
)

INSTALL_WRAPPER = """#!/usr/bin/env sh
set -eu

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$PACKAGE_DIR/scripts/manage_linux_user_install.py" install "$PACKAGE_DIR"
"""

UNINSTALL_WRAPPER = """#!/usr/bin/env sh
set -eu

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$PACKAGE_DIR/scripts/manage_linux_user_install.py" remove
"""


def write_package_wrappers(package_root: Path) -> int:
    package_root.mkdir(parents=True, exist_ok=True)
    for name, contents in (
        ("install-carv.sh", INSTALL_WRAPPER),
        ("uninstall-carv.sh", UNINSTALL_WRAPPER),
    ):
        destination = package_root / name
        destination.write_text(contents, encoding="utf-8")
        destination.chmod(0o755)
    return 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_run_installer(bundle_root: Path, output_path: Path, version: str) -> int:
    bundle_root = bundle_root.resolve()
    output_path = output_path.resolve()
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version) is None:
        print(f"Invalid Carv version: {version}", file=sys.stderr)
        return 1
    if not bundle_root.is_dir():
        print(f"Bundle directory is missing: {bundle_root}", file=sys.stderr)
        return 1
    if not (bundle_root / "install-carv.sh").is_file():
        print(f"Bundle is not installable: {bundle_root}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="carv-run-builder-") as temporary:
        payload = Path(temporary) / "carv-payload.tar.gz"
        with tarfile.open(payload, "w:gz") as archive:
            archive.add(bundle_root, arcname="carv")
        payload_sha256 = sha256_file(payload)

        header = f"""#!/usr/bin/env sh
set -eu

VERSION={version!r}
EXPECTED_SHA256={payload_sha256!r}
case "${{1:-}}" in
    --uninstall)
        UNINSTALLER="$HOME/.local/opt/carv/uninstall-carv.sh"
        if [ ! -x "$UNINSTALLER" ]; then
            printf '%s\n' "Carv is not installed for this user." >&2
            exit 1
        fi
        exec "$UNINSTALLER"
        ;;
    --help)
        printf '%s\n' "Install/update: bash $(basename -- "$0")"
        printf '%s\n' "Uninstall:      bash $(basename -- "$0") --uninstall"
        exit 0
        ;;
    "") ;;
    *)
        printf '%s\n' "Unknown installer option: $1" >&2
        exit 2
        ;;
esac
PAYLOAD_LINE=$(awk '/^__CARV_PAYLOAD_BELOW__$/ {{ print NR + 1; exit }}' "$0")
WORK_DIR=$(mktemp -d "${{TMPDIR:-/tmp}}/carv-installer.XXXXXX")
PAYLOAD="$WORK_DIR/carv-payload.tar.gz"
cleanup() {{ rm -rf "$WORK_DIR"; }}
trap cleanup EXIT HUP INT TERM

printf '%s\n' "Carv $VERSION installer"
tail -n +"$PAYLOAD_LINE" "$0" > "$PAYLOAD"
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256=$(sha256sum "$PAYLOAD" | awk '{{print $1}}')
else
    ACTUAL_SHA256=$(shasum -a 256 "$PAYLOAD" | awk '{{print $1}}')
fi
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    printf '%s\n' "Installer integrity check failed." >&2
    exit 1
fi
printf '%s\n' "Installer integrity check: OK"
tar -xzf "$PAYLOAD" -C "$WORK_DIR"
"$WORK_DIR/carv/install-carv.sh"
exit $?
__CARV_PAYLOAD_BELOW__
"""
        with output_path.open("wb") as output:
            output.write(header.encode("utf-8"))
            with payload.open("rb") as source:
                shutil.copyfileobj(source, output)
    output_path.chmod(0o755)
    print(f"Created Carv {version} installer: {output_path}")
    return 0


def write_deb_maintainer_script(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
fi
exit 0
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


def build_deb_package(
    bundle_root: Path,
    output_path: Path,
    version: str,
    architecture: str,
) -> int:
    bundle_root = bundle_root.resolve()
    output_path = output_path.resolve()
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version) is None:
        print(f"Invalid Carv version: {version}", file=sys.stderr)
        return 1
    if re.fullmatch(r"[a-z0-9][a-z0-9-]*", architecture) is None:
        print(f"Invalid Debian architecture: {architecture}", file=sys.stderr)
        return 1
    dpkg_deb = shutil.which("dpkg-deb")
    if not dpkg_deb:
        print("dpkg-deb is required to build the Ubuntu package.", file=sys.stderr)
        return 1
    if not bundle_root.is_dir() or not (bundle_root / "carv").is_file():
        print(f"Bundle is incomplete: {bundle_root}", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="carv-deb-builder-") as temporary:
        package_root = Path(temporary) / f"carv_{version}_{architecture}"
        install_root = package_root / "opt" / "carv"
        shutil.copytree(bundle_root, install_root, symlinks=True)
        for unnecessary in ("install-carv.sh", "uninstall-carv.sh"):
            (install_root / unnecessary).unlink(missing_ok=True)

        bin_dir = package_root / "usr" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "carv").symlink_to("/opt/carv/carv")
        (bin_dir / "carv-gui").symlink_to("/opt/carv/carv_gui")

        applications_dir = package_root / "usr" / "share" / "applications"
        applications_dir.mkdir(parents=True)
        write_desktop_entry(
            applications_dir / "carv.desktop",
            Path("/opt/carv/carv_gui"),
            Path("/opt/carv"),
            "Carv file recovery",
            "debian-package",
        )

        icon_path = (
            package_root
            / "usr"
            / "share"
            / "icons"
            / "hicolor"
            / "128x128"
            / "apps"
            / "carv.png"
        )
        icon_path.parent.mkdir(parents=True)
        shutil.copy2(install_root / "scripts" / "wrench_button_icon.png", icon_path)

        control_dir = package_root / "DEBIAN"
        control_dir.mkdir()
        (control_dir / "control").write_text(
            "\n".join(
                (
                    "Package: carv",
                    f"Version: {version}",
                    "Section: utils",
                    "Priority: optional",
                    f"Architecture: {architecture}",
                    "Maintainer: Carv pre-release",
                    "Depends: python3, libsqlite3-0",
                    "Recommends: python3-pyqt6",
                    "Description: metadata-aware file recovery",
                    " Carv recovers files through filesystem metadata and byte carving.",
                    "",
                )
            ),
            encoding="utf-8",
        )
        write_deb_maintainer_script(control_dir / "postinst")
        write_deb_maintainer_script(control_dir / "postrm")

        completed = subprocess.run(
            [dpkg_deb, "--root-owner-group", "--build", str(package_root), str(output_path)],
            check=False,
        )
        if completed.returncode != 0:
            print("dpkg-deb failed to build the Carv package.", file=sys.stderr)
            return completed.returncode
    print(f"Created clickable Carv {version} package: {output_path}")
    return 0


def user_paths() -> dict[str, Path]:
    data_home = Path(
        os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    ).expanduser()
    local_root = Path.home() / ".local"
    install_parent = local_root / "opt"
    install_dir = install_parent / "carv"
    return {
        "data_home": data_home,
        "install_parent": install_parent,
        "install_dir": install_dir,
        "applications_dir": data_home / "applications",
        "desktop_path": data_home / "applications" / "Carv.desktop",
        "icon_root": data_home / "icons" / "hicolor",
        "icon_path": data_home / "icons" / "hicolor" / "128x128" / "apps" / "carv.png",
        "bin_dir": local_root / "bin",
        "cli_link": local_root / "bin" / "carv",
        "gui_link": local_root / "bin" / "carv-gui",
    }


def required_source_files(source_root: Path) -> list[tuple[Path, Path]]:
    files: list[tuple[Path, Path]] = []
    files.extend((source_root / name, Path(name)) for name in ROOT_RUNTIME_FILES)
    files.extend(
        (source_root / "data" / name, Path("data") / name)
        for name in DATA_RUNTIME_FILES
    )
    files.extend(
        (source_root / "scripts" / name, Path("scripts") / name)
        for name in SCRIPT_RUNTIME_FILES
    )
    manpage = source_root / "carv.1"
    if manpage.is_file():
        files.append((manpage, Path("carv.1")))
    version_file = source_root / "VERSION"
    if version_file.is_file():
        files.append((version_file, Path("VERSION")))
    return files


def prepare_stage(source_root: Path, stage_dir: Path, existing_dir: Path) -> None:
    files = required_source_files(source_root)
    missing = [str(source) for source, _ in files if not source.is_file()]
    if missing:
        raise RuntimeError(
            "The Carv runtime package is incomplete; missing:\n  "
            + "\n  ".join(missing)
        )

    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True)
    for source, relative in files:
        destination = stage_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    saved_config = existing_dir / "carv_ui.ini"
    if saved_config.is_file():
        shutil.copy2(saved_config, stage_dir / "carv_ui.ini")

    for relative in (
        "carv",
        "carv_gui",
        "carv_gui_terminal",
        "install-carv.sh",
        "uninstall-carv.sh",
        "scripts/carv_gui_qt.py",
        "scripts/carv_gui_askpass.py",
        "scripts/manage_linux_user_install.py",
    ):
        (stage_dir / relative).chmod(0o755)


def install_command_link(link: Path, target: Path) -> None:
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        print(f"Kept existing command instead of replacing it: {link}")
        return
    temporary = link.with_name(f".{link.name}.carv-install-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    temporary.symlink_to(target)
    temporary.replace(link)


def remove_command_link(link: Path, expected_target: Path) -> None:
    if not link.is_symlink():
        return
    try:
        target = (link.parent / os.readlink(link)).resolve()
    except OSError:
        return
    if target == expected_target.resolve():
        link.unlink()


def install(source_root: Path) -> int:
    paths = user_paths()
    install_parent = paths["install_parent"]
    install_dir = paths["install_dir"]
    stage_dir = install_parent / f".carv-install-{os.getpid()}"
    backup_dir = install_parent / f".carv-backup-{os.getpid()}"
    activated_new_install = False
    source_root = source_root.resolve()
    if source_root == install_dir.resolve():
        print("Carv is already running from the installation directory.", file=sys.stderr)
        return 1

    install_parent.mkdir(parents=True, exist_ok=True)
    if install_dir.is_symlink():
        print(f"Refusing to replace symbolic-link installation: {install_dir}", file=sys.stderr)
        return 1
    try:
        prepare_stage(source_root, stage_dir, install_dir)
        if install_dir.exists():
            install_dir.rename(backup_dir)
        stage_dir.rename(install_dir)
        activated_new_install = True

        paths["applications_dir"].mkdir(parents=True, exist_ok=True)
        paths["icon_path"].parent.mkdir(parents=True, exist_ok=True)
        paths["bin_dir"].mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            install_dir / "scripts" / "wrench_button_icon.png",
            paths["icon_path"],
        )
        write_desktop_entry(
            paths["desktop_path"],
            install_dir / "carv_gui",
            install_dir,
            "Carv file recovery GUI",
            "user",
        )
        install_command_link(paths["cli_link"], install_dir / "carv")
        install_command_link(paths["gui_link"], install_dir / "carv_gui")
        refresh_desktop_caches(paths["applications_dir"], paths["icon_root"])
    except Exception as exc:
        if stage_dir.exists():
            shutil.rmtree(stage_dir)
        if activated_new_install and install_dir.exists():
            shutil.rmtree(install_dir)
        if backup_dir.exists():
            backup_dir.rename(install_dir)
        print(f"Carv installation failed: {exc}", file=sys.stderr)
        return 1

    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    version = "unknown version"
    try:
        version = (install_dir / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    print(f"Installed Carv {version} for {Path.home()}: {install_dir}")
    print(f"Application menu entry: {paths['desktop_path']}")
    print("Start Carv from Ubuntu's application menu.")
    if str(paths["bin_dir"]) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f"Optional: add {paths['bin_dir']} to PATH for carv and carv-gui commands.")
    return 0


def uninstall() -> int:
    paths = user_paths()
    install_dir = paths["install_dir"]
    expected_parent = (Path.home() / ".local" / "opt").resolve()
    if install_dir.parent.resolve() != expected_parent or install_dir.name != "carv":
        print("Refusing to remove an unexpected installation path.", file=sys.stderr)
        return 1

    remove_command_link(paths["cli_link"], install_dir / "carv")
    remove_command_link(paths["gui_link"], install_dir / "carv_gui")
    remove_user_entry = False
    try:
        remove_user_entry = (
            "X-Carv-InstallKind=user"
            in paths["desktop_path"].read_text(encoding="utf-8", errors="replace")
        )
    except FileNotFoundError:
        pass
    if remove_user_entry:
        for path in (paths["desktop_path"], paths["icon_path"]):
            try:
                path.unlink()
                print(f"Removed: {path}")
            except FileNotFoundError:
                pass
    if install_dir.exists():
        if install_dir.is_symlink():
            print(f"Refusing to remove symbolic-link installation: {install_dir}", file=sys.stderr)
            return 1
        shutil.rmtree(install_dir)
        print(f"Removed program files: {install_dir}")
    refresh_desktop_caches(paths["applications_dir"], paths["icon_root"])
    print("Recovery output and state directories were not touched.")
    return 0


def main(argv: list[str]) -> int:
    commands = {"install", "remove", "write-wrappers", "build-run", "build-deb"}
    if len(argv) < 2 or argv[1] not in commands:
        print(
            "usage: manage_linux_user_install.py "
            "install <package-root> | remove | write-wrappers <package-root> | "
            "build-run <bundle-root> <output.run> <version> | "
            "build-deb <bundle-root> <output.deb> <version> <architecture>",
            file=sys.stderr,
        )
        return 2
    if argv[1] == "remove":
        return uninstall()
    if argv[1] == "write-wrappers":
        if len(argv) != 3:
            print("write-wrappers requires <package-root>", file=sys.stderr)
            return 2
        return write_package_wrappers(Path(argv[2]).expanduser())
    if argv[1] == "build-run":
        if len(argv) != 5:
            print(
                "build-run requires <bundle-root> <output.run> <version>",
                file=sys.stderr,
            )
            return 2
        return build_run_installer(
            Path(argv[2]).expanduser(),
            Path(argv[3]).expanduser(),
            argv[4],
        )
    if argv[1] == "build-deb":
        if len(argv) != 6:
            print(
                "build-deb requires <bundle-root> <output.deb> <version> <architecture>",
                file=sys.stderr,
            )
            return 2
        return build_deb_package(
            Path(argv[2]).expanduser(),
            Path(argv[3]).expanduser(),
            argv[4],
            argv[5],
        )
    if len(argv) != 3:
        print("install requires <package-root>", file=sys.stderr)
        return 2
    return install(Path(argv[2]).expanduser())


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
