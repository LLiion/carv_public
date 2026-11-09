#!/usr/bin/env python3
"""Register or remove a user-local desktop launcher for this source tree."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys


DESKTOP_FILENAME = "Carv.desktop"
ICON_NAME = "carv.png"


def desktop_exec_quote(value: Path) -> str:
    text = str(value)
    for original, replacement in (
        ("\\", "\\\\"),
        ('"', '\\"'),
        ("`", "\\`"),
        ("$", "\\$"),
    ):
        text = text.replace(original, replacement)
    return f'"{text}"'


def refresh_desktop_caches(applications_dir: Path, icon_root: Path) -> None:
    commands = (
        ("update-desktop-database", [str(applications_dir)]),
        ("xdg-desktop-menu", ["forceupdate"]),
        ("xdg-icon-resource", ["forceupdate", "--theme", "hicolor"]),
    )
    for executable, arguments in commands:
        resolved = shutil.which(executable)
        if not resolved:
            continue
        subprocess.run(
            [resolved, *arguments],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    index_theme = icon_root / "index.theme"
    cache_tool = shutil.which("gtk-update-icon-cache")
    if cache_tool and index_theme.is_file():
        subprocess.run(
            [cache_tool, "-f", "-t", str(icon_root)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def write_desktop_entry(
    desktop_path: Path,
    executable: Path,
    working_directory: Path,
    comment: str,
    install_kind: str,
) -> None:
    desktop_path.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                "Name=Carv",
                f"Comment={comment}",
                f"Exec={desktop_exec_quote(executable)}",
                f"Path={working_directory}",
                "Icon=carv",
                "Terminal=false",
                "Categories=Utility;System;",
                "StartupNotify=true",
                "StartupWMClass=Carv",
                f"X-Carv-InstallKind={install_kind}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    desktop_path.chmod(0o755)


def install(project_root: Path) -> int:
    launcher = project_root / "carv_gui"
    icon_source = project_root / "scripts" / "wrench_button_icon.png"
    if not launcher.is_file():
        print(f"Carv GUI launcher is missing: {launcher}", file=sys.stderr)
        return 1
    if not icon_source.is_file():
        print(f"Carv wrench icon is missing: {icon_source}", file=sys.stderr)
        return 1

    data_home = Path(
        os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    ).expanduser()
    applications_dir = data_home / "applications"
    icon_root = data_home / "icons" / "hicolor"
    icon_dir = icon_root / "128x128" / "apps"
    desktop_path = applications_dir / DESKTOP_FILENAME
    icon_path = icon_dir / ICON_NAME
    applications_dir.mkdir(parents=True, exist_ok=True)
    icon_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(icon_source, icon_path)
    write_desktop_entry(
        desktop_path,
        launcher,
        project_root,
        "Carv file recovery GUI (development tree)",
        "development",
    )
    refresh_desktop_caches(applications_dir, icon_root)
    print(f"Installed development launcher: {desktop_path}")
    print(f"Installed wrench icon: {icon_path}")
    print("Start Carv from Ubuntu's application menu once to verify the dock icon.")
    return 0


def remove() -> int:
    data_home = Path(
        os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    ).expanduser()
    applications_dir = data_home / "applications"
    icon_root = data_home / "icons" / "hicolor"
    desktop_path = applications_dir / DESKTOP_FILENAME
    icon_path = icon_root / "128x128" / "apps" / ICON_NAME
    remove_development_entry = False
    try:
        remove_development_entry = (
            "X-Carv-InstallKind=development"
            in desktop_path.read_text(encoding="utf-8", errors="replace")
        )
    except FileNotFoundError:
        pass
    if remove_development_entry:
        for path in (desktop_path, icon_path):
            try:
                path.unlink()
                print(f"Removed: {path}")
            except FileNotFoundError:
                pass
    elif desktop_path.exists():
        print(f"Kept non-development desktop entry: {desktop_path}")
    refresh_desktop_caches(applications_dir, icon_root)
    return 0


def main(argv: list[str]) -> int:
    if len(argv) not in (2, 3) or argv[1] not in {"install", "remove"}:
        print(
            "usage: manage_linux_desktop_dev.py install <project-root> | remove",
            file=sys.stderr,
        )
        return 2
    if argv[1] == "remove":
        return remove()
    if len(argv) != 3:
        print("install requires <project-root>", file=sys.stderr)
        return 2
    return install(Path(argv[2]).expanduser().resolve())


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
