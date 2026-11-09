#!/usr/bin/env python3
"""Write a relocatable Linux .desktop launcher for a PyInstaller Carv folder."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: write_linux_desktop_launcher.py <bundle-dir> <executable-name>", file=sys.stderr)
        return 2

    bundle_dir = Path(argv[1])
    executable_name = argv[2]
    desktop_path = bundle_dir / f"{executable_name}.desktop"

    # %k expands to the desktop file's own path in common Linux desktop shells.
    # The shell wrapper keeps the launcher relocatable after extraction.
    desktop_path.write_text(
        "\n".join(
            [
                "[Desktop Entry]",
                "Type=Application",
                f"Name={executable_name}",
                "Comment=Carv file recovery GUI",
                "Icon=carv",
                "StartupWMClass=Carv",
                (
                    "Exec=sh -c 'launcher=\"$1\"; case \"$launcher\" in file://*) "
                    "launcher=\"${launcher#file://}\";; esac; dir=$(dirname \"$(readlink -f \"$launcher\")\"); "
                    f"exec \"$dir/{executable_name}\"' carv-launcher %k"
                ),
                "Terminal=false",
                "Categories=Utility;System;",
                "",
            ]
        ),
        encoding="utf-8",
    )
    os.chmod(desktop_path, 0o755)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
