#!/usr/bin/env python3
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys


def _env(name: str, default: str) -> str:
    value = os.environ.get(name, "").strip()
    return value or default


TITLE = _env("CARV_ASKPASS_TITLE", "Carv")
PROMPT = _env("CARV_ASKPASS_PROMPT", "Carv needs your password.")
OK_LABEL = _env("CARV_ASKPASS_OK", "Continue")
CANCEL_LABEL = _env("CARV_ASKPASS_CANCEL", "Cancel")


def _run(args):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=55,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _macos_password() -> int:
    script = [
        "osascript",
        "-e",
        (
            f'display dialog "{PROMPT.replace(chr(34), r"\\\"")}" '
            f'default answer "" with hidden answer '
            f'buttons {{"{CANCEL_LABEL.replace(chr(34), r"\\\"")}", "{OK_LABEL.replace(chr(34), r"\\\"")}"}} '
            f'default button "{OK_LABEL.replace(chr(34), r"\\\"")}" '
            f'with title "{TITLE.replace(chr(34), r"\\\"")}"'
        ),
        "-e",
        "text returned of result",
    ]
    result = _run(script)
    if result is None or result.returncode != 0:
        return 1
    sys.stdout.write(result.stdout.strip())
    return 0


def _linux_password() -> int:
    if shutil.which("zenity"):
        result = _run(
            [
                "zenity",
                "--password",
                f"--title={TITLE}",
                f"--text={PROMPT}",
            ]
        )
        if result is None or result.returncode != 0:
            return 1
        sys.stdout.write((result.stdout or "").strip())
        return 0

    if shutil.which("kdialog"):
        result = _run(
            [
                "kdialog",
                "--title",
                TITLE,
                "--password",
                PROMPT,
            ]
        )
        if result is None or result.returncode != 0:
            return 1
        sys.stdout.write((result.stdout or "").strip())
        return 0

    return 1


def main() -> int:
    system = platform.system()
    if system == "Darwin":
        return _macos_password()
    if system == "Linux":
        return _linux_password()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
