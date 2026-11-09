#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "hfsplus_fixture.py"


def main() -> int:
    result = subprocess.run(
        [sys.executable, str(TOOL), "self-test"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    if "self_test\tok" not in result.stdout:
        sys.stderr.write(f"Unexpected fixture test output:\n{result.stdout}")
        return 1
    print("HFS+ fixture round-trip checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
