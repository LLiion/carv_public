#!/usr/bin/env python3
"""Exercise the user-local Ubuntu installer without touching the real home."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANAGER = PROJECT_ROOT / "scripts" / "manage_linux_user_install.py"


with tempfile.TemporaryDirectory(prefix="carv-user-install-") as temporary:
    root = Path(temporary)
    home = root / "home"
    data_home = home / ".local" / "share"
    output_dir = home / "recovery-output"
    home.mkdir()
    output_dir.mkdir()
    evidence = output_dir / "must-survive.txt"
    evidence.write_text("recovery data\n", encoding="utf-8")
    environment = dict(os.environ)
    environment.update({"HOME": str(home), "XDG_DATA_HOME": str(data_home)})

    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(MANAGER), *arguments],
            cwd=PROJECT_ROOT,
            env=environment,
            check=True,
            text=True,
            capture_output=True,
        )

    package = root / "package"
    run("write-wrappers", str(package))
    assert (package / "install-carv.sh").stat().st_mode & 0o111
    assert (package / "uninstall-carv.sh").stat().st_mode & 0o111
    assert "manage_linux_user_install.py" in (
        package / "install-carv.sh"
    ).read_text(encoding="utf-8")

    run("install", str(PROJECT_ROOT))
    install_dir = home / ".local" / "opt" / "carv"
    desktop = data_home / "applications" / "Carv.desktop"
    icon = data_home / "icons" / "hicolor" / "128x128" / "apps" / "carv.png"
    assert (install_dir / "carv").is_file()
    assert (install_dir / "carv_gui").is_file()
    assert (install_dir / "scripts" / "carv_title_logo.png").is_file()
    assert (install_dir / "scripts" / "wrench_button_icon.png").is_file()
    assert desktop.is_file()
    assert f'Exec="{install_dir / "carv_gui"}"' in desktop.read_text(encoding="utf-8")
    assert "Icon=carv" in desktop.read_text(encoding="utf-8")
    assert "X-Carv-InstallKind=user" in desktop.read_text(encoding="utf-8")
    assert icon.read_bytes() == (PROJECT_ROOT / "scripts" / "wrench_button_icon.png").read_bytes()
    assert (home / ".local" / "bin" / "carv").is_symlink()
    assert (home / ".local" / "bin" / "carv-gui").is_symlink()

    saved_config = install_dir / "carv_ui.ini"
    saved_config.write_text("[gui]\ndefault_out=/kept/across/update\n", encoding="utf-8")
    run("install", str(PROJECT_ROOT))
    assert "default_out=/kept/across/update" in saved_config.read_text(encoding="utf-8")

    result = run("remove")
    assert "Recovery output and state directories were not touched." in result.stdout
    assert not install_dir.exists()
    assert not desktop.exists()
    assert not icon.exists()
    assert not (home / ".local" / "bin" / "carv").exists()
    assert not (home / ".local" / "bin" / "carv-gui").exists()
    assert evidence.read_text(encoding="utf-8") == "recovery data\n"

print("Linux user installer checks passed")
