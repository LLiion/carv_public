#!/usr/bin/env sh
set -eu

PACKAGE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$PACKAGE_DIR/scripts/manage_linux_user_install.py" install "$PACKAGE_DIR"
