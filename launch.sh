#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
set -eu
cd "$(dirname "$0")"
if python3 -c 'import tkinter' >/dev/null 2>&1; then
  exec python3 -m sovagrid_connect gui
fi
if [ -x /usr/bin/python3 ] && /usr/bin/python3 -c 'import sys, tkinter; assert sys.version_info >= (3, 9)' >/dev/null 2>&1; then
  exec /usr/bin/python3 -m sovagrid_connect gui
fi
echo "Install a Python 3.9+ build with Tkinter to use the graphical launcher." >&2
exit 2
