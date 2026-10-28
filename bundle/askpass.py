# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""PyInstaller entry point for the private OpenSSH askpass executable."""

from sovagrid_connect.askpass import main


if __name__ == "__main__":
    raise SystemExit(main())
