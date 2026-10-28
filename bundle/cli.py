# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""PyInstaller entry point for the command line connector."""

from sovagrid_connect.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
