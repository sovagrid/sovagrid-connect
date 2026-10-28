# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""PyInstaller entry point for the graphical connector.

Keep argument parsing ahead of the Tk import so a packaged --help smoke test
also works on a Linux CI runner without a display server.
"""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="SovaGrid-Connect-GUI",
        description="Launch the SovaGrid Connect desktop window.",
    )
    parser.add_argument("--legal-self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.legal_self_test:
        import json
        from sovagrid_connect import __version__
        from sovagrid_connect.legal import document, third_party_document, third_party_documents
        assert "GNU AFFERO GENERAL PUBLIC LICENSE" in document("LICENSE")
        assert "Jigokuraku01" in document("ATTRIBUTION.md")
        assert "CPython-3.13.16-LICENSE" in third_party_documents()
        assert "PyInstaller-6.22.3-COPYING.txt" in third_party_documents()
        assert "CPython 3.13.16" in third_party_document("INDEX.md")
        assert '"static_notices_sha256"' in third_party_document("runtime.json")
        assert json.loads(third_party_document("runtime.json"))["sovagrid_connect"] == __version__
        if sys.platform.startswith("linux"):
            assert "ubuntu/MANIFEST.json" in third_party_documents()
            assert '"packages"' in third_party_document("ubuntu/MANIFEST.json")
        elif sys.platform == "win32":
            assert "windows-runtime.json" in third_party_documents()
            assert "VCRUNTIME140.dll" in third_party_document("windows-runtime.json")
        return 0

    from sovagrid_connect.gui import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
