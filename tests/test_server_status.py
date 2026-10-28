# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The first-install offer must never overwrite a partial or Agent-only host."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from sovagrid_connect.server_status import STATUS_COMMAND, STATUS_SCRIPT, parse_status


class ServerStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text("ID=ubuntu\n", encoding="utf-8")

    def path(self, name: str) -> Path:
        target = self.root / name.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def classify(self) -> str:
        result = subprocess.run(
            [sys.executable, "-", str(self.root)], input=STATUS_SCRIPT,
            text=True, capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        return result.stdout.strip()

    def test_only_empty_ubuntu_is_installable(self) -> None:
        self.assertEqual(self.classify(), "SG_STATUS_V1:missing")
        status = parse_status(["SG_STATUS_V1:missing"], returncode=0)
        self.assertTrue(status.safe_first_install)
        self.path("/opt/sovagrid-agent").mkdir()
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")

    def test_managed_needs_both_source_and_install_marker(self) -> None:
        self.path("/opt/sovagrid-src/sovagrid-bundle.json").write_text("{}")
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")
        self.path("/var/lib/sovagrid/.managed-by-run-sh").write_text("1")
        self.assertEqual(self.classify(), "SG_STATUS_V1:managed")

    def test_agent_only_cannot_be_treated_as_empty(self) -> None:
        self.path("/opt/sovagrid-agent-installer/source-manifest.json").write_text("{}")
        self.path("/etc/systemd/system/sovagrid-agent.service").write_text("[Unit]\n")
        self.path("/var/lib/sovagrid-agent-enrollment").mkdir()
        self.assertEqual(self.classify(), "SG_STATUS_V1:agent_only")
        self.path("/opt/sovagrid-src").mkdir()
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")

    def test_symlink_and_stray_unit_block_auto_install(self) -> None:
        self.path("/opt").mkdir(exist_ok=True)
        self.path("/opt/sovagrid-src").symlink_to("/tmp/foreign")
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")
        self.path("/opt/sovagrid-src").unlink()
        self.path("/etc/systemd/system/sovagrid-other.service").write_text("[Unit]\n")
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")

    def test_mobile_install_transaction_blocks_desktop_first_install(self) -> None:
        self.path("/var/lib/sovagrid-first-install").mkdir()
        self.assertEqual(self.classify(), "SG_STATUS_V1:conflict")

    def test_unsupported_and_malformed_responses_never_install(self) -> None:
        (self.root / "etc/os-release").write_text("ID=debian\n", encoding="utf-8")
        self.assertEqual(self.classify(), "SG_STATUS_V1:unsupported")
        for markers, code in (([], 0), (["SG_STATUS_V1:missing"] * 2, 0),
                              (["SG_STATUS_V1:missing"], 1), (["SG_STATUS_V1:invented"], 0)):
            self.assertFalse(parse_status(markers, returncode=code).safe_first_install)

    def test_remote_probe_requires_root_or_passwordless_sudo(self) -> None:
        self.assertIn("sudo -n true", STATUS_COMMAND)
        self.assertIn("SG_STATUS_V1:unknown", STATUS_COMMAND)
        self.assertNotIn("curl", STATUS_COMMAND)


if __name__ == "__main__":
    unittest.main()
