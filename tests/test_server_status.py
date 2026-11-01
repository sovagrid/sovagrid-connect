# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The first-install offer must never overwrite a partial or Agent-only host."""

from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sovagrid_connect.server_status import STATUS_COMMAND, STATUS_SCRIPT, parse_status, _MANAGED_VPN_SOURCE_CHECK


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


@unittest.skipUnless(os.name == "posix", "remote Linux descriptor semantics")
class AgentVpnStatusTests(unittest.TestCase):
    path = ServerStatusTests.path
    classify = ServerStatusTests.classify

    def setUp(self):
        ServerStatusTests.setUp(self)
        self.path('/opt/sovagrid-agent-installer/source-manifest.json').write_text('{}')
        self.path('/etc/systemd/system/sovagrid-agent.service').write_text('[Unit]\n')
        self.path('/var/lib/sovagrid-agent-enrollment').mkdir()
        source_names = ('LICENSE', 'NOTICE', 'ATTRIBUTION.md', 'deploy/install-amnezia-control.py',
            'deploy/install-wireguard-control.py', 'deploy/sovagrid-amnezia-provision',
            'sovagrid_vpn/__init__.py', 'sovagrid_vpn/amnezia_install.py',
            'sovagrid_vpn/amnezia_admin.py', 'sovagrid_vpn/amnezia_provision.py',
            'sovagrid_vpn/wireguard_install.py')
        source, package = {}, {}
        for name in source_names:
            raw = ('# source fixture ' + name + '\n').encode()
            self.path('/opt/sovagrid-src/sovagrid-vpn/' + name).write_bytes(raw)
            source[name] = hashlib.sha256(raw).hexdigest()
            if name.startswith('sovagrid_vpn/'):
                leaf = name.split('/')[1]
                self.path('/opt/sovagrid-vpn/sovagrid_vpn/' + leaf).write_bytes(raw)
                package[leaf] = source[name]
        self.receipt = {'protocol': 1, 'phase': 'active', 'source_manifest_sha256': 'a' * 64,
            'source_files': source, 'package_files': package, 'garbage_stage': None}
        self.state = self.path('/var/lib/sovagrid/vpn-source/state.json')
        self.state.parent.chmod(0o700)
        self.write_receipt()

    def write_receipt(self):
        self.state.write_text(json.dumps(self.receipt, sort_keys=True, separators=(',', ':')))
        self.state.chmod(0o600)

    def test_verified_extension_and_publisher_metadata_remain_agent_only(self):
        self.assertEqual(self.classify(), 'SG_STATUS_V1:agent_only')
        status = self.path('/var/lib/sovagrid/vpn/status.json')
        status.write_text('{"schema_version":1,"collected_at":1}')
        status.chmod(0o640)
        self.path('/var/lib/sovagrid/vpn/.vpn-status-abcdefgh').write_text('{')
        self.path('/opt/sovagrid-vpn/sovagrid_vpn/__pycache__/amnezia_admin.cpython-312.pyc').write_bytes(b'cache')
        self.assertEqual(self.classify(), 'SG_STATUS_V1:agent_only')
        self.assertFalse(parse_status(['SG_STATUS_V1:agent_only'], returncode=0).safe_first_install)

    def test_source_and_package_drift_are_conflicts(self):
        for path in ('/opt/sovagrid-src/sovagrid-vpn/sovagrid_vpn/amnezia_admin.py',
                     '/opt/sovagrid-vpn/sovagrid_vpn/amnezia_admin.py'):
            target = self.path(path)
            raw = target.read_bytes()
            target.write_bytes(b'tampered')
            self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
            target.write_bytes(raw)

    def test_unknown_namespace_entries_and_partial_hub_are_conflicts(self):
        for name in ('/opt/sovagrid-src/foreign', '/opt/sovagrid-vpn/foreign',
                     '/var/lib/sovagrid/foreign', '/var/lib/sovagrid/vpn-source/foreign',
                     '/var/lib/sovagrid/vpn/foreign', '/etc/sovagrid-hub/foreign'):
            path = self.path(name)
            path.write_text('leave me')
            self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
            path.unlink()
            if path.parent.name == 'sovagrid-hub': path.parent.rmdir()

    def test_receipt_types_phase_and_package_projection_are_strict(self):
        for key, value in (('protocol', True), ('phase', 'pending'),
                           ('source_manifest_sha256', 'bad'), ('package_files', {'foreign.py': 'b' * 64})):
            previous = self.receipt[key]
            self.receipt[key] = value
            self.write_receipt()
            self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
            self.receipt[key] = previous
        self.write_receipt()

    def test_symlinks_hardlinks_writable_source_and_fifo_are_refused(self):
        path = self.path('/opt/sovagrid-vpn/sovagrid_vpn/amnezia_admin.py')
        raw = path.read_bytes()
        path.chmod(0o666)
        self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
        path.chmod(0o644)
        alias = self.root / 'alias'
        os.link(path, alias)
        self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
        alias.unlink()
        path.unlink()
        path.symlink_to(self.root / 'outside')
        self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
        path.unlink()
        os.mkfifo(path)
        self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')
        path.unlink()
        path.write_bytes(raw)

    def test_mutable_snapshot_requires_integer_schema(self):
        self.path('/var/lib/sovagrid/vpn/status.json').write_text('{"schema_version":true,"collected_at":1}')
        self.assertEqual(self.classify(), 'SG_STATUS_V1:conflict')

    def test_atomic_snapshot_replacement_reads_new_bytes_and_rejects_bad_replacement(self):
        namespace = {}
        exec(_MANAGED_VPN_SOURCE_CHECK, namespace)
        predicate = namespace['managed_vpn_source']
        status = self.path('/var/lib/sovagrid/vpn/status.json')
        for schema, expected in ((1, True), (True, False)):
            status.write_text('{"schema_version":1,"collected_at":1}')
            previous_inode = status.stat().st_ino
            original = os.read
            replaced = False
            read_new = False

            def replacing_read(fd, size):
                nonlocal replaced, read_new
                info = os.fstat(fd)
                result = original(fd, size)
                if info.st_ino == previous_inode and not replaced:
                    temporary = status.with_name('.vpn-status-abcdefgh')
                    temporary.write_text(json.dumps({'schema_version': schema, 'collected_at': 2}))
                    os.replace(temporary, status)
                    replaced = True
                elif replaced and info.st_ino == status.stat().st_ino:
                    read_new = True
                return result

            with patch('os.read', replacing_read):
                self.assertEqual(predicate(self.root, owner=os.getuid()), expected)
            self.assertTrue(replaced)
            self.assertTrue(read_new)

    def test_predicate_does_not_execute_the_managed_source(self):
        sentinel = self.root / 'executed'
        name = 'sovagrid_vpn/amnezia_admin.py'
        raw = ('raise RuntimeError(' + repr(str(sentinel)) + ')\n').encode()
        self.path('/opt/sovagrid-src/sovagrid-vpn/' + name).write_bytes(raw)
        self.path('/opt/sovagrid-vpn/' + name).write_bytes(raw)
        self.receipt['source_files'][name] = self.receipt['package_files']['amnezia_admin.py'] = hashlib.sha256(raw).hexdigest()
        self.write_receipt()
        self.assertEqual(self.classify(), 'SG_STATUS_V1:agent_only')
        self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
