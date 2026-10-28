# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""The staged Hub-only helper is never run before exact remote verification."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.hub_only_update import (
    HubOnlyUpdateController, _INSTALLED_SCRIPT, _STAGE_SCRIPT, _VERIFY_CANDIDATE_SCRIPT,
    _TIMER_HELPER_CHECK, _manifest,
)
from sovagrid_connect.installer import COMPONENTS, InstallError
from test_installer import make_bundle


SERVER_ID = 'c432d4dc-3cf2-4929-947c-8869fb85bff9'
OLD = 'b' * 64
OLD_COMMITS = {name: 'b' * 40 for name in COMPONENTS}
NEW_COMMITS = {name: 'a' * 40 for name in COMPONENTS}


class Transport:
    def __init__(self, options, archive_sha, manifest_sha, *, native=False):
        self.options = options.validated()
        self._privileged = '' if self.options.user == 'root' else 'sudo -n -- '
        self.archive_sha, self.manifest_sha = archive_sha, manifest_sha
        self.current_manifest = OLD
        self.current_commits = dict(OLD_COMMITS)
        self.native = native
        self.calls = []
        self.root_checks = 0
        self.remote_commits = dict(NEW_COMMITS)
        self.apply_failure = None

    def _verify_root_access(self):
        self.root_checks += 1

    def _execute(self, command, *, source=None, timeout=45, **_kwargs):
        self.calls.append((command, source, timeout))
        assert command.startswith(self._privileged)
        body = command[len(self._privileged):]
        if body == '/usr/bin/python3 -I -c ' + shlex.quote(_INSTALLED_SCRIPT):
            state = {'protocol': 1, 'phase': 'activated', 'external_agent_preserved': True,
                     'baseline_sha256': 'd' * 64, 'pinned_manifest_sha256': self.current_manifest,
                     'source_manifest_sha256': self.current_manifest,
                     'local_server_id': SERVER_ID, 'reason_code': None}
            return 0, json.dumps({'protocol': 1, 'manifest_sha256': self.current_manifest,
                                  'state': state, 'commits': self.current_commits,
                                  'native_updater': self.native}).encode()
        if body.startswith('/usr/bin/python3 -I -c ' + shlex.quote(_VERIFY_CANDIDATE_SCRIPT)):
            return 0, json.dumps({'protocol': 1, 'archive_sha256': self.archive_sha,
                                  'manifest_sha256': self.manifest_sha,
                                  'commits': self.remote_commits}).encode()
        if body == '/usr/bin/python3 -I -c ' + shlex.quote(_TIMER_HELPER_CHECK):
            return 0, (b'SG_HUB_ONLY_TIMER:AVAILABLE\n' if self.native else
                       b'SG_HUB_ONLY_TIMER:ABSENT\n')
        if body.startswith('bash -c ' + shlex.quote(_STAGE_SCRIPT)):
            assert source is not None and source.is_file()
            assert hashlib.sha256(source.read_bytes()).hexdigest() == self.archive_sha
            return 0, b'SG_HUB_ONLY_STAGE:TRANSFER\nSG_HUB_ONLY_STAGE:VERIFY\nSG_HUB_ONLY_STAGE:DONE\n'
        if ' preflight ' in body and '/hub_only_update.py ' in body:
            return 0, b'SG_HUB_ONLY_CANDIDATE:OK\n'
        if ' apply ' in body and '/hub_only_update.py ' in body:
            if self.apply_failure is not None:
                return 40, self.apply_failure
            self.current_manifest = self.manifest_sha
            self.current_commits = dict(NEW_COMMITS)
            self.native = True
            return 0, b'SG_HUB_ONLY_STAGE:INSTALLING\nSG_HUB_ONLY_STAGE:DONE\n'
        if body.endswith('/hub_only_auto_update.py status'):
            return 0, b'{"policy":null,"last":null}'
        if 'hub_only_auto_update.py arm ' in body:
            return 0, b'SG_HUB_ONLY_AUTO_UPDATE:ARMED\n'
        if body.endswith('/hub_only_auto_update.py disarm'):
            return 0, b'SG_HUB_ONLY_AUTO_UPDATE:DISABLED\n'
        raise AssertionError('unexpected SSH command: ' + body[-160:])


class HubOnlyUpdateTests(unittest.TestCase):
    def fixture(self, directory, *, user='root', native=False):
        bundle = Path(directory) / 'server.tar.gz'
        make_bundle(bundle, hub_only_update=True)
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        manifest = _manifest(bundle)
        options = ConnectionOptions(host='target.example.org', user=user,
                                    jump_host='relay.example.org', jump_user='relay')
        transport = Transport(options, digest, manifest, native=native)
        controller = HubOnlyUpdateController(options, approved_archive_sha256=digest,
                                             transport=transport)
        return bundle, controller, transport

    def test_sudo_bridge_checks_exact_archive_and_git_bytes_before_staged_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory, user='exampleuser')
            preview = controller.preview(bundle)
            self.assertEqual(preview.installed.manifest_sha256, OLD)
            prepared = controller.stage(bundle, preview)
            commands = [command for command, _source, _timeout in transport.calls]
            self.assertTrue(all(command.startswith('sudo -n -- ') for command in commands))
            stage = next(index for index, command in enumerate(commands) if 'SG_HUB_ONLY_STAGE:DONE' in command)
            verify = next(index for index, command in enumerate(commands)
                          if shlex.quote(_VERIFY_CANDIDATE_SCRIPT) in command)
            helper = next(index for index, command in enumerate(commands) if '/hub_only_update.py preflight ' in command)
            self.assertLess(stage, verify)
            self.assertLess(verify, helper)
            installed = controller.apply(prepared)
            self.assertEqual(installed.manifest_sha256, preview.manifest_sha256)
            self.assertEqual(installed.promotion.local_server_id, SERVER_ID)
            self.assertTrue(installed.native_updater)
            self.assertGreaterEqual(transport.root_checks, 4)

    def test_remote_git_mismatch_and_installed_drift_refuse_helper_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory)
            preview = controller.preview(bundle)
            transport.remote_commits['sovagrid-blueprint'] = 'c' * 40
            with self.assertRaisesRegex(InstallError, 'версии Git'):
                controller.stage(bundle, preview)
            self.assertFalse(any('/hub_only_update.py preflight ' in command
                                 for command, _source, _timeout in transport.calls))
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory)
            preview = controller.preview(bundle)
            transport.current_manifest = 'c' * 64
            with self.assertRaisesRegex(InstallError, 'изменились'):
                controller.stage(bundle, preview)
            self.assertFalse(any('SG_HUB_ONLY_STAGE:DONE' in command
                                 for command, _source, _timeout in transport.calls))

    def test_root_timer_arm_status_disarm_uses_one_staged_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory, native=True)
            preview = controller.preview(bundle)
            prepared = controller.stage(bundle, preview)
            self.assertFalse(controller.timer_status().armed)
            self.assertEqual(controller.arm(prepared), 'SG_HUB_ONLY_AUTO_UPDATE:ARMED')
            controller.disarm()
            commands = [command for command, _source, _timeout in transport.calls]
            self.assertTrue(any(command.endswith(' arm ' + preview.archive_sha256 + ' ' + OLD)
                                for command in commands))
            self.assertTrue(any(command.endswith('hub_only_auto_update.py disarm') for command in commands))

    def test_rollback_result_is_explicit_and_not_reported_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory)
            prepared = controller.stage(bundle, controller.preview(bundle))
            transport.apply_failure = b'SG_HUB_ONLY_STAGE:ROLLBACK\nSG_HUB_ONLY_STAGE:ROLLED_BACK\n'
            with self.assertRaisesRegex(InstallError, 'восстановлен'):
                controller.apply(prepared)
            transport.apply_failure = b'SG_HUB_ONLY_STAGE:ROLLBACK_FAILED\n'
            with self.assertRaisesRegex(InstallError, 'откат не удался'):
                controller.apply(prepared)

    def test_timer_disarm_remains_available_when_hub_inspection_is_unhealthy(self):
        with tempfile.TemporaryDirectory() as directory:
            _bundle, controller, transport = self.fixture(directory, native=True)
            transport.current_manifest = 'unhealthy'
            self.assertFalse(controller.timer_status().armed)
            controller.disarm()
            self.assertFalse(any(shlex.quote(_INSTALLED_SCRIPT) in command
                                 for command, _source, _timeout in transport.calls))

    def test_unapproved_or_changed_bundle_refused_before_remote_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle, controller, transport = self.fixture(directory)
            controller.approved_archive_sha256 = '0' * 64
            with self.assertRaises(InstallError):
                controller.preview(bundle)
            self.assertEqual(transport.calls, [])
            controller.approved_archive_sha256 = transport.archive_sha
            preview = controller.preview(bundle)
            bundle.write_bytes(bundle.read_bytes() + b'tampered')
            with self.assertRaises(InstallError):
                controller.stage(bundle, preview)
            self.assertFalse(any('SG_HUB_ONLY_STAGE:DONE' in command
                                 for command, _source, _timeout in transport.calls))

    def test_fixed_scripts_are_parseable_without_starting_services(self):
        compile(_INSTALLED_SCRIPT, 'installed_state_probe', 'exec')
        compile(_VERIFY_CANDIDATE_SCRIPT, 'candidate_verifier', 'exec')
        compile(_TIMER_HELPER_CHECK, 'timer_helper_probe', 'exec')
        if os.name != 'nt' and shutil.which('bash'):
            result = subprocess.run(['bash', '-n', '-c', _STAGE_SCRIPT], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
