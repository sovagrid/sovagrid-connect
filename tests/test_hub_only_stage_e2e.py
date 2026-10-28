# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable Ubuntu root fixture for the exact SSH stage and verifier scripts."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from sovagrid_connect.hub_only_update import _STAGE_SCRIPT, _VERIFY_CANDIDATE_SCRIPT, _manifest
from test_installer import make_bundle


@unittest.skipUnless(getattr(os, 'geteuid', lambda: -1)() == 0 and
                     os.environ.get('SOVAGRID_HUB_STAGE_E2E') == '1',
                     'disposable Ubuntu root fixture only')
class HubOnlyStageE2E(unittest.TestCase):
    def test_exact_archive_and_git_source_verified_before_helper_can_run(self):
        candidate_root = Path('/opt/sovagrid-candidates')
        if candidate_root.exists() or candidate_root.is_symlink():
            self.skipTest('candidate root already exists; fixture will not change it')
        with tempfile.TemporaryDirectory(prefix='sovagrid-hub-stage-e2e-') as directory:
            bundle = Path(directory) / 'bundle.tar.gz'
            make_bundle(bundle, hub_only_update=True)
            archive_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
            manifest_sha = _manifest(bundle)
            try:
                with bundle.open('rb') as source:
                    staged = subprocess.run(['bash', '-x', '-c', _STAGE_SCRIPT, 'sovagrid', archive_sha],
                                            stdin=source, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True, timeout=90)
                self.assertEqual(staged.returncode, 0,
                                 staged.stdout[-600:] + '\n' + staged.stderr[-3500:])
                self.assertIn('SG_HUB_ONLY_STAGE:DONE', staged.stdout.splitlines())
                lock = candidate_root / '.lock'
                self.assertEqual(lock.stat().st_mode & 0o777, 0o600)
                verifier = ['python3', '-I', '-c', _VERIFY_CANDIDATE_SCRIPT,
                            archive_sha, manifest_sha]
                checked = subprocess.run(verifier, capture_output=True, text=True, timeout=90)
                self.assertEqual(checked.returncode, 0, checked.stderr[-600:])
                record = json.loads(checked.stdout)
                self.assertEqual(record['archive_sha256'], archive_sha)
                self.assertEqual(record['manifest_sha256'], manifest_sha)
                self.assertEqual(set(record['commits']), {'sovagrid-blueprint', 'sovagrid-hub',
                                                          'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'})
                lock.chmod(0o666)
                with bundle.open('rb') as source:
                    unsafe = subprocess.run(['bash', '-c', _STAGE_SCRIPT, 'sovagrid', archive_sha],
                                            stdin=source, capture_output=True, text=True, timeout=90)
                self.assertNotEqual(unsafe.returncode, 0)
                self.assertIn('SG_HUB_ONLY_REFUSE:STAGE', unsafe.stdout.splitlines())
                lock.chmod(0o600)
                source_file = candidate_root / archive_sha / 'source/sovagrid-blueprint/run.sh'
                source_file.write_bytes(source_file.read_bytes() + b'tampered\n')
                rejected = subprocess.run(verifier, capture_output=True, text=True, timeout=90)
                self.assertNotEqual(rejected.returncode, 0)
            finally:
                if candidate_root.is_dir() and not candidate_root.is_symlink():
                    shutil.rmtree(candidate_root)


if __name__ == '__main__':
    unittest.main()
