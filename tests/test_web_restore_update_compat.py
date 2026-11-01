# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""The embedded updater preserves the Web restore recovery contract."""
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_remote_update import updater


class WebRestoreCandidateCompatibility(unittest.TestCase):
    def test_present_restore_state_requires_the_marker_and_complete_fixed_closure(self):
        code = updater()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            code.update(ROOT=root, PUBLIC_OWNER=os.getuid(), web_agent_managed=lambda: False,
                backup_broker_enabled=lambda: False, ssh_gateway_managed=lambda: False,
                managed_routing_enabled=lambda: False)
            source = root / "candidate"
            script = source / "sovagrid-blueprint/run.sh"
            script.parent.mkdir(parents=True); script.write_text("#!/bin/bash\n")
            check = lambda: code["candidate_features_compatible"](source, [])
            check()  # An old installation with no restore state may upgrade.
            namespace = root / code["WEB_RESTORE_DIR"].lstrip("/")
            namespace.mkdir(parents=True, mode=0o700)
            original = Path.lstat
            bad_group = []
            def root_group(path):
                info = original(path)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid, st_gid=1 if path in bad_group else 0,
                    st_nlink=info.st_nlink, st_size=info.st_size)
            with patch.object(Path, "lstat", root_group):
                with self.assertRaisesRegex(code["UpdateFailure"], "COMPAT"): check()
                script.write_text("#!/bin/bash\n# SOVAGRID_WEB_RESTORE_V1\n")
                for name in code["WEB_RESTORE_REQUIRED"]:
                    path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text("fixture\n")
                check()
                for name in code["WEB_RESTORE_REQUIRED"]:
                    path = source / name; path.unlink()
                    with self.subTest(name=name), self.assertRaisesRegex(code["UpdateFailure"], "COMPAT"): check()
                    path.write_text("fixture\n")
                bad_group.append(namespace)
                with self.assertRaisesRegex(code["UpdateFailure"], "STATE"): check()
                bad_group.clear()
                namespace.chmod(0o755)
                with self.assertRaisesRegex(code["UpdateFailure"], "STATE"): check()
                self.assertEqual(namespace.stat().st_mode & 0o777, 0o755)
                namespace.rmdir(); namespace.symlink_to(root / "missing", target_is_directory=True)
                with self.assertRaisesRegex(code["UpdateFailure"], "STATE"): check()
                self.assertTrue(namespace.is_symlink())
            self.assertNotIn(code["WEB_RESTORE_DIR"], code["SNAPSHOT"])
            self.assertNotIn("/var/cache/sovagrid-web-restores", code["SNAPSHOT"])


if __name__ == "__main__":
    unittest.main()
