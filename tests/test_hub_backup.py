# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root SSH backup flow cannot accept changed source or arbitrary identifiers."""

import hashlib
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.hub_backup import BACKUP_ENTRY, RESTORE_ENTRY, HubBackupController
from sovagrid_connect.hub_backup_remote import SCRIPT
from sovagrid_connect.installer import InstallError


MANIFEST = "a" * 64
IDENTITY = "ab85d58d-48a9-4b4f-9579-c0d4a15b5c79"
RESTORE_REQUEST = "311c7239-79bd-4ad8-8b61-44e59be1ecaa"
RESTORE_PLAN = "55bce488-3f48-4f44-88cc-7b411eb279aa"
SAFETY = "173f2311-95f8-45b6-a976-086164717ecd"
CREATED = {"ok": True, "id": IDENTITY, "created_at": 1793000000,
           "database_bytes": 24576, "telegram_token_included": True}
RESTORED = {"ok": True, "protocol": 1, "request_id": RESTORE_REQUEST,
            "target_id": IDENTITY, "phase": "complete", "safety_id": SAFETY,
            "plan_id": RESTORE_PLAN, "hub_running": True, "error": None,
            "created_at": 1793000100}


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("ubuntu.example.org", user=user).validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.calls = []
        self.root_proofs = 0
        self.source_valid = True
        self.ids = [IDENTITY]
        self.present = True
        self.verification_valid = True
        self.create_reply_lost = False
        self.restore_reply_lost = False
        self.restore_result = RESTORED.copy()

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout):
        self.calls.append((command, timeout))
        if "from sovagrid_hub.backup_restore import main" in command:
            if command.endswith(" list"):
                return 0, json.dumps({"ok": True, "protocol": 1,
                                      "restores": [{**self.restore_result, "created_at": 1793000100}]}).encode()
            if command.endswith(" status " + RESTORE_REQUEST):
                return (0 if self.restore_result["ok"] else 2), json.dumps(self.restore_result).encode()
            if command.endswith(" recover " + RESTORE_REQUEST):
                return (0 if self.restore_result["ok"] else 2), json.dumps(self.restore_result).encode()
            if command.endswith(" apply " + IDENTITY + " " + RESTORE_REQUEST):
                if self.restore_reply_lost:
                    return 255, b"ssh reply lost"
                return (0 if self.restore_result["ok"] else 2), json.dumps(self.restore_result).encode()
            raise AssertionError(command)
        if "from sovagrid_hub.backup import main" not in command:
            if not self.source_valid:
                return 40, b"SG_HUB_BACKUP_SOURCE_REFUSE:UNVERIFIED\n"
            if command.endswith(" " + MANIFEST + " source-only"):
                return 0, json.dumps({"protocol": 1, "manifest_sha256": MANIFEST,
                                      "source_verified": True}).encode()
            return 0, json.dumps({"protocol": 1, "manifest_sha256": MANIFEST,
                                  "backups_present": self.present}).encode()
        if command.endswith(" list"):
            return 0, json.dumps({"ok": True, "ids": self.ids}).encode()
        if command.endswith(" create"):
            self.present = True
            self.ids = [IDENTITY, *self.ids]
            if self.create_reply_lost:
                return 255, b"{}"
            return 0, json.dumps(CREATED).encode()
        if command.endswith(" verify " + IDENTITY):
            return 0, json.dumps({**CREATED, "verified": self.verification_valid}).encode()
        raise AssertionError(command)


class HubBackupTests(unittest.TestCase):
    def controller(self, transport, pin=MANIFEST):
        return HubBackupController(transport.options, transport=transport,
                                   approved_manifest_sha256=pin)

    def test_unapproved_or_changed_source_never_runs_backup_cli(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, None).inspect()
        self.assertEqual(transport.calls, [])
        transport.source_valid = False
        with self.assertRaisesRegex(InstallError, "не совпадают"):
            self.controller(transport).inspect()
        self.assertFalse(any("from sovagrid_hub.backup import main" in command
                             for command, _ in transport.calls))

    def test_create_rechecks_reviewed_list_and_verifies_result(self):
        transport = Transport("admin")
        transport.ids = []
        reviewed = self.controller(transport).inspect()
        self.assertEqual(reviewed.ids, ())
        created = self.controller(transport).create(reviewed)
        self.assertEqual(created.id, IDENTITY)
        self.assertTrue(created.verified)
        cli = [command for command, _ in transport.calls
               if "from sovagrid_hub.backup import main" in command]
        self.assertEqual([command.rsplit(" ", 1)[-1] for command in cli],
                         ["list", "list", "create", IDENTITY])
        self.assertTrue(all(command.startswith("sudo -n -- /usr/bin/python3 -B -I -c ") for command in cli))
        self.assertTrue(all(shlex.quote(BACKUP_ENTRY) in command
                            for command in cli))
        self.assertTrue(all("bot.token" not in command for command in cli))
        self.assertGreaterEqual(transport.root_proofs, 3)

    def test_changed_list_or_invalid_id_cannot_run_mutation(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.inspect()
        transport.ids = []
        with self.assertRaisesRegex(InstallError, "изменился"):
            controller.create(reviewed)
        self.assertFalse(any(command.endswith(" create") for command, _ in transport.calls))
        count = len(transport.calls)
        with self.assertRaisesRegex(InstallError, "идентификатор"):
            controller.verify("../hub.sqlite; rm -rf /tmp/example")
        self.assertFalse(any("rm -rf" in command for command, _ in transport.calls[count:]))

    def test_first_snapshot_without_backup_directory(self):
        transport = Transport()
        transport.present = False
        transport.ids = []
        inspected = self.controller(transport).inspect()
        self.assertEqual(inspected.ids, ())
        self.assertFalse(any(command.endswith(" list") for command, _ in transport.calls))

    def test_malformed_or_unverified_server_result_fails_closed(self):
        transport = Transport()
        transport.verification_valid = False
        with self.assertRaisesRegex(InstallError, "описание"):
            self.controller(transport).verify(IDENTITY)

    def test_lost_create_reply_does_not_repeat_snapshot(self):
        transport = Transport()
        transport.ids = []
        controller = self.controller(transport)
        reviewed = controller.inspect()
        transport.create_reply_lost = True
        with self.assertRaisesRegex(InstallError, "копия могла появиться.*список"):
            controller.create(reviewed)
        self.assertEqual(sum(command.endswith(" create") for command, _ in transport.calls), 1)
        self.assertEqual(controller.inspect().ids, (IDENTITY,))

    def test_restore_requires_exact_reviewed_copy_and_reports_durable_status(self):
        transport = Transport("admin")
        controller = self.controller(transport)
        reviewed = controller.inspect()
        details = controller.verify(IDENTITY)
        result = controller.restore(reviewed, details, RESTORE_REQUEST)
        self.assertEqual(result.phase, "complete")
        self.assertEqual(result.safety_id, SAFETY)
        self.assertEqual(result.hub_running, True)
        self.assertEqual(controller.restore_status(RESTORE_REQUEST), result)
        self.assertEqual(controller.restore_list()[0].created_at, 1793000100)
        restore_calls = [(command, timeout) for command, timeout in transport.calls
                         if "from sovagrid_hub.backup_restore import main" in command]
        self.assertEqual([timeout for _, timeout in restore_calls], [1800, 30, 30])
        self.assertTrue(all(command.startswith("sudo -n -- /usr/bin/python3 -B -I -c ")
                            for command, _ in restore_calls))
        self.assertTrue(all(shlex.quote(RESTORE_ENTRY) in command
                            for command, _ in restore_calls))

    def test_lost_restore_reply_reads_status_without_repeating_apply(self):
        transport = Transport()
        transport.restore_reply_lost = True
        controller = self.controller(transport)
        reviewed = controller.inspect()
        details = controller.verify(IDENTITY)
        result = controller.restore(reviewed, details, RESTORE_REQUEST)
        self.assertEqual(result.phase, "complete")
        restore_calls = [command for command, _ in transport.calls
                         if "from sovagrid_hub.backup_restore import main" in command]
        self.assertEqual(sum(" apply " in command for command in restore_calls), 1)
        self.assertEqual(sum(" status " in command for command in restore_calls), 1)

    def test_recovery_uses_same_request_without_new_apply(self):
        transport = Transport()
        controller = self.controller(transport)
        state = controller.recover_restore(RESTORE_REQUEST)
        self.assertEqual(state.phase, "complete")
        calls = [(command, timeout) for command, timeout in transport.calls
                 if "from sovagrid_hub.backup_restore import main" in command]
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith(" recover " + RESTORE_REQUEST))
        self.assertEqual(calls[0][1], 1800)

    def test_restore_status_stays_available_when_database_layout_is_damaged(self):
        transport = Transport()
        transport.present = False
        transport.restore_result = {**RESTORED, "ok": False,
                                    "phase": "recovery_required", "hub_running": False,
                                    "error": "RESTORE_RECOVERY_REQUIRED"}
        controller = self.controller(transport)
        status = controller.restore_status(RESTORE_REQUEST)
        self.assertEqual(status.phase, "recovery_required")
        self.assertFalse(status.hub_running)
        self.assertTrue(any(command.endswith(" " + MANIFEST + " source-only")
                            for command, _ in transport.calls))

    def test_restore_code_must_match_before_status_or_recover(self):
        transport = Transport()
        transport.source_valid = False
        controller = self.controller(transport)
        with self.assertRaisesRegex(InstallError, "Код Hub не совпадает"):
            controller.restore_status(RESTORE_REQUEST)
        with self.assertRaisesRegex(InstallError, "Ответ о восстановлении"):
            controller.recover_restore(RESTORE_REQUEST)
        self.assertFalse(any("from sovagrid_hub.backup_restore import main" in command
                             for command, _ in transport.calls))

    def test_restore_rejects_changed_list_and_untrusted_metadata_before_apply(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.inspect()
        details = controller.verify(IDENTITY)
        transport.ids = []
        with self.assertRaisesRegex(InstallError, "изменились"):
            controller.restore(reviewed, details, RESTORE_REQUEST)
        self.assertFalse(any(" apply " in command for command, _ in transport.calls))
        transport.restore_result = {**RESTORED, "target_id": "../bad"}
        with self.assertRaises(InstallError):
            controller.restore_status(RESTORE_REQUEST)
        transport.ids = [IDENTITY]
        transport.restore_result = {**RESTORED, "target_id": SAFETY}
        with self.assertRaisesRegex(InstallError, "другой резервной копии"):
            controller.restore(reviewed, details, RESTORE_REQUEST)

    def test_source_probe_is_read_only_and_compiles(self):
        compile(SCRIPT, "<hub-backup-source-probe>", "exec")
        self.assertNotIn("subprocess", SCRIPT)
        self.assertNotIn("mkdir", SCRIPT)
        self.assertIn("manifest['sha256']", SCRIPT)
        self.assertIn("seen == set(expected)", SCRIPT)
        self.assertIn("sovagrid_hub/amnezia_actions.py", SCRIPT)
        self.assertIn("sovagrid_hub/service_actions.py", SCRIPT)
        self.assertIn("read=False", SCRIPT)

    def test_component_proof_rejects_extra_or_missing_source(self):
        # Run the Linux scanner against a disposable tree. The POSIX account
        # module and filesystem owner/mode bits are simulated on client OSes.
        namespace = {}
        with mock.patch.dict(sys.modules, {"pwd": mock.Mock()}):
            exec(SCRIPT.split("\ntry:\n    need(len(sys.argv)", 1)[0], namespace)
        names = ("sovagrid_hub/__init__.py", "sovagrid_hub/backup.py",
                 "sovagrid_hub/amnezia_actions.py", "sovagrid_hub/service_actions.py",
                 "sovagrid_hub/store.py", "sovagrid_hub/auth.py", "README.md", "LICENSE")
        original_lstat = Path.lstat

        def root_lstat(path):
            info = original_lstat(path)
            return SimpleNamespace(st_mode=info.st_mode & ~0o022, st_uid=0, st_gid=0,
                                   st_nlink=info.st_nlink, st_size=info.st_size)

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "sovagrid-hub"
            source.mkdir()
            hashes = {}
            for relative in names:
                target = source / relative
                target.parent.mkdir(exist_ok=True)
                raw = relative.encode("ascii")
                target.write_bytes(raw)
                hashes["sovagrid-hub/" + relative] = hashlib.sha256(raw).hexdigest()
            cache = source / "sovagrid_hub/__pycache__"
            cache.mkdir()
            (cache / "backup.cpython-312.pyc").write_bytes(b"cache")
            namespace["SOURCE"] = source
            namespace["regular"] = lambda path, *_args, **_kwargs: path.read_bytes()
            with mock.patch.object(Path, "lstat", root_lstat):
                namespace["checked_component"]({"sha256": hashes})
                (source / "sovagrid_hub/extra.py").write_bytes(b"unexpected")
                with self.assertRaises(ValueError):
                    namespace["checked_component"]({"sha256": hashes})
                (source / "sovagrid_hub/extra.py").unlink()
                (source / "sovagrid_hub/store.py").unlink()
                with self.assertRaises(ValueError):
                    namespace["checked_component"]({"sha256": hashes})


if __name__ == "__main__":
    unittest.main()
