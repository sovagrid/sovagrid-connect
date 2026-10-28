# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Host archives require a pinned root source and unambiguous metadata replies."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.host_backup import HostArchive, HostBackupController
from sovagrid_connect.host_backup_request import HostBackupRequestStore
from sovagrid_connect.auto_update import target_id
from sovagrid_connect.host_backup_remote import SCRIPT
from sovagrid_connect.installer import InstallError


MANIFEST = "a" * 64
ARCHIVE_ID = "b" * 32
OTHER_ID = "c" * 32
RECORD = {"id": ARCHIVE_ID, "created_at": "2026-10-27T12:00:00+00:00",
          "layout": "full", "bytes": 2048, "files": 13}
PROTOCOL = "sovagrid-host-backup-v1"
OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"
REQUEST_ID = "d" * 32


def operation(phase="accepted", *, request_id=REQUEST_ID, archive=None, error=None):
    return {"ok": True, "protocol": OPERATION_PROTOCOL, "request_id": request_id,
            "phase": phase, "archive": archive, "error": error,
            "created_at": "2026-10-27T12:00:00+00:00"}


class Transport:
    def __init__(self):
        self.options = ConnectionOptions("ubuntu.example.org", user="admin").validated()
        self._privileged = "sudo -n -- "
        self.calls = []
        self.source_valid = True
        self.archives = []
        self.active_units = []
        self.running_containers = []
        self.create_reply_lost = False
        self.verify_reply = None
        self.operations = {}
        self.start_reply_lost = False
        self.recover_reply_lost = False
        self.recover_busy = False
        self.start_refusal = None

    def _verify_root_access(self):
        self.calls.append("root-proof")

    def _execute(self, command, *, timeout, limit=4096):
        self.calls.append(command)
        self.last_limit = limit
        if " -c " in command:
            if not self.source_valid:
                return 40, b"SG_HOST_BACKUP_SOURCE_REFUSE:UNVERIFIED"
            return 0, json.dumps({"protocol": 1, "manifest_sha256": MANIFEST,
                                  "host_backup_verified": True}).encode()
        if " -I /opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py " in command:
            action = command.split("host_backup_orchestrator.py ", 1)[1].split(" ", 1)[0]
            if action == "start":
                assert command.endswith(" " + REQUEST_ID + " " + MANIFEST)
                if self.start_refusal:
                    return 40, json.dumps({"ok": False, "protocol": OPERATION_PROTOCOL,
                                           "error": self.start_refusal}).encode()
                self.operations[REQUEST_ID] = operation()
                if self.start_reply_lost:
                    raise subprocess.TimeoutExpired(command, timeout)
                return 0, json.dumps(self.operations[REQUEST_ID]).encode()
            if action == "status":
                identity = command.rsplit(" ", 1)[-1]
                return 0, json.dumps(self.operations[identity]).encode()
            if action == "recover":
                identity = command.rsplit(" ", 1)[-1]
                if self.recover_busy:
                    return 40, json.dumps({"ok": False, "protocol": OPERATION_PROTOCOL,
                                           "error": "BUSY"}).encode()
                self.operations[identity] = operation("recovery_requested", request_id=identity)
                if self.recover_reply_lost:
                    raise subprocess.TimeoutExpired(command, timeout)
                return 0, json.dumps(self.operations[identity]).encode()
            if action == "list":
                return 0, json.dumps({"ok": True, "protocol": OPERATION_PROTOCOL,
                                      "operations": list(self.operations.values())}).encode()
        if command.endswith(" list"):
            return 0, json.dumps({"ok": True, "protocol": PROTOCOL,
                                  "archives": self.archives}).encode()
        if command.endswith(" plan"):
            return 0, json.dumps({"ok": True, "protocol": PROTOCOL,
                                  "layout": "full", "active_units": self.active_units,
                                  "running_containers": self.running_containers,
                                  "offline_ready": not self.active_units and
                                  not self.running_containers}).encode()
        if command.endswith(" create"):
            self.archives.insert(0, RECORD.copy())
            if self.create_reply_lost:
                raise subprocess.TimeoutExpired(command, timeout)
            return 0, json.dumps({"ok": True, "protocol": PROTOCOL,
                                  "archive": RECORD}).encode()
        if command.endswith(" verify " + ARCHIVE_ID):
            answer = self.verify_reply or {"ok": True, "protocol": PROTOCOL,
                                           "archive": RECORD, "verified": True}
            return 0, json.dumps(answer).encode()
        raise AssertionError(command)


class HostBackupTests(unittest.TestCase):
    def controller(self, transport, manifest=MANIFEST):
        return HostBackupController(transport.options, approved_manifest_sha256=manifest,
                                    transport=transport)

    def test_pinned_source_must_pass_before_backup_cli(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, None).inspect()
        self.assertFalse(transport.calls)
        transport.source_valid = False
        with self.assertRaisesRegex(InstallError, "проверенным выпуском"):
            self.controller(transport).inspect()
        self.assertFalse(any(" -I /opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup.py " in call
                             for call in transport.calls))
        compile(SCRIPT, "<host-backup-source-proof>", "exec")
        self.assertIn("sovagrid-blueprint/deploy/host_backup.py'", SCRIPT)
        self.assertIn("sovagrid-blueprint/deploy/host_backup_orchestrator.py'", SCRIPT)
        self.assertIn("actual == set(hashes)", SCRIPT)

    def test_create_rechecks_list_and_verifies_exact_result(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.inspect()
        created, state = controller.create(reviewed)
        self.assertEqual(created.id, ARCHIVE_ID)
        self.assertTrue(created.verified)
        self.assertEqual(state.archives[0], HostArchive(**RECORD))
        cli = [call for call in transport.calls
               if " -I /opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup.py " in call]
        self.assertEqual([call.rsplit(" ", 1)[-1] for call in cli],
                         ["plan", "list", "plan", "list", "create", "plan", "list", ARCHIVE_ID])
        self.assertTrue(all(call.startswith("sudo -n -- /usr/bin/python3 -B -I ") for call in cli))

    def test_changed_list_prevents_mutation_and_lost_reply_is_not_retried(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.inspect()
        transport.archives = [RECORD.copy()]
        with self.assertRaisesRegex(InstallError, "изменились"):
            controller.create(reviewed)
        self.assertFalse(any(call.endswith(" create") for call in transport.calls))
        reviewed = controller.inspect()
        transport.create_reply_lost = True
        with self.assertRaisesRegex(InstallError, "копия могла появиться"):
            controller.create(reviewed)
        self.assertEqual(sum(call.endswith(" create") for call in transport.calls), 1)

    def test_plan_refuses_create_while_writer_running(self):
        transport = Transport()
        transport.active_units = ["sovagrid-release-feed.timer"]
        controller = self.controller(transport)
        state = controller.inspect()
        self.assertFalse(state.plan.offline_ready)
        with self.assertRaises(InstallError):
            controller.create(state)
        self.assertFalse(any(call.endswith(" create") for call in transport.calls))

    def test_rejects_malformed_records_and_wrong_verify_reply(self):
        transport = Transport()
        controller = self.controller(transport)
        for change in ({"bytes": True}, {"created_at": "2026-10-27T12:00:00+03:00"},
                       {"id": "../other"}, {"layout": "other"}, {"files": 20001}):
            transport.archives = [{**RECORD, **change}]
            with self.assertRaises(InstallError):
                controller.inspect()
        transport.archives = [RECORD.copy()]
        transport.verify_reply = {"ok": True, "protocol": PROTOCOL,
                                  "archive": {**RECORD, "id": OTHER_ID}, "verified": True}
        with self.assertRaisesRegex(InstallError, "другой полной копии"):
            controller.verify(ARCHIVE_ID)

    def test_online_start_persists_request_and_lost_reply_uses_status(self):
        transport = Transport()
        transport.active_units = ["sovagrid-release-feed.timer"]
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(transport.options, transport=transport,
                                              approved_manifest_sha256=MANIFEST,
                                              request_store=store)
            reviewed = controller.inspect()
            transport.start_reply_lost = True
            started = controller.start_online(reviewed, REQUEST_ID)
            self.assertEqual(started.phase, "accepted")
            self.assertEqual(controller.saved_request().request_id, REQUEST_ID)
            self.assertEqual(controller.operation_list(), (started,))
            self.assertEqual(sum("host_backup_orchestrator.py start " in item
                                 for item in transport.calls), 1)
            restarted = HostBackupController(transport.options, transport=transport,
                                             approved_manifest_sha256=MANIFEST,
                                             request_store=store)
            self.assertEqual(restarted.saved_request().request_id, REQUEST_ID)
            self.assertEqual(restarted.operation_status(REQUEST_ID), started)
            with self.assertRaisesRegex(InstallError, "незавершённая"):
                controller.start_online(reviewed, "e" * 32)

    def test_recover_never_recreates_archive_and_refuses_terminal_request(self):
        transport = Transport()
        transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
        controller = self.controller(transport)
        with self.assertRaisesRegex(InstallError, "не требуется"):
            controller.recover_operation(REQUEST_ID)
        self.assertFalse(any("host_backup_orchestrator.py recover " in item
                             for item in transport.calls))
        transport.operations[REQUEST_ID] = operation("recovery_required", error="RESTART_FAILED")
        transport.recover_reply_lost = True
        recovered = controller.recover_operation(REQUEST_ID)
        self.assertEqual(recovered.phase, "recovery_requested")
        self.assertEqual(sum("host_backup_orchestrator.py recover " in item
                             for item in transport.calls), 1)
        self.assertFalse(any("host_backup_orchestrator.py start " in item
                             for item in transport.calls))

    def test_recover_during_active_worker_returns_current_state(self):
        transport = Transport()
        transport.operations[REQUEST_ID] = operation("archiving")
        transport.recover_busy = True
        state = self.controller(transport).recover_operation(REQUEST_ID)
        self.assertEqual(state.phase, "archiving")
        self.assertEqual(sum("host_backup_orchestrator.py recover " in item
                             for item in transport.calls), 1)

    def test_operation_parser_refuses_wrong_request_or_shape(self):
        transport = Transport()
        transport.operations[REQUEST_ID] = operation()
        controller = self.controller(transport)
        for malformed in ({"request_id": OTHER_ID}, {"phase": "unknown"},
                          {"created_at": "2026-10-27T12:00:00+03:00"},
                          {"archive": {**RECORD, "bytes": True}}, {"ok": False}):
            transport.operations[REQUEST_ID] = {**operation(), **malformed}
            with self.assertRaises(InstallError):
                controller.operation_status(REQUEST_ID)

    def test_unsafe_local_request_blocks_new_remote_mutation(self):
        transport = Transport()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "requests"
            folder.mkdir(mode=0o700)
            marker = folder / (target_id(transport.options) + ".json")
            marker.write_text("{}")
            marker.chmod(0o600)
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST,
                request_store=HostBackupRequestStore(folder))
            reviewed = controller.inspect()
            with self.assertRaisesRegex(InstallError, "повреждён"):
                controller.start_online(reviewed, REQUEST_ID)
            self.assertFalse(any("host_backup_orchestrator.py start " in item
                                 for item in transport.calls))

    def test_definite_start_refusal_clears_only_own_local_marker(self):
        transport = Transport()
        transport.start_refusal = "DEGRADED_CONTAINERS"
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(transport.options, transport=transport,
                                              approved_manifest_sha256=MANIFEST,
                                              request_store=store)
            reviewed = controller.inspect()
            with self.assertRaisesRegex(InstallError, "Контейнеры Hub/Web"):
                controller.start_online(reviewed, REQUEST_ID)
            self.assertIsNone(controller.saved_request())

    def test_bounded_large_history_uses_explicit_ssh_limit(self):
        transport = Transport()
        transport.operations = {f"{i:032x}": operation("failed", request_id=f"{i:032x}",
                                                       error="ARCHIVE_FAILED")
                                for i in range(100)}
        rows = self.controller(transport).operation_list()
        self.assertEqual(len(rows), 100)
        self.assertEqual(transport.last_limit, 98304)


if __name__ == "__main__":
    unittest.main()
