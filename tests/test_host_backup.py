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
from sovagrid_connect.host_backup import (HostArchive, HostBackupController,
                                          HostPortableOperation)
from sovagrid_connect.host_backup_request import HostBackupRequest, HostBackupRequestStore
from sovagrid_connect.auto_update import target_id
from sovagrid_connect.host_backup_remote import SCRIPT
from sovagrid_connect.installer import InstallError


MANIFEST = "a" * 64
NEW_MANIFEST = "e" * 64
ARCHIVE_ID = "b" * 32
OTHER_ID = "c" * 32
RECORD = {"id": ARCHIVE_ID, "created_at": "2026-10-27T12:00:00+00:00",
          "layout": "full", "bytes": 2048, "files": 13}
PROTOCOL = "sovagrid-host-backup-v1"
OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"
REQUEST_ID = "d" * 32
IMAGE_PROTOCOL = "sovagrid-host-images-v1"
RECEIPT = {
    "protocol": "sovagrid-portable-host-receipt-v1",
    "host_archive_id": ARCHIVE_ID,
    "host_archive_sha256": "1" * 64,
    "source_manifest_sha256": MANIFEST,
    "images_sha256": "2" * 64,
    "images": {"hub": "sha256:" + "3" * 64, "web": "sha256:" + "4" * 64},
    "container_ids": {"hub": "5" * 64, "web": "6" * 64},
    "exported_configs": {"hub": "sha256:" + "7" * 64,
                         "web": "sha256:" + "8" * 64},
    "rootfs_sha256": {"hub": "9" * 64, "web": "a" * 64},
    "active_units": ["sovagrid-release-feed.timer"],
    "unit_hashes": {"sovagrid-release-feed.timer": "b" * 64},
}


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
        self.source_manifest = MANIFEST
        self.portable_source_valid = True
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
        self.portable_requests = set()
        self.portable_receipt = None
        self.portable_status_reply = None
        self.portable_status_reply_lost = False
        self.image_verify_reply = None

    def _verify_root_access(self):
        self.calls.append("root-proof")

    def _execute(self, command, *, timeout, limit=4096):
        self.calls.append(command)
        self.last_limit = limit
        if " -c " in command:
            if not self.source_valid:
                return 40, b"SG_HOST_BACKUP_SOURCE_REFUSE:UNVERIFIED"
            portable = command.endswith(" portable")
            if portable and not self.portable_source_valid:
                return 40, b"SG_HOST_BACKUP_SOURCE_REFUSE:PORTABLE_UNAVAILABLE"
            answer = {"protocol": 1, "manifest_sha256": self.source_manifest,
                      "host_backup_verified": True}
            if portable:
                answer["portable_verified"] = True
            return 0, json.dumps(answer).encode()
        if " -I /opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py " in command:
            action = command.split("host_backup_orchestrator.py ", 1)[1].split(" ", 1)[0]
            if action in ("start", "start-portable"):
                identity, manifest = command.rsplit(" ", 2)[-2:]
                assert manifest == self.source_manifest
                if self.start_refusal:
                    return 40, json.dumps({"ok": False, "protocol": OPERATION_PROTOCOL,
                                           "error": self.start_refusal}).encode()
                self.operations[identity] = operation(request_id=identity)
                if action == "start-portable":
                    self.portable_requests.add(identity)
                if self.start_reply_lost:
                    raise subprocess.TimeoutExpired(command, timeout)
                return 0, json.dumps(self.operations[identity]).encode()
            if action == "portable-status":
                identity = command.rsplit(" ", 1)[-1]
                if self.portable_status_reply_lost:
                    raise subprocess.TimeoutExpired(command, timeout)
                if identity not in self.portable_requests:
                    return 40, json.dumps({"ok": False, "protocol": OPERATION_PROTOCOL,
                                           "error": "NOT_PORTABLE"}).encode()
                answer = self.portable_status_reply or {
                    **self.operations[identity], "image_receipt": self.portable_receipt}
                return 0, json.dumps(answer).encode()
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
        if " -I /opt/sovagrid-src/sovagrid-blueprint/deploy/host_image_export.py " in command:
            assert command.endswith(" verify-portable " + ARCHIVE_ID)
            answer = self.image_verify_reply or {
                "ok": True, "protocol": IMAGE_PROTOCOL, "id": ARCHIVE_ID,
                "verified": True, "image_count": 2, "bytes": 4096,
                "apply_available": False, "receipt": self.portable_receipt,
                "platforms": {"hub": {"os": "linux", "architecture": "amd64"},
                              "web": {"os": "linux", "architecture": "arm64"}}}
            return 0, json.dumps(answer).encode()
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

    def test_portable_start_persists_mode_and_verifies_paired_metadata(self):
        transport = Transport()
        transport.running_containers = ["hub", "web"]
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            reviewed = controller.inspect()
            started = controller.start_portable(reviewed, REQUEST_ID)
            self.assertIsInstance(started, HostPortableOperation)
            self.assertEqual(started.operation.phase, "accepted")
            self.assertIsNone(started.image_receipt)
            self.assertEqual(controller.saved_request().mode, "portable")
            raw = (store.directory / (target_id(transport.options) + ".json")).read_text()
            self.assertEqual(json.loads(raw)["format"], 2)
            self.assertIn('"mode":"portable"', raw)
            polled = controller.operation_status(REQUEST_ID)
            self.assertEqual(polled, started.operation)
            self.assertTrue(any("host_backup_orchestrator.py portable-status " +
                                REQUEST_ID in item for item in transport.calls))
            self.assertFalse(any("host_backup_orchestrator.py status " +
                                 REQUEST_ID in item for item in transport.calls))
            self.assertEqual(sum("host_backup_orchestrator.py start-portable " in item
                                 for item in transport.calls), 1)
            self.assertTrue(any(item.endswith(" " + MANIFEST + " portable")
                                for item in transport.calls))

            transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
            transport.portable_receipt = RECEIPT.copy()
            pair = controller.verify_portable(REQUEST_ID)
            self.assertEqual(pair.operation.request_id, REQUEST_ID)
            self.assertEqual(pair.archive, HostArchive(**RECORD, verified=True))
            self.assertEqual(pair.image_receipt, RECEIPT)
            self.assertEqual(pair.image_bytes, 4096)
            self.assertEqual(pair.image_count, 2)
            self.assertEqual(pair.platforms["web"]["architecture"], "arm64")
            self.assertEqual(transport.last_limit, 12288)
            self.assertTrue(any("host_image_export.py verify-portable " + ARCHIVE_ID in item
                                for item in transport.calls))

    def test_lost_portable_start_and_status_resume_from_saved_mode(self):
        transport = Transport()
        transport.running_containers = ["hub", "web"]
        transport.start_reply_lost = True
        transport.portable_status_reply_lost = True
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            reviewed = controller.inspect()
            with self.assertRaisesRegex(InstallError, "Ответ о запуске потерян"):
                controller.start_portable(reviewed, REQUEST_ID)
            self.assertEqual(store.load(transport.options).mode, "portable")
            self.assertEqual(sum("host_backup_orchestrator.py start-portable " in item
                                 for item in transport.calls), 1)
            transport.portable_status_reply_lost = False
            restarted = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            resumed = restarted.saved_operation_status()
            self.assertIsInstance(resumed, HostPortableOperation)
            self.assertEqual(resumed.operation.phase, "accepted")
            self.assertEqual(restarted.operation_status(REQUEST_ID), resumed.operation)
            self.assertEqual(sum("host_backup_orchestrator.py start-portable " in item
                                 for item in transport.calls), 1)
            with self.assertRaisesRegex(InstallError, "незавершённая"):
                restarted.start_portable(reviewed, "e" * 32)

    def test_lost_portable_start_reply_uses_portable_status(self):
        transport = Transport()
        transport.running_containers = ["hub", "web"]
        transport.start_reply_lost = True
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            started = controller.start_portable(controller.inspect(), REQUEST_ID)
            self.assertEqual(started.operation.phase, "accepted")
            self.assertTrue(any("host_backup_orchestrator.py portable-status " +
                                REQUEST_ID in item for item in transport.calls))

    def test_saved_portable_recovery_uses_generic_dialog_api(self):
        transport = Transport()
        transport.running_containers = ["hub", "web"]
        transport.recover_reply_lost = True
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            controller.start_portable(controller.inspect(), REQUEST_ID)
            resumed = controller.recover_operation(REQUEST_ID)
            self.assertEqual(resumed.phase, "recovery_requested")
            self.assertEqual(controller.operation_status(REQUEST_ID), resumed)
            self.assertEqual(sum("host_backup_orchestrator.py recover " in item
                                 for item in transport.calls), 1)
            self.assertFalse(any("host_backup_orchestrator.py status " +
                                 REQUEST_ID in item for item in transport.calls))

    def test_portable_rejects_wrong_receipt_and_wrong_mode(self):
        transport = Transport()
        transport.running_containers = ["hub", "web"]
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            controller.start_portable(controller.inspect(), REQUEST_ID)
            transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
            wrong_receipts = [
                {**RECEIPT, "host_archive_id": OTHER_ID},
                {**RECEIPT, "source_manifest_sha256": "0" * 64},
                {**RECEIPT, "images": {"hub": RECEIPT["images"]["hub"]}},
                {**RECEIPT, "active_units": RECEIPT["active_units"] * 2},
                {**RECEIPT, "extra": True},
            ]
            long_units = ["sovagrid-" + "x" * 73 + f"{i:02d}" + ".service"
                          for i in range(32)]
            oversized = {**RECEIPT, "active_units": long_units,
                         "unit_hashes": {unit: "b" * 64 for unit in long_units}}
            self.assertGreater(len(json.dumps(oversized, separators=(",", ":"))), 8192)
            self.assertLess(len(json.dumps(oversized, separators=(",", ":"))), 12288)
            wrong_receipts.append(oversized)
            for receipt in wrong_receipts:
                transport.portable_receipt = receipt
                with self.subTest(receipt=receipt.get("host_archive_id")):
                    with self.assertRaises(InstallError):
                        controller.portable_status(REQUEST_ID)
                    with self.assertRaises(InstallError):
                        controller.operation_status(REQUEST_ID)
            large_units = long_units[:24]
            large_receipt = {**RECEIPT, "active_units": large_units,
                             "unit_hashes": {unit: "b" * 64 for unit in large_units}}
            self.assertGreater(len(json.dumps(large_receipt, separators=(",", ":"))), 4096)
            transport.portable_receipt = large_receipt
            self.assertEqual(controller.portable_status(REQUEST_ID).image_receipt,
                             large_receipt)
            self.assertEqual(transport.last_limit, 12288)
            transport.portable_receipt = RECEIPT.copy()
            transport.portable_status_reply = {
                **operation("complete", archive=RECORD),
                "image_receipt": RECEIPT, "extra": True}
            with self.assertRaisesRegex(InstallError, "состояние переносимой"):
                controller.portable_status(REQUEST_ID)
            transport.portable_status_reply = None
            transport.image_verify_reply = {
                "ok": True, "protocol": IMAGE_PROTOCOL, "id": ARCHIVE_ID,
                "verified": True, "image_count": 2, "bytes": 4096,
                "apply_available": False,
                "receipt": {**RECEIPT, "images_sha256": "0" * 64},
                "platforms": {"hub": {"os": "linux", "architecture": "amd64"},
                              "web": {"os": "linux", "architecture": "arm64"}}}
            with self.assertRaisesRegex(InstallError, "результат проверки"):
                controller.verify_portable(REQUEST_ID)
            valid_image_reply = {**transport.image_verify_reply, "receipt": RECEIPT}
            for change in ({"image_count": True}, {"apply_available": True},
                           {"id": OTHER_ID}, {"extra": True},
                           {"platforms": {"hub": {"os": "linux",
                                                  "architecture": "amd64"}}}):
                transport.image_verify_reply = {**valid_image_reply, **change}
                with self.subTest(image_reply=change):
                    with self.assertRaisesRegex(InstallError, "результат проверки"):
                        controller.verify_portable(REQUEST_ID)
            online = HostBackupRequest.new(transport.options, REQUEST_ID, MANIFEST)
            store.save(online, replacing=REQUEST_ID)
            calls = len(transport.calls)
            with self.assertRaisesRegex(InstallError, "Режим"):
                controller.portable_status(REQUEST_ID)
            self.assertEqual(len(transport.calls), calls)

    def test_portable_refuses_old_pinned_source_before_start_or_verify(self):
        transport = Transport()
        transport.portable_source_valid = False
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            reviewed = controller.inspect()
            with self.assertRaisesRegex(InstallError, "проверенным выпуском"):
                controller.start_portable(reviewed, REQUEST_ID)
            self.assertIsNone(controller.saved_request())
            self.assertFalse(any("host_backup_orchestrator.py start-portable " in item
                                 for item in transport.calls))
            self.assertIn("verify-portable", SCRIPT)
            self.assertIn("portable-status", SCRIPT)
            self.assertIn("start-portable", SCRIPT)
            transport.portable_source_valid = True
            controller.start_portable(reviewed, REQUEST_ID)
            transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
            transport.portable_receipt = RECEIPT.copy()
            transport.portable_source_valid = False
            with self.assertRaisesRegex(InstallError, "проверенным выпуском"):
                controller.verify_portable(REQUEST_ID)
            self.assertFalse(any("host_image_export.py verify-portable " in item
                                 for item in transport.calls))

    def test_portable_definite_start_refusal_clears_its_marker(self):
        transport = Transport()
        transport.start_refusal = "STACK_NOT_READY"
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST, request_store=store)
            with self.assertRaises(InstallError):
                controller.start_portable(controller.inspect(), REQUEST_ID)
            self.assertIsNone(controller.saved_request())

    def test_saved_portable_receipt_and_terminal_replacement_after_upgrade(self):
        transport = Transport()
        transport.source_manifest = NEW_MANIFEST
        transport.running_containers = ["hub", "web"]
        transport.portable_requests.add(REQUEST_ID)
        transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
        transport.portable_receipt = RECEIPT.copy()
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            store.save(HostBackupRequest.new(transport.options, REQUEST_ID, MANIFEST,
                                             mode="portable"))
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=NEW_MANIFEST, request_store=store)
            self.assertEqual(controller.operation_status(REQUEST_ID).phase, "complete")
            self.assertEqual(controller.portable_status(REQUEST_ID).image_receipt,
                             RECEIPT)
            self.assertEqual(controller.verify_portable(REQUEST_ID).image_receipt,
                             RECEIPT)
            reviewed = controller.inspect()
            started = controller.start_online(reviewed, OTHER_ID)
            self.assertEqual(started.request_id, OTHER_ID)
            self.assertEqual(controller.saved_request().manifest_sha256, NEW_MANIFEST)
            self.assertEqual(controller.saved_request().mode, "online")

    def test_format_one_saved_request_resumes_as_online_and_migrates_on_write(self):
        transport = Transport()
        transport.source_manifest = NEW_MANIFEST
        with tempfile.TemporaryDirectory() as temporary:
            store = HostBackupRequestStore(Path(temporary) / "requests")
            store.directory.mkdir(mode=0o700)
            marker = store.directory / (target_id(transport.options) + ".json")
            marker.write_text(json.dumps({"format": 1,
                                          "target_id": target_id(transport.options),
                                          "request_id": REQUEST_ID,
                                          "manifest_sha256": MANIFEST,
                                          "created_at": 1}))
            marker.chmod(0o600)
            transport.operations[REQUEST_ID] = operation()
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=NEW_MANIFEST, request_store=store)
            self.assertEqual(controller.saved_request().mode, "online")
            self.assertEqual(controller.saved_operation_status().phase, "accepted")
            replacement = HostBackupRequest.new(transport.options, OTHER_ID,
                                                NEW_MANIFEST)
            store.save(replacement, replacing=REQUEST_ID)
            self.assertEqual(json.loads(marker.read_text())["mode"], "online")
            self.assertEqual(json.loads(marker.read_text())["format"], 2)

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
