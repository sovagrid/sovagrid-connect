# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Host archives require a pinned root source and unambiguous metadata replies."""

from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from sovagrid_connect import host_backup_transfer as transfer
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.host_backup import (HostArchive, HostBackupController,
                                          HostPortableOperation)
from sovagrid_connect.host_backup_request import HostBackupRequest, HostBackupRequestStore
from sovagrid_connect.host_backup_transfer import STREAM_SCRIPT
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


def portable_payloads(host_bytes, image_bytes, receipt):
    host_manifest = {**RECORD, "protocol": PROTOCOL,
                     "sha256": receipt["host_archive_sha256"],
                     "source_manifest_sha256": receipt["source_manifest_sha256"]}
    images_manifest = {
        "protocol": IMAGE_PROTOCOL, "id": ARCHIVE_ID,
        "host_archive_sha256": receipt["host_archive_sha256"],
        "source_manifest_sha256": receipt["source_manifest_sha256"],
        "layout": RECORD["layout"], "created_at": "2026-10-27T12:01:00+00:00",
        "bytes": len(image_bytes), "sha256": receipt["images_sha256"],
        "files": 17, "images": receipt["images"],
        "container_ids": receipt["container_ids"],
        "exported_configs": receipt["exported_configs"],
        "rootfs_sha256": receipt["rootfs_sha256"],
    }
    encode = lambda value: (json.dumps(value, sort_keys=True,
                                       separators=(",", ":")) + "\n").encode()
    return {"host_manifest": encode(host_manifest), "host": host_bytes,
            "images_manifest": encode(images_manifest), "images": image_bytes}


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


class StreamProcess:
    def __init__(self, payload, returncode=0):
        self.stdout = io.BytesIO(payload)
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def wait(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


class StreamManager:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []
        self._lock = threading.Lock()
        self._process = None

    @contextmanager
    def _session(self):
        yield "pinned-config", "askpass-helper"

    def _ssh(self, config, helper, command):
        self.calls.append((config, helper, command))
        _prefix, _manifest, kind, _identity, _size, _sha = command.rsplit(" ", 5)
        item = self.payloads[kind]
        process = StreamProcess(*item) if isinstance(item, tuple) else StreamProcess(item)
        self._process = process
        return process


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
            with self.assertRaisesRegex(InstallError, "не поддерживает переносимую копию"):
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
            with self.assertRaisesRegex(InstallError, "не поддерживает переносимую копию"):
                controller.verify_portable(REQUEST_ID)
            self.assertFalse(any("host_image_export.py verify-portable " in item
                                 for item in transport.calls))

    def test_portable_capability_probe_distinguishes_old_source_from_ssh_failure(self):
        transport = Transport()
        controller = self.controller(transport)
        self.assertTrue(controller.portable_available())
        transport.portable_source_valid = False
        self.assertFalse(controller.portable_available())
        transport.source_valid = False
        with self.assertRaisesRegex(InstallError, "проверенным выпуском"):
            controller.portable_available()
        self.assertFalse(self.controller(transport, None).portable_available())

    def test_export_portable_streams_exact_pair_into_private_published_folder(self):
        host_bytes = b"H" * RECORD["bytes"]
        image_bytes = b"I" * 4096
        receipt = {**RECEIPT,
                   "host_archive_sha256": hashlib.sha256(host_bytes).hexdigest(),
                   "images_sha256": hashlib.sha256(image_bytes).hexdigest()}
        transport = Transport()
        transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
        transport.portable_requests.add(REQUEST_ID)
        transport.portable_receipt = receipt
        payloads = portable_payloads(host_bytes, image_bytes, receipt)
        transport.manager = StreamManager(payloads)
        progress = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "chosen"
            selected.mkdir()
            store = HostBackupRequestStore(root / "requests")
            store.save(HostBackupRequest.new(transport.options, REQUEST_ID, MANIFEST,
                                             mode="portable"))
            controller = HostBackupController(
                transport.options, transport=transport, progress=progress.append,
                approved_manifest_sha256=MANIFEST, request_store=store)
            result = controller.export_portable(REQUEST_ID, selected)
            self.assertEqual(result, selected / ("sovagrid-backup-" + ARCHIVE_ID))
            self.assertEqual({item.name for item in result.iterdir()},
                             {ARCHIVE_ID + ".manifest.json", ARCHIVE_ID + ".tar.gz",
                              "manifest.json", "images.tar", "receipt.json"})
            self.assertEqual((result / (ARCHIVE_ID + ".tar.gz")).read_bytes(), host_bytes)
            self.assertEqual((result / (ARCHIVE_ID + ".manifest.json")).read_bytes(),
                             payloads["host_manifest"])
            self.assertEqual((result / "manifest.json").read_bytes(),
                             payloads["images_manifest"])
            self.assertEqual((result / "images.tar").read_bytes(), image_bytes)
            self.assertEqual(json.loads((result / "receipt.json").read_text()), receipt)
            if os.name == "nt":
                from sovagrid_connect.enrollment_journal import _windows_sid
                sid = _windows_sid()
                transfer._windows_verify(result, sid, directory=True)
                for name in transfer._filenames(ARCHIVE_ID):
                    transfer._windows_verify(result / name, sid)
            else:
                self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o700)
                self.assertTrue(all(stat.S_IMODE((result / name).stat().st_mode) == 0o600
                                    for name in transfer._filenames(ARCHIVE_ID)))
            self.assertEqual(len(transport.manager.calls), 4)
            self.assertTrue(all(config == "pinned-config" and helper == "askpass-helper" and
                                command.startswith("sudo -n -- /usr/bin/python3 -B -I -c ")
                                for config, helper, command in transport.manager.calls))
            self.assertEqual(
                [(command.rsplit(" ", 5)[-4], command.rsplit(" ", 5)[-3])
                 for _config, _helper, command in transport.manager.calls],
                [(kind, ARCHIVE_ID) for kind in transfer.PARTS])
            self.assertNotEqual(ARCHIVE_ID, REQUEST_ID)
            self.assertIn("Передаём архив образов", " ".join(progress))
            self.assertIn("source(manifest)", STREAM_SCRIPT)
            self.assertIn("sovagrid-host-image-exports", STREAM_SCRIPT)
            compile(STREAM_SCRIPT, "<host-backup-transfer>", "exec")

    def test_export_portable_rejects_corruption_and_cleans_staging(self):
        host_bytes = b"H" * RECORD["bytes"]
        image_bytes = b"I" * 4096
        receipt = {**RECEIPT,
                   "host_archive_sha256": hashlib.sha256(host_bytes).hexdigest(),
                   "images_sha256": hashlib.sha256(image_bytes).hexdigest()}
        original = portable_payloads(host_bytes, image_bytes, receipt)
        cases = [
            {**original, "images": b"X" * 4096},
            {**original, "host": host_bytes + b"X"},
            {**original, "images": (image_bytes, 40)},
            {**original, "images_manifest": (original["images_manifest"], 40)},
            {**original, "host_manifest": original["images_manifest"]},
            {**original, "images_manifest": original["host_manifest"]},
            {**original, "host_manifest": original["host_manifest"].replace(
                ARCHIVE_ID.encode(), OTHER_ID.encode())},
            {**original, "images_manifest": original["images_manifest"].replace(
                ARCHIVE_ID.encode(), OTHER_ID.encode())},
            {**original, "host_manifest": b"{" + b" " * transfer.MAX_HOST_MANIFEST_BYTES},
            {**original, "host_manifest": original["host_manifest"].replace(
                b'"id":"' + ARCHIVE_ID.encode() + b'"',
                b'"id":"' + ARCHIVE_ID.encode() + b'","id":"' +
                ARCHIVE_ID.encode() + b'"')},
        ]
        for payloads in cases:
            transport = Transport()
            transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
            transport.portable_requests.add(REQUEST_ID)
            transport.portable_receipt = receipt
            transport.manager = StreamManager(payloads)
            with self.subTest(payloads=payloads), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                selected = root / "chosen"
                selected.mkdir()
                controller = HostBackupController(
                    transport.options, transport=transport,
                    approved_manifest_sha256=MANIFEST,
                    request_store=HostBackupRequestStore(root / "requests"))
                with self.assertRaises(InstallError):
                    controller.export_portable(REQUEST_ID, selected)
                self.assertEqual(list(selected.iterdir()), [])

    def test_export_portable_refuses_archive_record_id_mismatch_before_streaming(self):
        transport = Transport()
        transport.manager = StreamManager({})
        with tempfile.TemporaryDirectory() as temporary:
            selected = Path(temporary)
            with self.assertRaisesRegex(InstallError, "Неверная квитанция"):
                transfer.export_portable_files(
                    transport, selected, archive_id=ARCHIVE_ID,
                    archive_bytes=RECORD["bytes"], image_bytes=4096,
                    receipt=RECEIPT, archive_record={**RECORD, "id": OTHER_ID},
                    current_manifest_sha256=MANIFEST,
                    progress=lambda _line: None)
            self.assertEqual(list(selected.iterdir()), [])
            self.assertEqual(transport.manager.calls, [])

    def test_export_portable_refuses_existing_or_symlink_destination(self):
        transport = Transport()
        transport.operations[REQUEST_ID] = operation("complete", archive=RECORD)
        transport.portable_requests.add(REQUEST_ID)
        transport.portable_receipt = RECEIPT.copy()
        transport.manager = StreamManager({"host": b"H" * RECORD["bytes"],
                                           "images": b"I" * 4096})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = root / "chosen"
            selected.mkdir()
            final = selected / ("sovagrid-backup-" + ARCHIVE_ID)
            final.mkdir()
            controller = HostBackupController(
                transport.options, transport=transport,
                approved_manifest_sha256=MANIFEST,
                request_store=HostBackupRequestStore(root / "requests"))
            with self.assertRaisesRegex(InstallError, "уже существует"):
                controller.export_portable(REQUEST_ID, selected)
            self.assertEqual(len(transport.manager.calls), 0)
            final.rmdir()
            try:
                final.symlink_to(root, target_is_directory=True)
            except OSError:
                if os.name == "nt":
                    return  # Windows may require Developer Mode for symlink creation.
                raise
            with self.assertRaisesRegex(InstallError, "уже существует"):
                controller.export_portable(REQUEST_ID, selected)
            final.unlink()
            linked_parent = root / "linked"
            linked_parent.symlink_to(selected, target_is_directory=True)
            with self.assertRaisesRegex(InstallError, "ссылку" if os.name == "nt" else "обычным каталогом"):
                controller.export_portable(REQUEST_ID, linked_parent)
            self.assertEqual(len(transport.manager.calls), 0)

    def test_windows_export_protects_empty_stage_and_files_before_streaming(self):
        host_bytes = b"H" * RECORD["bytes"]
        image_bytes = b"I" * 4096
        receipt = {**RECEIPT,
                   "host_archive_sha256": hashlib.sha256(host_bytes).hexdigest(),
                   "images_sha256": hashlib.sha256(image_bytes).hexdigest()}
        transport = Transport()
        payloads = portable_payloads(host_bytes, image_bytes, receipt)
        transport.manager = StreamManager(payloads)
        protected = []

        def protect(path, *, directory=False, sid=None):
            if directory:
                self.assertEqual(list(path.iterdir()), [])
            else:
                self.assertEqual(path.stat().st_size, 0)
            protected.append((path.name, directory, sid))
            return "current-user-sid"

        def publish(stage, final):
            self.assertFalse(os.path.lexists(final))
            self.assertEqual({item.name for item in stage.iterdir()},
                             set(transfer._filenames(ARCHIVE_ID)))
            stage.rename(final)

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            selected = Path(temporary) / "chosen"
            selected.mkdir()
            with patch.object(transfer, "_windows_protect", side_effect=protect), \
                 patch.object(transfer, "_windows_verify"), \
                 patch.object(transfer, "_windows_publish", side_effect=publish):
                result = transfer._export_windows(
                    transport, selected, archive_id=ARCHIVE_ID,
                    archive_bytes=RECORD["bytes"], image_bytes=4096,
                    receipt=receipt, archive_record=RECORD,
                    raw_receipt=json.dumps(receipt).encode(),
                    current_manifest_sha256=MANIFEST, progress=lambda _line: None)
            self.assertEqual(result.name, "sovagrid-backup-" + ARCHIVE_ID)
            self.assertEqual((result / (ARCHIVE_ID + ".tar.gz")).read_bytes(), host_bytes)
            self.assertEqual((result / "images.tar").read_bytes(), image_bytes)
            self.assertTrue(protected[0][0].startswith(".sovagrid-backup-" + ARCHIVE_ID))
            self.assertEqual([item[0] for item in protected[1:]],
                             list(transfer._filenames(ARCHIVE_ID)))
            self.assertTrue(protected[0][1])
            self.assertTrue(all(item[2] == "current-user-sid" for item in protected[1:]))

    def test_windows_export_cleans_failed_transfer_and_refuses_reparse_parent(self):
        host_bytes = b"H" * RECORD["bytes"]
        image_bytes = b"I" * 4096
        receipt = {**RECEIPT,
                   "host_archive_sha256": hashlib.sha256(host_bytes).hexdigest(),
                   "images_sha256": hashlib.sha256(image_bytes).hexdigest()}
        transport = Transport()
        original = portable_payloads(host_bytes, image_bytes, receipt)
        for payloads in ({**original, "images": b"X" * 4096},
                         {**original, "images_manifest":
                          (original["images_manifest"], 40)}):
            transport.manager = StreamManager(payloads)
            with self.subTest(payloads=payloads), \
                 tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
                root = Path(temporary)
                selected = root / "chosen"
                selected.mkdir()
                with patch.object(transfer, "_windows_protect",
                                  return_value="current-user-sid"), \
                     patch.object(transfer, "_windows_verify"), \
                     patch.object(transfer, "_windows_publish") as publish:
                    with self.assertRaises(InstallError):
                        transfer._export_windows(
                            transport, selected, archive_id=ARCHIVE_ID,
                            archive_bytes=RECORD["bytes"], image_bytes=4096,
                            receipt=receipt, archive_record=RECORD,
                            raw_receipt=json.dumps(receipt).encode(),
                            current_manifest_sha256=MANIFEST,
                            progress=lambda _line: None)
                    publish.assert_not_called()
                self.assertEqual(list(selected.iterdir()), [])
                linked = root / "linked"
                linked.symlink_to(selected, target_is_directory=True)
                with self.assertRaisesRegex(InstallError, "ссылку"):
                    transfer._windows_destination(linked)

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
