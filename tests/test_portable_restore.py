# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Real binary framing, stable local inputs and durable restore pointers."""
from copy import deepcopy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.auto_update import target_id
from sovagrid_connect.installer import InstallError
from sovagrid_connect.portable_restore import (
    CHUNK, PROTOCOL, ORDER, PortableArtifacts, PortableRestoreController,
    RestoreRecordStore, RestoreSSHStream, _canonical)


ID = "b" * 32
OP = "d" * 32


def files(directory):
    host, images = bytes(range(256)) * 8, b"image\x00\xff\n" * 1000
    receipt = {
        "protocol": "sovagrid-portable-host-receipt-v2", "host_archive_id": ID,
        "host_archive_sha256": hashlib.sha256(host).hexdigest(),
        "images_sha256": hashlib.sha256(images).hexdigest(), "source_manifest_sha256": "a" * 64,
        "images": {"hub": "sha256:" + "3" * 64, "web": "sha256:" + "4" * 64},
        "container_ids": {"hub": "5" * 64, "web": "6" * 64},
        "exported_configs": {"hub": "sha256:" + "7" * 64, "web": "sha256:" + "8" * 64},
        "rootfs_sha256": {"hub": "9" * 64, "web": "a" * 64},
        "active_units": ["sovagrid-release-feed.timer"],
        "unit_hashes": {"sovagrid-release-feed.timer": "b" * 64},
        "unit_states": {"sovagrid-release-feed.timer": {
            "active": True, "enablement": "enabled", "sha256": "b" * 64}},
    }
    manifest = {"protocol": "sovagrid-host-backup-v1", "id": ID, "layout": "full",
                "created_at": "2026-10-27T12:00:00+00:00", "bytes": len(host), "files": 13,
                "sha256": receipt["host_archive_sha256"], "source_manifest_sha256": "a" * 64}
    image_manifest = {"protocol": "sovagrid-host-images-v1", "id": ID, "layout": "full",
                      "created_at": "2026-10-27T12:00:00+00:00", "bytes": len(images), "files": 17,
                      "host_archive_sha256": receipt["host_archive_sha256"],
                      "sha256": receipt["images_sha256"], "source_manifest_sha256": "a" * 64,
                      **{key: receipt[key] for key in
                         ("images", "container_ids", "exported_configs", "rootfs_sha256")}}
    values = {"receipt.json": _canonical(receipt), ID + ".manifest.json": _canonical(manifest),
              ID + ".tar.gz": host, "manifest.json": _canonical(image_manifest), "images.tar": images}
    for name, raw in values.items():
        path = directory / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return receipt


def record(options, directory):
    with PortableArtifacts(directory) as parts:
        request = {"protocol": PROTOCOL, "operation_id": OP, "archive_id": ID,
                   "runner_manifest_sha256": "1" * 64, "runner_archive_sha256": "2" * 64,
                   "artifacts": deepcopy(parts.metadata)}
    return {"format": 1, "target_id": target_id(options), "operation_id": OP,
            "created_at": 1800000000, "folder": str(directory),
            "runner_path": str(directory / "runner.tar.gz"), "request": request}


class LocalRestoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sovagrid restore inputs ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipt = files(self.root)

    def test_all_five_inputs_are_hashed_and_binary_reads_keep_the_exact_bytes(self):
        with PortableArtifacts(self.root) as parts:
            self.assertEqual(parts.archive_id, ID)
            self.assertEqual(set(parts.files), set(ORDER))
            expected = (self.root / "images.tar").read_bytes()
            self.assertEqual(parts.read_chunk("images", 3, 4000), expected[3:4003])
            self.assertEqual(parts.metadata["images"]["sha256"], hashlib.sha256(expected).hexdigest())

    def test_modified_input_after_review_is_refused_before_its_next_chunk(self):
        with PortableArtifacts(self.root) as parts:
            with (self.root / "images.tar").open("r+b") as stream:
                stream.write(b"changed")
                stream.flush()
                os.fsync(stream.fileno())
            with self.assertRaises(InstallError):
                parts.read_chunk("images", 0, 10)

    def test_corruption_and_v1_copy_are_rejected_locally(self):
        (self.root / "images.tar").write_bytes(b"wrong image")
        with self.assertRaises(InstallError):
            with PortableArtifacts(self.root):
                pass
        files(self.root)
        self.receipt["protocol"] = "sovagrid-portable-host-receipt-v1"
        (self.root / "receipt.json").write_bytes(_canonical(self.receipt))
        with self.assertRaisesRegex(InstallError, "v2"):
            with PortableArtifacts(self.root):
                pass

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symbolic links")
    def test_link_instead_of_an_artifact_is_refused(self):
        original = self.root / "images.tar"
        copied = self.root / "image-copy.tar"
        original.rename(copied)
        try:
            original.symlink_to(copied.name)
        except OSError:
            self.skipTest("symlink permission unavailable")
        with self.assertRaises(InstallError):
            with PortableArtifacts(self.root):
                pass

    def test_record_is_atomic_immutable_and_bound_to_the_selected_route(self):
        options = ConnectionOptions("server.example.org", user="ubuntu").validated()
        value = record(options, self.root)
        store = RestoreRecordStore(self.root / "operations")
        store.save(value)
        store.save(value)
        self.assertEqual(store.load(OP), value)
        self.assertEqual(store.for_target(options), [value])
        self.assertEqual(store.for_target(ConnectionOptions("other.example.org", user="ubuntu").validated()), [])
        self.assertEqual(sorted(path.name for path in store.directory.iterdir()), [OP + ".json"])
        if os.name != "nt":
            self.assertEqual((store.directory / (OP + ".json")).stat().st_mode & 0o777, 0o600)
        changed = deepcopy(value)
        changed["request"]["runner_archive_sha256"] = "3" * 64
        with self.assertRaises(InstallError):
            store.save(changed)
        self.assertEqual(store.load(OP), value)
        changed = deepcopy(value)
        changed["password"] = "must never be persisted"
        with self.assertRaises(InstallError):
            store.save(changed)

    def test_transfer_ack_cannot_move_the_cursor_outside_a_bound_file(self):
        value = record(ConnectionOptions("server.example.org", user="ubuntu").validated(), self.root)
        request = value["request"]
        reply = {"request_sha256": hashlib.sha256(_canonical(request)).hexdigest(), "archive_id": ID,
                 "registered": False, "max_chunk_bytes": CHUNK,
                 "artifacts": {part: {**meta, "received": 0, "complete": False}
                               for part, meta in request["artifacts"].items()}}
        PortableRestoreController._transfer_state(reply, request)
        for bad in (True, -1, reply["artifacts"]["host"]["bytes"] + 1):
            changed = deepcopy(reply)
            changed["artifacts"]["host"]["received"] = bad
            with self.assertRaises(InstallError):
                PortableRestoreController._transfer_state(changed, request)
        reply["registered"] = True
        with self.assertRaises(InstallError):
            PortableRestoreController._transfer_state(reply, request)

    def test_cancel_during_hashing_cannot_start_the_remote_bootstrap(self):
        calls = []
        controller = PortableRestoreController(
            ConnectionOptions("server.example.org", user="ubuntu"), approved_archive_sha256="a" * 64,
            popen=lambda *args, **kwargs: calls.append(args))
        controller.progress = lambda _message: controller.cancel()
        with self.assertRaisesRegex(InstallError, "отменена"):
            controller.prepare(self.root, self.root / "not-opened.tar.gz")
        self.assertEqual(calls, [])

    def test_trusted_server_paths_can_supply_split_artifacts_without_bulk_spool_copy(self):
        names = {"host_manifest": ID + ".manifest.json", "host": ID + ".tar.gz",
                 "images_manifest": "manifest.json", "images": "images.tar", "receipt": "receipt.json"}
        mapping = {}
        for part, name in names.items():
            directory = self.root / part
            directory.mkdir()
            target = directory / name
            (self.root / name).rename(target)
            mapping[part] = target
        with PortableArtifacts(self.root / "not-a-co-location-directory", source_paths=mapping) as parts:
            self.assertEqual(parts.archive_id, ID)
            self.assertEqual(parts.read_chunk("images", 0, 8), mapping["images"].read_bytes()[:8])

    def test_stable_pinned_route_digest_can_survive_ephemeral_web_key_paths(self):
        key = self.root / "new-key"
        key.write_bytes(b"private fixture, not used for authentication")
        key.chmod(0o600)
        options = ConnectionOptions("server.example.org", user="ubuntu", identity=str(key))
        value = record(options, self.root)
        stable = "f" * 64
        value["target_id"] = stable
        controller = PortableRestoreController(options, approved_archive_sha256="a" * 64, record_target_id=stable)
        calls = []

        @contextmanager
        def connection(identity):
            calls.append(identity)
            yield types.SimpleNamespace(request=lambda *args, **kwargs: {
                "archive_id": ID, "request_sha256": hashlib.sha256(_canonical(value["request"])).hexdigest(),
                "phase": "ready", "backend_supported": False, "target_ready": False,
                "apply_available": False, "blockers": ["APPLY_NOT_IMPLEMENTED"]})

        controller.connection = connection
        self.assertEqual(controller.action(value, "operation-status")["phase"], "ready")
        self.assertEqual(calls, [OP])
        controller.record_target_id = "e" * 64
        with self.assertRaises(InstallError):
            controller.action(value, "operation-status")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_regular_to_fifo_swap_refuses_without_blocking_before_fstat(self):
        program = r'''
import os,sys
from pathlib import Path
from sovagrid_connect.portable_restore import PortableArtifacts,InstallError
original=os.open
def changed(path,flags,*args,**kwargs):
    if Path(path).name=='images.tar':
        os.unlink(path);os.mkfifo(path)
    return original(path,flags,*args,**kwargs)
os.open=changed
try:
    with PortableArtifacts(Path(sys.argv[1])): pass
except InstallError:
    raise SystemExit(0)
raise SystemExit(9)
'''
        result = subprocess.run([sys.executable, "-c", program, str(self.root)],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


SERVER = r'''
import sys,json,hashlib
identity=sys.argv[1]
sequence=0
while True:
    line=sys.stdin.buffer.readline()
    if not line: break
    frame=json.loads(line)
    raw=b''
    while len(raw)<frame.get('length',0):
        block=sys.stdin.buffer.read(frame['length']-len(raw))
        if not block: raise SystemExit(7)
        raw+=block
    sequence+=1
    answer={'ok':True,'protocol':'sovagrid-portable-restore-target-v1','operation_id':identity,
            'sequence':sequence,'received':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    print(json.dumps(answer),flush=True)
'''


class FramedSSHTests(unittest.TestCase):
    def child(self, program=SERVER, identity=OP):
        process = subprocess.Popen([sys.executable, "-u", "-c", program, identity],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   bufsize=0)

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()

        self.addCleanup(cleanup)
        return process

    def test_multiple_binary_frames_share_one_process_without_eof_between_chunks(self):
        channel = RestoreSSHStream(self.child(), OP)
        payload = bytes(range(256)) * 1000
        for number in (1, 2):
            reply = channel.request({"action": "receive", "length": len(payload)}, payload)
            self.assertEqual(reply["sequence"], number)
            self.assertEqual(reply["received"], len(payload))
            self.assertEqual(reply["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertIsNone(channel.process.poll())

    def test_other_operation_and_unbounded_error_text_are_refused(self):
        with self.assertRaises(InstallError):
            RestoreSSHStream(self.child(identity="c" * 32), OP).request({"action": "status"})
        program = "import json;print(json.dumps({'ok':False,'protocol':" + repr(PROTOCOL) + "," \
                  "'operation_id':" + repr(OP) + ",'error':'private/password/path'}),flush=True)"
        with self.assertRaisesRegex(InstallError, "некорректный"):
            RestoreSSHStream(self.child(program), OP).request({"action": "status"})

    def test_timeout_terminates_blocked_child_and_preserves_resume_error(self):
        process = self.child("import time;time.sleep(30)")
        with self.assertRaisesRegex(InstallError, "вовремя"):
            RestoreSSHStream(process, OP).request({"action": "status"}, timeout=0.1)
        process.wait(timeout=5)
        self.assertIsNotNone(process.returncode)

    def controller(self, program=SERVER):
        controller = PortableRestoreController(ConnectionOptions("server.example.org", user="ubuntu"),
                                               approved_archive_sha256="a" * 64)

        @contextmanager
        def session():
            yield "config", "helper"

        calls = []

        def start(*args, **kwargs):
            calls.append((args, kwargs))
            process = self.child(program)
            controller.manager._process = process
            return process

        controller.manager._session = session
        controller.manager._ssh = start
        self.addCleanup(controller.cancel)
        return controller, calls

    def test_review_and_later_polls_reuse_the_authenticated_process(self):
        controller, calls = self.controller()
        for expected in (1, 2, 3):
            with controller.connection(OP) as channel:
                reply = channel.request({"action": "status"})
                self.assertEqual(reply["sequence"], expected)
        self.assertEqual(len(calls), 1)
        process = controller._channel.process
        controller.cancel()
        self.assertIsNotNone(process.poll())

    def test_closing_during_blocked_request_reaps_process_and_allows_worker_to_finish(self):
        controller, calls = self.controller("import time;time.sleep(30)")
        waiting = threading.Event()
        errors = []

        def worker():
            try:
                with controller.connection(OP) as channel:
                    waiting.set()
                    channel.request({"action": "status"}, timeout=10)
            except InstallError as error:
                errors.append(error)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        self.assertTrue(waiting.wait(3))
        controller.cancel()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsNone(controller._channel)

    def test_wrong_binary_length_does_not_send_even_a_partial_frame(self):
        channel = RestoreSSHStream(self.child(), OP)
        with self.assertRaises(InstallError):
            channel.request({"action": "receive", "length": 8}, b"short")
        self.assertEqual(channel.request({"action": "status"})["sequence"], 1)


if __name__ == "__main__":
    unittest.main()
