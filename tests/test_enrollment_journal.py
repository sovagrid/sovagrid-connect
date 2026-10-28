# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

import copy
import base64
import struct
from dataclasses import asdict
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.enrollment_journal import (EnrollmentJournal, EnrollmentJournalConflict,
    EnrollmentJournalError, MAX_BYTES)


def local_path(name):
    return str(Path.home() / "sovagrid-missing-fixture" / name)


def details():
    connection = asdict(ConnectionOptions(host="fixture.example", user="root", identity=local_path("ssh-key")))
    connection.pop("ssh_executable")
    return {"protocol": 1, "request_id": str(uuid.uuid4()), "name": "Целевой сервер", "phase": "prepared",
            "hub_connection": connection, "target_connection": copy.deepcopy(connection),
            "hub_endpoint": {"host": "192.0.2.40", "port": 22, "local_port": 18767},
            "bundle": {"path": local_path("sovagrid.tar.gz"), "sha256": "a" * 64},
            "target": None, "registration": None, "hub_trust": None,
            "hub_authorized": False, "cleanup_required": False,
            "cas": {"hub": None, "target": None}, "stage": None}


# Locally generated public certificate only; its ephemeral signing key was sent
# directly to /dev/null and is neither needed nor included in the repository.
PUBLIC_CA = """-----BEGIN CERTIFICATE-----
MIIC0DCCAbgCCQDHEQ79sy3OBDANBgkqhkiG9w0BAQsFADAqMSgwJgYDVQQDDB9z
b3ZhZ3JpZC1qb3VybmFsLXB1YmxpYy1maXh0dXJlMB4XDTI2MTAyNTEyMDgxNVoX
DTM2MTAyMjEyMDgxNVowKjEoMCYGA1UEAwwfc292YWdyaWQtam91cm5hbC1wdWJs
aWMtZml4dHVyZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJdXiC+8
pLgjBxXUee+NeEVgnstyWnR5oE4LvSIJm5vMnRB3n4AJ5vAV09BBNi8WDUuyjuby
H0yCJF0wbiEuBmueqjwD/M7N7v0gCLiNEA7cB1Ff5rIAJs4WOKyH+4AXuU8cMxma
jSX09gsv9S/aNiAXApPCAFc1uF/j3I4eGw6nokieBxRlQCOz5EuMsCoxKsOZEmqZ
QV6ocjL9VHobEdRdx13uojoqkKxClZ198bRqLYvxCGL6GYc3m3Ng/aUvznlS05Uu
PzVMACcdsxph+tZnL/S6m42axE57fm2Zc844ZewW7xYcj1RWg1mVVTo7RmjeTSPS
PdQpQ4l7FUo4bmcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAL4ucZB1FPhXOIZsv
GJPrIGs8spqO+O+UuL652O6ilqUBP1yz4MUZWpwi80153moxu83TbKbChGOK28sP
tMEeXdYuv7hcdDm65u6z/5X+my3qWMRshRhp3vkWkoeukfV2EiUjntREmOr8mtC2
4cHPlYphjCQe08mrk9UbAK3Lt1gi6X81R81xbDnrFvaKTdDaMK9t22pJ2JpDfdAt
+zzYcdH/yfu2vE3Im7oH+0Qxx/RH44glb/Ui1BIybxJCieJR5KbtZ5t2cLt/eWbv
T5T3sW9gJuixyvb5F1pVPsos8U0XQJBkmRforVm9LC7891Gn9vQOuNxIvhnhMeJS
zDMN0g==
-----END CERTIFICATE-----
"""
WIRE_KEY = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(WIRE_KEY).decode("ascii")
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(WIRE_KEY).digest()).decode("ascii").rstrip("=")

def target(value, *, partial=False):
    return {"request_id": value["request_id"], "enrollment_id": str(uuid.uuid4()),
            "server_id": str(uuid.uuid4()), "phase": "prepared",
            "agent_token_sha256": None if partial else "b" * 64,
            "ssh_public_key": None if partial else PUBLIC_KEY,
            "ssh_key_fingerprint": None if partial else FINGERPRINT, "local_port": None}


def _race_update(root, request_id, ready, release, output):
    journal = EnrollmentJournal(Path(root))
    ready.put(True); release.wait(5)
    try:
        result = journal.update(request_id, {"cleanup_required": True}, 1)
        output.put(("saved", result["revision"]))
    except EnrollmentJournalConflict:
        output.put(("conflict", None))
    except Exception as error:
        output.put(("error", type(error).__name__))


class EnrollmentJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # macOS /var and /tmp are platform symlinks; the explicitly selected
        # real temporary parent keeps the store's no-symlink policy meaningful.
        self.parent = Path(self.temporary.name).resolve()
        self.root = self.parent / "checkpoints"
        self.journal = EnrollmentJournal(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_restart_exact_public_metadata_and_missing_key_paths(self):
        source = details()
        record = self.journal.create(source)
        self.assertEqual(record["revision"], 1)
        self.assertEqual(record["created_at"], record["updated_at"])
        restarted = EnrollmentJournal(self.root)
        self.assertEqual(restarted.load(source["request_id"]), record)
        self.assertEqual(restarted.list(), [record])
        self.assertIsNone(restarted.load(str(uuid.uuid4())))
        source["name"] = "Caller changed dictionary"
        record["hub_connection"]["user"] = "another"
        self.assertEqual(restarted.load(record["request_id"])["hub_connection"]["user"], "root")
        self.assertFalse(Path(local_path("ssh-key")).exists())

    def test_default_folder_and_private_metadata(self):
        with patch("sovagrid_connect.enrollment_journal.preference_file", return_value=self.parent / "preferences.json"):
            journal = EnrollmentJournal()
        self.assertEqual(journal.root, self.parent / "agent-enrollments")
        record = journal.create(details())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(journal.root.stat().st_mode), 0o700)
            for path in (journal.root / ".lock", journal.root / (record["request_id"] + ".json")):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_uid, os.getuid())
        else:
            # This executes the real Win32 owner/protected-DACL validator in CI.
            journal._inspect(journal.root, directory=True)
            journal._inspect(journal.root / (record["request_id"] + ".json"))

    def test_revision_conflicts_duplicate_create_and_local_only_removal(self):
        record = self.journal.create(details()); rid = record["request_id"]
        with self.assertRaises(EnrollmentJournalConflict):
            self.journal.create({key: value for key, value in record.items() if key not in {"revision", "created_at", "updated_at"}})
        changed = self.journal.update(rid, {"cleanup_required": True}, 1)
        self.assertEqual(changed["revision"], 2)
        self.assertGreaterEqual(changed["updated_at"], changed["created_at"])
        for method in (lambda: self.journal.update(rid, {}, 1), lambda: self.journal.remove(rid, 1)):
            with self.assertRaises(EnrollmentJournalConflict):
                method()
        bundle = self.parent / "unrelated-source.tar.gz"; bundle.write_bytes(b"keep fixture")
        self.journal.remove(rid, 2)
        self.assertIsNone(self.journal.load(rid))
        self.assertEqual(bundle.read_bytes(), b"keep fixture")
        self.assertEqual(self.journal.list(), [])

    def test_parallel_processes_cannot_clobber_the_same_revision(self):
        record = self.journal.create(details())
        ctx = multiprocessing.get_context("spawn")
        ready, output, release = ctx.Queue(), ctx.Queue(), ctx.Event()
        workers = [ctx.Process(target=_race_update, args=(str(self.root), record["request_id"], ready, release, output)) for _ in range(2)]
        try:
            for worker in workers: worker.start()
            for _ in workers: self.assertTrue(ready.get(timeout=10))
            release.set()
            outcomes = sorted(output.get(timeout=10)[0] for _ in workers)
            self.assertEqual(outcomes, ["conflict", "saved"])
            self.assertEqual(self.journal.load(record["request_id"])["revision"], 2)
        finally:
            release.set()
            for worker in workers:
                worker.join(5)
                if worker.is_alive(): worker.terminate(); worker.join(5)

    def test_bounded_os_lock_rejects_a_busy_store(self):
        self.journal.create(details())
        with self.journal._locked(), patch("sovagrid_connect.enrollment_journal.LOCK_TIMEOUT", 0.05):
            with self.assertRaises(EnrollmentJournalConflict):
                EnrollmentJournal(self.root).list()

    def test_credential_fields_rejected_at_every_whitelisted_object_boundary(self):
        for location in (None, "hub_connection", "target_connection", "hub_endpoint", "bundle", "cas"):
            for key in ("password", "token", "private_key", "ssh_executable"):
                value = details()
                (value if location is None else value[location])[key] = "private-canary-never-save"
                with self.subTest(location=location, key=key), self.assertRaises(EnrollmentJournalError) as error:
                    self.journal.create(value)
                self.assertNotIn("private-canary", str(error.exception))
                self.assertFalse(self.root.exists())
        value = details(); value["name"] = "PRIVATE KEY canary"
        with self.assertRaises(EnrollmentJournalError): self.journal.create(value)

    def test_safe_syntax_and_endpoint_types_are_required(self):
        for path in ("relative-key", "/tmp/../secret", "/tmp/key\nsecret"):
            value = details(); value["target_connection"]["identity"] = path
            with self.subTest(path=repr(path)), self.assertRaises(EnrollmentJournalError): self.journal.create(value)
        for host in ("127.0.0.1", "::1", "0.0.0.0", "ff02::1", "::ffff:127.0.0.1", "::ffff:224.0.0.1", 123, True):
            value = details(); value["hub_endpoint"]["host"] = host
            with self.subTest(host=host), self.assertRaises(EnrollmentJournalError): self.journal.create(value)
        for key in ("port", "local_port"):
            value = details(); value["hub_endpoint"][key] = True
            with self.assertRaises(EnrollmentJournalError): self.journal.create(value)

    def test_immutable_endpoints_bundle_and_safe_local_path_repair(self):
        value = self.journal.create(details()); rid = value["request_id"]
        bad_changes = [{"request_id": str(uuid.uuid4())}, {"protocol": 2},
            {"revision": 99}, {"updated_at": 0}, {"hub_endpoint": value["hub_endpoint"] | {"port": 2222}},
            {"bundle": value["bundle"] | {"sha256": "b" * 64}},
            {"target_connection": value["target_connection"] | {"host": "other.example"}}]
        for changes in bad_changes:
            with self.subTest(fields=list(changes)), self.assertRaises(EnrollmentJournalError):
                self.journal.update(rid, changes, 1)
        repaired = self.journal.update(rid, {"target_connection": value["target_connection"] | {"identity": local_path("new-key")},
                                           "bundle": value["bundle"] | {"path": local_path("relocated.tar.gz")}}, 1)
        self.assertEqual(repaired["target_connection"]["identity"], local_path("new-key"))
        self.assertEqual(repaired["revision"], 2)

    def test_capacity_and_file_size_are_bounded_without_replacing_other_records(self):
        first = self.journal.create(details())
        with patch("sovagrid_connect.enrollment_journal.MAX_RECORDS", 1), self.assertRaises(EnrollmentJournalConflict):
            self.journal.create(details())
        self.assertEqual(self.journal.list(), [first])
        path = self.root / (first["request_id"] + ".json")
        path.write_bytes(b" " * (MAX_BYTES + 1))
        with self.assertRaises(EnrollmentJournalError): self.journal.load(first["request_id"])

    def test_oversized_valid_public_metadata_never_creates_a_record(self):
        value = details()
        long_path = str(Path.home() / ("a" * (3900 - len(str(Path.home())))))
        value["bundle"]["path"] = long_path
        for side in ("hub_connection", "target_connection"):
            value[side].update(identity=long_path, jump_identity=long_path,
                               jump_host="relay.example", jump_user="root")
        value["hub_trust"] = {"hub_host_key": PUBLIC_KEY, "hub_ca_pem": PUBLIC_CA * 13}
        self.assertLessEqual(len(value["hub_trust"]["hub_ca_pem"].encode()), 16384)
        self.assertGreater(len(json.dumps(value).encode()), MAX_BYTES)
        with self.assertRaises(EnrollmentJournalError): self.journal.create(value)
        self.assertFalse(self.root.exists())

    def test_stage_checkpoint_before_upload_and_strict_public_nested_objects(self):
        value = details(); stage_id = uuid.uuid4().hex
        value["stage"] = {"remote_dir": "/var/tmp/sovagrid-agent-enroll." + stage_id, "stage_id": stage_id,
            "sha256": value["bundle"]["sha256"], "source_manifest_sha256": "b" * 64, "helper_sha256": "c" * 64}
        value["hub_trust"] = {"hub_host_key": PUBLIC_KEY, "hub_ca_pem": PUBLIC_CA}
        value["cas"] = {side: {field: "d" * 64 for field in
            ("source_manifest_sha256", "features_sha256", "policy_sha256", "state_sha256")} for side in ("hub", "target")}
        self.assertEqual(self.journal.create(value)["stage"], value["stage"])
        for location in ("stage", "hub_trust"):
            bad = copy.deepcopy(value); bad["request_id"] = str(uuid.uuid4())
            bad[location]["password"] = "private-fixture-canary"
            with self.subTest(location=location), self.assertRaises(EnrollmentJournalError): self.journal.create(bad)
        for change in ({"remote_dir": "/tmp/elsewhere"}, {"stage_id": str(uuid.uuid4())}, {"sha256": "e" * 64}):
            bad = copy.deepcopy(value); bad["request_id"] = str(uuid.uuid4()); bad["stage"].update(change)
            with self.assertRaises(EnrollmentJournalError): self.journal.create(bad)
        bad = copy.deepcopy(value); bad["hub_trust"]["hub_ca_pem"] = PUBLIC_CA + "\nPRIVATE KEY canary"
        with self.assertRaises(EnrollmentJournalError): self.journal.create(bad)

    def test_partial_prepared_can_fill_once_and_assigned_identity_pins_cannot_change(self):
        value = details(); value["target"] = target(value, partial=True)
        initial = self.journal.create(value)
        complete = initial["target"] | {"agent_token_sha256": "b" * 64, "ssh_public_key": PUBLIC_KEY, "ssh_key_fingerprint": FINGERPRINT}
        record = self.journal.update(value["request_id"], {"target": complete}, 1)
        self.assertEqual(record["target"], complete)
        for field, new in (("enrollment_id", str(uuid.uuid4())), ("server_id", str(uuid.uuid4())),
                           ("agent_token_sha256", "e" * 64), ("ssh_public_key", None)):
            changed = complete | {field: new}
            if field == "ssh_public_key": changed["ssh_key_fingerprint"] = None
            with self.subTest(field=field), self.assertRaises(EnrollmentJournalError):
                self.journal.update(value["request_id"], {"target": changed}, 2)
        with self.assertRaises(EnrollmentJournalError):
            self.journal.update(value["request_id"], {"target": None}, 2)
        ready = complete | {"phase": "transport_ready", "local_port": value["hub_endpoint"]["local_port"]}
        record = self.journal.update(value["request_id"], {"target": ready, "phase": "transport_ready"}, 2)
        with self.assertRaises(EnrollmentJournalError):
            self.journal.update(value["request_id"], {"phase": "prepared", "target": complete}, 3)
        broken = details(); broken["target"] = target(broken, partial=True) | {"phase": "transport_ready", "local_port": 18767}
        broken["phase"] = "transport_ready"
        with self.assertRaises(EnrollmentJournalError): self.journal.create(broken)

    def test_trust_is_immutable_and_registration_is_bound_to_target_and_active_sample(self):
        value = details(); value["target"] = target(value)
        value["hub_trust"] = {"hub_host_key": PUBLIC_KEY, "hub_ca_pem": PUBLIC_CA}
        record = self.journal.create(value); rid = value["request_id"]
        with self.assertRaises(EnrollmentJournalError): self.journal.update(rid, {"hub_trust": None}, 1)
        # Extra trailing whitespace is still a valid CA bundle, but changing an
        # already confirmed pin requires a new operation, even whitespace.
        with self.assertRaises(EnrollmentJournalError):
            self.journal.update(rid, {"hub_trust": value["hub_trust"] | {"hub_ca_pem": PUBLIC_CA + "\n"}}, 1)
        registration = {"id": value["target"]["enrollment_id"], "server_id": value["target"]["server_id"],
            "name": value["name"], "state": "pending", "revision": 1, "created_at": 100, "last_seen": None}
        for changed in (registration | {"server_id": str(uuid.uuid4())}, registration | {"token": "private-fixture-canary"}):
            with self.assertRaises(EnrollmentJournalError): self.journal.update(rid, {"registration": changed}, 1)
        active_target = value["target"] | {"phase": "active", "local_port": 18767}
        with self.assertRaises(EnrollmentJournalError):
            self.journal.update(rid, {"registration": registration, "phase": "active", "target": active_target}, 1)
        active = registration | {"state": "active", "last_seen": 101}
        done = self.journal.update(rid, {"registration": active, "phase": "active", "target": active_target}, 1)
        self.assertEqual(done["phase"], "active")

    def test_failed_replace_keeps_last_checkpoint_and_cleans_own_temporary(self):
        first = self.journal.create(details()); rid = first["request_id"]
        with patch("sovagrid_connect.enrollment_journal.os.replace", side_effect=OSError("private-os-canary")):
            if os.name == "nt": self.skipTest("Windows uses write-through MoveFileExW")
            with self.assertRaises(EnrollmentJournalError) as error:
                self.journal.update(rid, {"cleanup_required": True}, 1)
        self.assertNotIn("private-os-canary", str(error.exception))
        self.assertEqual(self.journal.load(rid), first)
        self.assertFalse(list(self.root.glob(".enrollment-*")))

    def test_malformed_json_duplicate_fields_and_filename_binding_are_rejected(self):
        record = self.journal.create(details()); path = self.root / (record["request_id"] + ".json")
        for raw in (b'{"protocol":1,"protocol":1}', b'[]', b'null', b'{', b'[' * 2000 + b']' * 2000):
            path.write_bytes(raw)
            with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])
        wrong = dict(record, request_id=str(uuid.uuid4()))
        path.write_text(json.dumps(wrong))
        with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])

    def test_record_and_lock_hardlinks_are_rejected_on_all_platforms(self):
        record = self.journal.create(details()); path = self.root / (record["request_id"] + ".json")
        outside = self.parent / "linked-fixture.json"
        os.link(path, outside)
        with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])
        outside.unlink()
        lock = self.root / ".lock"; outside = self.parent / "linked-fixture.lock"
        os.link(lock, outside)
        with self.assertRaises(EnrollmentJournalError): self.journal.list()
        self.assertTrue(lock.exists()); self.assertTrue(outside.exists())

    @unittest.skipUnless(os.name == "nt", "Native Windows current-user ACL regression")
    def test_windows_refuses_an_extra_everyone_read_ace(self):
        import subprocess
        from sovagrid_connect.keygen import _windows_tool
        self.journal.create(details())
        result = subprocess.run([_windows_tool("icacls.exe"), str(self.root), "/grant", "*S-1-1-0:(OI)(CI)R"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0)
        with self.assertRaises(EnrollmentJournalError): self.journal.list()

    @unittest.skipIf(os.name == "nt", "POSIX ownership and mode checks")
    def test_unsafe_permissions_owner_symlinks_and_hardlinks_are_not_followed(self):
        record = self.journal.create(details()); path = self.root / (record["request_id"] + ".json")
        original = path.read_bytes()
        path.chmod(0o644)
        with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])
        path.chmod(0o600)
        with patch("sovagrid_connect.enrollment_journal.os.getuid", return_value=os.getuid() + 1):
            with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])
        outside = self.parent / "outside.json"; outside.write_bytes(original); outside.chmod(0o600)
        path.unlink(); path.symlink_to(outside)
        with self.assertRaises(EnrollmentJournalError): self.journal.load(record["request_id"])
        self.assertEqual(outside.read_bytes(), original)
        path.unlink(); os.link(outside, path)
        with self.assertRaises(EnrollmentJournalError): self.journal.remove(record["request_id"], 1)
        self.assertEqual(outside.stat().st_nlink, 2)
        alias = self.parent / "alias"; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(EnrollmentJournalError): EnrollmentJournal(alias).list()
        self.root.chmod(0o755)
        with self.assertRaises(EnrollmentJournalError): self.journal.list()


if __name__ == "__main__":
    unittest.main()
