# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root policy transaction and Connect CAS tests without touching a server."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from sovagrid_connect.container_action_setup import (ContainerActionSetupController,
                                                     ContainerCandidate, policy_bytes)
from sovagrid_connect.container_action_setup_remote import SCRIPT
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError


MANIFEST = "a" * 64
IDENT = "1" * 64
IMAGE_ID = "sha256:" + "2" * 64
CANDIDATE = {"id": IDENT, "name": "web-api", "image_id": IMAGE_ID,
             "image": "example/web-api:1", "state": "running"}
SELECTED = {IDENT: {"status", "restart"}}


class FakeBroker:
    MAX_POLICY_BYTES = 8192
    MAX_CONTAINERS = 16

    def parse_policy(self, raw):
        value = json.loads(raw)
        if set(value) != {"version", "containers"} or value["version"] != 1:
            raise ValueError("invalid policy")
        entries = value["containers"]
        if not 1 <= len(entries) <= 16:
            raise ValueError("invalid entries")
        result = {}
        for entry in entries:
            if set(entry) != {"id", "name", "image_id", "actions"} or entry["id"] in result:
                raise ValueError("invalid entry")
            result[entry["id"]] = {"name": entry["name"], "image_id": entry["image_id"],
                                    "actions": frozenset(entry["actions"])}
        return result

    def read_policy(self, policy, enabled):
        if enabled.read_bytes() != b"enabled\n":
            raise PermissionError("disabled")
        for path in (policy, enabled):
            info = path.lstat()
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise PermissionError("mode")
        return self.parse_policy(policy.read_bytes())


class Harness:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.broker = FakeBroker()
        self.namespace = {"__name__": "container_action_remote_test"}
        exec(compile(SCRIPT, "<container-action-remote>", "exec"), self.namespace)
        self.namespace["CONFIGS"] = {"default": self.base / "default",
                                     "local": self.base / "local"}
        self.namespace["LOCK"] = self.base / "setup.lock"
        self.real_source = self.namespace["source"]
        self.namespace["source"] = lambda _manifest, _profile: self.broker
        self.candidates = [dict(CANDIDATE)]
        self.real_catalog = self.namespace["catalog"]
        self.namespace["catalog"] = lambda _broker, _profile: (list(self.candidates), 0)

        # The real helper requires root-owned files. For a developer test run
        # without sudo, retain all mode/link checks while mapping owner to the
        # current test user only inside this isolated namespace.
        uid, gid = os.getuid(), os.getgid()

        def test_directory(path, exact=False):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid or
                    (stat.S_IMODE(info.st_mode) != 0o700 if exact else bool(info.st_mode & 0o022))):
                raise self.namespace["Refusal"]("UNSAFE_PATH")

        def test_regular(path, modes, maximum):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) not in modes or
                    not 0 < info.st_size <= maximum):
                raise self.namespace["Refusal"]("UNSAFE_PATH")
            return path.read_bytes()

        self.namespace["directory"] = test_directory
        self.namespace["regular"] = test_regular

        def test_atomic(path, raw):
            # Production's fchown(0,0) requires root. Keep its fsync/replace
            # path and substitute a user-owned 0600 file in this test fixture.
            import os
            import tempfile as std_tempfile
            fd, name = std_tempfile.mkstemp(prefix=".sovagrid-", dir=path.parent)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, path)
                self.namespace["fsync_dir"](path.parent)
            finally:
                if os.path.exists(name):
                    os.unlink(name)

        self.namespace["atomic"] = test_atomic
        def test_create_config(config):
            config.mkdir(mode=0o700)
            config.chmod(0o700)
            self.namespace["fsync_dir"](config.parent)

        self.namespace["create_config"] = test_create_config

        def test_lock():
            import os
            import fcntl
            fd = os.open(self.namespace["LOCK"], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(fd)
            if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
                os.close(fd)
                raise self.namespace["Refusal"]("UNSAFE_PATH")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd

        self.namespace["lock"] = test_lock
        self.calls = []
        self.lost_arm_reply = False
        self.lost_finalize_reply = False
        self.lost_clear_reply = False

    def close(self):
        self.temporary.cleanup()

    def execute(self, command, *, data=None, timeout, limit=4096):
        self.calls.append((command, data, timeout, limit))
        parts = shlex.split(command)
        action, profile, manifest, revision, token = parts[-5:]
        try:
            result = self.namespace["run"](action, profile, manifest, revision, token, data or b"")
        except self.namespace["Refusal"] as exc:
            return 40, json.dumps({"ok": False, "error": str(exc)}).encode()
        if action == "preview":
            result["plan"]["config_path"] = ("/etc/sovagrid-container-actions-local"
                                              if profile == "local" else
                                              "/etc/sovagrid-container-actions")
        if action == "arm" and self.lost_arm_reply:
            self.lost_arm_reply = False
            raise TimeoutError("SSH response lost after commit")
        if action == "finalize" and self.lost_finalize_reply:
            self.lost_finalize_reply = False
            raise TimeoutError("SSH response lost after finalization")
        if action == "clear" and self.lost_clear_reply:
            self.lost_clear_reply = False
            raise TimeoutError("SSH response lost after clear")
        raw = json.dumps(result).encode()
        if len(raw) > limit:
            return 41, b""
        return 0, raw


class Transport:
    def __init__(self, harness, user="root"):
        self.harness = harness
        self.options = ConnectionOptions("ubuntu.example.org", user=user).validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.proofs = 0

    def _verify_root_access(self):
        self.proofs += 1

    def _execute(self, *args, **kwargs):
        return self.harness.execute(*args, **kwargs)


@unittest.skipUnless(os.name == "posix", "Ubuntu root broker fixture requires POSIX APIs")
class ContainerActionSetupTests(unittest.TestCase):
    def setUp(self):
        self.harness = Harness()
        self.addCleanup(self.harness.close)

    def controller(self, approved=MANIFEST, user="root"):
        transport = Transport(self.harness, user)
        return ContainerActionSetupController(transport.options, transport=transport,
                                              approved_manifest_sha256=approved), transport

    def test_pin_blocks_unapproved_release_before_ssh(self):
        controller, transport = self.controller(None)
        with self.assertRaisesRegex(InstallError, "проверенный"):
            controller.inspect("default")
        self.assertEqual(transport.proofs, 0)
        self.assertEqual(self.harness.calls, [])

    def test_exact_root_ssh_policy_arm_and_disarm(self):
        controller, transport = self.controller(user="admin")
        inspected = controller.inspect("default")
        self.assertFalse(inspected.armed)
        self.assertEqual(inspected.catalog[0].ident, IDENT)
        reviewed = controller.plan("default", SELECTED)
        self.assertEqual(reviewed.plan[0], "/etc/sovagrid-container-actions")
        enabled = controller.arm(reviewed, SELECTED)
        self.assertTrue(enabled.armed)
        self.assertEqual(enabled.policy[0][0], IDENT)
        config = self.harness.base / "default"
        self.assertEqual((config / "enabled").read_bytes(), b"enabled\n")
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((config / "policy.json").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((config / "enabled").stat().st_mode), 0o600)
        self.assertFalse((config / "setup-transaction").exists())
        self.assertFalse(controller.disarm(enabled).armed)
        self.assertFalse((config / "enabled").exists())
        self.assertTrue((config / "policy.json").exists())
        self.assertTrue(all("sudo -n -- /usr/bin/python3 -I -B -S -c" in call[0]
                            for call in self.harness.calls))
        self.assertGreater(transport.proofs, 0)

    def test_local_profile_is_separate(self):
        controller, _transport = self.controller()
        local = controller.arm(controller.plan("local", SELECTED), SELECTED)
        self.assertTrue(local.armed)
        self.assertFalse((self.harness.base / "default").exists())
        self.assertEqual((self.harness.base / "local" / "enabled").read_bytes(), b"enabled\n")
        self.assertFalse(controller.inspect("default").armed)

    def test_clear_removes_only_disarmed_saved_policy(self):
        controller, _transport = self.controller()
        default = controller.arm(controller.plan("default", SELECTED), SELECTED)
        local = controller.arm(controller.plan("local", SELECTED), SELECTED)
        disabled = controller.disarm(default)
        self.assertIsNotNone(disabled.policy_raw)
        cleared = controller.clear(disabled)
        self.assertFalse(cleared.armed or cleared.transaction_pending)
        self.assertIsNone(cleared.policy_raw)
        self.assertFalse((self.harness.base / "default").exists())
        self.assertTrue((self.harness.base / "local" / "enabled").exists())
        with self.assertRaises(InstallError):
            controller.clear(local)

    def test_clear_cas_refuses_changed_policy_and_pending_transaction(self):
        controller, _transport = self.controller()
        active = controller.arm(controller.plan("default", SELECTED), SELECTED)
        disabled = controller.disarm(active)
        config = self.harness.base / "default"
        changed = policy_bytes((ContainerCandidate(IDENT, "web-api", IMAGE_ID,
                                                   "example/web-api:1", "running"),),
                               {IDENT: {"status"}})
        (config / "policy.json").write_bytes(changed)
        with self.assertRaisesRegex(InstallError, "изменились"):
            controller.clear(disabled)
        self.assertEqual((config / "policy.json").read_bytes(), changed)
        transaction = config / "setup-transaction"
        transaction.write_bytes(b"{}")
        transaction.chmod(0o600)
        with self.assertRaises(InstallError):
            controller.clear(controller.status("default"))
        self.assertEqual((config / "policy.json").read_bytes(), changed)

    def test_lost_clear_reply_confirms_without_retry(self):
        controller, _transport = self.controller()
        active = controller.arm(controller.plan("default", SELECTED), SELECTED)
        disabled = controller.disarm(active)
        self.harness.lost_clear_reply = True
        cleared = controller.clear(disabled)
        self.assertIsNone(cleared.policy_raw)
        self.assertEqual(sum(shlex.split(command)[-5] == "clear"
                             for command, _data, _timeout, _limit in self.harness.calls), 1)

    def test_changed_identity_before_arm_never_writes(self):
        controller, _transport = self.controller()
        reviewed = controller.plan("default", SELECTED)
        self.harness.candidates = [dict(CANDIDATE, image_id="sha256:" + "3" * 64)]
        with self.assertRaises(InstallError):
            controller.arm(reviewed, SELECTED)
        self.assertFalse((self.harness.base / "default").exists())

    def test_cas_rejects_stale_policy_without_overwrite(self):
        controller, _transport = self.controller()
        reviewed = controller.plan("default", SELECTED)
        config = self.harness.base / "default"
        config.mkdir(mode=0o700)
        (config / "policy.json").write_bytes(policy_bytes((ContainerCandidate(**{
            "ident": IDENT, "name": "web-api", "image_id": IMAGE_ID,
            "image": "example/web-api:1", "state": "running"}),), {IDENT: {"status"}}))
        (config / "policy.json").chmod(0o600)
        with self.assertRaisesRegex(InstallError, "изменились"):
            controller.arm(reviewed, SELECTED)
        self.assertFalse((config / "enabled").exists())

    def test_symlinked_policy_is_rejected_without_following_it(self):
        controller, _transport = self.controller()
        config = self.harness.base / "default"
        config.mkdir(mode=0o700)
        outside = self.harness.base / "outside.json"
        outside.write_text("keep", encoding="ascii")
        (config / "policy.json").symlink_to(outside)
        with self.assertRaisesRegex(InstallError, "небезопасны"):
            controller.inspect("default")
        self.assertEqual(outside.read_text(encoding="ascii"), "keep")
        self.assertFalse((config / "enabled").exists())

    def test_lost_arm_ack_rolls_back_to_previous_policy(self):
        controller, _transport = self.controller()
        first = controller.arm(controller.plan("default", {IDENT: {"status"}}),
                               {IDENT: {"status"}})
        controller.disarm(first)
        previous = (self.harness.base / "default" / "policy.json").read_bytes()
        reviewed = controller.plan("default", SELECTED)
        self.harness.lost_arm_reply = True
        with self.assertRaisesRegex(InstallError, "восстановлены"):
            controller.arm(reviewed, SELECTED)
        config = self.harness.base / "default"
        self.assertEqual((config / "policy.json").read_bytes(), previous)
        self.assertFalse((config / "enabled").exists())
        self.assertFalse((config / "setup-transaction").exists())

    def test_lost_finalize_ack_is_confirmed_by_status(self):
        controller, _transport = self.controller()
        reviewed = controller.plan("default", SELECTED)
        self.harness.lost_finalize_reply = True
        result = controller.arm(reviewed, SELECTED)
        self.assertTrue(result.armed)
        self.assertFalse(result.transaction_pending)
        self.assertFalse((self.harness.base / "default" / "setup-transaction").exists())

    def test_stranded_transaction_can_be_explicitly_aborted(self):
        controller, _transport = self.controller()
        baseline = controller.inspect("default")
        raw = policy_bytes(baseline.catalog, SELECTED)
        self.harness.namespace["run"]("arm", "default", MANIFEST,
                                      baseline.state_revision, "b" * 32, raw)
        pending = controller.inspect("default")
        self.assertTrue(pending.transaction_pending)
        self.assertTrue(pending.armed)
        restored = controller.abort(pending)
        self.assertFalse(restored.armed)
        self.assertFalse(restored.transaction_pending)
        self.assertFalse((self.harness.base / "default").exists())

    def test_failed_transaction_creation_removes_new_config_directory(self):
        ns = self.harness.namespace
        baseline = ns["run"]("inspect", "default", MANIFEST, "-", "-", b"")
        raw = policy_bytes((ContainerCandidate(IDENT, "web-api", IMAGE_ID,
                                               "example/web-api:1", "running"),), SELECTED)
        original = ns["atomic"]
        def fail_transaction(path, content):
            if path.name == "setup-transaction":
                raise OSError("disk full")
            return original(path, content)
        ns["atomic"] = fail_transaction
        try:
            with self.assertRaises(OSError):
                ns["run"]("arm", "default", MANIFEST, baseline["state_revision"],
                          "d" * 32, raw)
        finally:
            ns["atomic"] = original
        self.assertFalse((self.harness.base / "default").exists())

    def test_status_and_disarm_work_while_docker_is_unavailable(self):
        controller, _transport = self.controller()
        active = controller.arm(controller.plan("default", SELECTED), SELECTED)
        def no_docker(_broker, _profile):
            raise OSError("Docker socket unavailable")
        self.harness.namespace["catalog"] = no_docker
        state = controller.inspect("default")
        self.assertTrue(state.armed)
        self.assertEqual(state.catalog_status, "unavailable")
        self.assertFalse(controller.disarm(active).armed)
        self.assertFalse((self.harness.base / "default" / "enabled").exists())

    def test_catalog_requires_inventory_matching_docker_before_inspect(self):
        ns = self.harness.namespace
        detail_calls = []

        class Broker:
            SOCKETS = {"docker": Path("/run/docker.sock")}
            CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
            NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
            IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")

            def _socket(self, _path):
                pass

            def _get(self, _path, endpoint, *, limit, timeout):
                if endpoint == "/containers/json?all=1":
                    return [{"Id": IDENT, "Names": ["/web-api"], "Image": "example/web-api:1"}]
                detail_calls.append(endpoint)
                return {"Id": IDENT, "Name": "/web-api", "Image": IMAGE_ID,
                        "Config": {"Image": "example/web-api:1"}}

            def _identity(self, detail, ident, expected):
                self_test.assertEqual(detail["Id"], ident)
                self_test.assertEqual(expected["image_id"], IMAGE_ID)
                return "running"

        self_test = self
        old_inventory = ns["inventory"]
        ns["inventory"] = lambda _profile: {"f" * 64: ("old", "old:image")}
        try:
            with self.assertRaises(ns["Refusal"]):
                self.harness.real_catalog(Broker(), "default")
            self.assertEqual(detail_calls, [])
            ns["inventory"] = lambda _profile: {IDENT: ("web-api", "example/web-api:1")}
            candidates, excluded = self.harness.real_catalog(Broker(), "default")
            self.assertEqual(candidates, [CANDIDATE])
            self.assertEqual(excluded, 0)
            self.assertEqual(detail_calls, ["/containers/" + IDENT + "/json"])
            class ProtectedBroker(Broker):
                def _identity(self, detail, ident, expected):
                    raise PermissionError("container shares a host mount")
            self.assertEqual(self.harness.real_catalog(ProtectedBroker(), "default"), ([], 1))
        finally:
            ns["inventory"] = old_inventory

    def test_inventory_requires_active_timer_and_fresh_complete_snapshot(self):
        ns = self.harness.namespace
        now = int(ns["time"].time())
        snapshot = {"collected_at": now,
                    "engines": [{"engine": "docker", "source_status": "ok",
                                 "reason": None, "truncated": False,
                                 "containers": [{"id": IDENT, "name": "web-api",
                                                 "image": "example/web-api:1"}]}]}
        container_module = SimpleNamespace(read_snapshot=lambda *args, **kwargs: snapshot)
        saved = sys.modules.get("sovagrid_agent.containers")
        old_inventories = ns["INVENTORIES"]
        ns["INVENTORIES"] = {"default": ("test-inventory.timer", self.harness.base / "snapshot.json",
                                       "test-group")}
        sys.modules["sovagrid_agent.containers"] = container_module
        try:
            with mock.patch.object(ns["grp"], "getgrnam", return_value=SimpleNamespace(gr_gid=42)), \
                 mock.patch.object(ns["subprocess"], "run",
                                   return_value=SimpleNamespace(returncode=0)) as timer:
                self.assertEqual(ns["inventory"]("default"),
                                 {IDENT: ("web-api", "example/web-api:1")})
                self.assertEqual(timer.call_count, 2)
                self.assertIn("test-inventory.timer", timer.call_args.args[0])
                snapshot["collected_at"] = now - 121
                with self.assertRaises(ns["Refusal"]):
                    ns["inventory"]("default")
                snapshot["collected_at"] = now
                snapshot["engines"][0]["truncated"] = True
                with self.assertRaises(ns["Refusal"]):
                    ns["inventory"]("default")
                snapshot["engines"][0]["truncated"] = False
                timer.return_value = SimpleNamespace(returncode=1)
                with self.assertRaises(ns["Refusal"]):
                    ns["inventory"]("default")
        finally:
            ns["INVENTORIES"] = old_inventories
            if saved is None:
                sys.modules.pop("sovagrid_agent.containers", None)
            else:
                sys.modules["sovagrid_agent.containers"] = saved

    def test_invalid_selection_never_contacts_ssh(self):
        controller, _transport = self.controller()
        for selected in ({}, {"f" * 64: {"status"}}, {IDENT: {"restart"}},
                         {IDENT: {"status", "exec"}}):
            before = len(self.harness.calls)
            if selected:
                with self.assertRaises(InstallError):
                    policy_bytes((ContainerCandidate(IDENT, "web-api", IMAGE_ID,
                                                     "example/web-api:1", "running"),), selected)
            else:
                with self.assertRaises(InstallError):
                    policy_bytes((), selected)
            self.assertEqual(len(self.harness.calls), before)

    def test_remote_script_compiles_and_has_pinned_broker_delegation(self):
        compile(SCRIPT, "<remote>", "exec")
        self.assertIn("broker._identity(detail, ident, entry)", SCRIPT)
        self.assertIn("broker.parse_policy(raw)", SCRIPT)
        self.assertIn("broker.read_policy(config / 'policy.json', config / 'enabled')", SCRIPT)
        self.assertIn("hashlib.sha256(src).hexdigest() == digest", SCRIPT)
        self.assertIn("exec(compile(verified[name + '.py']", SCRIPT)

    def test_source_proof_imports_only_verified_source_bytes(self):
        ns = self.harness.namespace
        source_root = self.harness.base / "opt" / "sovagrid-src"
        installed = self.harness.base / "opt" / "sovagrid-agent"
        originals = {name: __import__("sys").modules.get(name) for name in (
            "sovagrid_agent", "sovagrid_agent.containers", "sovagrid_agent.service_control",
            "sovagrid_agent.container_actions", "sovagrid_agent.container_collector",
            "sovagrid_agent.container_action_broker")}
        modules = {
            "__init__.py": b"\n",
            "agent.py": b"# verified Agent\n",
            "service_broker.py": b"# verified broker entry\n",
            "containers.py": b"import re\nCONTAINER_ID = re.compile(r'[0-9a-f]{64}\\Z')\n",
            "service_control.py": b"MAX_MESSAGE = 1024\n",
            "container_actions.py": b"ACTIONS = frozenset(('status', 'start', 'stop', 'restart'))\n",
            "container_collector.py": b"from pathlib import Path\nSOCKETS = {'docker': Path('/run/docker.sock')}\n",
            "container_action_broker.py": (
                b"from pathlib import Path\n"
                b"from .container_actions import ACTIONS\n"
                b"CONFIG = Path('/etc/sovagrid-container-actions')\n"
                b"LOCAL_CONFIG = Path('/etc/sovagrid-container-actions-local')\n"
                b"MAX_POLICY_BYTES = 8192\nMAX_CONTAINERS = 16\n"),
        }
        src_module = source_root / "sovagrid-agent" / "sovagrid_agent"
        dst_module = installed / "sovagrid_agent"
        src_module.mkdir(parents=True)
        dst_module.mkdir(parents=True)
        for path in (self.harness.base / "opt", source_root,
                     source_root / "sovagrid-agent", src_module, installed, dst_module):
            path.chmod(0o755)
        hashes = {}
        for name, raw in modules.items():
            relative = "sovagrid-agent/sovagrid_agent/" + name
            (src_module / name).write_bytes(raw)
            (dst_module / name).write_bytes(raw)
            (src_module / name).chmod(0o644)
            (dst_module / name).chmod(0o644)
            hashes[relative] = hashlib.sha256(raw).hexdigest()
        manifest = json.dumps({"format": 1, "components": {}, "sha256": hashes}).encode()
        (source_root / "sovagrid-bundle.json").write_bytes(manifest)
        (source_root / "sovagrid-bundle.json").chmod(0o644)
        ns["OPT"] = self.harness.base / "opt"
        ns["ROOT"] = source_root
        ns["INSTALLS"] = {"default": installed, "local": self.harness.base / "opt" / "local"}
        ns["check_root"] = lambda: True
        old_configs = ns["CONFIGS"]
        ns["CONFIGS"] = {"default": Path("/etc/sovagrid-container-actions"),
                         "local": Path("/etc/sovagrid-container-actions-local")}
        expected = hashlib.sha256(manifest).hexdigest()
        try:
            broker = self.harness.real_source(expected, "default")
            self.assertEqual(broker.MAX_POLICY_BYTES, 8192)
            self.assertEqual(broker.ACTIONS, frozenset(("status", "start", "stop", "restart")))
            (dst_module / "container_action_broker.py").write_bytes(b"MAX_POLICY_BYTES = 1\n")
            with self.assertRaises(ns["Refusal"]):
                self.harness.real_source(expected, "default")
        finally:
            ns["CONFIGS"] = old_configs
            import sys
            for name, previous in originals.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous


if __name__ == "__main__":
    unittest.main()
