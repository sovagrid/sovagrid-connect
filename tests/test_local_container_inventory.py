# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pin, CAS, recovery and uncertain SSH results for local Docker inventory."""

import json
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.local_container_inventory import (
    LocalContainerInventoryController, _SOURCE_PROBE)


MANIFEST = "a" * 64
LOCAL_ID = "c432d4dc-3cf2-4929-947c-8869fb85bff9"


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("target.example.org", user=user,
                                         jump_host="relay.example.org", jump_user="relay").validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.commands = []
        self.root_proofs = 0
        self.manifest = MANIFEST
        self.enabled = False
        self.pending = False
        self.failure = None
        self.lost_reply_after_apply = False

    def _verify_root_access(self):
        self.root_proofs += 1

    def _state(self):
        if self.pending:
            return {"protocol": 1, "phase": "recovery_required",
                    "previous_enabled": False, "requested_enabled": True,
                    "manifest_sha256": self.manifest, "local_server_id": LOCAL_ID,
                    "external_agent_preserved": True, "state_revision": None}
        return {"protocol": 1, "phase": "ready", "enabled": self.enabled,
                "manifest_sha256": self.manifest, "local_server_id": LOCAL_ID,
                "external_agent_preserved": True,
                "state_revision": ("b" if self.enabled else "a") * 64,
                "collector_active": self.enabled, "snapshot_fresh": self.enabled}

    def _execute(self, command, *, timeout):
        self.commands.append(command)
        assert command.startswith(self._privileged)
        if " -c " in command:
            return 0, wire({"protocol": 1, "manifest_sha256": self.manifest,
                            "local_server_id": LOCAL_ID})
        if command.endswith("local_container_inventory.py preview"):
            return 0, wire(self._state())
        if self.failure is not None:
            return 40, b"SG_LOCAL_CONTAINERS_REFUSE:" + self.failure + b"\n"
        if command.endswith("local_container_inventory.py recover"):
            self.pending = False
            self.enabled = False
        elif "local_container_inventory.py enable --expected-state " in command:
            assert command.endswith(("b" if self.enabled else "a") * 64)
            self.enabled = True
        elif "local_container_inventory.py disable --expected-state " in command:
            assert command.endswith(("b" if self.enabled else "a") * 64)
            self.enabled = False
        else:
            raise AssertionError("unexpected command: " + command[:120])
        if self.lost_reply_after_apply:
            self.lost_reply_after_apply = False
            raise OSError("SSH connection closed after apply")
        return 0, wire(self._state())


class LocalInventoryTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return LocalContainerInventoryController(transport.options, transport=transport,
                                                 approved_manifest_sha256=approved)

    def test_source_probe_is_fixed_and_approved_before_helper(self):
        compile(_SOURCE_PROBE, "<source-probe>", "exec")
        for name in ("local_container_inventory.py", "local_operations.py",
                     "promote_agent_only.py", "sovagrid-container-inventory-local.timer"):
            self.assertIn(name, _SOURCE_PROBE)
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, approved=None).preview()
        self.assertEqual(transport.commands, [])
        transport.manifest = "b" * 64
        with self.assertRaises(InstallError):
            self.controller(transport).preview()
        self.assertFalse(any(command.endswith("local_container_inventory.py preview")
                             for command in transport.commands))

    def test_enable_disable_sudo_route_and_cas(self):
        transport = Transport(user="exampleuser")
        controller = self.controller(transport)
        old = controller.preview()
        self.assertFalse(old.enabled)
        enabled = controller.change(True, old)
        self.assertTrue(enabled.enabled and enabled.snapshot_fresh and enabled.collector_active)
        disabled = controller.change(False, enabled)
        self.assertFalse(disabled.enabled)
        self.assertTrue(all(command.startswith("sudo -n -- ") for command in transport.commands))
        self.assertTrue(any("local_container_inventory.py enable --expected-state " in command
                            for command in transport.commands))
        self.assertTrue(any("local_container_inventory.py disable --expected-state " in command
                            for command in transport.commands))
        self.assertGreaterEqual(transport.root_proofs, 5)

    def test_changed_state_and_pending_block_mutation(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.enabled = True
        with self.assertRaisesRegex(InstallError, "изменилось"):
            controller.change(True, old)
        self.assertFalse(any("inventory.py enable" in command for command in transport.commands))
        transport.enabled = False
        transport.pending = True
        pending = controller.preview()
        self.assertEqual(pending.phase, "recovery_required")
        with self.assertRaises(InstallError):
            controller.change(True, pending)
        recovered = controller.recover(pending)
        self.assertEqual((recovered.phase, recovered.enabled), ("ready", False))

    def test_under_lock_state_change_rejected(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.failure = b"STATE_CHANGED"
        with self.assertRaisesRegex(InstallError, "повторите проверку"):
            controller.change(True, old)
        self.assertFalse(transport.enabled)

    def test_lost_reply_does_not_retry_mutation(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.lost_reply_after_apply = True
        enabled = controller.change(True, old)
        self.assertTrue(enabled.enabled)
        self.assertEqual(sum("local_container_inventory.py enable --expected-state " in command
                             for command in transport.commands), 1)

    def test_bad_protocol_and_refusal_markers(self):
        transport = Transport()
        controller = self.controller(transport)
        original = transport._state()
        for bad in ({**original, "enabled": 1},
                    {**original, "state_revision": "A" * 64},
                    {**original, "collector_active": True},
                    {**original, "external_agent_preserved": None},
                    {**original, "extra": True},
                    {**original, "phase": "recovery_required"}):
            with self.subTest(bad=bad):
                with self.assertRaises(InstallError):
                    controller._state(wire(bad), MANIFEST, LOCAL_ID)
        for marker, expected in ((b"ROLLED_BACK", "восстановлены"),
                                 (b"ROLLBACK_NEEDS_RECOVERY", "восстановление")):
            with self.subTest(marker=marker):
                self.assertIn(expected, str(controller._failure(b"SG_LOCAL_CONTAINERS_REFUSE:" + marker)))


if __name__ == "__main__":
    unittest.main()
