# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Root/sudo route, state, recovery and refusal gates for the local Agent."""

import json
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.local_operations import LocalOperationsController, _SOURCE_PROBE

MANIFEST = "a" * 64
LOCAL_ID = "c432d4dc-3cf2-4929-947c-8869fb85bff9"


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()


def flags(terminal=False, files=False):
    return {"protocol": 1, "terminal": terminal, "files": files}


def revision(current):
    return ("b" if current["terminal"] else "c" if current["files"] else "a") * 64


class Transport:
    def __init__(self, *, user="root"):
        self.options = ConnectionOptions("target.example.org", user=user,
                                         jump_host="relay.example.org", jump_user="relay").validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.commands = []
        self.root_proofs = 0
        self.manifest = MANIFEST
        self.flags = flags()
        self.pending = False
        self.action_failure = None

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout):
        self.commands.append(command)
        assert command.startswith(self._privileged)
        if " -c " in command:
            return 0, wire({"protocol": 1, "manifest_sha256": self.manifest,
                            "local_server_id": LOCAL_ID, "commands": True})
        if command.endswith("local_operations.py preview"):
            if self.pending:
                return 0, wire({"protocol": 1, "phase": "recovery_required",
                                "current": flags(), "requested": flags(True),
                                "external_agent_preserved": None, "state_revision": None})
            return 0, wire({"protocol": 1, "phase": "ready", "current": self.flags,
                            "local_server_id": LOCAL_ID, "external_agent_preserved": True,
                            "state_revision": revision(self.flags)})
        if self.action_failure is not None:
            return 40, b"SG_LOCAL_OPERATIONS_REFUSE:" + self.action_failure + b"\n"
        if command.endswith("local_operations.py recover"):
            self.pending = False
            self.flags = flags()
        elif "local_operations.py enable terminal --expected-state " in command:
            assert command.endswith(revision(self.flags))
            self.flags = {**self.flags, "terminal": True}
        elif "local_operations.py disable terminal --expected-state " in command:
            assert command.endswith(revision(self.flags))
            self.flags = {**self.flags, "terminal": False}
        elif "local_operations.py enable files --expected-state " in command:
            assert command.endswith(revision(self.flags))
            self.flags = {**self.flags, "files": True}
        elif "local_operations.py disable files --expected-state " in command:
            assert command.endswith(revision(self.flags))
            self.flags = {**self.flags, "files": False}
        else:
            raise AssertionError("unexpected command: " + command[:120])
        return 0, wire({"protocol": 1, "phase": "ready", "current": self.flags,
                        "local_server_id": LOCAL_ID, "external_agent_preserved": True,
                        "state_revision": revision(self.flags)})


class LocalOperationsTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return LocalOperationsController(transport.options, transport=transport,
                                         approved_manifest_sha256=approved)

    def test_unapproved_and_old_source_never_execute_installed_helper(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, approved=None).preview()
        self.assertEqual(transport.commands, [])
        transport.manifest = "b" * 64
        with self.assertRaises(InstallError):
            self.controller(transport).preview()
        self.assertEqual(len(transport.commands), 1)
        self.assertNotIn("local_operations.py preview", transport.commands[0])
        self.assertIn("sovagrid-terminal-local-control.socket", _SOURCE_PROBE)
        compile(_SOURCE_PROBE, "<local-source-probe>", "exec")

    def test_sudo_route_enables_and_disables_one_feature_without_changing_other(self):
        transport = Transport(user="exampleuser")
        controller = self.controller(transport)
        old = controller.preview()
        self.assertFalse(old.terminal or old.files)
        enabled = controller.change("terminal", True, old)
        self.assertTrue(enabled.terminal)
        self.assertFalse(enabled.files)
        self.assertTrue(all(command.startswith("sudo -n -- ") for command in transport.commands))
        self.assertTrue(any("local_operations.py enable terminal --expected-state " in command
                            for command in transport.commands))
        disabled = controller.change("terminal", False, enabled)
        self.assertFalse(disabled.terminal)
        self.assertFalse(disabled.files)
        self.assertTrue(any("local_operations.py disable terminal --expected-state " in command
                            for command in transport.commands))
        self.assertGreaterEqual(transport.root_proofs, 5)

    def test_changed_preview_refuses_before_mutation(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.flags = flags(files=True)
        with self.assertRaisesRegex(InstallError, "изменилось"):
            controller.change("terminal", True, old)
        self.assertFalse(any("local_operations.py enable " in command for command in transport.commands))

    def test_under_lock_state_change_requires_new_preview(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.action_failure = b"STATE_CHANGED"
        with self.assertRaisesRegex(InstallError, "повторите проверку"):
            controller.change("terminal", True, old)
        self.assertFalse(transport.flags["terminal"])
        mutations = [command for command in transport.commands
                     if "local_operations.py enable terminal" in command]
        self.assertEqual(len(mutations), 1)
        self.assertTrue(mutations[0].endswith("--expected-state " + old.state_revision))

        # An unchanged digest is still refused while the server has a pending
        # operation. The caller must recheck and review its recovery state.
        transport.action_failure = None
        transport.pending = True
        pending = controller.preview()
        self.assertEqual(pending.phase, "recovery_required")
        with self.assertRaisesRegex(InstallError, "восстановите"):
            controller.change("terminal", True, pending)
        self.assertEqual(len([command for command in transport.commands
                              if "local_operations.py enable terminal" in command]), 1)

    def test_pending_state_blocks_feature_change_and_explicit_recovery_restores_prior_flags(self):
        transport = Transport()
        transport.pending = True
        controller = self.controller(transport)
        pending = controller.preview()
        self.assertEqual(pending.phase, "recovery_required")
        self.assertIsNone(pending.external_agent_preserved)
        self.assertEqual((pending.requested_terminal, pending.requested_files), (True, False))
        with self.assertRaisesRegex(InstallError, "восстановите"):
            controller.change("files", True, pending)
        recovered = controller.recover(pending)
        self.assertEqual(recovered.phase, "ready")
        self.assertEqual((recovered.terminal, recovered.files), (False, False))
        self.assertTrue(any(command.endswith("local_operations.py recover")
                            for command in transport.commands))

    def test_rollback_outcomes_are_distinct(self):
        for marker, expected in ((b"ROLLED_BACK", "восстановлены"),
                                 (b"ROLLBACK_NEEDS_RECOVERY", "восстановление")):
            with self.subTest(marker=marker):
                transport = Transport()
                controller = self.controller(transport)
                old = controller.preview()
                transport.action_failure = marker
                with self.assertRaisesRegex(InstallError, expected):
                    controller.change("files", True, old)

    def test_ready_and_recovery_protocol_reject_unexpected_keys_and_types(self):
        transport = Transport()
        controller = self.controller(transport)
        for bad in (
            {"protocol": 1, "phase": "ready", "current": flags(), "local_server_id": LOCAL_ID,
             "external_agent_preserved": None, "state_revision": "a" * 64},
            {"protocol": 1, "phase": "recovery_required", "current": flags(),
             "external_agent_preserved": None, "state_revision": None},
            {"protocol": 1, "phase": "ready", "current": flags(terminal=1),
             "local_server_id": LOCAL_ID, "external_agent_preserved": True,
             "state_revision": "a" * 64},
            {"protocol": 1, "phase": "ready", "current": flags(),
             "local_server_id": LOCAL_ID, "external_agent_preserved": True,
             "state_revision": "A" * 64},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(InstallError):
                    controller._state(wire(bad), MANIFEST, LOCAL_ID)


if __name__ == "__main__":
    unittest.main()
