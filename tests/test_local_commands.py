# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit local command opt-in review, CAS, and bounded remote program."""

import json
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.local_commands import LocalCommandsController
from sovagrid_connect.local_commands_remote import SCRIPT


MANIFEST = "3" * 64
LOCAL_ID = "c432d4dc-3cf2-4929-947c-8869fb85bff9"


def wire(enabled=False):
    return json.dumps({"protocol": 1, "phase": "ready", "manifest_sha256": MANIFEST,
                       "local_server_id": LOCAL_ID, "commands_enabled": enabled,
                       "external_agent_preserved": True,
                       "state_revision": ("b" if enabled else "a") * 64}).encode()


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("target.example.org", user=user,
                                         jump_host="relay.example.org", jump_user="relay").validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.commands = []
        self.root_proofs = 0
        self.enabled = False
        self.action_failure = None
        self.reply = None

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout):
        self.commands.append(command)
        assert command.startswith(self._privileged + "/usr/bin/python3 -I -c ")
        if command.endswith(" preview " + MANIFEST):
            return 0, self.reply or wire(self.enabled)
        if command.endswith(" enable " + MANIFEST + " " + "a" * 64):
            assert timeout == 720
            if self.action_failure is not None:
                return 40, b"SG_LOCAL_COMMANDS_REFUSE:" + self.action_failure + b"\n"
            self.enabled = True
            return 0, wire(True)
        raise AssertionError("Unexpected command suffix")


class LocalCommandsTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return LocalCommandsController(transport.options, transport=transport,
                                       approved_manifest_sha256=approved)

    def test_unapproved_release_never_contacts_ssh_host(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, approved=None).preview()
        self.assertEqual(transport.root_proofs, 0)
        self.assertEqual(transport.commands, [])

    def test_sudo_route_requires_review_and_enables_only_once(self):
        transport = Transport(user="exampleuser")
        controller = self.controller(transport)
        reviewed = controller.preview()
        self.assertFalse(reviewed.commands_enabled)
        active = controller.enable(reviewed)
        self.assertTrue(active.commands_enabled)
        self.assertNotEqual(active.state_revision, reviewed.state_revision)
        self.assertEqual(sum(" enable " + MANIFEST in command for command in transport.commands), 1)
        self.assertTrue(all(command.startswith("sudo -n -- ") for command in transport.commands))
        self.assertGreaterEqual(transport.root_proofs, 3)
        with self.assertRaises(InstallError):
            controller.enable(active)

    def test_changed_review_and_server_cas_refusal_have_no_claimed_success(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.enabled = True
        with self.assertRaisesRegex(InstallError, "повторите проверку"):
            controller.enable(old)
        self.assertFalse(any(" enable " + MANIFEST in command for command in transport.commands))

        transport.enabled = False
        transport.action_failure = b"STATE_CHANGED"
        with self.assertRaisesRegex(InstallError, "повторите проверку"):
            controller.enable(old)
        self.assertFalse(transport.enabled)
        self.assertEqual(sum(" enable " + MANIFEST in command for command in transport.commands), 1)

    def test_partial_failure_is_not_reported_as_rollback(self):
        transport = Transport()
        controller = self.controller(transport)
        old = controller.preview()
        transport.action_failure = b"ENABLE_UNCONFIRMED"
        with self.assertRaisesRegex(InstallError, "частичном сбое"):
            controller.enable(old)
        self.assertFalse(transport.enabled)

    def test_rejects_unexpected_json_and_remote_script_has_locked_bounded_opt_in(self):
        transport = Transport()
        controller = self.controller(transport)
        for bad in (
            {"protocol": 1, "phase": "ready", "manifest_sha256": MANIFEST,
             "local_server_id": LOCAL_ID, "commands_enabled": 1,
             "external_agent_preserved": True, "state_revision": "a" * 64},
            {"protocol": 1, "phase": "ready", "manifest_sha256": MANIFEST,
             "local_server_id": LOCAL_ID, "commands_enabled": False,
             "external_agent_preserved": None, "state_revision": "a" * 64},
            {"protocol": 1, "phase": "ready", "manifest_sha256": MANIFEST,
             "local_server_id": LOCAL_ID, "commands_enabled": False,
             "external_agent_preserved": True, "state_revision": "A" * 64},
        ):
            transport.reply = json.dumps(bad).encode()
            with self.subTest(bad=bad), self.assertRaises(InstallError):
                controller.preview()
        compile(SCRIPT, "<local-commands-remote>", "exec")
        for required in ("/run/sovagrid-promotion.lock", "LOCK_EX | fcntl.LOCK_NB",
                         "before['state_revision'] == revision", "activate', '--enable-commands'",
                         "remaining = 2 * 1024 * 1024", "source['commands']", "remote_commands_enabled"):
            self.assertIn(required, SCRIPT)
        self.assertNotIn("'disable'", SCRIPT)


if __name__ == "__main__":
    unittest.main()
