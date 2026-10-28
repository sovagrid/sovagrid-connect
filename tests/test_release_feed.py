# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Signed-feed review and bounded compare-and-swap control."""

import json
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.release_feed import ReleaseFeedController
from sovagrid_connect.release_feed_remote import MUTATION_SCRIPT, SCRIPT


MANIFEST = "3" * 64
FINGERPRINT = "a" * 64


def wire(*, enabled=False, keys=None, installed=True, manual=True, revision="b" * 64):
    keys = {"fixture-key": FINGERPRINT} if keys is None else keys
    return json.dumps({
        "protocol": 1, "source_manifest_sha256": MANIFEST, "units_verified": installed,
        "feed": {"format": 1, "channel": "stable", "enabled": enabled,
                 "key_id": "fixture-key" if enabled else None, "available_keys": keys,
                 "timer_installed": installed, "timer_enabled": enabled,
                 "timer_active": enabled, "installed_manifest_sha256": MANIFEST,
                 "state_revision": revision,
                 "manual_candidate_active": manual,
                 "ledger": {"format": 1, "highest_sequence": 2,
                            "highest_version": "0.5.2", "highest_issued_at": 1800000000,
                            "last_seen_at": 1800000300}},
    }).encode()


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("server.example.org", user=user,
                                         jump_host="relay.example.org", jump_user="relay").validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.commands = []
        self.root_proofs = 0
        self.reply = wire()
        self.code = 0
        self.scripted = []

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout, limit=4096):
        self.commands.append(command)
        assert command.startswith(self._privileged + "/usr/bin/python3 -I -c ")
        if " mutate " + MANIFEST in command:
            assert command.endswith(" enable " + "b" * 64 + " fixture-key") or command.endswith(
                " disable " + "c" * 64 + " -") or command.endswith(
                " disable " + "b" * 64 + " -")
            assert timeout == 300
            assert limit == 512
        else:
            assert command.endswith(" status " + MANIFEST)
            assert timeout == 120
        return self.scripted.pop(0) if self.scripted else (self.code, self.reply)


class ReleaseFeedTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return ReleaseFeedController(transport.options, transport=transport,
                                     approved_manifest_sha256=approved)

    def test_no_approved_server_never_contacts_host(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, None).preview()
        self.assertEqual(transport.root_proofs, 0)
        self.assertEqual(transport.commands, [])

    def test_sudo_status_shows_embedded_key_and_separate_candidate(self):
        transport = Transport("admin")
        state = self.controller(transport).preview()
        self.assertEqual(state.available_keys, (("fixture-key", FINGERPRINT),))
        self.assertTrue(state.units_verified)
        self.assertTrue(state.manual_candidate_active)
        self.assertFalse(state.enabled)
        self.assertFalse(state.timer_enabled)
        self.assertEqual(state.state_revision, "b" * 64)
        self.assertEqual(state.highest_sequence, 2)
        self.assertEqual(transport.root_proofs, 1)
        self.assertTrue(transport.commands[0].startswith("sudo -n -- "))

    def test_old_server_and_unconfigured_key_are_read_only(self):
        transport = Transport()
        transport.reply = wire(installed=False, keys={})
        controller = self.controller(transport)
        state = controller.preview()
        self.assertFalse(state.units_verified)
        self.assertEqual(state.available_keys, ())
        with self.assertRaisesRegex(InstallError, "встроенный ключ"):
            controller.enable(state, "fixture-key")
        with self.assertRaisesRegex(InstallError, "уже выключен"):
            controller.disable(state)
        self.assertEqual(len(transport.commands), 1)

    def test_enable_and_disable_recheck_source_and_result(self):
        transport = Transport("admin")
        transport.scripted = [(0, wire()), (0, wire()),
                              (0, b"SG_RELEASE_FEED_CLIENT_APPLIED:enable\n"),
                              (0, wire(enabled=True, revision="c" * 64)),
                              (0, wire(enabled=True, revision="c" * 64)),
                              (0, b"SG_RELEASE_FEED_CLIENT_APPLIED:disable\n"),
                              (0, wire(revision="d" * 64))]
        controller = self.controller(transport)
        initial = controller.preview()
        enabled = controller.enable(initial, "fixture-key")
        self.assertTrue(enabled.enabled)
        self.assertEqual(enabled.state_revision, "c" * 64)
        disabled = controller.disable(enabled)
        self.assertFalse(disabled.enabled)
        self.assertEqual(disabled.state_revision, "d" * 64)
        self.assertEqual(len(transport.commands), 7)
        self.assertEqual(transport.root_proofs, 5)
        self.assertTrue(any(" mutate " + MANIFEST + " enable " in command for command in
                            transport.commands))
        self.assertTrue(any(" mutate " + MANIFEST + " disable " in command for command in
                            transport.commands))

    def test_stale_review_or_server_cas_refusal_never_reuses_state(self):
        transport = Transport()
        transport.scripted = [(0, wire()), (0, wire(revision="c" * 64))]
        controller = self.controller(transport)
        state = controller.preview()
        with self.assertRaisesRegex(InstallError, "изменилось"):
            controller.enable(state, "fixture-key")
        self.assertEqual(len(transport.commands), 2)
        with self.assertRaisesRegex(InstallError, "повторно проверьте"):
            controller.enable(state, "fixture-key")

        transport = Transport()
        transport.scripted = [(0, wire()), (0, wire()),
                              (40, b"SG_RELEASE_FEED_CLIENT_REFUSE:STATE_CHANGED\n")]
        controller = self.controller(transport)
        state = controller.preview()
        with self.assertRaisesRegex(InstallError, "изменилось"):
            controller.enable(state, "fixture-key")
        self.assertEqual(len(transport.commands), 3)

    def test_no_anchor_and_source_or_units_refusal_cannot_mutate(self):
        transport = Transport()
        transport.reply = wire(keys={})
        controller = self.controller(transport)
        state = controller.preview()
        with self.assertRaisesRegex(InstallError, "встроенный ключ"):
            controller.enable(state, "fixture-key")
        self.assertEqual(len(transport.commands), 1)

        for refusal in (b"SG_RELEASE_FEED_CLIENT_REFUSE:SOURCE_HASH\n",
                        b"SG_RELEASE_FEED_CLIENT_REFUSE:UNIT_CONTENT\n"):
            transport = Transport()
            transport.scripted = [(0, wire()), (0, wire()), (40, refusal)]
            controller = self.controller(transport)
            state = controller.preview()
            with self.subTest(refusal=refusal), self.assertRaisesRegex(InstallError,
                                                                        "не подтвердил"):
                controller.enable(state, "fixture-key")
            self.assertEqual(len(transport.commands), 3)

    def test_removed_anchor_is_visible_and_can_only_be_disabled(self):
        transport = Transport()
        transport.scripted = [(0, wire(enabled=True, keys={})),
                              (0, wire(enabled=True, keys={})),
                              (0, b"SG_RELEASE_FEED_CLIENT_APPLIED:disable\n"),
                              (0, wire(keys={}, revision="c" * 64))]
        controller = self.controller(transport)
        state = controller.preview()
        self.assertEqual(state.key_id, "fixture-key")
        self.assertEqual(state.available_keys, ())
        with self.assertRaisesRegex(InstallError, "встроенный ключ"):
            controller.enable(state, "fixture-key")
        result = controller.disable(state)
        self.assertFalse(result.enabled)
        self.assertEqual(result.available_keys, ())
        self.assertEqual(len(transport.commands), 4)

    def test_success_marker_without_confirmed_timer_is_not_success(self):
        transport = Transport()
        transport.scripted = [(0, wire()), (0, wire()),
                              (0, b"SG_RELEASE_FEED_CLIENT_APPLIED:enable\n"),
                              (0, wire(revision="c" * 64))]
        controller = self.controller(transport)
        state = controller.preview()
        with self.assertRaisesRegex(InstallError, "отличается от плана"):
            controller.enable(state, "fixture-key")
        with self.assertRaisesRegex(InstallError, "повторно проверьте"):
            controller.enable(state, "fixture-key")

    def test_rejects_unverified_fingerprint_and_inconsistent_state(self):
        transport = Transport()
        for raw in (wire(keys={"fixture-key": "A" * 64}),
                    wire(enabled=True, keys={}).replace(b'"key_id": "fixture-key"',
                                                        b'"key_id": "bad key"'),
                    wire(installed=False, manual=False).replace(b'"timer_installed": false',
                                                               b'"timer_installed": true'),
                    wire().replace(b'"installed_manifest_sha256": "' + MANIFEST.encode(),
                                   b'"installed_manifest_sha256": "' + b'c' * 64),
                    wire().replace(b'"protocol": 1', b'"protocol": 2'),
                    wire().replace(b'"timer_enabled": false', b'"timer_enabled": 0'),
                    wire().replace(b'"state_revision": "' + b'b' * 64,
                                   b'"state_revision": "' + b'A' * 64),
                    b'{"protocol":1,"protocol":1}'):
            transport.reply = raw
            with self.subTest(raw=raw), self.assertRaises(InstallError):
                self.controller(transport).preview()

    def test_remote_programs_prove_exact_source_before_installed_helper(self):
        compile(SCRIPT, "<release-feed-status>", "exec")
        compile(MUTATION_SCRIPT, "<release-feed-mutate>", "exec")
        for required in ("source(expected)", "units(hashes)",
                         "available_keys", "sovagrid-release-feed.timer",
                         "SOURCE_HASH", "UNIT_CONTENT"):
            self.assertIn(required, SCRIPT)
        for required in ("source(expected)", "units(hashes)",
                         "'--expected-state', revision", "STATE_CHANGED",
                         "SG_RELEASE_FEED_CLIENT_APPLIED"):
            self.assertIn(required, MUTATION_SCRIPT)


if __name__ == "__main__":
    unittest.main()
