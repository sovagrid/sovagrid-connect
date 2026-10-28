# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

from collections import deque
from email.utils import formatdate
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import BundleSummary, InstallError
from sovagrid_connect.promotion import PromotionController, verify_promoted_panel
from sovagrid_connect.promotion_protocol import PromotionState, parse_promotion_state
from sovagrid_connect.promotion_remote import ACTION_SCRIPT, STAGE_SCRIPT


ARCHIVE = "a" * 64
MANIFEST = "b" * 64
BASELINE = "c" * 64
SERVER_ID = "12345678-1234-4234-8234-123456789abc"


def state(phase: str, *, manifest: str = MANIFEST) -> PromotionState:
    return PromotionState(
        phase=phase,
        external_agent_preserved=phase not in ("external_changed", "unknown"),
        baseline_sha256=None if phase == "eligible" else BASELINE,
        pinned_manifest_sha256=None if phase == "eligible" else manifest,
        source_manifest_sha256=manifest if phase in ("source_staged", "hub_installed", "activated") else None,
        local_server_id=SERVER_ID if phase == "activated" else None,
        reason_code=None if phase not in ("external_changed", "unknown") else "UNSAFE_STATE",
    )


def encoded(value: PromotionState) -> bytes:
    return json.dumps({"protocol": 1, **value.__dict__}).encode("utf-8")


class PromotionProtocolTests(unittest.TestCase):
    def test_accepts_precise_resume_states_and_rejects_secrets(self) -> None:
        for phase in ("eligible", "prepared", "source_staged", "hub_installed", "activated"):
            self.assertEqual(parse_promotion_state(encoded(state(phase))), state(phase))
        payload = json.loads(encoded(state("prepared")))
        payload["agent_token"] = "secret"
        with self.assertRaises(ValueError):
            parse_promotion_state(json.dumps(payload).encode())
        with self.assertRaises(ValueError):
            parse_promotion_state(encoded(state("eligible")).replace(b'"protocol": 1',
                b'"protocol": 1, "protocol": 1'))

    def test_rejects_loose_types_and_inconsistent_pins(self) -> None:
        for change in (
            {"protocol": True}, {"external_agent_preserved": 1},
            {"source_manifest_sha256": "d" * 64}, {"baseline_sha256": None},
            {"local_server_id": "bad-id"}, {"reason_code": "UNSAFE_STATE"},
        ):
            payload = json.loads(encoded(state("activated")))
            payload.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                parse_promotion_state(json.dumps(payload).encode())
        with self.assertRaises(ValueError):
            parse_promotion_state(b"{" + b"a" * 4097)
        payload = json.loads(encoded(state("prepared")))
        payload["local_server_id"] = SERVER_ID
        with self.assertRaises(ValueError):
            parse_promotion_state(json.dumps(payload).encode())

    def test_refuses_unknown_or_changed_external_agent(self) -> None:
        for phase in ("unknown", "external_changed"):
            self.assertFalse(parse_promotion_state(encoded(state(phase))).can_continue)


class FakePromotion(PromotionController):
    def __init__(self, sequence: list[PromotionState], *, user: str = "root"):
        super().__init__(ConnectionOptions(host="target.example", user=user, jump_host="relay.example",
                                           jump_user="root"), approved_archive_sha256=ARCHIVE)
        self.states = deque(sequence)
        self.actions = []

    def _inspect(self, helper: bytes, manifest_sha: str) -> PromotionState:
        self.actions.append(("inspect", manifest_sha))
        result = self.states.popleft()
        from sovagrid_connect.promotion import _check_state
        _check_state(result, manifest_sha)
        return result

    def _execute(self, command: str, *, data=None, source=None, timeout=45):
        if command in ("id -u", "sudo -n -- id -u"):
            return 0, b"0\n"
        self.actions.append(("prepare", command))
        self.assert_prepare_command(command, data)
        return 0, b'{}'

    @staticmethod
    def assert_prepare_command(command, data):
        assert "prepare --manifest-sha256" in command and MANIFEST in command
        assert data == b"#!/usr/bin/env python3\n"

    def _marker(self, command: str, expected: bytes, *, data=None, source=None, timeout: float):
        self.actions.append((expected.decode(), command))
        assert command.startswith(self._privileged + "python3 -c ")
        if expected == b"SG_PROMOTION_STAGE:DONE":
            assert source is not None and ARCHIVE in command and MANIFEST in command
        else:
            assert source is None and MANIFEST in command


class PromotionControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.summary = BundleSummary(Path("bundle.tar.gz"), 1000, 260, {"sovagrid-blueprint": "d" * 40})
        self.snapshot = patch("sovagrid_connect.promotion._snapshot_with_digest",
                              return_value=(self.summary, ARCHIVE))
        self.parts = patch("sovagrid_connect.promotion._candidate_parts",
                           return_value=(MANIFEST, b"#!/usr/bin/env python3\n"))
        self.snapshot.start(); self.parts.start()
        self.addCleanup(self.snapshot.stop); self.addCleanup(self.parts.stop)

    def test_resumes_every_confirmed_phase_in_order(self) -> None:
        phases = [state(name) for name in ("eligible", "eligible", "prepared", "source_staged",
                                           "hub_installed", "activated")]
        controller = FakePromotion(phases)
        preview = controller.preview(Path("bundle.tar.gz"))
        self.assertEqual(controller.apply(Path("bundle.tar.gz"), preview).local_server_id, SERVER_ID)
        self.assertEqual([entry[0] for entry in controller.actions if entry[0] != "inspect"],
                         ["prepare", "SG_PROMOTION_STAGE:DONE", "SG_PROMOTION_HUB:DONE",
                          "SG_PROMOTION_AGENT:DONE"])
        self.assertFalse(controller.states)

    def test_reopens_after_transfer_without_preparing_or_uploading_again(self) -> None:
        controller = FakePromotion([state("source_staged"), state("source_staged"),
                                    state("hub_installed"), state("activated")])
        preview = controller.preview(Path("bundle.tar.gz"))
        controller.apply(Path("bundle.tar.gz"), preview)
        self.assertEqual([entry[0] for entry in controller.actions if entry[0] != "inspect"],
                         ["SG_PROMOTION_HUB:DONE", "SG_PROMOTION_AGENT:DONE"])

    def test_passwordless_sudo_route_wraps_every_mutating_stage(self) -> None:
        phases = [state(name) for name in ("eligible", "eligible", "prepared", "source_staged",
                                           "hub_installed", "activated")]
        controller = FakePromotion(phases, user="exampleuser")
        preview = controller.preview(Path("bundle.tar.gz"))
        self.assertEqual(controller.apply(Path("bundle.tar.gz"), preview).phase, "activated")
        commands = [entry[1] for entry in controller.actions if entry[0] != "inspect"]
        self.assertEqual(len(commands), 4)
        self.assertTrue(all(command.startswith("sudo -n -- ") for command in commands))

    def test_drift_and_wrong_manifest_stop_before_any_mutation(self) -> None:
        for second in (state("prepared"), state("prepared", manifest="d" * 64)):
            controller = FakePromotion([state("eligible"), second])
            preview = controller.preview(Path("bundle.tar.gz"))
            with self.assertRaises(InstallError):
                controller.apply(Path("bundle.tar.gz"), preview)
            self.assertEqual([entry[0] for entry in controller.actions if entry[0] != "inspect"], [])
        controller = FakePromotion([state("prepared", manifest="d" * 64)])
        with self.assertRaises(InstallError):
            controller.preview(Path("bundle.tar.gz"))

    def test_rejects_unpinned_bundle_and_requires_existing_noninteractive_sudo(self) -> None:
        with self.assertRaises(InstallError):
            PromotionController(ConnectionOptions(host="target.example", user="root"),
                                approved_archive_sha256="bad")
        for user, command in (("root", "id -u"), ("exampleuser", "sudo -n -- id -u")):
            controller = PromotionController(ConnectionOptions(host="target.example", user=user),
                                             approved_archive_sha256=ARCHIVE)
            with patch.object(controller, "_execute", return_value=(0, b"0\n")) as execute:
                controller._verify_root_access()
                execute.assert_called_once_with(command, timeout=45)
            with patch.object(controller, "_execute", return_value=(1, b"")):
                with self.assertRaises(InstallError):
                    controller._verify_root_access()
            with patch.object(controller, "_execute", return_value=(0, encoded(state("eligible")))) as execute:
                controller._inspect(b"#!/usr/bin/env python3\n", MANIFEST)
                execute.assert_called_once_with(
                    ("" if user == "root" else "sudo -n -- ") + "python3 - inspect",
                    data=b"#!/usr/bin/env python3\n", timeout=90)

    def test_remote_programs_compile_and_activation_does_not_enable_commands(self) -> None:
        compile(STAGE_SCRIPT, "stage", "exec")
        compile(ACTION_SCRIPT, "action", "exec")
        self.assertIn("'activate'", ACTION_SCRIPT)
        self.assertNotIn("--enable-commands", ACTION_SCRIPT)


class PromotionPanelProofTests(unittest.TestCase):
    class Reply:
        def __init__(self, value, *, server_time=1000):
            self.status = 200
            self.value = json.dumps(value).encode()
            self.headers = {"Date": formatdate(server_time, usegmt=True)}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return self.value

    class Opener:
        def __init__(self, online, *, last_seen=1000):
            self.online = online
            self.last_seen = last_seen
            self.methods = []

        def open(self, request, timeout):
            self.methods.append(request.get_method())
            if request.get_method() == "POST":
                return PromotionPanelProofTests.Reply({"token": "X" * 43})
            if request.get_method() == "GET":
                return PromotionPanelProofTests.Reply({"servers": [{"id": SERVER_ID,
                    "online": self.online, "last_seen": self.last_seen}]})
            return PromotionPanelProofTests.Reply({})

    def test_requires_live_local_metric_and_revokes_temporary_session(self) -> None:
        tunnel = SimpleNamespace(url="http://127.0.0.1:18766", alive=True,
                                 request_ssh_grant=lambda: SimpleNamespace(value="A" * 43))
        for online in (True, False):
            opener = self.Opener(online)
            with patch("sovagrid_connect.promotion.build_opener", return_value=opener):
                if online:
                    verify_promoted_panel(tunnel, SERVER_ID)
                else:
                    with self.assertRaises(InstallError):
                        verify_promoted_panel(tunnel, SERVER_ID)
            self.assertEqual(opener.methods, ["POST", "GET", "DELETE"])

    def test_refuses_nonloopback_panel_before_requesting_a_grant(self) -> None:
        called = []
        tunnel = SimpleNamespace(url="http://example.org:8766", alive=True,
                                 request_ssh_grant=lambda: called.append(True))
        with self.assertRaises(InstallError):
            verify_promoted_panel(tunnel, SERVER_ID)
        self.assertEqual(called, [])

    def test_rejects_stale_metric_even_if_hub_online_setting_is_long(self) -> None:
        tunnel = SimpleNamespace(url="http://127.0.0.1:18766", alive=True,
                                 request_ssh_grant=lambda: SimpleNamespace(value="A" * 43))
        opener = self.Opener(True, last_seen=800)
        with patch("sovagrid_connect.promotion.build_opener", return_value=opener):
            with self.assertRaises(InstallError):
                verify_promoted_panel(tunnel, SERVER_ID)
        self.assertEqual(opener.methods, ["POST", "GET", "DELETE"])


if __name__ == "__main__":
    unittest.main()
