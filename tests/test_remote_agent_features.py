# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Meaningful policy ordering, interruption and private checkpoint regressions."""
import copy
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

from sovagrid_connect.agent_rpc import Stage, RPCError
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.remote_agent_features import RemoteAgentFeatures, FeatureError, FeatureCancelled
from sovagrid_connect.remote_feature_journal import FeatureJournal
from sovagrid_connect.enrollment_journal import EnrollmentJournalError
from sovagrid_connect.enrollment_api import EnrollmentAPIError

SID, EID, RID = (str(uuid.UUID(int=n)) for n in (1, 2, 3))
OFF = {"commands": False, "terminal": False, "files": False}
ON = {"commands": True, "terminal": True, "files": True}


class Backend:
    def __init__(self):
        self.current = dict(OFF)
        self.policy = {"server_id": SID, "enrollment_id": EID, "agent_token_sha256": "a"*64, "enabled": False, "revision": 0}
        self.identity = {"request_id": RID, "enrollment_id": EID, "server_id": SID, "agent_token_sha256": "a"*64}
        self.version = 0
        self.applied = False
        self.after_apply_reads = 0
        self.fail_target = False
        self.calls = []
        self.stages = {}

    def cas(self):
        return {"source_manifest_sha256": "f"*64, "features_sha256": "b"*64,
                "policy_sha256": "c"*64, "state_sha256": str(self.version)*64}

    def reply(self):
        return {"protocol": 1, "ok": True, "identity": dict(self.identity), "current": dict(self.current),
                "expected": self.cas(), "source_manifest_sha256": "f"*64, "recovery_required": False,
                "pending_features": None, "services": {"agent": True, "tunnel": True, "terminal": self.current["terminal"]}}


class FakeAPI:
    def __init__(self, backend): self.backend = backend; self.logins = 0
    def login(self, username, password): self.logins += 1
    def logout(self): self.backend.calls.append(("logout",))
    def list_servers(self): return [{"id": SID, "name": "home"}]
    def management(self, server_id): return copy.deepcopy(self.backend.policy)
    def set_management(self, expected, enabled):
        if expected != self.backend.policy:
            raise FeatureError("CAS conflict")
        self.backend.calls.append(("gate", enabled))
        if enabled != self.backend.policy["enabled"]:
            self.backend.policy["revision"] += 1
        self.backend.policy["enabled"] = enabled
        return copy.deepcopy(self.backend.policy)
    def get(self, enrollment_id):
        seen = 100
        if self.backend.applied:
            self.backend.after_apply_reads += 1
            if self.backend.after_apply_reads >= 2: seen = 101
        return {"id": enrollment_id, "server_id": SID, "name": "home", "state": "active", "revision": 1,
                "created_at": 1, "last_seen": seen}


class FakeRPC:
    def __init__(self, backend): self.backend = backend
    def preflight(self): return {"ubuntu_version": "26.04", "python_version": "3.14", "systemd_version": "259"}
    def cancel(self): pass
    def stage_target(self, path, sha, checkpoint=None):
        ident = uuid.uuid4().hex
        stage = Stage("/var/tmp/sovagrid-agent-enroll."+ident, sha, "f"*64, "e"*64, ident)
        if checkpoint: checkpoint(stage.descriptor())
        self.backend.stages[ident] = stage
        return stage
    def recover_stage(self, descriptor, for_cleanup=False):
        if descriptor["stage_id"] not in self.backend.stages: raise RPCError("STAGE_NOT_FOUND")
        return self.backend.stages[descriptor["stage_id"]]
    def cleanup_stage(self, stage): self.backend.stages.pop(stage.stage_id)
    def call(self, action, payload, stage=None):
        if action == "target-features-apply":
            if payload["expected"] != self.backend.cas(): raise RPCError("STALE_PREVIEW")
            self.backend.calls.append(("target", dict(payload["features"])))
            self.backend.current = dict(payload["features"])
            self.backend.version += 1; self.backend.applied = True; self.backend.after_apply_reads = 0
            if self.backend.fail_target: raise RPCError("SERVICE_FAILED")
        result = self.backend.reply()
        if action != "target-features-status":
            result.update(desired=dict(payload["features"]), changed=result["current"] != payload["features"])
        if action == "target-features-apply": result["applied"] = True
        return result


class FeatureControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.backend = Backend(); self.api = FakeAPI(self.backend)
        options = ConnectionOptions("hub.example", user="root")
        self.tunnel = types.SimpleNamespace(options=options, alive=True, url="http://127.0.0.1:12345")
        self.journal = FeatureJournal(self.root / "features")
        self.controller = self.make_controller()
        self.bundle = patch('sovagrid_connect.remote_agent_features.feature_bundle',
            return_value=({"path": str(self.root / "approved.tar.gz"), "sha256": "d"*64}, types.SimpleNamespace(commits={"sovagrid-agent": "e"*40})))
        self.bundle.start(); self.addCleanup(self.bundle.stop)

    def make_controller(self):
        return RemoteAgentFeatures(self.tunnel, journal=self.journal, api_factory=lambda _t: self.api,
                                   rpc_factory=lambda *_a, **_k: FakeRPC(self.backend))

    def prepare(self, controller=None):
        return (controller or self.controller).prepare(target_options=ConnectionOptions("target.example", user="operator"),
            server_id=SID, bundle=self.root / "approved.tar.gz", username="admin", password="memory-only-fixture")

    def test_prepare_and_review_never_change_policy_and_apply_orders_both_machines(self):
        self.prepare(); plan = self.controller.preview(ON)
        self.assertEqual(self.backend.calls, [])
        self.assertTrue(plan["change_required"])
        result = self.controller.apply()
        self.assertEqual(self.backend.calls, [("gate", False), ("target", ON), ("gate", True)])
        self.assertTrue(result["applied"]); self.assertTrue(result["fresh_metric_verified"])
        self.assertEqual(self.backend.after_apply_reads, 2, 'baseline must be read after target mutation')
        self.assertEqual(self.backend.stages, {}); self.assertEqual(self.journal.list(), [])

    def test_concurrent_policy_change_prevents_any_mutation(self):
        self.prepare(); self.controller.preview(ON)
        self.backend.policy["revision"] += 1
        with self.assertRaises(FeatureError): self.controller.apply()
        self.assertEqual(self.backend.calls, []); self.assertEqual(self.backend.current, OFF)

    def test_policy_changed_during_fresh_metric_wait_is_not_reported_as_success(self):
        self.prepare(); self.controller.preview(ON)
        original = self.api.get
        def close_while_waiting(enrollment_id):
            row = original(enrollment_id)
            if self.backend.applied and self.backend.after_apply_reads >= 2:
                # A second administrator changes the Hub after our CAS open,
                # while we are still waiting for the next measurement.
                self.backend.policy["enabled"] = False
                self.backend.policy["revision"] += 1
            return row
        with patch.object(self.api, 'get', side_effect=close_while_waiting):
            with self.assertRaises(FeatureError):
                self.controller.apply()
        self.assertFalse(self.backend.policy["enabled"])
        self.assertEqual(self.backend.policy["revision"], 2)
        self.assertEqual(self.backend.calls, [("gate", False), ("target", ON), ("gate", True)],
                         'a failed final confirmation must not reopen a concurrently closed gate')
        self.assertEqual(self.journal.list()[0]["phase"], 'uncertain')

    def test_lost_gate_close_reply_preserves_disable_intent_across_recovery_cancel(self):
        self.backend.current = dict(ON)
        self.backend.policy.update(enabled=True, revision=1)
        self.prepare(); self.controller.preview(OFF)
        original = self.api.set_management
        def lost_reply(expected, enabled):
            original(expected, enabled)
            raise EnrollmentAPIError('fixed lost-reply fixture')
        with patch.object(self.api, 'set_management', side_effect=lost_reply):
            with self.assertRaises(FeatureError):
                self.controller.apply()
        self.assertFalse(self.backend.policy["enabled"])
        self.assertEqual(self.backend.current, ON, 'the target has not been changed yet')
        second = self.make_controller()
        recovered = self.prepare(second)
        self.assertEqual(recovered["desired"], OFF)
        self.assertTrue(recovered["recovery_required"])
        second.cancel()  # Close the read-only recovery window before preview.
        third = self.make_controller()
        recovered_again = self.prepare(third)
        self.assertEqual(recovered_again["desired"], OFF,
                         'another cancelled inspection must not replace a pending disable with enabled target defaults')
        self.assertTrue(recovered_again["recovery_required"])
        self.assertEqual(self.backend.calls, [("gate", False)], 'recovery preparation is read-only')
        self.assertFalse(self.backend.policy["enabled"])
        self.assertEqual(self.backend.current, ON)

    def test_identity_mismatch_is_rejected_before_review_and_credentials_are_cleared(self):
        self.backend.identity["agent_token_sha256"] = "9"*64
        credentials = {"username": "admin", "password": "memory-only-fixture"}
        with self.assertRaises(FeatureError):
            self.controller.prepare(target_options=ConnectionOptions("target.example", user="root"), server_id=SID,
                bundle=self.root / "approved.tar.gz", credentials=credentials)
        self.assertEqual(credentials, {}); self.assertEqual(self.backend.calls, [])

    def test_partial_target_reply_never_reopens_gate_and_next_prepare_uses_fresh_actual_state(self):
        self.prepare(); self.controller.preview(ON); self.backend.fail_target = True
        with self.assertRaises(FeatureError): self.controller.apply()
        self.assertFalse(self.backend.policy["enabled"])
        old = self.journal.list(); self.assertEqual(len(old), 1); self.assertEqual(old[0]["phase"], "uncertain")
        self.backend.fail_target = False
        second = self.make_controller(); info = self.prepare(second)
        self.assertEqual(info["desired"], ON); self.assertTrue(info["recovery_required"])
        second.preview(ON); second.apply()
        self.assertTrue(self.backend.policy["enabled"])
        self.assertEqual(self.journal.list(), []); self.assertEqual(self.backend.stages, {})

    def test_cancel_before_start_has_no_network_and_clears_credentials(self):
        self.controller.cancel(); credentials = {"username": "admin", "password": "memory-only-fixture"}
        with self.assertRaises(FeatureCancelled): self.controller.list_servers(credentials=credentials)
        self.assertEqual(credentials, {}); self.assertEqual(self.api.logins, 0)

    def test_lost_final_reply_can_be_explicitly_reconciled_when_actual_flags_already_match(self):
        self.prepare(); self.controller.preview(ON)
        original = self.api.set_management
        def lose_open_reply(expected, enabled):
            result = original(expected, enabled)
            if enabled:
                raise FeatureError('lost reply after commit')
            return result
        with patch.object(self.api, 'set_management', side_effect=lose_open_reply):
            with self.assertRaises(FeatureError): self.controller.apply()
        self.assertEqual(self.backend.current, ON); self.assertTrue(self.backend.policy['enabled'])
        second = self.make_controller(); info = self.prepare(second)
        self.assertTrue(info['recovery_required'])
        plan = second.preview(ON)
        self.assertTrue(plan['change_required'], 'recovery must offer an explicit final verification')
        result = second.apply()
        self.assertFalse(result['recovery_required'])
        self.assertEqual(self.journal.list(), [])

    def test_journal_whitelist_rejects_secrets_and_actual_file_is_private(self):
        self.prepare()
        path = self.journal.root / (self.controller.record["request_id"] + '.json')
        self.journal._inspect(path)
        text = path.read_text(); self.assertNotIn('memory-only-fixture', text)
        before = path.read_bytes()
        with self.assertRaises(EnrollmentJournalError):
            self.journal.update(self.controller.record["request_id"], {'password': 'must-not-be-saved'},
                                self.controller.record["revision"])
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__': unittest.main()
