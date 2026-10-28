# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Safety checks around per-host pinned automatic update approvals."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from sovagrid_connect.auto_update import (
    AutoUpdateError, AutoUpdatePolicy, AutoUpdatePolicyStore, run_pinned_update, target_id,
)
from sovagrid_connect.core import ConnectionOptions


class InstallerFixture:
    def __init__(self, digest: str, manifest: str, options: ConnectionOptions,
                 *, automatic: bool = False):
        self.digest = digest
        self.manifest = manifest
        self.options = options
        self.events = []
        if automatic:
            self.apply_automatic_update = self._automatic

    def preview_update(self, archive: Path, *, expected_sha256: str):
        self.events.append(("preview", archive, expected_sha256))
        return SimpleNamespace(sha256=self.digest, current_manifest_sha256=self.manifest)

    def prepare_update(self, archive: Path, *, expected_sha256: str):
        self.events.append(("prepare", archive, expected_sha256))
        return SimpleNamespace(sha256=self.digest,
                               remote_path=f"/opt/sovagrid-candidates/{self.digest}")

    def apply_update(self, *_args, **_kwargs):
        raise AssertionError("Manual update must never be called automatically")

    def _automatic(self, prepared, *, expected_current_manifest: str):
        self.events.append(("apply-auto", prepared.sha256, expected_current_manifest))


class AutoUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / "candidate.tar.gz"
        self.archive.write_bytes(b"immutable fixture archive")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.manifest = "a" * 64
        self.options = ConnectionOptions(host="server.example", user="root")
        self.now = datetime(2026, 10, 26, 2, 0, tzinfo=timezone.utc).timestamp()

    def policy(self, **changes):
        return replace(AutoUpdatePolicy.approve(
            self.options, self.archive, self.digest, self.manifest, enabled=True,
        ), **changes)

    def test_disabled_or_wrong_route_never_opens_ssh(self):
        installer = InstallerFixture(self.digest, self.manifest, self.options)
        disabled = replace(self.policy(), enabled=False)
        self.assertEqual(run_pinned_update(disabled, self.options, installer, now=self.now).status, "disabled")
        with self.assertRaises(AutoUpdateError):
            run_pinned_update(self.policy(), ConnectionOptions("other.example", "root"),
                              installer, now=self.now)
        installer.options = ConnectionOptions("other.example", "root")
        with self.assertRaises(AutoUpdateError):
            run_pinned_update(self.policy(), self.options, installer, now=self.now)
        self.assertEqual(installer.events, [])

    def test_window_and_changed_archive_fail_before_ssh(self):
        installer = InstallerFixture(self.digest, self.manifest, self.options)
        policy = self.policy(window_start_utc=23, window_end_utc=1)
        self.assertEqual(run_pinned_update(policy, self.options, installer, now=self.now).status,
                         "outside_window")
        policy = self.policy()
        self.archive.write_bytes(b"changed fixture archive")
        with self.assertRaises(AutoUpdateError):
            run_pinned_update(policy, self.options, installer, now=self.now)
        self.assertEqual(installer.events, [])
        self.archive.unlink()
        self.archive.symlink_to(self.root / "other.tar.gz")
        with self.assertRaises(AutoUpdateError):
            run_pinned_update(policy, self.options, installer, now=self.now)
        self.assertEqual(installer.events, [])

    def test_stale_server_manifest_never_stages_or_applies(self):
        installer = InstallerFixture(self.digest, "b" * 64, self.options, automatic=True)
        with self.assertRaises(AutoUpdateError):
            run_pinned_update(self.policy(), self.options, installer, now=self.now)
        self.assertEqual([event[0] for event in installer.events], ["preview"])

    def test_old_client_only_stages_and_new_idle_gated_client_applies(self):
        installer = InstallerFixture(self.digest, self.manifest, self.options)
        self.assertEqual(run_pinned_update(self.policy(), self.options, installer, now=self.now).status,
                         "staged")
        self.assertEqual([event[0] for event in installer.events], ["preview", "prepare"])
        enabled = InstallerFixture(self.digest, self.manifest, self.options, automatic=True)
        self.assertEqual(run_pinned_update(self.policy(), self.options, enabled, now=self.now).status,
                         "applied")
        self.assertEqual([event[0] for event in enabled.events], ["preview", "prepare", "apply-auto"])
        self.assertEqual(enabled.events[-1][1:], (self.digest, self.manifest))

    def test_private_policy_store_refuses_symlinks_and_unknown_fields(self):
        folder = self.root / "policies"
        store = AutoUpdatePolicyStore(folder)
        policy = self.policy()
        self.assertIsNone(store.load(policy.target_id))
        store.save(policy)
        self.assertEqual(store.load(target_id(self.options)), policy)
        destination = folder / (policy.target_id + ".json")
        if os.name != "nt":
            destination.chmod(0o644)
            with self.assertRaises(AutoUpdateError):
                store.load(policy.target_id)
            destination.chmod(0o600)
        destination.write_text(json.dumps({**json.loads(destination.read_text()), "untrusted": True}))
        with self.assertRaises(AutoUpdateError):
            store.load(policy.target_id)
        destination.unlink()
        destination.symlink_to(self.archive)
        with self.assertRaises(AutoUpdateError):
            store.load(policy.target_id)
        with self.assertRaises(AutoUpdateError):
            store.save(policy)

    def test_bool_is_not_valid_hour_or_digest(self):
        with self.assertRaises(AutoUpdateError):
            self.policy(window_start_utc=True).validated()
        with self.assertRaises(AutoUpdateError):
            self.policy(archive_sha256="0" * 63).validated()


if __name__ == "__main__":
    unittest.main()
