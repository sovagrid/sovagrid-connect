# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""A dual release approval chooses one installed digest without widening proof."""

import unittest

from sovagrid_connect.approved_manifest import ApprovedManifestSet, ApprovedManifestMixin
from sovagrid_connect.installer import InstallError


OLD = "a" * 64
NEW = "b" * 64
OTHER = "c" * 64


class Transport:
    def __init__(self, digest=NEW, *, sudo=False):
        self._privileged = "sudo -n -- " if sudo else ""
        self.digest = digest
        self.calls = []
        self.root_proofs = 0
        self.reply = None

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout, limit):
        self.calls.append((command, timeout, limit))
        return 0, self.reply if self.reply is not None else (
            self.digest + "  /opt/sovagrid-src/sovagrid-bundle.json\n").encode()


class VpnStyleController(ApprovedManifestMixin):
    def __init__(self, transport, approved):
        self.transport = transport
        self.manifest = approved


class ManifestApprovalTests(unittest.TestCase):
    def test_both_reviewed_releases_resolve_lazily_and_cache_one_digest(self):
        for digest in (OLD, NEW):
            with self.subTest(digest=digest):
                transport = Transport(digest, sudo=True)
                controller = VpnStyleController(transport, (OLD, NEW))
                self.assertEqual(transport.calls, [])
                self.assertEqual(controller.manifest, digest)
                self.assertEqual(controller.approved_manifest_sha256, digest)
                self.assertEqual(transport.root_proofs, 1)
                self.assertEqual(transport.calls, [
                    ("sudo -n -- /usr/bin/sha256sum -- /opt/sovagrid-src/sovagrid-bundle.json",
                     45, 256)])

    def test_single_existing_pin_and_disabled_gate_do_not_probe_ssh(self):
        transport = Transport()
        self.assertEqual(ApprovedManifestSet(OLD).resolve(transport), OLD)
        self.assertIsNone(ApprovedManifestSet(None).resolve(transport))
        self.assertEqual(transport.calls, [])

    def test_unreviewed_or_malformed_remote_digest_refused(self):
        for digest, raw in ((OTHER, None), (NEW, b"bad reply"),
                            (NEW, (NEW + "  /wrong/path\n").encode())):
            with self.subTest(digest=digest, raw=raw):
                transport = Transport(digest)
                transport.reply = raw
                with self.assertRaises(InstallError):
                    ApprovedManifestSet((OLD, NEW)).resolve(transport)
                self.assertEqual(len(transport.calls), 1)

    def test_invalid_allowlist_rejected_before_any_ssh(self):
        for value in ((OLD, OLD), (OLD, "not-a-sha"), (OLD, []),
                      tuple(f"{index:064x}" for index in range(17)),
                      [OLD, NEW], 42):
            with self.subTest(value=value):
                with self.assertRaises(InstallError):
                    ApprovedManifestSet(value)


if __name__ == "__main__":
    unittest.main()
