# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Server timer status may be displayed only after a bounded strict parse."""

import json
import unittest

from sovagrid_connect.server_timer import parse_server_timer_status


def payload():
    return {"policy": {"format": 1, "archive_sha256": "a" * 64,
                       "expected_current_manifest": "b" * 64,
                       "created_at": 1000, "expires_at": 2000},
            "last": {"format": 1, "state": "armed", "updated_at": 1001,
                     "archive_sha256": "a" * 64,
                     "expected_current_manifest": "b" * 64, "detail": ""}}


class ServerTimerStatusTests(unittest.TestCase):
    def parse(self, value):
        return parse_server_timer_status(json.dumps(value).encode())

    def test_exact_status(self):
        status = self.parse(payload())
        self.assertTrue(status.armed)
        self.assertEqual(status.archive_sha256, "a" * 64)
        self.assertEqual(status.last_state, "armed")
        self.assertFalse(self.parse({"policy": None, "last": None}).armed)

    def test_rejects_extra_fields_wrong_types_and_unbounded_data(self):
        for changed in (
            {**payload(), "token": "do-not-display"},
            {**payload(), "policy": {**payload()["policy"], "expires_at": True}},
            {**payload(), "policy": {**payload()["policy"], "archive_sha256": "bad"}},
            {**payload(), "last": {**payload()["last"], "state": ["armed"]}},
            {**payload(), "last": {**payload()["last"], "detail": "x" * 161}},
        ):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.parse(changed)
        with self.assertRaises(ValueError):
            parse_server_timer_status(b"{" + b"x" * 4096)


if __name__ == "__main__":
    unittest.main()
