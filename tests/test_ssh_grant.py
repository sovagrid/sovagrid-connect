# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

import json
import time
import unittest
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from sovagrid_connect.core import _SSH_GRANT_COMMAND
from sovagrid_connect.ssh_grant import LoopbackGrantBroker, SSHGrant, parse_grant


class SSHGrantTests(unittest.TestCase):
    def test_strict_protocol_and_short_lifetime(self) -> None:
        value = "A" * 43
        raw = json.dumps({"protocol": 1, "grant": value, "expires_at": 1060, "username": "admin"}).encode()
        self.assertEqual(parse_grant(raw, now=1000), SSHGrant(value, 1060, "admin"))
        for changed in (
            {"protocol": 2, "grant": value, "expires_at": 1060, "username": "admin"},
            {"protocol": 1, "grant": "bad", "expires_at": 1060, "username": "admin"},
            {"protocol": 1, "grant": value, "expires_at": 1361, "username": "admin"},
            {"protocol": 1, "grant": value, "expires_at": 699, "username": "admin"},
            {"protocol": 1, "grant": value, "expires_at": 1060, "username": "admin", "extra": True},
        ):
            with self.assertRaises(ValueError):
                parse_grant(json.dumps(changed).encode(), now=1000)

    def test_fresh_ssh_grant_accepts_bounded_server_clock_skew(self) -> None:
        value = "A" * 43
        for expiry in (900, 1220):  # Hub clock 160 s behind or ahead of client.
            raw = json.dumps({"protocol": 1, "grant": value, "expires_at": expiry,
                              "username": "admin"}).encode()
            self.assertEqual(parse_grant(raw, now=1000).expires_at, expiry)

    def test_compose_command_has_no_grant_and_no_root_owned_database_writer(self) -> None:
        self.assertIn("--env-file /etc/sovagrid/deploy.env", _SSH_GRANT_COMMAND)
        self.assertIn("run --rm --no-deps -T --entrypoint python3 hub", _SSH_GRANT_COMMAND)
        self.assertIn("sudo -n", _SSH_GRANT_COMMAND)
        self.assertNotIn("exec -u 0", _SSH_GRANT_COMMAND)

    def test_loopback_broker_rejects_other_origin_and_consumes_once(self) -> None:
        grant = SSHGrant("Z" * 43, int(time.time()) + 45, "admin")
        broker = LoopbackGrantBroker(grant, panel_origin="http://127.0.0.1:8766")
        self.addCleanup(broker.close)
        url = f"http://127.0.0.1:{broker.port}/grant"
        opener = build_opener(ProxyHandler({}))
        try:
            opener.open(Request(url, headers={"Origin": "http://evil.example"}), timeout=3)
        except HTTPError as exc:
            self.assertEqual(exc.code, 403)
        self.assertTrue(broker.available)
        self.assertNotIn(grant.value, broker.browser_url("http://127.0.0.1:8766/"))
        self.assertNotIn(grant.value, broker.browser_url("http://127.0.0.1:8766/sovagrid/monitoring/"))
        with self.assertRaises(ValueError):
            broker.browser_url("http://127.0.0.1:8766/unreviewed/")
        custom = LoopbackGrantBroker(grant, panel_origin="http://127.0.0.1:8766",
                                     panel_path="/ops/panel/")
        self.addCleanup(custom.close)
        self.assertIn("/ops/panel/#sg-bootstrap=", custom.browser_url("http://127.0.0.1:8766/ops/panel/"))
        with self.assertRaises(ValueError):
            custom.browser_url("http://127.0.0.1:8766/other/")
        with opener.open(Request(url, headers={"Origin": "http://127.0.0.1:8766"}), timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "http://127.0.0.1:8766")
            self.assertEqual(json.loads(response.read()), {"grant": grant.value})
        self.assertFalse(broker.available)


if __name__ == "__main__":
    unittest.main()
