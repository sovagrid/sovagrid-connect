# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""One-use loopback handoff from trusted SSH to the browser panel.

Only the port enters the browser URL. The short-lived Hub grant stays in this
process, is handed to the panel's exact loopback origin once, and is never
persisted or placed in argv, browser history, or the clipboard.
"""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import threading
import time


_GRANT = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_PANEL_PATH = re.compile(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}\Z")
# The Hub and phone/desktop clocks can differ. The grant is minted by a
# fixed SSH command immediately before this parse and Hub enforces its own
# one-use 60-second expiry. Bound skew here, then use a separate local TTL.
_MAX_CLOCK_SKEW_SECONDS = 300
_HUB_GRANT_LIFETIME_SECONDS = 60
_LOCAL_HANDOFF_SECONDS = 30


@dataclass(frozen=True)
class SSHGrant:
    value: str
    expires_at: int
    username: str


def parse_grant(raw: bytes, *, now: float | None = None) -> SSHGrant:
    if len(raw) > 512:
        raise ValueError("SSH grant response is too large")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SSH grant response is invalid") from exc
    if not isinstance(record, dict) or set(record) != {"protocol", "grant", "expires_at", "username"}:
        raise ValueError("SSH grant response has unexpected fields")
    if type(record["protocol"]) is not int or record["protocol"] != 1:
        raise ValueError("SSH grant protocol is unsupported")
    value, expiry, username = record["grant"], record["expires_at"], record["username"]
    current = time.time() if now is None else now
    if not isinstance(value, str) or not _GRANT.fullmatch(value) or \
       type(expiry) is not int or \
       not current - _MAX_CLOCK_SKEW_SECONDS < expiry <= current + _MAX_CLOCK_SKEW_SECONDS + _HUB_GRANT_LIFETIME_SECONDS or \
       not isinstance(username, str) or not 1 <= len(username) <= 64:
        raise ValueError("SSH grant response is invalid")
    return SSHGrant(value, expiry, username)


class LoopbackGrantBroker:
    """Expose a grant exactly once to one panel origin for at most 60 seconds."""

    def __init__(self, grant: SSHGrant, *, panel_origin: str,
                 panel_path: str = "/sovagrid/monitoring/") -> None:
        if not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", panel_origin):
            raise ValueError("SSH grant handoff requires a loopback panel")
        if panel_path != "/" and _PANEL_PATH.fullmatch(panel_path) is None:
            raise ValueError("SSH grant handoff requires a validated panel path")
        self._grant: SSHGrant | None = grant
        self._origin = panel_origin
        self._panel_url = panel_origin + panel_path
        self._lock = threading.Lock()
        self._deadline = time.monotonic() + _LOCAL_HANDOFF_SECONDS
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._server.daemon_threads = True
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._timer = threading.Timer(_LOCAL_HANDOFF_SECONDS, self.close)
        self._timer.daemon = True
        self._thread.start()
        self._timer.start()

    def _handler(self):
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                pass

            def _send(self, status: int, body: bytes = b"") -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Vary", "Origin")
                if self.headers.get("Origin") == broker._origin:
                    self.send_header("Access-Control-Allow-Origin", broker._origin)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path != "/grant" or self.headers.get("Host") != f"127.0.0.1:{broker.port}" or \
                   self.headers.get("Origin") != broker._origin:
                    self._send(403)
                    return
                with broker._lock:
                    grant = broker._grant
                    if grant is None or time.monotonic() >= broker._deadline:
                        self._send(410)
                        return
                    broker._grant = None
                try:
                    self._send(200, json.dumps({"grant": grant.value}, separators=(",", ":")).encode("ascii"))
                finally:
                    threading.Thread(target=broker.close, daemon=True).start()

        return Handler

    def browser_url(self, panel_url: str) -> str:
        if panel_url not in (self._origin + "/", self._panel_url):
            raise ValueError("panel origin changed")
        return panel_url + "#sg-bootstrap=" + str(self.port)

    @property
    def available(self) -> bool:
        with self._lock:
            return self._grant is not None and time.monotonic() < self._deadline

    def close(self) -> None:
        with self._lock:
            self._grant = None
        self._timer.cancel()
        self._server.shutdown()
        self._server.server_close()
