# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
import contextlib
import io
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from unittest import mock
import uuid

from sovagrid_connect.enrollment_api import EnrollmentAPI, EnrollmentAPIError, enrollment_reply

TOKEN = 'test-admin-token-for-local-fixture'
BORROWED = 'b' * 43
EID, SID = str(uuid.uuid4()), str(uuid.uuid4())
USER = {'id': str(uuid.uuid4()), 'username': 'owner', 'role': 'admin', 'enabled': True}
ACCESS = {'access': {'mode': 'all', 'revision': 0, 'unrestricted_admin': True}}


class Tunnel:
    url = 'http://127.0.0.1:18766'
    alive = True


def record(**changes):
    return {'id': EID, 'server_id': SID, 'name': 'Target', 'state': 'pending',
            'revision': 1, 'created_at': 100, 'last_seen': None} | changes


class Harness:
    def __init__(self, hook=None):
        self.calls = []
        self.tunnel = Tunnel()
        self.hook = hook
        self.client = EnrollmentAPI(self.tunnel, opener=self.open)

    def open(self, request, timeout):
        self.calls.append(request)
        value = self.hook(request) if self.hook else None
        if value is None:
            if request.full_url.endswith('/session/access'):
                value = ACCESS
            elif request.full_url.endswith('/session'):
                value = {'user': dict(USER)}
                if request.method == 'POST':
                    value['token'] = TOKEN
            else:
                value = {'protocol': 1, 'enrollment': record()}
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        return contextlib.closing(io.BytesIO(raw))


class EnrollmentAPITests(unittest.TestCase):
    def test_borrowed_browser_admin_session_registers_without_login_or_revoking_browser(self):
        h = Harness(); h.client.adopt_bearer(BORROWED)
        self.assertEqual([req.method for req in h.calls], ['GET', 'GET'])
        self.assertEqual(h.client.register(EID, SID, 'Target', '1' * 64), record())
        self.assertEqual([req.method for req in h.calls], ['GET', 'GET', 'GET', 'GET', 'POST'])
        self.assertEqual(h.calls[-1].get_header('Authorization'), 'Bearer ' + BORROWED)
        self.assertNotIn(BORROWED, repr(h.client))
        self.assertTrue(all(BORROWED not in req.full_url for req in h.calls))
        h.client.logout()
        self.assertEqual(h.calls[-1].method, 'POST')
        self.assertIsNone(h.client._token)

    def test_borrowed_session_refuses_limited_or_malformed_access_before_registration(self):
        for access in [
            {'access': {'mode': 'selected', 'revision': 1, 'unrestricted_admin': False}},
            {'access': {'mode': 'all', 'revision': True, 'unrestricted_admin': True}},
            {'access': {'mode': 'all', 'revision': 0, 'unrestricted_admin': True, 'secret': 'unexpected'}},
        ]:
            with self.subTest(access=access):
                h = Harness(lambda req: access if req.full_url.endswith('/session/access') else None)
                with self.assertRaises(EnrollmentAPIError): h.client.adopt_bearer(BORROWED)
                self.assertIsNone(h.client._token)
                self.assertFalse(any(req.method == 'POST' or req.method == 'DELETE' for req in h.calls))

    def test_borrowed_session_detects_access_revision_change_before_mutation(self):
        revision = 0
        def hook(req):
            if req.full_url.endswith('/session/access'):
                return {'access': ACCESS['access'] | {'revision': revision}}
        h = Harness(hook); h.client.adopt_bearer(BORROWED); revision = 1
        with self.assertRaises(EnrollmentAPIError):
            h.client.register(EID, SID, 'Target', '1' * 64)
        self.assertIsNone(h.client._token)
        self.assertFalse(any('/agent-enrollments/' in req.full_url or req.method == 'DELETE' for req in h.calls))

    def test_borrowed_session_detects_role_change_and_never_revokes_browser_token(self):
        role = 'admin'
        def hook(req):
            if req.full_url.endswith('/session'):
                return {'user': USER | {'role': role}}
        h = Harness(hook); h.client.adopt_bearer(BORROWED); role = 'viewer'
        with self.assertRaises(EnrollmentAPIError):
            h.client.register(EID, SID, 'Target', '1' * 64)
        self.assertIsNone(h.client._token)
        self.assertFalse(any('/agent-enrollments/' in req.full_url or req.method == 'DELETE' for req in h.calls))

    def test_revoked_browser_token_cannot_be_replayed_into_enrollment(self):
        def hook(req):
            if req.full_url.endswith('/session'):
                raise HTTPError(req.full_url, 401, 'revoked', {}, io.BytesIO(b'{}'))
        h = Harness(hook)
        with self.assertRaises(EnrollmentAPIError): h.client.adopt_bearer(BORROWED)
        self.assertIsNone(h.client._token)
        self.assertFalse(any('/agent-enrollments/' in req.full_url or req.method == 'DELETE' for req in h.calls))

    def test_replacing_borrowed_session_does_not_delete_it(self):
        h = Harness(); h.client.adopt_bearer(BORROWED)
        h.client.login('owner', 'fixture-password')
        self.assertFalse(any(req.method == 'DELETE' and req.get_header('Authorization') == 'Bearer ' + BORROWED
                             for req in h.calls))
        h.client.logout()
        self.assertEqual(h.calls[-1].method, 'DELETE')
        self.assertEqual(h.calls[-1].get_header('Authorization'), 'Bearer ' + TOKEN)

    def test_stale_http_error_cannot_clear_re_adopted_same_browser_token(self):
        started = threading.Event(); release = threading.Event(); errors = []
        block_once = False
        def hook(req):
            nonlocal block_once
            if block_once and req.method == 'GET' and req.full_url.endswith('/session'):
                block_once = False
                started.set(); self.assertTrue(release.wait(3))
                raise HTTPError(req.full_url, 401, 'stale', {}, io.BytesIO(b'{}'))
        h = Harness(hook); h.client.adopt_bearer(BORROWED)
        block_once = True
        def get():
            try: h.client.get(EID)
            except EnrollmentAPIError as error: errors.append(error)
        thread = threading.Thread(target=get); thread.start()
        self.assertTrue(started.wait(3))
        h.client.adopt_bearer(BORROWED)
        release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors)
        self.assertEqual(h.client._token, BORROWED)
        h.client.logout()
        self.assertFalse(any(req.method == 'DELETE' for req in h.calls))

    def test_only_verified_live_loopback_tunnel_is_accepted(self):
        for url in ['http://example.com', 'https://127.0.0.1:80', 'http://localhost:80',
                    'http://127.0.0.1:80/?secret', 'http://a:b@127.0.0.1:80', 'http://127.0.0.1:80/path']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                EnrollmentAPI(type('Wrong', (), {'url': url, 'alive': True})())
        with self.assertRaises(EnrollmentAPIError):
            EnrollmentAPI(type('Closed', (), {'url': Tunnel.url, 'alive': False})())

    def test_login_and_hash_registration_keep_credentials_out_of_urls_and_repr(self):
        h = Harness(); h.client.login('owner', 'a-private-fixture-passphrase')
        digest = '1' * 64
        self.assertEqual(h.client.register(EID, SID, 'Target', digest), record())
        req = h.calls[-1]
        self.assertEqual(req.full_url, Tunnel.url + '/api/v1/agent-enrollments/' + EID)
        self.assertEqual(json.loads(req.data), {'server_id': SID, 'name': 'Target', 'agent_token_sha256': digest})
        self.assertEqual(req.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertNotIn(TOKEN, repr(h.client))
        self.assertTrue(all('private-fixture' not in req.full_url and TOKEN not in req.full_url for req in h.calls))
        h.client.logout()
        self.assertEqual(h.calls[-1].method, 'DELETE')
        with self.assertRaises(EnrollmentAPIError):
            h.client.get(EID)

    def test_mutation_checks_current_admin_identity_and_declines_a_changed_user(self):
        changed = False
        def hook(req):
            if req.method == 'GET' and req.full_url.endswith('/session') and changed:
                return {'user': USER | {'id': str(uuid.uuid4())}}
        h = Harness(hook); h.client.login('owner', 'fixture-password'); changed = True
        with self.assertRaises(EnrollmentAPIError):
            h.client.register(EID, SID, 'Target', '2' * 64)
        self.assertFalse(any('/agent-enrollments/' in r.full_url for r in h.calls))
        self.assertIsNone(h.client._token)

    def test_viewer_login_revokes_issued_session_and_never_registers(self):
        def hook(req):
            if req.method == 'POST':
                return {'token': TOKEN, 'user': USER | {'role': 'viewer'}}
        h = Harness(hook)
        with self.assertRaises(EnrollmentAPIError):
            h.client.login('reader', 'fixture-password')
        self.assertEqual(h.calls[-1].method, 'DELETE')
        self.assertIsNone(h.client._token)

    def test_response_limit_duplicate_fields_and_malformed_identity_fail_closed(self):
        for value in [b'x' * 4097, b'[' * 1500 + b']' * 1500, b'{"token":"first","token":"second"}',
                      {'token': TOKEN, 'user': None}, {'token': TOKEN, 'user': USER | {'role': 'superadmin'}}]:
            h = Harness(lambda req: value if req.method == 'POST' else {})
            with self.subTest(value=type(value).__name__), self.assertRaises(EnrollmentAPIError):
                h.client.login('owner', 'fixture-password')
            self.assertIsNone(h.client._token)

    def test_http_failure_does_not_echo_a_remote_secret_or_blindly_retry(self):
        active = False
        def hook(req):
            if active and '/agent-enrollments/' in req.full_url:
                raise HTTPError(req.full_url, 503, 'remote-private-canary', {}, io.BytesIO(b'remote-private-canary'))
        h = Harness(hook); h.client.login('owner', 'fixture-password'); active = True
        with self.assertRaises(EnrollmentAPIError) as caught:
            h.client.register(EID, SID, 'Target', '3' * 64)
        self.assertNotIn('remote-private-canary', str(caught.exception))
        self.assertEqual(sum('/agent-enrollments/' in r.full_url for r in h.calls), 1)

    def test_late_login_after_logout_cannot_restore_a_session(self):
        started = threading.Event(); release = threading.Event(); errors = []
        def hook(req):
            if req.method == 'POST':
                started.set(); self.assertTrue(release.wait(3))
        h = Harness(hook)
        def login():
            try:
                h.client.login('owner', 'fixture-password')
            except EnrollmentAPIError as error:
                errors.append(error)
        thread = threading.Thread(target=login); thread.start()
        self.assertTrue(started.wait(3)); h.client.logout(); release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors)
        self.assertIsNone(h.client._token)
        self.assertEqual(h.calls[-1].method, 'DELETE')

    def test_late_identity_reply_does_not_revoke_a_new_session(self):
        started = threading.Event(); release = threading.Event(); errors = []
        blocking = False
        def hook(req):
            if blocking and req.method == 'GET' and req.full_url.endswith('/session'):
                started.set(); self.assertTrue(release.wait(3))
                return {'user': USER | {'id': 'old-invalid-id'}}
        h = Harness(hook); h.client.login('owner', 'fixture-password'); blocking = True
        def get():
            try:
                h.client.get(EID)
            except EnrollmentAPIError as error:
                errors.append(error)
        thread = threading.Thread(target=get); thread.start(); self.assertTrue(started.wait(3))
        h.client.logout(); blocking = False
        # New server-issued token, as real Hub sessions are always unique.
        h.hook = lambda req: {'token': TOKEN + '-new', 'user': USER} if req.method == 'POST' else None
        h.client.login('owner', 'fixture-password'); release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertTrue(errors)
        self.assertEqual(h.client._token, TOKEN + '-new')

    def test_tunnel_closure_prevents_sending_credentials(self):
        h = Harness(); h.client.login('owner', 'fixture-password'); count = len(h.calls)
        h.tunnel.alive = False
        with self.assertRaises(EnrollmentAPIError):
            h.client.get(EID)
        self.assertEqual(len(h.calls), count)

    def test_late_operation_response_after_logout_or_new_login_is_not_success(self):
        for action in ['get', 'register', 'cancel']:
            for relogin in [False, True]:
                with self.subTest(action=action, relogin=relogin):
                    started = threading.Event(); release = threading.Event(); errors = []; values = []
                    def hook(req):
                        if '/agent-enrollments/' in req.full_url:
                            started.set(); self.assertTrue(release.wait(3))
                            return {'protocol': 1, 'enrollment': record(state='cancelled', revision=2) if action == 'cancel' else record()}
                    h = Harness(hook); h.client.login('owner', 'fixture-password')
                    def worker():
                        try:
                            if action == 'get': value = h.client.get(EID)
                            elif action == 'register': value = h.client.register(EID, SID, 'Target', '3' * 64)
                            else: value = h.client.cancel(EID, 1)
                            values.append(value)
                        except EnrollmentAPIError as error:
                            errors.append(error)
                    thread = threading.Thread(target=worker); thread.start(); self.assertTrue(started.wait(3))
                    h.client.logout()
                    if relogin:
                        h.hook = lambda req: {'token': TOKEN + '-new', 'user': USER} if req.method == 'POST' else None
                        h.client.login('owner', 'fixture-password')
                    release.set(); thread.join(3)
                    self.assertFalse(thread.is_alive()); self.assertTrue(errors); self.assertFalse(values)
                    self.assertEqual(h.client._token, TOKEN + '-new' if relogin else None)

    def test_late_wrong_login_does_not_cancel_a_new_valid_login(self):
        first_started = threading.Event(); second_started = threading.Event()
        release_first = threading.Event(); release_second = threading.Event(); errors = []
        count = 0; lock = threading.Lock()
        def hook(req):
            nonlocal count
            if req.method == 'POST':
                with lock:
                    index = count; count += 1
                if index == 0:
                    first_started.set(); self.assertTrue(release_first.wait(3))
                    raise HTTPError(req.full_url, 401, 'wrong', {}, io.BytesIO(b'{}'))
                second_started.set(); self.assertTrue(release_second.wait(3))
                return {'token': TOKEN + '-new', 'user': USER}
        h = Harness(hook)
        def login(password):
            try: h.client.login('owner', password)
            except EnrollmentAPIError as error: errors.append(error)
        first = threading.Thread(target=login, args=('wrong-fixture',)); first.start(); self.assertTrue(first_started.wait(3))
        second = threading.Thread(target=login, args=('right-fixture',)); second.start(); self.assertTrue(second_started.wait(3))
        release_first.set(); first.join(3); release_second.set(); second.join(3)
        self.assertFalse(first.is_alive() or second.is_alive()); self.assertEqual(len(errors), 1)
        self.assertEqual(h.client._token, TOKEN + '-new')

    def test_valid_1024_character_unicode_password_is_not_limited_to_4k_json(self):
        h = Harness(); password = '\U0001f989' * 1024
        h.client.login('owner', password)
        self.assertEqual(json.loads(h.calls[0].data)['password'], password)
        self.assertGreater(len(h.calls[0].data), 4096)
        with self.assertRaises(ValueError): h.client.login('owner', password + 'x')
        with self.assertRaises(ValueError): h.client.login('owner', '\ud800')

    def test_public_enrollment_reply_rejects_extra_secret_and_wrong_types(self):
        for change in [{'id': str(uuid.uuid4())}, {'revision': True}, {'state': 'ready'}, {'state': 'active'},
                       {'last_seen': 101}, {'last_seen': False}, {'token': TOKEN}]:
            with self.subTest(change=tuple(change)), self.assertRaises(EnrollmentAPIError):
                enrollment_reply({'protocol': 1, 'enrollment': record(**change)}, EID)
        self.assertIsNone(enrollment_reply({'protocol': 1, 'enrollment': None}, EID))
        with self.assertRaises(EnrollmentAPIError):
            enrollment_reply({'protocol': True, 'enrollment': record()}, EID)

    def test_real_loopback_http_ignores_proxy_environment(self):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                calls.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                raw = json.dumps({'token': TOKEN, 'user': USER}).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def do_DELETE(self):
                self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        tunnel = Tunnel(); tunnel.url = f'http://127.0.0.1:{server.server_port}'
        try:
            with mock.patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1', 'HTTP_PROXY': 'http://127.0.0.1:1',
                                             'no_proxy': '', 'NO_PROXY': ''}):
                client = EnrollmentAPI(tunnel)
                client.login('owner', 'fixture-private-passphrase'); client.logout()
            self.assertEqual(calls, [('/api/v1/session', {'username': 'owner', 'password': 'fixture-private-passphrase'})])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_real_redirect_cannot_forward_login_body_or_bearer(self):
        received = []
        class Destination(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                received.append('GET'); self.send_response(200); self.end_headers()
            do_POST = do_GET
        destination = ThreadingHTTPServer(('127.0.0.1', 0), Destination)
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(307); self.send_header('Location', f'http://127.0.0.1:{destination.server_port}/private-canary')
                self.send_header('Content-Length', '0'); self.end_headers()
        redirect = ThreadingHTTPServer(('127.0.0.1', 0), Redirect)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in [destination, redirect]]
        for thread in threads: thread.start()
        tunnel = Tunnel(); tunnel.url = f'http://127.0.0.1:{redirect.server_port}'
        try:
            client = EnrollmentAPI(tunnel)
            with self.assertRaises(EnrollmentAPIError) as caught:
                client.login('owner', 'fixture-private-passphrase')
            self.assertEqual(caught.exception.status, 307)
            self.assertNotIn('private-canary', str(caught.exception)); self.assertEqual(received, [])
        finally:
            for server in [redirect, destination]: server.shutdown(); server.server_close()
            for thread in threads: thread.join(2)


if __name__ == '__main__':
    unittest.main()
