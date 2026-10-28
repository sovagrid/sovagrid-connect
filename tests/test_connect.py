# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.request import urlopen

from sovagrid_connect.askpass import classify_prompt, helper_path, main as askpass_main
from sovagrid_connect.core import ConnectionOptions, Tunnel, TunnelError, _proxy_safe_path, _ssh_config


FAKE_SSH = r'''
import http.server
import json
import signal
import socketserver
import sys
import time

args = sys.argv[1:]
config = open(args[args.index("-F") + 1], encoding="utf-8").read()
if "--fail" in config:
    sys.exit(37)
if "-L" not in args:
    if args[-2:] != ["sovagrid-target", "head -c 257 /etc/sovagrid/admin-password"]:
        sys.exit(39)
    if "--credential-denied" in config:
        sys.exit(1)
    if "--credential-slow" in config:
        time.sleep(10)
    if "--credential-oversized" in config:
        sys.stdout.buffer.write(b"A" * 100000)
        sys.stdout.buffer.flush()
        time.sleep(10)
    if "--credential-malformed" in config:
        sys.stdout.buffer.write(b"not a generated bootstrap password\n")
    else:
        sys.stdout.buffer.write(b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\n")
    sys.exit(0)
port = int(args[args.index("-L") + 1].split(":")[1])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            data = b'{"ok":false}' if "--bad-health" in config else b'{"ok":true}'
        elif self.path == "/api/v1/panel-location" and "custom.invalid" in config:
            data = b'{"panel_path":"/ops/panel/"}'
        elif self.path == "/api/v1/panel-location" and "invalid-path.invalid" in config:
            data = b'{"panel_path":"//other/"}'
        elif self.path == "/ops/panel/" and "custom.invalid" in config:
            data = b'<title>SovaGrid</title>'
        elif self.path == "/sovagrid/monitoring/" and "legacy.invalid" not in config:
            data = b'<title>SovaGrid</title>'
        elif self.path == "/":
            data = b'<title>SovaGrid</title>'
        elif self.path.endswith("/manifest.webmanifest") and (self.path == "/manifest.webmanifest" or
                "legacy.invalid" not in config):
            data = json.dumps({"name": "SovaGrid — управление серверами"}).encode()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if self.path == "/healthz" else
                         "application/json" if self.path == "/api/v1/panel-location" else
                         "application/manifest+json" if self.path.endswith(".webmanifest") else "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *_args):
        pass
class LoopbackServer(http.server.HTTPServer):
    def server_bind(self):
        # HTTPServer normally calls getfqdn() after bind. Runner reverse DNS
        # can stall that call even though this fixture only serves loopback.
        socketserver.TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]
server = LoopbackServer(("127.0.0.1", port), Handler)
if "--no-forward-marker" not in config:
    with open(args[args.index("-E") + 1], "a", encoding="utf-8") as log:
        log.write("Authenticated to fixture using publickey.\n")
        log.write(f"debug1: Local forwarding listening on 127.0.0.1 port {port}.\n")
signal.signal(signal.SIGTERM, lambda *_args: sys.exit(0))
server.serve_forever()
'''


class ConnectionTests(unittest.TestCase):
    def test_askpass_prompt_classification_and_output_channel(self) -> None:
        prompt = (
            "The authenticity of host 'example.org (192.0.2.4)' can't be established.\n"
            "ED25519 key fingerprint is SHA256:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno.\n"
            "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
        )
        self.assertEqual(classify_prompt(prompt), "host_key")
        self.assertEqual(classify_prompt("Are you sure you want to continue connecting (yes/no)?"), "deny")
        self.assertEqual(classify_prompt("REMOTE HOST IDENTIFICATION HAS CHANGED!"), "deny")
        self.assertEqual(classify_prompt("operator@example.org's password:"), "secret")
        self.assertEqual(classify_prompt("Enter passphrase for key '/tmp/id_ed25519':"), "secret")
        self.assertEqual(classify_prompt("Enter passphrase (empty for no passphrase):"), "secret")
        self.assertEqual(classify_prompt("Enter same passphrase again:"), "secret")
        self.assertEqual(classify_prompt("Verification code:"), "secret")
        self.assertEqual(classify_prompt("Run a remote command?"), "deny")
        output = []
        with patch("sovagrid_connect.askpass._ask_secret", return_value="private secret"), \
             patch("sovagrid_connect.askpass.os.write", side_effect=lambda fd, data: output.append((fd, data))):
            self.assertEqual(askpass_main(["operator@example.org's password:"]), 0)
        self.assertEqual(output, [(1, b"private secret\n")])
        with patch("sovagrid_connect.askpass._ask_secret", return_value="line one\nline two"), \
             patch("sovagrid_connect.askpass.os.write") as writer:
            self.assertEqual(askpass_main(["Password:"]), 1)
            writer.assert_not_called()

    @unittest.skipIf(os.name == "nt", "source-mode helper needs a packaged Windows executable")
    def test_source_askpass_launcher_is_private_and_has_pipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(helper_path(directory))
            self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o700)
            self.assertNotIn("password", helper.read_text().lower())
            result = subprocess.run([str(helper), "--self-test"], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b"SovaGrid askpass pipe OK\n")

    @unittest.skipIf(os.name == "nt", "source-mode helper needs a packaged Windows executable")
    def test_gui_tunnel_uses_askpass_and_confirmed_host_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            captured = {}

            def fake_popen(argv, **kwargs):
                captured["argv"] = argv
                captured["kwargs"] = kwargs
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="operator", ssh_executable=sys.executable),
                gui_prompts=True, popen=fake_popen,
            )
            tunnel.start(timeout=3)
            try:
                config = Path(tunnel._directory.name, "ssh_config").read_text()
                self.assertIn("StrictHostKeyChecking ask", config)
                self.assertIn("FingerprintHash sha256", config)
                self.assertNotIn("BatchMode yes", config)
                environment = captured["kwargs"]["env"]
                self.assertEqual(environment["SSH_ASKPASS_REQUIRE"], "force")
                self.assertEqual(captured["kwargs"]["stdin"], subprocess.DEVNULL)
                self.assertEqual(captured["kwargs"]["stderr"], subprocess.DEVNULL)
                self.assertEqual(Path(environment["SSH_ASKPASS"]).parent, Path(tunnel._directory.name))
                self.assertNotIn("private secret", str(captured))
            finally:
                tunnel.close()

    def test_windows_proxyjump_config_path_uses_safe_forward_slashes(self) -> None:
        self.assertEqual(_proxy_safe_path(r"C:\Temp\sovagrid-connect-123\ssh_config"),
                         "C:/Temp/sovagrid-connect-123/ssh_config")
        self.assertIsNone(_proxy_safe_path(r"C:\Users\My Name\ssh_config"))

    def test_rejects_injection_and_bad_options(self) -> None:
        for host in ["-oProxyCommand=evil", "server;touch /tmp/x", "a b", "bad\nHost *", "foo@bar"]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                ConnectionOptions(host=host, user="root").validated()
        with self.assertRaises(ValueError):
            ConnectionOptions(host="example.org", user="root;id").validated()
        with self.assertRaises(ValueError):
            ConnectionOptions(host="example.org", user="root", jump_user="admin").validated()
        with self.assertRaises(ValueError):
            ConnectionOptions(host="example.org", user="root", remote_port=0).validated()

    def test_ipv6_and_separate_jump_key_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target_key = Path(directory, "target key")
            jump_key = Path(directory, "jump key")
            target_key.write_text("fixture")
            jump_key.write_text("fixture")
            options = ConnectionOptions(
                host="[2001:db8::3]",
                user="ubuntu",
                port=2223,
                jump_host="relay.example.net",
                jump_user="relay",
                identity=str(target_key),
                jump_identity=str(jump_key),
                host_key_alias="home-via-vps",
            ).validated()
            config = _ssh_config(options)
            self.assertIn("StrictHostKeyChecking yes", config)
            self.assertIn("ProxyJump sovagrid-jump", config)
            self.assertIn("HostKeyAlias home-via-vps", config)
            self.assertIn("HostName 2001:db8::3", config)
            self.assertIn('IdentityFile "' + target_key.resolve().as_posix() + '"', config)
            self.assertIn('IdentityFile "' + jump_key.resolve().as_posix() + '"', config)
            self.assertNotIn("StrictHostKeyChecking accept-new", config)
            self.assertIn("BatchMode yes", _ssh_config(options, batch_mode=True))
            if shutil.which("ssh"):
                config_file = Path(directory, "ssh_config")
                config_file.write_text(config)
                for alias, identity in [
                    ("sovagrid-target", target_key.resolve()),
                    ("sovagrid-jump", jump_key.resolve()),
                ]:
                    result = subprocess.run(
                        ["ssh", "-G", "-F", str(config_file), alias],
                        check=True, capture_output=True, text=True, timeout=5,
                    )
                    self.assertIn(f"identityfile {identity.as_posix()}", result.stdout)

    def test_opens_only_verified_panel_and_cleans_temporary_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="operator", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            tunnel.start(timeout=3)
            try:
                self.assertTrue(tunnel.alive)
                self.assertTrue(tunnel.url.startswith("http://127.0.0.1:"))
                self.assertTrue(tunnel.panel_url.endswith("/sovagrid/monitoring/"))
                self.assertIn(b"SovaGrid", urlopen(tunnel.panel_url, timeout=1).read())
                config = Path(tunnel._directory.name, "ssh_config")
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                self.assertIn("StrictHostKeyChecking yes", config.read_text())
                self.assertIn("127.0.0.1:", tunnel._process.args[tunnel._process.args.index("-L") + 1])
                self.assertIsInstance(tunnel._process.args, list)
                temporary = Path(tunnel._directory.name)
            finally:
                tunnel.close()
            self.assertFalse(temporary.exists())
            self.assertFalse(tunnel.alive)

    def test_legacy_server_uses_root_when_prefixed_assets_are_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            tunnel = Tunnel(ConnectionOptions(host="legacy.invalid", user="operator",
                                              ssh_executable=sys.executable), popen=fake_popen)
            try:
                tunnel.start(timeout=3)
                self.assertTrue(tunnel.panel_url.endswith("/"))
                self.assertFalse(tunnel.panel_url.endswith("/sovagrid/monitoring/"))
            finally:
                tunnel.close()

    def test_advertised_custom_panel_path_is_verified_before_opening(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            tunnel = Tunnel(ConnectionOptions(host="custom.invalid", user="operator",
                                              ssh_executable=sys.executable), popen=fake_popen)
            try:
                tunnel.start(timeout=3)
                self.assertTrue(tunnel.panel_url.endswith("/ops/panel/"))
            finally:
                tunnel.close()

    def test_invalid_advertised_path_never_falls_back_to_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            tunnel = Tunnel(ConnectionOptions(host="invalid-path.invalid", user="operator",
                                              ssh_executable=sys.executable), popen=fake_popen)
            with self.assertRaises(TunnelError):
                tunnel.start(timeout=.7)

    @patch("sovagrid_connect.askpass.helper_path", return_value="fixture-askpass")
    def test_initial_password_uses_fixed_ssh_command_and_private_pipe(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                gui_prompts=True, popen=fake_popen,
            )
            with self.assertRaisesRegex(TunnelError, "Connect to the panel"):
                tunnel.read_bootstrap_password()
            tunnel.start(timeout=3)
            try:
                secret = tunnel.read_bootstrap_password(timeout=3)
                self.assertEqual(secret, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG")
                argv, kwargs = calls[-1]
                self.assertEqual(argv[-2:], [
                    "sovagrid-target", "head -c 257 /etc/sovagrid/admin-password",
                ])
                self.assertEqual(kwargs["stdout"], subprocess.PIPE)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["bufsize"], 0)
                self.assertEqual(kwargs["env"]["SSH_ASKPASS_REQUIRE"], "force")
                self.assertNotIn(secret, str(argv))
                self.assertNotIn(secret, str(kwargs["env"]))
                self.assertNotIn(secret, Path(tunnel._directory.name, "ssh_config").read_text())
                self.assertNotIn(secret, Path(tunnel._directory.name, "ssh_log").read_text())
                with open(Path(tunnel._directory.name, "ssh_config"), "a", encoding="utf-8") as config:
                    config.write("# --credential-denied\n")
                with self.assertRaisesRegex(TunnelError, "cannot read"):
                    tunnel.read_bootstrap_password(timeout=3)
                with open(Path(tunnel._directory.name, "ssh_config"), "a", encoding="utf-8") as config:
                    config.write("# --credential-malformed\n")
                # Remove the permission marker to exercise format checking.
                config_path = Path(tunnel._directory.name, "ssh_config")
                config_path.write_text(config_path.read_text().replace("--credential-denied", ""))
                with self.assertRaisesRegex(TunnelError, "unexpected format"):
                    tunnel.read_bootstrap_password(timeout=3)
            finally:
                tunnel.close()
            self.assertIsNone(tunnel._bootstrap_process)

    @patch("sovagrid_connect.askpass.helper_path", return_value="fixture-askpass")
    def test_oversized_remote_output_is_bounded_and_rejected(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")

            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                gui_prompts=True, popen=fake_popen,
            )
            tunnel.start(timeout=3)
            try:
                with open(Path(tunnel._directory.name, "ssh_config"), "a", encoding="utf-8") as config:
                    config.write("# --credential-oversized\n")
                began = time.monotonic()
                with self.assertRaisesRegex(TunnelError, "too large"):
                    tunnel.read_bootstrap_password(timeout=3)
                self.assertLess(time.monotonic() - began, 4)
                self.assertIsNone(tunnel._bootstrap_process)
            finally:
                tunnel.close()

    @patch("sovagrid_connect.askpass.helper_path", return_value="fixture-askpass")
    def test_slow_remote_password_read_times_out_and_stops_ssh(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")

            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                gui_prompts=True, popen=fake_popen,
            )
            tunnel.start(timeout=3)
            try:
                with open(Path(tunnel._directory.name, "ssh_config"), "a", encoding="utf-8") as config:
                    config.write("# --credential-slow\n")
                with self.assertRaisesRegex(TunnelError, "Timed out"):
                    tunnel.read_bootstrap_password(timeout=0.2)
                self.assertIsNone(tunnel._bootstrap_process)
            finally:
                tunnel.close()

    @patch("sovagrid_connect.askpass.helper_path", return_value="fixture-askpass")
    def test_disconnect_terminates_inflight_password_read(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")

            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                gui_prompts=True, popen=fake_popen,
            )
            tunnel.start(timeout=3)
            with open(Path(tunnel._directory.name, "ssh_config"), "a", encoding="utf-8") as config:
                config.write("# --credential-slow\n")
            result = []
            worker = threading.Thread(target=lambda: result.append(self._read_initial_password_result(tunnel)))
            worker.start()
            deadline = time.monotonic() + 2
            while tunnel._bootstrap_process is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNotNone(tunnel._bootstrap_process)
            tunnel.close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, ["unavailable"])
            self.assertIsNone(tunnel._bootstrap_process)

    @staticmethod
    def _read_initial_password_result(tunnel: Tunnel) -> str:
        try:
            tunnel.read_bootstrap_password(timeout=12)
        except TunnelError:
            return "unavailable"
        return "unexpected secret"

    def test_early_ssh_exit_is_a_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            # The fake process exits if this marker is present in config. It is
            # injected only by overriding the config generator for this test.
            class FailingTunnel(Tunnel):
                def _write_config(self) -> str:
                    path = super()._write_config()
                    with open(path, "a", encoding="utf-8") as config:
                        config.write("# --fail\n")
                    return path

            tunnel = FailingTunnel(
                ConnectionOptions(host="example.org", user="operator", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(TunnelError, "SSH exited"):
                tunnel.start(timeout=2)
            self.assertIsNone(tunnel._directory)
            self.assertFalse(tunnel.alive)

    def test_occupied_port_cannot_be_accepted_as_ssh_tunnel(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            def forbidden_popen(*_args, **_kwargs):
                self.fail("SSH must not start when the local port is occupied")
            tunnel = Tunnel(
                ConnectionOptions(host="example.org", user="operator", local_port=port),
                popen=forbidden_popen,
            )
            with self.assertRaisesRegex(TunnelError, "already in use"):
                tunnel.start(timeout=1)
            self.assertIsNone(tunnel._directory)
            self.assertFalse(tunnel.alive)

    def test_http_response_without_openssh_forward_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            class UnverifiedTunnel(Tunnel):
                def _write_config(self) -> str:
                    path = super()._write_config()
                    with open(path, "a", encoding="utf-8") as config:
                        config.write("# --no-forward-marker\n")
                    return path
            tunnel = UnverifiedTunnel(
                ConnectionOptions(host="example.org", user="operator", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(TunnelError, "did not answer"):
                tunnel.start(timeout=0.6)
            self.assertIsNone(tunnel._directory)
            self.assertFalse(tunnel.alive)

    def test_unexpected_health_response_never_opens_panel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "ssh-fake.py")
            fake_ssh.write_text(FAKE_SSH, encoding="utf-8")

            def fake_popen(argv, **kwargs):
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            class WrongPanelTunnel(Tunnel):
                def _write_config(self) -> str:
                    path = super()._write_config()
                    with open(path, "a", encoding="utf-8") as config:
                        config.write("# --bad-health\n")
                    return path

            tunnel = WrongPanelTunnel(
                ConnectionOptions(host="example.org", user="operator", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(TunnelError, "did not answer"):
                tunnel.start(timeout=0.6)
            self.assertIsNone(tunnel._directory)
            self.assertFalse(tunnel.alive)

    @unittest.skipUnless(shutil.which("ssh"), "OpenSSH is not installed")
    def test_open_ssh_parses_strict_policy_for_both_hosts(self) -> None:
        options = ConnectionOptions(
            host="127.0.0.1", user="home", port=2223,
            jump_host="relay.example.net", jump_user="relay",
        ).validated()
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory, "ssh_config")
            config.write_text(_ssh_config(options))
            for alias in ("sovagrid-target", "sovagrid-jump"):
                result = subprocess.run(
                    ["ssh", "-G", "-F", str(config), alias],
                    check=True, capture_output=True, text=True, timeout=5,
                )
                self.assertIn("stricthostkeychecking true", result.stdout.lower())
            target = subprocess.run(
                ["ssh", "-G", "-F", str(config), "sovagrid-target"],
                check=True, capture_output=True, text=True, timeout=5,
            )
            self.assertIn("proxyjump sovagrid-jump", target.stdout.lower())


if __name__ == "__main__":
    unittest.main()
