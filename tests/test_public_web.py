# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Public HTTPS has a strict public-only wire and verifies source before exec."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from sovagrid_connect.agent_rpc import AgentRPC, RPCError
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.public_web import (HELPER, PublicWebError, PublicWebRPC,
    _PUBLIC_SCRIPT, config_for_address, public_panel_url, public_url)

CONFIG = {"mode": "dns", "address": "panel.sovagrid.org", "acme_environment": "production",
          "panel_path": "/sovagrid/monitoring/", "root_behavior": "panel"}
STATE = "a" * 64
SOURCE = "b" * 64


def reply(action):
    if action == "status":
        return {"protocol": 1, "ok": True, "enabled": True, "config": CONFIG, "expected_state_sha256": STATE}
    if action == "disable":
        return {"protocol": 1, "ok": True, "enabled": False, "changed": True, "expected_state_sha256": None}
    value = {"protocol": 1, "ok": True, "config": CONFIG, "expected_state_sha256": STATE,
             "source_manifest_sha256": SOURCE, "changed": True, "url": public_url(CONFIG),
             "certificate_verified": action == "apply"}
    if action == "apply":
        value["enabled"] = True
    return value


CHILD = r'''
import json,pathlib,sys,time
settings=json.loads(pathlib.Path(sys.argv[1]).read_text())
if sys.argv[2]=='preflight':
    uid=0 if sys.argv[3]=='sudo' else settings.get('uid',0)
    value={'protocol':1,'ok':True,'euid':uid,'ubuntu_version':'24.04','python_version':'3.12','systemd_version':'255'}
else:
    request=json.load(sys.stdin)
    pathlib.Path(sys.argv[1]).with_suffix('.received').write_text(json.dumps(request))
    if settings.get('sleep'): time.sleep(60)
    if 'raw' in settings:
        sys.stdout.write(settings['raw']);sys.exit(settings.get('exit',0))
    value=settings['reply']
sys.stdout.write(json.dumps(value));sys.stdout.flush()
sys.exit(settings.get('exit',0))
'''


class PublicWebWireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.child = self.base / "child.py"
        self.child.write_text(CHILD)
        self.settings_path = self.base / "settings.json"
        self.settings = {"reply": reply("status")}
        self.calls, self.children = [], []
        self.started = threading.Event()
        prompt = mock.patch("sovagrid_connect.installer.helper_path", return_value=str(self.base / "unused-prompt"))
        prompt.start()
        self.addCleanup(prompt.stop)
        self.transport = AgentRPC(ConnectionOptions("fixture.invalid", user="fixture"), role="hub", popen=self.spawn)
        self.rpc = PublicWebRPC(self.transport.options, transport=self.transport)

    def tearDown(self):
        for child in self.children:
            if child.poll() is None:
                AgentRPC._kill(child)
                child.wait(timeout=3)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            job = getattr(child, "_sovagrid_rpc_job", None)
            if job:
                job.close()

    def spawn(self, argv, **kwargs):
        self.calls.append(argv)
        command = argv[-1]
        kind = "public" if "SOVAGRID_PUBLIC_WEB_RPC_V1" in command else "preflight"
        child = subprocess.Popen([sys.executable, str(self.child), str(self.settings_path), kind,
            "sudo" if command.startswith("sudo -n -- ") else "direct"], **kwargs)
        self.children.append(child)
        if kind == "public":
            self.started.set()
        return child

    def configure(self, **changes):
        self.settings.update(changes)
        self.settings_path.write_text(json.dumps(self.settings))

    def invoke(self, action):
        if action == "status":
            return self.rpc.status()
        if action == "preview":
            return self.rpc.preview(CONFIG)
        if action == "apply":
            return self.rpc.apply(CONFIG, expected_state_sha256=STATE, source_manifest_sha256=SOURCE)
        return self.rpc.disable(expected_state_sha256=STATE)

    def test_fixed_source_script_and_public_json_channel_preserve_sudo_preflight_and_action_gates(self):
        self.configure(uid=1000)
        self.rpc.status()
        self.assertFalse(self.calls[0][-1].startswith("sudo"))
        self.assertTrue(self.calls[1][-1].startswith("sudo -n -- /usr/bin/python3 -I -c "))
        for action in ("preview", "apply", "disable"):
            self.configure(reply=reply(action))
            result = self.invoke(action)
            self.assertEqual(result, reply(action))
            received = json.loads(self.settings_path.with_suffix(".received").read_text())
            self.assertEqual(set(received), {"action", "payload"})
            self.assertEqual(received["action"], action)
            if action != "disable":
                self.assertEqual(received["payload"]["config"], CONFIG)
            self.assertNotIn(CONFIG["address"], self.calls[-1][-1])
            self.assertNotIn(STATE, self.calls[-1][-1])
        count = len(self.calls)
        with self.assertRaises(RPCError):
            self.transport.call("preview", {})
        self.assertEqual(len(self.calls), count)
        self.assertTrue(all(child.poll() is not None and child.stdin.closed and child.stdout.closed for child in self.children))

    def test_bad_config_and_cas_never_reach_ssh_and_user_field_normalizes_only_safe_addresses(self):
        self.assertEqual(config_for_address(" PANEL.SOVAGRID.ORG "), {**CONFIG, "root_behavior": "untouched"})
        self.assertEqual(config_for_address("2606:4700:0000:0000:0000:0000:0000:1111")["address"], "2606:4700::1111")
        self.assertEqual(public_url(config_for_address("2606:4700::1111")), "https://[2606:4700::1111]")
        self.assertEqual(public_panel_url(CONFIG), "https://panel.sovagrid.org/sovagrid/monitoring/")
        self.assertEqual(config_for_address("panel.sovagrid.org", panel_path="/ops/", root_behavior="redirect")
                         ["root_behavior"], "redirect")
        for address in ("127.0.0.1", "0.0.0.0", "10.0.0.1", "::ffff:8.8.8.8", "ff00::1", "fe80::1%eth0",
                        "https://panel.sovagrid.org", "user@panel.sovagrid.org", "panel.sovagrid.org:443",
                        "panel.sovagrid.org/path", "-panel.sovagrid.org", "panel.local", "panel.invalid", "x.123",
                        "panel.sovagrid.org;id", "ключ.рф"):
            with self.subTest(address=address), self.assertRaises(PublicWebError):
                self.rpc.preview({**CONFIG, "address": address})
        for config in ({**CONFIG, "acme_environment": "staging"}, {**CONFIG, "password": "never-serialized"},
                       {**CONFIG, "mode": []}, {**CONFIG, "address": "PANEL.SOVAGRID.ORG"},
                       {**CONFIG, "panel_path": "/"}, {**CONFIG, "panel_path": "/ops//panel/"},
                       {**CONFIG, "panel_path": "/ops/{path}/"}, {**CONFIG, "panel_path": "/api/v1/"},
                       {**CONFIG, "panel_path": "/healthz/"}, {**CONFIG, "root_behavior": "elsewhere"}):
            with self.assertRaises(PublicWebError):
                self.rpc.preview(config)
            with self.assertRaises(PublicWebError):
                self.rpc.apply(config, expected_state_sha256=STATE, source_manifest_sha256=SOURCE)
        for state, source in (("not-hash", SOURCE), (STATE, None), (True, SOURCE)):
            with self.assertRaises(PublicWebError):
                self.rpc.apply(CONFIG, expected_state_sha256=state, source_manifest_sha256=source)
        for action, payload in (("compose-overlay", {}), ("status", {"password": "never-serialized"}),
                                ("apply", {"config": CONFIG}), ([], {})):
            with self.assertRaises(PublicWebError):
                self.rpc._call(action, payload)
        self.assertEqual(self.calls, [])

    def test_strict_success_and_errors_never_trust_remote_message_or_unverified_certificate(self):
        self.transport._prefix = ""
        cases = [
            ("status", {**reply("status"), "token": "remote-canary"}),
            ("status", {**reply("status"), "protocol": True}),
            ("status", {**reply("status"), "config": {**CONFIG, "acme_environment": "unknown"}}),
            ("status", {**reply("status"), "enabled": False}),
            ("status", {**reply("status"), "expected_state_sha256": None}),
            ("preview", {**reply("preview"), "certificate_verified": True}),
            ("preview", {**reply("preview"), "url": "https://other.sovagrid.org"}),
            ("apply", {**reply("apply"), "certificate_verified": False}),
            ("apply", {**reply("apply"), "source_manifest_sha256": "c" * 64}),
            ("apply", {**reply("apply"), "enabled": 1}),
            ("disable", {**reply("disable"), "enabled": True}),
        ]
        for action, value in cases:
            self.configure(reply=value)
            with self.subTest(action=action, value=value), self.assertRaises(PublicWebError) as caught:
                self.invoke(action)
            self.assertEqual(caught.exception.code, "INVALID_REPLY")
        for raw in ('{"protocol":1,"protocol":1,"ok":true}', "[" * 1500 + "]" * 1500, "x" * 4097):
            self.configure(raw=raw)
            with self.assertRaises(PublicWebError):
                self.rpc.status()
        self.settings.pop("raw")
        self.configure(reply=reply("status"), exit=1)
        with self.assertRaises(PublicWebError):
            self.rpc.status()
        self.configure(reply={"protocol": 1, "ok": False, "error": {"code": "SOURCE_UNTRUSTED", "message": "remote-canary"}})
        with self.assertRaises(PublicWebError) as caught:
            self.rpc.status()
        self.assertEqual(caught.exception.code, "SOURCE_UNTRUSTED")
        self.assertNotIn("remote-canary", str(caught.exception))

    def test_saved_staging_status_can_be_read_and_disabled_without_allowing_staging_mutations(self):
        staged = {**CONFIG, "acme_environment": "staging"}
        self.configure(reply={**reply("status"), "config": staged})
        status = self.rpc.status()
        self.assertEqual(status["config"], staged)
        self.assertEqual(public_url(status["config"]), "https://panel.sovagrid.org")
        count = len(self.calls)
        for action in ("preview", "apply"):
            with self.assertRaises(PublicWebError):
                if action == "preview":
                    self.rpc.preview(staged)
                else:
                    self.rpc.apply(staged, expected_state_sha256=STATE, source_manifest_sha256=SOURCE)
        self.assertEqual(len(self.calls), count)
        self.configure(reply=reply("disable"))
        self.assertFalse(self.rpc.disable(expected_state_sha256=status["expected_state_sha256"])["enabled"])
        self.configure(reply=reply("preview"))
        production = config_for_address(status["config"]["address"], root_behavior="panel")
        self.assertEqual(self.rpc.preview(production)["config"]["acme_environment"], "production")

    def test_legacy_saved_config_defaults_preserve_root_and_allow_new_path(self):
        legacy = {key: CONFIG[key] for key in ("mode", "address", "acme_environment")}
        self.configure(reply={**reply("status"), "config": legacy})
        status = self.rpc.status()
        self.assertEqual(status["config"], legacy)
        self.assertEqual(public_panel_url(status["config"]),
                         "https://panel.sovagrid.org/sovagrid/monitoring/")

    def test_cancel_is_sticky_reaps_actual_process_and_concurrent_call_cannot_clobber_it(self):
        self.transport._prefix = ""
        self.configure(sleep=True)
        errors = []
        def run():
            try:
                self.rpc.status()
            except PublicWebError as error:
                errors.append(error.code)
        worker = threading.Thread(target=run)
        worker.start()
        self.assertTrue(self.started.wait(2))
        with self.assertRaises(PublicWebError) as caught:
            self.rpc.status()
        self.assertEqual(caught.exception.code, "BUSY")
        start = time.monotonic()
        self.rpc.cancel()
        self.assertLess(time.monotonic() - start, .1)
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ["CANCELLED"])
        self.assertTrue(all(child.poll() is not None and child.stdin.closed and child.stdout.closed for child in self.children))
        count = len(self.calls)
        with self.assertRaises(PublicWebError) as caught:
            self.rpc.status()
        self.assertEqual(caught.exception.code, "CANCELLED")
        self.assertEqual(len(self.calls), count)

    def test_deadlines_bound_preflight_and_late_cancel_cannot_report_success(self):
        self.transport._prefix = ""
        for action, budget in (("status", 90), ("preview", 90), ("apply", 600), ("disable", 300)):
            with mock.patch.object(self.transport, "_exchange", return_value=(json.dumps(reply(action)).encode(), 0)) as exchange:
                self.invoke(action)
            self.assertGreater(exchange.call_args.args[2], budget - 1)
            self.assertLessEqual(exchange.call_args.args[2], budget)
        # At this representable clock value, adding then subtracting 90 yields
        # 90.00000000000006. The transmitted deadline must still obey its cap.
        with mock.patch("sovagrid_connect.public_web.time.monotonic", return_value=500.2), \
             mock.patch.object(self.transport, "_exchange", return_value=(json.dumps(reply("status")).encode(), 0)) as exchange:
            self.rpc.status()
        self.assertEqual(exchange.call_args.args[2], 90)
        with mock.patch.object(self.transport, "_exchange", side_effect=lambda *_args: (
                self.rpc.cancel() or json.dumps(reply("status")).encode(), 0)):
            with self.assertRaises(PublicWebError) as caught:
                self.rpc.status()
        self.assertEqual(caught.exception.code, "CANCELLED")


@unittest.skipUnless(os.name == "posix", "Remote bootstrap requires Ubuntu filesystem semantics")
class PublicWebPreexecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir(mode=0o755)
        self.canary = self.base / "compiled"
        code = ("import json,sys\nfrom pathlib import Path\n"
                f"Path({str(self.canary)!r}).write_text('verified')\n"
                "def main():\n"
                "    assert sys.argv == [__file__, 'status']\n"
                "    assert json.load(sys.stdin) == {}\n"
                "    print(json.dumps({'protocol':1,'ok':True,'enabled':False,'config':None,'expected_state_sha256':None}))\n"
                "    return 0\n").encode()
        self.files = {HELPER: code,
            "sovagrid-blueprint/deploy/remote_agent.py": b"# SOVAGRID_REMOTE_AGENT_HELPER_V1\n"}
        for component in ("sovagrid-agent", "sovagrid-hub", "sovagrid-web", "sovagrid-vpn"):
            self.files[component + "/README.md"] = b"fixture\n"
        for name, data in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            path.write_bytes(data)
            path.chmod(0o644)
        self.write_manifest()
        self.lstat, self.fstat = os.lstat, os.fstat

    def write_manifest(self):
        components = {name.split("/")[0] for name in self.files}
        value = {"format": 1, "components": {component: {"commit": "a" * 40,
            "file_count": sum(name.startswith(component + "/") for name in self.files)} for component in components},
            "sha256": {name: hashlib.sha256(data).hexdigest() for name, data in self.files.items()}}
        (self.source / "sovagrid-bundle.json").write_text(json.dumps(value))

    @staticmethod
    def root_stat(call, *args, **kwargs):
        value = list(call(*args, **kwargs))
        value[4] = 0
        return os.stat_result(value)

    def execute(self, action="status", payload=None):
        script = _PUBLIC_SCRIPT.replace("source_root='/opt/sovagrid-src'", "source_root=" + repr(str(self.source)))
        request = {"action": action, "payload": payload or {}}
        incoming = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
        stream = io.BytesIO()
        outgoing = io.TextIOWrapper(stream, write_through=True)
        with mock.patch.object(sys, "stdin", incoming), mock.patch.object(sys, "stdout", outgoing), \
             mock.patch.object(sys, "argv", []), mock.patch.object(os, "geteuid", return_value=0), \
             mock.patch.object(os, "lstat", side_effect=lambda *a, **kw: self.root_stat(self.lstat, *a, **kw)), \
             mock.patch.object(os, "fstat", side_effect=lambda *a, **kw: self.root_stat(self.fstat, *a, **kw)):
            try:
                exec(compile(script, "trusted-public-wrapper", "exec"), {"__name__": "__main__"})
            except SystemExit:
                pass
        return json.loads(stream.getvalue())

    def test_verified_helper_executes_with_fixed_argv_but_changed_bytes_do_not_compile(self):
        self.assertTrue(self.execute()["ok"])
        self.assertTrue(self.canary.exists())
        self.canary.unlink()
        path = self.source / HELPER
        path.write_bytes(path.read_bytes() + b"\n# changed\n")
        self.assertEqual(self.execute()["error"]["code"], "SOURCE_CHANGED")
        self.assertFalse(self.canary.exists())

    def test_insecure_mode_symlink_and_hardlink_are_rejected_before_execution(self):
        path = self.source / HELPER
        path.chmod(0o666)
        self.assertFalse(self.execute()["ok"])
        self.assertFalse(self.canary.exists())
        path.chmod(0o644)
        saved = self.base / "saved-helper"
        path.rename(saved)
        path.symlink_to(saved)
        self.assertFalse(self.execute()["ok"])
        path.unlink()
        os.link(saved, path)
        self.assertFalse(self.execute()["ok"])
        self.assertFalse(self.canary.exists())

    def test_stale_source_cas_and_unrelated_component_change_block_before_compile(self):
        self.assertEqual(self.execute("apply", {"config": CONFIG, "expected_state_sha256": None,
            "source_manifest_sha256": "0" * 64})["error"]["code"], "STALE_PREVIEW")
        self.assertFalse(self.canary.exists())
        path = self.source / "sovagrid-web/README.md"
        path.write_text("changed outside public helper")
        self.assertEqual(self.execute()["error"]["code"], "SOURCE_CHANGED")
        self.assertFalse(self.canary.exists())


if __name__ == "__main__":
    unittest.main()
