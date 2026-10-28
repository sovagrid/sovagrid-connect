# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Local filesystem fixtures for the SSH-delivered update transaction."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
from contextlib import closing, nullcontext, redirect_stdout
from unittest.mock import patch

from sovagrid_connect.remote_update import REMOTE_SCRIPT
from test_installer import make_bundle


def updater() -> dict:
    namespace = {"__name__": "fixture"}
    exec(compile(REMOTE_SCRIPT, "remote_update", "exec"), namespace)
    return namespace


@unittest.skipIf(os.name == "nt", "remote transaction fixtures require Ubuntu/POSIX filesystem semantics")
class RemoteUpdateTests(unittest.TestCase):
    def test_socket_activated_services_need_listening_sockets_not_idle_workers(self) -> None:
        code = updater()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "etc/sovagrid"
            config.mkdir(parents=True)
            (config / "agent.json").write_text(json.dumps({"allow_interactive_terminal": True}))
            (config / ".vpn-control-managed-by-run-sh").write_text("managed")
            (config / ".terminal-unit-managed-by-run-sh").write_text("managed")
            code["ROOT"] = root
            code["managed_routing_enabled"] = lambda: False
            code["backup_broker_enabled"] = lambda: False
            flags, expected = code["managed_flags"]()
        self.assertEqual(flags, ["--with-wireguard", "--with-terminal"])
        self.assertIn("sovagrid-vpn-control.socket", expected)
        self.assertIn("sovagrid-terminal-control.socket", expected)
        self.assertNotIn("sovagrid-vpn-control.service", expected)
        self.assertNotIn("sovagrid-terminal-control.service", expected)

    def test_auto_update_units_are_rollback_safe_without_service_recursion(self) -> None:
        code = updater()
        self.assertIn('/etc/systemd/system/sovagrid-auto-update.service', code['SNAPSHOT'])
        self.assertIn('/etc/systemd/system/sovagrid-auto-update.timer', code['SNAPSHOT'])
        self.assertIn('sovagrid-auto-update.timer', code['UNITS'])
        self.assertNotIn('sovagrid-auto-update.service', code['UNITS'])
        self.assertIn('/var/lib/sovagrid-containers', code['SNAPSHOT'])
        self.assertIn('/etc/systemd/system/sovagrid-container-inventory.timer', code['SNAPSHOT'])
        self.assertIn('sovagrid-container-inventory.timer', code['UNITS'])

    def test_snapshot_layouts_preserve_connect_legacy_and_match_blueprint_versions(self) -> None:
        code = updater()
        self.assertEqual(code['LEGACY_SNAPSHOT'][5:7],
                         ('/var/lib/sovagrid-containers', '/var/lib/sovagrid/hub'))
        self.assertEqual(code['RELEASE_FEED_SNAPSHOT'][5:9],
                         ('/var/lib/sovagrid/hub', '/var/lib/sovagrid/caddy',
                          '/var/lib/sovagrid/vpn', '/var/lib/sovagrid-containers'))
        self.assertEqual(code['RELEASE_FEED_SNAPSHOT'][-4:], (
            '/var/lib/sovagrid/.release-feed-units-managed-by-run-sh',
            '/var/lib/sovagrid/release-feed-state.json',
            '/etc/systemd/system/sovagrid-release-feed.service',
            '/etc/systemd/system/sovagrid-release-feed.timer'))
        self.assertEqual(code['SERVICE_SNAPSHOT'][-3:], (
            '/etc/sovagrid-service',
            '/etc/systemd/system/sovagrid-service-control.socket',
            '/etc/systemd/system/sovagrid-service-control.service'))
        self.assertEqual(code['ROUTING_SNAPSHOT'][-3:], (
            '/etc/sovagrid-vpn-routing/policy.json',
            '/etc/sysctl.d/70-sovagrid-vpn-routing.conf',
            '/etc/systemd/system/sovagrid-vpn-routing.service'))
        self.assertEqual(code['ROUTING_SNAPSHOT'][:len(code['SERVICE_SNAPSHOT'])], code['SERVICE_SNAPSHOT'])
        self.assertEqual(code['HUB_BACKUP_SNAPSHOT'][-4:], (
            '/var/lib/sovagrid/.hub-backup-broker-managed-by-run-sh',
            '/var/lib/sovagrid/backups/.broker-requests',
            '/etc/systemd/system/sovagrid-hub-backup-control.socket',
            '/etc/systemd/system/sovagrid-hub-backup-control.service'))
        self.assertEqual(code['SNAPSHOT'][:-1], code['HUB_BACKUP_SNAPSHOT'])
        self.assertEqual(code['SNAPSHOT'][-1], code['SSH_GATEWAY_MARKER'])
        self.assertEqual(code['HUB_BACKUP_SNAPSHOT'][:len(code['ROUTING_SNAPSHOT'])],
                         code['ROUTING_SNAPSHOT'])
        self.assertEqual(code['ROUTING_ALL_UNITS'][-1], 'sovagrid-vpn-routing.service')
        self.assertEqual(code['UNITS'][-2:], code['BACKUP_BROKER_UNITS'])
        self.assertNotIn('sovagrid-service-control.service', code['LEGACY_UNITS'])
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'snapshot/6').mkdir(parents=True)
            (folder / 'snapshot/6/hub.sqlite').write_text('old')
            self.assertIs(code['rollback_layout'](folder, {'phase': 'running'})[0],
                          code['LEGACY_SNAPSHOT'])
            (folder / 'snapshot/5').mkdir()
            (folder / 'snapshot/5/hub.sqlite').write_text('old')
            with self.assertRaises(code['UpdateFailure']):
                code['rollback_layout'](folder, {'phase': 'running'})
            (folder / 'snapshot/6/hub.sqlite').unlink()
            self.assertIs(code['rollback_layout'](folder, {'phase': 'running'})[0],
                          code['BLUEPRINT_LEGACY_SNAPSHOT'])
            self.assertIs(code['rollback_layout'](folder, {
                'phase': 'running', 'snapshot_layout': 'release_feed_v1'})[0],
                code['RELEASE_FEED_SNAPSHOT'])
            self.assertIs(code['rollback_layout'](folder, {
                'phase': 'running', 'snapshot_layout': 'service_control_v1'})[0],
                code['SERVICE_SNAPSHOT'])
            self.assertIs(code['rollback_layout'](folder, {
                'phase': 'running', 'snapshot_layout': 'routing_v1'})[0],
                code['ROUTING_SNAPSHOT'])
            self.assertIs(code['rollback_layout'](folder, {
                'phase': 'running', 'snapshot_layout': 'hub_backup_broker_v1'})[0],
                code['HUB_BACKUP_SNAPSHOT'])
            self.assertIs(code['rollback_layout'](folder, {
                'phase': 'running', 'snapshot_layout': 'ssh_gateway_v1'})[0],
                code['SNAPSHOT'])
            with self.assertRaises(code['UpdateFailure']):
                code['rollback_layout'](folder, {'phase': 'running', 'snapshot_layout': 'future'})

    def test_backup_broker_marker_requires_owned_units_and_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code['ROOT'], code['PUBLIC_OWNER'] = root, os.getuid()
            code['BROKER_OWNER_GID'] = os.getgid()
            marker = root / code['BACKUP_BROKER_MARKER'].lstrip('/')
            marker.parent.mkdir(parents=True)
            marker.write_bytes(b'SOVAGRID_HUB_BACKUP_BROKER_V1\n')
            marker.chmod(0o600)
            for name in code['BACKUP_BROKER_UNITS']:
                target = root / 'etc/systemd/system' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('unit\n')
                target.chmod(0o644)
            ledger = root / code['BACKUP_BROKER_LEDGER'].lstrip('/')
            ledger.mkdir(parents=True)
            ledger.parent.chmod(0o700)
            ledger.chmod(0o700)
            self.assertTrue(code['backup_broker_enabled']())
            marker.chmod(0o644)
            with self.assertRaises(code['UpdateFailure']):
                code['backup_broker_enabled']()
            marker.chmod(0o600)
            ledger.rename(ledger.parent / 'saved-ledger')
            marker.unlink()
            with self.assertRaises(code['UpdateFailure']):
                code['backup_broker_enabled']()

    def test_failed_update_restores_backup_broker_ledger_and_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            marker_name = code['BACKUP_BROKER_MARKER']
            ledger_name = code['BACKUP_BROKER_LEDGER']
            units = code['BACKUP_BROKER_UNITS']
            code['SNAPSHOT'] += (marker_name, ledger_name) + tuple(
                '/etc/systemd/system/' + name for name in units)
            code['UNITS'] += units
            marker = root / marker_name.lstrip('/')
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.write_text('old marker\n')
            ledger = root / ledger_name.lstrip('/')
            ledger.mkdir(parents=True)
            (ledger / 'request.json').write_text('old reservation\n')
            first_unit = root / 'etc/systemd/system' / units[0]
            second_unit = root / 'etc/systemd/system' / units[1]
            first_unit.write_text('old socket\n')
            second_unit.write_text('old service\n')
            code['backup_broker_enabled'] = lambda: marker.is_file()
            code['backup_broker_socket_ready'] = lambda: None
            original = code['command']
            def command(args, **kwargs):
                if args[0] == 'bash':
                    marker.unlink()
                    (ledger / 'request.json').write_text('new reservation\n')
                    first_unit.write_text('new socket\n')
                    second_unit.unlink()
                return original(args, **kwargs)
            code['command'] = command
            with self.assertRaises(code['UpdateFailure']):
                code['apply']('a' * 64, 'b' * 64)
            self.assertEqual(marker.read_text(), 'old marker\n')
            self.assertEqual((ledger / 'request.json').read_text(), 'old reservation\n')
            self.assertEqual(first_unit.read_text(), 'old socket\n')
            self.assertEqual(second_unit.read_text(), 'old service\n')
            self.assertIn(['systemctl', 'start', units[0]], calls)
            start = calls.index(['systemctl', 'start', units[0]])
            compose_up = next(i for i, args in enumerate(calls)
                              if args[:2] == ['docker', 'compose'] and 'up' in args)
            self.assertLess(start, compose_up)

    def test_automatic_idle_requires_no_live_sessions_jobs_or_confirmations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "var/lib/sovagrid/hub/hub.sqlite"
            database.parent.mkdir(parents=True)
            with closing(sqlite3.connect(database)) as db:
                db.executescript("""
                    CREATE TABLE sessions (token_hash TEXT, expires_at INTEGER);
                    CREATE TABLE jobs (id TEXT, state TEXT);
                    CREATE TABLE pending_commands (code_hash TEXT, expires_at INTEGER);
                """)
                db.commit()
            code = updater()
            code["ROOT"] = root
            code["automatic_idle"]()
            now = int(time.time())
            with closing(sqlite3.connect(database)) as db:
                db.execute("INSERT INTO sessions VALUES ('x', ?)", (now + 60,))
                db.commit()
            with self.assertRaises(code["UpdateFailure"]):
                code["automatic_idle"]()
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE sessions SET expires_at=?", (now - 301,))
                db.execute("INSERT INTO jobs VALUES ('a', 'delivered')")
                db.commit()
            with self.assertRaises(code["UpdateFailure"]):
                code["automatic_idle"]()
            with closing(sqlite3.connect(database)) as db:
                db.execute("UPDATE jobs SET state='succeeded'")
                db.execute("INSERT INTO pending_commands VALUES ('p', ?)", (now + 60,))
                db.commit()
            with self.assertRaises(code["UpdateFailure"]):
                code["automatic_idle"]()
            with closing(sqlite3.connect(database)) as db:
                db.execute("DELETE FROM pending_commands")
                db.execute("DROP TABLE sessions")
                db.commit()
            with self.assertRaises(code["UpdateFailure"]):
                code["automatic_idle"]()  # Unknown/old schema fails closed.

    def test_automatic_busy_gate_refuses_before_service_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=False)
            seen = []
            def idle():
                seen.append(True)
                if len(seen) == 3:
                    raise code["UpdateFailure"]("busy")
            code["automatic_idle"] = idle
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64, automatic=True)
            self.assertEqual(len(seen), 3)
            self.assertFalse(any(args[:3] == ["docker", "compose", "stop"] for args in calls))
            self.assertEqual((root / "opt/sovagrid-src/version").read_text(), "old")
            self.assertEqual((root / "var/lib/sovagrid/hub/hub.sqlite").read_text(), "old data")

    def test_install_log_requires_root_owned_private_regular_file(self) -> None:
        code = updater()
        proper = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        code["validate_private_install_log"](proper)
        for changes in ({"st_uid": 1000}, {"st_mode": stat.S_IFLNK | 0o600},
                        {"st_mode": stat.S_IFREG | 0o644}, {"st_nlink": 2}):
            invalid = types.SimpleNamespace(**{**vars(proper), **changes})
            with self.subTest(changes=changes), self.assertRaises(code["UpdateFailure"]):
                code["validate_private_install_log"](invalid)

    def test_saved_log_sets_root_group_and_private_mode(self) -> None:
        code = updater()
        with patch.object(os, "fchown") as chown, patch.object(os, "fchmod") as chmod:
            code["secure_log_fd"](123)
        chown.assert_called_once_with(123, 0, 0)
        chmod.assert_called_once_with(123, 0o600)

    def test_saved_log_directory_requires_root_owned_private_directory(self) -> None:
        code = updater()
        proper = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        code["validate_private_log_dir"](proper)
        for changes in ({"st_uid": 1000}, {"st_mode": stat.S_IFLNK | 0o700},
                        {"st_mode": stat.S_IFDIR | 0o755}):
            invalid = types.SimpleNamespace(**{**vars(proper), **changes})
            with self.subTest(changes=changes), self.assertRaises(code["UpdateFailure"]):
                code["validate_private_log_dir"](invalid)

    def test_install_command_keeps_stderr_in_private_log(self) -> None:
        code = updater()
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "install.log"
            with log.open("wb") as output:
                code["command"]([sys.executable, "-c",
                                 "import sys; print('stdout'); print('stderr', file=sys.stderr)"],
                                stdout=output)
            self.assertEqual(set(log.read_text().splitlines()), {"stdout", "stderr"})

    def test_health_accepts_running_web_without_docker_healthcheck(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "var/lib/sovagrid/vpn/status.json"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_text("{}")
            code = updater()
            code["ROOT"] = root
            code["command"] = lambda *_args, **_kwargs: 0
            code["source_manifest"] = lambda *_args, **_kwargs: ("b" * 64, {})
            inspected = []
            def docker(args, **_kwargs):
                inspected.append(args)
                if args[:2] == ["docker", "ps"]:
                    if "label=com.docker.compose.service=hub" in args:
                        value = "hub-id\n"
                    elif "label=com.docker.compose.service=web" in args:
                        value = "web-id\n"
                    else:
                        value = ""
                elif '{{.Image}}' in args or '{{.Id}}' in args:
                    value = "sha256:expected\n"
                elif '{{.State.Status}}' in args:
                    value = "running\n"
                elif '{{.State.Health.Status}}' in args:
                    if "web-id" in args:
                        self.fail("Web must not require a Docker healthcheck")
                    value = "healthy\n"
                else:
                    self.fail(f"Unexpected Docker command: {args}")
                return types.SimpleNamespace(stdout=value)
            code["subprocess"] = types.SimpleNamespace(run=docker)
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *_args): return None
            code["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(
                urlopen=lambda *_args, **_kwargs: Response()))
            code["ssl"] = types.SimpleNamespace(create_default_context=lambda **_kwargs: None)
            code["health"](root / "opt/sovagrid-src", ["sovagrid-agent.service"])
            self.assertEqual(sum('{{.State.Health.Status}}' in args for args in inspected), 1)

    def test_managed_gateway_requires_healthy_container(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshot = root / "var/lib/sovagrid/vpn/status.json"
            snapshot.parent.mkdir(parents=True)
            snapshot.write_text("{}")
            code = updater()
            code["ROOT"] = root
            code["ssh_gateway_managed"] = lambda: True
            code["command"] = lambda *_args, **_kwargs: 0
            code["source_manifest"] = lambda *_args, **_kwargs: ("b" * 64, {})
            code["browser_ssh_route_health"] = lambda: None
            inspected = []
            gateway_health = ["unhealthy"]
            def docker(args, **_kwargs):
                inspected.append(args)
                if args[:2] == ["docker", "ps"]:
                    service = next(item.rsplit("=", 1)[-1] for item in args
                                   if item.startswith("label=com.docker.compose.service="))
                    value = service + "-id\n"
                elif '{{.Image}}' in args or '{{.Id}}' in args:
                    value = "sha256:expected\n"
                elif '{{.State.Status}}' in args:
                    value = "running\n"
                elif '{{.State.Health.Status}}' in args:
                    value = gateway_health[0] + "\n" if "ssh-gateway-id" in args else "healthy\n"
                else:
                    self.fail(f"Unexpected Docker command: {args}")
                return types.SimpleNamespace(stdout=value)
            code["subprocess"] = types.SimpleNamespace(run=docker)
            class Response:
                status = 200
                def __enter__(self): return self
                def __exit__(self, *_args): return None
            code["urllib"] = types.SimpleNamespace(request=types.SimpleNamespace(
                urlopen=lambda *_args, **_kwargs: Response()))
            code["ssl"] = types.SimpleNamespace(create_default_context=lambda **_kwargs: None)
            with self.assertRaisesRegex(code["UpdateFailure"], "ssh-gateway"):
                code["health"](root / "opt/sovagrid-src", [])
            gateway_health[0] = "healthy"
            code["health"](root / "opt/sovagrid-src", [])
            self.assertEqual(sum('{{.State.Health.Status}}' in args for args in inspected), 4)

    def test_gateway_created_during_update_is_removed_only_with_exact_compose_labels(self) -> None:
        code = updater()
        identity = "a" * 64
        labels = ["sovagrid:ssh-gateway"]
        listed = [identity]
        removed = []
        def docker(args, **_kwargs):
            if args[:2] == ["docker", "ps"]:
                self.assertIn("--no-trunc", args)
                return types.SimpleNamespace(stdout="\n".join(listed) + "\n")
            if args[:2] == ["docker", "inspect"]:
                self.assertEqual(args[-1], identity)
                return types.SimpleNamespace(stdout=labels[0] + "\n")
            self.fail(f"Unexpected Docker command: {args}")
        code["subprocess"] = types.SimpleNamespace(run=docker)
        code["command"] = lambda args, **_kwargs: removed.append(args)
        code["remove_new_gateway_on_rollback"]()
        self.assertEqual(removed, [["docker", "rm", "-f", identity]])
        removed.clear()
        code["remove_new_gateway_on_rollback"]([identity])
        self.assertFalse(removed)
        labels[0] = "other:ssh-gateway"
        with self.assertRaisesRegex(code["UpdateFailure"], "labels"):
            code["remove_new_gateway_on_rollback"]()
        self.assertFalse(removed)
        listed[0] = identity[:12]
        with self.assertRaisesRegex(code["UpdateFailure"], "ambiguous"):
            code["remove_new_gateway_on_rollback"]()
        self.assertFalse(removed)

    def test_unmarked_stopped_gateway_blocks_update_before_snapshot(self) -> None:
        code = updater()
        code['ssh_gateway_managed'] = lambda: False
        identity = 'a' * 64
        listed = [identity]
        def docker(args, **_kwargs):
            if args[:2] == ['docker', 'ps']:
                self.assertIn('-a', args)
                return types.SimpleNamespace(stdout='\n'.join(listed), returncode=0)
            if args[:3] == ['docker', 'image', 'inspect']:
                return types.SimpleNamespace(stdout='', returncode=1)
            self.fail(f'Unexpected Docker command: {args}')
        code['subprocess'] = types.SimpleNamespace(run=docker)
        with self.assertRaises(code['UpdateFailure']):
            code['gateway_prior_state']()
        listed.clear()
        self.assertEqual(code['gateway_prior_state'](), {'container_ids': [], 'image': None})

    def test_browser_ssh_route_health_requires_real_host_key_reply(self) -> None:
        code = updater()
        class Response:
            status = 200
            def __init__(self, body): self.body = body
            def read(self, _limit): return self.body
            def __enter__(self): return self
            def __exit__(self, *_args): return None
        reply = [b'{"protocol":1,"port":22,"key_type":"ssh-ed25519","fingerprint":"SHA256:' +
                 b'A' * 43 + b'"}']
        requests = []
        def urlopen(request, **_kwargs):
            requests.append(request)
            return Response(reply[0])
        code['urllib'] = types.SimpleNamespace(request=types.SimpleNamespace(
            Request=lambda *args, **kwargs: types.SimpleNamespace(args=args, kwargs=kwargs),
            urlopen=urlopen))
        code['browser_ssh_route_health']()
        self.assertEqual(requests[0].kwargs['method'], 'POST')
        self.assertEqual(requests[0].kwargs['headers']['Origin'], 'http://127.0.0.1:8766')
        reply[0] = b'{"ok":true}'
        with self.assertRaisesRegex(code['UpdateFailure'], 'reply invalid'):
            code['browser_ssh_route_health']()

    def test_staged_bundle_rechecks_archive_and_extracted_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.tar.gz"
            make_bundle(bundle)
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            candidate = root / "opt/sovagrid-candidates" / digest
            source = candidate / "source"
            source.mkdir(parents=True)
            shutil.copy2(bundle, candidate / "bundle.tar.gz")
            (candidate / ".ready").write_text(digest + "\n")
            with tarfile.open(bundle, "r:gz") as archive:
                # A package created by this fixture; filter= is unavailable on Python 3.9.
                archive.extractall(source)
            code = updater()
            code["ROOT"] = root
            # The fixture is owned by the test user; production checks root
            # ownership and permissions in safe_tree before any reading.
            code["safe_tree"] = lambda *_args, **_kwargs: None
            self.assertEqual(len(code["candidate_source"](digest)[1]), 5)
            caddyfile = source / "sovagrid-web/deploy/Caddyfile.container"
            self.assertEqual(caddyfile.stat().st_mode & 0o777, 0o644)
            caddyfile.chmod(0o600)
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_source"](digest)
            caddyfile.chmod(0o644)
            cache = source / "sovagrid-hub/sovagrid_hub/__pycache__/store.cpython-312.pyc"
            cache.parent.mkdir(parents=True)
            cache.write_bytes(b"generated bytecode")
            self.assertEqual(len(code["source_manifest"](source, allow_generated=True)[1]), 5)
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_source"](digest)
            cache.unlink()
            cache.parent.rmdir()
            cache.parent.parent.rmdir()
            (source / "sovagrid-hub/Dockerfile").write_text("tampered\n")
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_source"](digest)
            (source / "sovagrid-hub/Dockerfile").write_bytes(b"FROM scratch\n")
            (candidate / "bundle.tar.gz").write_bytes(b"tampered archive")
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_source"](digest)

    def _transaction_fixture(self, root: Path, *, fail_install: bool) -> tuple[dict, list[list[str]]]:
        code = updater()
        code["ROOT"] = root
        code["SNAPSHOT"] = ("/etc/sovagrid", "/var/lib/sovagrid/hub",
                            "/etc/systemd/system/sovagrid-vpn-status.service")
        code["UNITS"] = ("sovagrid-agent.service", "sovagrid-vpn-routing.service")
        code["private_candidate_root"] = lambda _path: None
        code["validate_lock"] = lambda _info: None
        code["service_setup_lock"] = nullcontext
        code["managed_vpn_locks"] = nullcontext
        code["PUBLIC_OWNER"] = os.getuid()
        # The fixture runs as an ordinary user. Production requires root:root.
        code["validate_private_install_log"] = lambda _info: None
        code["validate_private_log_dir"] = lambda _info: None
        code["secure_log_fd"] = lambda fd: os.fchmod(fd, 0o600)
        old = root / "opt/sovagrid-src"
        old.mkdir(parents=True)
        (old / "version").write_text("old")
        candidate_root = root / "opt/sovagrid-candidates"
        candidate_root.mkdir()
        staged = candidate_root / ("a" * 64) / "source"
        staged.mkdir(parents=True)
        (staged / "version").write_text("new")
        config = root / "etc/sovagrid"
        config.mkdir(parents=True)
        (config / "agent.json").write_text("old config")
        (config / "deploy.env").write_text("SOVAGRID_HUB_DATA_DIR=/var/lib/sovagrid/hub\n"
                                           "SOVAGRID_CADDY_DATA_DIR=/var/lib/sovagrid/caddy\n")
        hub = root / "var/lib/sovagrid/hub"
        hub.mkdir(parents=True)
        (hub / "hub.sqlite").write_text("old data")
        unit = root / "etc/systemd/system/sovagrid-vpn-status.service"
        unit.parent.mkdir(parents=True)
        unit.write_text("old unit")
        old_commits = {"sovagrid-hub": "b" * 40}
        new_commits = {"sovagrid-hub": "c" * 40}
        flags = ["--with-wireguard", "--with-terminal", "--with-files", "--with-journal",
                 "--journal-unit", "sovagrid-agent.service"]
        expected_units = ["sovagrid-agent.service"]
        code["inspect_state"] = lambda: (old, "b" * 64, old_commits, flags, expected_units)
        code["candidate_source"] = lambda _digest: (staged, new_commits)
        code["candidate_features_compatible"] = lambda _source, _flags: None
        code["source_manifest"] = lambda source, **_kwargs: (("b" * 64, old_commits) if
            (source / "version").read_text() == "old" else ("c" * 64, new_commits))
        code["managed_flags"] = lambda: (flags, expected_units)
        code["gateway_prior_state"] = lambda: {"container_ids": [], "image": None}
        code["original_compose_args"] = code["compose_args"]
        code["compose_args"] = lambda _source, **_kwargs: (["docker", "compose"], {})
        code["health"] = lambda _source, _units: None

        def copy_item(source: Path, destination: Path) -> None:
            if source.is_dir():
                shutil.copytree(source, destination)
            else:
                shutil.copy2(source, destination)
        code["copy_item"] = copy_item
        code["subprocess"] = types.SimpleNamespace(
            run=lambda args, **_kwargs: types.SimpleNamespace(
                stdout="" if args[:2] == ["docker", "ps"] else "sha256:old-image\n"),
        )
        calls: list[list[str]] = []
        def command(args, **_kwargs):
            calls.append(list(args))
            if args[0] == "bash":
                _kwargs["stdout"].write(b"private fixture diagnostic: sample-secret\n")
                (config / "agent.json").write_text("new config")
                (hub / "hub.sqlite").write_text("new data")
                unit.write_text("new unit")
                if fail_install:
                    raise code["UpdateFailure"]("fixture installer failure")
            return 0
        code["command"] = command
        return code, calls

    def _public_fixture(self, root: Path) -> tuple[Path, str]:
        base = root / "etc/sovagrid/public-web"
        generation = base / "generations" / ("d" * 32)
        generation.mkdir(parents=True)
        base.chmod(0o700)
        generation.chmod(0o700)
        (base / ".managed").write_bytes(b"SOVAGRID_PUBLIC_WEB_V1\n")
        (base / ".managed").chmod(0o600)
        files = {"compose.yaml": b"services: {web: {ports: ['80:9080', '443:9443']}}\n",
                 "caddy/global/public.options": b"default_sni 8.8.8.8\n",
                 "caddy/sites/public.caddy": b"https://8.8.8.8:9443 { respond 'fixture' }\n"}
        for name, raw in files.items():
            target = generation / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o644)
        state = {"protocol": 1, "generation": "d" * 32,
                 "config": {"mode": "ip", "address": "8.8.8.8", "acme_environment": "production"},
                 "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
        (base / "state.json").write_text(json.dumps(state))
        (base / "state.json").chmod(0o600)
        return base, str(generation / "compose.yaml")

    def _local_fixture(self, root: Path) -> tuple[Path, str]:
        base = root / "etc/sovagrid/local-web"
        generation = base / "generations" / ("e" * 32)
        generation.mkdir(parents=True)
        base.chmod(0o700)
        generation.chmod(0o700)
        (base / ".managed").write_bytes(b"SOVAGRID_LOCAL_WEB_V1\n")
        (base / ".managed").chmod(0o600)
        files = {"compose.yaml": b"services: {web: {volumes: ['panel']}}\n",
                 "caddy/panel.caddy": b"handle_path /sovagrid/monitoring/* { reverse_proxy hub:8766 }\n"}
        for name, raw in files.items():
            target = generation / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o644)
        state = {"protocol": 1, "generation": "e" * 32,
                 "config": {"panel_path": "/sovagrid/monitoring/", "root_behavior": "untouched"},
                 "sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}}
        (base / "state.json").write_text(json.dumps(state))
        (base / "state.json").chmod(0o600)
        return base, str(generation / "compose.yaml")

    def test_current_public_layout_accepts_valid_path_and_rejects_changed_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"], code["PUBLIC_OWNER"] = root, os.getuid()
            base, overlay = self._public_fixture(root)
            state_file = base / "state.json"
            state = json.loads(state_file.read_text())
            panel = base / "generations" / ("d" * 32) / "caddy/local/panel.caddy"
            panel.parent.mkdir(parents=True)
            panel.write_text("handle /sovagrid/monitoring/* { reverse_proxy hub:8766 }\n")
            state["config"].update(panel_path="/sovagrid/monitoring/", root_behavior="untouched")
            state["sha256"]["caddy/local/panel.caddy"] = hashlib.sha256(panel.read_bytes()).hexdigest()
            state_file.write_text(json.dumps(state))
            self.assertEqual(code["public_web_overlay"](), overlay)
            state["config"]["panel_path"] = "/api/"
            state_file.write_text(json.dumps(state))
            with self.assertRaises(code["UpdateFailure"]):
                code["public_web_overlay"]()
            state["config"]["panel_path"] = "/sovagrid/monitoring/"
            state_file.write_text(json.dumps(state))
            panel.write_text("tampered")
            with self.assertRaises(code["UpdateFailure"]):
                code["public_web_overlay"]()

    def test_local_only_overlay_is_pinned_and_requires_candidate_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"], code["PUBLIC_OWNER"] = root, os.getuid()
            base, overlay = self._local_fixture(root)
            self.assertEqual(code["local_web_overlay"](), overlay)
            source = root / "candidate"
            script = source / "sovagrid-blueprint/run.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\n")
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_features_compatible"](source, [])
            script.write_text("#!/bin/bash\n# SOVAGRID_LOCAL_WEB_V1\n")
            deploy = source / "sovagrid-blueprint/deploy"
            deploy.mkdir()
            for name in ("local_web.py", "compose.local-web.template"):
                (deploy / name).write_text("fixture")
            caddy = source / "sovagrid-web/deploy/Caddyfile.container"
            caddy.parent.mkdir(parents=True)
            caddy.write_text("import /etc/caddy/local/*.caddy\n")
            code["candidate_features_compatible"](source, [])
            args, _ = code["compose_args"](source)
            self.assertEqual(args[-2:], ["-f", overlay])
            (base / "generations" / ("e" * 32) / "caddy/panel.caddy").write_text("tampered")
            with self.assertRaises(code["UpdateFailure"]):
                code["local_web_overlay"]()

    def test_public_and_local_overlay_cannot_be_active_together(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"], code["PUBLIC_OWNER"] = root, os.getuid()
            self._public_fixture(root)
            self._local_fixture(root)
            with self.assertRaises(code["UpdateFailure"]):
                code["compose_args"](root / "candidate")

    def test_public_config_blocks_downgrade_and_requires_verified_source_features(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"], code["PUBLIC_OWNER"] = root, os.getuid()
            self._public_fixture(root)
            source = root / "candidate"
            script = source / "sovagrid-blueprint/run.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/bin/bash\n")
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_features_compatible"](source, [])
            script.write_text("#!/bin/bash\n# SOVAGRID_PUBLIC_WEB_V1\n")
            for name in ("public_web.py", "public-web.site.template", "compose.public-web.template"):
                destination = source / "sovagrid-blueprint/deploy" / name
                destination.parent.mkdir(exist_ok=True)
                destination.write_text("fixture")
            caddy = source / "sovagrid-web/deploy/Caddyfile.container"
            caddy.parent.mkdir(parents=True)
            caddy.write_text(":8080 { respond 'old' }\n")
            with self.assertRaises(code["UpdateFailure"]):
                code["candidate_features_compatible"](source, [])
            caddy.write_text("import /etc/caddy/public/global/*.options\nimport /etc/caddy/public/sites/*.caddy\n")
            code["candidate_features_compatible"](source, [])

    def test_enabled_container_inventory_blocks_incompatible_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            script = source / 'sovagrid-blueprint/run.sh'
            script.parent.mkdir(parents=True)
            script.write_text('#!/bin/bash\n')
            code = updater()
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, ['--with-containers'])
            script.write_text('#!/bin/bash\n# SOVAGRID_CONTAINER_INVENTORY_V1\n--with-containers\n')
            for name in ('sovagrid_agent/containers.py', 'sovagrid_agent/container_collector.py',
                         'deploy/sovagrid-container-inventory.service',
                         'deploy/sovagrid-container-inventory.timer'):
                path = source / 'sovagrid-agent' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture\n')
            code['candidate_features_compatible'](source, ['--with-containers'])
            (source / 'sovagrid-agent/deploy/sovagrid-container-inventory.timer').unlink()
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, ['--with-containers'])

    def test_managed_gateway_blocks_candidate_without_ssh_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code['ROOT'] = root
            code['ssh_gateway_managed'] = lambda: True
            source = root / 'candidate'
            script = source / 'sovagrid-blueprint/run.sh'
            script.parent.mkdir(parents=True)
            script.write_text('#!/bin/bash\n')
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, [])
            script.write_text('#!/bin/bash\n# SOVAGRID_SSH_GATEWAY_INSTALL_V1\n')
            for name in ('sovagrid-web/Dockerfile.ssh-gateway',
                         'sovagrid-web/gateway/package.json',
                         'sovagrid-web/gateway/package-lock.json',
                         'sovagrid-web/gateway/server.js'):
                item = source / name
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_text('fixture\n')
            caddy = source / 'sovagrid-web/deploy/Caddyfile.container'
            caddy.parent.mkdir(parents=True)
            caddy.write_text(':8080 { respond "old" }\n')
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, [])
            caddy.write_text('handle /api/v1/browser-ssh/* { reverse_proxy ssh-gateway:8768 }\n')
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, [])
            script.write_text(script.read_text() + '# SOVAGRID_PUBLIC_SSH_REFRESH_V1\n')
            code['candidate_features_compatible'](source, [])

    def test_existing_release_feed_blocks_candidate_without_feed_units(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code['ROOT'] = root
            marker = root / 'var/lib/sovagrid/.release-feed-units-managed-by-run-sh'
            marker.parent.mkdir(parents=True)
            marker.write_text('managed\n')
            source = root / 'candidate'
            script = source / 'sovagrid-blueprint/run.sh'
            script.parent.mkdir(parents=True)
            script.write_text('#!/bin/bash\n')
            with self.assertRaises(code['UpdateFailure']):
                code['candidate_features_compatible'](source, [])
            script.write_text('#!/bin/bash\n# SOVAGRID_RELEASE_FEED_UNITS_V1\n')
            deploy = source / 'sovagrid-blueprint/deploy'
            deploy.mkdir()
            for name in ('release_feed.py', 'sovagrid-release-feed.service',
                         'sovagrid-release-feed.timer'):
                (deploy / name).write_text('fixture\n')
            code['candidate_features_compatible'](source, [])

    def test_public_overlay_never_silently_accepts_foreign_or_changed_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"], code["PUBLIC_OWNER"] = root, os.getuid()
            base, overlay = self._public_fixture(root)
            self.assertEqual(code["public_web_overlay"](), overlay)
            (base / ".managed").chmod(0o644)
            with self.assertRaises(code["UpdateFailure"]):
                code["public_web_overlay"]()
            (base / ".managed").chmod(0o600)
            Path(overlay).write_text("changed outside SovaGrid")
            with self.assertRaises(code["UpdateFailure"]):
                code["public_web_overlay"]()
            Path(overlay).unlink()
            Path(overlay).symlink_to(base / "state.json")
            with self.assertRaises(code["UpdateFailure"]):
                code["public_web_overlay"]()

    def test_rollback_recreates_web_with_original_public_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            _, overlay = self._public_fixture(root)
            code["compose_args"] = code["original_compose_args"]
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            restarted = [args for args in calls if args[:2] == ["docker", "compose"] and "--force-recreate" in args]
            self.assertEqual(len(restarted), 1)
            self.assertIn(overlay, restarted[0])
            self.assertEqual(code["public_web_overlay"](), overlay)

    def test_rollback_restores_local_overlay_and_recreates_web_with_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            base, overlay = self._local_fixture(root)
            state_before = (base / "state.json").read_bytes()
            code["compose_args"] = code["original_compose_args"]
            original_command = code["command"]
            def command(args, **kwargs):
                if args[0] == "bash":
                    (base / "state.json").write_text("changed during failed install")
                return original_command(args, **kwargs)
            code["command"] = command
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            self.assertFalse(any((root / "opt/sovagrid-candidates/transactions").iterdir()))
            stops = [args for args in calls if args[:2] == ["docker", "compose"] and args[-1] == "stop"]
            self.assertEqual(len(stops), 2)
            self.assertIn(overlay, stops[0])
            self.assertNotIn(overlay, stops[1])
            self.assertTrue(stops[1][3].endswith("/snapshot/0/deploy.env"))
            restarted = [args for args in calls if args[:2] == ["docker", "compose"] and "--force-recreate" in args]
            self.assertEqual(len(restarted), 1)
            self.assertIn(overlay, restarted[0])
            self.assertEqual((base / "state.json").read_bytes(), state_before)
            self.assertEqual(code["local_web_overlay"](), overlay)

    def test_update_supervisor_holds_public_lock_while_installing_and_during_rollback(self) -> None:
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, _calls = self._transaction_fixture(root, fail_install=True)
            original = code["command"]
            checked = []
            def command(args, **kwargs):
                if args[0] == "bash" or "--force-recreate" in args:
                    with (root / "var/lib/sovagrid/.public-web.lock").open("rb") as lock:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    checked.append(args[0])
                if args[0] == "bash":
                    self.assertEqual(kwargs["env"]["SOVAGRID_PUBLIC_WEB_LOCK_HELD"], "1")
                return original(args, **kwargs)
            code["command"] = command
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            self.assertEqual(checked, ["bash", "docker"])

    def test_service_setup_lock_is_exclusive_and_rejects_symlink(self) -> None:
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'etc').mkdir()
            code = updater()
            code['ROOT'] = root
            actual_fstat = os.fstat

            def root_owned(fd):
                info = actual_fstat(fd)
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                                             st_nlink=info.st_nlink)

            with patch.object(os, 'fstat', side_effect=root_owned):
                with code['service_setup_lock']():
                    with (root / 'etc/sovagrid-service-setup.lock').open('rb') as second:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lock = root / 'etc/sovagrid-service-setup.lock'
            lock.unlink()
            lock.symlink_to(root / 'etc/other')
            with self.assertRaises(code['UpdateFailure']):
                with code['service_setup_lock']():
                    pass

    def test_service_units_refresh_only_when_installed_copy_matches_old_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code['ROOT'] = root
            old = root / 'old/sovagrid-agent/deploy'
            new = root / 'new/sovagrid-agent/deploy'
            old.mkdir(parents=True)
            new.mkdir(parents=True)
            unit_name = 'sovagrid-service-control.socket'
            (old / unit_name).write_text('old unit\n')
            (new / unit_name).write_text('new unit\n')
            unit = root / 'etc/systemd/system' / unit_name
            unit.parent.mkdir(parents=True)
            unit.write_text('old unit\n')
            unit.chmod(0o644)
            code['public_path'] = lambda value, **_kwargs: Path(value).read_bytes()
            calls = []
            code['command'] = lambda args, **_kwargs: calls.append(args)
            real_lstat = Path.lstat

            def root_lstat(item):
                info = real_lstat(item)
                if item != unit:
                    return info
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=0,
                                             st_nlink=info.st_nlink)

            states = {name: {'active': False, 'enabled': False} for name in code['SERVICE_UNITS']}
            with patch.object(Path, 'lstat', root_lstat):
                code['refresh_service_units'](root / 'old', root / 'new', states)
                self.assertEqual(unit.read_text(), 'new unit\n')
                self.assertEqual(calls, [['systemctl', 'daemon-reload']])
                unit.write_text('modified by operator\n')
                with self.assertRaises(code['UpdateFailure']):
                    code['refresh_service_units'](root / 'old', root / 'new', states)
                self.assertEqual(unit.read_text(), 'modified by operator\n')

    def test_new_updater_waiting_for_old_candidate_lock_does_not_hold_public_lock(self) -> None:
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, _calls = self._transaction_fixture(root, fail_install=False)
            candidate = root / "opt/sovagrid-candidates/.lock"
            reached = threading.Event()
            failures = []
            actual_flock = fcntl.flock
            def observed_flock(file, operation):
                if not isinstance(file, int) and operation == fcntl.LOCK_EX:
                    reached.set()  # candidate lock is reached but held by old updater
                return actual_flock(file, operation)
            def update():
                try:
                    code["apply"]("a" * 64, "b" * 64)
                except BaseException as error:
                    failures.append(error)
            with candidate.open("a+b") as old_lock:
                actual_flock(old_lock, fcntl.LOCK_EX)
                with patch.object(fcntl, "flock", observed_flock):
                    worker = threading.Thread(target=update, daemon=True)
                    worker.start()
                    try:
                        self.assertTrue(reached.wait(2))
                        public = root / "var/lib/sovagrid/.public-web.lock"
                        with public.open("a+b") as old_public:
                            # Old updater can finish run.sh: the new updater has
                            # not taken public while waiting for candidate.
                            actual_flock(old_public, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            actual_flock(old_public, fcntl.LOCK_UN)
                    finally:
                        actual_flock(old_lock, fcntl.LOCK_UN)
                        worker.join(3)
                    self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_successful_rollback_retains_only_bounded_private_install_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, _calls = self._transaction_fixture(root, fail_install=True)
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            logs = list((root / "opt/sovagrid-candidates/failure-logs").iterdir())
            self.assertEqual(len(logs), 1)
            self.assertTrue(logs[0].name.startswith("install-"))
            self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode), 0o600)
            self.assertIn("sample-secret", logs[0].read_text())
            self.assertEqual(list((root / "opt/sovagrid-candidates/transactions").iterdir()), [])
            self.assertIn("SG_APPLY_STAGE:LOG_SAVED", output.getvalue())
            self.assertNotIn("sample-secret", output.getvalue())
            self.assertEqual((root / "opt/sovagrid-src/version").read_text(), "old")

    def test_failure_log_is_capped_and_old_logs_are_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = updater()
            code["ROOT"] = root
            code["private_candidate_root"] = lambda _path: None
            code["validate_private_install_log"] = lambda _info: None
            code["validate_private_log_dir"] = lambda _info: None
            code["secure_log_fd"] = lambda fd: os.fchmod(fd, 0o600)
            code["MAX_FAILURE_LOG"] = 4096
            code["MAX_FAILURE_LOGS"] = 3
            folder = root / "opt/sovagrid-candidates/transactions/fixture"
            folder.mkdir(parents=True)
            (folder / "install.log").write_bytes(b"sensitive-prefix" + b"x" * 8000 + b"last-error")
            (folder / "install.log").chmod(0o600)
            for _ in range(5):
                self.assertTrue(code["preserve_install_log"](folder))
            logs = list((root / "opt/sovagrid-candidates/failure-logs").iterdir())
            self.assertEqual(len(logs), 3)
            for log in logs:
                data = log.read_bytes()
                self.assertLessEqual(len(data), 4096)
                self.assertIn(b"last-error", data)
                self.assertNotIn(b"sensitive-prefix", data)

    def test_installer_failure_restores_source_config_and_hub_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            self.assertEqual((root / "opt/sovagrid-src/version").read_text(), "old")
            self.assertEqual((root / "etc/sovagrid/agent.json").read_text(), "old config")
            self.assertEqual((root / "var/lib/sovagrid/hub/hub.sqlite").read_text(), "old data")
            self.assertEqual((root / "etc/systemd/system/sovagrid-vpn-status.service").read_text(), "old unit")
            self.assertIn("--journal-unit", next(args for args in calls if args[0] == "bash"))
            self.assertTrue(any(args[-3:] == ["up", "-d", "--no-build"] or
                                "--force-recreate" in args for args in calls))

    def test_container_marker_timer_and_snapshot_restore_after_failed_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            code['SNAPSHOT'] += ('/var/lib/sovagrid-containers',
                                 '/etc/systemd/system/sovagrid-container-inventory.service',
                                 '/etc/systemd/system/sovagrid-container-inventory.timer')
            code['UNITS'] += ('sovagrid-container-inventory.service', 'sovagrid-container-inventory.timer')
            marker = root / 'etc/sovagrid/.containers-managed-by-run-sh'
            timer = root / 'etc/systemd/system/sovagrid-container-inventory.timer'
            service = root / 'etc/systemd/system/sovagrid-container-inventory.service'
            snapshot = root / 'var/lib/sovagrid-containers/snapshot.json'
            snapshot.parent.mkdir(parents=True)
            marker.write_text('managed\n')
            timer.write_text('old timer\n')
            service.write_text('old service\n')
            snapshot.write_text('{"old":true}\n')
            original_command = code['command']

            def command(args, **kwargs):
                if args[0] == 'bash':
                    marker.unlink()
                    timer.write_text('changed timer\n')
                    service.unlink()
                    snapshot.unlink()
                return original_command(args, **kwargs)

            code['command'] = command
            with self.assertRaises(code['UpdateFailure']):
                code['apply']('a' * 64, 'b' * 64)
            self.assertEqual(marker.read_text(), 'managed\n')
            self.assertEqual(timer.read_text(), 'old timer\n')
            self.assertEqual(service.read_text(), 'old service\n')
            self.assertEqual(snapshot.read_text(), '{"old":true}\n')
            self.assertIn(['systemctl', 'restart', 'sovagrid-container-inventory.timer'], calls)

    def test_failed_update_restores_release_feed_and_service_broker_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=True)
            code['SNAPSHOT'] += (
                '/var/lib/sovagrid/.release-feed-units-managed-by-run-sh',
                '/var/lib/sovagrid/release-feed-state.json',
                '/etc/systemd/system/sovagrid-release-feed.timer',
                '/etc/sovagrid-service',
                '/etc/systemd/system/sovagrid-service-control.socket',
            )
            feed_dir = root / 'var/lib/sovagrid'
            (feed_dir / '.release-feed-units-managed-by-run-sh').write_text('old marker\n')
            (feed_dir / 'release-feed-state.json').write_text('old feed\n')
            feed_timer = root / 'etc/systemd/system/sovagrid-release-feed.timer'
            feed_timer.write_text('old timer\n')
            policy = root / 'etc/sovagrid-service'
            policy.mkdir()
            (policy / 'policy.json').write_text('old policy\n')
            broker = root / 'etc/systemd/system/sovagrid-service-control.socket'
            broker.write_text('old broker\n')
            original_command = code['command']

            def command(args, **kwargs):
                if args[0] == 'bash':
                    self.assertEqual(kwargs['env']['SOVAGRID_RELEASE_FEED_SNAPSHOT'], '1')
                    transaction = next((root / 'opt/sovagrid-candidates/transactions').iterdir())
                    self.assertEqual(json.loads((transaction / 'state.json').read_text())['snapshot_layout'],
                                     'ssh_gateway_v1')
                    self.assertEqual(kwargs['env']['SOVAGRID_HUB_BACKUP_BROKER_SNAPSHOT'], '1')
                    self.assertEqual(kwargs['env']['SOVAGRID_SSH_GATEWAY_SNAPSHOT'], '1')
                    (feed_dir / 'release-feed-state.json').write_text('new feed\n')
                    feed_timer.unlink()
                    (policy / 'policy.json').write_text('new policy\n')
                    broker.write_text('new broker\n')
                return original_command(args, **kwargs)

            code['command'] = command
            with self.assertRaises(code['UpdateFailure']):
                code['apply']('a' * 64, 'b' * 64)
            self.assertEqual((feed_dir / 'release-feed-state.json').read_text(), 'old feed\n')
            self.assertEqual(feed_timer.read_text(), 'old timer\n')
            self.assertEqual((policy / 'policy.json').read_text(), 'old policy\n')
            self.assertEqual(broker.read_text(), 'old broker\n')
            self.assertEqual(calls.count(['systemctl', 'stop', 'sovagrid-service-control.service',
                                          'sovagrid-service-control.socket']), 2)

    def test_success_commits_new_source_and_keeps_exact_feature_flags(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=False)
            code["apply"]("a" * 64, "b" * 64)
            self.assertEqual((root / "opt/sovagrid-src/version").read_text(), "new")
            self.assertEqual((root / "etc/sovagrid/agent.json").read_text(), "new config")
            self.assertEqual(next(args for args in calls if args[0] == "bash")[-6:],
                             ["--with-wireguard", "--with-terminal", "--with-files",
                              "--with-journal", "--journal-unit", "sovagrid-agent.service"])
            self.assertFalse(any((root / "opt/sovagrid-candidates/transactions").iterdir()))

    def test_changed_installed_manifest_refuses_before_stopping_services(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=False)
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "c" * 64)
            self.assertEqual(calls, [])
            self.assertEqual((root / "opt/sovagrid-src/version").read_text(), "old")
            self.assertEqual((root / "var/lib/sovagrid/hub/hub.sqlite").read_text(), "old data")

    def test_incomplete_rollback_keeps_private_snapshot_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, _calls = self._transaction_fixture(root, fail_install=True)
            original_copy = code["copy_item"]
            def fail_only_restore(source: Path, destination: Path) -> None:
                if source.parent.name == "snapshot":
                    raise code["UpdateFailure"]("fixture restore failure")
                original_copy(source, destination)
            code["copy_item"] = fail_only_restore
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            folders = list((root / "opt/sovagrid-candidates/transactions").iterdir())
            self.assertEqual(len(folders), 1)
            state = json.loads((folders[0] / "state.json").read_text())
            self.assertEqual(state["phase"], "rollback_failed")
            self.assertTrue((folders[0] / "snapshot/0").is_dir())
            self.assertTrue((folders[0] / "snapshot/1").is_dir())

    def test_next_attempt_recovers_interrupted_transaction_first(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=False)
            folder = root / "opt/sovagrid-candidates/transactions/old-interrupted"
            snapshot = folder / "snapshot"
            snapshot.mkdir(parents=True)
            # Old Connect transactions had no layout marker, and stored Hub at
            # index 6 rather than Blueprint's index 5.
            shutil.copytree(root / "etc/sovagrid", snapshot / "2")
            shutil.copytree(root / "var/lib/sovagrid/hub", snapshot / "6")
            old_source = root / "opt/sovagrid-src"
            old_source.rename(folder / "source-before")
            shutil.copytree(root / ("opt/sovagrid-candidates/" + "a" * 64) / "source", old_source)
            (root / "etc/sovagrid/agent.json").write_text("new config")
            (root / "var/lib/sovagrid/hub/hub.sqlite").write_text("new data")
            code["state_write"](folder, {
                "phase": "running", "old_manifest": "b" * 64,
                "images": {"hub": "sha256:old-image", "web": "sha256:old-image"},
                "units": {"sovagrid-agent.service": {"active": True, "enabled": True}},
                "expected_units": ["sovagrid-agent.service"],
            })
            with self.assertRaises(code["UpdateFailure"]):
                code["apply"]("a" * 64, "b" * 64)
            self.assertEqual(old_source.joinpath("version").read_text(), "old")
            self.assertEqual((root / "etc/sovagrid/agent.json").read_text(), "old config")
            self.assertEqual((root / "var/lib/sovagrid/hub/hub.sqlite").read_text(), "old data")
            self.assertFalse(folder.exists())
            self.assertFalse(any(args[0] == "bash" for args in calls))

    def test_ambiguous_legacy_transaction_stays_available_without_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, calls = self._transaction_fixture(root, fail_install=False)
            folder = root / 'opt/sovagrid-candidates/transactions/ambiguous'
            (folder / 'snapshot').mkdir(parents=True)
            code['state_write'](folder, {'phase': 'running', 'old_manifest': 'b' * 64,
                                          'images': {'hub': 'sha256:old', 'web': 'sha256:old'},
                                          'units': {}, 'expected_units': []})
            with self.assertRaises(code['UpdateFailure']):
                code['apply']('a' * 64, 'b' * 64)
            self.assertTrue(folder.exists())
            self.assertEqual(calls, [])
            self.assertEqual((root / 'opt/sovagrid-src/version').read_text(), 'old')


if __name__ == "__main__":
    unittest.main()
