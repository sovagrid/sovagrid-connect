# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
from __future__ import annotations

import hashlib
import io
import json
import os
import queue
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import contextmanager
from types import SimpleNamespace

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import (
    COMPONENTS, InstallError, InstallFeatures, PreparedUpdate, ServerInstaller, snapshot_bundle,
    verify_bundle, nearby_server_bundle, parse_journal_units, FeatureState,
    _INSTALL_SCRIPT, _STAGE_UPDATE_SCRIPT, _FEATURE_ENABLE_SCRIPT, _FEATURE_PROBE_SCRIPT, _EXISTING_CHECKS,
)
from sovagrid_connect.remote_update import REMOTE_SCRIPT
from sovagrid_connect.server_timer import SERVER_TIMER_COMMAND
from sovagrid_connect.server_status import ServerStatus
from sovagrid_connect.server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256

try:
    from sovagrid_connect.gui import Launcher
except ImportError:  # Headless Python builds need not include Tkinter.
    Launcher = None


REQUIRED = {
    "sovagrid-blueprint/run.sh": b"#!/bin/bash\n",
    "sovagrid-blueprint/deploy/compose.yaml": b"services: {}\n",
    "sovagrid-hub/Dockerfile": b"FROM scratch\n",
    "sovagrid-web/Dockerfile": b"FROM scratch\n",
    "sovagrid-web/deploy/Caddyfile.container": b":8080 { respond \"ok\" }\n",
    "sovagrid-agent/deploy/sovagrid-agent.service": b"[Service]\n",
    "sovagrid-vpn/deploy/sovagrid-vpn-status.service": b"[Service]\n",
}


def make_bundle(path: Path, *, altered_hash: bool = False, extra_name: str | None = None,
                special_link: bool = False, duplicate: bool = False,
                unsafe_mode: bool = False, commit: str = "a" * 40,
                journal: bool = False, caddy_mode: int = 0o644,
                hub_only_update: bool = False) -> None:
    files = dict(REQUIRED)
    if journal:
        files["sovagrid-blueprint/run.sh"] += b"# SOVAGRID_JOURNAL_INSTALL_V1\n"
        for name in (
            "sovagrid-agent/sovagrid_agent/journal_broker.py",
            "sovagrid-agent/deploy/sovagrid-journal-control.socket",
            "sovagrid-agent/deploy/sovagrid-journal-control.service",
        ):
            files[name] = b"fixture\n"
    if hub_only_update:
        for name in (
            "sovagrid-blueprint/deploy/promote_agent_only.py",
            "sovagrid-blueprint/deploy/hub_only_update.py",
            "sovagrid-blueprint/deploy/hub_only_auto_update.py",
            "sovagrid-blueprint/deploy/remote_update_worker.py",
            "sovagrid-blueprint/deploy/sovagrid-hub-only-update.service",
            "sovagrid-blueprint/deploy/sovagrid-hub-only-update.timer",
        ):
            files[name] = b"fixture\n"
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    if altered_hash:
        hashes["sovagrid-blueprint/run.sh"] = "0" * 64
    manifest = {
        "format": 1,
        "components": {
            name: {"commit": commit, "file_count": sum(key.startswith(name + "/") for key in files)}
            for name in COMPONENTS
        },
        "sha256": hashes,
    }
    with tarfile.open(path, "w:gz") as archive:
        directories = {"/".join(name.split("/")[:index]) for name in files
                       for index in range(1, len(name.split("/")))}
        for name in sorted(directories, key=lambda value: (value.count("/"), value)):
            item = tarfile.TarInfo(name + "/")
            item.type = tarfile.DIRTYPE
            item.mode = 0o755
            archive.addfile(item)
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = (0o4755 if unsafe_mode else 0o755) if name == "sovagrid-blueprint/run.sh" else (
                caddy_mode if name == "sovagrid-web/deploy/Caddyfile.container" else 0o644)
            archive.addfile(item, io.BytesIO(data))
            if duplicate and name == "sovagrid-blueprint/run.sh":
                archive.addfile(item, io.BytesIO(data))
        if extra_name:
            item = tarfile.TarInfo(extra_name)
            item.mode = 0o644
            if special_link:
                item.type = tarfile.SYMTYPE
                item.linkname = "/etc/passwd"
                archive.addfile(item)
            else:
                item.size = 1
                archive.addfile(item, io.BytesIO(b"x"))
        payload = json.dumps(manifest).encode("utf-8")
        item = tarfile.TarInfo("sovagrid-bundle.json")
        item.size = len(payload)
        item.mode = 0o644
        archive.addfile(item, io.BytesIO(payload))


FAKE_SSH = r'''
import hashlib
from pathlib import Path
import sys

args = sys.argv[1:]
command = args[-1]
if command.startswith("/usr/bin/python3 -I /opt/sovagrid-src/sovagrid-blueprint/deploy/auto_update.py "):
    import json
    Path(__file__).with_suffix(".timer_command").write_text(command)
    if command.endswith(" status"):
        print(json.dumps({"policy": {"format": 1, "archive_sha256": "a" * 64,
                          "expected_current_manifest": "b" * 64,
                          "created_at": 1000, "expires_at": 2000},
                          "last": {"format": 1, "state": "armed", "updated_at": 1001,
                                   "archive_sha256": "a" * 64,
                                   "expected_current_manifest": "b" * 64, "detail": ""}}))
        raise SystemExit(0)
    if command.endswith(" disarm"):
        print("SG_AUTO_UPDATE:DISABLED")
        raise SystemExit(0)
    if " arm " in command:
        print("SG_AUTO_UPDATE:ARMED")
        raise SystemExit(0)
    raise SystemExit(2)
if command == "python3 - preview":
    data = sys.stdin.buffer.read()
    Path(__file__).with_suffix(".remote_script").write_bytes(data)
    print("SG_CURRENT_MANIFEST:" + "b" * 64)
    for name in ("sovagrid-blueprint", "sovagrid-hub", "sovagrid-web", "sovagrid-agent", "sovagrid-vpn"):
        print("SG_CURRENT_COMMIT:" + name + ":" + "b" * 40)
    print("SG_VERSION_PREFLIGHT:OK")
    raise SystemExit(0)
if command.startswith("python3 - apply "):
    data = sys.stdin.buffer.read()
    Path(__file__).with_suffix(".remote_script").write_bytes(data)
    print("SG_APPLY_STAGE:VERIFIED")
    print("SG_APPLY_STAGE:STOPPED")
    print("SG_APPLY_STAGE:INSTALLING")
    if "--fixture-fail-apply" in open(args[args.index("-F") + 1]).read():
        print("SG_APPLY_STAGE:ROLLBACK")
        print("SG_APPLY_STAGE:ROLLED_BACK")
        print("private diagnostic: sample-secret")
        print("SG_APPLY_STAGE:LOG_SAVED")
        raise SystemExit(40)
    print("SG_APPLY_STAGE:CHECKING")
    print("SG_APPLY_STAGE:DONE")
    raise SystemExit(0)
if command.startswith("python3 - apply-auto "):
    Path(__file__).with_suffix(".auto_command").write_text(command)
    print("SG_UPDATE_REFUSE:BUSY")
    raise SystemExit(43)
if "SG_UPDATE_STAGE:DONE" in command:
    if "--fixture-unmanaged" in open(args[args.index("-F") + 1]).read():
        print("SG_INSTALL_REFUSE:UNMANAGED")
        raise SystemExit(30)
    data = sys.stdin.buffer.read()
    Path(__file__).with_suffix(".digest").write_text(hashlib.sha256(data).hexdigest())
    if "--fixture-bad-remote-hash" in open(args[args.index("-F") + 1]).read():
        print("SG_INSTALL_REFUSE:HASH")
        raise SystemExit(30)
    print("SG_FEATURE:WIREGUARD:1")
    print("SG_FEATURE:TERMINAL:0")
    print("SG_FEATURE:FILES:0")
    print("SG_FEATURE:JOURNAL:0")
    print("SG_FEATURE:JOURNAL_CONFIGURED:0")
    print("SG_FEATURE:JOURNAL_SUPPORTED:1")
    print("SG_FEATURE_PREFLIGHT:OK")
    print("SG_UPDATE_STAGE:TRANSFER")
    print("SG_UPDATE_STAGE:VERIFY")
    print("SG_UPDATE_STAGE:DONE")
    raise SystemExit(0)
if "SG_FEATURE_PREFLIGHT:OK" in command:
    fixture = open(args[args.index("-F") + 1]).read()
    if "--fixture-unmanaged" in fixture:
        print("SG_INSTALL_REFUSE:UNMANAGED")
        raise SystemExit(30)
    print("SG_FEATURE:WIREGUARD:1")
    print("SG_FEATURE:TERMINAL:0")
    print("SG_FEATURE:FILES:0")
    print("SG_FEATURE:JOURNAL:0")
    print("SG_FEATURE:JOURNAL_CONFIGURED:0")
    print("SG_FEATURE:JOURNAL_SUPPORTED:1")
    enabled = "--fixture-containers-enabled" in fixture
    print("SG_FEATURE:CONTAINERS:" + str(int(enabled)))
    print("SG_FEATURE:CONTAINERS_CONFIGURED:" + str(int(enabled)))
    print("SG_FEATURE:CONTAINERS_SUPPORTED:" + str(int("--fixture-old-containers" not in fixture)))
    print("SG_FEATURE_CAS:" + "a" * 64)
    print("SG_FEATURE_PREFLIGHT:OK")
    if "SG_INSTALL_STAGE:DONE" in command:
        print("SG_INSTALL_STAGE:RUN")
        print("SG_INSTALL_STAGE:BUILD")
        print("SG_INSTALL_STAGE:DONE")
    raise SystemExit(0)
if "SG_INSTALL_STAGE:DONE" not in command:
    if "--fixture-existing" in open(args[args.index("-F") + 1]).read():
        print("SG_INSTALL_REFUSE:EXISTING")
        raise SystemExit(22)
    print("SG_INSTALL_PREFLIGHT:OK")
    raise SystemExit(0)
data = sys.stdin.buffer.read()
Path(__file__).with_suffix(".digest").write_text(hashlib.sha256(data).hexdigest())
print("SG_INSTALL_STAGE:TRANSFER")
print("SG_INSTALL_STAGE:EXTRACT")
print("SG_INSTALL_STAGE:RUN")
if "--fixture-fail-run" in open(args[args.index("-F") + 1]).read():
    raise SystemExit(1)
print("SG_INSTALL_STAGE:DONE")
'''


class BundleTests(unittest.TestCase):
    def test_real_distribution_manifest_and_snapshot(self) -> None:
        real = Path(__file__).resolve().parents[2] / "SovaGrid-server-source.tar.gz"
        if not real.is_file():
            self.skipTest("release bundle is not in a standalone Connect checkout")
        summary = verify_bundle(real)
        self.assertEqual(set(summary.commits), COMPONENTS)
        self.assertGreater(summary.files, 100)
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory, "verified.tar.gz")
            self.assertEqual(snapshot_bundle(real, copy).files, summary.files)
            self.assertEqual(hashlib.sha256(copy.read_bytes()).digest(), hashlib.sha256(real.read_bytes()).digest())

    def test_rejects_traversal_link_duplicate_and_changed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "bundle.tar.gz")
            for options in (
                {"extra_name": "../escape"},
                {"extra_name": "sovagrid-hub/unsafe", "special_link": True},
                {"duplicate": True},
                {"altered_hash": True},
                {"unsafe_mode": True},
                {"caddy_mode": 0o600},
                {"caddy_mode": 0o755},
            ):
                with self.subTest(options=options):
                    make_bundle(path, **options)
                    with self.assertRaises(InstallError):
                        verify_bundle(path)
            make_bundle(path)
            self.assertEqual(verify_bundle(path).files, len(REQUIRED))

    def test_rejects_oversized_or_symlinked_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            make_bundle(source)
            link = Path(directory, "link.tar.gz")
            try:
                link.symlink_to(source)
            except OSError:
                pass  # Some Windows runners do not grant symlink creation.
            else:
                with self.assertRaises(InstallError):
                    verify_bundle(link)
            source.write_bytes(b"invalid")
            with self.assertRaises(InstallError):
                verify_bundle(source)
            with source.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            with self.assertRaises(InstallError):
                verify_bundle(source)


class InstallTests(unittest.TestCase):
    def test_journal_units_are_exact_bounded_and_canonical(self) -> None:
        self.assertEqual(parse_journal_units(" ssh.service\nnginx@site-1.service\n"),
                         ("ssh.service", "nginx@site-1.service"))
        features = InstallFeatures(journal_units=("ssh.service", "nginx@site-1.service"))
        self.assertEqual(features.flags(),
                         ("--with-journal", "--journal-unit", "ssh.service",
                          "--journal-unit", "nginx@site-1.service"))
        for value in ("", "ssh", "ssh.service;id", "ssh.service\nssh.service",
                      "ssh.service\n" * 17, "a" * 97 + ".service", "--help.service\x00"):
            with self.subTest(value=value), self.assertRaises(InstallError):
                parse_journal_units(value)
        with self.assertRaises(InstallError):
            InstallFeatures(journal_units=("ssh.service", "ssh.service"))

    def test_journal_feature_state_requires_exact_current_allowlist(self) -> None:
        markers = ["SG_FEATURE:WIREGUARD:0", "SG_FEATURE:TERMINAL:1", "SG_FEATURE:FILES:0",
                   "SG_FEATURE:JOURNAL:1", "SG_FEATURE:JOURNAL_CONFIGURED:1",
                   "SG_FEATURE:JOURNAL_SUPPORTED:1",
                   "SG_JOURNAL_UNIT:ssh.service", "SG_JOURNAL_UNIT:nginx.service"]
        state = FeatureState.from_markers(markers)
        self.assertTrue(state.journal_supported)
        self.assertTrue(state.covers(InstallFeatures(journal_units=("nginx.service", "ssh.service"))))
        self.assertFalse(state.covers(InstallFeatures(journal_units=("ssh.service",))))
        self.assertFalse(state.covers(InstallFeatures(journal_disable=True)))
        self.assertEqual(InstallFeatures(journal_disable=True).flags(), ("--disable-journal",))
        self.assertTrue(FeatureState.from_markers([
            "SG_FEATURE:WIREGUARD:0", "SG_FEATURE:TERMINAL:0", "SG_FEATURE:FILES:0",
            "SG_FEATURE:JOURNAL:0", "SG_FEATURE:JOURNAL_CONFIGURED:0",
            "SG_FEATURE:JOURNAL_SUPPORTED:1",
        ]).covers(InstallFeatures(journal_disable=True)))
        with self.assertRaises(InstallError):
            InstallFeatures(journal_units=("ssh.service",), journal_disable=True)
        with self.assertRaises(InstallError):
            FeatureState.from_markers(markers + ["SG_JOURNAL_UNIT:ssh.service"])

    def test_journal_run_guard_and_preflight_are_read_only(self) -> None:
        self.assertIn("/etc/sovagrid-journal/units.json", _EXISTING_CHECKS)
        self.assertIn("SG_FEATURE:JOURNAL_SUPPORTED", _EXISTING_CHECKS)
        self.assertIn("refuse JOURNAL", _FEATURE_ENABLE_SCRIPT)
        self.assertLess(_FEATURE_ENABLE_SCRIPT.index("refuse JOURNAL"),
                        _FEATURE_ENABLE_SCRIPT.index("bash /opt/sovagrid-src/sovagrid-blueprint/run.sh"))
        if os.name != "nt" and shutil.which("bash"):
            for command in (_EXISTING_CHECKS, _FEATURE_ENABLE_SCRIPT):
                result = subprocess.run(["bash", "-n", "-c", command], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_container_choices_state_and_exact_flags(self) -> None:
        absent = ["SG_FEATURE:WIREGUARD:0", "SG_FEATURE:TERMINAL:0", "SG_FEATURE:FILES:0",
                  "SG_FEATURE:JOURNAL:0", "SG_FEATURE:JOURNAL_CONFIGURED:0",
                  "SG_FEATURE:JOURNAL_SUPPORTED:1", "SG_FEATURE:CONTAINERS:0",
                  "SG_FEATURE:CONTAINERS_CONFIGURED:0", "SG_FEATURE:CONTAINERS_SUPPORTED:1",
                  "SG_FEATURE_CAS:" + "a" * 64]
        state = FeatureState.from_markers(absent)
        self.assertTrue(state.containers_supported)
        self.assertFalse(state.covers(InstallFeatures(containers=True)))
        self.assertTrue(state.covers(InstallFeatures(containers_disable=True)))
        self.assertEqual(InstallFeatures(containers=True).flags(), ("--with-containers",))
        self.assertEqual(InstallFeatures(containers_disable=True).flags(), ("--disable-containers",))
        enabled = FeatureState.from_markers([
            marker.replace("SG_FEATURE:CONTAINERS:0", "SG_FEATURE:CONTAINERS:1")
                  .replace("SG_FEATURE:CONTAINERS_CONFIGURED:0", "SG_FEATURE:CONTAINERS_CONFIGURED:1")
            for marker in absent
        ])
        self.assertTrue(enabled.covers(InstallFeatures(containers=True)))
        self.assertFalse(enabled.covers(InstallFeatures(containers_disable=True)))
        with self.assertRaisesRegex(InstallError, "одновременно"):
            InstallFeatures(containers=True, containers_disable=True)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_container_enable_disable_require_supported_source_and_pass_cas(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            for fixture, choice, expected in (
                    ("", InstallFeatures(containers=True), "--with-containers"),
                    ("--fixture-containers-enabled", InstallFeatures(containers_disable=True), "--disable-containers")):
                with self.subTest(choice=expected):
                    calls = []

                    def fake_popen(argv, **kwargs):
                        calls.append(argv)
                        config = Path(argv[argv.index("-F") + 1])
                        with config.open("a") as stream:
                            stream.write("# " + fixture + "\n")
                        return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

                    manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                                ssh_executable=sys.executable), popen=fake_popen)
                    state = manager.preflight_features()
                    self.assertEqual(state.containers, bool(fixture))
                    manager.enable_features(choice, expected_state=state)
                    self.assertEqual(len(calls), 2)
                    self.assertTrue(calls[1][-1].endswith("sovagrid " + "a" * 64 + " " + expected))
                    passed = calls[1][-1].rsplit(" sovagrid ", 1)[-1]
                    self.assertEqual(passed, "a" * 64 + " " + expected)

            calls = []

            def old_popen(argv, **kwargs):
                calls.append(argv)
                config = Path(argv[argv.index("-F") + 1])
                with config.open("a") as stream:
                    stream.write("# --fixture-old-containers\n")
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            old = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                    ssh_executable=sys.executable), popen=old_popen)
            state = old.preflight_features()
            self.assertFalse(state.containers_supported)
            for choice in (InstallFeatures(containers=True), InstallFeatures(containers_disable=True)):
                with self.subTest(old_source=choice.flags()), self.assertRaisesRegex(InstallError, "новой версии сервера"):
                    old.enable_features(choice, expected_state=state)
            self.assertEqual(len(calls), 1)

    def test_container_remote_guard_checks_cas_and_source_before_run_sh(self) -> None:
        action = _FEATURE_ENABLE_SCRIPT[len(_FEATURE_PROBE_SCRIPT):]
        self.assertIn("SOVAGRID_CONTAINER_INVENTORY_V1", _EXISTING_CHECKS)
        self.assertLess(action.index("$current_cas =="),
                        action.index("bash /opt/sovagrid-src/sovagrid-blueprint/run.sh"))
        self.assertLess(action.index("refuse CONTAINERS"),
                        action.index("bash /opt/sovagrid-src/sovagrid-blueprint/run.sh"))
        if os.name == "nt" or not shutil.which("bash"):
            return
        with tempfile.TemporaryDirectory() as directory:
            args_file = Path(directory, "run-args")
            prefix = ("current_cas=" + "a" * 64 + "\n"
                      "grep() { [[ ${FIXTURE_OLD:-0} == 0 ]]; }\n"
                      "bash() { printf '%s\\n' \"$@\" > \"$FIXTURE_ARGS\"; }\n")
            for old, cas, flag, marker, ran in (
                    ("0", "a" * 64, "--with-containers", "SG_INSTALL_STAGE:DONE", True),
                    ("0", "a" * 64, "--disable-containers", "SG_INSTALL_STAGE:DONE", True),
                    ("0", "b" * 64, "--with-containers", "SG_INSTALL_REFUSE:STATE", False),
                    ("1", "a" * 64, "--with-containers", "SG_INSTALL_REFUSE:CONTAINERS", False)):
                with self.subTest(old=old, flag=flag, cas=cas[:4]):
                    args_file.unlink(missing_ok=True)
                    result = subprocess.run(["bash", "-c", prefix + action, "sovagrid", cas, flag],
                                            capture_output=True, text=True,
                                            env=os.environ | {"FIXTURE_OLD": old, "FIXTURE_ARGS": str(args_file)})
                    self.assertIn(marker, result.stdout)
                    self.assertEqual(args_file.exists(), ran)
                    if ran:
                        self.assertEqual(args_file.read_text().splitlines(),
                                         ["/opt/sovagrid-src/sovagrid-blueprint/run.sh", flag])

    @unittest.skipUnless(os.name != "nt" and shutil.which("bash") and shutil.which("sha256sum"),
                         "requires GNU sha256sum used by the Ubuntu server")
    def test_feature_cas_changes_with_source_and_agent_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            run_sh = source / "run.sh"
            run_sh.write_text("v1\n")
            config = root / "agent.json"
            config.write_text('{"journal_units":["ssh.service"]}\n')
            fake_checks = "printf 'SG_FEATURE:CONTAINERS:0\\nSG_FEATURE_PREFLIGHT:OK\\n'"
            probe = (_FEATURE_PROBE_SCRIPT
                     .replace(shlex.quote(_EXISTING_CHECKS), shlex.quote(fake_checks))
                     .replace("/opt/sovagrid-src", str(source))
                     .replace("/etc/sovagrid/agent.json", str(config)))

            def cas() -> str:
                result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True, check=True)
                return next(line.removeprefix("SG_FEATURE_CAS:") for line in result.stdout.splitlines()
                            if line.startswith("SG_FEATURE_CAS:"))

            first = cas()
            run_sh.write_text("v2\n")
            second = cas()
            config.write_text('{"journal_units":["nginx.service"]}\n')
            third = cas()
            self.assertEqual([len(value) for value in (first, second, third)], [64, 64, 64])
            self.assertEqual(len({first, second, third}), 3)

    def test_first_install_shares_mobile_transaction_lock_and_rechecks(self) -> None:
        self.assertIn("/var/lib/sovagrid-first-install", _INSTALL_SCRIPT)
        self.assertIn("exec 9>/run/sovagrid-first-install.lock", _INSTALL_SCRIPT)
        self.assertIn("flock -n 9", _INSTALL_SCRIPT)
        self.assertEqual(_INSTALL_SCRIPT.count("for path in /opt/sovagrid-src"), 2)
        self.assertLess(_INSTALL_SCRIPT.rindex("for path in /opt/sovagrid-src"),
                        _INSTALL_SCRIPT.index('mv -T -- "$stage" /opt/sovagrid-src'))
        if os.name != "nt" and shutil.which("bash"):
            result = subprocess.run(["bash", "-n", "-c", _INSTALL_SCRIPT], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_old_bundle_refuses_journal_before_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            make_bundle(source)
            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root"),
                                      popen=lambda *_args, **_kwargs: self.fail("SSH must not start"))
            with self.assertRaisesRegex(InstallError, "ещё не поддерживает"):
                manager.install(source, InstallFeatures(journal_units=("ssh.service",)))

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_new_bundle_installs_exact_journal_units_without_shell_input(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            fake_ssh = Path(directory, "fake_ssh.py")
            make_bundle(source, journal=True)
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                        ssh_executable=sys.executable), popen=fake_popen)
            result = manager.install(source, InstallFeatures(journal_units=("ssh.service", "nginx@site.service")))
            self.assertEqual(result.files, len(REQUIRED) + 3)
            self.assertEqual(len(calls), 2)
            command = calls[1][0][-1]
            self.assertIn("--with-journal --journal-unit ssh.service --journal-unit nginx@site.service", command)
            self.assertNotIn("journalctl", command)
            self.assertEqual(calls[1][1]["stderr"], subprocess.DEVNULL)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_existing_journal_enable_preflights_then_passes_only_fixed_flags(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                        ssh_executable=sys.executable), popen=fake_popen)
            state = manager.preflight_features()
            self.assertTrue(state.journal_supported)
            self.assertFalse(state.journal)
            manager.enable_features(InstallFeatures(journal_units=("ssh.service",)))
            self.assertEqual(len(calls), 2)
            self.assertIn("--with-journal --journal-unit ssh.service", calls[1][0][-1])
            self.assertNotIn("/opt/sovagrid-candidates", calls[1][0][-1])
            for _argv, kwargs in calls:
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_existing_journal_disable_uses_fixed_flag_and_never_stages_source(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append(argv)
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                        ssh_executable=sys.executable), popen=fake_popen)
            manager.enable_features(InstallFeatures(journal_disable=True))
            self.assertEqual(len(calls), 1)
            self.assertTrue(calls[0][-1].endswith("sovagrid - --disable-journal"))
            self.assertNotIn("/opt/sovagrid-candidates", calls[0][-1])

    def test_starter_gui_offers_adjacent_bundle_with_visible_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "SovaGrid-server-source.tar.gz"
            bundle.write_bytes(b"fixture bundle")
            for executable in (
                root / "SovaGrid-Connect-GUI" / "SovaGrid-Connect-GUI.exe",
                root / "SovaGrid-Connect-GUI.app" / "Contents" / "MacOS" / "SovaGrid-Connect-GUI",
            ):
                with self.subTest(executable=executable), \
                     patch("sovagrid_connect.installer.sys.executable", str(executable)), \
                     patch("sovagrid_connect.installer.sys.frozen", True, create=True):
                    self.assertEqual(nearby_server_bundle(), (bundle.resolve(), hashlib.sha256(bundle.read_bytes()).hexdigest()))

    def test_starter_gui_does_not_hash_oversized_adjacent_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "SovaGrid-server-source.tar.gz"
            with bundle.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            executable = root / "SovaGrid-Connect-GUI" / "SovaGrid-Connect-GUI.exe"
            with patch("sovagrid_connect.installer.sys.executable", str(executable)), \
                 patch("sovagrid_connect.installer.sys.frozen", True, create=True):
                self.assertIsNone(nearby_server_bundle())

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_install_uses_gui_ssh_to_send_exact_bundle_and_fixed_flags(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            fake_ssh = Path(directory, "fake_ssh.py")
            make_bundle(source)
            fake_ssh.write_text(FAKE_SSH)
            calls = []
            messages = []

            def fake_popen(argv, **kwargs):
                config = Path(argv[argv.index("-F") + 1]).read_text()
                calls.append((argv, kwargs, config))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            options = ConnectionOptions(
                host="127.0.0.1", user="root", jump_host="relay.example.org",
                jump_user="relay", ssh_executable=sys.executable,
            )
            installer = ServerInstaller(options, popen=fake_popen, progress=messages.append)
            result = installer.install(source, InstallFeatures(wireguard=True, terminal=True, files=True))
            self.assertEqual(result.files, len(REQUIRED))
            self.assertEqual(len(calls), 2)
            digest = fake_ssh.with_suffix(".digest").read_text()
            self.assertEqual(digest, hashlib.sha256(source.read_bytes()).hexdigest())
            for argv, kwargs, config in calls:
                self.assertIn("ProxyJump sovagrid-jump", config)
                self.assertIn("StrictHostKeyChecking ask", config)
                self.assertIn("ClearAllForwardings=yes", argv)
                self.assertEqual(kwargs["env"]["SSH_ASKPASS_REQUIRE"], "force")
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertNotIn("secret", str(argv) + str(config))
                self.assertNotIn("--with-amnezia-control", argv[-1])
            self.assertIs(calls[0][1]["stdin"], subprocess.DEVNULL)
            self.assertTrue(calls[1][1]["stdin"].closed)
            self.assertIn("--with-wireguard", calls[1][0][-1])
            self.assertIn("--with-terminal", calls[1][0][-1])
            self.assertIn("--with-files", calls[1][0][-1])
            self.assertIn("Установка завершена", messages[-1])

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_existing_host_refused_before_upload(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            fake_ssh = Path(directory, "fake_ssh.py")
            make_bundle(source)
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append(argv)
                config = Path(argv[argv.index("-F") + 1])
                with config.open("a") as stream:
                    stream.write("# --fixture-existing\n")
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            installer = ServerInstaller(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(InstallError, "уже есть SovaGrid"):
                installer.install(source)
            self.assertEqual(len(calls), 1)

    def test_nonroot_refused_locally(self) -> None:
        installer = ServerInstaller(ConnectionOptions(host="example.org", user="ubuntu"))
        with self.assertRaisesRegex(InstallError, "root"):
            installer.install(Path("missing.tar.gz"))

    def test_changed_suggested_bundle_refused_before_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            make_bundle(source)
            installer = ServerInstaller(ConnectionOptions(host="example.org", user="root"),
                                        popen=lambda *_args, **_kwargs: self.fail("SSH must not start"))
            with self.assertRaisesRegex(InstallError, "Пакет изменился"):
                installer.install(source, expected_sha256="0" * 64)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_existing_feature_preflight_then_fixed_root_run_sh(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs, Path(argv[argv.index("-F") + 1]).read_text()))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(
                ConnectionOptions(host="127.0.0.1", user="root", jump_host="relay.example.org",
                                  jump_user="relay", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            state = manager.preflight_features()
            self.assertTrue(state.wireguard)
            self.assertFalse(state.terminal)
            self.assertFalse(state.files)
            self.assertTrue(state.covers(InstallFeatures(wireguard=True)))
            self.assertFalse(state.covers(InstallFeatures(terminal=True)))
            manager.enable_features(InstallFeatures(terminal=True, files=True))
            self.assertEqual(len(calls), 2)
            for argv, kwargs, config in calls:
                self.assertIn("StrictHostKeyChecking ask", config)
                self.assertIn("ProxyJump sovagrid-jump", config)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
                self.assertEqual(kwargs["env"]["SSH_ASKPASS_REQUIRE"], "force")
                self.assertNotIn("--with-amnezia-control", argv[-1])
            self.assertIn("/opt/sovagrid-src/sovagrid-blueprint/run.sh", calls[1][0][-1])
            self.assertIn("--with-terminal", calls[1][0][-1])
            self.assertIn("--with-files", calls[1][0][-1])
            self.assertNotIn("--with-wireguard", calls[1][0][-1])

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_unmanaged_existing_server_refused_without_run_sh(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append(argv)
                config = Path(argv[argv.index("-F") + 1])
                with config.open("a") as stream:
                    stream.write("# --fixture-unmanaged\n")
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(InstallError, "подтверждённой установки"):
                manager.preflight_features()
            self.assertEqual(len(calls), 1)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_update_preview_is_read_only_then_stages_exact_confirmed_bundle(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            fake_ssh = Path(directory, "fake_ssh.py")
            make_bundle(source)
            fake_ssh.write_text(FAKE_SSH)
            calls = []
            progress = []

            def fake_popen(argv, **kwargs):
                calls.append((argv, kwargs, Path(argv[argv.index("-F") + 1]).read_text()))
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(
                ConnectionOptions(host="127.0.0.1", user="root", jump_host="relay.example.org",
                                  jump_user="relay", ssh_executable=sys.executable),
                popen=fake_popen, progress=progress.append,
            )
            preview = manager.preview_update(source)
            self.assertEqual(preview.sha256, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(preview.bundle.commits["sovagrid-hub"], "a" * 40)
            self.assertTrue(preview.features.wireguard)
            self.assertEqual(preview.current_manifest_sha256, "b" * 64)
            self.assertEqual(preview.current_commits["sovagrid-hub"], "b" * 40)
            self.assertEqual(len(calls), 2)
            self.assertIs(calls[0][1]["stdin"], subprocess.DEVNULL)
            self.assertNotIn("/opt/sovagrid-candidates", calls[0][0][-1])
            self.assertEqual(fake_ssh.with_suffix(".remote_script").read_text(), REMOTE_SCRIPT)

            result = manager.prepare_update(source, expected_sha256=preview.sha256)
            self.assertEqual(result.remote_path, "/opt/sovagrid-candidates/" + preview.sha256)
            self.assertFalse(result.already_prepared)
            self.assertEqual(len(calls), 3)
            self.assertEqual(fake_ssh.with_suffix(".digest").read_text(), preview.sha256)
            self.assertTrue(calls[2][1]["stdin"].closed)
            self.assertEqual(calls[2][1]["stderr"], subprocess.DEVNULL)
            self.assertEqual(calls[2][1]["env"]["SSH_ASKPASS_REQUIRE"], "force")
            self.assertIn("ProxyJump sovagrid-jump", calls[2][2])
            self.assertIn("StrictHostKeyChecking ask", calls[2][2])
            self.assertIn(preview.sha256, calls[2][0][-1])
            self.assertNotIn("bash /opt/sovagrid-src/sovagrid-blueprint/run.sh", calls[2][0][-1])
            self.assertNotIn("--with-amnezia-control", calls[2][0][-1])
            self.assertIn("не менялись", progress[-1])

            manager.apply_update(result, expected_current_manifest=preview.current_manifest_sha256)
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[3][0][-1], f"python3 - apply {preview.sha256} {'b' * 64}")
            self.assertEqual(fake_ssh.with_suffix(".remote_script").read_text(), REMOTE_SCRIPT)
            self.assertIn("Обновление применено", progress[-1])

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_update_reports_verified_rollback_not_success(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            def fake_popen(argv, **kwargs):
                config = Path(argv[argv.index("-F") + 1])
                with config.open("a") as stream:
                    stream.write("# --fixture-fail-apply\n")
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)
            progress: list[str] = []
            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                        ssh_executable=sys.executable), popen=fake_popen,
                                      progress=progress.append)
            prepared = PreparedUpdate(None, "a" * 64, "/opt/sovagrid-candidates/" + "a" * 64, False)
            with self.assertRaisesRegex(InstallError, "Предыдущая версия восстановлена") as failure:
                manager.apply_update(prepared, expected_current_manifest="b" * 64)
            self.assertIn("/opt/sovagrid-candidates/failure-logs/", str(failure.exception))
            self.assertNotIn("sample-secret", str(failure.exception))
            self.assertNotIn("sample-secret", "\n".join(progress))

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_automatic_apply_uses_idle_gated_remote_mode(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            manager = ServerInstaller(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                popen=lambda argv, **kwargs: subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs),
            )
            prepared = PreparedUpdate(None, "a" * 64, "/opt/sovagrid-candidates/" + "a" * 64, False)
            with self.assertRaisesRegex(InstallError, "автоматическое обновление отложено"):
                manager.apply_automatic_update(prepared, expected_current_manifest="b" * 64)
            self.assertEqual(fake_ssh.with_suffix(".auto_command").read_text(),
                             "python3 - apply-auto " + "a" * 64 + " " + "b" * 64)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_server_timer_arms_exact_prepared_pin_and_reads_status(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "fake_ssh.py")
            fake_ssh.write_text(FAKE_SSH)
            commands = []

            def fake_popen(argv, **kwargs):
                commands.append(argv[-1])
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root",
                                                        jump_host="relay.example.org", jump_user="relay",
                                                        ssh_executable=sys.executable), popen=fake_popen)
            prepared = PreparedUpdate(None, "a" * 64, "/opt/sovagrid-candidates/" + "a" * 64, False)
            self.assertEqual(manager.arm_server_timer(prepared, expected_current_manifest="b" * 64), "armed")
            self.assertEqual(commands[-1], SERVER_TIMER_COMMAND + " arm " + "a" * 64 + " " + "b" * 64)
            status = manager.server_timer_status()
            self.assertTrue(status.armed)
            self.assertEqual(status.archive_sha256, "a" * 64)
            self.assertEqual(status.expires_at, 2000)
            manager.disarm_server_timer()
            self.assertEqual(commands[-1], SERVER_TIMER_COMMAND + " disarm")

    def test_server_timer_rejects_unpinned_or_nonroot_before_ssh(self) -> None:
        prepared = PreparedUpdate(None, "a" * 64, "/opt/sovagrid-candidates/" + "a" * 64, False)
        no_ssh = lambda *_args, **_kwargs: self.fail("SSH must not start")
        nonroot = ServerInstaller(ConnectionOptions(host="example.org", user="ubuntu"), popen=no_ssh)
        with self.assertRaisesRegex(InstallError, "root"):
            nonroot.arm_server_timer(prepared, expected_current_manifest="b" * 64)
        with self.assertRaisesRegex(InstallError, "root"):
            nonroot.server_timer_status()
        root = ServerInstaller(ConnectionOptions(host="example.org", user="root"), popen=no_ssh)
        forged = PreparedUpdate(None, "a" * 64, "/tmp/other-candidate", False)
        with self.assertRaisesRegex(InstallError, "неверный формат"):
            root.arm_server_timer(forged, expected_current_manifest="b" * 64)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_old_server_timer_fallback_is_explicit(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake_ssh = Path(directory, "old_ssh.py")
            fake_ssh.write_text("import sys\nraise SystemExit(2)\n")
            manager = ServerInstaller(
                ConnectionOptions(host="old.example.org", user="root", ssh_executable=sys.executable),
                popen=lambda argv, **kwargs: subprocess.Popen(
                    [sys.executable, str(fake_ssh), *argv[1:]], **kwargs),
            )
            prepared = PreparedUpdate(None, "a" * 64, "/opt/sovagrid-candidates/" + "a" * 64, False)
            with self.assertRaisesRegex(InstallError, "ещё не поддерживает"):
                manager.arm_server_timer(prepared, expected_current_manifest="b" * 64)
            with self.assertRaisesRegex(InstallError, "нет работающего таймера"):
                manager.server_timer_status()

    def test_update_rejects_changed_bundle_before_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            make_bundle(source)
            expected = hashlib.sha256(source.read_bytes()).hexdigest()
            make_bundle(source, commit="b" * 40)
            manager = ServerInstaller(ConnectionOptions(host="example.org", user="root"),
                                      popen=lambda *_args, **_kwargs: self.fail("SSH must not start"))
            with self.assertRaisesRegex(InstallError, "Пакет изменился"):
                manager.prepare_update(source, expected_sha256=expected)

    @patch("sovagrid_connect.installer.helper_path", return_value="fixture-askpass")
    def test_update_remote_refusal_never_claims_prepared(self, _helper) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "bundle.tar.gz")
            fake_ssh = Path(directory, "fake_ssh.py")
            make_bundle(source)
            fake_ssh.write_text(FAKE_SSH)
            calls = []

            def fake_popen(argv, **kwargs):
                calls.append(argv)
                config = Path(argv[argv.index("-F") + 1])
                with config.open("a") as stream:
                    stream.write("# --fixture-bad-remote-hash\n")
                return subprocess.Popen([sys.executable, str(fake_ssh), *argv[1:]], **kwargs)

            manager = ServerInstaller(
                ConnectionOptions(host="example.org", user="root", ssh_executable=sys.executable),
                popen=fake_popen,
            )
            with self.assertRaisesRegex(InstallError, "SHA-256"):
                manager.prepare_update(source, expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(len(calls), 1)

    def test_update_script_parses_and_never_runs_active_source(self) -> None:
        if os.name == "nt" or shutil.which("bash") is None:
            self.skipTest("Ubuntu remote script is syntax-checked on POSIX runners")
        result = subprocess.run(["bash", "-n", "-c", _STAGE_UPDATE_SCRIPT], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("bash /opt/sovagrid-src/sovagrid-blueprint/run.sh", _STAGE_UPDATE_SCRIPT)
        self.assertLess(_STAGE_UPDATE_SCRIPT.index("sha256sum \"$stage/bundle.tar.gz\""),
                        _STAGE_UPDATE_SCRIPT.index("tar --no-same-owner"))

    def test_both_remote_extractions_keep_verified_modes_under_private_umask(self) -> None:
        if os.name == "nt" or shutil.which("tar") is None:
            self.skipTest("remote tar extraction is tested on POSIX runners")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle.tar.gz"
            make_bundle(bundle)
            verify_bundle(bundle)
            for script in (_INSTALL_SCRIPT, _STAGE_UPDATE_SCRIPT):
                with self.subTest(stage="install" if script == _INSTALL_SCRIPT else "update"):
                    destination = root / ("install" if script == _INSTALL_SCRIPT else "update")
                    destination.mkdir()
                    line = next(line for line in script.splitlines() if "tar --no-same-owner" in line)
                    command = shlex.split(line[line.index("tar "):].split(" >/dev/null", 1)[0])
                    command[command.index("-xzf") + 1] = str(bundle)
                    command[command.index("-C") + 1] = str(destination)
                    result = subprocess.run(command, capture_output=True, text=True,
                                            preexec_fn=lambda: os.umask(0o077))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual((destination / "sovagrid-web/deploy/Caddyfile.container").stat().st_mode & 0o777, 0o644)
                    self.assertEqual((destination / "sovagrid-blueprint/run.sh").stat().st_mode & 0o777, 0o755)
                    self.assertEqual((destination / "sovagrid-web/deploy").stat().st_mode & 0o777, 0o755)


@unittest.skipIf(Launcher is None, "Tkinter unavailable")
class GuiFirstInstallDownloadTests(unittest.TestCase):
    @staticmethod
    def _launcher():
        launcher = Launcher.__new__(Launcher)
        launcher.status = Mock()
        launcher.events = queue.SimpleQueue()
        launcher.closing = False
        launcher.installing = False
        return launcher

    @staticmethod
    def _run_thread(target, daemon):
        return SimpleNamespace(start=target)

    def test_auto_install_downloads_before_ssh_and_keeps_source_until_install_returns(self) -> None:
        launcher = self._launcher()
        tunnel = SimpleNamespace(options=ConnectionOptions("server.example", "root"), start=Mock())
        manager = Mock()
        seen = []
        saved_paths = []

        @contextmanager
        def downloaded(*, progress):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "bundle.tar.gz")
                path.write_bytes(b"verified")
                saved_paths.append(path)
                seen.append("downloaded")
                progress("Скачано")
                yield path

        def install(path, *, expected_sha256):
            self.assertEqual(seen, ["downloaded"])
            self.assertEqual(path.read_bytes(), b"verified")
            self.assertEqual(expected_sha256, PUBLISHED_SERVER_SOURCE_SHA256)
            seen.append("ssh")

        manager.install.side_effect = install
        with patch("sovagrid_connect.gui.ServerInstaller", return_value=manager), \
             patch("sovagrid_connect.gui.downloaded_server_bundle", side_effect=downloaded), \
             patch("sovagrid_connect.gui.threading.Thread", side_effect=self._run_thread), \
             patch.object(Launcher, "_prepare_browser_login", return_value=None):
            launcher._auto_install_and_connect(tunnel, None)
        self.assertEqual(seen, ["downloaded", "ssh"])
        self.assertFalse(saved_paths[0].exists())
        tunnel.start.assert_called_once_with(timeout=180)
        self.assertEqual([launcher.events.get()[0] for _ in range(3)],
                         ["auto_install_progress", "connected", "auto_install_end"])

    def test_failed_download_never_starts_install_or_tunnel(self) -> None:
        launcher = self._launcher()
        tunnel = SimpleNamespace(options=ConnectionOptions("server.example", "root"), start=Mock())
        manager = Mock()

        @contextmanager
        def failed(*, progress):
            raise InstallError("SHA-256 не совпадает")
            yield  # pragma: no cover

        with patch("sovagrid_connect.gui.ServerInstaller", return_value=manager), \
             patch("sovagrid_connect.gui.downloaded_server_bundle", side_effect=failed), \
             patch("sovagrid_connect.gui.threading.Thread", side_effect=self._run_thread):
            launcher._auto_install_and_connect(tunnel, None)
        manager.install.assert_not_called()
        tunnel.start.assert_not_called()
        event, failure = launcher.events.get()
        self.assertEqual(event, "error")
        self.assertIsInstance(failure, InstallError)
        self.assertEqual(launcher.events.get()[0], "auto_install_end")

    def test_empty_host_without_adjacent_bundle_offers_download(self) -> None:
        launcher = self._launcher()
        launcher.connecting = True
        launcher.root = Mock()
        tunnel = SimpleNamespace(options=ConnectionOptions("server.example", "root"), alive=True)
        launcher.tunnel = tunnel
        launcher.events.put(("server_status", (tunnel, ServerStatus("missing"))))
        with patch("sovagrid_connect.gui.nearby_server_bundle", return_value=None), \
             patch("sovagrid_connect.gui.messagebox.askyesno", return_value=True) as confirm, \
             patch.object(Launcher, "_auto_install_and_connect") as start:
            launcher.pump()
        confirm.assert_called_once()
        self.assertIn("Скачать", confirm.call_args.args[1])
        start.assert_called_once_with(tunnel, None)
        launcher.root.after.assert_called_once_with(100, launcher.pump)

    def test_install_dialog_defaults_to_download_when_no_local_bundle(self) -> None:
        launcher = self._launcher()
        launcher.root = Mock()
        launcher.theme = Mock()
        launcher.connecting = False
        launcher.feature_window = launcher.update_window = launcher.install_window = None
        launcher._lift_management_window = Mock(return_value=False)
        launcher._options = lambda: ConnectionOptions("server.example", "root")
        for name in ("install_button", "feature_button", "update_button", "connect_button"):
            setattr(launcher, name, Mock())
        buttons = {}
        source_modes = []
        manager = Mock()

        class Variable:
            def __init__(self, value=None):
                self.value = value

            def get(self):
                return self.value

            def set(self, value):
                self.value = value

        def button(*args, **kwargs):
            if kwargs.get("text") == "Установить":
                buttons["begin"] = kwargs["command"]
            return Mock()

        def radio(*args, **kwargs):
            source_modes.append(kwargs["variable"])
            return Mock()

        @contextmanager
        def downloaded(*, progress):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory, "bundle.tar.gz")
                path.write_bytes(b"verified")
                progress("Пакет скачан")
                yield path

        with patch("sovagrid_connect.gui.nearby_server_bundle", return_value=None), \
             patch("sovagrid_connect.gui.tk.Toplevel", return_value=Mock()), \
             patch("sovagrid_connect.gui.tk.StringVar", Variable), \
             patch("sovagrid_connect.gui.tk.BooleanVar", Variable), \
             patch("sovagrid_connect.gui.tk.Text", return_value=Mock()), \
             patch("sovagrid_connect.gui.ttk.Frame", return_value=Mock()), \
             patch("sovagrid_connect.gui.ttk.Label", return_value=Mock()), \
             patch("sovagrid_connect.gui.ttk.Entry", return_value=Mock()), \
             patch("sovagrid_connect.gui.ttk.Checkbutton", return_value=Mock()), \
             patch("sovagrid_connect.gui.ttk.Radiobutton", side_effect=radio), \
             patch("sovagrid_connect.gui.ttk.Button", side_effect=button), \
             patch("sovagrid_connect.gui.messagebox.askyesno", return_value=True) as confirm, \
             patch("sovagrid_connect.gui.ServerInstaller", return_value=manager), \
             patch("sovagrid_connect.gui.downloaded_server_bundle", side_effect=downloaded), \
             patch("sovagrid_connect.gui.threading.Thread", side_effect=self._run_thread):
            launcher.open_install()
            self.assertEqual(source_modes[0].get(), "release")
            buttons["begin"]()
        self.assertIn("Скачать", confirm.call_args.args[1])
        manager.install.assert_called_once()
        self.assertEqual(manager.install.call_args.kwargs["expected_sha256"], PUBLISHED_SERVER_SOURCE_SHA256)
        self.assertEqual([launcher.events.get()[0] for _ in range(2)], ["install_progress", "install_done"])


if __name__ == "__main__":
    unittest.main()
