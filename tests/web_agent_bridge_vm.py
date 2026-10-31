#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ../ATTRIBUTION.md.
"""Exercise Connect's Web Agent update and rollback on one disposable Ubuntu VM."""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import urllib.request

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError, ServerInstaller, verify_bundle


OLD_MANIFESTS = frozenset({
    "f6d3b246d29661ffac4975f78dbc3a5481405b47e23826ea30a388e41f2b1280",
    "c57e46f652fcf8d3cf2ddd9e10957dedfe56e7709ccffabdd5081bb60a12e286",
})
NEW_MANIFEST = "ec6f567b0292916dd3f104f1441451708a955b79d02ef91f82237a8cf8603f1f"
SOURCE = Path("/opt/sovagrid-src")
WEB_AGENT = Path("/var/lib/sovagrid/web-agent")
MARKER = Path("/var/lib/sovagrid/.web-agent-installer-managed-by-run-sh")
SENTINEL = WEB_AGENT / ".bridge-vm-sentinel"
EXECUTED = Path("/run/sovagrid-ci-fixture-executed")
RUN_SH = "sovagrid-blueprint/run.sh"
FEED = SOURCE / "sovagrid-blueprint/deploy/release_feed.py"


def require(value: bool, message: str) -> None:
    if not value:
        raise AssertionError(message)


def output(*command: str) -> str:
    return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=45).strip()


def installed_manifest() -> str:
    return hashlib.sha256((SOURCE / "sovagrid-bundle.json").read_bytes()).hexdigest()


def health(expected_manifest: str) -> None:
    require(installed_manifest() == expected_manifest, "installed bundle manifest changed")
    require(MARKER.is_file() and not MARKER.is_symlink() and
            MARKER.read_bytes() == b"SOVAGRID_WEB_AGENT_INSTALL_V1\n", "Web Agent marker changed")
    marker_info = MARKER.stat()
    require((marker_info.st_uid, marker_info.st_gid, stat.S_IMODE(marker_info.st_mode)) ==
            (0, 0, 0o600), "Web Agent marker owner or mode changed")
    directory = WEB_AGENT.stat()
    require(WEB_AGENT.is_dir() and not WEB_AGENT.is_symlink() and
            (directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)) ==
            (0, 0, 0o700), "Web Agent journal directory changed")
    require(SENTINEL.read_bytes() == b"original\n", "Web Agent journal content not preserved")
    for unit in ("sovagrid-web-agent-control.socket", "sovagrid-web-agent-control.service",
                 "sovagrid-agent.service"):
        subprocess.run(("systemctl", "is-active", "--quiet", unit), check=True, timeout=15)
    endpoint = Path("/run/sovagrid-web-agent/control.sock")
    require(endpoint.exists() and not endpoint.is_symlink() and
            stat.S_ISSOCK(endpoint.stat().st_mode), "Web Agent socket missing")
    with urllib.request.urlopen("http://127.0.0.1:8766/healthz", timeout=15) as response:
        require(response.status == 200, "Web health failed")
    for service in ("hub", "web", "ssh-gateway"):
        ids = output("docker", "ps", "--filter", "label=com.docker.compose.project=sovagrid",
                     "--filter", "label=com.docker.compose.service=" + service, "--format", "{{.ID}}")
        require(bool(ids) and "\n" not in ids, "Compose service missing: " + service)


def failure_candidate(source: Path, destination: Path) -> str:
    """Change one reviewed candidate in runner scratch only to force late rollback."""
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(source, "r:gz") as archive:
        for member in archive:
            stream = archive.extractfile(member) if member.isfile() else None
            members.append((copy.copy(member), stream.read() if stream is not None else None))
    manifest_member = next(data for info, data in members if info.name == "sovagrid-bundle.json")
    require(manifest_member is not None, "candidate manifest missing")
    manifest = json.loads(manifest_member)
    script = next(data for info, data in members if info.name == RUN_SH)
    require(script is not None and script.count(b"set -euo pipefail\n") == 1,
            "candidate installer anchor changed")
    fixture = (b"printf 'yes\\n' > /run/sovagrid-ci-fixture-executed\n"
               b"printf 'changed\\n' > /var/lib/sovagrid/web-agent/.bridge-vm-sentinel\n"
               b"printf 'VM deliberate installer failure\\n' >&2\n"
               b"exit 73\n")
    changed_script = script.replace(b"set -euo pipefail\n", b"set -euo pipefail\n" + fixture, 1)
    manifest["sha256"][RUN_SH] = hashlib.sha256(changed_script).hexdigest()
    # The fixture is a distinct source revision with the same component set.
    manifest["components"]["sovagrid-blueprint"]["commit"] = "f" * 40
    changed_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    with destination.open("wb") as file:
        with gzip.GzipFile(fileobj=file, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for member, data in members:
                    if member.name == RUN_SH:
                        data = changed_script
                    elif member.name == "sovagrid-bundle.json":
                        data = changed_manifest
                    if data is not None:
                        member.size = len(data)
                        archive.addfile(member, io.BytesIO(data))
                    else:
                        archive.addfile(member)
    verify_bundle(destination)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def update(installer: ServerInstaller, archive: Path, expected_archive_sha: str,
           current_manifest: str, *, failure: bool) -> None:
    preview = installer.preview_update(archive, expected_sha256=expected_archive_sha)
    require(preview.current_manifest_sha256 == current_manifest, "Connect preview old manifest mismatch")
    prepared = installer.prepare_update(archive, expected_sha256=expected_archive_sha)
    require(prepared.sha256 == expected_archive_sha, "Connect staged a different archive")
    if failure:
        try:
            installer.apply_update(prepared, expected_current_manifest=current_manifest)
        except InstallError as error:
            require("Предыдущая версия восстановлена" in str(error), "rollback was not confirmed")
        else:
            raise AssertionError("deliberate installer failure unexpectedly applied")
        require(EXECUTED.read_bytes() == b"yes\n", "fixture did not reach candidate run.sh")
    else:
        installer.apply_update(prepared, expected_current_manifest=current_manifest)


def signed_feed_ready() -> None:
    status = json.loads(output(sys.executable, "-B", "-I", str(FEED), "status"))
    require(status["installed_manifest_sha256"] == NEW_MANIFEST and not status["enabled"] and
            not status["manual_candidate_active"],
            "feed status does not show new disabled source")
    revision = status["state_revision"]
    require(re.fullmatch(r"[0-9a-f]{64}", revision) is not None, "feed revision invalid")
    output(sys.executable, "-B", "-I", str(FEED), "enable", "--expected-state", revision)
    result = output(sys.executable, "-B", "-I", str(FEED), "poll")
    require("SG_RELEASE_FEED:CURRENT" in result, "signed feed not current after migration")
    latest = json.loads(output(sys.executable, "-B", "-I", str(FEED), "status"))
    require(latest["enabled"] and latest["installed_manifest_sha256"] == NEW_MANIFEST,
            "signed feed subscription missing")
    output(sys.executable, "-B", "-I", str(FEED), "disable", "--expected-state",
           latest["state_revision"])


def main() -> None:
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
            os.environ.get("SOVAGRID_BRIDGE_VM_FIXTURE") == "1" and
            os.geteuid() == 0 and sys.platform == "linux", "disposable root VM required")
    require(len(sys.argv) == 5,
            "usage: web_agent_bridge_vm.py TARGET_ARCHIVE TARGET_SHA SCRATCH OLD_MANIFEST")
    target, target_sha, scratch, old_manifest = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4])
    require(re.fullmatch(r"[0-9a-f]{64}", target_sha) is not None and scratch.is_dir() and
            old_manifest in OLD_MANIFESTS, "invalid target pin, scratch or old manifest")
    require(hashlib.sha256(target.read_bytes()).hexdigest() == target_sha,
            "target archive differs from release pin")
    with tarfile.open(target, "r:gz") as archive:
        manifest_file = archive.extractfile("sovagrid-bundle.json")
        require(manifest_file is not None and
                hashlib.sha256(manifest_file.read()).hexdigest() == NEW_MANIFEST,
                "target manifest differs from release pin")
    require(installed_manifest() == old_manifest, "wrong initial server source")
    require(MARKER.is_file() and WEB_AGENT.is_dir(), "default install lacks managed Web Agent")
    SENTINEL.write_bytes(b"original\n")
    SENTINEL.chmod(0o600)
    health(old_manifest)

    options = ConnectionOptions(host="127.0.0.1", user="root", port=22022,
                                identity="/run/sovagrid-ci-client")
    installer = ServerInstaller(options)
    bad = scratch / "deliberate-failure.tar.gz"
    bad_sha = failure_candidate(target, bad)
    update(installer, bad, bad_sha, old_manifest, failure=True)
    health(old_manifest)
    print("VM bridge rollback restored prior server and managed Web Agent", flush=True)

    update(installer, target, target_sha, old_manifest, failure=False)
    health(NEW_MANIFEST)
    print("VM bridge applied v0.14.1 and preserved managed Web Agent", flush=True)
    signed_feed_ready()
    print("VM signed feed enable/current/disable passed", flush=True)


if __name__ == "__main__":
    main()
