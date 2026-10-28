#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Disposable Ubuntu root/sudo status proof with a temporary test trust anchor."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.release_feed import ReleaseFeedController


SOURCE = Path("/opt/sovagrid-src")
UNIT = Path("/etc/systemd/system/sovagrid-release-feed.service")
POLICY = Path("/etc/sovagrid/auto-update.json")


def need(value: bool, reason: str) -> None:
    if not value:
        raise SystemExit("Connect release feed VM: " + reason)


class LocalTransport:
    def __init__(self, mode: str):
        self.options = ConnectionOptions("127.0.0.1", user="root" if mode == "root" else "runner").validated()
        self._privileged = "" if mode == "root" else "sudo -n -- "

    def _verify_root_access(self) -> None:
        code, raw = self._execute(self._privileged + "id -u", timeout=20)
        need(code == 0 and raw.strip() == b"0", "noninteractive root access unavailable")

    def _execute(self, command: str, *, timeout: float) -> tuple[int, bytes]:
        result = subprocess.run(["bash", "-c", command], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout)
        need(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
             "remote output was not bounded")
        return result.returncode, result.stdout + result.stderr


def root_run(mode: str, *args: str) -> None:
    prefix = [] if mode == "root" else ["sudo", "-n", "--"]
    subprocess.run(prefix + list(args), check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)


def root_hash(mode: str, path: Path) -> str:
    prefix = [] if mode == "root" else ["sudo", "-n", "--"]
    result = subprocess.run(prefix + ["/usr/bin/sha256sum", str(path)], check=True,
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    return result.stdout.split(maxsplit=1)[0].decode("ascii")


def main(args: list[str]) -> None:
    need(len(args) == 2 and args[0] in ("root", "sudo"), "usage: root|sudo fingerprint")
    mode, fingerprint = args
    need(os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
         os.environ.get("SOVAGRID_RELEASE_FEED_CLIENT_VM_FIXTURE") == "1" and
         Path("/proc/1/comm").read_text().strip() == "systemd" and
         (os.geteuid() == 0) == (mode == "root") and
         len(fingerprint) == 64, "not an approved disposable VM")
    manifest = hashlib.sha256((SOURCE / "sovagrid-bundle.json").read_bytes()).hexdigest()
    transport = LocalTransport(mode)
    controller = ReleaseFeedController(transport.options,
                                       approved_manifest_sha256=manifest,
                                       transport=transport)
    policy_before = root_hash(mode, POLICY)
    state = controller.preview()
    need(not state.enabled and not state.timer_active and state.units_verified and
         state.manual_candidate_active and state.available_keys == (("vm-fixture", fingerprint),),
         "read-only status lost the test trust anchor or separate policy")
    for path in (SOURCE / "sovagrid-blueprint/deploy/release_feed.py", UNIT):
        backup = Path(os.environ["RUNNER_TEMP"]) / (path.name + ".backup")
        root_run(mode, "/usr/bin/install", "-o", "root", "-g", "root", "-m", "0600",
                 str(path), str(backup))
        try:
            # Truncate without writing unknown content; restore from the root-only copy.
            root_run(mode, "/usr/bin/truncate", "-s", "1", str(path))
            try:
                controller.preview()
            except InstallError:
                pass
            else:
                raise SystemExit("Connect release feed VM: tampered source or unit was trusted")
        finally:
            root_run(mode, "/usr/bin/install", "-o", "root", "-g", "root", "-m", "0644",
                     str(backup), str(path))
            root_run(mode, "/usr/bin/rm", "-f", str(backup))
    need(controller.preview() == state, "source/unit restoration did not recover status")
    need(root_hash(mode, POLICY) == policy_before,
         "manual one-candidate permission changed")
    need(not Path("/etc/sovagrid/release-feed.json").exists(),
         "read-only review created a feed opt-in")
    print("Connect signed feed VM", mode, "read-only source, trust and rollback passed")


if __name__ == "__main__":
    main(sys.argv[1:])
