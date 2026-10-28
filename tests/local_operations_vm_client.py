#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exercise Connect's exact local Agent controller on a disposable Ubuntu VM.

Promotion and the published bundle are verified by promotion-vm.yml first.
This fixture uses the same root or sudo command prefix as the SSH transport,
with the remote command executed locally on the isolated hosted runner.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.local_operations import LocalOperationsController


MANIFEST = "30bb872c4977c6e80e2868a8a12c4211e5c25ef1a974d859e3c35fc40c61bbfc"
SOURCE = Path("/opt/sovagrid-src/sovagrid-bundle.json")
HELPER = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/local_operations.py")


def need(value: bool, reason: str) -> None:
    if not value:
        raise SystemExit("Connect local operations VM: " + reason)


class LocalTransport:
    def __init__(self, mode: str):
        self.options = ConnectionOptions("127.0.0.1", user=("root" if mode == "root" else "runner")).validated()
        self._privileged = "" if mode == "root" else "sudo -n -- "

    def _verify_root_access(self) -> None:
        code, raw = self._execute(self._privileged + "id -u", timeout=20)
        need(code == 0 and raw.strip() == b"0", "noninteractive root access unavailable")

    def _execute(self, command: str, *, timeout: float) -> tuple[int, bytes]:
        result = subprocess.run(["bash", "-c", command], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                check=False, timeout=timeout)
        need(len(result.stdout) <= 4096 and len(result.stderr) <= 4096,
             "remote command exceeded bounded output")
        return result.returncode, result.stdout if result.returncode == 0 else result.stderr


def main(args: list[str]) -> None:
    need(len(args) == 1 and args[0] in ("root", "sudo"), "usage: root|sudo")
    mode = args[0]
    need(os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
         os.environ.get("SOVAGRID_PROMOTION_VM_FIXTURE") == "1" and
         Path("/proc/1/comm").read_text().strip() == "systemd" and
         (os.geteuid() == 0) == (mode == "root"), "not an approved disposable VM")

    prefix = [] if mode == "root" else ["sudo", "-n", "--"]
    digest = subprocess.run(prefix + ["sha256sum", str(SOURCE)], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False, timeout=20)
    need(digest.returncode == 0 and digest.stdout.split(maxsplit=1)[0].decode() == MANIFEST,
         "installed source is not the exact published 0.5.1 manifest")
    inspect = subprocess.run(prefix + ["/usr/bin/python3", "-I", str(HELPER), "preview"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, check=False, timeout=90)
    need(inspect.returncode == 0 and len(inspect.stdout) <= 4096,
         "installed helper cannot preview the local Agent")
    server_preview = json.loads(inspect.stdout)
    need(server_preview.get("phase") == "ready" and
         server_preview.get("external_agent_preserved") is True and
         server_preview.get("current") == {"protocol": 1, "terminal": False, "files": False},
         "local Agent is not ready with features disabled")

    transport = LocalTransport(mode)
    controller = LocalOperationsController(
        transport.options, approved_manifest_sha256=MANIFEST, transport=transport,
    )
    initial = controller.preview()
    need(initial.state_revision == server_preview.get("state_revision") and
         initial.local_server_id == server_preview.get("local_server_id"),
         "Connect preview differs from the installed helper")

    terminal_on = controller.change("terminal", True, initial)
    need(terminal_on.terminal and not terminal_on.files, "terminal opt-in failed")
    files_on = controller.change("files", True, terminal_on)
    need(files_on.terminal and files_on.files, "files opt-in changed terminal")

    stale = subprocess.run(prefix + ["/usr/bin/python3", "-I", str(HELPER), "disable",
                                     "files", "--expected-state", initial.state_revision],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=False, timeout=90)
    need(stale.returncode == 40 and
         stale.stderr.strip() == b"SG_LOCAL_OPERATIONS_REFUSE:STATE_CHANGED" and
         not stale.stdout.strip(), "old CAS revision was not refused by the installed helper")
    try:
        controller.change("terminal", False, terminal_on)
    except InstallError as exc:
        need("повторите проверку" in str(exc), "stale Connect review gave wrong refusal")
    else:
        need(False, "Connect accepted stale feature review")

    terminal_off = controller.change("terminal", False, files_on)
    need(not terminal_off.terminal and terminal_off.files, "terminal opt-out changed files")
    restored = controller.change("files", False, terminal_off)
    need(not restored.terminal and not restored.files and
         restored.state_revision == initial.state_revision,
         "final local Agent feature state differs from initial revision")
    print("Connect local operations VM", mode, "passed with exact 0.5.1 source and CAS")


if __name__ == "__main__":
    main(sys.argv[1:])
