#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Run the exact reviewed GUI command opt-in on a disposable promoted VM."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.local_commands import LocalCommandsController
from sovagrid_connect.local_commands_remote import SCRIPT


MANIFEST = "30bb872c4977c6e80e2868a8a12c4211e5c25ef1a974d859e3c35fc40c61bbfc"
SOURCE = Path("/opt/sovagrid-src/sovagrid-bundle.json")


def need(value: bool, reason: str) -> None:
    if not value:
        raise SystemExit("Connect local commands VM: " + reason)


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
             "remote command exceeded bounded output")
        return result.returncode, result.stdout + result.stderr


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
         "installed source is not the published 0.5.1 package")

    transport = LocalTransport(mode)
    controller = LocalCommandsController(transport.options,
                                         approved_manifest_sha256=MANIFEST,
                                         transport=transport)
    initial = controller.preview()
    need(not initial.commands_enabled and initial.external_agent_preserved,
         "new promotion did not leave local commands disabled")
    enabled = controller.enable(initial)
    need(enabled.commands_enabled and enabled.local_server_id == initial.local_server_id and
         enabled.state_revision != initial.state_revision, "reviewed opt-in did not confirm success")

    stale = subprocess.run(prefix + ["/usr/bin/python3", "-I", "-c", SCRIPT,
                                     "enable", MANIFEST, initial.state_revision],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, check=False, timeout=120)
    need(stale.returncode == 40 and
         stale.stdout.strip() == b"SG_LOCAL_COMMANDS_REFUSE:STATE_CHANGED" and
         not stale.stderr.strip(), "old CAS revision was not refused under root lock")
    again = controller.preview()
    need(again == enabled, "stale refusal changed local command permission")
    print("Connect local commands VM", mode, "passed with published 0.5.1 source and CAS")


if __name__ == "__main__":
    main(sys.argv[1:])
