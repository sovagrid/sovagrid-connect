#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Run the exact Connect promotion programs on a disposable CI Ubuntu VM.

The root mode proves direct root commands. The sudo mode starts as the
unprivileged hosted runner and uses the same noninteractive sudo prefix as
PromotionController. This file refuses any non-CI or non-pristine target.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sovagrid_connect.core import _SSH_GRANT_COMMAND
from sovagrid_connect.promotion import _LOCKED_PREPARE, verify_promoted_panel
from sovagrid_connect.promotion_protocol import parse_promotion_state
from sovagrid_connect.promotion_remote import ACTION_SCRIPT, STAGE_SCRIPT
from sovagrid_connect.ssh_grant import parse_grant


PUBLISHED_BUNDLES = {
    "0.3.9": (
        "a812024d044f1b4746b8302ecae2e7d36f1af355586a763a4839a3c09a47c41a",
        "8a844437b56bea4d7122ae2c2012ec1bc2bdb4f72037fa6a2ea11b2201a887eb",
    ),
    "0.4.0": (
        "c38d4ea2818dd7e7317707088bc007fd90c8dca944dc41d3ff16b4617648fc62",
        "7e11c59b3a089179a2945db24f7fccd0adcf931ec9c727258d080a8d2315383e",
    ),
    "0.5.1": (
        "c18b067bdb5061f9307df7ed1794b0a3c8f661bb1f0700207e33e8438169c537",
        "30bb872c4977c6e80e2868a8a12c4211e5c25ef1a974d859e3c35fc40c61bbfc",
    ),
}
MARKERS = {
    "prepare": b"",
    "wrong-stage": b"SG_PROMOTION_REFUSE:STAGE",
    "stage": b"SG_PROMOTION_STAGE:DONE",
    "hub": b"SG_PROMOTION_HUB:DONE",
    "activate": b"SG_PROMOTION_AGENT:DONE",
    "panel": b"",
}


def need(value: bool, message: str) -> None:
    if not value:
        raise SystemExit("Connect promotion VM: " + message)


def main(args: list[str]) -> None:
    need(len(args) == 4, "usage: MODE ACTION SOURCE ARCHIVE")
    mode, action, source_arg, archive_arg = args
    need(mode in ("root", "sudo") and action in MARKERS, "invalid mode or action")
    need(os.environ.get("GITHUB_ACTIONS") == "true" and
         os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
         os.environ.get("SOVAGRID_PROMOTION_VM_FIXTURE") == "1" and
         Path("/proc/1/comm").read_text().strip() == "systemd", "not a disposable VM")
    version = os.environ.get("SOVAGRID_PROMOTION_VM_VERSION")
    need(version in PUBLISHED_BUNDLES, "unapproved bundle version")
    archive_sha, manifest_sha = PUBLISHED_BUNDLES[version]
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    source = Path(source_arg).resolve(strict=True)
    archive = Path(archive_arg).resolve(strict=True)
    need(source == runner_temp / "sovagrid-promotion-source" and
         archive == runner_temp / ("sovagrid-" + version + ".tar.gz"),
         "unapproved source path")
    need(hashlib.sha256(archive.read_bytes()).hexdigest() == archive_sha and
         hashlib.sha256((source / "sovagrid-bundle.json").read_bytes()).hexdigest() == manifest_sha,
         "published bundle changed")
    need((mode == "root") == (os.geteuid() == 0), "wrong runner identity")
    prefix = [] if mode == "root" else ["sudo", "-n", "--"]
    proof = subprocess.run(prefix + ["id", "-u"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=False, timeout=20)
    need(proof.returncode == 0 and proof.stdout.strip() == b"0", "root access unavailable")

    if action == "panel":
        helper = Path("/opt/sovagrid-src/sovagrid-blueprint/deploy/promote_agent_only.py")
        inspection = subprocess.run(prefix + ["python3", str(helper), "inspect"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, check=False, timeout=45)
        need(inspection.returncode == 0 and len(inspection.stdout) <= 4096,
             "installed helper cannot inspect the local Hub")
        state = parse_promotion_state(inspection.stdout)
        need(state.phase == "activated" and state.local_server_id is not None,
             "local Agent is not active")
        grant_result = subprocess.run(["sh", "-c", _SSH_GRANT_COMMAND],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, check=False, timeout=90)
        need(grant_result.returncode == 0 and len(grant_result.stdout) <= 512,
             "Hub SSH grant unavailable")
        grant = parse_grant(grant_result.stdout)
        tunnel = SimpleNamespace(alive=True, url="http://127.0.0.1:8766",
                                 request_ssh_grant=lambda: grant)
        verify_promoted_panel(tunnel, state.local_server_id)
        print("Connect promotion VM", mode, action, "passed")
        return

    if action == "prepare":
        command = prefix + ["bash", "-c", _LOCKED_PREPARE, "sovagrid", manifest_sha]
        input_path = source / "sovagrid-blueprint/deploy/promote_agent_only.py"
        timeout = 120
    elif action in ("stage", "wrong-stage"):
        digest = archive_sha if action == "stage" else "0" * 64
        command = prefix + ["python3", "-c", STAGE_SCRIPT, digest, manifest_sha]
        input_path = archive
        timeout = 900
    else:
        command = prefix + ["python3", "-c", ACTION_SCRIPT, action, manifest_sha]
        input_path = None
        timeout = 1800 if action == "hub" else 600
    with input_path.open("rb") if input_path else open(os.devnull, "rb") as stream:
        result = subprocess.run(command, stdin=stream, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False, timeout=timeout)
    expected = MARKERS[action]
    if action == "wrong-stage":
        need(result.returncode != 0 and result.stdout.strip() == expected,
             "changed archive was not refused")
    elif action == "prepare":
        need(result.returncode == 0, "root prepare failed")
    else:
        need(result.returncode == 0 and result.stdout.strip() == expected,
             "promotion action did not confirm success")
    print("Connect promotion VM", mode, action, "passed")


if __name__ == "__main__":
    main(sys.argv[1:])
