# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Exact SSH command, source and compare-and-swap gates for service setup."""

import json
import unittest

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.service_setup import ServiceSetupController, policy_bytes
from sovagrid_connect.service_setup_remote import SCRIPT


MANIFEST = "a" * 64
REVISION = "b" * 64
NEXT = "c" * 64
POLICY = {"ssh.service": {"status", "restart"}}


def state(profile="default", *, armed=False, revision=REVISION, plan=False):
    policy = {"ssh.service": ["restart", "status"]} if armed else None
    profiles = {
        "default": {"armed": armed if profile == "default" else False,
                    "policy_status": "present" if armed and profile == "default" else "absent",
                    "policy": policy if profile == "default" else None,
                    "socket": ["enabled", "active"] if armed and profile == "default"
                    else ["disabled", "inactive"]},
        "local": {"armed": armed if profile == "local" else False,
                  "policy_status": "present" if armed and profile == "local" else "absent",
                  "policy": policy if profile == "local" else None,
                  "socket": ["enabled", "active"] if armed and profile == "local"
                  else ["disabled", "inactive"]},
    }
    result = {"ok": True, "state_revision": revision,
              "armed": profiles[profile]["armed"],
              "sockets": {name: record["socket"] for name, record in profiles.items()},
              "profiles": profiles, "policy_status": profiles[profile]["policy_status"],
              "policy": profiles[profile]["policy"]}
    if plan:
        result["plan"] = {"profile": profile, "install_units": ["sovagrid-service-control.socket"],
                          "change_policy": True, "enable_socket": True,
                          "configure_local_agent": profile == "local"}
    return json.dumps(result).encode()


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("ubuntu.example.org", user=user).validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.calls = []
        self.root_proofs = 0
        self.revision = REVISION
        self.armed = False
        self.mutate = None
        self.source_valid = True
        self.catalog_limit = None

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, data=None, timeout, limit=4096):
        self.calls.append((command, data, timeout))
        if " -I -c " in command:
            if not self.source_valid:
                return 40, b"SG_SERVICE_SOURCE_REFUSE:UNVERIFIED\n"
            profile = command.rsplit(" ", 1)[-1]
            return 0, json.dumps({"protocol": 1, "manifest_sha256": MANIFEST,
                                  "profile": profile}).encode()
        if "list-unit-files" in command:
            self.catalog_limit = limit
            return 0, b"ssh.service enabled\nnginx.service disabled\nfoo@.service disabled\n"
        profile = "local" if "--profile local" in command else "default"
        if " preview" in command:
            planned = data is not None
            if self.mutate:
                self.revision = self.mutate
            return 0, state(profile if planned else "default", armed=self.armed,
                            revision=self.revision, plan=planned)
        if " arm" in command:
            self.armed = True
            self.revision = NEXT
            return 0, state(profile, armed=True, revision=NEXT)
        if " disarm" in command:
            self.armed = False
            self.revision = NEXT
            return 0, state(profile, armed=False, revision=NEXT)
        raise AssertionError(command)


class ServiceSetupTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return ServiceSetupController(transport.options, transport=transport,
                                      approved_manifest_sha256=approved)

    def test_unapproved_release_never_contacts_host(self):
        transport = Transport()
        with self.assertRaises(InstallError):
            self.controller(transport, None).inspect("default")
        self.assertEqual(transport.root_proofs, 0)
        self.assertEqual(transport.calls, [])

    def test_exact_source_and_sudo_command_with_policy_stdin(self):
        transport = Transport("admin")
        controller = self.controller(transport)
        inspected = controller.inspect("default")
        self.assertFalse(inspected.armed)
        reviewed = controller.plan("default", POLICY)
        self.assertEqual(reviewed.plan[1:], (True, True, False))
        result = controller.arm(reviewed, POLICY)
        self.assertTrue(result.armed)
        commands = [entry for entry in transport.calls if "-m sovagrid_agent.service_setup" in entry[0]]
        self.assertTrue(all("cd /opt/sovagrid-agent && sudo -n -- /usr/bin/python3 -B -E -S"
                            in command for command, _data, _timeout in commands))
        writes = [(command, data) for command, data, _timeout in commands if " arm " in command]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], policy_bytes(POLICY))
        self.assertIn("--expected-state " + REVISION, writes[0][0])
        self.assertNotIn("ssh.service", writes[0][0])

    def test_stale_plan_cannot_write_and_profile_is_bound(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.plan("local", POLICY)
        local_commands = [command for command, _data, _timeout in transport.calls
                          if "-m sovagrid_agent.service_setup" in command]
        self.assertTrue(local_commands)
        self.assertTrue(all(command.startswith("cd /opt/sovagrid-agent-local && ")
                            for command in local_commands))
        transport.mutate = NEXT
        with self.assertRaisesRegex(InstallError, "изменились"):
            controller.arm(reviewed, POLICY)
        self.assertFalse(any(" arm " in command for command, _data, _timeout in transport.calls))
        transport.mutate = None
        with self.assertRaises(InstallError):
            controller.arm(reviewed, {"nginx.service": {"start"}})
        self.assertFalse(any(" arm " in command for command, _data, _timeout in transport.calls))

    def test_disarm_rechecks_cas_and_rejects_wrong_source(self):
        transport = Transport()
        controller = self.controller(transport)
        reviewed = controller.plan("default", POLICY)
        enabled = controller.arm(reviewed, POLICY)
        transport.source_valid = False
        with self.assertRaisesRegex(InstallError, "не совпадает"):
            controller.disarm(enabled)
        self.assertFalse(any(" disarm " in command for command, _data, _timeout in transport.calls))

    def test_policy_rejects_shell_and_empty_list_without_ssh(self):
        for value in ({}, {"nginx.service; reboot": {"restart"}},
                      {"ssh.service": set()}, {"ssh.service": {"exec"}},
                      {"ssh.service": {"restart"}}):
            with self.subTest(value=value), self.assertRaises(InstallError):
                policy_bytes(value)
        transport = Transport()
        controller = self.controller(transport)
        with self.assertRaises(InstallError):
            controller.plan("default", {"ssh.service; reboot": {"restart"}})
        self.assertEqual(transport.calls, [])

    def test_catalog_is_bounded_and_excludes_templates(self):
        transport = Transport()
        self.assertEqual(self.controller(transport).catalog("default"),
                         ("nginx.service", "ssh.service"))
        self.assertEqual(transport.catalog_limit, 98304)

    def test_probe_compiles_and_contains_only_read_operations(self):
        compile(SCRIPT, "<service-source-probe>", "exec")
        self.assertIn("hashlib.sha256(source).hexdigest() == digest", SCRIPT)
        self.assertIn("module == source", SCRIPT)
        self.assertNotIn("subprocess", SCRIPT)


if __name__ == "__main__":
    unittest.main()
