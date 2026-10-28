# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""VPN setup uses exact root source, reviewed targets and server CAS."""

import json
import shlex
import subprocess
import unittest
from types import SimpleNamespace

from sovagrid_connect.core import ConnectionOptions
from sovagrid_connect.installer import InstallError
from sovagrid_connect.vpn_setup import VpnSetupController, awg_settings_patch
from sovagrid_connect.vpn_setup_remote import SCRIPT
from sovagrid_connect.nftables_dependency_remote import SCRIPT as NFT_SCRIPT


MANIFEST = "a" * 64
CONTAINER = "b" * 64
REVISION = "c" * 64
NEXT = "d" * 64
IMAGE = "sha256:" + "e" * 64


def routing(*, armed=False, configured=False, revision=REVISION):
    return json.dumps({"name": "phone-vpn", "armed": armed,
                       "routing_configured": configured, "recovery_required": False,
                       "forwarding": configured, "nat": configured,
                       "upstream_firewall_unverified": True,
                       "state_revision": revision}).encode()


def amnezia(*, target="awg2", marker="absent", installed=True, ready=True,
            other="absent", clients=2):
    return json.dumps({"schema_version": 1, "action": "preview", "writes": False,
                       "selected_target": target, "marker": marker,
                       "other_marker": other, "socket_active": marker == "valid" or other == "valid",
                       "service_active": False, "installer_ready": True,
                       "installed_current": installed,
                       "can_arm": marker == "absent" and installed and ready,
                       "target": {"ready": True, "container_id": CONTAINER,
                                  "configured_clients": clients, "owned_clients": []} if ready else
                       {"ready": False, "reason": "not enrolled"}}).encode()


def amnezia_settings(*, target="awg2", clients=2):
    awg = target == "awg2"
    parameters = {name: "10" for name in ("Jc", "Jmin", "Jmax")}
    parameters.update({name: "16" for name in ("S1", "S2", "S3", "S4")})
    parameters.update({name: "1-2" for name in ("H1", "H2", "H3", "H4")})
    return {"target": target, "container_id": CONTAINER, "image_id": IMAGE,
            "config_sha256": REVISION, "table_sha256": NEXT, "generation": 3,
            "protocol": "amneziawg" if awg else "wireguard",
            "interface": "awg0" if awg else "wg0", "listen_port": 49289,
            "server_address": "10.44.0.1", "server_subnet": "10.44.0.0/24",
            "configured_clients": clients, "managed_clients": 0, "external_clients": clients,
            "awg_parameters": parameters if awg else {},
            "awg_parameters_runtime_verified": False,
            "header_protection_key_present": awg,
            "awg3_required_parameters_present": awg,
            "apply_supported": False,
            "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE",
                               "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION"]}


def amnezia_plan(patch, *, clients=2):
    current = amnezia_settings()["awg_parameters"]
    proposed = {**current, **patch}
    return {"target": "awg2", "container_id": CONTAINER, "image_id": IMAGE,
            "generation": 3, "config_sha256": REVISION, "table_sha256": NEXT,
            "proposed_config_sha256": "f" * 64,
            "current_awg_parameters": current, "proposed_awg_parameters": proposed,
            "changed_fields": sorted(patch), "configured_clients": clients,
            "apply_supported": clients == 0,
            "apply_blockers": ["CLIENT_PROFILES_REQUIRE_REISSUE"] if clients else []}


class Transport:
    def __init__(self, user="root"):
        self.options = ConnectionOptions("server.example.org", user=user).validated()
        self._privileged = "" if user == "root" else "sudo -n -- "
        self.root_proofs = 0
        self.calls = []
        self.source_valid = True
        self.nft = True
        self.route_revision = REVISION
        self.route_armed = False
        self.amnezia_installed = True
        self.amnezia_marker = {"awg2": "absent", "wireguard": "absent"}
        self.amnezia_clients = 2
        self.settings_marker = "absent"
        self.settings_runtime_verified = True
        self.settings_lost_reply = False
        self.settings_access_override = None
        self.nft_revision = REVISION

    def _verify_root_access(self):
        self.root_proofs += 1

    def _execute(self, command, *, timeout):
        self.calls.append(command)
        if "DPkg::Lock::Timeout=30" in command:
            install = " install " in command
            if install:
                self.nft = True
                self.nft_revision = NEXT
            return 0, json.dumps({
                "ok": True, "protocol": 1, "state_revision": self.nft_revision,
                "ubuntu_version": "24.04", "package": "installed" if self.nft else "absent",
                "nft_version": "nftables v1.0.9 (Old Doc Yak #3)" if self.nft else None,
                "service_enabled": "disabled" if self.nft else "not-found",
                "service_active": "inactive",
            }).encode()
        if " -I -c " in command:
            if not self.source_valid:
                return 40, b"SG_VPN_SOURCE_REFUSE:UNVERIFIED\n"
            return 0, json.dumps({"protocol": 1, "manifest_sha256": MANIFEST,
                                  "feature": command.rsplit(" ", 1)[-1]}).encode()
        if "command -v nft" in command:
            return (0 if self.nft else 1), b""
        if "sovagrid_vpn.manage instances" in command:
            return 0, b'[{"name":"phone-vpn"}]'
        if "sovagrid_vpn.routing preview " in command:
            return 0, routing(armed=self.route_armed, configured=self.route_armed,
                              revision=self.route_revision)
        if "sovagrid_vpn.routing arm " in command:
            self.route_armed = True
            self.route_revision = NEXT
            return 0, routing(armed=True, configured=True, revision=NEXT)
        if "sovagrid_vpn.routing disarm " in command:
            self.route_armed = False
            self.route_revision = NEXT
            return 0, routing(armed=False, configured=False, revision=NEXT)
        if "sovagrid_vpn.amnezia_install preview " in command:
            target = command.rsplit(" ", 1)[-1]
            other = "awg2" if target == "wireguard" else "wireguard"
            return 0, amnezia(target=target, marker=self.amnezia_marker[target],
                              other=self.amnezia_marker[other], installed=self.amnezia_installed,
                              clients=self.amnezia_clients)
        if "sovagrid_vpn.amnezia_install preview-settings" in command:
            reason = ("ALREADY_ARMED" if self.settings_marker == "valid" else
                      "CLIENTS_PRESENT" if self.amnezia_clients else
                      "POLICY_NOT_READY" if self.amnezia_marker["awg2"] != "valid" else
                      "RUNTIME_UNVERIFIED" if not self.settings_runtime_verified else None)
            value = {
                "schema_version": 1, "action": "preview-settings", "selected_target": "awg2",
                "settings_marker": self.settings_marker, "peer_marker": self.amnezia_marker["awg2"],
                "socket_active": self.amnezia_marker["awg2"] == "valid",
                "target_ready": True, "container_id": CONTAINER,
                "configured_clients": self.amnezia_clients,
                "awg3_runtime_verified": self.settings_runtime_verified,
                "can_arm": reason is None, "reason": reason,
            }
            return 0, json.dumps(self.settings_access_override or value).encode()
        if "sovagrid_vpn.amnezia_install arm-settings " in command:
            if ("--confirm-container-id " + CONTAINER not in command or
                    "--confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG3_SETTINGS" not in command or
                    self.amnezia_marker["awg2"] != "valid" or self.amnezia_clients):
                return 40, b""
            self.settings_marker = "valid"
            if self.settings_lost_reply:
                raise subprocess.TimeoutExpired(command, timeout)
            return 0, json.dumps({"action": "settings_armed", "settings_marker": "valid",
                                  "selected_target": "awg2", "container_id": CONTAINER}).encode()
        if "sovagrid_vpn.amnezia_install disarm-settings" in command:
            self.settings_marker = "absent"
            if self.settings_lost_reply:
                raise subprocess.TimeoutExpired(command, timeout)
            return 0, json.dumps({"action": "settings_disarmed", "settings_marker": "absent",
                                  "selected_target": "awg2"}).encode()
        if "sovagrid_vpn.amnezia_install install" in command:
            self.amnezia_installed = True
            return 0, json.dumps({"action": "installed", "socket_active": False,
                                  "marker": "absent", "target_changed": False}).encode()
        if "sovagrid_vpn.amnezia_install arm " in command:
            target = "wireguard" if "--target wireguard" in command else "awg2"
            self.amnezia_marker[target] = "valid"
            return 0, json.dumps({"action": "armed", "socket_active": True,
                                  "marker": "valid", "selected_target": target,
                                  "target_changed": False}).encode()
        if "sovagrid_vpn.amnezia_install disarm " in command:
            target = command.rsplit(" ", 1)[-1]
            self.amnezia_marker[target] = "absent"
            if target == "awg2":
                self.settings_marker = "absent"
            return 0, json.dumps({"action": "disarmed", "marker": "absent",
                                  "selected_target": target,
                                  "service_may_remain_running": True}).encode()
        raise AssertionError(command)


class EnrollmentTransport(Transport):
    def __init__(self, user="root"):
        super().__init__(user)
        self.enrolled = False
        self.table_sha = REVISION
        self.lost_reply = False
        self.preview_override = None
        self.settings_override = None
        self.plan_override = None

    def _execute(self, command, *, timeout):
        if "sovagrid_vpn.amnezia_admin " in command:
            self.calls.append(command)
            if " settings-preview " in command:
                target = command.rsplit(" ", 1)[-1]
                return 0, json.dumps(self.settings_override or amnezia_settings(
                    target=target, clients=self.amnezia_clients)).encode()
            if " settings-plan " in command:
                parts = shlex.split(command)
                index = parts.index("settings-plan")
                if parts[index + 1:index + 4] != ["awg2", REVISION, "3"]:
                    return 2, b""
                patch = json.loads(parts[index + 4])
                return 0, json.dumps(self.plan_override or amnezia_plan(
                    patch, clients=self.amnezia_clients)).encode()
            if " enroll-preview " in command:
                if self.enrolled:
                    return 2, b""
                value = {"target": "awg2", "container_id": CONTAINER,
                                      "image_id": IMAGE, "config_sha256": REVISION,
                                      "table_sha256": self.table_sha, "configured_clients": 2,
                                      "protocol": "amneziawg", "interface": "awg0",
                                      "listen_port": 49289,
                                      "server_subnet": "10.44.0.0/24"}
                return 0, json.dumps(self.preview_override or value).encode()
            if " enroll " in command:
                if ("--confirm-container-id " + CONTAINER not in command or
                        "--confirm-image-id " + IMAGE not in command or
                        "--confirm-config-sha256 " + REVISION not in command or
                        "--confirm-table-sha256 " + self.table_sha not in command):
                    return 2, b""
                self.enrolled = True
                if self.lost_reply:
                    raise subprocess.TimeoutExpired(command, timeout)
                return 0, b'{"target":"awg2","enrolled":true,"configured_clients":2}'
        if "sovagrid_vpn.amnezia_install preview " in command:
            self.calls.append(command)
            target = command.rsplit(" ", 1)[-1]
            other = "awg2" if target == "wireguard" else "wireguard"
            return 0, amnezia(target=target, ready=self.enrolled,
                              marker=self.amnezia_marker[target],
                              other=self.amnezia_marker[other], installed=self.amnezia_installed,
                              clients=self.amnezia_clients)
        return super()._execute(command, timeout=timeout)


class VpnSetupTests(unittest.TestCase):
    def controller(self, transport, approved=MANIFEST):
        return VpnSetupController(transport.options, transport=transport,
                                  approved_manifest_sha256=approved)

    def test_no_pin_never_contacts_server(self):
        t = Transport()
        with self.assertRaises(InstallError):
            self.controller(t, None).instances()
        self.assertEqual(t.calls, [])
        self.assertEqual(t.root_proofs, 0)

    def test_routing_exact_revision_and_dependency_hint(self):
        t = Transport("admin")
        c = self.controller(t)
        self.assertEqual(c.instances(), ("phone-vpn",))
        t.nft = False
        with self.assertRaisesRegex(InstallError, "nftables"):
            c.routing_preview("phone-vpn")
        t.nft = True
        preview = c.routing_preview("phone-vpn")
        armed = c.routing_arm(preview)
        self.assertTrue(armed.configured)
        command = next(command for command in t.calls if "sovagrid_vpn.routing arm " in command)
        self.assertIn("cd /opt/sovagrid-vpn && sudo -n -- /usr/bin/python3 -B -E -S", command)
        self.assertIn("--expected-state " + REVISION, command)
        after = c.routing_disarm(armed)
        self.assertFalse(after.armed)

    def test_stale_routing_preview_refuses_mutation(self):
        t = Transport()
        c = self.controller(t)
        preview = c.routing_preview("phone-vpn")
        t.route_revision = NEXT
        with self.assertRaisesRegex(InstallError, "изменился"):
            c.routing_arm(preview)
        self.assertFalse(any("sovagrid_vpn.routing arm " in item for item in t.calls))
        with self.assertRaises(InstallError):
            c.routing_preview("phone-vpn;reboot")

    def test_explicit_nftables_install_checks_revision_and_service_state(self):
        t = Transport("admin")
        t.nft = False
        c = self.controller(t)
        before = c.nftables_status()
        self.assertIsNone(before.nft_version)
        after = c.nftables_install(before)
        self.assertEqual(after.package, "installed")
        self.assertEqual(after.service_enabled, "disabled")
        self.assertEqual(after.service_active, "inactive")
        self.assertIn("Old Doc Yak", after.nft_version)
        self.assertEqual(sum(" install " in item and "DPkg::Lock::Timeout=30" in item
                             for item in t.calls), 1)
        self.assertTrue(any("sudo -n -- /usr/bin/python3 -I -c " in item
                            for item in t.calls))

    def test_stale_dependency_status_does_not_run_apt(self):
        t = Transport()
        t.nft = False
        c = self.controller(t)
        before = c.nftables_status()
        t.nft_revision = NEXT
        with self.assertRaisesRegex(InstallError, "изменилось"):
            c.nftables_install(before)
        self.assertFalse(any(" install " in item and "DPkg::Lock::Timeout=30" in item
                             for item in t.calls))

    def test_amnezia_install_arm_disarm_are_target_bound(self):
        t = Transport()
        t.amnezia_installed = False
        c = self.controller(t)
        initial = c.amnezia_preview("wireguard")
        self.assertFalse(initial.installed_current)
        installed = c.amnezia_install(initial)
        self.assertTrue(installed.installed_current)
        armed = c.amnezia_arm(installed)
        self.assertEqual(armed.marker, "valid")
        command = next(command for command in t.calls if "amnezia_install arm " in command)
        self.assertIn("--target wireguard", command)
        self.assertIn("--confirm-container-id " + CONTAINER, command)
        self.assertIn("I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD", command)
        stopped = c.amnezia_disarm(armed)
        self.assertEqual(stopped.marker, "absent")
        self.assertEqual(t.amnezia_marker["awg2"], "absent")

    def test_source_change_and_target_change_refuse_write(self):
        t = Transport()
        c = self.controller(t)
        reviewed = c.amnezia_preview("awg2")
        t.source_valid = False
        with self.assertRaisesRegex(InstallError, "не совпадает"):
            c.amnezia_arm(reviewed)
        self.assertFalse(any("amnezia_install arm " in item for item in t.calls))
        t.source_valid = True
        t.amnezia_marker["awg2"] = "valid"
        with self.assertRaisesRegex(InstallError, "изменились"):
            c.amnezia_arm(reviewed)

    def test_amnezia_enroll_preview_and_pinned_consent(self):
        t = EnrollmentTransport("admin")
        c = self.controller(t)
        preview = c.amnezia_enroll_preview("awg2")
        self.assertEqual(preview.container_id, CONTAINER)
        self.assertEqual(preview.server_subnet, "10.44.0.0/24")
        state = c.amnezia_enroll(preview)
        self.assertTrue(state.target_ready)
        self.assertEqual(state.container_id, CONTAINER)
        self.assertEqual(t.amnezia_marker["awg2"], "absent")
        command = next(item for item in t.calls if "sovagrid_vpn.amnezia_admin enroll awg2" in item)
        for pin in (CONTAINER, IMAGE, REVISION):
            self.assertIn(pin, command)
        self.assertTrue(command.startswith("cd /opt/sovagrid-vpn && sudo -n -- "))

    def test_amnezia_enroll_rejects_stale_preview_without_mutation(self):
        t = EnrollmentTransport()
        c = self.controller(t)
        preview = c.amnezia_enroll_preview("awg2")
        t.table_sha = NEXT
        with self.assertRaisesRegex(InstallError, "изменился"):
            c.amnezia_enroll(preview)
        self.assertFalse(t.enrolled)
        self.assertFalse(any("sovagrid_vpn.amnezia_admin enroll awg2" in item for item in t.calls))

    def test_amnezia_enroll_lost_reply_reads_state_without_retry(self):
        t = EnrollmentTransport()
        c = self.controller(t)
        preview = c.amnezia_enroll_preview("awg2")
        t.lost_reply = True
        state = c.amnezia_enroll(preview)
        self.assertTrue(state.target_ready)
        self.assertEqual(sum("sovagrid_vpn.amnezia_admin enroll awg2" in item for item in t.calls), 1)

    def test_amnezia_enroll_preview_rejects_wrong_shape(self):
        t = EnrollmentTransport()
        c = self.controller(t)
        base = {"target": "awg2", "container_id": CONTAINER, "image_id": IMAGE,
                "config_sha256": REVISION, "table_sha256": REVISION,
                "configured_clients": 2, "protocol": "amneziawg", "interface": "awg0",
                "listen_port": 49289, "server_subnet": "10.44.0.0/24"}
        for invalid in ({"listen_port": True}, {"server_subnet": "10.44.0.1/24"},
                        {"configured_clients": True}, {"image_id": "../wrong"}):
            t.preview_override = {**base, **invalid}
            with self.assertRaises(InstallError):
                c.amnezia_enroll_preview("awg2")
        self.assertFalse(any("sovagrid_vpn.amnezia_admin enroll awg2" in item for item in t.calls))

    def test_amnezia_settings_preview_is_read_only_and_target_bound(self):
        t = EnrollmentTransport("admin")
        t.enrolled = True
        c = self.controller(t)
        for target in ("awg2", "wireguard"):
            with self.subTest(target=target):
                state = c.amnezia_preview(target)
                preview = c.amnezia_settings_preview(state)
                self.assertEqual(preview.target, target)
                self.assertEqual(preview.container_id, CONTAINER)
                self.assertEqual(preview.configured_clients, 2)
                self.assertEqual(preview.managed_clients, 0)
                self.assertEqual(preview.external_clients, 2)
                self.assertEqual(bool(preview.awg_parameters), target == "awg2")
                command = next(command for command in t.calls if
                               "sovagrid_vpn.amnezia_admin settings-preview " + target in command)
                self.assertIn("sudo -n -- ", command)
                self.assertNotIn("PrivateKey", command)
        self.assertFalse(any(" amnezia_admin enroll " in command or
                             " amnezia_install arm " in command for command in t.calls))

    def test_amnezia_settings_preview_rejects_unverified_or_secret_response(self):
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        valid = amnezia_settings()
        variants = (
            {**valid, "server_private_key": "secret"},
            {**valid, "container_id": "0" * 64},
            {**valid, "configured_clients": 3},
            {**valid, "awg_parameters_runtime_verified": True},
            {**valid, "apply_supported": True},
            {**valid, "awg_parameters": {**valid["awg_parameters"], "Jc": "999999"}},
            {**valid, "server_subnet": "10.45.0.0/24"},
        )
        for variant in variants:
            with self.subTest(variant=next(key for key in variant if variant[key] != valid.get(key))):
                t.settings_override = variant
                with self.assertRaises(InstallError):
                    c.amnezia_settings_preview(state)
        t.settings_override = valid
        self.assertEqual(c.amnezia_settings_preview(state).listen_port, 49289)

    def test_amnezia_settings_preview_needs_current_review_and_bundle_pin(self):
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        reviewed = c.amnezia_preview("awg2")
        t.amnezia_marker["awg2"] = "valid"
        with self.assertRaisesRegex(InstallError, "изменились"):
            c.amnezia_settings_preview(reviewed)
        self.assertFalse(any(" settings-preview " in command for command in t.calls))
        unpinned = self.controller(EnrollmentTransport(), None)
        with self.assertRaises(InstallError):
            unpinned.amnezia_settings_preview(reviewed)

    def test_amnezia_awg3_plan_is_cas_pinned_and_read_only(self):
        t = EnrollmentTransport("admin")
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        proposal = dict(preview.awg_parameters)
        proposal["Jc"] = "12"
        proposal["H1"] = "3-5"
        plan = c.amnezia_settings_plan(state, preview, proposal)
        self.assertEqual(plan.changed_fields, ("H1", "Jc"))
        self.assertEqual(plan.proposed_config_sha256, "f" * 64)
        self.assertFalse(plan.apply_supported)
        self.assertEqual(plan.apply_blockers, ("CLIENT_PROFILES_REQUIRE_REISSUE",))
        commands = [item for item in t.calls if "sovagrid_vpn.amnezia_admin settings-plan " in item]
        self.assertEqual(len(commands), 1)
        parts = shlex.split(commands[0])
        index = parts.index("settings-plan")
        self.assertEqual(parts[index + 1:index + 4], ["awg2", REVISION, "3"])
        self.assertEqual(json.loads(parts[index + 4]), {"H1": "3-5", "Jc": "12"})
        self.assertIn("sudo -n -- /usr/bin/python3", commands[0])
        self.assertFalse(any(" settings-apply " in item for item in t.calls))
        for secret in ("PrivateKey", "PresharedKey", "HeaderProtectionKey"):
            self.assertNotIn(secret, commands[0])

    def test_amnezia_awg3_plan_validates_all_public_inputs_before_ssh(self):
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        valid = dict(preview.awg_parameters)
        variants = (
            valid,
            {**valid, "Jc": "65536"},
            {**valid, "Jc": "01"},
            {**valid, "Jc": "1-2"},
            {**valid, "Jmin": "11"},
            {**valid, "S1": "11"},
            {**valid, "H1": "5-3"},
            {**valid, "H1": "4294967296"},
            {**valid, "unknown": "1"},
        )
        for proposal in variants:
            with self.subTest(proposal=proposal):
                with self.assertRaises(InstallError):
                    c.amnezia_settings_plan(state, preview, proposal)
        self.assertFalse(any(" settings-plan " in item for item in t.calls))
        wg = c.amnezia_settings_preview(c.amnezia_preview("wireguard"))
        with self.assertRaises(InstallError):
            awg_settings_patch(wg, valid)

    def test_amnezia_awg3_plan_rejects_stale_preview_and_untrusted_response(self):
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        proposal = {**dict(preview.awg_parameters), "Jc": "12"}
        t.settings_override = {**amnezia_settings(), "config_sha256": "0" * 64}
        with self.assertRaisesRegex(InstallError, "изменились"):
            c.amnezia_settings_plan(state, preview, proposal)
        self.assertFalse(any(" settings-plan " in item for item in t.calls))
        t.settings_override = None
        valid = amnezia_plan({"Jc": "12"})
        variants = (
            {**valid, "server_private_key": "secret"},
            {**valid, "container_id": "0" * 64},
            {**valid, "config_sha256": "0" * 64},
            {**valid, "table_sha256": "0" * 64},
            {**valid, "generation": 4},
            {**valid, "proposed_config_sha256": REVISION},
            {**valid, "current_awg_parameters": {**valid["current_awg_parameters"], "Jc": "9"}},
            {**valid, "proposed_awg_parameters": {**valid["proposed_awg_parameters"], "Jc": "13"}},
            {**valid, "changed_fields": ["S1"]},
            {**valid, "configured_clients": 1},
            {**valid, "apply_supported": True},
            {**valid, "apply_blockers": []},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                t.plan_override = variant
                with self.assertRaisesRegex(InstallError, "неверный план"):
                    c.amnezia_settings_plan(state, preview, proposal)
        t.plan_override = valid
        self.assertEqual(c.amnezia_settings_plan(state, preview, proposal).changed_fields, ("Jc",))

    def test_amnezia_awg3_zero_client_plan_support_is_strict(self):
        t = EnrollmentTransport()
        t.enrolled = True
        t.amnezia_clients = 0
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        proposal = {**dict(preview.awg_parameters), "Jc": "12"}
        plan = c.amnezia_settings_plan(state, preview, proposal)
        self.assertTrue(plan.apply_supported)
        self.assertEqual(plan.apply_blockers, ())
        valid = amnezia_plan({"Jc": "12"}, clients=0)
        for variant in ({**valid, "apply_supported": False},
                        {**valid, "apply_blockers": ["RUNTIME_PARAMETERS_UNVERIFIED"]},
                        {**valid, "configured_clients": 1}):
            t.plan_override = variant
            with self.assertRaisesRegex(InstallError, "неверный план"):
                c.amnezia_settings_plan(state, preview, proposal)

    def test_amnezia_awg3_settings_permission_requires_reviewed_zero_client_target(self):
        t = Transport("admin")
        t.amnezia_marker["awg2"] = "valid"
        t.amnezia_clients = 0
        c = self.controller(t)
        reviewed = c.amnezia_settings_access()
        self.assertTrue(reviewed.can_arm)
        self.assertEqual(reviewed.container_id, CONTAINER)
        self.assertEqual(reviewed.configured_clients, 0)
        armed = c.amnezia_settings_arm(reviewed)
        self.assertEqual(armed.settings_marker, "valid")
        self.assertFalse(armed.can_arm)
        self.assertTrue(any("arm-settings --confirm-container-id " + CONTAINER in item and
                            "--confirm-maintenance-window I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG3_SETTINGS" in item
                            for item in t.calls))
        disarmed = c.amnezia_settings_disarm(armed)
        self.assertEqual(disarmed.settings_marker, "absent")
        self.assertEqual(t.amnezia_marker["awg2"], "valid")
        self.assertFalse(any(" settings-apply " in item for item in t.calls))

    def test_amnezia_awg3_settings_permission_rejects_stale_and_untrusted_preview(self):
        t = Transport()
        t.amnezia_marker["awg2"] = "valid"
        t.amnezia_clients = 0
        c = self.controller(t)
        reviewed = c.amnezia_settings_access()
        valid = {"schema_version": 1, "action": "preview-settings", "selected_target": "awg2",
                 "settings_marker": "absent", "peer_marker": "valid", "socket_active": True,
                 "target_ready": True, "container_id": CONTAINER, "configured_clients": 0,
                 "awg3_runtime_verified": True, "can_arm": True, "reason": None}
        variants = (
            {**valid, "private_key": "secret"},
            {**valid, "container_id": "wrong"},
            {**valid, "configured_clients": None},
            {**valid, "reason": "PRIVATE_REASON"},
            {**valid, "reason": {}},
            {**valid, "peer_marker": "absent"},
            {**valid, "awg3_runtime_verified": False},
            {**valid, "can_arm": 1},
            {**valid, "target_ready": False},
        )
        for value in variants:
            with self.subTest(value=value):
                t.settings_access_override = value
                with self.assertRaises(InstallError):
                    c.amnezia_settings_access()
        t.settings_access_override = None
        t.amnezia_clients = 2
        with self.assertRaisesRegex(InstallError, "изменились"):
            c.amnezia_settings_arm(reviewed)
        self.assertFalse(any("arm-settings" in item for item in t.calls))
        unpinned = self.controller(Transport(), None)
        with self.assertRaises(InstallError):
            unpinned.amnezia_settings_access()

    def test_amnezia_awg3_settings_permission_recovers_lost_ssh_reply(self):
        t = Transport()
        t.amnezia_marker["awg2"] = "valid"
        t.amnezia_clients = 0
        c = self.controller(t)
        t.settings_lost_reply = True
        armed = c.amnezia_settings_arm(c.amnezia_settings_access())
        self.assertEqual(armed.settings_marker, "valid")
        disarmed = c.amnezia_settings_disarm(armed)
        self.assertEqual(disarmed.settings_marker, "absent")

    def test_amnezia_settings_dialog_explains_read_only_limits_without_secrets(self):
        try:
            from sovagrid_connect.vpn_setup_dialog import AmneziaDialog
        except ModuleNotFoundError as exc:
            if exc.name != "_tkinter":
                raise
            self.skipTest("Tk is unavailable in this Python runtime")
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        shown, statuses = [], []
        dialog = SimpleNamespace(state=state, settings_preview=None,
                                 _show=shown.append, status=SimpleNamespace(set=statuses.append))
        AmneziaDialog._result(dialog, "settings_preview", preview)
        self.assertIs(dialog.settings_preview, preview)
        self.assertIn("Jc=10", shown[0])
        self.assertIn("миграции их профилей", shown[0])
        self.assertIn("без изменения", statuses[0])
        for secret in ("PrivateKey", "PresharedKey", "clientsTable", "HeaderProtectionKey"):
            self.assertNotIn(secret, shown[0])

    def test_amnezia_settings_plan_dialog_shows_changes_and_blockers(self):
        try:
            from sovagrid_connect.vpn_setup_dialog import AmneziaDialog
        except ModuleNotFoundError as exc:
            if exc.name != "_tkinter":
                raise
            self.skipTest("Tk is unavailable in this Python runtime")
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        plan = c.amnezia_settings_plan(state, preview,
                                       {**dict(preview.awg_parameters), "Jc": "12"})
        shown, statuses = [], []
        dialog = SimpleNamespace(settings_preview=preview, settings_plan=None,
                                 _show=shown.append, status=SimpleNamespace(set=statuses.append))
        AmneziaDialog._result(dialog, "settings_plan", plan)
        self.assertIs(dialog.settings_plan, plan)
        self.assertIn("Jc: 10 → 12", shown[0])
        self.assertIn("Применение недоступно", shown[0])
        self.assertIn("перевыпустить", shown[0])
        self.assertIn("не применены", shown[0])
        self.assertIn("без изменений", statuses[0])
        for secret in ("PrivateKey", "PresharedKey", "HeaderProtectionKey"):
            self.assertNotIn(secret, shown[0])

    def test_amnezia_settings_plan_ui_queues_work_without_blocking(self):
        try:
            from sovagrid_connect.vpn_setup_dialog import AmneziaDialog
        except ModuleNotFoundError as exc:
            if exc.name != "_tkinter":
                raise
            self.skipTest("Tk is unavailable in this Python runtime")
        t = EnrollmentTransport()
        t.enrolled = True
        c = self.controller(t)
        state = c.amnezia_preview("awg2")
        preview = c.amnezia_settings_preview(state)
        proposal = {**dict(preview.awg_parameters), "Jc": "12"}
        queued, statuses = [], []
        dialog = SimpleNamespace(busy=False, state=state, settings_preview=preview,
                                 settings_plan=None, status=SimpleNamespace(set=statuses.append),
                                 _run=lambda kind, operation: queued.append((kind, operation)),
                                 _controller=lambda: c)
        self.assertTrue(AmneziaDialog.request_settings_plan(dialog, preview, proposal))
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0][0], "settings_plan")
        self.assertFalse(any(" settings-plan " in item for item in t.calls))
        self.assertEqual(queued[0][1]().changed_fields, ("Jc",))

    def test_probe_compiles_and_requires_bundle_hashes(self):
        compile(SCRIPT, "<vpn-source-probe>", "exec")
        self.assertIn("installed == source", SCRIPT)
        self.assertIn("hashlib.sha256(source).hexdigest() == digest", SCRIPT)
        self.assertNotIn("subprocess", SCRIPT)
        compile(NFT_SCRIPT, "<nftables-dependency>", "exec")
        self.assertIn("'--no-install-recommends', '--no-remove'", NFT_SCRIPT)
        self.assertIn("version_result = run([NFT, '--version']", NFT_SCRIPT)
        self.assertNotIn("run([SYSTEMCTL, 'enable'", NFT_SCRIPT)
        self.assertNotIn("run([SYSTEMCTL, 'start'", NFT_SCRIPT)
        self.assertNotIn("run([NFT, 'add'", NFT_SCRIPT)


if __name__ == "__main__":
    unittest.main()
