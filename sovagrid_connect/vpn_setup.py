# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first root SSH setup for owned WG routing and Amnezia peer broker."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
import shlex
import subprocess
from typing import Callable

from .core import ConnectionOptions
from .installer import InstallError
from .local_operations import _unique
from .nftables_dependency_remote import SCRIPT as NFT_DEPENDENCY_SCRIPT
from .promotion import PromotionController
from .vpn_setup_remote import SCRIPT


SHA = re.compile(r"[0-9a-f]{64}\Z")
INSTANCE = re.compile(r"[a-z][a-z0-9-]{1,31}\Z")
TARGETS = ("awg2", "wireguard")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONFIRM = {
    "awg2": "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG2",
    "wireguard": "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_WIREGUARD",
}
AWG_NUMBERS = frozenset(("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"))
AWG_RANGES = frozenset(("H1", "H2", "H3", "H4"))
AWG_FIELDS = AWG_NUMBERS | AWG_RANGES
SETTINGS_FIELDS = frozenset((
    "target", "container_id", "image_id", "config_sha256", "table_sha256",
    "generation", "protocol", "interface", "listen_port", "server_address",
    "server_subnet", "configured_clients", "managed_clients", "external_clients",
    "awg_parameters", "awg_parameters_runtime_verified",
    "header_protection_key_present", "awg3_required_parameters_present",
    "apply_supported", "apply_blockers",
))
SETTINGS_BLOCKERS = ("CLIENT_PROFILES_REQUIRE_REISSUE",
                     "PORT_REQUIRES_CONTAINER_NETWORK_MIGRATION")
PLAN_FIELDS = frozenset((
    "target", "container_id", "image_id", "generation", "config_sha256",
    "table_sha256", "proposed_config_sha256", "current_awg_parameters",
    "proposed_awg_parameters", "changed_fields", "configured_clients",
    "apply_supported", "apply_blockers",
))
SETTINGS_CONFIRM = "I_HAVE_A_MAINTENANCE_WINDOW_FOR_AMNEZIA_AWG3_SETTINGS"
SETTINGS_ACCESS_FIELDS = frozenset((
    "schema_version", "action", "selected_target", "settings_marker", "peer_marker",
    "socket_active", "target_ready", "container_id", "configured_clients",
    "awg3_runtime_verified", "can_arm", "reason",
))
SETTINGS_REASONS = frozenset((
    "INSTALL_NOT_CURRENT", "TARGET_UNAVAILABLE", "CLIENTS_PRESENT",
    "AWG3_INCOMPLETE", "RUNTIME_UNVERIFIED", "POLICY_NOT_READY",
    "POLICY_UNSAFE", "ALREADY_ARMED",
))


def _object(raw: bytes, *, maximum: int = 16384) -> dict:
    if len(raw) > maximum:
        raise InstallError("Сервер прислал слишком большой VPN-ответ")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверный VPN-ответ") from exc
    if not isinstance(value, dict):
        raise InstallError("Сервер прислал неверный VPN-ответ")
    return value


@dataclass(frozen=True)
class RoutingState:
    options: ConnectionOptions
    manifest_sha256: str
    name: str
    revision: str
    armed: bool
    configured: bool
    recovery_required: bool
    forwarding: bool
    nat: bool


@dataclass(frozen=True)
class NftablesState:
    options: ConnectionOptions
    manifest_sha256: str
    revision: str
    ubuntu_version: str
    package: str
    nft_version: str | None
    service_enabled: str
    service_active: str


@dataclass(frozen=True)
class AmneziaState:
    options: ConnectionOptions
    manifest_sha256: str
    target: str
    marker: str
    other_marker: str
    socket_active: bool
    service_active: bool
    installer_ready: bool
    installed_current: bool
    can_arm: bool
    target_ready: bool
    container_id: str | None
    configured_clients: int


@dataclass(frozen=True)
class AmneziaEnrollmentPreview:
    options: ConnectionOptions
    manifest_sha256: str
    target: str
    container_id: str
    image_id: str
    config_sha256: str
    table_sha256: str
    configured_clients: int
    protocol: str
    interface: str
    listen_port: int
    server_subnet: str


@dataclass(frozen=True)
class AmneziaSettingsPreview:
    target: str
    container_id: str
    image_id: str
    config_sha256: str
    table_sha256: str
    generation: int
    protocol: str
    interface: str
    listen_port: int
    server_address: str
    server_subnet: str
    configured_clients: int
    managed_clients: int
    external_clients: int
    awg_parameters: tuple[tuple[str, str], ...]
    header_protection_key_present: bool
    awg3_required_parameters_present: bool


@dataclass(frozen=True)
class AmneziaSettingsPlan:
    target: str
    container_id: str
    image_id: str
    generation: int
    config_sha256: str
    table_sha256: str
    proposed_config_sha256: str
    current_awg_parameters: tuple[tuple[str, str], ...]
    proposed_awg_parameters: tuple[tuple[str, str], ...]
    changed_fields: tuple[str, ...]
    configured_clients: int
    apply_supported: bool
    apply_blockers: tuple[str, ...]


@dataclass(frozen=True)
class AmneziaSettingsAccess:
    options: ConnectionOptions
    manifest_sha256: str
    settings_marker: str
    peer_marker: str
    socket_active: bool
    target_ready: bool
    container_id: str | None
    configured_clients: int | None
    awg3_runtime_verified: bool
    can_arm: bool
    reason: str | None


def awg_settings_patch(preview: AmneziaSettingsPreview, proposal: dict[str, str]) -> dict[str, str]:
    """Validate a complete public AWG3 form and return only changed values."""
    if (not isinstance(preview, AmneziaSettingsPreview) or preview.target != "awg2" or
            not preview.awg3_required_parameters_present or
            not preview.header_protection_key_present or
            set(dict(preview.awg_parameters)) != AWG_FIELDS):
        raise InstallError("Для плана нужен полный набор параметров принятого AWG2")
    if not isinstance(proposal, dict) or set(proposal) != AWG_FIELDS:
        raise InstallError("Заполните все поля Jc, Jmin, Jmax, S1–S4 и H1–H4")
    for name, encoded in proposal.items():
        if not isinstance(encoded, str) or re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", encoded) is None:
            raise InstallError(f"Поле {name}: введите число или допустимый диапазон")
        numbers = tuple(int(part) for part in encoded.split("-"))
        if encoded != "-".join(str(part) for part in numbers):
            raise InstallError(f"Поле {name}: уберите ведущие нули")
        maximum = 65535 if name in AWG_NUMBERS else 4294967295
        if (max(numbers) > maximum or
                len(numbers) == 2 and (name in AWG_NUMBERS or numbers[0] > numbers[1])):
            raise InstallError(f"Поле {name}: значение вне допустимого диапазона")
        if name in ("S1", "S2", "S3", "S4") and numbers[0] < 12:
            raise InstallError(f"Поле {name}: для AWG3 требуется не менее 12")
    if int(proposal["Jmin"]) > int(proposal["Jmax"]):
        raise InstallError("Jmin не может быть больше Jmax")
    current = dict(preview.awg_parameters)
    changed = {name: proposal[name] for name in sorted(AWG_FIELDS) if proposal[name] != current[name]}
    if not changed:
        raise InstallError("Измените хотя бы одно поле, чтобы построить план")
    return changed


class VpnSetupController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_manifest_sha256 is not None and SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного VPN-выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.manifest = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _source(self, feature: str) -> None:
        if self.manifest is None:
            raise InstallError("VPN-мастер ждёт общий проверенный серверный выпуск")
        if feature not in ("routing", "amnezia"):
            raise InstallError("Неизвестная VPN-функция")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " +
                   shlex.quote(SCRIPT) + " " + self.manifest + " " + feature)
        code, raw = self.transport._execute(command, timeout=90)
        if code != 0 or _object(raw, maximum=512) != {
                "protocol": 1, "manifest_sha256": self.manifest, "feature": feature}:
            raise InstallError("VPN-код сервера не совпадает с проверенным выпуском. Сервер не изменён")

    def _module(self, module: str, args: tuple[str, ...], *, timeout: int = 90) -> dict | list:
        if module not in ("sovagrid_vpn.routing", "sovagrid_vpn.amnezia_install", "sovagrid_vpn.manage"):
            raise InstallError("Неизвестная VPN-команда")
        command = ("cd /opt/sovagrid-vpn && " + self.transport._privileged +
                   "/usr/bin/python3 -B -E -S -m " + module + " " + " ".join(args))
        code, raw = self.transport._execute(command, timeout=timeout)
        if code != 0:
            raise InstallError("VPN-сервер отклонил действие. Повторите проверку состояния.")
        if module == "sovagrid_vpn.manage" and args == ("instances",):
            if len(raw) > 65536:
                raise InstallError("Список VPN-инстансов слишком велик")
            try:
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
            except (UnicodeError, ValueError) as exc:
                raise InstallError("Сервер прислал неверный список VPN-инстансов") from exc
            if not isinstance(value, list):
                raise InstallError("Сервер прислал неверный список VPN-инстансов")
            return value
        return _object(raw)

    def instances(self) -> tuple[str, ...]:
        self._source("routing")
        rows = self._module("sovagrid_vpn.manage", ("instances",))
        if len(rows) > 64 or any(not isinstance(row, dict) or
                                 not isinstance(row.get("name"), str) or
                                 INSTANCE.fullmatch(row["name"]) is None for row in rows):
            raise InstallError("Сервер прислал неверный список VPN-инстансов")
        names = [row["name"] for row in rows]
        if len(set(names)) != len(names):
            raise InstallError("В списке VPN-инстансов есть повторы")
        return tuple(sorted(names))

    def _nft_present(self) -> None:
        command = "command -v nft >/dev/null 2>&1"
        code, _raw = self.transport._execute(command, timeout=15)
        if code != 0:
            raise InstallError("Для полного маршрута на сервере нужен пакет nftables. "
                               "Нажмите «Установить nftables» в этом мастере.")

    def _dependency(self, action: str, expected: str | None = None) -> NftablesState:
        if action not in ("preview", "install") or (
                action == "preview" and expected is not None) or (
                action == "install" and (expected is None or SHA.fullmatch(expected) is None)):
            raise InstallError("Неверный запрос установки nftables")
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " +
                   shlex.quote(NFT_DEPENDENCY_SCRIPT) + " " + action)
        if expected is not None:
            command += " " + expected
        code, raw = self.transport._execute(command, timeout=660 if action == "install" else 50)
        value = _object(raw, maximum=4096)
        if code != 0 or value.get("ok") is not True:
            reasons = {
                "UNSUPPORTED_OS": "Автоматическая установка nftables поддерживает Ubuntu 22.04/24.04/26.04.",
                "PACKAGE_STATE_UNSAFE": "Состояние пакета или nftables.service необычно; установка остановлена.",
                "STATE_CHANGED": "Пакеты или состояние службы изменились. Повторите проверку.",
                "APT_FAILED": "APT не смог установить nftables. Пакеты могли измениться; проверьте сервер.",
                "APT_UNCERTAIN": "APT прервался или не ответил. Проверьте пакеты и службу перед повтором.",
                "SERVICE_CHANGED": "После установки nftables.service не остался выключенным. "
                                   "Проверьте firewall сервера перед продолжением.",
            }
            reason = value.get("error") if isinstance(value.get("error"), str) else ""
            raise InstallError(reasons.get(reason, "Не удалось подтвердить безопасную установку nftables."))
        keys = {"ok", "protocol", "state_revision", "ubuntu_version", "package",
                "nft_version", "service_enabled", "service_active"}
        if (set(value) != keys or type(value["protocol"]) is not int or value["protocol"] != 1 or
                not isinstance(value["state_revision"], str) or SHA.fullmatch(value["state_revision"]) is None or
                value["ubuntu_version"] not in ("22.04", "24.04", "26.04") or
                value["package"] not in ("absent", "not-installed", "installed") or
                value["service_enabled"] not in ("not-found", "disabled", "enabled", "masked", "static") or
                value["service_active"] not in ("inactive", "not-found", "unknown", "active", "failed") or
                (value["nft_version"] is not None and (
                    not isinstance(value["nft_version"], str) or
                    not value["nft_version"].startswith("nftables v") or
                    len(value["nft_version"]) > 128))):
            raise InstallError("Сервер прислал неверное состояние nftables")
        return NftablesState(self.options, self.manifest, value["state_revision"],
                             value["ubuntu_version"], value["package"], value["nft_version"],
                             value["service_enabled"], value["service_active"])

    def nftables_status(self) -> NftablesState:
        self._source("routing")
        return self._dependency("preview")

    def nftables_install(self, reviewed: NftablesState) -> NftablesState:
        if reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest:
            raise InstallError("Проверьте пакет nftables на выбранном сервере заново")
        if reviewed.nft_version is not None:
            return reviewed
        if (reviewed.package not in ("absent", "not-installed") or
                reviewed.service_enabled != "not-found" or
                reviewed.service_active not in ("inactive", "not-found", "unknown")):
            raise InstallError("Состояние nftables не подходит для новой установки")
        if self.nftables_status() != reviewed:
            raise InstallError("Состояние пакетов изменилось. Повторите проверку")
        self._source("routing")
        installed = self._dependency("install", reviewed.revision)
        if (installed.package != "installed" or installed.nft_version is None or
                installed.service_enabled != "disabled" or installed.service_active != "inactive"):
            raise InstallError("Установка nftables не подтвердилась; проверьте службу сервера")
        if self.nftables_status() != installed:
            raise InstallError("После установки состояние nftables изменилось; проверьте сервер")
        return installed

    def _routing_state(self, name: str, value: dict) -> RoutingState:
        keys = {"name", "armed", "routing_configured", "recovery_required", "forwarding",
                "nat", "upstream_firewall_unverified", "state_revision"}
        if (set(value) != keys or value["name"] != name or
                not isinstance(value["state_revision"], str) or SHA.fullmatch(value["state_revision"]) is None or
                any(type(value[key]) is not bool for key in keys -
                    {"name", "state_revision"}) or
                value["upstream_firewall_unverified"] is not True):
            raise InstallError("Сервер прислал неверное состояние VPN-маршрута")
        return RoutingState(self.options, self.manifest, name, value["state_revision"],
                            value["armed"], value["routing_configured"],
                            value["recovery_required"], value["forwarding"], value["nat"])

    def routing_preview(self, name: str) -> RoutingState:
        if not isinstance(name, str) or INSTANCE.fullmatch(name) is None:
            raise InstallError("Выберите управляемый WireGuard-инстанс")
        self._source("routing")
        self._nft_present()
        return self._routing_state(name, self._module("sovagrid_vpn.routing", ("preview", name)))

    def routing_arm(self, reviewed: RoutingState) -> RoutingState:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest or
                not reviewed.name or reviewed.recovery_required):
            raise InstallError("Нужна свежая проверка VPN-маршрута")
        if self.routing_preview(reviewed.name) != reviewed:
            raise InstallError("VPN-маршрут изменился. Повторите проверку")
        result = self._routing_state(reviewed.name, self._module(
            "sovagrid_vpn.routing", ("arm", reviewed.name, "--expected-state", reviewed.revision),
            timeout=150))
        if not result.configured:
            raise InstallError("Полный маршрут не подтвердился. Проверьте сервер повторно")
        return result

    def routing_disarm(self, reviewed: RoutingState) -> RoutingState:
        if reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest:
            raise InstallError("Нужна свежая проверка VPN-маршрута")
        if self.routing_preview(reviewed.name) != reviewed:
            raise InstallError("VPN-маршрут изменился. Повторите проверку")
        result = self._routing_state(reviewed.name, self._module(
            "sovagrid_vpn.routing", ("disarm", reviewed.name, "--expected-state", reviewed.revision),
            timeout=150))
        if result.armed:
            raise InstallError("Отключение полного маршрута не подтвердилось")
        return result

    def _amnezia_state(self, target: str, value: dict) -> AmneziaState:
        keys = {"schema_version", "action", "writes", "selected_target", "marker",
                "other_marker", "socket_active", "service_active", "installer_ready",
                "installed_current", "can_arm", "target"}
        if set(value) not in (keys, keys | {"reason"}):
            raise InstallError("Сервер прислал неверный статус Amnezia")
        if (type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                value["action"] != "preview" or value["writes"] is not False or
                value["selected_target"] != target or
                value["marker"] not in ("absent", "valid", "unsafe") or
                value["other_marker"] not in ("absent", "valid", "unsafe") or
                any(type(value[key]) is not bool for key in
                    ("socket_active", "service_active", "installer_ready", "installed_current", "can_arm")) or
                not isinstance(value["target"], dict)):
            raise InstallError("Сервер прислал неверный статус Amnezia")
        selected = value["target"]
        ready = selected.get("ready")
        if type(ready) is not bool:
            raise InstallError("Сервер прислал неверный контейнер Amnezia")
        container = None
        clients = 0
        if ready:
            if (set(selected) != {"ready", "container_id", "configured_clients", "owned_clients"} or
                    not isinstance(selected["container_id"], str) or SHA.fullmatch(selected["container_id"]) is None or
                    type(selected["configured_clients"]) is not int or
                    selected["configured_clients"] < 0 or selected["configured_clients"] > 100000 or
                    not isinstance(selected["owned_clients"], list) or
                    len(selected["owned_clients"]) > 10000):
                raise InstallError("Сервер прислал неверный контейнер Amnezia")
            container, clients = selected["container_id"], selected["configured_clients"]
        elif set(selected) != {"ready", "reason"} or not isinstance(selected["reason"], str):
            raise InstallError("Сервер прислал неверный контейнер Amnezia")
        if value["can_arm"] and (not ready or not value["installed_current"] or value["marker"] != "absent"):
            raise InstallError("Сервер прислал противоречивый статус Amnezia")
        return AmneziaState(self.options, self.manifest, target, value["marker"],
                            value["other_marker"], value["socket_active"], value["service_active"],
                            value["installer_ready"], value["installed_current"],
                            value["can_arm"], ready, container, clients)

    def amnezia_preview(self, target: str) -> AmneziaState:
        if target not in TARGETS:
            raise InstallError("Выберите AWG2 или WireGuard")
        self._source("amnezia")
        return self._amnezia_state(target, self._module(
            "sovagrid_vpn.amnezia_install", ("preview", "--target", target)))

    def amnezia_settings_access(self) -> AmneziaSettingsAccess:
        """Read the separate AWG3 write policy from the verified installer."""
        self._source("amnezia")
        value = self._module("sovagrid_vpn.amnezia_install", ("preview-settings",))
        if (not isinstance(value, dict) or set(value) != SETTINGS_ACCESS_FIELDS or
                type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                value["action"] != "preview-settings" or value["selected_target"] != "awg2" or
                value["settings_marker"] not in ("absent", "valid", "unsafe") or
                value["peer_marker"] not in ("absent", "valid", "unsafe") or
                any(type(value[name]) is not bool for name in (
                    "socket_active", "target_ready", "awg3_runtime_verified", "can_arm")) or
                (value["reason"] is not None and
                 (not isinstance(value["reason"], str) or
                  value["reason"] not in SETTINGS_REASONS))):
            raise InstallError("Сервер прислал неверное разрешение AWG3")
        if value["target_ready"]:
            if (not isinstance(value["container_id"], str) or
                    CONTAINER_ID.fullmatch(value["container_id"]) is None or
                    type(value["configured_clients"]) is not int or
                    not 0 <= value["configured_clients"] <= 2048):
                raise InstallError("Сервер прислал неверный контейнер AWG3")
        elif value["container_id"] is not None or value["configured_clients"] is not None:
            raise InstallError("Сервер прислал неверный контейнер AWG3")
        if (value["awg3_runtime_verified"] and not value["target_ready"] or
                value["can_arm"] and (
                    value["settings_marker"] != "absent" or
                    value["peer_marker"] != "valid" or not value["socket_active"] or
                    not value["target_ready"] or value["configured_clients"] != 0 or
                    not value["awg3_runtime_verified"] or value["reason"] is not None)):
            raise InstallError("Сервер прислал противоречивое разрешение AWG3")
        return AmneziaSettingsAccess(
            self.options, self.manifest, value["settings_marker"], value["peer_marker"],
            value["socket_active"], value["target_ready"], value["container_id"],
            value["configured_clients"], value["awg3_runtime_verified"],
            value["can_arm"], value["reason"])

    def _same_settings_access(self, reviewed: AmneziaSettingsAccess) -> None:
        if (not isinstance(reviewed, AmneziaSettingsAccess) or
                reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest or
                self.amnezia_settings_access() != reviewed):
            raise InstallError("Разрешение или контейнер AWG3 изменились. Повторите проверку")

    def amnezia_settings_arm(self, reviewed: AmneziaSettingsAccess) -> AmneziaSettingsAccess:
        self._same_settings_access(reviewed)
        if not reviewed.can_arm or reviewed.container_id is None:
            raise InstallError("Контейнер AWG3 не готов к включению настроек")
        try:
            result = self._module("sovagrid_vpn.amnezia_install", (
                "arm-settings", "--confirm-container-id", reviewed.container_id,
                "--confirm-maintenance-window", SETTINGS_CONFIRM), timeout=150)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                after = self.amnezia_settings_access()
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Результат включения AWG3 неизвестен. Проверьте состояние сервера") from exc
            if after.settings_marker == "valid" and after.container_id == reviewed.container_id:
                return after
            raise InstallError("Включение AWG3 не подтверждено. Проверьте состояние сервера") from exc
        if result != {"action": "settings_armed", "settings_marker": "valid",
                      "selected_target": "awg2", "container_id": reviewed.container_id}:
            raise InstallError("Сервер не подтвердил включение настроек AWG3")
        after = self.amnezia_settings_access()
        if after.settings_marker != "valid" or after.container_id != reviewed.container_id:
            raise InstallError("Разрешение AWG3 не сохранилось. Проверьте состояние сервера")
        return after

    def amnezia_settings_disarm(self, reviewed: AmneziaSettingsAccess) -> AmneziaSettingsAccess:
        self._same_settings_access(reviewed)
        if reviewed.settings_marker != "valid":
            raise InstallError("Разрешение на изменение AWG3 не включено")
        try:
            result = self._module("sovagrid_vpn.amnezia_install", ("disarm-settings",), timeout=150)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                after = self.amnezia_settings_access()
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Результат выключения AWG3 неизвестен. Проверьте состояние сервера") from exc
            if after.settings_marker == "absent":
                return after
            raise InstallError("Выключение AWG3 не подтверждено. Проверьте состояние сервера") from exc
        if result != {"action": "settings_disarmed", "settings_marker": "absent",
                      "selected_target": "awg2"}:
            raise InstallError("Сервер не подтвердил выключение настроек AWG3")
        after = self.amnezia_settings_access()
        if after.settings_marker != "absent":
            raise InstallError("Разрешение AWG3 осталось включённым")
        return after

    def _amnezia_admin(self, action: str, target: str,
                       preview: AmneziaEnrollmentPreview | None = None, *,
                       plan: tuple[AmneziaSettingsPreview, dict[str, str]] | None = None) -> dict:
        if (target not in TARGETS or
                action not in ("enroll-preview", "enroll", "settings-preview", "settings-plan") or
                (action == "enroll") is not (preview is not None) or
                (action == "settings-plan") is not (plan is not None) or
                action == "settings-plan" and target != "awg2"):
            raise InstallError("Недопустимое действие с контейнером Amnezia")
        args = [action, target]
        if preview is not None:
            args += ["--confirm-container-id", preview.container_id,
                     "--confirm-image-id", preview.image_id,
                     "--confirm-config-sha256", preview.config_sha256,
                     "--confirm-table-sha256", preview.table_sha256]
        if plan is not None:
            reviewed, patch = plan
            args += [reviewed.config_sha256, str(reviewed.generation),
                     json.dumps(patch, sort_keys=True, separators=(",", ":"))]
        command = ("cd /opt/sovagrid-vpn && " + self.transport._privileged +
                   "/usr/bin/python3 -B -E -S -m sovagrid_vpn.amnezia_admin " +
                   " ".join(shlex.quote(arg) for arg in args))
        code, raw = self.transport._execute(command, timeout=120)
        if code != 0:
            raise InstallError("Контейнер Amnezia изменился или сервер отклонил действие. "
                               "Проверьте его состояние заново")
        return _object(raw, maximum=4096)

    def amnezia_settings_preview(self, reviewed: AmneziaState) -> AmneziaSettingsPreview:
        """Read only a pinned container's public settings, never its keys or peers."""
        self._same_amnezia(reviewed)
        if not reviewed.target_ready or reviewed.container_id is None:
            raise InstallError("Сначала примите и проверьте контейнер Amnezia")
        self._source("amnezia")
        value = self._amnezia_admin("settings-preview", reviewed.target)
        target = reviewed.target
        expected = ("amneziawg", "awg0") if target == "awg2" else ("wireguard", "wg0")
        error = InstallError("Сервер прислал неверный обзор настроек Amnezia")
        if (set(value) != SETTINGS_FIELDS or value["target"] != target or
                value["container_id"] != reviewed.container_id or
                not isinstance(value["image_id"], str) or IMAGE_ID.fullmatch(value["image_id"]) is None or
                any(not isinstance(value[name], str) or SHA.fullmatch(value[name]) is None
                    for name in ("config_sha256", "table_sha256")) or
                (value["protocol"], value["interface"]) != expected or
                any(type(value[name]) is not int or not 0 <= value[name] <= maximum
                    for name, maximum in (("generation", 1_000_000_000),
                                          ("configured_clients", 2048), ("managed_clients", 2048),
                                          ("external_clients", 2048))) or
                value["configured_clients"] != value["managed_clients"] + value["external_clients"] or
                type(value["listen_port"]) is not int or not 1 <= value["listen_port"] <= 65535 or
                any(type(value[name]) is not bool for name in (
                    "awg_parameters_runtime_verified", "header_protection_key_present",
                    "awg3_required_parameters_present", "apply_supported")) or
                value["awg_parameters_runtime_verified"] is not False or
                value["apply_supported"] is not False or
                value["apply_blockers"] != list(SETTINGS_BLOCKERS) or
                not isinstance(value["awg_parameters"], dict) or
                set(value["awg_parameters"]) - (AWG_NUMBERS | AWG_RANGES)):
            raise error
        try:
            address = ipaddress.IPv4Address(value["server_address"])
            network = ipaddress.IPv4Network(value["server_subnet"], strict=True)
        except (TypeError, ValueError) as exc:
            raise error from exc
        if (str(address) != value["server_address"] or
                str(network) != value["server_subnet"] or address not in network):
            raise error
        parameters = value["awg_parameters"]
        for name, encoded in parameters.items():
            if not isinstance(encoded, str) or re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", encoded) is None:
                raise error
            numbers = tuple(int(part) for part in encoded.split("-"))
            if max(numbers) > (65535 if name in AWG_NUMBERS else 4294967295) or (
                    len(numbers) == 2 and (name in AWG_NUMBERS or numbers[0] > numbers[1])):
                raise error
        if ("Jmin" in parameters and "Jmax" in parameters and
                int(parameters["Jmin"]) > int(parameters["Jmax"])):
            raise error
        required = (AWG_NUMBERS | AWG_RANGES).issubset(parameters) and value["header_protection_key_present"]
        if (target == "awg2" and value["awg3_required_parameters_present"] != required or
                target == "wireguard" and (parameters or value["header_protection_key_present"] or
                                            value["awg3_required_parameters_present"])):
            raise error
        return AmneziaSettingsPreview(
            target, value["container_id"], value["image_id"], value["config_sha256"],
            value["table_sha256"], value["generation"], value["protocol"],
            value["interface"], value["listen_port"], str(address), str(network),
            value["configured_clients"], value["managed_clients"], value["external_clients"],
            tuple(sorted(parameters.items())), value["header_protection_key_present"],
            value["awg3_required_parameters_present"])

    def amnezia_settings_plan(self, reviewed: AmneziaState, preview: AmneziaSettingsPreview,
                              proposal: dict[str, str]) -> AmneziaSettingsPlan:
        """Ask root for a CAS-pinned, read-only AWG3 proposal; never apply it."""
        if (reviewed.target != "awg2" or not reviewed.target_ready or
                reviewed.container_id is None or not isinstance(preview, AmneziaSettingsPreview) or
                preview.target != reviewed.target or preview.container_id != reviewed.container_id):
            raise InstallError("Сначала примите AWG2 и проверьте его настройки")
        patch = awg_settings_patch(preview, proposal)
        if self.amnezia_settings_preview(reviewed) != preview:
            raise InstallError("Настройки Amnezia изменились. Прочитайте их заново")
        value = self._amnezia_admin("settings-plan", "awg2", plan=(preview, patch))
        expected_proposed = {**dict(preview.awg_parameters), **patch}
        expected_changed = sorted(patch)
        expected_blockers = (["CLIENT_PROFILES_REQUIRE_REISSUE"] if preview.configured_clients else [])
        expected_apply = preview.configured_clients == 0
        error = InstallError("Сервер прислал неверный план настроек Amnezia")
        if (set(value) != PLAN_FIELDS or value["target"] != "awg2" or
                value["container_id"] != preview.container_id or
                value["image_id"] != preview.image_id or
                value["config_sha256"] != preview.config_sha256 or
                value["table_sha256"] != preview.table_sha256 or
                type(value["generation"]) is not int or value["generation"] != preview.generation or
                type(value["configured_clients"]) is not int or
                value["configured_clients"] != preview.configured_clients or
                not isinstance(value["proposed_config_sha256"], str) or
                SHA.fullmatch(value["proposed_config_sha256"]) is None or
                value["proposed_config_sha256"] == preview.config_sha256 or
                not isinstance(value["current_awg_parameters"], dict) or
                value["current_awg_parameters"] != dict(preview.awg_parameters) or
                not isinstance(value["proposed_awg_parameters"], dict) or
                value["proposed_awg_parameters"] != expected_proposed or
                value["changed_fields"] != expected_changed or
                value["apply_supported"] is not expected_apply or
                value["apply_blockers"] != expected_blockers):
            raise error
        return AmneziaSettingsPlan(
            "awg2", preview.container_id, preview.image_id, preview.generation,
            preview.config_sha256, preview.table_sha256, value["proposed_config_sha256"],
            preview.awg_parameters, tuple(sorted(expected_proposed.items())),
            tuple(expected_changed), preview.configured_clients, expected_apply,
            tuple(expected_blockers))

    def amnezia_enroll_preview(self, target: str) -> AmneziaEnrollmentPreview:
        if target not in TARGETS:
            raise InstallError("Выберите AWG2 или WireGuard")
        self._source("amnezia")
        value = self._amnezia_admin("enroll-preview", target)
        keys = {"target", "container_id", "image_id", "config_sha256", "table_sha256",
                "configured_clients", "protocol", "interface", "listen_port", "server_subnet"}
        expected = ("amneziawg", "awg0") if target == "awg2" else ("wireguard", "wg0")
        if (set(value) != keys or value["target"] != target or
                not isinstance(value["container_id"], str) or
                CONTAINER_ID.fullmatch(value["container_id"]) is None or
                not isinstance(value["image_id"], str) or
                IMAGE_ID.fullmatch(value["image_id"]) is None or
                any(not isinstance(value[name], str) or SHA.fullmatch(value[name]) is None
                    for name in ("config_sha256", "table_sha256")) or
                type(value["configured_clients"]) is not int or
                not 0 <= value["configured_clients"] <= 4096 or
                (value["protocol"], value["interface"]) != expected or
                type(value["listen_port"]) is not int or
                not 1 <= value["listen_port"] <= 65535 or
                not isinstance(value["server_subnet"], str) or
                len(value["server_subnet"]) > 32):
            raise InstallError("Сервер прислал неверный обзор контейнера Amnezia")
        try:
            network = ipaddress.IPv4Network(value["server_subnet"], strict=True)
        except ValueError as exc:
            raise InstallError("Сервер прислал неверную VPN-подсеть") from exc
        if str(network) != value["server_subnet"]:
            raise InstallError("Сервер прислал неверную VPN-подсеть")
        return AmneziaEnrollmentPreview(
            self.options, self.manifest, target, value["container_id"], value["image_id"],
            value["config_sha256"], value["table_sha256"], value["configured_clients"],
            value["protocol"], value["interface"], value["listen_port"],
            value["server_subnet"])

    def amnezia_enroll(self, reviewed: AmneziaEnrollmentPreview) -> AmneziaState:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest or
                reviewed.target not in TARGETS or
                self.amnezia_enroll_preview(reviewed.target) != reviewed):
            raise InstallError("Контейнер Amnezia изменился после просмотра. Проверьте его заново")
        self._source("amnezia")
        try:
            result = self._amnezia_admin("enroll", reviewed.target, reviewed)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                state = self.amnezia_preview(reviewed.target)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Результат принятия контейнера неизвестен. "
                                   "Проверьте его состояние; не повторяйте действие вслепую") from exc
            if state.target_ready and state.container_id == reviewed.container_id:
                return state
            raise InstallError("Принятие контейнера не подтверждено. "
                               "Проверьте его состояние перед повтором") from exc
        if (set(result) != {"target", "enrolled", "configured_clients"} or
                result["target"] != reviewed.target or result["enrolled"] is not True or
                type(result["configured_clients"]) is not int or
                result["configured_clients"] != reviewed.configured_clients):
            raise InstallError("Сервер не подтвердил принятие контейнера. Проверьте его состояние")
        state = self.amnezia_preview(reviewed.target)
        if not state.target_ready or state.container_id != reviewed.container_id:
            raise InstallError("Контейнер принят, но итоговая проверка не подтвердилась")
        return state

    def _same_amnezia(self, reviewed: AmneziaState) -> None:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.manifest or
                reviewed.target not in TARGETS or self.amnezia_preview(reviewed.target) != reviewed):
            raise InstallError("Контейнер или настройки Amnezia изменились. Повторите проверку")

    def amnezia_install(self, reviewed: AmneziaState) -> AmneziaState:
        self._same_amnezia(reviewed)
        if (not reviewed.installer_ready or reviewed.installed_current or
                reviewed.marker != "absent" or reviewed.other_marker != "absent" or
                reviewed.socket_active or reviewed.service_active):
            raise InstallError("Брокер Amnezia уже установлен или его состояние требует диагностики")
        result = self._module("sovagrid_vpn.amnezia_install", ("install",), timeout=150)
        if result != {"action": "installed", "socket_active": False,
                      "marker": "absent", "target_changed": False}:
            raise InstallError("Установка брокера Amnezia не подтвердилась")
        after = self.amnezia_preview(reviewed.target)
        if not after.installed_current:
            raise InstallError("Брокер Amnezia установлен не полностью")
        return after

    def amnezia_arm(self, reviewed: AmneziaState) -> AmneziaState:
        self._same_amnezia(reviewed)
        if not reviewed.can_arm or reviewed.container_id is None:
            raise InstallError("Контейнер Amnezia не готов к включению")
        result = self._module("sovagrid_vpn.amnezia_install", (
            "arm", "--target", reviewed.target,
            "--confirm-container-id", reviewed.container_id,
            "--confirm-maintenance-window", CONFIRM[reviewed.target]), timeout=150)
        if result != {"action": "armed", "socket_active": True, "marker": "valid",
                      "selected_target": reviewed.target, "target_changed": False}:
            raise InstallError("Включение брокера Amnezia не подтвердилось")
        after = self.amnezia_preview(reviewed.target)
        if after.marker != "valid" or not after.socket_active:
            raise InstallError("Брокер Amnezia не остался включённым")
        return after

    def amnezia_disarm(self, reviewed: AmneziaState) -> AmneziaState:
        self._same_amnezia(reviewed)
        if reviewed.marker != "valid":
            raise InstallError("Брокер выбранной цели не включён")
        result = self._module("sovagrid_vpn.amnezia_install", (
            "disarm", "--target", reviewed.target), timeout=150)
        if (set(result) != {"action", "marker", "selected_target", "service_may_remain_running"} or
                result["action"] != "disarmed" or result["marker"] != "absent" or
                result["selected_target"] != reviewed.target or
                result["service_may_remain_running"] is not True):
            raise InstallError("Выключение брокера Amnezia не подтвердилось")
        after = self.amnezia_preview(reviewed.target)
        if after.marker != "absent":
            raise InstallError("Разрешение Amnezia осталось включённым")
        return after
