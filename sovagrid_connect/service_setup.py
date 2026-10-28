# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned, review-first root SSH control of the optional systemd broker."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shlex
import subprocess
from typing import Callable

from .core import ConnectionOptions
from .installer import InstallError
from .local_operations import _unique
from .promotion import PromotionController
from .service_setup_remote import SCRIPT


SHA = re.compile(r"[0-9a-f]{64}\Z")
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,87}[.]service\Z")
PROFILES = ("default", "local")
ACTIONS = ("status", "start", "stop", "restart")
ENABLED_STATES = {"enabled", "disabled", "not-found", "unavailable"}
ACTIVE_STATES = {"active", "inactive", "failed", "unknown", "unavailable"}
ERRORS = {
    "STATE_CHANGED": "Настройки служб изменились. Повторите проверку.",
    "LOCAL_AGENT_MISSING": "Локальный Agent не установлен или его конфигурация недоступна.",
    "LOCAL_AGENT_INACTIVE": "Локальный Agent должен быть запущен перед включением служб.",
    "UNIT_DRIFT": "Установленный systemd-брокер отличается от проверенного выпуска.",
    "UNSAFE_CODE_TREE": "Установленный код Agent имеет небезопасные права доступа.",
    "INVALID_POLICY": "Выберите от одной до шестнадцати служб и допустимые действия.",
    "ROLLBACK_INCOMPLETE": "Откат не подтвердился. Проверьте сервер перед следующим действием.",
    "SETUP_BUSY": "Другой процесс меняет настройки служб. Повторите проверку позже.",
}


def _object(raw: bytes, maximum: int = 16384) -> dict:
    if len(raw) > maximum:
        raise InstallError("Сервер прислал слишком большой ответ о службах")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверный ответ о службах") from exc
    if not isinstance(value, dict):
        raise InstallError("Сервер прислал неверный ответ о службах")
    return value


def _units(value: object) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not isinstance(value, dict) or len(value) > 16:
        raise InstallError("Сервер прислал неверные разрешения служб")
    result = []
    for unit, actions in value.items():
        if (not isinstance(unit, str) or UNIT.fullmatch(unit) is None or unit.endswith("@.service") or
                not isinstance(actions, list) or not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS for action in actions) or
                len(set(actions)) != len(actions)):
            raise InstallError("Сервер прислал неверные разрешения служб")
        result.append((unit, tuple(sorted(actions))))
    return tuple(sorted(result))


def policy_bytes(units: dict[str, set[str] | tuple[str, ...]]) -> bytes:
    if not isinstance(units, dict) or not 1 <= len(units) <= 16:
        raise InstallError("Добавьте от одной до шестнадцати служб")
    validated = {}
    for unit, actions in units.items():
        if (not isinstance(unit, str) or UNIT.fullmatch(unit) is None or unit.endswith("@.service") or
                not isinstance(actions, (tuple, list, set, frozenset)) or
                not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS for action in actions) or
                len(set(actions)) != len(actions) or "status" not in actions):
            raise InstallError("Проверьте имя службы и её действия")
        validated[unit] = sorted(actions)
    raw = (json.dumps({"version": 1, "units": validated}, sort_keys=True,
                      separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > 4096:
        raise InstallError("Список служб слишком велик")
    return raw


@dataclass(frozen=True)
class ServiceSetupState:
    options: ConnectionOptions
    manifest_sha256: str
    profile: str
    state_revision: str
    armed: bool
    policy: tuple[tuple[str, tuple[str, ...]], ...] | None
    socket_enabled: str
    socket_active: str
    plan: tuple | None = None


class ServiceSetupController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_manifest_sha256 is not None and SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного серверного выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _source(self, profile: str) -> None:
        expected = self.approved_manifest_sha256
        if expected is None:
            raise InstallError("Настройка служб ждёт общий проверенный серверный выпуск")
        if profile not in PROFILES:
            raise InstallError("Выберите профиль Agent")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " + shlex.quote(SCRIPT) +
                   " " + expected + " " + profile)
        code, raw = self.transport._execute(command, timeout=90)
        if code != 0 or _object(raw, 512) != {
                "protocol": 1, "manifest_sha256": expected, "profile": profile}:
            raise InstallError("Код Agent на сервере не совпадает с проверенным выпуском. Сервер не изменён")

    def _command(self, profile: str, action: str, *, policy: bytes | None = None,
                 expected: str | None = None) -> dict:
        if (profile not in PROFILES or action not in {"preview", "arm", "disarm"} or
                (action == "arm" and policy is None) or
                (action == "preview" and expected is not None) or
                (action != "preview" and (expected is None or SHA.fullmatch(expected) is None))):
            raise InstallError("Недопустимое действие настройки служб")
        installed = "/opt/sovagrid-agent-local" if profile == "local" else "/opt/sovagrid-agent"
        command = ("cd " + installed + " && " + self.transport._privileged + "/usr/bin/python3 -B -E -S "
                   "-m sovagrid_agent.service_setup " + action)
        if action != "preview" or policy is not None:
            command += " --profile " + profile
        if expected is not None:
            command += " --expected-state " + expected
        code, raw = self.transport._execute(command, data=policy,
                                            timeout=150 if action != "preview" else 60)
        value = _object(raw)
        if code != 0 or value.get("ok") is not True:
            reason = value.get("error") if isinstance(value.get("error"), str) else ""
            raise InstallError(ERRORS.get(reason, "Сервер не подтвердил изменение служб. Повторите проверку."))
        return value

    def _state(self, profile: str, value: dict, *, planned: bool,
               selected_top: bool = False) -> ServiceSetupState:
        keys = {"ok", "state_revision", "armed", "sockets", "profiles", "policy_status", "policy"}
        if planned:
            keys.add("plan")
        if (set(value) != keys or value.get("ok") is not True or
                not isinstance(value["state_revision"], str) or SHA.fullmatch(value["state_revision"]) is None or
                type(value["armed"]) is not bool or
                not isinstance(value["sockets"], dict) or set(value["sockets"]) != set(PROFILES) or
                not isinstance(value["profiles"], dict) or set(value["profiles"]) != set(PROFILES)):
            raise InstallError("Сервер прислал неверное состояние служб")
        for name in PROFILES:
            socket = value["sockets"][name]
            record = value["profiles"][name]
            if (not isinstance(socket, list) or len(socket) != 2 or
                    socket[0] not in ENABLED_STATES or socket[1] not in ACTIVE_STATES or
                    not isinstance(record, dict) or set(record) !=
                    {"armed", "policy_status", "policy", "socket"} or
                    type(record["armed"]) is not bool or record["socket"] != socket or
                    record["policy_status"] not in {"present", "absent", "invalid"} or
                    (record["policy"] is None) != (record["policy_status"] != "present")):
                raise InstallError("Сервер прислал неверный профиль Agent")
            if record["policy"] is not None:
                _units(record["policy"])
        top = value["profiles"][profile if planned or selected_top else "default"]
        if (value["armed"] is not top["armed"] or value["policy_status"] != top["policy_status"] or
                value["policy"] != top["policy"]):
            raise InstallError("Сервер прислал противоречивый профиль Agent")
        selected = value["profiles"][profile]
        plan = None
        if planned:
            candidate = value["plan"]
            if (not isinstance(candidate, dict) or set(candidate) !=
                    {"profile", "install_units", "change_policy", "enable_socket", "configure_local_agent"} or
                    candidate["profile"] != profile or
                    not isinstance(candidate["install_units"], list) or
                    any(not isinstance(unit, str) or not unit.startswith("sovagrid-service-") or
                        not unit.endswith((".socket", ".service")) for unit in candidate["install_units"]) or
                    any(type(candidate[key]) is not bool for key in
                        ("change_policy", "enable_socket", "configure_local_agent"))):
                raise InstallError("Сервер прислал неверный план настройки служб")
            plan = (tuple(candidate["install_units"]), candidate["change_policy"],
                    candidate["enable_socket"], candidate["configure_local_agent"])
        socket = value["sockets"][profile]
        return ServiceSetupState(self.options, self.approved_manifest_sha256, profile,
                                 value["state_revision"], selected["armed"],
                                 None if selected["policy"] is None else _units(selected["policy"]),
                                 socket[0], socket[1], plan)

    def inspect(self, profile: str) -> ServiceSetupState:
        self.progress("Проверка SSH, точного кода Agent и состояния systemd без изменений…")
        self._source(profile)
        return self._state(profile, self._command(profile, "preview"), planned=False)

    def plan(self, profile: str, units: dict[str, set[str] | tuple[str, ...]]) -> ServiceSetupState:
        raw = policy_bytes(units)
        self._source(profile)
        return self._state(profile, self._command(profile, "preview", policy=raw), planned=True)

    def arm(self, reviewed: ServiceSetupState, units: dict[str, set[str] | tuple[str, ...]]) -> ServiceSetupState:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES or reviewed.plan is None):
            raise InstallError("Сначала проверьте план разрешений служб")
        if self.plan(reviewed.profile, units) != reviewed:
            raise InstallError("Состояние сервера или разрешения изменились. Повторите проверку плана")
        result = self._state(reviewed.profile, self._command(reviewed.profile, "arm",
                             policy=policy_bytes(units), expected=reviewed.state_revision),
                             planned=False, selected_top=True)
        if not result.armed or result.policy != _units(json.loads(policy_bytes(units))["units"]):
            raise InstallError("Включение служб не подтвердилось. Повторите проверку состояния")
        return result

    def disarm(self, reviewed: ServiceSetupState) -> ServiceSetupState:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES):
            raise InstallError("Сначала проверьте состояние служб")
        if self.inspect(reviewed.profile) != reviewed:
            raise InstallError("Состояние служб изменилось. Повторите проверку")
        result = self._state(reviewed.profile, self._command(reviewed.profile, "disarm",
                             expected=reviewed.state_revision), planned=False, selected_top=True)
        if result.armed or result.socket_enabled == "enabled" or result.socket_active == "active":
            raise InstallError("Выключение служб не подтвердилось. Повторите проверку")
        return result

    def catalog(self, profile: str) -> tuple[str, ...]:
        self._source(profile)
        command = (self.transport._privileged + "/usr/bin/systemctl --system --no-pager --no-legend "
                   "--plain list-unit-files --type=service --all")
        code, raw = self.transport._execute(command, timeout=30, limit=98304)
        if code != 0:
            raise InstallError("Не удалось получить список служб сервера")
        try:
            lines = raw.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise InstallError("Сервер прислал неверный список служб") from exc
        names = set()
        for line in lines:
            if len(names) >= 2048:
                break
            fields = line.split()
            name = fields[0] if fields else ""
            if UNIT.fullmatch(name) and not name.endswith("@.service"):
                names.add(name)
        return tuple(sorted(names))
