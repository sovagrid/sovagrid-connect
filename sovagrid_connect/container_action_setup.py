# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first Docker lifecycle policy for either installed Agent profile."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
import json
import re
import secrets
import shlex
import subprocess
from typing import Callable

from .container_action_setup_remote import SCRIPT
from .core import ConnectionOptions
from .installer import InstallError
from .local_operations import _unique
from .promotion import PromotionController


SHA = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
ACTIONS = ("status", "start", "stop", "restart")
STATES = {"created", "running", "paused", "restarting", "removing", "exited", "dead"}
PROFILES = ("default", "local")
ERRORS = {
    "SOURCE_UNVERIFIED": "Код Agent на сервере не совпадает с проверенным выпуском. Сервер не изменён.",
    "UNSAFE_PATH": "Права файлов Agent или разрешений небезопасны. Проверьте сервер вручную.",
    "INVALID_STATE": "Настройки контейнеров на сервере повреждены или изменились.",
    "INVALID_POLICY": "Выберите от одного до шестнадцати допустимых контейнеров и действий.",
    "INVALID_INPUT": "Сервер отклонил формат запроса.",
    "STATE_CHANGED": "Настройки контейнеров изменились. Проверьте план заново.",
    "IDENTITY_CHANGED": "Контейнер изменился или больше не проходит проверки безопасности.",
    "CATALOG_TOO_LARGE": "Docker вернул слишком много контейнеров или данных для безопасной проверки.",
    "INVENTORY_UNAVAILABLE": "Нужен активный сборщик и свежий полный Docker-инвентарь этого Agent. Настройки не изменены.",
    "DISARM_FIRST": "Сначала выключите действующие разрешения контейнеров.",
    "TRANSACTION_PENDING": "Предыдущая операция не завершена. Проверьте состояние сервера.",
    "TRANSACTION_CHANGED": "Операция изменилась. Автоматический откат остановлен.",
    "TRANSACTION_MISSING": "Запись операции исчезла. Проверьте фактическое состояние сервера.",
    "SETUP_BUSY": "Другой процесс меняет разрешения контейнеров. Повторите позже.",
    "ROLLBACK_INCOMPLETE": "Откат не подтвердился. Проверьте разрешения на сервере вручную.",
    "UNCONFIRMED": "Сервер не подтвердил результат. Проверьте состояние перед повтором.",
}


def _object(raw: bytes) -> dict:
    if len(raw) > 32768:
        raise InstallError("Сервер прислал слишком большой ответ о контейнерах")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверный ответ о контейнерах") from exc
    if not isinstance(value, dict):
        raise InstallError("Сервер прислал неверный ответ о контейнерах")
    return value


def _protected_name(name: str) -> bool:
    lower = name.casefold()
    return (lower.startswith(("sovagrid", "amnezia", "docker", "containerd", "wireguard",
                              "openvpn", "tailscale", "xray", "sing-box")) or
            "tunnel" in lower or "ssh" in lower)


@dataclass(frozen=True)
class ContainerCandidate:
    ident: str
    name: str
    image_id: str
    image: str
    state: str


def _candidate(value: object) -> ContainerCandidate:
    if not isinstance(value, dict) or set(value) != {"id", "name", "image_id", "image", "state"}:
        raise InstallError("Сервер прислал неверные данные контейнера")
    ident, name, image_id = value["id"], value["name"], value["image_id"]
    image, state = value["image"], value["state"]
    if (not isinstance(ident, str) or SHA.fullmatch(ident) is None or
            not isinstance(name, str) or NAME.fullmatch(name) is None or _protected_name(name) or
            not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None or
            not isinstance(image, str) or not 1 <= len(image) <= 160 or not image.isprintable() or
            state not in STATES):
        raise InstallError("Сервер прислал неверные данные контейнера")
    return ContainerCandidate(ident, name, image_id, image, state)


def _policy(raw: bytes) -> tuple[tuple[str, str, str, tuple[str, ...]], ...]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 8192:
        raise InstallError("Сервер прислал неверный список разрешений контейнеров")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверный список разрешений контейнеров") from exc
    if (not isinstance(value, dict) or set(value) != {"version", "containers"} or
            type(value["version"]) is not int or value["version"] != 1 or
            not isinstance(value["containers"], list) or not 1 <= len(value["containers"]) <= 16):
        raise InstallError("Сервер прислал неверный список разрешений контейнеров")
    result = []
    seen = set()
    for entry in value["containers"]:
        if not isinstance(entry, dict) or set(entry) != {"id", "name", "image_id", "actions"}:
            raise InstallError("Сервер прислал неверный список разрешений контейнеров")
        ident, name, image_id, actions = (entry[key] for key in ("id", "name", "image_id", "actions"))
        if (not isinstance(ident, str) or SHA.fullmatch(ident) is None or ident in seen or
                not isinstance(name, str) or NAME.fullmatch(name) is None or _protected_name(name) or
                not isinstance(image_id, str) or IMAGE_ID.fullmatch(image_id) is None or
                not isinstance(actions, list) or not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS for action in actions) or
                len(set(actions)) != len(actions) or "status" not in actions):
            raise InstallError("Сервер прислал неверный список разрешений контейнеров")
        seen.add(ident)
        result.append((ident, name, image_id, tuple(sorted(actions))))
    return tuple(sorted(result))


def policy_bytes(candidates: tuple[ContainerCandidate, ...],
                 actions_by_id: dict[str, set[str] | tuple[str, ...]]) -> bytes:
    if not isinstance(actions_by_id, dict) or not 1 <= len(actions_by_id) <= 16:
        raise InstallError("Добавьте от одного до шестнадцати контейнеров")
    available = {item.ident: item for item in candidates}
    entries = []
    for ident, actions in sorted(actions_by_id.items()):
        item = available.get(ident)
        if (item is None or not isinstance(actions, (tuple, list, set, frozenset)) or
                not 1 <= len(actions) <= len(ACTIONS) or
                any(not isinstance(action, str) or action not in ACTIONS for action in actions) or
                len(set(actions)) != len(actions) or "status" not in actions):
            raise InstallError("Проверьте контейнеры и разрешённые действия")
        entries.append({"id": item.ident, "name": item.name,
                        "image_id": item.image_id, "actions": sorted(actions)})
    raw = (json.dumps({"version": 1, "containers": entries}, sort_keys=True,
                      separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > 8192:
        raise InstallError("Список разрешений контейнеров слишком велик")
    _policy(raw)
    return raw


@dataclass(frozen=True)
class ContainerActionState:
    options: ConnectionOptions
    manifest_sha256: str
    profile: str
    state_revision: str
    armed: bool
    policy: tuple[tuple[str, str, str, tuple[str, ...]], ...] | None
    policy_raw: bytes | None
    transaction_pending: bool
    catalog: tuple[ContainerCandidate, ...]
    excluded: int
    catalog_status: str
    plan: tuple[str, tuple[tuple[str, str, str, tuple[str, ...]], ...], bool, bool] | None = None


class ContainerActionSetupController:
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

    def _command(self, profile: str, action: str, *, policy: bytes | None = None,
                 expected: str = "-", token: str = "-") -> dict:
        manifest = self.approved_manifest_sha256
        if manifest is None:
            raise InstallError("Мастер ждёт общий проверенный серверный выпуск с Docker-брокером")
        if (profile not in PROFILES or action not in
                {"status", "inspect", "preview", "arm", "rollback", "finalize", "disarm", "clear", "abort"} or
                (action in {"preview", "arm"}) != (policy is not None) or
                (expected != "-" and SHA.fullmatch(expected) is None) or
                (token != "-" and re.fullmatch(r"[0-9a-f]{32}", token) is None)):
            raise InstallError("Недопустимое действие настройки контейнеров")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -I -B -S -c " +
                   shlex.quote(SCRIPT) + " " + " ".join((action, profile, manifest, expected, token)))
        code, raw = self.transport._execute(command, data=policy, timeout=180, limit=32768)
        value = _object(raw)
        if code != 0 or value.get("ok") is not True:
            reason = value.get("error") if isinstance(value.get("error"), str) else "UNCONFIRMED"
            raise InstallError(ERRORS.get(reason, ERRORS["UNCONFIRMED"]))
        return value

    def _state(self, profile: str, value: dict, *, planned: bool = False,
               catalog_required: bool = True) -> ContainerActionState:
        keys = {"ok", "profile", "state_revision", "armed", "policy", "policy_raw",
                "transaction_pending"}
        if catalog_required:
            keys.update(("catalog", "excluded", "catalog_status"))
        if planned:
            keys.add("plan")
        if (set(value) != keys or value["ok"] is not True or value["profile"] != profile or
                not isinstance(value["state_revision"], str) or
                SHA.fullmatch(value["state_revision"]) is None or
                type(value["armed"]) is not bool or type(value["transaction_pending"]) is not bool or
                (value["policy"] is None) != (value["policy_raw"] is None)):
            raise InstallError("Сервер прислал неверное состояние разрешений контейнеров")
        raw = None
        parsed = None
        if value["policy_raw"] is not None:
            if not isinstance(value["policy_raw"], str):
                raise InstallError("Сервер прислал неверные разрешения контейнеров")
            try:
                raw = base64.b64decode(value["policy_raw"], validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise InstallError("Сервер прислал неверные разрешения контейнеров") from exc
            parsed = _policy(raw)
            if (not isinstance(value["policy"], list) or
                    _policy(json.dumps({"version": 1, "containers": value["policy"]}).encode()) != parsed):
                raise InstallError("Сервер прислал противоречивые разрешения контейнеров")
        if value["armed"] and parsed is None:
            raise InstallError("Сервер прислал противоречивое состояние контейнеров")
        catalog: tuple[ContainerCandidate, ...] = ()
        excluded = 0
        catalog_status = "not_requested"
        if catalog_required:
            items = value["catalog"]
            if (not isinstance(items, list) or len(items) > 64 or
                    type(value["excluded"]) is not int or value["excluded"] < 0 or
                    value["excluded"] > 64 or
                    value["catalog_status"] not in ("ok", "unavailable") or
                    (value["catalog_status"] == "unavailable" and (items or value["excluded"]))):
                raise InstallError("Сервер прислал неверный список контейнеров")
            catalog = tuple(_candidate(item) for item in items)
            if len({item.ident for item in catalog}) != len(catalog):
                raise InstallError("Сервер прислал повторяющиеся контейнеры")
            excluded = value["excluded"]
            catalog_status = value["catalog_status"]
        plan = None
        if planned:
            candidate = value["plan"]
            if (not isinstance(candidate, dict) or set(candidate) !=
                    {"config_path", "containers", "write_policy", "enable"} or
                    candidate["config_path"] !=
                    ("/etc/sovagrid-container-actions-local" if profile == "local" else
                     "/etc/sovagrid-container-actions") or
                    type(candidate["write_policy"]) is not bool or
                    candidate["enable"] is not True):
                raise InstallError("Сервер прислал неверный план разрешений контейнеров")
            proposed = _policy(json.dumps({"version": 1, "containers": candidate["containers"]}).encode())
            ids = {item.ident: item for item in catalog}
            if any(ident not in ids or ids[ident].name != name or ids[ident].image_id != image_id
                   for ident, name, image_id, _actions in proposed):
                raise InstallError("Контейнеры в плане отличаются от проверенных")
            plan = (candidate["config_path"], proposed, candidate["write_policy"], True)
        return ContainerActionState(self.options, self.approved_manifest_sha256, profile,
                                    value["state_revision"], value["armed"], parsed, raw,
                                    value["transaction_pending"], catalog, excluded,
                                    catalog_status, plan)

    def status(self, profile: str) -> ContainerActionState:
        return self._state(profile, self._command(profile, "status"), catalog_required=False)

    def inspect(self, profile: str) -> ContainerActionState:
        self.progress("Проверяем установленный Agent и безопасные Docker-контейнеры…")
        return self._state(profile, self._command(profile, "inspect"))

    def plan(self, profile: str, selected: dict[str, set[str] | tuple[str, ...]]) -> ContainerActionState:
        baseline = self.inspect(profile)
        if baseline.catalog_status != "ok":
            raise InstallError("Docker недоступен для проверки контейнеров. Настройки не изменены.")
        if baseline.armed or baseline.transaction_pending:
            raise InstallError(ERRORS["DISARM_FIRST"])
        policy = policy_bytes(baseline.catalog, selected)
        return self._state(profile, self._command(profile, "preview", policy=policy), planned=True)

    def arm(self, reviewed: ContainerActionState,
            selected: dict[str, set[str] | tuple[str, ...]]) -> ContainerActionState:
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES or reviewed.plan is None):
            raise InstallError("Сначала проверьте план разрешений контейнеров")
        fresh = self.plan(reviewed.profile, selected)
        if fresh != reviewed:
            raise InstallError("Состояние сервера или контейнеры изменились. Проверьте план заново")
        raw = policy_bytes(reviewed.catalog, selected)
        token = secrets.token_hex(16)
        try:
            pending = self._state(reviewed.profile,
                                  self._command(reviewed.profile, "arm", policy=raw,
                                                expected=reviewed.state_revision, token=token),
                                  catalog_required=False)
            if not pending.armed or not pending.transaction_pending or pending.policy != _policy(raw):
                raise InstallError("Включение разрешений контейнеров не подтвердилось")
            final = self._state(reviewed.profile,
                                self._command(reviewed.profile, "finalize", token=token),
                                catalog_required=False)
            if not final.armed or final.transaction_pending or final.policy != _policy(raw):
                raise InstallError("Завершение разрешений контейнеров не подтвердилось")
        except Exception as exc:
            try:
                observed = self.status(reviewed.profile)
                if (observed.armed and not observed.transaction_pending and
                        observed.policy == _policy(raw)):
                    return replace(observed, catalog=reviewed.catalog,
                                   excluded=reviewed.excluded, catalog_status="ok")
            except Exception:
                pass
            try:
                restored = self._state(reviewed.profile,
                                       self._command(reviewed.profile, "rollback",
                                                     expected=reviewed.state_revision, token=token),
                                       catalog_required=False)
                if (restored.armed or restored.transaction_pending or
                        restored.policy_raw != reviewed.policy_raw):
                    raise InstallError(ERRORS["ROLLBACK_INCOMPLETE"])
            except Exception as rollback_exc:
                try:
                    restored = self.status(reviewed.profile)
                    if (restored.armed or restored.transaction_pending or
                            restored.policy_raw != reviewed.policy_raw):
                        raise InstallError(ERRORS["ROLLBACK_INCOMPLETE"])
                except Exception as inspect_exc:
                    raise InstallError(ERRORS["ROLLBACK_INCOMPLETE"]) from inspect_exc
            raise InstallError("Включение не подтвердилось; предыдущие разрешения восстановлены. " +
                               str(exc)) from exc
        return replace(final, catalog=reviewed.catalog, excluded=reviewed.excluded,
                       catalog_status="ok")

    def disarm(self, reviewed: ContainerActionState) -> ContainerActionState:
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES or not reviewed.armed):
            raise InstallError("Сначала проверьте включённые разрешения контейнеров")
        current = self.status(reviewed.profile)
        if (current.state_revision != reviewed.state_revision or
                current.policy_raw != reviewed.policy_raw or not current.armed):
            raise InstallError("Разрешения контейнеров изменились. Проверьте сервер заново")
        try:
            result = self._state(reviewed.profile,
                                 self._command(reviewed.profile, "disarm",
                                               expected=reviewed.state_revision),
                                 catalog_required=False)
        except InstallError:
            result = self.status(reviewed.profile)
            if result.armed:
                raise
        if result.armed or result.transaction_pending:
            raise InstallError("Выключение разрешений контейнеров не подтвердилось")
        return replace(result, catalog=reviewed.catalog, excluded=reviewed.excluded,
                       catalog_status=reviewed.catalog_status)

    def abort(self, reviewed: ContainerActionState) -> ContainerActionState:
        """Explicitly restore the baseline of a stranded, token-bound setup."""
        if (reviewed.options != self.options or reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES or not reviewed.transaction_pending):
            raise InstallError("Сначала проверьте незавершённую настройку контейнеров")
        if self.status(reviewed.profile).state_revision != reviewed.state_revision:
            raise InstallError("Настройка контейнеров изменилась. Проверьте сервер заново")
        try:
            result = self._state(reviewed.profile,
                                 self._command(reviewed.profile, "abort",
                                               expected=reviewed.state_revision),
                                 catalog_required=False)
        except InstallError:
            result = self.status(reviewed.profile)
            if result.transaction_pending:
                raise
        if result.armed or result.transaction_pending:
            raise InstallError("Восстановление разрешений контейнеров не подтвердилось")
        return replace(result, catalog=reviewed.catalog, excluded=reviewed.excluded,
                       catalog_status=reviewed.catalog_status)

    def clear(self, reviewed: ContainerActionState) -> ContainerActionState:
        """Remove a disarmed saved allowlist using the reviewed state revision."""
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                reviewed.profile not in PROFILES or reviewed.armed or
                reviewed.transaction_pending or reviewed.policy_raw is None):
            raise InstallError("Сначала проверьте выключенный сохранённый список разрешений")
        current = self.status(reviewed.profile)
        if (current.state_revision != reviewed.state_revision or
                current.policy_raw != reviewed.policy_raw or current.armed or
                current.transaction_pending):
            raise InstallError("Разрешения контейнеров изменились. Проверьте сервер заново")
        try:
            result = self._state(reviewed.profile,
                                 self._command(reviewed.profile, "clear",
                                               expected=reviewed.state_revision),
                                 catalog_required=False)
        except Exception as exc:
            # A lost SSH reply may follow a successful unlink. Never repeat
            # the mutation; only confirm a fresh read-only status.
            try:
                result = self.status(reviewed.profile)
            except Exception as status_exc:
                raise InstallError("Результат удаления не подтверждён. Проверьте сервер заново") from status_exc
            if result.armed or result.transaction_pending or result.policy_raw is not None:
                if isinstance(exc, InstallError):
                    raise exc
                raise InstallError("Результат удаления не подтверждён. Проверьте сервер заново") from exc
        if result.armed or result.transaction_pending or result.policy_raw is not None:
            raise InstallError("Очистка сохранённых разрешений не подтвердилась")
        return replace(result, catalog=reviewed.catalog, excluded=reviewed.excluded,
                       catalog_status=reviewed.catalog_status)
