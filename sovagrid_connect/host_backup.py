# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Pinned root SSH control of offline archives and journaled online backup jobs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import re
import shlex
import subprocess
from typing import Callable

from .core import ConnectionOptions
from .host_backup_remote import SCRIPT
from .host_backup_request import HostBackupRequest, HostBackupRequestStore
from .hub_backup import _object
from .installer import InstallError
from .promotion import PromotionController


PROTOCOL = "sovagrid-host-backup-v1"
OPERATION_PROTOCOL = "sovagrid-host-backup-operation-v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
ARCHIVE_ID = re.compile(r"[0-9a-f]{32}\Z")
UTC_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00\Z")
MAX_ARCHIVES = 100
MAX_BYTES = 8 * 1024**3
MAX_FILES = 20_000
OPERATION_PHASES = frozenset(("accepted", "stopping", "archiving", "restarting",
                              "complete", "recovery_requested", "recovered", "failed",
                              "recovery_required"))
TERMINAL_PHASES = frozenset(("complete", "recovered", "failed"))
OPERATION_ERROR = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
UNIT = re.compile(r"sovagrid-[a-z0-9_.@-]{1,80}\.(?:service|socket|timer)\Z")
CONTAINER = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
ERRORS = {
    "SERVICES_RUNNING": "Перед полной копией остановите службы SovaGrid на сервере.",
    "CONTAINERS_RUNNING": "Перед полной копией остановите контейнеры SovaGrid на сервере.",
    "OFFLINE_CHECK_UNAVAILABLE": "Не удалось подтвердить, что службы и контейнеры остановлены.",
    "UNMANAGED_UNIT": "Служба SovaGrid не совпадает с управляемой установкой.",
    "CONTAINER_AMBIGUOUS": "Набор контейнеров SovaGrid неоднозначен.",
    "BUSY": "Сервер сейчас занят обновлением или другой операцией.",
    "LOCK_UNAVAILABLE": "Защитная блокировка сервера недоступна.",
    "MISSING_SOURCE": "На сервере отсутствует обязательная часть SovaGrid.",
    "UNSAFE_SOURCE": "Файлы SovaGrid на сервере не прошли проверку владельца и типа.",
    "SOURCE_UNSAFE": "Установленный пакет SovaGrid изменился. Обновите его из проверенного выпуска.",
    "SOURCE_UNAVAILABLE": "Исходный код SovaGrid недоступен для проверки.",
    "DISK_SPACE": "Недостаточно свободного места для полной копии.",
    "TIME_LIMIT": "Создание копии превысило допустимое время.",
    "SIZE_LIMIT": "Размер данных превышает предел полной копии.",
    "FILE_LIMIT": "Количество файлов превышает предел полной копии.",
    "ARCHIVE_LIMIT": "На сервере достигнут предел сохранённых копий.",
    "OPERATION_LIMIT": "На сервере достигнут предел заданий полной копии.",
    "DEGRADED_CONTAINERS": "Контейнеры Hub/Web запущены не полностью. Проверьте сервер перед копией.",
    "SOURCE_CHANGED": "Установленный серверный пакет изменился. Проверьте его заново.",
    "SPAWN_FAILED": "Сервер не смог запустить задание полной копии.",
    "UNSAFE_STATE": "Журнал задания имеет небезопасные права или повреждён.",
    "INVALID_STATE": "Журнал задания повреждён или не совпадает с текущим сервером.",
    "NOT_FOUND": "Копия больше не найдена на сервере.",
    "ARCHIVE_CHANGED": "Архив изменился и не прошёл проверку.",
    "INVALID_ARCHIVE": "Архив повреждён или имеет недопустимую структуру.",
    "UNSAFE_ARCHIVE": "Права или тип архива изменились; проверка остановлена.",
    "INVALID_MANIFEST": "Описание архива повреждено.",
}


def _id(value: object) -> str:
    if not isinstance(value, str) or ARCHIVE_ID.fullmatch(value) is None:
        raise InstallError("Неверный идентификатор полной копии")
    return value


@dataclass(frozen=True)
class HostArchive:
    id: str
    created_at: str
    layout: str
    bytes: int
    files: int
    verified: bool = False


@dataclass(frozen=True)
class HostBackupPlan:
    layout: str
    active_units: tuple[str, ...]
    running_containers: tuple[str, ...]
    offline_ready: bool


@dataclass(frozen=True)
class HostBackupState:
    options: ConnectionOptions
    manifest_sha256: str
    archives: tuple[HostArchive, ...]
    plan: HostBackupPlan


@dataclass(frozen=True)
class HostBackupOperation:
    request_id: str
    phase: str
    archive: HostArchive | None
    error: str | None
    created_at: str

    @property
    def terminal(self) -> bool:
        return self.phase in TERMINAL_PHASES


class HostBackupRejected(InstallError):
    """A structured server refusal before the requested mutation was accepted."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class HostBackupController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None,
                 request_store: HostBackupRequestStore | None = None) -> None:
        if approved_manifest_sha256 is not None and SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного серверного выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)
        self.request_store = request_store or HostBackupRequestStore.default()

    def _source(self) -> None:
        expected = self.approved_manifest_sha256
        if expected is None:
            raise InstallError("Полная копия ждёт общий проверенный серверный выпуск")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -B -I -c " +
                   shlex.quote(SCRIPT) + " " + expected)
        code, raw = self.transport._execute(command, timeout=120)
        if code != 0:
            raise InstallError("Установленный серверный пакет не совпал с проверенным выпуском")
        value = _object(raw, 1024)
        if (set(value) != {"protocol", "manifest_sha256", "host_backup_verified"} or
                type(value["protocol"]) is not int or value["protocol"] != 1 or
                value["manifest_sha256"] != expected or
                value["host_backup_verified"] is not True):
            raise InstallError("Установленный серверный пакет не совпал с проверенным выпуском")

    @staticmethod
    def _archive(value: object, *, verified: bool) -> HostArchive:
        if (not isinstance(value, dict) or
                set(value) != {"id", "created_at", "layout", "bytes", "files"} or
                not isinstance(value["created_at"], str) or
                UTC_TIME.fullmatch(value["created_at"]) is None or
                value["layout"] not in ("full", "hub-only") or
                type(value["bytes"]) is not int or not 0 < value["bytes"] <= MAX_BYTES or
                type(value["files"]) is not int or not 0 < value["files"] <= MAX_FILES):
            raise InstallError("Сервер прислал неверное описание полной копии")
        try:
            stamp = datetime.fromisoformat(value["created_at"])
        except ValueError as exc:
            raise InstallError("Сервер прислал неверное время полной копии") from exc
        if stamp.utcoffset() != timedelta(0):
            raise InstallError("Сервер прислал неверное время полной копии")
        return HostArchive(_id(value["id"]), value["created_at"], value["layout"],
                           value["bytes"], value["files"], verified)

    def _action(self, action: str, identity: str | None = None) -> dict:
        if action not in ("plan", "list", "create", "verify") or (identity is None) != (action != "verify"):
            raise InstallError("Недопустимое действие с полной копией")
        argument = "" if identity is None else " " + _id(identity)
        command = (self.transport._privileged + "/usr/bin/python3 -B -I " +
                   "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup.py " +
                   action + argument)
        timeout = {"plan": 60, "list": 60, "create": 420, "verify": 420}[action]
        code, raw = self.transport._execute(command, timeout=timeout,
                                            limit=32768 if action == "list" else 4096)
        try:
            value = _object(raw, 32768)
        except InstallError as exc:
            if action == "create":
                raise InstallError("Ответ о создании потерян: копия могла появиться. "
                                   "Обновите список перед повтором") from exc
            raise
        if value.get("protocol") != PROTOCOL or type(value.get("ok")) is not bool:
            raise InstallError("Сервер прислал неверный ответ о полной копии")
        if code != 0 or value["ok"] is not True:
            reason = value.get("error")
            if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                    not isinstance(reason, str) or
                    re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", reason) is None):
                raise InstallError("Сервер не подтвердил результат полной копии")
            explanation = ERRORS.get(reason, "Сервер отказал в операции с полной копией.")
            if action == "create":
                explanation += " Обновите список перед повтором."
            raise InstallError(explanation)
        return value

    def inspect(self) -> HostBackupState:
        self.progress("Проверяем исходный код и список полных копий без изменений…")
        self._source()
        plan_value = self._action("plan")
        if (set(plan_value) != {"ok", "protocol", "layout", "active_units",
                                "running_containers", "offline_ready"} or
                plan_value["layout"] not in ("full", "hub-only") or
                type(plan_value["offline_ready"]) is not bool or
                not isinstance(plan_value["active_units"], list) or
                not isinstance(plan_value["running_containers"], list) or
                len(plan_value["active_units"]) > 64 or
                len(plan_value["running_containers"]) > 16 or
                any(not isinstance(item, str) or UNIT.fullmatch(item) is None
                    for item in plan_value["active_units"]) or
                any(not isinstance(item, str) or CONTAINER.fullmatch(item) is None
                    for item in plan_value["running_containers"]) or
                len(set(plan_value["active_units"])) != len(plan_value["active_units"]) or
                len(set(plan_value["running_containers"])) != len(plan_value["running_containers"]) or
                (plan_value["offline_ready"] and
                 (plan_value["active_units"] or plan_value["running_containers"]))):
            raise InstallError("Сервер прислал неверный план полной копии")
        plan = HostBackupPlan(plan_value["layout"], tuple(plan_value["active_units"]),
                              tuple(plan_value["running_containers"]),
                              plan_value["offline_ready"])
        value = self._action("list")
        records = value.get("archives")
        if (set(value) != {"ok", "protocol", "archives"} or
                not isinstance(records, list) or len(records) > MAX_ARCHIVES):
            raise InstallError("Сервер прислал неверный список полных копий")
        archives = tuple(self._archive(item, verified=False) for item in records)
        if len({item.id for item in archives}) != len(archives):
            raise InstallError("Сервер прислал повторяющиеся полные копии")
        return HostBackupState(self.options, self.approved_manifest_sha256, archives, plan)

    def verify(self, identity: str) -> HostArchive:
        self._source()
        identity = _id(identity)
        value = self._action("verify", identity)
        if (set(value) != {"ok", "protocol", "archive", "verified"} or
                value["verified"] is not True):
            raise InstallError("Сервер не подтвердил проверку полной копии")
        archive = self._archive(value["archive"], verified=True)
        if archive.id != identity:
            raise InstallError("Сервер ответил о другой полной копии")
        return archive

    def create(self, reviewed: HostBackupState) -> tuple[HostArchive, HostBackupState]:
        if (reviewed.options != self.options or not reviewed.plan.offline_ready or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("Список копий или код сервера изменились. Обновите список")
        self.progress("Создаём полную закрытую копию узла; не закрывайте окно…")
        try:
            value = self._action("create")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise InstallError("Ответ о создании потерян: копия могла появиться. "
                               "Обновите список перед повтором") from exc
        if set(value) != {"ok", "protocol", "archive"}:
            raise InstallError("Сервер не подтвердил создание полной копии")
        created = self._archive(value["archive"], verified=False)
        state = self.inspect()
        if created not in state.archives:
            raise InstallError("Копия создана, но исчезла из списка. Проверьте сервер")
        verified = self.verify(created.id)
        if (verified.id, verified.created_at, verified.layout, verified.bytes, verified.files) != (
                created.id, created.created_at, created.layout, created.bytes, created.files):
            raise InstallError("Копия создана, но проверка дала другой результат")
        return verified, state

    @staticmethod
    def _operation(value: object, identity: str | None = None) -> HostBackupOperation:
        keys = {"ok", "protocol", "request_id", "phase", "archive", "error", "created_at"}
        if (not isinstance(value, dict) or set(value) != keys or value["ok"] is not True or
                value["protocol"] != OPERATION_PROTOCOL or
                not isinstance(value["phase"], str) or
                value["phase"] not in OPERATION_PHASES or
                (value["error"] is not None and
                 (not isinstance(value["error"], str) or
                  OPERATION_ERROR.fullmatch(value["error"]) is None)) or
                not isinstance(value["created_at"], str) or
                UTC_TIME.fullmatch(value["created_at"]) is None):
            raise InstallError("Сервер прислал неверное состояние полной копии")
        request_id = _id(value["request_id"])
        if identity is not None and request_id != identity:
            raise InstallError("Сервер ответил о другом запросе полной копии")
        try:
            stamp = datetime.fromisoformat(value["created_at"])
        except ValueError as exc:
            raise InstallError("Сервер прислал неверное время запроса") from exc
        if stamp.utcoffset() != timedelta(0):
            raise InstallError("Сервер прислал неверное время запроса")
        archive = (None if value["archive"] is None else
                   HostBackupController._archive(value["archive"], verified=False))
        if value["phase"] == "complete" and archive is None:
            raise InstallError("Завершённая полная копия не содержит архив")
        return HostBackupOperation(request_id, value["phase"], archive,
                                   value["error"], value["created_at"])

    def _operation_action(self, action: str, request_id: str | None = None) -> dict:
        if action not in ("start", "status", "recover", "list") or (
                request_id is None) != (action == "list"):
            raise InstallError("Недопустимое действие с заданием полной копии")
        self._source()
        arguments = " " + action
        if request_id is not None:
            arguments += " " + _id(request_id)
        if action == "start":
            if self.approved_manifest_sha256 is None:
                raise InstallError("Задание ждёт проверенный серверный выпуск")
            arguments += " " + self.approved_manifest_sha256
        command = (self.transport._privileged + "/usr/bin/python3 -B -I " +
                   "/opt/sovagrid-src/sovagrid-blueprint/deploy/host_backup_orchestrator.py" +
                   arguments)
        maximum = 98304 if action == "list" else 4096
        code, raw = self.transport._execute(command, timeout=90 if action == "start" else 60,
                                            limit=maximum)
        value = _object(raw, maximum)
        if value.get("protocol") != OPERATION_PROTOCOL or type(value.get("ok")) is not bool:
            raise InstallError("Сервер прислал неверный ответ задания полной копии")
        if code != 0 or value["ok"] is not True:
            error = value.get("error")
            if (set(value) != {"ok", "protocol", "error"} or value["ok"] is not False or
                    not isinstance(error, str) or OPERATION_ERROR.fullmatch(error) is None):
                raise InstallError("Сервер не подтвердил задание полной копии")
            if action == "recover" and error == "BUSY":
                raise HostBackupRejected(error, "Операция ещё выполняется. Сервер не стал запускать восстановление параллельно")
            if error == "NOT_FOUND":
                raise HostBackupRejected(error, "Задание полной копии не найдено на сервере")
            raise HostBackupRejected(error, ERRORS.get(error, "Сервер отказал в задании полной копии."))
        return value

    def saved_request(self) -> HostBackupRequest | None:
        return self.request_store.load(self.options)

    def operation_status(self, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        return self._operation(self._operation_action("status", identity), identity)

    def operation_list(self) -> tuple[HostBackupOperation, ...]:
        value = self._operation_action("list")
        records = value.get("operations")
        if (set(value) != {"ok", "protocol", "operations"} or
                not isinstance(records, list) or len(records) > 100):
            raise InstallError("Сервер прислал неверную историю полных копий")
        operations = tuple(self._operation(record) for record in records)
        if len({item.request_id for item in operations}) != len(operations):
            raise InstallError("Сервер прислал повторяющиеся задания")
        return operations

    def start_online(self, reviewed: HostBackupState, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        if (reviewed.options != self.options or
                reviewed.manifest_sha256 != self.approved_manifest_sha256 or
                self.inspect() != reviewed):
            raise InstallError("План или серверный пакет изменились. Обновите список")
        current = self.saved_request()
        if current is not None:
            previous = self.operation_status(current.request_id)
            if not previous.terminal:
                raise InstallError("На этом SSH-маршруте есть незавершённая полная копия. "
                                   "Проверьте её состояние")
        marker = HostBackupRequest.new(self.options, identity, self.approved_manifest_sha256)
        self.request_store.save(marker, replacing=current.request_id if current else None)
        self.progress("Задание сохранено. Сервер остановит только свои записывающие службы…")
        try:
            value = self._operation_action("start", identity)
            return self._operation(value, identity)
        except HostBackupRejected as exc:
            # A structured start refusal is definitive: the server writes an
            # accepted journal before it can return ok:true. Remove only our
            # exact local marker so the user can revise the plan and retry.
            if self.saved_request() == marker:
                self.request_store.clear(marker)
            raise
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.operation_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о запуске потерян. Запрос сохранён; проверьте его "
                                   "состояние, не запускайте новую копию") from exc

    def recover_operation(self, request_id: str) -> HostBackupOperation:
        identity = _id(request_id)
        before = self.operation_status(identity)
        if before.terminal:
            raise InstallError("Восстановление служб не требуется для этого задания")
        self.progress("Сервер запускает только службы, остановленные для этой копии…")
        try:
            return self._operation(self._operation_action("recover", identity), identity)
        except (InstallError, OSError, subprocess.TimeoutExpired) as exc:
            try:
                return self.operation_status(identity)
            except (InstallError, OSError, subprocess.TimeoutExpired):
                raise InstallError("Ответ о восстановлении служб потерян. Запрос сохранён; "
                                   "проверьте его состояние, не повторяйте действие вслепую") from exc
