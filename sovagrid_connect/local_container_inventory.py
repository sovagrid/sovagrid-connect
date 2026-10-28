# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewed root SSH setup for the promoted Hub's isolated Docker inventory."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import shlex
import subprocess
from typing import Callable
import uuid

from .core import ConnectionOptions
from .installer import InstallError
from .local_operations import _unique
from .promotion import PromotionController


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HELPER = "/opt/sovagrid-src/sovagrid-blueprint/deploy/local_container_inventory.py"

# This runs before any installed helper. It checks exactly the executable and
# imported source against the approved root-owned bundle, including the pin.
_SOURCE_PROBE = r'''
import hashlib, json, os, pathlib, re, stat, sys, uuid
expected = sys.argv[1]
assert re.fullmatch('[0-9a-f]{64}', expected)
root = pathlib.Path('/opt/sovagrid-src')
for path in (pathlib.Path('/opt'), root, root/'sovagrid-blueprint',
             root/'sovagrid-blueprint/deploy', root/'sovagrid-agent',
             root/'sovagrid-agent/deploy', pathlib.Path('/var/lib/sovagrid-promotion')):
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
def checked(path, modes, maximum):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
    assert info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes
    assert 0 < info.st_size <= maximum
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        assert (opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size)
        value = stream.read(maximum + 1)
    assert len(value) == info.st_size
    return value
manifest_raw = checked(root/'sovagrid-bundle.json', {0o644}, 524288)
assert hashlib.sha256(manifest_raw).hexdigest() == expected
manifest = json.loads(manifest_raw)
assert isinstance(manifest, dict) and set(manifest) == {'format', 'components', 'sha256'}
assert type(manifest['format']) is int and manifest['format'] == 1
hashes = manifest['sha256']
assert isinstance(hashes, dict)
for relative in ('sovagrid-blueprint/deploy/local_container_inventory.py',
                 'sovagrid-blueprint/deploy/local_operations.py',
                 'sovagrid-blueprint/deploy/promote_agent_only.py',
                 'sovagrid-agent/deploy/sovagrid-container-inventory-local.service',
                 'sovagrid-agent/deploy/sovagrid-container-inventory-local.timer'):
    digest = hashes.get(relative)
    assert isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest)
    value = checked(root/relative, {0o644, 0o755}, 1048576)
    assert hashlib.sha256(value).hexdigest() == digest
pin = json.loads(checked(pathlib.Path('/var/lib/sovagrid-promotion/bundle-pin.json'), {0o600}, 32768))
assert isinstance(pin, dict) and set(pin) == {'protocol', 'manifest_sha256'}
assert type(pin['protocol']) is int and pin['protocol'] == 1 and pin['manifest_sha256'] == expected
local = json.loads(checked(pathlib.Path('/var/lib/sovagrid-promotion/local-agent.json'), {0o600}, 32768))
assert isinstance(local, dict) and set(local) == {'protocol', 'server_id', 'token_sha256', 'commands'}
assert type(local['protocol']) is int and local['protocol'] == 1
server_id = local['server_id']
assert isinstance(server_id, str) and str(uuid.UUID(server_id)) == server_id
assert type(local['commands']) is bool
print(json.dumps({'protocol': 1, 'manifest_sha256': expected,
                  'local_server_id': server_id}, separators=(',', ':')))
'''


def _json(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise InstallError("Ответ локального Docker-сборщика слишком велик")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError) as exc:
        raise InstallError("Сервер прислал неверное состояние Docker-сборщика") from exc
    if not isinstance(value, dict) or type(value.get("protocol")) is not int or value["protocol"] != 1:
        raise InstallError("Сервер прислал неподдерживаемое состояние Docker-сборщика")
    return value


@dataclass(frozen=True)
class LocalContainerInventoryState:
    options: ConnectionOptions
    manifest_sha256: str
    local_server_id: str
    phase: str
    enabled: bool
    requested_enabled: bool | None
    collector_active: bool | None
    snapshot_fresh: bool | None
    state_revision: str | None


class LocalContainerInventoryController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_manifest_sha256 is not None and _SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного серверного выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress)
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _run(self, command: str, *, timeout: float = 90) -> tuple[int, bytes]:
        return self.transport._execute(self.transport._privileged + command, timeout=timeout)

    def _source(self) -> tuple[str, str]:
        approved = self.approved_manifest_sha256
        if approved is None:
            raise InstallError("Для локального Docker-сборщика нужен проверенный серверный выпуск")
        self.transport._verify_root_access()
        code, raw = self._run("/usr/bin/python3 -I -B -S -c " + shlex.quote(_SOURCE_PROBE) + " " + approved)
        if code != 0:
            raise InstallError("Код Docker-сборщика на сервере не совпадает с проверенным выпуском")
        value = _json(raw)
        if (set(value) != {"protocol", "manifest_sha256", "local_server_id"} or
                value["manifest_sha256"] != approved or
                not isinstance(value["local_server_id"], str)):
            raise InstallError("Сервер прислал неверное подтверждение исходников")
        try:
            if str(uuid.UUID(value["local_server_id"])) != value["local_server_id"]:
                raise ValueError("noncanonical UUID")
        except ValueError as exc:
            raise InstallError("Сервер прислал неверный ID локального Agent") from exc
        return approved, value["local_server_id"]

    def _helper(self, action: str, *, expected_state: str | None = None,
                timeout: float = 90) -> tuple[int, bytes]:
        if (action not in {"preview", "enable", "disable", "recover"} or
                (action in {"enable", "disable"}) != (expected_state is not None) or
                (expected_state is not None and _SHA.fullmatch(expected_state) is None)):
            raise ValueError("unsupported local inventory action")
        command = "/usr/bin/python3 -I -B " + _HELPER + " " + action
        if expected_state is not None:
            command += " --expected-state " + expected_state
        return self._run(command, timeout=timeout)

    @staticmethod
    def _failure(raw: bytes) -> InstallError:
        lines = raw.splitlines()
        if b"SG_LOCAL_CONTAINERS_REFUSE:ROLLED_BACK" in lines:
            return InstallError("Изменение не удалось; прежние настройки Docker-сборщика восстановлены")
        if b"SG_LOCAL_CONTAINERS_REFUSE:ROLLBACK_NEEDS_RECOVERY" in lines:
            return InstallError("Изменение прервано; требуется восстановление в этом мастере")
        if b"SG_LOCAL_CONTAINERS_REFUSE:STATE_CHANGED" in lines:
            return InstallError("Настройки Docker-сборщика изменились; повторите проверку")
        if b"SG_LOCAL_CONTAINERS_REFUSE:RECOVERY_REQUIRED" in lines:
            return InstallError("Сначала восстановите незавершённую настройку Docker-сборщика")
        if b"SG_LOCAL_CONTAINERS_REFUSE:EXTERNAL_CHANGED" in lines:
            return InstallError("Внешний Agent изменился; локальная настройка остановлена")
        if b"SG_LOCAL_CONTAINERS_REFUSE:SOURCE_PIN" in lines:
            return InstallError("Версия сервера изменилась; проверьте пакет заново")
        return InstallError("Сервер отклонил настройку Docker-сборщика; проверьте состояние")

    def _state(self, raw: bytes, manifest: str, local_id: str) -> LocalContainerInventoryState:
        value = _json(raw)
        if (value.get("manifest_sha256") != manifest or
                value.get("local_server_id") != local_id or
                value.get("external_agent_preserved") is not True):
            raise InstallError("Сервер не подтвердил локальный и внешний Agent")
        phase = value.get("phase")
        if phase == "ready":
            if (set(value) != {"protocol", "phase", "enabled", "manifest_sha256",
                               "local_server_id", "external_agent_preserved", "state_revision",
                               "collector_active", "snapshot_fresh"} or
                    type(value["enabled"]) is not bool or
                    type(value["collector_active"]) is not bool or
                    type(value["snapshot_fresh"]) is not bool or
                    not isinstance(value["state_revision"], str) or
                    _SHA.fullmatch(value["state_revision"]) is None or
                    (not value["enabled"] and (value["collector_active"] or value["snapshot_fresh"]))):
                raise InstallError("Сервер прислал неверные настройки Docker-сборщика")
            return LocalContainerInventoryState(self.options, manifest, local_id, phase,
                                                value["enabled"], None,
                                                value["collector_active"], value["snapshot_fresh"],
                                                value["state_revision"])
        if phase == "recovery_required":
            if (set(value) != {"protocol", "phase", "previous_enabled", "requested_enabled",
                               "manifest_sha256", "local_server_id", "external_agent_preserved",
                               "state_revision"} or
                    type(value["previous_enabled"]) is not bool or
                    type(value["requested_enabled"]) is not bool or
                    value["previous_enabled"] == value["requested_enabled"] or
                    value["state_revision"] is not None):
                raise InstallError("Сервер прислал неверный журнал Docker-сборщика")
            return LocalContainerInventoryState(self.options, manifest, local_id, phase,
                                                value["previous_enabled"],
                                                value["requested_enabled"], None, None, None)
        raise InstallError("Сервер прислал неизвестный этап настройки Docker-сборщика")

    def preview(self) -> LocalContainerInventoryState:
        self.progress("Проверка локального Agent, внешнего туннеля и Docker-сборщика…")
        manifest, local_id = self._source()
        code, raw = self._helper("preview")
        if code != 0:
            raise self._failure(raw)
        return self._state(raw, manifest, local_id)

    def _recheck(self, expected: LocalContainerInventoryState) -> None:
        if (expected.options != self.options or
                expected.manifest_sha256 != self.approved_manifest_sha256 or
                self.preview() != expected):
            raise InstallError("Состояние сервера изменилось; повторите проверку перед действием")

    def change(self, enabled: bool, expected: LocalContainerInventoryState) -> LocalContainerInventoryState:
        if type(enabled) is not bool or expected.phase != "ready":
            raise InstallError("Сначала проверьте состояние Docker-сборщика")
        self._recheck(expected)
        if expected.state_revision is None:
            raise InstallError("Сервер не подтвердил ревизию настроек Docker-сборщика")
        if expected.enabled == enabled:
            return expected
        self.progress("Настройка изолированного Docker-сборщика…")
        try:
            code, raw = self._helper("enable" if enabled else "disable",
                                     expected_state=expected.state_revision, timeout=420)
            if code != 0:
                raise self._failure(raw)
            result = self._state(raw, expected.manifest_sha256, expected.local_server_id)
            if (result.phase != "ready" or result.enabled != enabled or
                    (enabled and (not result.collector_active or not result.snapshot_fresh))):
                raise InstallError("Сервер не подтвердил изменение Docker-сборщика")
        except Exception as exc:
            # A lost SSH reply is never retried as a mutation. A fresh status
            # can still confirm completion or expose a pending recovery.
            try:
                observed = self.preview()
                if observed.phase == "ready" and observed.enabled == enabled:
                    return observed
            except Exception:
                pass
            if isinstance(exc, InstallError):
                raise
            raise InstallError("Ответ сервера не получен; проверьте состояние Docker-сборщика") from exc
        after = self.preview()
        if after.phase != "ready" or after.enabled != enabled or after.state_revision != result.state_revision:
            raise InstallError("Сервер изменился после настройки; повторите проверку")
        return after

    def recover(self, expected: LocalContainerInventoryState) -> LocalContainerInventoryState:
        if expected.phase != "recovery_required":
            raise InstallError("На сервере нет подтверждённой операции для восстановления")
        self._recheck(expected)
        self.progress("Восстановление прежнего состояния Docker-сборщика…")
        try:
            code, raw = self._helper("recover", timeout=420)
            if code != 0:
                raise self._failure(raw)
            result = self._state(raw, expected.manifest_sha256, expected.local_server_id)
        except Exception as exc:
            try:
                observed = self.preview()
                if observed.phase == "ready" and observed.enabled == expected.enabled:
                    return observed
            except Exception:
                pass
            if isinstance(exc, InstallError):
                raise
            raise InstallError("Ответ сервера не получен; проверьте восстановление Docker-сборщика") from exc
        after = self.preview()
        if (result.phase != "ready" or result.enabled != expected.enabled or
                after.phase != "ready" or after.enabled != expected.enabled or
                after.state_revision != result.state_revision):
            raise InstallError("Сервер не подтвердил восстановление Docker-сборщика")
        return after
