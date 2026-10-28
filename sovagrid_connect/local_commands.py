# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit, compare-and-swap opt-in for commands on a promoted local Agent."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from typing import Callable
import uuid

from .core import ConnectionOptions
from .installer import InstallError
from .local_commands_remote import SCRIPT
from .local_operations import _json
from .promotion import PromotionController


_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class LocalCommandsState:
    options: ConnectionOptions
    manifest_sha256: str
    local_server_id: str
    commands_enabled: bool
    external_agent_preserved: bool
    state_revision: str


class LocalCommandsController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_manifest_sha256 is not None and _SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного серверного выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress,
        )
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)

    def _run(self, action: str, expected_state: str | None = None) -> tuple[int, bytes]:
        manifest = self.approved_manifest_sha256
        if manifest is None or action not in {"preview", "enable"} or (
                action == "preview" and expected_state is not None) or (
                action == "enable" and
                (expected_state is None or _SHA.fullmatch(expected_state) is None)):
            raise InstallError("Для команд локального Agent нужен проверенный серверный выпуск")
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " +
                   shlex.quote(SCRIPT) + " " + action + " " + manifest)
        if expected_state is not None:
            command += " " + expected_state
        return self.transport._execute(command, timeout=720 if action == "enable" else 120)

    @staticmethod
    def _failure(raw: bytes, *, action: str) -> InstallError:
        lines = set(raw.splitlines())
        if b"SG_LOCAL_COMMANDS_REFUSE:STATE_CHANGED" in lines or b"SG_LOCAL_COMMANDS_REFUSE:BUSY" in lines:
            return InstallError("Состояние локального Agent изменилось; повторите проверку")
        if b"SG_LOCAL_COMMANDS_REFUSE:COMMANDS_INCONSISTENT" in lines:
            return InstallError("Разрешение команд на сервере частично изменено; автоматическое действие остановлено")
        if action == "enable":
            return InstallError("Результат включения команд не подтверждён; проверьте сервер заново. "
                                "При частичном сбое требуется отдельная диагностика")
        return InstallError("Локальный Hub не подтвердил безопасное состояние команд; сервер не изменён")

    def _state(self, raw: bytes) -> LocalCommandsState:
        value = _json(raw)
        manifest = self.approved_manifest_sha256
        if (set(value) != {"protocol", "phase", "manifest_sha256", "local_server_id",
                           "commands_enabled", "external_agent_preserved", "state_revision"} or
                value["phase"] != "ready" or value["manifest_sha256"] != manifest or
                type(value["commands_enabled"]) is not bool or
                value["external_agent_preserved"] is not True or
                not isinstance(value["state_revision"], str) or
                _SHA.fullmatch(value["state_revision"]) is None or
                not isinstance(value["local_server_id"], str)):
            raise InstallError("Сервер прислал неверное подтверждение команд локального Agent")
        try:
            if str(uuid.UUID(value["local_server_id"])) != value["local_server_id"]:
                raise ValueError("noncanonical UUID")
        except ValueError as exc:
            raise InstallError("Сервер прислал неверный ID локального Agent") from exc
        return LocalCommandsState(self.options, manifest, value["local_server_id"],
                                  value["commands_enabled"], True, value["state_revision"])

    def preview(self) -> LocalCommandsState:
        if self.approved_manifest_sha256 is None:
            raise InstallError("Для команд локального Agent нужен проверенный серверный выпуск")
        self.progress("Проверка SSH-маршрута, исходников и разрешения команд без изменений…")
        self.transport._verify_root_access()
        code, raw = self._run("preview")
        if code != 0:
            raise self._failure(raw, action="preview")
        return self._state(raw)

    def enable(self, expected: LocalCommandsState) -> LocalCommandsState:
        if (expected.options != self.options or
                expected.manifest_sha256 != self.approved_manifest_sha256 or
                expected.external_agent_preserved is not True or
                expected.commands_enabled):
            raise InstallError("Для включения команд нужна свежая проверка сервера")
        if self.preview() != expected:
            raise InstallError("Состояние локального Agent изменилось; повторите проверку")
        self.progress("Сервер повторно проверяет ревизию и включает команды локального Agent…")
        code, raw = self._run("enable", expected.state_revision)
        if code != 0:
            raise self._failure(raw, action="enable")
        result = self._state(raw)
        if (not result.commands_enabled or
                result.local_server_id != expected.local_server_id or
                self.preview() != result):
            raise InstallError("Включение команд не подтвердилось после проверки сервера; "
                                "повторите проверку, возможен частичный результат")
        return result
