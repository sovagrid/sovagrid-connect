# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewed SSH status and compare-and-swap control of the signed feed."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from typing import Callable

from .core import ConnectionOptions
from .installer import InstallError
from .local_operations import _json
from .promotion import PromotionController
from .release_feed_remote import MUTATION_SCRIPT, SCRIPT


SHA = re.compile(r"[0-9a-f]{64}\Z")
KEY_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")


@dataclass(frozen=True)
class ReleaseFeedState:
    options: ConnectionOptions
    manifest_sha256: str
    units_verified: bool
    enabled: bool
    key_id: str | None
    available_keys: tuple[tuple[str, str], ...]
    timer_active: bool
    manual_candidate_active: bool
    highest_sequence: int
    highest_version: str
    last_seen_at: int
    timer_enabled: bool = False
    state_revision: str | None = None


class ReleaseFeedController:
    def __init__(self, options: ConnectionOptions, *, approved_manifest_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_manifest_sha256 is not None and SHA.fullmatch(approved_manifest_sha256) is None:
            raise InstallError("SHA-256 проверенного серверного выпуска неверен")
        self.transport = transport or PromotionController(
            options, approved_archive_sha256="0" * 64, popen=popen, progress=progress,
        )
        self.options = self.transport.options
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.progress = progress or (lambda _message: None)
        self._reviewed_state: ReleaseFeedState | None = None

    def _state(self, raw: bytes) -> ReleaseFeedState:
        result = _json(raw)
        feed = result.get("feed")
        if (set(result) != {"protocol", "source_manifest_sha256", "units_verified", "feed"} or
                result["source_manifest_sha256"] != self.approved_manifest_sha256 or
                type(result["units_verified"]) is not bool or not isinstance(feed, dict) or
                set(feed) != {"format", "channel", "enabled", "key_id", "available_keys",
                              "timer_installed", "timer_enabled", "timer_active",
                              "manual_candidate_active", "installed_manifest_sha256",
                              "state_revision", "ledger"} or
                type(feed["format"]) is not int or feed["format"] != 1 or
                feed["channel"] != "stable" or
                any(type(feed[key]) is not bool for key in
                    ("enabled", "timer_installed", "timer_enabled", "timer_active",
                     "manual_candidate_active")) or
                feed["timer_installed"] is not result["units_verified"] or
                (feed["timer_active"] and not feed["timer_installed"]) or
                feed["installed_manifest_sha256"] != self.approved_manifest_sha256 or
                not isinstance(feed["state_revision"], str) or
                SHA.fullmatch(feed["state_revision"]) is None):
            raise InstallError("Сервер прислал неверный статус подписанного канала")
        keys = feed["available_keys"]
        selected = feed["key_id"]
        if (not isinstance(keys, dict) or len(keys) > 16 or
                any(not isinstance(key, str) or KEY_ID.fullmatch(key) is None or
                    not isinstance(fingerprint, str) or SHA.fullmatch(fingerprint) is None
                    for key, fingerprint in keys.items()) or
                (selected is not None and
                 (not isinstance(selected, str) or KEY_ID.fullmatch(selected) is None)) or
                feed["enabled"] is not (selected is not None)):
            raise InstallError("Сервер прислал неверное состояние доверенных ключей")
        ledger = feed["ledger"]
        if (not isinstance(ledger, dict) or
                set(ledger) != {"format", "highest_sequence", "highest_version",
                                "highest_issued_at", "last_seen_at"} or
                type(ledger["format"]) is not int or ledger["format"] != 1 or
                any(type(ledger[key]) is not int or ledger[key] < 0 for key in
                    ("highest_sequence", "highest_issued_at", "last_seen_at")) or
                not isinstance(ledger["highest_version"], str) or
                VERSION.fullmatch(ledger["highest_version"]) is None):
            raise InstallError("Сервер прислал неверный журнал подписанного канала")
        return ReleaseFeedState(
            self.options, result["source_manifest_sha256"], result["units_verified"],
            feed["enabled"], selected, tuple(sorted(keys.items())), feed["timer_active"],
            feed["manual_candidate_active"], ledger["highest_sequence"],
            ledger["highest_version"], ledger["last_seen_at"],
            feed["timer_enabled"], feed["state_revision"],
        )

    def preview(self) -> ReleaseFeedState:
        self._reviewed_state = None
        manifest = self.approved_manifest_sha256
        if manifest is None:
            raise InstallError("Подписанный канал ждёт проверенный серверный выпуск")
        self.progress("Проверка SSH-маршрута, исходников, systemd и ключей без изменений…")
        self.transport._verify_root_access()
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " +
                   shlex.quote(SCRIPT) + " status " + manifest)
        code, raw = self.transport._execute(command, timeout=120)
        if code != 0:
            raise InstallError("Сервер не подтвердил точный исходный код или units канала; "
                               "состояние не изменено")
        state = self._state(raw)
        self._reviewed_state = state
        return state

    def _change(self, state: ReleaseFeedState, action: str, key_id: str) -> ReleaseFeedState:
        if (state is not self._reviewed_state or
                state.options != self.options or
                state.manifest_sha256 != self.approved_manifest_sha256 or
                state.state_revision is None or SHA.fullmatch(state.state_revision) is None):
            raise InstallError("Сначала повторно проверьте состояние подписанного канала")
        if action == "enable":
            if (state.enabled or not state.units_verified or
                    not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None or
                    key_id not in dict(state.available_keys)):
                raise InstallError("Для включения нужен проверенный встроенный ключ и systemd таймер")
        elif action == "disable":
            if not state.enabled or key_id != "-":
                raise InstallError("Подписанный канал уже выключен; повторите проверку")
        else:
            raise InstallError("Неизвестное действие подписанного канала")
        if self.preview() != state:
            raise InstallError("Состояние канала изменилось; повторите проверку")
        self._reviewed_state = None
        self.progress("Сервер проверяет ревизию под root-блокировкой…")
        command = (self.transport._privileged + "/usr/bin/python3 -I -c " +
                   shlex.quote(MUTATION_SCRIPT) + " mutate " +
                   state.manifest_sha256 + " " + action + " " +
                   state.state_revision + " " + key_id)
        code, raw = self.transport._execute(command, timeout=300, limit=512)
        if code != 0:
            if raw == b"SG_RELEASE_FEED_CLIENT_REFUSE:STATE_CHANGED\n":
                raise InstallError("Состояние канала изменилось; повторите проверку")
            raise InstallError("Сервер не подтвердил изменение канала. "
                               "Проверьте статус заново: результат мог быть частичным")
        if raw != ("SG_RELEASE_FEED_CLIENT_APPLIED:" + action + "\n").encode():
            raise InstallError("Ответ сервера не подтвердил изменение канала; "
                               "проверьте статус заново")
        try:
            result = self.preview()
        except Exception as exc:
            raise InstallError("Команда могла выполниться, но повторная проверка не удалась. "
                               "Откройте статус канала заново") from exc
        if (result.enabled is not (action == "enable") or
                (action == "enable" and
                 (result.key_id != key_id or not result.timer_enabled or
                  not result.timer_active)) or
                (action == "disable" and (result.timer_enabled or result.timer_active))):
            self._reviewed_state = None
            raise InstallError("Результат изменения канала отличается от плана; "
                               "проверьте сервер заново")
        return result

    def enable(self, state: ReleaseFeedState, key_id: str) -> ReleaseFeedState:
        return self._change(state, "enable", key_id)

    def disable(self, state: ReleaseFeedState) -> ReleaseFeedState:
        return self._change(state, "disable", "-")
