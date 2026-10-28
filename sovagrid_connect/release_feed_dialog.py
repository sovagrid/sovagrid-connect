# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewed control of a server's signed update channel."""

from __future__ import annotations

from datetime import datetime, timezone
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .release_feed import ReleaseFeedController, ReleaseFeedState


class ReleaseFeedDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: ReleaseFeedController | None = None
        self.state: ReleaseFeedState | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Проверка только читает локальное состояние сервера."
            if approved_manifest_sha256 else "Ожидается проверенный серверный выпуск с подписанным каналом."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Подписанные обновления · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("790x500")
        self.window.minsize(650, 440)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(5, weight=1)
        ttk.Label(body, text="Подписанный канал обновлений сервера",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        self.route_label = ttk.Label(body, text="SSH-маршрут: " + route, wraplength=740)
        self.route_label.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(body, text=(
            "Канал доверяет только публичным ключам, встроенным в проверенный серверный выпуск. "
            "Отпечаток ниже — SHA-256 DER SPKI. Ключ из сети не загружается. "
            "Для проверки нужен SSH-вход root или действующее sudo без запроса пароля."
        ), wraplength=740).grid(row=2, column=0, sticky="w", pady=(10, 8))
        ttk.Label(body, text=(
            "Разрешение на одно заранее выбранное обновление действует отдельно. "
            "Отключение подписанного канала его не отменит. Перед изменением сервер "
            "повторно проверяет исходники и ревизию состояния под root-блокировкой."
        ), wraplength=740).grid(row=3, column=0, sticky="w")
        key_row = ttk.Frame(body)
        key_row.grid(row=4, column=0, sticky="w", pady=(10, 0))
        ttk.Label(key_row, text="Встроенный ключ:").pack(side="left")
        self.key_value = tk.StringVar(value="Пока не проверен")
        self.key_selector = ttk.Combobox(key_row, textvariable=self.key_value,
                                         state="disabled", width=40)
        self.key_selector.pack(side="left", padx=(8, 0))
        self.key_selector.bind("<<ComboboxSelected>>", lambda _event: self._controls())
        self.details = tk.Text(body, height=9, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=5, column=0, sticky="nsew", pady=(10, 8))
        ttk.Label(body, textvariable=self.status, wraplength=740).grid(row=6, column=0, sticky="w")
        actions = ttk.Frame(body)
        actions.grid(row=7, column=0, sticky="w", pady=(10, 0))
        self.check_button = ttk.Button(
            actions, text="Проверить без изменений", command=self.check,
            state="normal" if approved_manifest_sha256 else "disabled")
        self.check_button.pack(side="left")
        self.enable_button = ttk.Button(actions, text="Включить канал", command=self.enable,
                                        state="disabled")
        self.enable_button.pack(side="left", padx=(8, 0))
        self.disable_button = ttk.Button(actions, text="Отключить канал", command=self.disable,
                                         state="disabled")
        self.disable_button.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Закрыть", command=self.close).pack(side="left", padx=(8, 0))
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> ReleaseFeedController:
        if self.controller is None:
            self.controller = ReleaseFeedController(
                self.options, approved_manifest_sha256=self.approved_manifest_sha256,
                progress=lambda value: self.events.put(("progress", value)),
            )
        return self.controller

    def _show(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")

    def _controls(self) -> None:
        state = self.state
        keys = dict(state.available_keys) if state is not None else {}
        can_change = (state is not None and not self.busy and
                      state.state_revision is not None and
                      self.approved_manifest_sha256 == state.manifest_sha256)
        self.check_button.configure(state=("disabled" if self.busy or
                                           self.approved_manifest_sha256 is None else "normal"))
        self.key_selector.configure(state=("readonly" if can_change and
                                           not state.enabled and keys else "disabled"))
        self.enable_button.configure(state=("normal" if can_change and
                                            not state.enabled and state.units_verified and
                                            self.key_value.get() in keys else "disabled"))
        self.disable_button.configure(state=("normal" if can_change and state.enabled else
                                             "disabled"))

    def _render(self, state: ReleaseFeedState) -> None:
        self.state = state
        keys = dict(state.available_keys)
        self.key_selector.configure(values=tuple(keys))
        current_key = self.key_value.get()
        self.key_value.set(state.key_id or (current_key if current_key in keys else
                           next(iter(keys)) if len(keys) == 1 else
                           "Выберите встроенный ключ" if keys else
                           "Нет встроенного доверенного ключа"))
        seen = (datetime.fromtimestamp(state.last_seen_at, tz=timezone.utc)
                .strftime("%Y-%m-%d %H:%M:%S UTC") if state.last_seen_at else "ещё не проверялся")
        lines = [
            f"Проверенный манифест исходников: {state.manifest_sha256}",
            "Systemd units: " + ("точно совпадают с исходниками" if state.units_verified else
                                "не установлены; включение невозможно"),
            "Канал: " + ("включён" if state.enabled else "выключен"),
            "Таймер: " + ("включён" if state.timer_enabled else "выключен") +
            (", активен" if state.timer_active else ", неактивен"),
            "Отдельное разрешение на один архив: " +
            ("есть, сохраняется при отключении канала" if state.manual_candidate_active else "нет"),
            f"Журнал: выпуск №{state.highest_sequence}, версия {state.highest_version}; "
            f"последняя проверка {seen}",
            f"Ревизия состояния: {state.state_revision}",
        ]
        lines.extend(f"Публичный ключ {key_id}: SHA-256 DER SPKI {fingerprint}"
                     for key_id, fingerprint in state.available_keys)
        retired_key = state.enabled and state.key_id not in keys
        if retired_key:
            lines.append(f"Настроенный ключ {state.key_id} больше не встроен в этот выпуск; "
                         "проверка новых выпусков остановлена до отключения канала.")
        elif not keys:
            lines.append("В этом выпуске нет встроенного доверенного ключа.")
        self._show("\n".join(lines))
        self.status.set("Настроенный ключ больше не доверен. Отключите канал после проверки." if
                        retired_key else
                        "Нет встроенного ключа; канал доступен только для просмотра." if not keys else
                        "Канал включён. Для отключения потребуется подтверждение." if state.enabled else
                        "Статус проверен. Выберите ключ и подтвердите включение.")
        self._controls()

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.state = None
        self.busy = True
        self._controls()
        self.status.set("Проверка серверного кода и units без изменений…")
        controller = self._controller()

        def worker() -> None:
            try:
                self.events.put(("result", controller.preview()))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def _change(self, action: str, state: ReleaseFeedState, key_id: str = "") -> None:
        self.busy = True
        self._controls()
        self.status.set("Проверка ревизии и изменение канала на сервере…")
        controller = self._controller()

        def worker() -> None:
            try:
                result = (controller.enable(state, key_id) if action == "enable" else
                          controller.disable(state))
                self.events.put(("mutated", (action, result)))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def enable(self) -> None:
        state = self.state
        if self.busy or state is None or state.enabled or not state.units_verified:
            return
        key_id = self.key_value.get()
        fingerprint = dict(state.available_keys).get(key_id)
        if fingerprint is None or state.state_revision is None:
            return
        if not messagebox.askyesno(
                "Включить подписанные обновления",
                f"Включить периодическую проверку обновлений на {state.options.user}@{state.options.host}?\n"
                f"Встроенный ключ: {key_id}\nОтпечаток SHA-256 DER SPKI: {fingerprint}\n"
                f"Проверенный манифест: {state.manifest_sha256}\n"
                f"Ревизия: {state.state_revision}\n\n"
                "Сервер проверит действующий подписанный канал перед включением таймера. "
                "Подписанный выпуск может быть установлен автоматически по правилам сервера.",
                parent=self.window):
            return
        self._change("enable", state, key_id)

    def disable(self) -> None:
        state = self.state
        if self.busy or state is None or not state.enabled or state.state_revision is None:
            return
        if not messagebox.askyesno(
                "Отключить подписанные обновления",
                f"Отключить проверку новых выпусков на {state.options.user}@{state.options.host}?\n"
                f"Ревизия: {state.state_revision}\n\n"
                "Отдельное разрешение на один заранее выбранный архив останется в силе.",
                parent=self.window):
            return
        self._change("disable", state)

    def _pump(self) -> None:
        if self.closed:
            return
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "progress":
                self.status.set(str(payload))
            elif event == "result":
                self.busy = False
                if isinstance(payload, ReleaseFeedState):
                    self._render(payload)
                else:
                    self.state = None
                    self.status.set("Сервер прислал неверный статус; повторите проверку.")
                    self._controls()
            elif event == "mutated":
                self.busy = False
                action, result = payload
                if action in ("enable", "disable") and isinstance(result, ReleaseFeedState):
                    self._render(result)
                    self.status.set("Канал включён и повторно проверен." if action == "enable" else
                                    "Канал отключён и повторно проверен.")
                else:
                    self.state = None
                    self.status.set("Ответ сервера не подтверждён; повторите проверку.")
                    self._controls()
            elif event == "error":
                self.busy = False
                self.state = None
                self._controls()
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Статус не подтверждён; вывод SSH скрыт.")
                self.status.set(message)
                messagebox.showerror("Подписанные обновления", message, parent=self.window)
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Подписанные обновления", "Дождитесь проверки сервера.",
                                parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
