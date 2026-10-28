# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Graphical setup for the promoted Hub's isolated read-only Docker snapshot."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .local_container_inventory import (LocalContainerInventoryController,
                                        LocalContainerInventoryState)


class LocalContainerInventoryDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: LocalContainerInventoryController | None = None
        self.state: LocalContainerInventoryState | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Проверьте локальный Agent и настройки Docker без изменений сервера."
            if approved_manifest_sha256 else
            "Функция ждёт проверенный серверный выпуск с отдельным Docker-сборщиком."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Docker своего Hub · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("770x510")
        self.window.minsize(620, 430)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1)
        ttk.Label(body, text="Docker-мониторинг собственного Hub",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(body, text="SSH-маршрут: " + route, wraplength=720).grid(
            row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(body, text=(
            "Сборщик читает Docker от root и передаёт локальному Agent только ограниченный "
            "снимок контейнеров. Он работает через отдельную группу и папку. Внешний Agent, "
            "его данные и обратные туннели сохраняются. Это включает мониторинг; права "
            "запуска и остановки контейнеров настраиваются отдельно."
        ), wraplength=720).grid(row=2, column=0, sticky="w", pady=(10, 8))
        ttk.Label(body, text=(
            "Для изменения нужен SSH-вход root либо действующее sudo без запроса пароля. "
            "Перед действием мастер ещё раз сверит установленный пакет и состояние сервера. "
            "Если операция оборвётся, сначала восстановите её в этом окне."
        ), wraplength=720).grid(row=3, column=0, sticky="w")
        self.details = tk.Text(body, height=10, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky="nsew", pady=(12, 8))
        ttk.Label(body, textvariable=self.status, wraplength=720).grid(row=5, column=0, sticky="w")
        actions = ttk.Frame(body)
        actions.grid(row=6, column=0, sticky="w", pady=(12, 0))
        self.check_button = ttk.Button(actions, text="Проверить без изменений", command=self.check,
                                       state="normal" if approved_manifest_sha256 else "disabled")
        self.check_button.pack(side="left")
        self.change_button = ttk.Button(actions, text="Включить мониторинг", command=self.change,
                                        state="disabled")
        self.change_button.pack(side="left", padx=(8, 0))
        self.recover_button = ttk.Button(actions, text="Восстановить", command=self.recover,
                                         state="disabled")
        self.recover_button.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Закрыть", command=self.close).pack(side="left", padx=(8, 0))
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> LocalContainerInventoryController:
        if self.controller is None:
            self.controller = LocalContainerInventoryController(
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
        ready = state is not None and state.phase == "ready"
        self.check_button.configure(state="disabled" if self.busy or not self.approved_manifest_sha256 else "normal")
        self.change_button.configure(state="normal" if ready and not self.busy else "disabled",
                                     text=("Выключить мониторинг" if state and state.enabled else
                                           "Включить мониторинг"))
        self.recover_button.configure(state=("normal" if state is not None and
                                             state.phase == "recovery_required" and not self.busy else "disabled"))

    def _render(self, state: LocalContainerInventoryState) -> None:
        self.state = state
        lines = [f"SSH: {state.options.user}@{state.options.host}:{state.options.port}",
                 f"Проверенный манифест: {state.manifest_sha256}",
                 f"Локальный Agent: {state.local_server_id}"]
        if state.phase == "recovery_required":
            lines.extend(("", "Незавершённая операция: новые изменения заблокированы.",
                          "Прежнее состояние: " + ("включено" if state.enabled else "выключено"),
                          "Запрашивалось: " + ("включить" if state.requested_enabled else "выключить"),
                          "Восстановление вернёт прежнее состояние после подтверждения."))
            self.status.set("Требуется восстановление прерванной операции.")
        else:
            lines.extend(("", "Мониторинг: " + ("включён" if state.enabled else "выключен"),
                          "Таймер: " + ("активен" if state.collector_active else "неактивен"),
                          "Снимок Docker: " + ("свежий" if state.snapshot_fresh else "пока недоступен"),
                          "Ревизия: " + str(state.state_revision),
                          "Внешний Agent и туннели подтверждены."))
            self.status.set("Настройки проверены." if not state.enabled or state.snapshot_fresh else
                            "Мониторинг включён, но свежего снимка пока нет. Повторите проверку.")
        self._show("\n".join(lines))
        self._controls()

    def _start(self, label: str, action) -> None:
        if self.busy:
            return
        self.busy = True
        self._controls()
        self.status.set(label)

        def worker() -> None:
            try:
                self.events.put(("result", action()))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.state = None
        self._controls()
        self._start("Проверка локального и внешнего Agent без изменений…", self._controller().preview)

    def change(self) -> None:
        state = self.state
        if self.busy or state is None or state.phase != "ready":
            return
        enabled = not state.enabled
        action = "Включить" if enabled else "Выключить"
        if not messagebox.askyesno(
            "Подтвердить Docker-мониторинг",
            f"{action} Docker-мониторинг локального Hub на "
            f"{state.options.user}@{state.options.host}:{state.options.port}?\n"
            f"Манифест: {state.manifest_sha256}\n"
            f"Локальный Agent: {state.local_server_id}\n"
            f"Ревизия: {state.state_revision}\n\n"
            "Сборщик будет читать Docker от root. Управляющие команды этим действием не разрешаются. "
            "Внешний Agent и обратные туннели сохраняются.", parent=self.window,
        ):
            return
        self._start(action + " мониторинг и проверка результата…",
                    lambda: self._controller().change(enabled, state))

    def recover(self) -> None:
        state = self.state
        if self.busy or state is None or state.phase != "recovery_required":
            return
        if not messagebox.askyesno(
            "Восстановить Docker-мониторинг",
            f"Вернуть прежнее состояние на {state.options.user}@{state.options.host}:{state.options.port}?\n"
            f"Манифест: {state.manifest_sha256}\n"
            f"Локальный Agent: {state.local_server_id}\n\n"
            "Сервер проверит внешний Agent и остановит незавершённую настройку.", parent=self.window,
        ):
            return
        self._start("Восстановление прежнего Docker-мониторинга…",
                    lambda: self._controller().recover(state))

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
                if isinstance(payload, LocalContainerInventoryState):
                    self._render(payload)
                else:
                    self.state = None
                    self._controls()
                    self.status.set("Сервер прислал неверный результат; повторите проверку.")
            elif event == "error":
                self.busy = False
                self.state = None
                self._controls()
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Действие не подтверждено. Повторите проверку сервера; вывод SSH скрыт."
                )
                self.status.set(message)
                messagebox.showerror("Docker своего Hub", message, parent=self.window)
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Docker своего Hub", "Дождитесь результата действия или повторной проверки.",
                                parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
