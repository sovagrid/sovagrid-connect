# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Separate graphical consent for command access on a promoted local Agent."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .local_commands import LocalCommandsController, LocalCommandsState


class LocalCommandsDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: LocalCommandsController | None = None
        self.state: LocalCommandsState | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Сначала проверьте локальный Agent без изменений сервера."
            if approved_manifest_sha256 else
            "Функция ждёт проверенный серверный выпуск."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Команды локального Agent · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("760x440")
        self.window.minsize(620, 390)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1)
        ttk.Label(body, text="Разрешение команд своему локальному Agent",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        self.route_label = ttk.Label(body, text="SSH-маршрут: " + route, wraplength=710)
        self.route_label.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(body, text=(
            "Разрешение команд даёт администраторам собственного Hub возможность выполнять действия "
            "через второго Agent. Это нужно для терминала и файлов, но выдаётся отдельно. "
            "Права определяются ролями Hub; используйте только доверенные учётные записи. "
            "Нужен SSH-вход root или уже действующее sudo без запроса пароля. "
            "Внешний Agent и его обратный SSH-туннель останутся отдельными."
        ), wraplength=710).grid(row=2, column=0, sticky="w", pady=(10, 8))
        ttk.Label(body, text=(
            "Проверка только читает состояние. Включение перезапустит второй Agent и может прервать "
            "его текущие сеансы. При отказе или обрыве связи повторно проверьте состояние: "
            "частичный результат не считается откатом. Выключение команд здесь пока недоступно."
        ), wraplength=710).grid(row=3, column=0, sticky="w")
        self.details = tk.Text(body, height=8, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky="nsew", pady=(10, 8))
        ttk.Label(body, textvariable=self.status, wraplength=710).grid(row=5, column=0, sticky="w")
        actions = ttk.Frame(body)
        actions.grid(row=6, column=0, sticky="w", pady=(10, 0))
        self.check_button = ttk.Button(
            actions, text="Проверить без изменений", command=self.check,
            state="normal" if approved_manifest_sha256 else "disabled")
        self.check_button.pack(side="left")
        self.enable_button = ttk.Button(actions, text="Разрешить команды", command=self.enable,
                                        state="disabled")
        self.enable_button.pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Закрыть", command=self.close).pack(side="left", padx=(8, 0))
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> LocalCommandsController:
        if self.controller is None:
            self.controller = LocalCommandsController(
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
        self.check_button.configure(state="disabled" if self.busy or not self.approved_manifest_sha256 else "normal")
        self.enable_button.configure(state=("normal" if state is not None and
                                            not state.commands_enabled and not self.busy else "disabled"))

    def _render(self, state: LocalCommandsState) -> None:
        self.state = state
        self._show("\n".join((
            f"SSH: {state.options.user}@{state.options.host}:{state.options.port}",
            f"Проверенный манифест: {state.manifest_sha256}",
            f"Локальный Agent: {state.local_server_id}",
            "Команды: " + ("разрешены" if state.commands_enabled else "выключены"),
            f"Ревизия состояния: {state.state_revision}",
            "Внешний Agent и его туннель подтверждены.",
        )))
        self.status.set("Команды уже разрешены." if state.commands_enabled else
                        "Проверка завершена. Разрешение команд требует отдельного подтверждения.")
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
        self._start("Проверка локального Hub и внешнего Agent без изменений…",
                    self._controller().preview)

    def enable(self) -> None:
        state = self.state
        if self.busy or state is None or state.commands_enabled:
            return
        if not messagebox.askyesno(
            "Разрешить команды локального Agent",
            f"Разрешить команды второго Agent на {state.options.user}@{state.options.host}:{state.options.port}?\n"
            f"Манифест: {state.manifest_sha256}\n"
            f"Локальный Agent: {state.local_server_id}\n"
            f"Ревизия: {state.state_revision}\n\n"
            "Администраторы собственного Hub с соответствующей ролью смогут выполнять команды. "
            "Второй Agent будет перезапущен. Внешний Agent и туннель останутся отдельными.",
            parent=self.window,
        ):
            return
        self._start("Включение команд после повторной серверной проверки…",
                    lambda: self._controller().enable(state))

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
                if isinstance(payload, LocalCommandsState):
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
                    "Действие не подтверждено. Повторите проверку сервера; вывод SSH скрыт.")
                self.status.set(message)
                messagebox.showerror("Команды локального Agent", message, parent=self.window)
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Команды локального Agent",
                                "Дождитесь завершения действия или повторной проверки.", parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
