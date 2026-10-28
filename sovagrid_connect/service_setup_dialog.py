# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Graphical per-Agent allowlist for fixed systemd service actions."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .service_setup import ACTIONS, PROFILES, UNIT, ServiceSetupController, ServiceSetupState


LABELS = {"status": "Состояние", "start": "Запуск", "stop": "Остановка", "restart": "Перезапуск"}
PROFILE_LABELS = {"default": "Основной Agent", "local": "Локальный Agent своего Hub"}


class ServiceSetupDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: ServiceSetupController | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.state: ServiceSetupState | None = None
        self.reviewed: ServiceSetupState | None = None
        self.reviewed_units: dict[str, set[str]] | None = None
        self.units: dict[str, set[str]] = {}
        self.profile = tk.StringVar(value="default")
        self.unit = tk.StringVar()
        self.action_values = {action: tk.BooleanVar(value=action == "status") for action in ACTIONS}
        self.status = tk.StringVar(value=(
            "Сначала проверьте сервер. До подтверждения настройки не меняются."
            if approved_manifest_sha256 else "Мастер ждёт общий проверенный серверный выпуск."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Службы Agent · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("810x660")
        self.window.minsize(650, 550)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(7, weight=1)
        ttk.Label(body, text="Управление системными службами Agent",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(body, text="SSH-маршрут: " + route, wraplength=760).grid(
            row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(body, text=(
            "Выберите Agent, затем только те службы и действия, которые нужны администраторам Hub. "
            "Состояние обязательно для любого действия; перед запуском, остановкой или перезапуском "
            "панель проверяет его заново. Список ограничен шестнадцатью службами. "
            "Остановка SSH или сети может оборвать доступ."
        ), wraplength=760).grid(row=2, column=0, sticky="w", pady=(8, 6))
        profile_row = ttk.Frame(body)
        profile_row.grid(row=3, column=0, sticky="ew", pady=(3, 7))
        ttk.Label(profile_row, text="Agent:").pack(side="left")
        self.profile_choice = ttk.Combobox(profile_row, textvariable=self.profile,
                                           values=PROFILES, state="readonly", width=16)
        self.profile_choice.pack(side="left", padx=(8, 8))
        self.profile_description = ttk.Label(profile_row, text=PROFILE_LABELS["default"])
        self.profile_description.pack(side="left")
        editor = ttk.LabelFrame(body, text="Разрешение для службы", padding=10)
        editor.grid(row=4, column=0, sticky="ew")
        editor.columnconfigure(1, weight=1)
        ttk.Label(editor, text="Служба").grid(row=0, column=0, sticky="w")
        self.unit_choice = ttk.Combobox(editor, textvariable=self.unit, width=45)
        self.unit_choice.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(editor, text="Выберите службу из списка сервера или введите точное имя .service.",
                  wraplength=680).grid(row=1, column=0, columnspan=2, sticky="w", pady=(3, 5))
        action_row = ttk.Frame(editor)
        action_row.grid(row=2, column=0, columnspan=2, sticky="w")
        self.action_checks = {}
        for action in ACTIONS:
            checkbox = ttk.Checkbutton(action_row, text=LABELS[action], variable=self.action_values[action])
            checkbox.pack(side="left", padx=(0, 12))
            self.action_checks[action] = checkbox
        self.add_button = ttk.Button(editor, text="Добавить или обновить", command=self.add_unit)
        self.add_button.grid(row=3, column=0, columnspan=2, sticky="w", pady=(7, 0))
        list_frame = ttk.Frame(body)
        list_frame.grid(row=5, column=0, sticky="nsew", pady=(8, 3))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.list = ttk.Treeview(list_frame, columns=("unit", "actions"), show="headings", height=7)
        self.list.heading("unit", text="Служба")
        self.list.heading("actions", text="Разрешённые действия")
        self.list.column("unit", width=280)
        self.list.column("actions", width=350)
        self.list.grid(row=0, column=0, sticky="nsew")
        self.list.bind("<<TreeviewSelect>>", self._selected)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.list.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.list.configure(yscrollcommand=scroll.set)
        self.remove_button = ttk.Button(body, text="Убрать выбранную службу", command=self.remove_unit)
        self.remove_button.grid(row=6, column=0, sticky="w")
        self.details = tk.Text(body, height=5, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=7, column=0, sticky="nsew", pady=(10, 5))
        ttk.Label(body, textvariable=self.status, wraplength=760).grid(row=8, column=0, sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=9, column=0, sticky="ew", pady=(10, 0))
        self.check_button = ttk.Button(buttons, text="Проверить сервер", command=self.check)
        self.check_button.pack(side="left")
        self.plan_button = ttk.Button(buttons, text="Проверить план", command=self.plan)
        self.plan_button.pack(side="left", padx=(8, 0))
        self.arm_button = ttk.Button(buttons, text="Включить разрешения", command=self.arm)
        self.arm_button.pack(side="left", padx=(8, 0))
        self.disarm_button = ttk.Button(buttons, text="Выключить", command=self.disarm)
        self.disarm_button.pack(side="left", padx=(8, 0))
        self.close_button = ttk.Button(buttons, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        self.profile.trace_add("write", self._profile_changed)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> ServiceSetupController:
        if self.controller is None:
            self.controller = ServiceSetupController(
                self.options, approved_manifest_sha256=self.approved_manifest_sha256,
                progress=lambda value: self.events.put(("progress", value)))
        return self.controller

    def _show(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")

    def _controls(self) -> None:
        ready = not self.busy and self.approved_manifest_sha256 is not None
        self.check_button.configure(state="normal" if ready else "disabled")
        self.profile_choice.configure(state="readonly" if not self.busy else "disabled")
        for control in (self.unit_choice, self.add_button,
                        *(self.action_checks[action] for action in ACTIONS if action != "status")):
            control.configure(state="normal" if ready and self.state is not None else "disabled")
        self.action_checks["status"].configure(state="disabled")
        self.remove_button.configure(state="normal" if ready and self.list.selection() else "disabled")
        self.plan_button.configure(state="normal" if ready and self.state is not None and self.units else "disabled")
        self.arm_button.configure(state="normal" if ready and self.reviewed is not None else "disabled")
        self.disarm_button.configure(state="normal" if ready and self.state is not None and
                                     self.state.armed else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def _profile_changed(self, *_args) -> None:
        self.profile_description.configure(text=PROFILE_LABELS.get(self.profile.get(), ""))
        self.state = self.reviewed = self.reviewed_units = None
        self.units.clear()
        self._render_units()
        self._show("")
        self.status.set("Профиль Agent изменён. Проверьте сервер заново.")
        self._controls()

    def _render_units(self) -> None:
        for row in self.list.get_children():
            self.list.delete(row)
        for unit, actions in sorted(self.units.items()):
            self.list.insert("", "end", iid=unit,
                             values=(unit, ", ".join(LABELS[action] for action in ACTIONS if action in actions)))
        self._controls()

    def _selected(self, _event=None) -> None:
        selected = self.list.selection()
        if selected:
            name = selected[0]
            self.unit.set(name)
            for action, variable in self.action_values.items():
                variable.set(action in self.units[name])
        self._controls()

    def _invalidate(self) -> None:
        self.reviewed = self.reviewed_units = None
        self._show("Разрешения изменены. Проверьте план перед включением.")
        self._controls()

    def add_unit(self) -> None:
        if self.busy or self.state is None:
            return
        name = self.unit.get().strip()
        actions = {action for action, variable in self.action_values.items() if variable.get()}
        actions.add("status")
        self.action_values["status"].set(True)
        if not UNIT.fullmatch(name) or name.endswith("@.service"):
            messagebox.showerror("Службы Agent", "Выберите точное имя .service.",
                                 parent=self.window)
            return
        if name not in self.units and len(self.units) >= 16:
            messagebox.showerror("Службы Agent", "Можно разрешить не более шестнадцати служб.",
                                 parent=self.window)
            return
        self.units[name] = actions
        self._invalidate()
        self._render_units()

    def remove_unit(self) -> None:
        selected = self.list.selection()
        if not selected or self.busy:
            return
        self.units.pop(selected[0], None)
        self._invalidate()
        self._render_units()

    def _run(self, kind: str, operation) -> None:
        self.busy = True
        self._controls()
        def worker() -> None:
            try:
                self.events.put((kind, operation()))
            except Exception as exc:
                self.events.put(("error", exc))
        threading.Thread(target=worker, daemon=True).start()

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        profile = self.profile.get()
        self.state = self.reviewed = self.reviewed_units = None
        self.units.clear()
        self._render_units()
        controller = self._controller()
        self.status.set("Проверяем код, systemd и доступные службы…")
        self._run("checked", lambda: (controller.inspect(profile), controller.catalog(profile)))

    def plan(self) -> None:
        if self.busy or self.state is None:
            return
        profile, units = self.profile.get(), {unit: set(actions) for unit, actions in self.units.items()}
        controller = self._controller()
        self.status.set("Сверяем план разрешений без изменения сервера…")
        self._run("planned", lambda: (controller.plan(profile, units), units))

    def arm(self) -> None:
        if self.busy or self.reviewed is None or self.reviewed_units is None:
            return
        reviewed = self.reviewed
        units = {unit: set(actions) for unit, actions in self.reviewed_units.items()}
        summary = "\n".join(f"{unit}: {', '.join(LABELS[action] for action in ACTIONS if action in actions)}"
                            for unit, actions in sorted(units.items()))
        if not messagebox.askyesno("Включить управление службами?",
                                   f"Agent: {PROFILE_LABELS[reviewed.profile]}\n\n{summary}\n\n"
                                   "Включить эти действия для администраторов Hub?",
                                   parent=self.window):
            return
        self.status.set("Применяем точно проверенный план и подтверждаем состояние…")
        self._run("armed", lambda: self._controller().arm(reviewed, units))

    def disarm(self) -> None:
        if self.busy or self.state is None or not self.state.armed:
            return
        state = self.state
        if not messagebox.askyesno("Выключить управление службами?",
                                   f"Выключить действия для «{PROFILE_LABELS[state.profile]}»? "
                                   "Список разрешений останется на сервере для последующего включения.",
                                   parent=self.window):
            return
        self.status.set("Выключаем socket брокера и проверяем состояние…")
        self._run("disarmed", lambda: self._controller().disarm(state))

    def _render_state(self, state: ServiceSetupState) -> None:
        self.state = state
        self.units = {unit: set(actions) for unit, actions in state.policy or ()}
        self._render_units()
        self._show("\n".join((
            f"Профиль: {PROFILE_LABELS[state.profile]}",
            f"Управление: {'включено' if state.armed else 'выключено'}",
            f"Socket: {state.socket_enabled}, {state.socket_active}",
            f"Разрешено служб: {len(self.units)}",
            "Изменение затрагивает только выбранный Agent.",
        )))
        self.status.set("Состояние проверено. Измените разрешения и проверьте план.")
        self._controls()

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
                continue
            self.busy = False
            if event == "checked":
                state, catalog = payload
                if state.profile == self.profile.get():
                    self.unit_choice.configure(values=catalog)
                    self._render_state(state)
            elif event == "planned":
                state, units = payload
                if state.profile == self.profile.get():
                    self.reviewed, self.reviewed_units = state, units
                    plan = state.plan or ()
                    self._show("\n".join((
                        f"Профиль: {PROFILE_LABELS[state.profile]}",
                        f"Служб: {len(units)}",
                        f"Установить файлы брокера: {len(plan[0]) if plan else 0}",
                        f"Обновить разрешения: {'да' if plan and plan[1] else 'нет'}",
                        f"Включить socket: {'да' if plan and plan[2] else 'нет'}",
                        f"Перезапустить локальный Agent: {'да' if plan and plan[3] else 'нет'}",
                    )))
                    self.status.set("План проверен. Подтвердите включение.")
            elif event in ("armed", "disarmed"):
                self.reviewed = self.reviewed_units = None
                self._render_state(payload)
                self.status.set("Изменение подтверждено сервером.")
            elif event == "error":
                self.reviewed = self.reviewed_units = None
                self.state = None
                self.units.clear()
                self._render_units()
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Сервер не подтвердил результат. Проверьте фактическое состояние перед повтором.")
                self.status.set(message)
                messagebox.showerror("Службы Agent", message, parent=self.window)
            self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Службы Agent", "Дождитесь ответа сервера.", parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
