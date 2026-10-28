# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Graphical allowlist for exact Docker container actions through root SSH."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .container_action_setup import (ACTIONS, PROFILES, ContainerActionSetupController,
                                     ContainerActionState, ContainerCandidate)
from .installer import InstallError


LABELS = {"status": "Состояние", "start": "Запуск", "stop": "Остановка", "restart": "Перезапуск"}
PROFILE_LABELS = {"default": "Основной Agent", "local": "Локальный Agent своего Hub"}


class ContainerActionSetupDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: ContainerActionSetupController | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.state: ContainerActionState | None = None
        self.reviewed: ContainerActionState | None = None
        self.reviewed_actions: dict[str, set[str]] | None = None
        self.selected_actions: dict[str, set[str]] = {}
        self.candidates: dict[str, ContainerCandidate] = {}
        self.profile = tk.StringVar(value="default")
        self.action_values = {action: tk.BooleanVar(value=action == "status") for action in ACTIONS}
        self.status = tk.StringVar(value=(
            "Проверьте сервер. До подтверждения разрешения не меняются."
            if approved_manifest_sha256 else
            "Мастер ждёт проверенный выпуск Agent с Docker-брокером."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Контейнеры Agent · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("900x700")
        self.window.minsize(720, 580)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(5, weight=1)
        body.rowconfigure(7, weight=1)
        ttk.Label(body, text="Действия с Docker-контейнерами", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(body, text="SSH-маршрут: " + route, wraplength=860).grid(
            row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(body, text=(
            "Мастер показывает только изолированные контейнеры, которые прошли проверку Agent. "
            "Инфраструктура SovaGrid, VPN, SSH и сети, контейнеры с монтированиями, "
            "устройствами, дополнительными capabilities или общими пространствами имён исключаются. "
            "Состояние включается всегда; остальные действия выбирайте отдельно."
        ), wraplength=860).grid(row=2, column=0, sticky="w", pady=(8, 6))
        profile_row = ttk.Frame(body)
        profile_row.grid(row=3, column=0, sticky="ew", pady=(2, 8))
        ttk.Label(profile_row, text="Agent:").pack(side="left")
        self.profile_choice = ttk.Combobox(profile_row, textvariable=self.profile,
                                           values=PROFILES, state="readonly", width=16)
        self.profile_choice.pack(side="left", padx=(8, 8))
        self.profile_description = ttk.Label(profile_row, text=PROFILE_LABELS["default"])
        self.profile_description.pack(side="left")
        candidate_frame = ttk.LabelFrame(body, text="Контейнеры, доступные для настройки", padding=8)
        candidate_frame.grid(row=4, column=0, sticky="nsew", pady=(0, 8))
        candidate_frame.columnconfigure(0, weight=1)
        candidate_frame.rowconfigure(0, weight=1)
        self.catalog = ttk.Treeview(candidate_frame, columns=("name", "image", "state", "id"),
                                    show="headings", height=6, selectmode="browse")
        for key, label, width in (("name", "Имя", 180), ("image", "Образ", 260),
                                  ("state", "Состояние", 110), ("id", "ID", 170)):
            self.catalog.heading(key, text=label)
            self.catalog.column(key, width=width, stretch=key in ("name", "image"))
        self.catalog.grid(row=0, column=0, sticky="nsew")
        catalog_scroll = ttk.Scrollbar(candidate_frame, orient="vertical", command=self.catalog.yview)
        catalog_scroll.grid(row=0, column=1, sticky="ns")
        self.catalog.configure(yscrollcommand=catalog_scroll.set)
        self.catalog.bind("<<TreeviewSelect>>", self._catalog_selected)
        selector = ttk.Frame(body)
        selector.grid(row=5, column=0, sticky="nsew")
        selector.columnconfigure(0, weight=1)
        selector.rowconfigure(2, weight=1)
        action_row = ttk.Frame(selector)
        action_row.grid(row=0, column=0, sticky="w", pady=(0, 7))
        self.action_checks = {}
        for action in ACTIONS:
            control = ttk.Checkbutton(action_row, text=LABELS[action],
                                      variable=self.action_values[action])
            control.pack(side="left", padx=(0, 14))
            self.action_checks[action] = control
        self.add_button = ttk.Button(action_row, text="Добавить или обновить", command=self.add_container)
        self.add_button.pack(side="left")
        ttk.Label(selector, text="Разрешения выбранного Agent (не более 16 контейнеров):").grid(
            row=1, column=0, sticky="w")
        list_frame = ttk.Frame(selector)
        list_frame.grid(row=2, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.allowed = ttk.Treeview(list_frame, columns=("name", "id", "actions"),
                                    show="headings", height=6, selectmode="browse")
        for key, label, width in (("name", "Контейнер", 190), ("id", "ID", 180),
                                  ("actions", "Разрешённые действия", 420)):
            self.allowed.heading(key, text=label)
            self.allowed.column(key, width=width, stretch=key == "actions")
        self.allowed.grid(row=0, column=0, sticky="nsew")
        self.allowed.bind("<<TreeviewSelect>>", self._allowed_selected)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.allowed.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.allowed.configure(yscrollcommand=scroll.set)
        self.remove_button = ttk.Button(selector, text="Убрать выбранное разрешение",
                                        command=self.remove_container)
        self.remove_button.grid(row=3, column=0, sticky="w", pady=(5, 0))
        self.details = tk.Text(body, height=6, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=7, column=0, sticky="nsew", pady=(9, 5))
        ttk.Label(body, textvariable=self.status, wraplength=860).grid(row=8, column=0, sticky="w")
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
        self.clear_button = ttk.Button(buttons, text="Удалить сохранённый список", command=self.clear)
        self.clear_button.pack(side="left", padx=(8, 0))
        self.abort_button = ttk.Button(buttons, text="Восстановить прежнее", command=self.abort)
        self.abort_button.pack(side="left", padx=(8, 0))
        self.close_button = ttk.Button(buttons, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        self.profile.trace_add("write", self._profile_changed)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> ContainerActionSetupController:
        if self.controller is None:
            self.controller = ContainerActionSetupController(
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
        editable = ready and self.state is not None and self.state.catalog_status == "ok" and \
            not self.state.armed and \
            not self.state.transaction_pending
        self.profile_choice.configure(state="readonly" if not self.busy else "disabled")
        self.check_button.configure(state="normal" if ready else "disabled")
        for control in (self.add_button,
                        *(self.action_checks[action] for action in ACTIONS if action != "status")):
            control.configure(state="normal" if editable else "disabled")
        self.action_checks["status"].configure(state="disabled")
        self.remove_button.configure(state="normal" if editable and self.allowed.selection() else "disabled")
        self.plan_button.configure(state="normal" if editable and self.selected_actions else "disabled")
        self.arm_button.configure(state="normal" if ready and self.reviewed is not None else "disabled")
        self.disarm_button.configure(state="normal" if ready and self.state is not None and
                                     self.state.armed and not self.state.transaction_pending else "disabled")
        self.clear_button.configure(state="normal" if ready and self.state is not None and
                                    not self.state.armed and not self.state.transaction_pending and
                                    self.state.policy_raw is not None else "disabled")
        self.abort_button.configure(state="normal" if ready and self.state is not None and
                                    self.state.transaction_pending else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def _profile_changed(self, *_args) -> None:
        self.profile_description.configure(text=PROFILE_LABELS.get(self.profile.get(), ""))
        self.state = self.reviewed = self.reviewed_actions = None
        self.selected_actions.clear()
        self.candidates.clear()
        self._render()
        self._show("")
        self.status.set("Agent изменён. Проверьте сервер заново.")
        self._controls()

    def _render(self) -> None:
        for table in (self.catalog, self.allowed):
            for row in table.get_children():
                table.delete(row)
        for item in sorted(self.candidates.values(), key=lambda candidate: candidate.name):
            self.catalog.insert("", "end", iid=item.ident,
                                values=(item.name, item.image, item.state, item.ident[:16]))
        for ident, actions in sorted(self.selected_actions.items(),
                                     key=lambda entry: self.candidates[entry[0]].name):
            item = self.candidates[ident]
            self.allowed.insert("", "end", iid=ident,
                                values=(item.name, ident[:16],
                                        ", ".join(LABELS[action] for action in ACTIONS if action in actions)))
        self._controls()

    def _catalog_selected(self, _event=None) -> None:
        selection = self.catalog.selection()
        if selection:
            actions = self.selected_actions.get(selection[0], {"status"})
            for action, variable in self.action_values.items():
                variable.set(action in actions)
            item = self.candidates[selection[0]]
            self._show(f"Контейнер: {item.name}\nID: {item.ident}\nОбраз: {item.image}\n"
                       f"ID образа: {item.image_id}\nСостояние: {item.state}")
        self._controls()

    def _allowed_selected(self, _event=None) -> None:
        selection = self.allowed.selection()
        if selection:
            self.catalog.selection_set(selection[0])
            self.catalog.see(selection[0])
        self._controls()

    def _invalidate(self) -> None:
        self.reviewed = self.reviewed_actions = None
        self.status.set("Разрешения изменены. Проверьте план заново.")
        self._controls()

    def add_container(self) -> None:
        selection = self.catalog.selection()
        if self.busy or self.state is None or not selection:
            return
        ident = selection[0]
        if ident not in self.selected_actions and len(self.selected_actions) >= 16:
            messagebox.showerror("Контейнеры Agent", "Можно разрешить не более 16 контейнеров.",
                                 parent=self.window)
            return
        actions = {action for action, variable in self.action_values.items() if variable.get()}
        actions.add("status")
        self.action_values["status"].set(True)
        self.selected_actions[ident] = actions
        self._invalidate()
        self._render()

    def remove_container(self) -> None:
        selection = self.allowed.selection()
        if self.busy or not selection:
            return
        self.selected_actions.pop(selection[0], None)
        self._invalidate()
        self._render()

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
        self.state = self.reviewed = self.reviewed_actions = None
        self.selected_actions.clear()
        self.candidates.clear()
        self._render()
        self.status.set("Проверяем код Agent, Docker и текущие разрешения…")
        self._run("checked", lambda: self._controller().inspect(profile))

    def plan(self) -> None:
        if self.busy or self.state is None or not self.selected_actions:
            return
        profile = self.profile.get()
        selected = {ident: set(actions) for ident, actions in self.selected_actions.items()}
        self.status.set("Сверяем контейнеры и план без изменения сервера…")
        self._run("planned", lambda: (self._controller().plan(profile, selected), selected))

    def arm(self) -> None:
        if self.busy or self.reviewed is None or self.reviewed_actions is None:
            return
        reviewed = self.reviewed
        selected = {ident: set(actions) for ident, actions in self.reviewed_actions.items()}
        names = {item.ident: item.name for item in reviewed.catalog}
        summary = "\n".join(f"{names[ident]} ({ident[:16]}): " +
                            ", ".join(LABELS[action] for action in ACTIONS if action in actions)
                            for ident, actions in sorted(selected.items()))
        if not messagebox.askyesno("Включить действия с контейнерами?",
                                   f"Agent: {PROFILE_LABELS[reviewed.profile]}\n\n{summary}\n\n"
                                   "Включить эти действия для администраторов Hub?",
                                   parent=self.window):
            return
        self.status.set("Применяем проверенный план и подтверждаем результат…")
        self._run("armed", lambda: self._controller().arm(reviewed, selected))

    def disarm(self) -> None:
        if self.busy or self.state is None or not self.state.armed:
            return
        reviewed = self.state
        if not messagebox.askyesno("Выключить действия с контейнерами?",
                                   f"Выключить действия для «{PROFILE_LABELS[reviewed.profile]}»? "
                                   "Список останется на сервере, но Agent перестанет его применять.",
                                   parent=self.window):
            return
        self.status.set("Выключаем разрешения и проверяем результат…")
        self._run("disarmed", lambda: self._controller().disarm(reviewed))

    def abort(self) -> None:
        if self.busy or self.state is None or not self.state.transaction_pending:
            return
        reviewed = self.state
        if not messagebox.askyesno("Восстановить прежние разрешения?",
                                   "Незавершённая настройка будет отменена. Действия с контейнерами "
                                   "выключатся, а прежний список разрешений восстановится.",
                                   parent=self.window):
            return
        self.status.set("Восстанавливаем предыдущую политику и проверяем результат…")
        self._run("aborted", lambda: self._controller().abort(reviewed))

    def clear(self) -> None:
        if (self.busy or self.state is None or self.state.armed or
                self.state.transaction_pending or self.state.policy_raw is None):
            return
        reviewed = self.state
        if not messagebox.askyesno(
            "Удалить сохранённые разрешения?",
            f"Удалить выключенный список для «{PROFILE_LABELS[reviewed.profile]}»?\n"
            f"Ревизия: {reviewed.state_revision}\n\n"
            "Разрешения уже выключены. Сохранённый список будет удалён с сервера.",
            parent=self.window,
        ):
            return
        self.status.set("Удаляем выключенный список и проверяем результат…")
        self._run("cleared", lambda: self._controller().clear(reviewed))

    def _render_state(self, state: ContainerActionState) -> None:
        self.state = state
        self.candidates = {item.ident: item for item in state.catalog}
        self.selected_actions = {ident: set(actions) for ident, _name, _image_id, actions
                                 in state.policy or () if ident in self.candidates}
        self._render()
        lines = [
            f"Agent: {PROFILE_LABELS[state.profile]}",
            f"Действия: {'включены' if state.armed else 'выключены'}",
            (f"Проверенных контейнеров: {len(state.catalog)}; исключено: {state.excluded}"
             if state.catalog_status == "ok" else
             "Docker недоступен. Можно проверить и выключить разрешения; выбор контейнеров недоступен."),
            f"Сохранено разрешений: {len(state.policy or ())}",
            "Предыдущая операция требует проверки." if state.transaction_pending else
            "Для изменения действующих разрешений сначала выключите их.",
        ]
        for ident, name, _image_id, actions in state.policy or ():
            lines.append(f"{name} ({ident[:16]}): " +
                         ", ".join(LABELS[action] for action in ACTIONS if action in actions))
        self._show("\n".join(lines))
        self.status.set("Состояние проверено. Выберите контейнеры и проверьте план."
                        if state.catalog_status == "ok" else
                        "Состояние проверено. Для выбора контейнеров нужен активный свежий Docker-инвентарь Agent.")
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
                if payload.profile == self.profile.get():
                    self._render_state(payload)
            elif event == "planned":
                state, selected = payload
                if state.profile == self.profile.get():
                    self.reviewed, self.reviewed_actions = state, selected
                    lines = [f"Agent: {PROFILE_LABELS[state.profile]}",
                             f"Путь разрешений: {state.plan[0]}",
                             f"Контейнеров: {len(selected)}",
                             f"Обновить список: {'да' if state.plan[2] else 'нет'}",
                             "Включить отдельный root-маркер: да"]
                    for ident, name, image_id, actions in state.plan[1]:
                        lines.extend((f"{name}: {', '.join(actions)}",
                                      f"  ID {ident}", f"  образ {image_id}"))
                    self._show("\n".join(lines))
                    self.status.set("План проверен. Подтвердите включение.")
            elif event in ("armed", "disarmed", "cleared", "aborted"):
                self.reviewed = self.reviewed_actions = None
                self._render_state(payload)
                self.status.set("Изменение подтверждено сервером.")
            elif event == "error":
                self.reviewed = self.reviewed_actions = None
                self.state = None
                self.selected_actions.clear()
                self.candidates.clear()
                self._render()
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Сервер не подтвердил результат. Проверьте фактическое состояние перед повтором.")
                self.status.set(message)
                messagebox.showerror("Контейнеры Agent", message, parent=self.window)
            self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Контейнеры Agent", "Дождитесь ответа сервера.", parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
