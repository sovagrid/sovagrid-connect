# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Desktop metadata controls for root-only SovaGrid host archives."""

from __future__ import annotations

from datetime import datetime
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
import uuid

from .host_backup import (HostArchive, HostBackupController, HostBackupOperation,
                          HostBackupPlan, HostBackupState)
from .installer import InstallError


def _archive_text(archive: HostArchive) -> str:
    when = datetime.fromisoformat(archive.created_at).strftime("%Y-%m-%d %H:%M:%S UTC")
    layout = "Hub и Agent" if archive.layout == "full" else "локальный Hub"
    return "\n".join((
        f"Копия: {archive.id}", f"Создана: {when}", f"Установка: {layout}",
        f"Размер архива: {archive.bytes:,} байт", f"Объектов: {archive.files:,}",
        "Целостность: проверена" if archive.verified else "Целостность: ещё не проверена",
        "Архив хранится только на сервере. Доступ к нему имеет root.",
    ))


def _plan_text(plan: HostBackupPlan) -> str:
    layout = "Hub и Agent" if plan.layout == "full" else "локальный Hub"
    lines = [f"Установка: {layout}",
             "Создание сейчас: доступно" if plan.offline_ready else
             "Создание сейчас: службы или контейнеры записывают данные"]
    if plan.active_units:
        lines.append("Активные управляемые службы: " + ", ".join(plan.active_units))
    if plan.running_containers:
        lines.append("Запущенные контейнеры: " + ", ".join(plan.running_containers))
    if not plan.offline_ready:
        lines.append("Проверка списка и существующих копий остаётся доступной.")
    return "\n".join(lines)


PHASES = {
    "accepted": "Принято сервером", "stopping": "Останавливаем записывающие службы",
    "archiving": "Создаём закрытый архив", "restarting": "Запускаем прежние службы",
    "complete": "Завершено", "recovery_requested": "Восстанавливаем службы",
    "recovered": "Службы восстановлены после сбоя",
    "failed": "Завершилось с ошибкой", "recovery_required": "Нужно восстановить службы",
}


def _operation_text(operation: HostBackupOperation) -> str:
    when = datetime.fromisoformat(operation.created_at).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [f"Запрос: {operation.request_id}", f"Начало: {when}",
             f"Состояние: {PHASES[operation.phase]}"]
    if operation.archive is not None:
        lines.extend((f"Архив: {operation.archive.id}",
                      f"Размер: {operation.archive.bytes:,} байт"))
    if operation.error is not None:
        lines.append(f"Код ошибки: {operation.error}")
    if operation.phase == "recovery_required":
        lines.append("Службы могут быть остановлены. Нажмите «Проверить и восстановить службы…».")
    return "\n".join(lines)


class HostBackupDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: HostBackupController | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.state: HostBackupState | None = None
        self.verified: HostArchive | None = None
        self.request_id: str | None = None
        self.operation: HostBackupOperation | None = None
        self._next_poll = 0.0
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Проверьте сервер, чтобы увидеть полные копии."
            if approved_manifest_sha256 else "Мастер ждёт общий проверенный серверный выпуск."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Полные копии сервера · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("800x630")
        self.window.minsize(650, 500)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)
        ttk.Label(body, text="Полные копии SovaGrid на сервере",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(body, text="SSH-маршрут: " + route, wraplength=710).grid(
            row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(body, text=(
            "Полная копия включает данные Hub, сертификаты Web, настройки Agent и VPN, "
            "а также конфигурацию SovaGrid. Она содержит секреты и хранится только в закрытом "
            "каталоге сервера. Сервер временно остановит только свои записывающие службы и "
            "контейнеры, создаст архив и запустит прежние компоненты."
        ), wraplength=710).grid(row=2, column=0, sticky="w", pady=(9, 8))
        list_frame = ttk.Frame(body)
        list_frame.grid(row=3, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.list = ttk.Treeview(list_frame, columns=("time", "layout", "size", "id"),
                                 show="headings", height=10)
        for key, heading, width in (("time", "Создана UTC", 155),
                                    ("layout", "Установка", 120),
                                    ("size", "Размер", 110), ("id", "ID", 300)):
            self.list.heading(key, text=heading)
            self.list.column(key, width=width)
        self.list.grid(row=0, column=0, sticky="nsew")
        self.list.bind("<<TreeviewSelect>>", self._selection_changed)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.list.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.list.configure(yscrollcommand=scroll.set)
        self.details = tk.Text(body, height=8, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky="ew", pady=(9, 5))
        ttk.Label(body, textvariable=self.status, wraplength=710).grid(
            row=5, column=0, sticky="w")
        actions = ttk.Frame(body)
        actions.grid(row=6, column=0, sticky="ew", pady=(11, 0))
        self.refresh_button = ttk.Button(actions, text="Проверить сервер", command=self.refresh)
        self.refresh_button.pack(side="left")
        self.verify_button = ttk.Button(actions, text="Проверить выбранную", command=self.verify)
        self.verify_button.pack(side="left", padx=(8, 0))
        self.create_button = ttk.Button(actions, text="Создать полную копию…", command=self.create)
        self.create_button.pack(side="left", padx=(8, 0))
        self.close_button = ttk.Button(actions, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        operation_actions = ttk.Frame(body)
        operation_actions.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        self.status_button = ttk.Button(operation_actions, text="Состояние задания",
                                        command=self.check_operation)
        self.status_button.pack(side="left")
        self.recover_button = ttk.Button(operation_actions, text="Проверить и восстановить службы…",
                                         command=self.recover_operation)
        self.recover_button.pack(side="left", padx=(8, 0))
        self.history_button = ttk.Button(operation_actions, text="История заданий",
                                         command=self.operation_history)
        self.history_button.pack(side="left", padx=(8, 0))
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        try:
            saved = self._controller().saved_request()
            if saved is not None:
                self.request_id = saved.request_id
                self.status.set("Найден сохранённый запрос. Проверяем состояние на сервере…")
        except InstallError as exc:
            self.status.set(str(exc))
        self._controls()
        self._pump_after = self.window.after(100, self._pump)
        if self.request_id:
            self.window.after(150, self.check_operation)

    def _controller(self) -> HostBackupController:
        if self.controller is None:
            self.controller = HostBackupController(
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
        self.refresh_button.configure(state="normal" if ready else "disabled")
        previous_done = self.operation is None and self.request_id is None or (
            self.operation is not None and self.operation.terminal)
        self.create_button.configure(state="normal" if ready and self.state and
                                     previous_done else "disabled")
        self.verify_button.configure(state="normal" if ready and self.state and
                                     self.list.selection() else "disabled")
        self.status_button.configure(state="normal" if ready and self.request_id else "disabled")
        self.recover_button.configure(state="normal" if ready and self.operation is not None and
                                      not self.operation.terminal else "disabled")
        self.history_button.configure(state="normal" if ready else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def _selection_changed(self, _event=None) -> None:
        selected = self.list.selection()
        if self.verified is not None and (not selected or selected[0] != self.verified.id):
            self.verified = None
        if selected and self.state is not None:
            archive = next((item for item in self.state.archives if item.id == selected[0]), None)
            self._show((_archive_text(self.verified or archive) + "\n\n" +
                        _plan_text(self.state.plan)) if archive is not None else "")
        else:
            self._show(_plan_text(self.state.plan) if self.state is not None else "")
        self._controls()

    def _run(self, kind: str, operation) -> None:
        self.busy = True
        self._controls()
        def worker():
            try:
                self.events.put((kind, operation()))
            except Exception as exc:
                self.events.put(("error", (kind, exc)))
        threading.Thread(target=worker, daemon=True).start()

    def _render_state(self, state: HostBackupState) -> None:
        self.state, self.verified = state, None
        for row in self.list.get_children():
            self.list.delete(row)
        for archive in state.archives:
            when = datetime.fromisoformat(archive.created_at).strftime("%Y-%m-%d %H:%M")
            label = "Hub и Agent" if archive.layout == "full" else "локальный Hub"
            self.list.insert("", "end", iid=archive.id,
                             values=(when, label, f"{archive.bytes:,} Б", archive.id))
        self._show((_operation_text(self.operation) + "\n\n" if self.operation else "") +
                   _plan_text(state.plan))
        self.status.set(f"Найдено полных копий: {len(state.archives)}. "
                        "Сервер подготовит остановку и запуск служб при создании.")
        self._controls()

    def refresh(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.state = self.verified = None
        self._show("")
        self.status.set("Сверяем установленный серверный пакет и список копий…")
        self._run("refreshed", self._controller().inspect)

    def verify(self) -> None:
        if self.busy or self.state is None or not self.list.selection():
            return
        identity = self.list.selection()[0]
        if identity not in {item.id for item in self.state.archives}:
            return
        self.status.set("Проверяем хеш и структуру архива на сервере…")
        self._run("verified", lambda: self._controller().verify(identity))

    def create(self) -> None:
        if (self.busy or self.state is None or
                self.request_id is not None and
                (self.operation is None or not self.operation.terminal)):
            return
        reviewed = self.state
        stopped = ", ".join(reviewed.plan.active_units) or "нет"
        containers = ", ".join(reviewed.plan.running_containers) or "нет"
        if not messagebox.askyesno("Создать полную копию?", (
                f"Сервер: {self.options.user}@{self.options.host}:{self.options.port}\n"
                f"Службы на время копии: {stopped}\n"
                f"Контейнеры на время копии: {containers}\n"
                f"Найдено прежних копий: {len(reviewed.archives)}\n\n"
                "Архив может включать пароли, ключи VPN и сертификаты. Он останется в закрытом "
                "каталоге на этом сервере. Доступ к Hub/Web может временно прерваться; "
                "сервер затем запустит прежние службы. SSH-маршрут и внешний Agent "
                "не входят в этот план. Создать копию?"
        ), parent=self.window):
            return
        if (self.busy or self.state is not reviewed or
                self.request_id is not None and
                (self.operation is None or not self.operation.terminal)):
            return
        request_id = uuid.uuid4().hex
        self.request_id, self.operation = request_id, None
        self.status.set("Запрос сохранится до остановки служб. Ждём подтверждения сервера…")
        self._run("started", lambda: self._controller().start_online(reviewed, request_id))

    def check_operation(self) -> None:
        if self.busy or not self.request_id:
            return
        identity = self.request_id
        self.status.set("Читаем сохранённое состояние задания…")
        self._run("operation", lambda: self._controller().operation_status(identity))

    def recover_operation(self) -> None:
        operation = self.operation
        if self.busy or operation is None or operation.terminal:
            return
        if not messagebox.askyesno("Проверить и восстановить службы?", (
                f"Сервер: {self.options.user}@{self.options.host}:{self.options.port}\n"
                f"Запрос: {operation.request_id}\nСостояние: {PHASES[operation.phase]}\n\n"
                "Проверить журнал задания и, только если его worker уже завершился, запустить "
                "службы и контейнеры, которые остановил этот запрос? Пока worker работает, "
                "сервер откажет. Архив повторно создаваться не будет."
        ), parent=self.window):
            return
        if self.busy or self.operation is not operation:
            return
        self.status.set("Сервер сверяет журнал и запускает прежние компоненты…")
        self._run("recovered", lambda: self._controller().recover_operation(operation.request_id))

    def operation_history(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.status.set("Читаем историю заданий на сервере…")
        self._run("history", self._controller().operation_list)

    def _show_history(self, operations: tuple[HostBackupOperation, ...]) -> None:
        window = tk.Toplevel(self.window)
        window.title("История полных копий · SovaGrid")
        window.transient(self.window)
        window.geometry("810x430")
        self.theme.style_window(window)
        body = ttk.Frame(window, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Выберите запрос для проверки", wraplength=760).pack(anchor="w")
        tree = ttk.Treeview(body, columns=("time", "phase", "archive", "request"), show="headings")
        for key, title, width in (("time", "Начало UTC", 150),
                                  ("phase", "Состояние", 250),
                                  ("archive", "Архив", 135), ("request", "Запрос", 250)):
            tree.heading(key, text=title)
            tree.column(key, width=width)
        tree.pack(fill="both", expand=True, pady=(10, 8))
        for row in operations:
            when = datetime.fromisoformat(row.created_at).strftime("%Y-%m-%d %H:%M")
            tree.insert("", "end", iid=row.request_id,
                        values=(when, PHASES[row.phase], row.archive.id[:8] if row.archive else "—",
                                row.request_id))
        actions = ttk.Frame(body)
        actions.pack(fill="x")
        def select():
            selected = tree.selection()
            if not selected:
                return
            self.request_id = selected[0]
            self.operation = None
            window.destroy()
            self.check_operation()
        ttk.Button(actions, text="Проверить выбранное", command=select).pack(side="left")
        ttk.Button(actions, text="Закрыть", command=window.destroy).pack(side="right")
        self.status.set(f"Заданий в истории: {len(operations)}.")

    def _render_operation(self, operation: HostBackupOperation) -> None:
        self.request_id, self.operation = operation.request_id, operation
        self._show(_operation_text(operation) +
                   ("\n\n" + _plan_text(self.state.plan) if self.state else ""))
        if operation.phase == "complete":
            self.status.set("Копия создана. Обновите список и проверьте архив.")
        elif operation.phase == "recovered":
            self.status.set("Службы восстановлены после сбоя. Проверьте состояние сервера.")
        elif operation.phase == "failed":
            self.status.set("Задание завершилось с ошибкой. Проверьте сервер и историю.")
        elif operation.phase == "recovery_required":
            self.status.set("Службы могли остаться остановленными. Нажмите «Проверить и восстановить службы…».")
        else:
            self.status.set("Сервер выполняет задание. Состояние обновится автоматически.")
            self._next_poll = time.monotonic() + 5.0

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
            if event == "refreshed":
                self._render_state(payload)
            elif event == "verified":
                self.verified = payload
                self._show(_archive_text(payload))
                self.status.set("Архив проверен на сервере. Секреты не показаны в приложении.")
            elif event == "created":
                archive, state = payload
                self._render_state(state)
                self.list.selection_set(archive.id)
                self.list.see(archive.id)
                self.verified = archive
                self._show(_archive_text(archive))
                self.status.set("Полная копия создана и проверена на сервере.")
            elif event in ("started", "operation", "recovered"):
                self._render_operation(payload)
            elif event == "history":
                self._show_history(payload)
            elif event == "error":
                kind, error = payload
                if kind not in ("started", "operation", "recovered", "history"):
                    self.state = self.verified = None
                    self._show("")
                if kind == "started":
                    try:
                        saved = self._controller().saved_request()
                        if saved is None or saved.request_id != self.request_id:
                            self.request_id = None
                    except InstallError:
                        pass
                if kind == "operation":
                    self._next_poll = float("inf")
                if kind == "recovered":
                    self._next_poll = time.monotonic() + 5.0
                message = str(error) if isinstance(error, InstallError) else (
                    "Сервер не подтвердил результат. Проверьте сохранённый запрос перед повтором.")
                if kind in ("started", "operation", "recovered") and self.request_id:
                    message += "\nЗапрос: " + self.request_id
                self.status.set(message)
                messagebox.showerror("Полные копии сервера", message, parent=self.window)
            self._controls()
        if (not self.busy and self.operation is not None and not self.operation.terminal and
                self.operation.phase != "recovery_required" and
                time.monotonic() >= self._next_poll):
            self.check_operation()
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy or self.closed:
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
