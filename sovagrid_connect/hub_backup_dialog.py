# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first desktop controls for Hub data snapshots."""

from __future__ import annotations

from datetime import datetime, timezone
import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import uuid

from .hub_backup import (HubBackupController, HubBackupDetails, HubBackupState,
                         HubRestoreStatus)
from .installer import InstallError


def _details_text(details: HubBackupDetails) -> str:
    created = datetime.fromtimestamp(details.created_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return "\n".join((
        f"Копия: {details.id}",
        f"Создана: {created}",
        f"База Hub: {details.database_bytes:,} байт",
        f"Токен Telegram: {'включён' if details.telegram_token_included else 'не задан'}",
        "Целостность: проверена" if details.verified else "Целостность: не проверена",
    ))


_RESTORE_PHASE = {
    "pending": "Ожидает запуска", "stopping": "Останавливаем Hub",
    "stopped": "Hub остановлен", "planning": "Делаем страховочную копию",
    "planned": "План готов", "applying": "Восстанавливаем данные",
    "applied": "Данные восстановлены", "starting": "Запускаем Hub",
    "started": "Проверяем Hub", "finalizing": "Завершаем восстановление",
    "complete": "Завершено", "failed_recovered": "Прежние данные возвращены",
    "recovery_required": "Требуется восстановление сервера",
}


def _restore_text(result: HubRestoreStatus) -> str:
    hub = {True: "работает", False: "остановлен", None: "состояние не подтверждено"}[result.hub_running]
    created = datetime.fromtimestamp(result.created_at, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [f"Запрос: {result.request_id}", f"Начало: {created}",
             f"Состояние: {_RESTORE_PHASE[result.phase]}", f"Hub: {hub}"]
    if result.target_id:
        lines.append(f"Выбранная копия: {result.target_id}")
    if result.safety_id:
        lines.append(f"Страховочная копия: {result.safety_id}")
    if result.plan_id:
        lines.append(f"План восстановления: {result.plan_id}")
    if result.error:
        lines.append(f"Код ошибки: {result.error}")
    return "\n".join(lines)


class HubBackupDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: HubBackupController | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.state: HubBackupState | None = None
        self.verified: HubBackupDetails | None = None
        self.restore_request_id: str | None = None
        self.restore_result: HubRestoreStatus | None = None
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Проверьте сервер, чтобы увидеть копии и создать новую."
            if approved_manifest_sha256 else "Мастер ждёт общий проверенный серверный выпуск."
        ))
        self.window = tk.Toplevel(root)
        self.window.title("Резервные копии Hub · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("820x660")
        self.window.minsize(650, 520)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)
        ttk.Label(body, text="Резервные копии данных Hub", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(body, text="SSH-маршрут: " + route, wraplength=720).grid(
            row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(body, text=(
            "Копия включает базу Hub и, если задан, секретный токен Telegram. "
            "Она хранится только в закрытом каталоге на этом сервере. "
            "VPN-ключи, Caddy CA, Agent и файлы сервера в неё не входят."
        ), wraplength=720).grid(row=2, column=0, sticky="w", pady=(9, 8))
        list_frame = ttk.Frame(body)
        list_frame.grid(row=3, column=0, sticky="nsew")
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        self.list = ttk.Treeview(list_frame, columns=("id",), show="headings", height=11)
        self.list.heading("id", text="ID копии (выберите для проверки)")
        self.list.column("id", width=650)
        self.list.grid(row=0, column=0, sticky="nsew")
        self.list.bind("<<TreeviewSelect>>", self._selection_changed)
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.list.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.list.configure(yscrollcommand=scroll.set)
        self.details = tk.Text(body, height=8, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky="ew", pady=(9, 5))
        ttk.Label(body, textvariable=self.status, wraplength=720).grid(row=5, column=0, sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=6, column=0, sticky="ew", pady=(11, 0))
        self.refresh_button = ttk.Button(buttons, text="Проверить сервер", command=self.refresh)
        self.refresh_button.pack(side="left")
        self.verify_button = ttk.Button(buttons, text="Проверить выбранную", command=self.verify)
        self.verify_button.pack(side="left", padx=(8, 0))
        self.create_button = ttk.Button(buttons, text="Создать копию…", command=self.create)
        self.create_button.pack(side="left", padx=(8, 0))
        restore_buttons = ttk.Frame(body)
        restore_buttons.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        self.restore_button = ttk.Button(restore_buttons, text="Восстановить…", command=self.restore)
        self.restore_button.pack(side="left", padx=(8, 0))
        self.restore_status_button = ttk.Button(restore_buttons, text="Состояние восстановления",
                                                command=self.check_restore)
        self.restore_status_button.pack(side="left", padx=(8, 0))
        self.recover_button = ttk.Button(restore_buttons, text="Исправить сбой…",
                                         command=self.recover_restore)
        self.recover_button.pack(side="left", padx=(8, 0))
        self.restore_history_button = ttk.Button(restore_buttons, text="История восстановлений",
                                                 command=self.restore_history)
        self.restore_history_button.pack(side="left", padx=(8, 0))
        self.close_button = ttk.Button(buttons, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> HubBackupController:
        if self.controller is None:
            self.controller = HubBackupController(
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
        no_pending_restore = (self.restore_request_id is None or
                              self.restore_result is not None and
                              self.restore_result.phase in ("complete", "failed_recovered") and
                              self.restore_result.hub_running is True)
        self.refresh_button.configure(state="normal" if ready else "disabled")
        self.verify_button.configure(state="normal" if ready and self.state is not None and
                                     self.list.selection() else "disabled")
        self.create_button.configure(state="normal" if ready and self.state is not None and
                                     no_pending_restore else "disabled")
        selected = self.list.selection()
        self.restore_button.configure(state="normal" if ready and self.state is not None and
                                      self.verified is not None and selected and
                                      selected[0] == self.verified.id and no_pending_restore
                                      else "disabled")
        self.restore_status_button.configure(state="normal" if ready and self.restore_request_id
                                             else "disabled")
        self.recover_button.configure(state="normal" if ready and self.restore_request_id and
                                      self.restore_result is not None and
                                      self.restore_result.phase not in ("complete", "failed_recovered")
                                      else "disabled")
        self.restore_history_button.configure(state="normal" if ready else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def _selection_changed(self, _event=None) -> None:
        selected = self.list.selection()
        if self.verified is not None and (not selected or selected[0] != self.verified.id):
            self.verified = None
            self._show("")
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

    def _render_state(self, state: HubBackupState) -> None:
        self.state = state
        self.verified = None
        for row in self.list.get_children():
            self.list.delete(row)
        for identity in state.ids:
            self.list.insert("", "end", iid=identity, values=(identity,))
        self.status.set(f"Найдено копий: {len(state.ids)}. Выберите копию для проверки."
                        if state.ids else "Копий пока нет. Можно создать первую.")
        self._controls()

    def refresh(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.state = None
        self.verified = None
        self._show("")
        self.status.set("Сверяем установленный код Hub и список копий…")
        self._run("refreshed", self._controller().inspect)

    def verify(self) -> None:
        if self.busy or self.state is None or not self.list.selection():
            return
        identity = self.list.selection()[0]
        if identity not in self.state.ids:
            return
        self.status.set("Проверяем содержимое и целостность выбранной копии…")
        self._run("verified", lambda: self._controller().verify(identity))

    def restore(self) -> None:
        if (self.busy or self.state is None or self.verified is None or
                self.list.selection() != (self.verified.id,)):
            return
        if self.restore_request_id and (self.restore_result is None or
                self.restore_result.phase not in ("complete", "failed_recovered") or
                self.restore_result.hub_running is not True):
            return
        reviewed, details = self.state, self.verified
        created = datetime.fromtimestamp(details.created_at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if not messagebox.askyesno("Восстановить Hub?", (
                f"Сервер: {self.options.user}@{self.options.host}:{self.options.port}\n"
                f"Копия: {details.id}\nСоздана: {created}\n\n"
                "Hub временно остановится. Перед заменой будет создана страховочная копия текущих данных. "
                "Сеансы и ожидающие команды после восстановления будут сброшены. "
                "Продолжить?"), parent=self.window):
            return
        request_id = str(uuid.uuid4())
        self.restore_request_id, self.restore_result = request_id, None
        self.status.set("Останавливаем Hub и создаём страховочную копию. Не повторяйте действие при потере связи…")
        self._run("restored", lambda: self._controller().restore(reviewed, details, request_id))

    def check_restore(self) -> None:
        if self.busy or not self.restore_request_id:
            return
        request_id = self.restore_request_id
        self.status.set("Читаем сохранённое состояние восстановления…")
        self._run("restore_status", lambda: self._controller().restore_status(request_id))

    def recover_restore(self) -> None:
        result = self.restore_result
        if (self.busy or not self.restore_request_id or result is None or
                result.phase in ("complete", "failed_recovered")):
            return
        request_id = result.request_id
        if not messagebox.askyesno("Восстановление после сбоя", (
                f"Сервер: {self.options.user}@{self.options.host}:{self.options.port}\n"
                f"Запрос: {request_id}\nСостояние: {_RESTORE_PHASE[result.phase]}\n\n"
                "Сверить контейнер и данные с сохранённым планом, затем продолжить безопасную часть "
                "восстановления или вернуть прежние данные? При неясном состоянии Hub останется остановлен."
                ), parent=self.window):
            return
        self.status.set("Сверяем сохранённый план. Не повторяйте действие при потере связи…")
        self._run("recovered", lambda: self._controller().recover_restore(request_id))

    def restore_history(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.status.set("Читаем историю восстановлений на сервере…")
        self._run("restore_history", self._controller().restore_list)

    def _render_restore(self, result: HubRestoreStatus) -> None:
        self.restore_request_id, self.restore_result = result.request_id, result
        self._show(_restore_text(result))
        if result.phase == "complete" and result.hub_running is True:
            self.status.set("Hub запущен, восстановление завершено. Войдите в панель заново.")
            self.state = None
            self.verified = None
        elif result.phase == "failed_recovered":
            self.status.set("Восстановление не завершилось; прежние данные возвращены. Проверьте Hub.")
        elif result.phase == "recovery_required":
            self.status.set("Требуется восстановление сервера. Hub может быть остановлен; страховочная копия и план сохранены. Не запускайте новое восстановление.")
        else:
            self.status.set("Сервер продолжает восстановление. Используйте «Состояние восстановления» для проверки.")

    def _show_restore_history(self, records: tuple[HubRestoreStatus, ...]) -> None:
        window = tk.Toplevel(self.window)
        window.title("История восстановлений · SovaGrid")
        window.transient(self.window)
        window.geometry("810x410")
        self.theme.style_window(window)
        body = ttk.Frame(window, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Выберите запрос, чтобы проверить его состояние", wraplength=760).pack(anchor="w")
        tree = ttk.Treeview(body, columns=("time", "phase", "backup", "hub"), show="headings")
        for key, title, width in (("time", "Начало UTC", 160), ("phase", "Состояние", 245),
                                  ("backup", "Копия", 160), ("hub", "Hub", 105)):
            tree.heading(key, text=title)
            tree.column(key, width=width)
        tree.pack(fill="both", expand=True, pady=(10, 8))
        for row in records:
            created = datetime.fromtimestamp(row.created_at, timezone.utc).strftime("%Y-%m-%d %H:%M")
            hub = {True: "Работает", False: "Остановлен", None: "Неизвестно"}[row.hub_running]
            tree.insert("", "end", iid=row.request_id,
                        values=(created, _RESTORE_PHASE[row.phase], (row.target_id or "—")[:8], hub))
        actions = ttk.Frame(body)
        actions.pack(fill="x")
        def inspect_selected():
            selected = tree.selection()
            if not selected:
                return
            self.restore_request_id = selected[0]
            self.restore_result = None
            window.destroy()
            self.check_restore()
        ttk.Button(actions, text="Проверить выбранное", command=inspect_selected).pack(side="left")
        ttk.Button(actions, text="Закрыть", command=window.destroy).pack(side="right")
        if not records:
            self.status.set("Восстановлений на сервере пока нет.")
        else:
            self.status.set(f"В истории восстановлений: {len(records)}. Выберите запрос для проверки.")

    def create(self) -> None:
        if (self.busy or self.state is None or
                self.restore_request_id is not None and
                (self.restore_result is None or self.restore_result.phase not in
                 ("complete", "failed_recovered") or self.restore_result.hub_running is not True)):
            return
        reviewed = self.state
        if not messagebox.askyesno("Создать копию Hub?", (
                f"Сервер: {self.options.user}@{self.options.host}:{self.options.port}\n"
                f"Проверенных записей в списке: {len(reviewed.ids)}\n\n"
                "Создать новый снимок базы Hub и токена Telegram на этом сервере? "
                "Операция не меняет текущие данные Hub."), parent=self.window):
            return
        self.status.set("Создаём и проверяем новую копию. Это может занять несколько минут…")
        self._run("created", lambda: (self._controller().create(reviewed),
                                      self._controller().inspect()))

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
                self._show(_details_text(payload))
                self.status.set("Копия прошла проверку. Секреты не показаны в приложении.")
            elif event == "created":
                details, state = payload
                self._render_state(state)
                self.list.selection_set(details.id)
                self.list.see(details.id)
                self.verified = details
                self._show(_details_text(details))
                self.status.set("Новая копия создана и проверена на сервере.")
            elif event in ("restored", "restore_status", "recovered"):
                self._render_restore(payload)
            elif event == "restore_history":
                self._show_restore_history(payload)
            elif event == "error":
                kind, error = payload
                if kind not in ("restored", "restore_status", "restore_history", "recovered"):
                    self.state = None
                    self.verified = None
                    self._show("")
                message = str(error) if isinstance(error, InstallError) else (
                    "Результат не подтверждён. Проверьте список копий перед повтором.")
                if kind in ("restored", "restore_status", "recovered") and self.restore_request_id:
                    message += ("\nЗапрос: " + self.restore_request_id +
                                "\nПроверьте его состояние в этом окне или в истории восстановлений.")
                self.status.set(message)
                messagebox.showerror("Резервные копии Hub", message, parent=self.window)
            self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Резервные копии Hub", "Дождитесь ответа сервера.", parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
