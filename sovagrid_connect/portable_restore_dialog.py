# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Restore a portable backup onto a clean SSH target without shell commands."""
from __future__ import annotations

from datetime import datetime, timezone
from copy import deepcopy
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .installer import InstallError
from .portable_restore import PortableRestoreController, RestoreRecordStore, SHA
from .server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256, cached_published_server_bundle


PHASES = {"receiving": "Передача копии", "ready": "Копия проверена", "review": "План готов",
          "accepted": "Принято сервером", "starting": "Запуск на сервере", "applying": "Восстановление",
          "recovering": "Безопасный откат", "committed": "Восстановлено и проверено",
          "rolled_back": "Прежнее состояние цели возвращено", "recovery_required": "Нужна проверка восстановления",
          "failed": "Операция остановлена", "retry_required": "Нужно завершить подготовку повтора",
          "finished": "Проверка серверной операции завершена"}
BLOCKERS = {
    "APPLY_NOT_IMPLEMENTED": "В выбранном выпуске исполнителя полное восстановление ещё не включено.",
    "TARGET_NOT_CLEAN": "На целевом сервере уже есть данные SovaGrid.",
    "TARGET_NOT_EMPTY": "На целевом сервере уже есть данные SovaGrid.",
    "RECEIPT_V1_UNSUPPORTED": "Нужна переносимая копия нового формата v2.",
    "RESTORE_LAYOUT_UNSUPPORTED": "Эта копия имеет неподдерживаемую схему установки.",
    "RESTORE_DISK_SPACE": "На целевом сервере недостаточно свободного места.",
    "RESTORE_ROUTING_STATE_UNSUPPORTED": "В копии включена VPN-маршрутизация, перенос которой пока не поддерживается.",
    "RESTORE_IDENTITY_EXISTS": "На цели уже заняты служебные учётные записи из копии.",
    "RESTORE_RUNTIME_STATE_PRESENT": "На цели уже есть рабочие данные восстанавливаемой службы.",
    "STALE_RESTORE_REVIEW": "Состояние изменилось. Получите новый план перед подтверждением.",
}


def review_text(reply, record, options):
    lines = [f"Цель: {options.user}@{options.host}:{options.port}",
             f"Копия: {record['request']['archive_id']}",
             f"Операция: {record['operation_id']}",
             "Состояние: " + PHASES.get(reply.get("phase"), "Проверка состояния")]
    if options.jump_host:
        lines.append(f"Через SSH-хост: {options.jump_host}:{options.jump_port}")
    preview = reply.get("preview")
    if isinstance(preview, dict):
        for key, label in (("target_free_bytes", "Свободно"), ("required_free_bytes", "Требуется")):
            value = preview.get(key)
            if type(value) is int:
                lines.append(f"{label}: {value / 1024**3:.2f} ГиБ")
    if reply.get("blockers"):
        lines.append("\nДля продолжения:")
        lines.extend("• " + BLOCKERS.get(code, "Проверка сервера: " + code)
                     for code in reply["blockers"])
    if reply.get("apply_available"):
        lines.extend(("\nБудут восстановлены Hub, Agent, данные, образы и поддерживаемые службы.",
                      "Ожидающие команды и подтверждения Telegram из копии будут отменены.",
                      "Запуск VPN после переноса выполняется отдельно.",
                      "Работающий код из выбранной резервной копии будет запущен на целевом сервере."))
    if reply.get("worker_active"):
        lines.append("\nСервер выполняет операцию самостоятельно. Приложение можно закрыть и подключиться позже.")
    if reply.get("phase") == "recovery_required":
        lines.append("\nАвтоматическое восстановление не завершено. Данные сохранены; повторное применение закрыто. "
                     "Отдельная проверка безопасного отката сохранит данные, если они уже изменились.")
    if reply.get("phase") == "committed":
        lines.append("\nПроверка завершилась успешно. Можно открыть восстановленную панель через SSH.")
    return "\n".join(lines)


class PortableRestoreDialog:
    def __init__(self, root, theme, options, on_closed, *, on_ready=None,
                 controller_factory=PortableRestoreController, store=None, bundle_loader=cached_published_server_bundle):
        self.root, self.options, self.on_closed, self.on_ready = root, options, on_closed, on_ready
        self.factory, self.bundle_loader = controller_factory, bundle_loader
        self.store = store or RestoreRecordStore.default()
        self.controller = None
        self.record = self.reply = None
        self.busy = self.closed = False
        self.events = queue.SimpleQueue()
        self.next_poll = 0.0
        self.history = {}
        self.folder = tk.StringVar()
        self.selection = tk.StringVar(value="Новая операция")
        self.status = tk.StringVar(value="Выберите папку с пятью файлами переносимой копии.")
        self.window = tk.Toplevel(root)
        self.window.title("Восстановить сервер из копии · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("820x680")
        self.window.minsize(660, 560)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(6, weight=1)
        ttk.Label(body, text=f"Чистый Ubuntu-сервер: {options.user}@{options.host}:{options.port}",
                  font=("TkDefaultFont", 12, "bold")).grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Label(body, wraplength=740, text=(
            "SSH-адрес, ключ или пароль и промежуточный хост берутся из основного окна. "
            "Мастер доставит проверенный исполнитель и зависимости, передаст копию и покажет план. "
            "Обычная установка SovaGrid на цель перед восстановлением не нужна."
        )).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 14))
        ttk.Label(body, text="Сохранённая операция").grid(row=2, column=0, sticky="w")
        self.saved = ttk.Combobox(body, textvariable=self.selection, state="readonly")
        self.saved.grid(row=3, column=0, sticky="ew", pady=(4, 10))
        self.saved.bind("<<ComboboxSelected>>", self.select_saved)
        self.choose_button = ttk.Button(body, text="Выбрать папку копии…", command=self.choose_folder)
        self.choose_button.grid(row=3, column=1, padx=(10, 0), pady=(4, 10))
        ttk.Label(body, textvariable=self.folder, wraplength=730).grid(
            row=4, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Label(body, textvariable=self.status, wraplength=730).grid(row=5, column=0, columnspan=2, sticky="ew")
        self.details = tk.Text(body, wrap="word", height=15, state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=(10, 10))
        self.progress = ttk.Progressbar(body, mode="indeterminate")
        self.progress.grid(row=7, column=0, columnspan=2, sticky="ew")
        first = ttk.Frame(body)
        first.grid(row=8, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.prepare_button = ttk.Button(first, text="Подготовить и проверить…", command=self.prepare)
        self.prepare_button.pack(side="left")
        self.status_button = ttk.Button(first, text="Проверить состояние", command=self.check)
        self.status_button.pack(side="left", padx=(8, 0))
        self.apply_button = ttk.Button(first, text="Восстановить сервер…", command=self.apply)
        self.apply_button.pack(side="left", padx=(8, 0))
        second = ttk.Frame(body)
        second.grid(row=9, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.recover_button = ttk.Button(second, text="Проверить безопасный откат…", command=self.recover)
        self.recover_button.pack(side="left")
        self.retry_button = ttk.Button(second, text="Новая проверка после отката…", command=self.retry)
        self.retry_button.pack(side="left", padx=(8, 0))
        self.open_button = ttk.Button(second, text="Открыть панель", command=self.open_panel)
        self.open_button.pack(side="left", padx=(8, 0))
        ttk.Button(second, text="Закрыть", command=self.close).pack(side="left", padx=(8, 0))
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.reload_history()
        self.controls()
        self.timer = self.window.after(100, self.pump)

    def reload_history(self):
        try:
            self.history = {}
            for record in self.store.for_target(self.options):
                stamp = datetime.fromtimestamp(record["created_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                self.history[f"{stamp} · {record['operation_id'][:12]}"] = record
            self.saved.configure(values=("Новая операция", *self.history))
        except (InstallError, OSError) as exc:
            self.status.set(str(exc))

    def select_saved(self, _event=None):
        if self.controller:
            self.controller.cancel()
            self.controller = None
        self.record = self.history.get(self.selection.get())
        self.reply = None
        self.folder.set(self.record["folder"] if self.record else "")
        self.status.set("Сначала проверьте состояние сохранённой операции." if self.record else
                        "Выберите папку с пятью файлами переносимой копии.")
        self.show("")
        self.controls()

    def choose_folder(self):
        selected = filedialog.askdirectory(title="Папка переносимой копии SovaGrid", parent=self.window,
                                          mustexist=True)
        if selected:
            if self.controller:
                self.controller.cancel()
                self.controller = None
            self.selection.set("Новая операция")
            self.record = self.reply = None
            self.folder.set(selected)
            self.status.set("Копия выбрана. Подготовьте сервер, чтобы получить точный план.")
            self.show("")
            self.controls()

    def show(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def controls(self):
        idle = not self.busy
        state = self.reply or {}
        active = state.get("worker_active") is True
        self.prepare_button.configure(state="normal" if idle and self.folder.get() and not active and
                                      state.get("phase") not in ("committed", "recovery_required", "rolled_back") else "disabled")
        self.status_button.configure(state="normal" if idle and self.record else "disabled")
        digest = state.get("apply_review_sha256")
        self.apply_button.configure(state="normal" if idle and state.get("apply_available") is True and
                                    isinstance(digest, str) and SHA.fullmatch(digest) else "disabled")
        self.recover_button.configure(state="normal" if idle and self.record and not active and
                                      state.get("phase") in ("accepted", "starting", "applying", "recovering", "recovery_required", "failed") else "disabled")
        terminal = state.get("terminal_sha256")
        self.retry_button.configure(state="normal" if idle and state.get("retry_available") is True and
                                    isinstance(terminal, str) and SHA.fullmatch(terminal) else "disabled")
        self.open_button.configure(state="normal" if idle and state.get("phase") == "committed" and self.on_ready else "disabled")
        self.choose_button.configure(state="normal" if idle and not active else "disabled")
        self.saved.configure(state="readonly" if idle else "disabled")

    def run(self, task):
        if self.busy or self.closed:
            return
        self.busy = True
        self.next_poll = 0.0
        self.progress.start(15)
        if self.controller is None:
            self.controller = self.factory(self.options, approved_archive_sha256=PUBLISHED_SERVER_SOURCE_SHA256,
                                           store=self.store,
                                           progress=lambda message: self.events.put(("progress", message)))
        self.controls()

        def worker():
            try:
                self.events.put(("result", task(self.controller)))
            except (InstallError, OSError, ValueError) as exc:
                self.events.put(("error", (str(exc), getattr(self.controller, "current_record", None))))
            except Exception:
                self.events.put(("error", ("Не удалось завершить запрос. Проверьте сохранённую операцию перед повтором.",
                                           getattr(self.controller, "current_record", None))))

        threading.Thread(target=worker, daemon=True).start()

    def prepare(self):
        if self.busy or not self.folder.get():
            return
        if self.record and self.reply and self.reply.get("registered") is True:
            saved = deepcopy(self.record)
            self.run(lambda controller: (saved, controller.action(saved, "preview")))
            return
        folder, saved = Path(self.folder.get()), deepcopy(self.record)
        if not messagebox.askyesno("Подготовить восстановление",
                f"Цель: {self.options.user}@{self.options.host}:{self.options.port}\n\n"
                f"Копия: {folder}\n\n"
                "На сервер будут доставлены проверенный исполнитель и выбранная копия. "
                "Недостающие системные зависимости установятся автоматически. "
                "Применение копии потребует отдельного подтверждения после проверки плана.", parent=self.window):
            return

        def task(controller):
            runner = Path(saved["runner_path"]) if saved else self.bundle_loader(
                progress=lambda text: self.events.put(("progress", text)))
            return controller.prepare(folder, runner, record=saved)

        self.run(task)

    def check(self):
        if self.record:
            saved = self.record
            self.run(lambda controller: (saved, controller.action(saved, "operation-status")))

    def apply(self):
        if not self.record or not self.reply or self.reply.get("apply_available") is not True:
            return
        saved, reviewed = deepcopy(self.record), deepcopy(self.reply)
        digest = reviewed["apply_review_sha256"]
        if not messagebox.askyesno("Восстановить выбранный сервер",
                review_text(reviewed, saved, self.options) +
                "\n\nПрименить этот план на указанном сервере?", parent=self.window):
            return
        if self.record != saved or self.reply != reviewed:
            self.status.set("План изменился во время подтверждения. Проверьте состояние заново.")
            self.reply = None
            self.controls()
            return
        self.run(lambda controller: (saved, controller.action(saved, "start", apply_review_sha256=digest)))

    def recover(self):
        saved = deepcopy(self.record)
        if saved and messagebox.askyesno("Проверить безопасный откат",
                "Исполнитель проверит сохранённую операцию и попробует завершить её откат. "
                "Изменённые работающей системой данные сохранятся; неоднозначное состояние остановит автоматический откат.",
                parent=self.window):
            self.run(lambda controller: (saved, controller.action(saved, "recover")))

    def retry(self):
        if not self.record or not self.reply or self.reply.get("retry_available") is not True:
            return
        saved, reviewed = deepcopy(self.record), deepcopy(self.reply)
        terminal = reviewed["terminal_sha256"]
        if messagebox.askyesno("Повторная проверка",
                "Предыдущая попытка завершилась откатом. Сохранить её историю и получить новый план? "
                "Повторное применение снова потребует подтверждения.", parent=self.window):
            if self.record != saved or self.reply != reviewed:
                self.status.set("Состояние отката изменилось. Проверьте его заново.")
                self.reply = None
                self.controls()
                return
            self.run(lambda controller: (saved, controller.action(saved, "retry", terminal_sha256=terminal)))

    def pump(self):
        if self.closed:
            return
        while not self.events.empty():
            event, payload = self.events.get()
            if event == "progress":
                self.status.set(payload)
                continue
            self.busy = False
            self.progress.stop()
            self.reload_history()
            if event == "error":
                message, saved = payload
                if saved is not None:
                    self.record = saved
                self.reply = None
                self.status.set(message + (" Проверьте состояние сохранённой операции." if self.record else ""))
                self.show("План не подтверждён." +
                          (f"\nСохранённая операция: {self.record['operation_id']}\nПроверьте её состояние перед повтором."
                           if self.record else ""))
            else:
                self.record, self.reply = payload
                self.show(review_text(self.reply, self.record, self.options))
                self.status.set(PHASES.get(self.reply["phase"], "Состояние получено"))
                if self.reply.get("worker_active") or self.reply["phase"] in ("accepted", "starting", "applying", "recovering"):
                    self.next_poll = time.monotonic() + 3
            self.controls()
        if self.next_poll and time.monotonic() >= self.next_poll and not self.busy:
            self.check()
        self.timer = self.window.after(100, self.pump)

    def open_panel(self):
        if self.reply and self.reply.get("phase") == "committed" and self.on_ready:
            ready = self.on_ready
            self.close()
            self.root.after(0, ready)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.controller:
            self.controller.cancel()
        self.window.after_cancel(self.timer)
        self.progress.stop()
        self.window.destroy()
        self.on_closed()
