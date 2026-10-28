# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first Tk wizard for an Agent-only host's independent local Hub."""

from __future__ import annotations

from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .installer import InstallError, nearby_server_bundle
from .promotion import PromotionController, PromotionPreview


_PHASE_LABEL = {
    "eligible": "Внешний Agent работает; локального Hub ещё нет",
    "prepared": "Снимок внешнего Agent сохранён; пакет ещё не передан",
    "source_staged": "Проверенные исходники переданы; Hub ещё не запущен",
    "hub_installed": "Локальный Hub работает; отдельный Agent ещё не подключён",
    "activated": "Локальный Hub и отдельный Agent активны",
}


class PromotionDialog:
    def __init__(self, root, theme, options, on_closed, on_ready, *, approved_sha256: str | None):
        self.root, self.theme, self.options = root, theme, options
        self.on_closed, self.on_ready = on_closed, on_ready
        self.approved_sha256 = approved_sha256
        self.controller: PromotionController | None = None
        self.preview_result: PromotionPreview | None = None
        self.ready_state = None
        self.busy = False
        self.closed = False
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        nearby = nearby_server_bundle()
        suggested = str(nearby[0]) if nearby and nearby[1] == approved_sha256 else ""
        self.source = tk.StringVar(value=suggested)
        self.status = tk.StringVar(value=(
            "Выберите пакет и проверьте сервер без изменений."
            if approved_sha256 is not None else
            "Мастер ждёт проверенный выпуск с протоколом сохранения внешнего Agent."
        ))

        window = self.window = tk.Toplevel(root)
        window.title("Собственный Hub на сервере с Agent · SovaGrid Connect")
        window.transient(root)
        window.geometry("760x520")
        window.minsize(620, 420)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        theme.style_window(window)
        body = ttk.Frame(window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(5, weight=1)
        ttk.Label(body, text="Собственный Hub для сервера с внешним Agent",
                  font=("TkDefaultFont", 14, "bold")).grid(row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        self.route_label = ttk.Label(body, text="SSH-маршрут: " + route, wraplength=700)
        self.route_label.grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Label(
            body,
            text="Мастер оставит существующий Agent, его ключи, данные и обратный туннель. "
                 "Собственный Hub создаст отдельные аккаунты и отдельного локального Agent. "
                 "Команды нового Agent сначала выключены. Нужен root либо существующее sudo без запроса пароля. "
                 "Для панели нужен проверенный SSH-маршрут.",
            wraplength=700,
        ).grid(row=2, column=0, sticky="w", pady=(9, 12))
        chooser = ttk.Frame(body)
        chooser.grid(row=3, column=0, sticky="ew")
        chooser.columnconfigure(0, weight=1)
        self.source_entry = ttk.Entry(chooser, textvariable=self.source, state="readonly")
        self.source_entry.grid(row=0, column=0, sticky="ew")
        ttk.Button(chooser, text="Выбрать проверенный пакет…", command=self._choose).grid(
            row=0, column=1, padx=(8, 0))
        self.source.trace_add("write", lambda *_args: self._invalidate())
        self.details = tk.Text(body, height=10, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=5, column=0, sticky="nsew", pady=(12, 8))
        ttk.Label(body, textvariable=self.status, wraplength=700).grid(row=6, column=0, sticky="w", pady=(3, 9))
        buttons = ttk.Frame(body)
        buttons.grid(row=7, column=0, sticky="w")
        self.check_button = ttk.Button(buttons, text="Проверить без изменений", command=self.check,
                                       state="normal" if approved_sha256 else "disabled")
        self.check_button.pack(side="left")
        self.apply_button = ttk.Button(buttons, text="Создать локальный Hub", command=self.apply,
                                       state="disabled")
        self.apply_button.pack(side="left", padx=(8, 0))
        self.open_button = ttk.Button(buttons, text="Проверить и открыть панель", command=self.open_panel,
                                      state="disabled")
        self.open_button.pack(side="left", padx=(8, 0))
        ttk.Button(buttons, text="Закрыть", command=self.close).pack(side="left", padx=(8, 0))
        window.protocol("WM_DELETE_WINDOW", self.close)
        window.after(100, self._pump)

    def _show(self, value: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", value)
        self.details.configure(state="disabled")

    def _invalidate(self) -> None:
        self.preview_result = None
        self.ready_state = None
        self.apply_button.configure(state="disabled")
        self.open_button.configure(state="disabled")
        self._show("")

    def _choose(self) -> None:
        if self.busy:
            return
        selected = filedialog.askopenfilename(parent=self.window, title="Проверенный пакет SovaGrid",
                                               filetypes=[("Архив SovaGrid", "*.tar.gz"), ("Все файлы", "*")])
        if selected:
            self.source.set(selected)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.check_button.configure(state="disabled" if busy or not self.approved_sha256 else "normal")
        self.apply_button.configure(state="disabled" if busy or self.preview_result is None or
                                    self.ready_state is not None else "normal")
        self.open_button.configure(state="disabled" if busy or self.ready_state is None else "normal")

    def check(self) -> None:
        if self.busy or not self.approved_sha256 or not self.source.get():
            return
        self._invalidate()
        self._set_busy(True)
        self.status.set("Проверка пакета и внешнего Agent без изменений…")
        selected = Path(self.source.get())

        def worker() -> None:
            try:
                controller = PromotionController(
                    self.options, approved_archive_sha256=self.approved_sha256,
                    progress=lambda text: self.events.put(("progress", text)),
                )
                result = controller.preview(selected)
                self.events.put(("checked", (controller, result)))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def apply(self) -> None:
        result, controller = self.preview_result, self.controller
        if self.busy or result is None or controller is None:
            return
        route = f"{self.options.user}@{self.options.host}:{self.options.port}"
        if self.options.jump_host:
            route += f" через {self.options.jump_user}@{self.options.jump_host}:{self.options.jump_port}"
        if not messagebox.askyesno(
            "Создать локальный Hub",
            f"SSH-сервер: {route}\n"
            f"SHA-256 архива: {result.archive_sha256}\n"
            f"SHA-256 манифеста: {result.manifest_sha256}\n"
            f"Текущее состояние: {_PHASE_LABEL[result.state.phase]}\n\n"
            "Создать отдельный локальный Hub? Работающий внешний Agent и его туннель будут сохранены. "
            "На сервере могут устанавливаться Docker и другие зависимости; работа нового Hub начнётся после проверки.",
            parent=self.window,
        ):
            return
        self._set_busy(True)
        self.status.set("Выполняется подтверждённая операция. Не закрывайте окно…")
        selected = Path(self.source.get())

        def worker() -> None:
            try:
                state = controller.apply(selected, result)
                self.events.put(("applied", state))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def open_panel(self) -> None:
        state = self.ready_state
        if state is not None and not self.busy:
            self.on_ready(self.options, state)

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
            elif event == "checked":
                self.controller, self.preview_result = payload
                preview = self.preview_result
                state = preview.state
                self._show(
                    f"SSH: {preview.options.user}@{preview.options.host}:{preview.options.port}\n"
                    f"Архив SHA-256: {preview.archive_sha256}\n"
                    f"Манифест SHA-256: {preview.manifest_sha256}\n"
                    f"Проверено файлов: {preview.bundle.files}\n"
                    f"Состояние: {_PHASE_LABEL[state.phase]}\n"
                    f"Снимок внешнего Agent: {state.baseline_sha256 or 'будет создан после подтверждения'}\n"
                    "Внешний Agent и SSH-туннель подтверждены."
                )
                if state.phase == "activated":
                    self.ready_state = state
                    self.status.set("Локальный Hub уже активен. Проверьте панель и свежие метрики.")
                else:
                    self.status.set("План готов. Сверьте SSH-сервер и SHA-256 перед подтверждением.")
                self._set_busy(False)
            elif event == "applied":
                self.ready_state = payload
                self.status.set("Локальный Hub активен. Осталась независимая проверка панели и метрик.")
                self._set_busy(False)
            elif event == "error":
                self._set_busy(False)
                self.preview_result = None
                self.ready_state = None
                self.apply_button.configure(state="disabled")
                self.open_button.configure(state="disabled")
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Проверка не завершена. Повторно проверьте сервер; секреты и вывод SSH не показываются."
                )
                self.status.set(message)
                messagebox.showerror("Локальный Hub", message, parent=self.window)
        self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo("Локальный Hub", "Операция выполняется. Дождитесь результата; при потере связи "
                                "повторная проверка покажет этап продолжения.", parent=self.window)
            return
        self.closed = True
        self.window.destroy()
        self.on_closed()
