# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review public HTTPS settings and apply them without terminal input."""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk
import webbrowser

from .public_web import (DEFAULT_PANEL_PATH, PublicWebError, PublicWebRPC,
                         config_for_address, public_panel_url, public_url, validate_config)


ROOT_CHOICES = {
    "Не занимать корень сайта /": "untouched",
    "Показывать панель, как сейчас": "panel",
    "Перенаправлять на путь панели": "redirect",
    "Не открывать панель на корне": "not_found",
}
ROOT_LABELS = {value: label for label, value in ROOT_CHOICES.items()}


class PublicWebDialog:
    def __init__(self, root, theme, options, on_closed, *, rpc_factory=PublicWebRPC):
        self.options, self.on_closed, self.rpc_factory = options, on_closed, rpc_factory
        self.rpc = self.progress_binding = None
        self.current = self.preview = None
        self.confirmed_url = None
        self.generation = 0
        self.busy = self.closed = self.close_requested = False
        self.events = queue.SimpleQueue()
        self.window = tk.Toplevel(root)
        self.window.title("Публичный HTTPS · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry(f"690x{min(730, max(500, self.window.winfo_screenheight() - 140))}")
        self.window.minsize(540, 500)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        shell = ttk.Frame(self.window, padding=18)
        shell.grid(sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)
        canvas = tk.Canvas(shell, highlightthickness=0, borderwidth=0, background=self.window.cget("background"))
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        canvas.configure(yscrollcommand=scroll.set)
        body = ttk.Frame(canvas, padding=(0, 0, 10, 0))
        body.columnconfigure(0, weight=1)
        item = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        def resize(event):
            canvas.itemconfigure(item, width=event.width)
            for child in body.winfo_children():
                if isinstance(child, ttk.Label):
                    child.configure(wraplength=max(280, event.width - 20))
        canvas.bind("<Configure>", resize)
        self.window.bind("<MouseWheel>", lambda event: canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"))
        self.window.bind("<Button-4>", lambda _event: canvas.yview_scroll(-3, "units"))
        self.window.bind("<Button-5>", lambda _event: canvas.yview_scroll(3, "units"))
        ttk.Label(body, text="Панель на телефоне — по обычной ссылке", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 10))
        ttk.Label(body, text=f"Сервер: {options.user}@{options.host}:{options.port}", wraplength=620).grid(
            row=1, column=0, sticky="w", pady=(0, 10))
        ttk.Label(body, text="Укажите публичный IP сервера или свой домен. Мастер проверит адрес, включит HTTPS "
            "и подтвердит сертификат. Затем откройте панель на телефоне и нажмите «Сделать приложением». "
            "На первой странице доступен вход по SSH или по учётной записи панели.", wraplength=620).grid(row=2, column=0, sticky="w")
        try:
            initial = config_for_address(options.host)["address"]
        except PublicWebError:
            initial = ""
        self.address = tk.StringVar(value=initial)
        self.panel_path = tk.StringVar(value=DEFAULT_PANEL_PATH)
        self.root_behavior = tk.StringVar(value=ROOT_LABELS["untouched"])
        self.status = tk.StringVar(value="Проверяем текущие настройки по SSH…")
        self.state_label = tk.StringVar(value="Состояние ещё не проверено.")
        address_row = ttk.Frame(body, padding=(0, 14, 0, 0))
        address_row.grid(row=3, column=0, sticky="ew")
        address_row.columnconfigure(0, weight=1)
        ttk.Label(address_row, text="Публичный IP или домен (без https://)").grid(row=0, column=0, sticky="w")
        self.address_entry = ttk.Entry(address_row, textvariable=self.address)
        self.address_entry.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(address_row, text="Путь панели").grid(row=2, column=0, sticky="w", pady=(13, 0))
        self.path_entry = ttk.Entry(address_row, textvariable=self.panel_path)
        self.path_entry.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(address_row, text="Что показывать по адресу /").grid(row=4, column=0, sticky="w", pady=(13, 0))
        self.root_select = ttk.Combobox(address_row, textvariable=self.root_behavior,
                                        values=list(ROOT_CHOICES), state="readonly")
        self.root_select.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        ttk.Label(body, text="В этой версии используйте публичный IPv4. Для домена заранее направьте DNS-запись A "
            "на этот сервер; записей AAAA быть не должно. "
            "Для выдачи и продления сертификата нужны входящие порты 80 и 443. "
            "Используется доверенный сертификат Let's Encrypt с автоматическим продлением.", wraplength=620).grid(
            row=4, column=0, sticky="w", pady=(10, 12))
        ttk.Label(body, textvariable=self.state_label, wraplength=620).grid(row=5, column=0, sticky="w", pady=(0, 8))
        self.details = tk.Text(body, height=9, width=65, wrap="word", state="disabled")
        self.details.grid(row=6, column=0, sticky="ew")
        theme.style_text(self.details)
        status_label = ttk.Label(shell, textvariable=self.status, wraplength=620)
        status_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(12, 10))
        shell.bind("<Configure>", lambda event: status_label.configure(wraplength=max(280, event.width - 36)))
        controls = ttk.Frame(shell)
        controls.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.check_button = ttk.Button(controls, text="Проверить", command=self.check)
        self.check_button.pack(side="left")
        self.apply_button = ttk.Button(controls, text="Включить HTTPS", command=self.apply, state="disabled")
        self.apply_button.pack(side="left", padx=8)
        self.disable_button = ttk.Button(controls, text="Отключить HTTPS", command=self.disable, state="disabled")
        self.disable_button.pack(side="left")
        footer = ttk.Frame(shell, padding=(0, 10, 0, 0))
        footer.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.open_button = ttk.Button(footer, text="Открыть проверенный сайт", command=self.open_site, state="disabled")
        self.open_button.pack(side="left")
        self.close_button = ttk.Button(footer, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        self.address.trace_add("write", self._edited)
        self.panel_path.trace_add("write", self._edited)
        self.root_behavior.trace_add("write", self._edited)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.grab_set()
        self._pump_after = self.window.after(100, self.pump)
        self._refresh_after = self.window.after(0, self._initial_refresh)

    def _show(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _controls(self):
        available = not self.busy and not self.close_requested
        self.address_entry.configure(state="normal" if available else "disabled")
        self.path_entry.configure(state="normal" if available else "disabled")
        self.root_select.configure(state="readonly" if available else "disabled")
        self.check_button.configure(state="normal" if available else "disabled")
        self.apply_button.configure(state="normal" if available and self.preview is not None else "disabled")
        self.disable_button.configure(state="normal" if available and self.current is not None
                                      and self.current["enabled"] else "disabled")
        self.open_button.configure(state="normal" if available and self.confirmed_url else "disabled")
        self.close_button.configure(state="disabled" if self.close_requested else "normal",
                                    text="Остановить и закрыть" if self.busy else "Закрыть")

    def _edited(self, *_args):
        if self.busy or self.closed or self.close_requested:
            return
        self.preview = None
        self.status.set("Настройки изменены. Нажмите «Проверить» перед включением HTTPS.")
        self._show("")
        self._controls()

    def _fresh_rpc(self):
        binding = {"generation": self.generation + 1}
        self.rpc = self.rpc_factory(self.options,
            progress=lambda text: self.events.put((binding["generation"], "progress", text)))
        self.progress_binding = binding

    def _start(self, action, function):
        self.busy = True
        self.generation += 1
        generation = self.generation
        self.progress_binding["generation"] = generation
        self._controls()
        def worker():
            try:
                result = function()
            except Exception as error:
                text = str(error) if isinstance(error, PublicWebError) else "Не удалось завершить проверку HTTPS. Повторите проверку состояния."
                self.events.put((generation, "error", (action, text)))
            else:
                self.events.put((generation, "done", (action, result)))
        threading.Thread(target=worker, daemon=True, name="sovagrid-public-web").start()

    def _begin_read(self, *, config=None):
        if self.busy or self.closed or self.close_requested:
            return
        try:
            self._fresh_rpc()
        except Exception:
            self.status.set("Не удалось подготовить SSH-подключение. Проверьте его настройки.")
            return
        self.current = self.preview = self.confirmed_url = None
        self.state_label.set("Проверяем сохранённые настройки…")
        self._show("")
        self.status.set("Подключаемся по SSH. Ответьте на запросы доступа в отдельных окнах…")
        rpc, generation = self.rpc, self.generation + 1
        def run():
            state = rpc.status()
            if config is None:
                return state
            self.events.put((generation, "state", state))
            return rpc.preview(config)
        self._start("check" if config is not None else "status", run)

    def _initial_refresh(self):
        self._refresh_after = None
        self.refresh()

    def refresh(self):
        self._begin_read()

    def _config(self):
        behavior = ROOT_CHOICES.get(self.root_behavior.get())
        if behavior is None:
            raise PublicWebError("INVALID_REQUEST")
        return config_for_address(self.address.get(), panel_path=self.panel_path.get(),
                                  root_behavior=behavior)

    def check(self):
        if self.busy or self.closed or self.close_requested:
            return
        try:
            config = self._config()
        except PublicWebError as error:
            self.preview = None
            self.status.set(str(error))
            self._controls()
            return
        self.address.set(config["address"])
        self._begin_read(config=config)

    def apply(self):
        if self.busy or self.closed or self.close_requested or self.preview is None:
            return
        preview, rpc, generation = self.preview, self.rpc, self.generation
        try:
            if self._config() != validate_config(preview["config"]):
                self._edited()
                return
        except PublicWebError:
            self._edited()
            return
        if not messagebox.askyesno("Включить публичный HTTPS",
                f"Открыть панель по адресу {public_panel_url(preview['config'])}?\n\n"
                "SovaGrid опубликует Web на портах 80 и 443 и запросит доверенный сертификат. "
                "Для входа нужен доступ SSH или учётная запись панели.", parent=self.window):
            return
        if (self.closed or self.close_requested or self.busy or self.preview is not preview
                or self.rpc is not rpc or self.generation != generation):
            return
        try:
            if self._config() != validate_config(preview["config"]):
                self._edited()
                return
        except PublicWebError:
            self._edited()
            return
        self.current = self.preview = self.confirmed_url = None
        self.state_label.set("Применяем настройки. Текущее состояние ещё не подтверждено.")
        self.status.set("Включаем HTTPS. Сертификат и публичный адрес будут проверены перед сообщением об успехе…")
        self._start("apply", lambda: rpc.apply(preview["config"],
            expected_state_sha256=preview["expected_state_sha256"], source_manifest_sha256=preview["source_manifest_sha256"]))

    def disable(self):
        if (self.busy or self.closed or self.close_requested or self.current is None
                or not self.current["enabled"]):
            return
        current, rpc, generation = self.current, self.rpc, self.generation
        if not messagebox.askyesno("Отключить публичный HTTPS",
                f"Отключить публичный адрес {public_url(current['config'])}?\n\n"
                "Панель по этой ссылке перестанет открываться. Вход через существующее SSH-подключение останется доступен.",
                parent=self.window):
            return
        if (self.closed or self.close_requested or self.busy or self.current is not current
                or self.rpc is not rpc or self.generation != generation):
            return
        self.current = self.preview = self.confirmed_url = None
        self.state_label.set("Отключаем публичный адрес. Текущее состояние ещё не подтверждено.")
        self.status.set("Применяем отключение и проверяем локальный доступ…")
        self._start("disable", lambda: rpc.disable(expected_state_sha256=current["expected_state_sha256"]))

    def _accept_state(self, state):
        self.current = state
        if state["enabled"]:
            if state["config"]["acme_environment"] == "staging":
                self.state_label.set("Настроен тестовый адрес: " + public_panel_url(state["config"])
                    + ". Тестовый сертификат, доступность не подтверждена.")
            else:
                self.state_label.set("Настроен адрес: " + public_panel_url(state["config"]) + ". Доступность и сертификат ещё не проверены.")
        else:
            self.state_label.set("Публичный HTTPS отключён. Панель доступна через SSH-подключение.")

    def open_site(self):
        if self.confirmed_url and not self.busy and not self.closed and not self.close_requested:
            webbrowser.open(self.confirmed_url)

    def close(self):
        if self.closed:
            return
        self.close_requested = True
        self.preview = self.confirmed_url = None
        if self.busy:
            self.rpc.cancel()
            self.status.set("Останавливаем SSH-подключение. Изменение могло завершиться; при следующем запуске повторите проверку.")
            self._controls()
        else:
            self._finish()

    def _finish(self):
        if self.closed:
            return
        self.closed = True
        self.rpc = self.progress_binding = None
        for name in ("_pump_after", "_refresh_after"):
            identifier = getattr(self, name, None)
            if identifier is not None:
                self.window.after_cancel(identifier)
                setattr(self, name, None)
        self.window.grab_release()
        self.window.destroy()
        self.on_closed()

    def pump(self):
        self._pump_after = None
        if self.closed:
            return
        while not self.events.empty():
            generation, kind, value = self.events.get()
            if generation != self.generation:
                continue
            if kind == "progress":
                if not self.close_requested:
                    self.status.set(value)
                continue
            if kind == "state":
                if not self.close_requested:
                    self._accept_state(value)
                continue
            self.busy = False
            if self.close_requested:
                self._finish()
                return
            action, result = value
            if kind == "error":
                self.preview = self.confirmed_url = None
                self.status.set(result + " Нажмите «Проверить», прежде чем повторять действие.")
            elif action == "status":
                if result["enabled"]:
                    self.address.set(result["config"]["address"])
                    self.panel_path.set(result["config"].get("panel_path", DEFAULT_PANEL_PATH))
                    self.root_behavior.set(ROOT_LABELS[result["config"].get("root_behavior", "panel")])
                self._accept_state(result)
                self.status.set("Сохранённые настройки прочитаны. Укажите адрес и нажмите «Проверить».")
            elif action == "check":
                self.preview = result
                self._show(f"Адрес панели: {public_panel_url(result['config'])}\n"
                    f"Корень сайта: {ROOT_LABELS[result['config']['root_behavior']]}\n\n"
                    "Будут опубликованы порты 80 и 443 существующей Web-панели. "
                    "Вход по SSH и учётной записи панели остаётся защищён.\n\n"
                    "Сертификат пока не проверен: его выдача и проверка выполняются при включении.\n\n"
                    f"SHA-256 серверного пакета:\n{result['source_manifest_sha256']}")
                self.status.set("Адрес и установка проверены. Просмотрите план и нажмите «Включить HTTPS».")
            elif action == "apply":
                self._accept_state({"protocol": 1, "ok": True, "enabled": True,
                    "config": result["config"], "expected_state_sha256": result["expected_state_sha256"]})
                self.confirmed_url = public_panel_url(result["config"])
                self.state_label.set("HTTPS проверен: " + self.confirmed_url)
                self.status.set("Публичная панель и доверенный сертификат проверены. Откройте эту ссылку на телефоне.")
                self._show(self.confirmed_url + "\n\nВ панели нажмите «Сделать приложением», чтобы добавить её на экран телефона.")
            elif action == "disable":
                self._accept_state({"protocol": 1, "ok": True, "enabled": False,
                                    "config": None, "expected_state_sha256": None})
                self._show("")
                self.status.set("Публичный HTTPS отключён; локальный доступ проверен.")
            self._controls()
        self._pump_after = self.window.after(100, self.pump)
