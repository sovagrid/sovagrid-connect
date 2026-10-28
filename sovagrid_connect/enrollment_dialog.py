# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewable, resumable GUI for attaching another Ubuntu server to a Hub."""
from __future__ import annotations

from dataclasses import asdict
import ipaddress
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .agent_enrollment import AgentEnrollment, EnrollmentError
from .agent_rpc import RPCError
from .core import ConnectionOptions
from .enrollment_api import EnrollmentAPIError
from .enrollment_journal import EnrollmentJournal, EnrollmentJournalError
from .installer import InstallError, nearby_server_bundle
from .ssh_profiles import OpenSSHProfiles, ProfileImportError

PHASE_LABELS = {"prepared": "подготовка", "transport_ready": "связь проверена",
                "registered": "ожидаем измерение", "active": "подключён"}


def friendly_error(error):
    # Fixed exception families never contain SSH stderr, response bodies,
    # credentials or source content. Never queue an exception/traceback.
    if isinstance(error, (EnrollmentError, EnrollmentAPIError, EnrollmentJournalError,
                          RPCError, InstallError, ProfileImportError)):
        return str(error)
    return "Не удалось завершить действие. Проверьте подключение и сохранённую установку перед повтором."


class EnrollmentDialog:
    def __init__(self, root, theme, tunnel, on_closed, *, journal=None,
                 controller_factory=AgentEnrollment):
        self.root, self.theme, self.tunnel, self.on_closed = root, theme, tunnel, on_closed
        self.journal = journal if journal is not None else EnrollmentJournal()
        self.controller_factory = controller_factory
        self.controller = None
        self.busy = False
        self.closed = False
        self.close_requested = False
        self.cleanup_requested = False
        self.reviewed = False
        self.events = queue.SimpleQueue()
        self.generation = 0
        self.progress_binding = None
        self.records = {}
        self.fields = {}
        self.entries = {}
        self.input_controls = []
        self.selection = tk.StringVar(value="Новая установка")
        self.status = tk.StringVar(value="Выберите новый сервер или продолжите сохранённую установку.")
        self.window = tk.Toplevel(root)
        self.window.title("Добавить сервер · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry(f"790x{min(850, max(480, self.window.winfo_screenheight() - 160))}")
        self.window.minsize(620, 420)
        theme.style_window(self.window)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        shell = ttk.Frame(self.window, padding=14)
        shell.grid(sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(shell, highlightthickness=0, borderwidth=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(shell, orient="vertical", command=self.canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=scroll.set, background=self.window.cget("background"))
        body = ttk.Frame(self.canvas, padding=(2, 2, 12, 8))
        body.columnconfigure(1, weight=1)
        item = self.canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(item, width=e.width))
        self.window.bind("<MouseWheel>", self._scroll)
        self.window.bind("<Button-4>", lambda _e: self.canvas.yview_scroll(-3, "units"))
        self.window.bind("<Button-5>", lambda _e: self.canvas.yview_scroll(3, "units"))
        ttk.Label(body, text="Отдельный Agent для другого сервера", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))
        hub = tunnel.options
        ttk.Label(body, text=f"Центр мониторинга: {hub.user}@{hub.host}:{hub.port}", wraplength=660).grid(
            row=1, column=0, columnspan=3, sticky="w")
        ttk.Label(body, text="Мастер настроит сбор метрик и проверки доступности. Данные доступа Agent создаются "
                  "автоматически на сервере. Терминал, команды, файлы и VPN этим действием не включаются.",
                  wraplength=660).grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 12))
        ttk.Label(body, text="Установка").grid(row=3, column=0, sticky="w")
        self.record_choice = ttk.Combobox(body, textvariable=self.selection, state="readonly")
        self.record_choice.grid(row=3, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=4)
        self.record_choice.bind("<<ComboboxSelected>>", self._select_record)
        self.input_controls.append(self.record_choice)
        self.profile = tk.StringVar()
        ttk.Label(body, text="Профиль OpenSSH").grid(row=4, column=0, sticky="w")
        self.profile_choice = ttk.Combobox(body, textvariable=self.profile, state="readonly")
        self.profile_choice.grid(row=4, column=1, sticky="ew", padx=(10, 0), pady=4)
        self.profile_choice.bind("<<ComboboxSelected>>", self._import_profile)
        self.input_controls.append(self.profile_choice)
        profile_file = ttk.Button(body, text="Другой config…", command=self._profile_file)
        profile_file.grid(row=4, column=2, padx=(8, 0))
        self.input_controls.append(profile_file)
        self.profile_file_button = profile_file
        definitions = (
            ("name", "Название сервера", ""),
            ("host", "Сервер SSH", ""), ("user", "SSH-пользователь", "root"),
            ("port", "Порт SSH", "22"), ("identity", "Приватный ключ (необяз.)", ""),
            ("jump_host", "Промежуточный хост", ""), ("jump_user", "Его пользователь", ""),
            ("jump_port", "Его порт SSH", "22"), ("jump_identity", "Ключ перехода (необяз.)", ""),
            ("host_key_alias", "Имя ключа сервера (необяз.)", ""),
            ("jump_host_key_alias", "Имя ключа перехода (необяз.)", ""),
            ("hub_host", "IP Hub, видимый с сервера", self._hub_ip(hub.host)),
            ("hub_port", "Порт SSH Hub", str(hub.port)),
            ("agent_port", "Локальный порт Agent", "18767"),
            ("bundle", "Серверный пакет", str(nearby_server_bundle() or "")),
            ("username", "Логин администратора Hub", "admin"),
            ("password", "Пароль Hub", ""),
        )
        for row, (key, label, initial) in enumerate(definitions, 5):
            ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=3)
            self.fields[key] = tk.StringVar(value=initial)
            entry = ttk.Entry(body, textvariable=self.fields[key], show="●" if key == "password" else "", width=36)
            entry.grid(row=row, column=1, columnspan=1 if key in ("identity", "jump_identity", "bundle") else 2,
                       sticky="ew", padx=(10, 0), pady=3)
            self.entries[key] = entry
            self.input_controls.append(entry)
            if key in ("identity", "jump_identity", "bundle"):
                button = ttk.Button(body, text="Выбрать…", command=lambda selected=key: self._choose(selected))
                button.grid(row=row, column=2, padx=(8, 0), pady=3)
                self.input_controls.append(button)
        row = 5 + len(definitions)
        ttk.Label(body, text="Нужен Ubuntu 22.04, 24.04 или 26.04 и root SSH либо sudo без запроса пароля. "
                  "SSH-пароль, пароль ключа и подтверждение нового SSH-хоста вводятся в отдельных окнах. "
                  "Новый сервер будет сам поддерживать соединение с Hub после закрытия Connect.", wraplength=660).grid(
            row=row, column=0, columnspan=3, sticky="w", pady=(10, 12))
        self.preview = tk.Text(body, height=9, wrap="word", state="disabled", width=72)
        self.preview.grid(row=row + 1, column=0, columnspan=3, sticky="ew")
        theme.style_text(self.preview)
        footer = ttk.Frame(shell, padding=(0, 12, 0, 0))
        footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        ttk.Label(footer, textvariable=self.status, wraplength=700).pack(anchor="w", pady=(0, 8))
        controls = ttk.Frame(footer)
        controls.pack(fill="x")
        self.check_button = ttk.Button(controls, text="Проверить серверы", command=self.check)
        self.check_button.pack(side="left")
        self.apply_button = ttk.Button(controls, text="Установить Agent", command=self.apply, state="disabled")
        self.apply_button.pack(side="left", padx=8)
        self.cleanup_button = ttk.Button(controls, text="Отменить и очистить", command=self.request_cleanup, state="disabled")
        self.cleanup_button.pack(side="left")
        self.close_button = ttk.Button(controls, text="Закрыть", command=self.close)
        self.close_button.pack(side="right", padx=(8, 0))
        self.catalog = None
        self._load_profiles(Path.home() / ".ssh" / "config", quiet=True)
        self._load_records()
        for key, value in self.fields.items():
            if key != "password":
                value.trace_add("write", self._edited)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.grab_set()
        self.window.after(100, self.pump)

    @staticmethod
    def _hub_ip(host):
        try:
            value = ipaddress.ip_address(host)
            return str(value) if not value.is_loopback and not value.is_unspecified else ""
        except ValueError:
            return ""

    def _scroll(self, event):
        if event.delta:
            self.canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _edited(self, *_args):
        if not self.busy and self.reviewed:
            self.reviewed = False
            self.apply_button.configure(state="disabled")
            self.status.set("Поля изменены. Повторите проверку перед установкой.")

    def _show(self, text):
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", text)
        self.preview.configure(state="disabled")

    def _choose(self, key):
        if self.busy:
            return
        selected = filedialog.askopenfilename(parent=self.window, title="Выберите серверный пакет" if key == "bundle"
                                               else "Выберите приватный SSH-ключ")
        if selected:
            self.fields[key].set(selected)

    def _profile_file(self):
        if self.busy:
            return
        selected = filedialog.askopenfilename(parent=self.window, title="Выберите SSH config")
        if selected:
            self._load_profiles(Path(selected))

    def _load_profiles(self, path, quiet=False):
        self.catalog = None
        self.profile.set("")
        self.profile_choice.configure(values=())
        try:
            catalog = OpenSSHProfiles(path)
            self.catalog = catalog
            self.profile_choice.configure(values=catalog.aliases)
        except ProfileImportError as error:
            if not quiet:
                self.status.set(str(error))

    def _import_profile(self, _event=None):
        if self.busy or self.catalog is None or self.selection.get() != "Новая установка":
            return
        profile = self.catalog.profile(self.profile.get())
        if profile.errors or profile.connection is None:
            self._show("\n".join(profile.errors) or "Не удалось импортировать профиль.")
            return
        if profile.warnings and not messagebox.askyesno("Импорт SSH", "\n".join(profile.warnings)
                + "\n\nИмпортировать поддерживаемые поля?", parent=self.window):
            return
        for key, value in asdict(profile.connection).items():
            if key in self.fields:
                self.fields[key].set("" if value is None else str(value))
        if not self.fields["name"].get():
            self.fields["name"].set(profile.alias)

    def _load_records(self):
        try:
            records = self.journal.list()
            self.records = {f"{item['name']} · {item['target_connection']['host']} · "
                            f"{PHASE_LABELS[item['phase']]} · {item['request_id'][:8]}": item for item in records}
        except EnrollmentJournalError as error:
            self.records = {}
            self.status.set(str(error))
        self.record_choice.configure(values=("Новая установка", *self.records))

    def _select_record(self, _event=None):
        if self.busy:
            return
        self.reviewed = False
        self.apply_button.configure(state="disabled")
        self.cleanup_button.configure(state="disabled")
        selected = self.records.get(self.selection.get())
        if selected is not None:
            for key, value in selected["target_connection"].items():
                if key in self.fields:
                    self.fields[key].set("" if value is None else str(value))
            self.fields["name"].set(selected["name"])
            for key in ("host", "port"):
                self.fields["hub_" + key].set(str(selected["hub_endpoint"][key]))
            self.fields["agent_port"].set(str(selected["hub_endpoint"]["local_port"]))
            self.fields["bundle"].set(selected["bundle"]["path"])
            self._show(f"Сохранена установка: {selected['name']}\nСтадия: {PHASE_LABELS[selected['phase']]}\n"
                       "Проверка сверит обе машины и регистрацию. Можно выбрать перемещённый файл ключа или тот же пакет.")
        else:
            self._show("")
        self._controls()

    def _controls(self):
        saved = self.selection.get() in self.records
        frozen = {"name", "host", "user", "port", "jump_host", "jump_user", "jump_port",
                  "host_key_alias", "jump_host_key_alias", "hub_host", "hub_port", "agent_port"}
        for control in self.input_controls:
            control.configure(state="disabled" if self.busy else "normal")
        for key, entry in self.entries.items():
            entry.configure(state="disabled" if self.busy or saved and key in frozen else "normal")
        self.record_choice.configure(state="disabled" if self.busy else "readonly")
        self.profile_choice.configure(state="disabled" if self.busy or saved else "readonly")
        self.profile_file_button.configure(state="disabled" if self.busy or saved else "normal")
        self.check_button.configure(state="disabled" if self.busy else "normal")
        self.apply_button.configure(state="normal" if not self.busy and self.reviewed else "disabled")
        selected = self.records.get(self.selection.get())
        can_clean = (self.controller is not None and self.controller.record is not None
                     and selected is not None and selected["request_id"] == self.controller.record["request_id"])
        self.cleanup_button.configure(state="normal" if can_clean and not self.close_requested else "disabled")
        self.close_button.configure(text="Остановить и закрыть" if self.busy else "Закрыть")

    def _start(self, action, function):
        self.busy = True
        self.generation += 1
        generation = self.generation
        if self.progress_binding is not None and self.controller is not None:
            self.progress_binding["generation"] = generation
        self._controls()
        def worker():
            try:
                result = function()
            except Exception as error:
                self.events.put((generation, "error", (action, friendly_error(error))))
            else:
                self.events.put((generation, "done", (action, result)))
        threading.Thread(target=worker, daemon=True, name="sovagrid-agent-enrollment").start()

    def check(self):
        if self.busy:
            return
        credentials = {"username": self.fields["username"].get().strip(), "password": self.fields["password"].get()}
        self.fields["password"].set("")
        selected = self.records.get(self.selection.get())
        try:
            if selected is None:
                values = {key: self.fields[key].get().strip() for key in self.fields if key != "password"}
                options = ConnectionOptions(host=values["host"], user=values["user"], port=int(values["port"]),
                    jump_host=values["jump_host"] or None, jump_user=values["jump_user"] or None,
                    jump_port=int(values["jump_port"]), identity=values["identity"] or None,
                    jump_identity=values["jump_identity"] or None, host_key_alias=values["host_key_alias"] or None,
                    jump_host_key_alias=values["jump_host_key_alias"] or None).validated()
                arguments = dict(target_options=options, name=values["name"], bundle=values["bundle"],
                    hub_host=values["hub_host"], hub_port=int(values["hub_port"]), local_port=int(values["agent_port"]))
            else:
                arguments = dict(request_id=selected["request_id"],
                    target_identity=self.fields["identity"].get().strip() or None,
                    jump_identity=self.fields["jump_identity"].get().strip() or None,
                    bundle_path=self.fields["bundle"].get().strip())
        except (ValueError, OSError):
            credentials.clear()
            self.status.set("Проверьте адреса, пользователей, SSH-ключи и номера портов.")
            return
        previous = self.controller
        binding = {"generation": self.generation + 1}
        try:
            self.controller = self.controller_factory(self.tunnel, journal=self.journal,
                progress=lambda text: self.events.put((binding["generation"], "progress", text)))
        except Exception as error:
            credentials.clear()
            self.status.set(friendly_error(error))
            return
        self.progress_binding = binding
        controller = self.controller
        self.reviewed = False
        self.status.set("Проверяем соединения и права. Ответьте на запросы SSH…")
        def run():
            try:
                if previous is not None:
                    previous.close()
                return (controller.resume if selected else controller.prepare)(**arguments, credentials=credentials)
            finally:
                credentials.clear()
        self._start("check", run)

    def apply(self):
        if self.busy or not self.reviewed or self.controller is None:
            return
        self.reviewed = False
        self.status.set("Подключаем сервер. Можно остановить мастер; результат останется доступен для проверки.")
        self._start("apply", self.controller.apply)

    def request_cleanup(self):
        selected = self.records.get(self.selection.get())
        if (self.controller is None or self.controller.record is None or self.close_requested or selected is None
                or selected["request_id"] != self.controller.record["request_id"]):
            return
        controller = self.controller
        request_id = controller.record["request_id"]
        if not messagebox.askyesno("Очистить незавершённую установку",
                "Мастер проверит обе машины и удалит только принадлежащую ему незавершённую установку. "
                "Если Agent уже прислал первое измерение, подключённый сервер будет сохранён. Продолжить?",
                parent=self.window):
            return
        # Native confirmation runs a nested Tk event loop. A worker result,
        # lost tunnel or parent close can change the context while it is open.
        if (self.closed or self.close_requested or self.controller is not controller
                or controller.record is None or controller.record["request_id"] != request_id):
            return
        selected = self.records.get(self.selection.get())
        if selected is None or selected["request_id"] != request_id:
            return
        self.cleanup_requested = True
        self.reviewed = False
        if self.busy:
            self.controller.cancel()
            self.status.set("Останавливаем текущее действие перед проверкой и очисткой…")
        else:
            self._cleanup()

    def _cleanup(self):
        self.cleanup_requested = False
        self._start("cleanup", self.controller.cleanup)

    def close(self):
        if self.closed:
            return
        self.close_requested = True
        self.fields["password"].set("")
        if self.busy:
            if self.controller is not None:
                self.controller.cancel()
            self.status.set("Останавливаем действие. Сохранённую установку можно будет проверить при следующем запуске.")
            self._controls()
            return
        self._finish()

    def _finish(self):
        if self.controller is not None:
            controller, self.controller = self.controller, None
            self._start("logout", controller.close)
            return
        self.closed = True
        self.window.grab_release()
        self.window.destroy()
        self.on_closed()

    def pump(self):
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
            self.busy = False
            action, result = value
            if action == "logout":
                self._finish()
                return
            if kind == "error":
                self.reviewed = False
                self.status.set(result + " Нажмите «Проверить серверы», чтобы продолжить или очистить установку.")
                # The controller owns the last durable request, even if its
                # initial staging/preview failed before producing a preview.
                self._load_records()
                self._select_current()
            elif action == "check":
                record = result["record"]
                self._load_records()
                self._select_current()
                self.reviewed = not record["cleanup_required"] and record["phase"] != "active"
                platform = result["platform"]
                self._show(f"{record['name']} · {record['target_connection']['user']}@"
                    f"{record['target_connection']['host']}:{record['target_connection']['port']}\n"
                    f"Ubuntu {platform['ubuntu_version']} · Python {platform['python_version']}\n"
                    f"Hub: {record['hub_endpoint']['host']}:{record['hub_endpoint']['port']}\n"
                    f"SSH-отпечаток Hub: {result['hub_fingerprint']}\nSHA-256 пакета: {record['bundle']['sha256']}\n"
                    "Будут настроены отдельный Agent, служба постоянного SSH-соединения и ограниченный доступ на Hub. "
                    "Метрики и проверки работают без открытого порта на новом сервере.")
                if record["phase"] == "active":
                    self.status.set("Сервер уже подключён. Очистка уберёт только временный пакет и сохранит работающий Agent.")
                elif record["cleanup_required"]:
                    self.status.set("Незавершённая установка требует очистки. Проверьте сведения и нажмите «Отменить и очистить».")
                else:
                    self.status.set("Серверы проверены. Проверьте сведения и нажмите «Установить Agent».")
                self.canvas.yview_moveto(1)
            elif action == "apply":
                self.reviewed = False
                self._load_records()
                self._select_current()
                self.status.set("Сервер подключён и прислал измерение. Откройте панель, чтобы увидеть мониторинг."
                    + (" Временный пакет ещё требует очистки." if result["cleanup_required"] else ""))
            elif action == "cleanup":
                self.reviewed = False
                self._load_records()
                self._select_current()
                self.status.set("Agent уже подключён; работающий сервер сохранён." if result["active"]
                                else "Незавершённая установка очищена. Можно начать новую.")
            if self.close_requested:
                self._finish()
                # _finish revokes the temporary Hub session on a new worker.
                # This event consumed the current poll; keep polling until its
                # logout result arrives before destroying the window.
                if not self.closed:
                    self.window.after(100, self.pump)
                return
            if self.cleanup_requested:
                self._cleanup()
            self._controls()
        self.window.after(100, self.pump)

    def _select_current(self):
        identifier = self.controller.record["request_id"] if self.controller is not None and self.controller.record is not None else None
        choice = next((label for label, record in self.records.items() if record["request_id"] == identifier), "Новая установка")
        self.selection.set(choice)
