# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Explicit, reviewable feature management for an enrolled remote Agent."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .agent_rpc import RPCError
from .core import ConnectionOptions
from .enrollment_api import EnrollmentAPIError
from .installer import InstallError, nearby_server_bundle
from .ssh_profiles import OpenSSHProfiles, ProfileImportError


def friendly_error(error):
    # Queue only messages from local, sanitized exception families. Unknown
    # exception text may contain response data, SSH diagnostics or credentials.
    try:
        from .remote_agent_features import FeatureError
    except ImportError:
        feature_errors = ()
    else:
        feature_errors = (FeatureError,)
    if isinstance(error, feature_errors + (RPCError, EnrollmentAPIError, InstallError, ProfileImportError)):
        return str(error)
    return "Не удалось завершить действие. Повторно проверьте сервер и фактические настройки перед повтором."


class RemoteFeaturesDialog:
    def __init__(self, root, theme, tunnel, on_closed, *, controller_factory=None):
        if controller_factory is None:
            from .remote_agent_features import RemoteAgentFeatures
            controller_factory = RemoteAgentFeatures
        self.root, self.theme, self.tunnel, self.on_closed = root, theme, tunnel, on_closed
        self.controller_factory = controller_factory
        self.controller = self.progress_binding = None
        self.prepared = self.review = None
        self.prepared_context = None
        self.pending_context = None
        self.authenticated = False
        self.busy = self.closed = self.close_requested = False
        self.generation = 0
        self.events = queue.SimpleQueue()
        self.servers = {}
        self.catalog = None
        self.fields, self.entries, self.input_controls = {}, {}, []
        self._syncing = False
        self.selection, self.profile = tk.StringVar(), tk.StringVar()
        self.status = tk.StringVar(value="Войдите как администратор Hub и загрузите список серверов.")
        self.feature_values = {name: tk.BooleanVar(value=False) for name in ("commands", "terminal", "files")}
        self.window = tk.Toplevel(root)
        self.window.title("Функции другого сервера · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry(f"790x{min(850, max(500, self.window.winfo_screenheight() - 140))}")
        self.window.minsize(600, 500)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        shell = ttk.Frame(self.window, padding=14)
        shell.grid(sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)
        self.canvas = tk.Canvas(shell, highlightthickness=0, borderwidth=0, background=self.window.cget("background"))
        self.canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(shell, orient="vertical", command=self.canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.canvas.configure(yscrollcommand=scroll.set)
        body = ttk.Frame(self.canvas, padding=(2, 2, 12, 8))
        body.columnconfigure(1, weight=1)
        item = self.canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        def resize(event):
            self.canvas.itemconfigure(item, width=event.width)
            for child in body.winfo_children():
                if isinstance(child, ttk.Label):
                    child.configure(wraplength=max(280, event.width - 25))
        self.canvas.bind("<Configure>", resize)
        self.window.bind("<MouseWheel>", lambda event: self.canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"))
        self.window.bind("<Button-4>", lambda _event: self.canvas.yview_scroll(-3, "units"))
        self.window.bind("<Button-5>", lambda _event: self.canvas.yview_scroll(3, "units"))
        ttk.Label(body, text="Команды, терминал и файлы удалённого Agent", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        hub = tunnel.options
        ttk.Label(body, text=f"Центр мониторинга: {hub.user}@{hub.host}:{hub.port}").grid(
            row=1, column=0, columnspan=3, sticky="w")
        ttk.Label(body, text="Выберите уже подключённый сервер. Сначала мастер без изменений сверит Hub, SSH-доступ "
            "и установленный Agent. Затем выберите функции и проверьте отдельный план перед применением.",
            wraplength=680).grid(row=2, column=0, columnspan=3, sticky="w", pady=(7, 12))
        for row, (key, label, initial) in enumerate((("username", "Администратор Hub", "admin"),
                                                   ("password", "Пароль Hub", "")), 3):
            self._entry(body, row, key, label, initial)
        self.load_button = ttk.Button(body, text="Загрузить серверы", command=self.load_servers)
        self.load_button.grid(row=5, column=1, sticky="w", padx=(10, 0), pady=(4, 9))
        self.input_controls.append(self.load_button)
        ttk.Label(body, text="Сервер в Hub").grid(row=6, column=0, sticky="w")
        self.server_choice = ttk.Combobox(body, textvariable=self.selection, state="readonly")
        self.server_choice.grid(row=6, column=1, columnspan=2, sticky="ew", padx=(10, 0), pady=4)
        self.server_choice.bind("<<ComboboxSelected>>", self._context_edited)
        self.input_controls.append(self.server_choice)
        ttk.Label(body, text="Профиль OpenSSH").grid(row=7, column=0, sticky="w")
        self.profile_choice = ttk.Combobox(body, textvariable=self.profile, state="readonly")
        self.profile_choice.grid(row=7, column=1, sticky="ew", padx=(10, 0), pady=4)
        self.profile_choice.bind("<<ComboboxSelected>>", self._import_profile)
        self.input_controls.append(self.profile_choice)
        config_button = ttk.Button(body, text="Другой config…", command=self._profile_file)
        config_button.grid(row=7, column=2, padx=(8, 0))
        self.input_controls.append(config_button)
        definitions = (
            ("host", "Сервер SSH", ""), ("user", "SSH-пользователь", "root"), ("port", "Порт SSH", "22"),
            ("identity", "Приватный ключ (необяз.)", ""),
            ("jump_host", "Промежуточный хост", ""), ("jump_user", "Его пользователь", ""),
            ("jump_port", "Его порт SSH", "22"), ("jump_identity", "Ключ перехода (необяз.)", ""),
            ("host_key_alias", "Имя ключа сервера (необяз.)", ""),
            ("jump_host_key_alias", "Имя ключа перехода (необяз.)", ""),
            ("bundle", "Проверяемый серверный пакет", str(nearby_server_bundle() or "")),
        )
        for row, (key, label, initial) in enumerate(definitions, 8):
            self._entry(body, row, key, label, initial, choose=key in ("identity", "jump_identity", "bundle"))
        row = 8 + len(definitions)
        ttk.Label(body, text="Нужен root SSH либо sudo без запроса пароля. SSH-пароли и подтверждение ключа хоста "
            "появятся в отдельных окнах. Данные доступа Agent и существующий SSH-маршрут сохраняются.",
            wraplength=680).grid(row=row, column=0, columnspan=3, sticky="w", pady=(9, 10))
        self.feature_checks = {}
        labels = {"commands": "Удалённое управление: команды", "terminal": "Интерактивный терминал (PTY)",
                  "files": "Файлы в разрешённом каталоге workspace"}
        for offset, name in enumerate(("commands", "terminal", "files"), 1):
            check = ttk.Checkbutton(body, text=labels[name], variable=self.feature_values[name], command=self._feature_edited)
            check.grid(row=row + offset, column=0, columnspan=3, sticky="w", padx=0 if name == "commands" else 18, pady=3)
            self.feature_checks[name] = check
        ttk.Label(body, text="Терминал и файлы требуют разрешения удалённых команд. Разовые команды администратора "
            "получают доступ пользователя Agent на сервере; PTY использует отдельную учётную запись. "
            "При применении текущие удалённые сеансы закрываются и Agent кратко перезапускается. "
            "Файлы пользователя при выключении функций сохраняются.", wraplength=680).grid(
            row=row + 4, column=0, columnspan=3, sticky="w", pady=(7, 10))
        self.details = tk.Text(body, height=12, width=70, wrap="word", state="disabled")
        self.details.grid(row=row + 5, column=0, columnspan=3, sticky="ew")
        theme.style_text(self.details)
        footer = ttk.Frame(shell, padding=(0, 12, 0, 0))
        footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        status_label = ttk.Label(footer, textvariable=self.status, wraplength=700)
        status_label.pack(anchor="w", pady=(0, 8))
        shell.bind("<Configure>", lambda event: status_label.configure(wraplength=max(280, event.width - 30)))
        controls = ttk.Frame(footer)
        controls.pack(fill="x")
        self.check_button = ttk.Button(controls, text="Проверить сервер", command=self.check)
        self.check_button.pack(side="left")
        self.preview_button = ttk.Button(controls, text="Проверить план", command=self.preview_features)
        self.preview_button.pack(side="left", padx=(8, 0))
        self.apply_button = ttk.Button(controls, text="Применить", command=self.apply)
        self.apply_button.pack(side="left", padx=(8, 0))
        self.close_button = ttk.Button(controls, text="Закрыть", command=self.close)
        self.close_button.pack(side="right", padx=(8, 0))
        self._load_profiles(Path.home() / ".ssh" / "config", quiet=True)
        for key, value in self.fields.items():
            value.trace_add("write", self._auth_edited if key in ("username", "password") else self._context_edited)
        self.selection.trace_add("write", self._context_edited)
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.grab_set()
        self._controls()
        self._pump_after = self.window.after(100, self.pump)

    def _entry(self, body, row, key, label, initial, *, choose=False):
        ttk.Label(body, text=label).grid(row=row, column=0, sticky="w", pady=3)
        self.fields[key] = tk.StringVar(value=initial)
        entry = ttk.Entry(body, textvariable=self.fields[key], show="●" if key == "password" else "", width=34)
        entry.grid(row=row, column=1, columnspan=1 if choose else 2, sticky="ew", padx=(10, 0), pady=3)
        self.entries[key] = entry
        self.input_controls.append(entry)
        if choose:
            button = ttk.Button(body, text="Выбрать…", command=lambda selected=key: self._choose(selected))
            button.grid(row=row, column=2, padx=(8, 0), pady=3)
            self.input_controls.append(button)

    def _show(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _controls(self):
        available = not self.busy and not self.close_requested
        for control in self.input_controls:
            control.configure(state="normal" if available else "disabled")
        self.server_choice.configure(state="readonly" if available and self.servers else "disabled")
        self.profile_choice.configure(state="readonly" if available else "disabled")
        self.check_button.configure(state="normal" if available and self.authenticated and self.selection.get() in self.servers else "disabled")
        self.preview_button.configure(state="normal" if available and self.prepared is not None else "disabled")
        self.apply_button.configure(state="normal" if available and self.review is not None
                                    and self.review.get("change_required", True) else "disabled")
        for name, control in self.feature_checks.items():
            enabled = available and self.prepared is not None and (name == "commands" or self.feature_values["commands"].get())
            control.configure(state="normal" if enabled else "disabled")
        self.close_button.configure(state="disabled" if self.close_requested else "normal",
                                    text="Остановить и закрыть" if self.busy else "Закрыть")

    def _invalidate(self):
        self.prepared = self.review = self.prepared_context = None
        self._syncing = True
        try:
            for value in self.feature_values.values():
                value.set(False)
        finally:
            self._syncing = False

    def _auth_edited(self, *_args):
        if self._syncing or self.busy or self.closed or self.close_requested:
            return
        self.authenticated = False
        self.servers = {}
        self.selection.set("")
        self.server_choice.configure(values=())
        self._invalidate()
        self.status.set("Данные входа изменены. Загрузите список серверов заново.")
        self._controls()

    def _context_edited(self, *_args):
        if self._syncing or self.busy or self.closed or self.close_requested:
            return
        self._invalidate()
        self._show("")
        self.status.set("Проверьте выбранный сервер перед изменением функций.")
        self._controls()

    def _feature_edited(self):
        if self.busy or self.closed or self.close_requested or self.prepared is None:
            return
        if not self.feature_values["commands"].get():
            self.feature_values["terminal"].set(False)
            self.feature_values["files"].set(False)
        self.review = None
        self.status.set("Функции выбраны. Нажмите «Проверить план» перед применением.")
        self._controls()

    def _choose(self, key):
        if self.busy or self.closed or self.close_requested:
            return
        selected = filedialog.askopenfilename(parent=self.window,
            title="Выберите серверный пакет" if key == "bundle" else "Выберите приватный SSH-ключ")
        if not self.closed and not self.close_requested and not self.busy and selected:
            self.fields[key].set(selected)

    def _profile_file(self):
        if self.busy or self.closed or self.close_requested:
            return
        selected = filedialog.askopenfilename(parent=self.window, title="Выберите SSH config")
        if not self.closed and not self.close_requested and not self.busy and selected:
            self._load_profiles(Path(selected))

    def _load_profiles(self, path, quiet=False):
        self.catalog = None
        self.profile.set("")
        self.profile_choice.configure(values=())
        try:
            self.catalog = OpenSSHProfiles(path)
            self.profile_choice.configure(values=self.catalog.aliases)
        except ProfileImportError as error:
            if not quiet:
                self.status.set(str(error))

    def _import_profile(self, _event=None):
        if self.busy or self.closed or self.close_requested or self.catalog is None:
            return
        profile = self.catalog.profile(self.profile.get())
        if profile.errors or profile.connection is None:
            self._show("\n".join(profile.errors) or "Не удалось импортировать профиль.")
            return
        generation = self.generation
        if profile.warnings and not messagebox.askyesno("Импорт SSH", "\n".join(profile.warnings)
                + "\n\nИмпортировать поддерживаемые поля?", parent=self.window):
            return
        if self.closed or self.close_requested or self.busy or self.generation != generation:
            return
        for key, value in asdict(profile.connection).items():
            if key in self.fields:
                self.fields[key].set("" if value is None else str(value))

    def _credentials(self):
        result = {"username": self.fields["username"].get().strip(), "password": self.fields["password"].get()}
        self._syncing = True
        try:
            self.fields["password"].set("")
        finally:
            self._syncing = False
        return result

    def _new_controller(self):
        previous = self.controller
        binding = {"generation": self.generation + 1}
        controller = self.controller_factory(self.tunnel,
            progress=lambda text: self.events.put((binding["generation"], "progress", text)))
        self.controller, self.progress_binding = controller, binding
        return previous, controller

    def _start(self, action, function):
        self.busy = True
        self.generation += 1
        generation = self.generation
        if self.progress_binding is not None:
            self.progress_binding["generation"] = generation
        self._controls()
        def worker():
            try:
                result = function()
            except Exception as error:
                self.events.put((generation, "error", (action, friendly_error(error))))
            else:
                self.events.put((generation, "done", (action, result)))
        threading.Thread(target=worker, daemon=True, name="sovagrid-remote-features").start()

    def load_servers(self):
        if self.busy or self.closed or self.close_requested:
            return
        credentials = self._credentials()
        reuse = self.controller is not None and self.authenticated and not credentials["password"]
        try:
            previous, controller = (None, self.controller) if reuse else self._new_controller()
        except Exception as error:
            credentials.clear()
            self.status.set(friendly_error(error))
            return
        self._invalidate()
        self.status.set("Подтверждаем администратора и загружаем серверы Hub…")
        def run():
            try:
                if previous is not None:
                    previous.close()
                return controller.list_servers(**({} if reuse else {"credentials": credentials}))
            finally:
                credentials.clear()
        self._start("servers", run)

    def _context(self):
        values = {key: value.get().strip() for key, value in self.fields.items() if key not in ("username", "password")}
        selected = self.servers.get(self.selection.get())
        if selected is None:
            raise ValueError("Select a server")
        options = ConnectionOptions(host=values["host"], user=values["user"], port=int(values["port"]),
            identity=values["identity"] or None, jump_host=values["jump_host"] or None,
            jump_user=values["jump_user"] or None, jump_port=int(values["jump_port"]),
            jump_identity=values["jump_identity"] or None, host_key_alias=values["host_key_alias"] or None,
            jump_host_key_alias=values["jump_host_key_alias"] or None).validated()
        return selected["id"], options, values["bundle"]

    def check(self):
        if self.busy or self.closed or self.close_requested or self.controller is None or not self.authenticated:
            return
        try:
            server_id, options, bundle = self._context()
        except (ValueError, OSError):
            self.status.set("Выберите сервер Hub, проверьте SSH-адрес, ключи, порты и серверный пакет.")
            return
        self._invalidate()
        controller = self.controller
        self.pending_context = (server_id, options, bundle)
        self.status.set("Проверяем установленный Agent и доступ по SSH без изменений…")
        self._start("prepare", lambda: controller.prepare(target_options=options, server_id=server_id, bundle=bundle))

    def _features(self):
        return {name: value.get() for name, value in self.feature_values.items()}

    def preview_features(self):
        if self.busy or self.closed or self.close_requested or self.controller is None or self.prepared is None:
            return
        try:
            if self._context() != self.prepared_context:
                self._context_edited()
                return
        except (ValueError, OSError):
            self._context_edited()
            return
        features = self._features()
        if (features["terminal"] or features["files"]) and not features["commands"]:
            self.status.set("Для терминала и файлов явно разрешите удалённые команды.")
            return
        self.review = None
        controller = self.controller
        self.status.set("Повторно проверяем состояние и готовим план…")
        self._start("preview", lambda: controller.preview(features))

    def _review_text(self, result):
        labels = {"commands": "Удалённые команды", "terminal": "Терминал PTY", "files": "Файлы workspace"}
        current, desired = result.get("current", {}), result.get("desired", result.get("current", {}))
        state = lambda value: "включено" if value else "выключено"
        lines = [f"Сервер: {result.get('name', '')}"]
        if result.get("recovery_required"):
            lines.append("Найдена незавершённая операция. Повторная проверка сверит фактические настройки перед продолжением.")
        if self.prepared_context is not None:
            _identifier, options, _bundle = self.prepared_context
            lines.append(f"SSH: {options.user}@{options.host}:{options.port}")
            if options.jump_host:
                lines.append(f"Через: {options.jump_user or options.user}@{options.jump_host}:{options.jump_port}")
        lines.extend(f"{labels[key]}: {state(current.get(key))} → {state(desired.get(key))}" for key in labels)
        bundle = result.get("bundle", {})
        if bundle.get("sha256"):
            lines.extend(("", "SHA-256 проверенного пакета:", bundle["sha256"]))
        lines.extend(("", "Перед изменениями Hub закроет удалённое управление и текущие сеансы. "
            "Мастер настроит выбранные функции, перезапустит Agent и проверит результат, затем согласует доступ в Hub. "
            "Существующий SSH-маршрут и файлы пользователя сохраняются."))
        return "\n".join(lines)

    def apply(self):
        if self.busy or self.closed or self.close_requested or self.review is None or self.controller is None:
            return
        review, controller, generation = self.review, self.controller, self.generation
        try:
            context, features = self._context(), self._features()
        except (ValueError, OSError):
            self._context_edited()
            return
        if context != self.prepared_context or features != review["desired"]:
            self._feature_edited()
            return
        if not messagebox.askyesno("Применить функции удалённого Agent", self._review_text(review)
                + "\n\nПрименить этот план?", parent=self.window):
            return
        # Native confirmation runs a nested Tk loop: selection, parent close or
        # a late worker result may have replaced the reviewed operation.
        if (self.closed or self.close_requested or self.busy or self.review is not review
                or self.controller is not controller or self.generation != generation):
            return
        try:
            if self._context() != context or self._features() != features:
                self._context_edited()
                return
        except (ValueError, OSError):
            self._context_edited()
            return
        self.review = None
        self.status.set("Применяем проверенный план. При прерывании потребуется повторно проверить фактическое состояние.")
        self._start("apply", controller.apply)

    def close(self):
        if self.closed:
            return
        self.close_requested = True
        self.review = None
        self.fields["password"].set("")
        if self.busy:
            if self.controller is not None:
                try:
                    self.controller.cancel()
                except Exception:
                    pass
            self.status.set("Останавливаем действие. Изменение могло завершиться; при следующем запуске повторите проверку.")
            self._controls()
        else:
            self._finish()

    def _finish(self):
        if self.closed:
            return
        if self.controller is not None:
            controller, self.controller = self.controller, None
            self._start("logout", controller.close)
            return
        self.closed = True
        if self._pump_after is not None:
            self.window.after_cancel(self._pump_after)
            self._pump_after = None
        try:
            self.window.grab_release()
        except tk.TclError:
            pass
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
            self.busy = False
            action, result = value
            if action == "logout":
                self._finish()
                return
            if self.close_requested:
                self._finish()
                break
            if kind == "error":
                self._invalidate()
                if action == "servers":
                    self.authenticated = False
                self.status.set(result + " Повторите проверку перед новым применением.")
            elif action == "servers":
                self.authenticated = True
                old = self.servers.get(self.selection.get(), {}).get("id")
                self.servers = {f"{item['name']} · {item['id'][:8]} ({index + 1})": item
                                for index, item in enumerate(result)}
                self.server_choice.configure(values=tuple(self.servers))
                self._syncing = True
                try:
                    self.selection.set(next((label for label, item in self.servers.items() if item["id"] == old),
                                            next(iter(self.servers), "")))
                finally:
                    self._syncing = False
                self.status.set("Выберите сервер, укажите его SSH-доступ и нажмите «Проверить сервер»." if self.servers
                                else "Подходящих подключённых Agent не найдено. Сначала добавьте сервер в Hub.")
            elif action == "prepare":
                try:
                    matching = self._context() == self.pending_context
                except (ValueError, OSError):
                    matching = False
                if not matching:
                    self._invalidate()
                    self.status.set("Выбор сервера изменился. Повторите проверку текущих полей.")
                    self._controls()
                    continue
                self.prepared = result
                self.prepared_context = self.pending_context
                self._syncing = True
                try:
                    for name, value in self.feature_values.items():
                        value.set(result.get("desired", result["current"])[name])
                finally:
                    self._syncing = False
                self._show(self._review_text(result))
                self.status.set("Найдена незавершённая операция. Проверьте выбранные функции и повторно проверьте план."
                                if result.get("recovery_required") else
                                "Сервер проверен. Выберите функции и нажмите «Проверить план».")
                self.canvas.yview_moveto(1)
            elif action == "preview":
                try:
                    matching = self._context() == self.prepared_context and self._features() == result["desired"]
                except (ValueError, OSError, KeyError):
                    matching = False
                if not matching:
                    self.review = None
                    self.status.set("Выбор функций изменился. Повторите проверку плана.")
                    self._controls()
                    continue
                self.review = result
                self._show(self._review_text(result))
                self.status.set("План проверен. Просмотрите изменения и нажмите «Применить»." if result.get("change_required", True)
                                else "Выбранные функции уже настроены. Изменения не требуются.")
                self.canvas.yview_moveto(1)
            elif action == "apply":
                self._show(self._review_text(result))
                self._invalidate()
                # Keep the verified state visible while further edits require a
                # fresh check; clearing these boxes would imply it was disabled.
                for name, value in self.feature_values.items():
                    value.set(result["current"][name])
                self.status.set("Функции применены и проверены. Повторная проверка покажет текущее состояние сервера."
                                + (" Временный пакет ещё требует очистки при следующей проверке."
                                   if result.get("cleanup_required") else ""))
            self._controls()
        if not self.closed:
            self._pump_after = self.window.after(100, self.pump)
