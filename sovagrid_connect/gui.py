# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Small Tk launcher; the browser runs the full SovaGrid web client."""

from __future__ import annotations

import queue
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser
from pathlib import Path
from dataclasses import replace
from contextlib import nullcontext

from .core import ConnectionOptions, Tunnel
from .installer import (InstallError, InstallFeatures, PreparedUpdate, ServerInstaller,
                        UpdatePreview, nearby_server_bundle, parse_journal_units)
from .server_bundle_download import PUBLISHED_SERVER_SOURCE_SHA256, downloaded_server_bundle
from .ssh_profiles import OpenSSHProfiles, ProfileImportError
from .theme import CHOICES, LABELS, ThemeManager
from .legal import ATTRIBUTION, SOURCE_URL, document, third_party_document, third_party_documents
from .keygen import GeneratedKey
from .keygen_dialog import KeyGenerationDialog
from .enrollment_dialog import EnrollmentDialog
from .public_web_dialog import PublicWebDialog
from .remote_features_dialog import RemoteFeaturesDialog
from .promotion_dialog import PromotionDialog
from .hub_only_update_dialog import HubOnlyUpdateDialog
from .local_operations_dialog import LocalOperationsDialog
from .local_container_inventory_dialog import LocalContainerInventoryDialog
from .local_commands_dialog import LocalCommandsDialog
from .release_feed_dialog import ReleaseFeedDialog
from .service_setup_dialog import ServiceSetupDialog
from .container_action_setup_dialog import ContainerActionSetupDialog
from .hub_backup_dialog import HubBackupDialog
from .host_backup_dialog import HostBackupDialog
from .vpn_setup_dialog import RoutingDialog, AmneziaDialog
from .promotion import verify_promoted_panel
from .server_status import ServerStatus
from .ssh_grant import LoopbackGrantBroker
from .auto_update import (AutoUpdatePolicy, AutoUpdatePolicyStore, AutoUpdateError,
                          run_pinned_update, target_id)


# Published server-v0.11.0 source bundle. Connect verifies these exact bytes
# and the installed source before each root operation; signed discovery stays off.
_APPROVED_SERVER_SOURCE_SHA256 = PUBLISHED_SERVER_SOURCE_SHA256
_APPROVED_PROMOTION_BUNDLE_SHA256: str | None = "10abb18ca39d789d3a9cc8bd04d36126f6dd624a81e48219bd814fb6a15ab766"
_APPROVED_HUB_ONLY_UPDATE_BUNDLE_SHA256: str | None = "10abb18ca39d789d3a9cc8bd04d36126f6dd624a81e48219bd814fb6a15ab766"
_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
_APPROVED_LOCAL_CONTAINER_INVENTORY_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
# Pin only after the signed-feed server bundle and under-lock CAS contract pass VM review.
_APPROVED_RELEASE_FEED_MANIFEST_SHA256: str | None = None
_APPROVED_SERVICE_SETUP_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
_APPROVED_CONTAINER_ACTION_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
_APPROVED_VPN_SETUP_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
_APPROVED_HUB_BACKUP_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"
_APPROVED_HOST_BACKUP_MANIFEST_SHA256: str | None = "a0e34d21e059ed6519710b7c441e995f390eca93fdf809aaea7da688d9e67389"


class Launcher:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("SovaGrid Connect")
        root.resizable(True, True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.values: dict[str, tk.StringVar] = {}
        self.status = tk.StringVar(value="Готово к подключению")
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.tunnel: Tunnel | None = None
        self.grant_broker: LoopbackGrantBroker | None = None
        self.connecting = False
        self.fetching_password = False
        self.installing = False
        self.installer: ServerInstaller | None = None
        self.install_window: tk.Toplevel | None = None
        self.install_status: tk.StringVar | None = None
        self.install_start_button: ttk.Button | None = None
        self.feature_window: tk.Toplevel | None = None
        self.feature_status: tk.StringVar | None = None
        self.feature_start_button: ttk.Button | None = None
        self.feature_manager: ServerInstaller | None = None
        self.feature_checks: list[ttk.Checkbutton] = []
        self.feature_journal_text: tk.Text | None = None
        self.update_window: tk.Toplevel | None = None
        self.update_options: ConnectionOptions | None = None
        self.update_status: tk.StringVar | None = None
        self.update_start_button: ttk.Button | None = None
        self.update_apply_button: ttk.Button | None = None
        self.update_manager: ServerInstaller | None = None
        self.update_preview: UpdatePreview | None = None
        self.update_prepared: PreparedUpdate | None = None
        self.update_auto_button: ttk.Button | None = None
        self.update_server_auto_button: ttk.Button | None = None
        self.update_server_status_button: ttk.Button | None = None
        self.update_server_disarm_button: ttk.Button | None = None
        self._auto_update_inflight = False
        # First policy check runs on the 60-second startup tick even on macOS
        # Python builds whose monotonic clock starts near zero per process.
        self._auto_last_check = time.monotonic() - 300.0
        self.closing = False
        self.key_window: KeyGenerationDialog | None = None
        self.enrollment_window: EnrollmentDialog | None = None
        self.public_web_window: PublicWebDialog | None = None
        self.remote_features_window: RemoteFeaturesDialog | None = None
        self.promotion_window: PromotionDialog | None = None
        self.hub_only_update_window: HubOnlyUpdateDialog | None = None
        self.local_operations_window: LocalOperationsDialog | None = None
        self.local_container_inventory_window: LocalContainerInventoryDialog | None = None
        self.local_commands_window: LocalCommandsDialog | None = None
        self.release_feed_window: ReleaseFeedDialog | None = None
        self.service_setup_window: ServiceSetupDialog | None = None
        self.container_action_setup_window: ContainerActionSetupDialog | None = None
        self.hub_backup_window: HubBackupDialog | None = None
        self.host_backup_window: HostBackupDialog | None = None
        self.routing_window: RoutingDialog | None = None
        self.amnezia_window: AmneziaDialog | None = None
        self.initial_password = tk.StringVar(value="")
        self._initial_secret: str | None = None
        self._copied_password: str | None = None
        self._clipboard_timer: str | None = None
        self.theme = ThemeManager(root)

        shell = ttk.Frame(root, padding=18)
        shell.grid(sticky="nsew")
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)
        self.main_canvas = tk.Canvas(shell, highlightthickness=0, borderwidth=0,
                                     background=root.cget("background"))
        self.main_canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(shell, orient="vertical", command=self.main_canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.main_canvas.configure(yscrollcommand=scroll.set)
        frame = self.main_body = ttk.Frame(self.main_canvas, padding=(0, 0, 10, 10))
        frame.columnconfigure(1, weight=1)
        body_item = self.main_canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _event: self.main_canvas.configure(
            scrollregion=self.main_canvas.bbox("all")))
        self.main_canvas.bind("<Configure>", lambda event: self.main_canvas.itemconfigure(
            body_item, width=event.width))
        # ThemeManager changes ttk styles and the root background together.
        # Keep the exposed canvas edge in the same palette after a theme change.
        self.main_canvas.bind("<<ThemeChanged>>", lambda _event: self.main_canvas.configure(
            background=root.cget("background")))
        root.bind("<MouseWheel>", self._scroll_main)
        root.bind("<Button-4>", self._scroll_main)
        root.bind("<Button-5>", self._scroll_main)
        root.bind("<FocusIn>", self._reveal_main_focus)
        fields = [
            ("host", "Сервер SSH", ""),
            ("user", "Пользователь", ""),
            ("port", "Порт SSH", "22"),
            ("jump_host", "Промежуточный хост", ""),
            ("jump_user", "Его пользователь", ""),
            ("jump_port", "Его порт SSH", "22"),
            ("identity", "Приватный ключ сервера", ""),
            ("jump_identity", "Приватный ключ перехода", ""),
            ("host_key_alias", "Имя ключа сервера (необ.)", ""),
            ("jump_host_key_alias", "Имя ключа перехода (необ.)", ""),
            ("local_port", "Локальный порт (0 = авто)", "0"),
        ]
        for row, (key, label, initial) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            variable = tk.StringVar(value=initial)
            self.values[key] = variable
            ttk.Entry(frame, textvariable=variable, width=38).grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=3)
            if key in ("identity", "jump_identity"):
                ttk.Button(frame, text="Выбрать…", command=lambda selected=key: self.choose_key(selected)).grid(
                    row=row, column=2, padx=(8, 0), pady=3
                )
                ttk.Button(frame, text="Создать…", command=lambda selected=key: self.open_key_generation(selected)).grid(
                    row=row, column=3, padx=(8, 0), pady=3
                )
            elif key == "host":
                ttk.Button(frame, text="Из SSH config…", command=self.open_ssh_profiles).grid(
                    row=row, column=2, padx=(8, 0), pady=3
                )

        ttk.Label(
            frame,
            text="SSH-пароль, пароль ключа и подтверждение нового ключа сервера появятся в отдельных окнах.",
            wraplength=470,
        ).grid(row=len(fields), column=0, columnspan=4, sticky="w", pady=(10, 5))
        self.main_footer = ttk.Frame(shell, padding=(0, 12, 0, 0))
        self.main_footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        status_label = ttk.Label(self.main_footer, textvariable=self.status, wraplength=700)
        status_label.pack(anchor="w", pady=(0, 10))
        self.main_footer.bind("<Configure>", lambda event: status_label.configure(
            wraplength=max(240, event.width - 10)))
        connection_buttons = ttk.Frame(self.main_footer)
        connection_buttons.pack(fill="x")
        self.connect_button = ttk.Button(connection_buttons, text="Подключиться", command=self.connect)
        self.connect_button.pack(side="left")
        self.browser_button = ttk.Button(connection_buttons, text="Открыть панель", command=self.open_browser,
                                         state="disabled")
        self.browser_button.pack(side="left", padx=(8, 0))
        self.disconnect_button = ttk.Button(connection_buttons, text="Отключиться", command=self.disconnect,
                                            state="disabled")
        self.disconnect_button.pack(side="left", padx=(8, 0))
        buttons = ttk.Frame(frame)
        buttons.grid(row=len(fields) + 1, column=0, columnspan=4, sticky="ew", pady=(5, 0))
        self.install_button = ttk.Button(buttons, text="Установить на сервер…", command=self.open_install)
        self.install_button.pack(side="left")
        self.feature_button = ttk.Button(buttons, text="Включить функции…", command=self.open_features)
        self.feature_button.pack(side="left", padx=(8, 0))
        self.update_button = ttk.Button(buttons, text="Обновить сервер…", command=self.open_update)
        self.update_button.pack(side="left", padx=(8, 0))
        self.promotion_button = ttk.Button(buttons, text="Свой Hub на сервере с Agent…",
                                           command=self.open_promotion)
        self.promotion_button.pack(side="left", padx=(8, 0))
        password_panel = ttk.LabelFrame(frame, text="Первый вход в панель", padding=10)
        password_panel.grid(row=len(fields) + 2, column=0, columnspan=4, sticky="ew", pady=(12, 0))
        ttk.Label(password_panel, text="Логин: admin").grid(row=0, column=0, sticky="w")
        ttk.Entry(password_panel, textvariable=self.initial_password, width=27, state="readonly").grid(
            row=0, column=1, sticky="ew", padx=(12, 8)
        )
        self.copy_password_button = ttk.Button(
            password_panel, text="Копировать", command=self.copy_initial_password, state="disabled"
        )
        self.copy_password_button.grid(row=0, column=2)
        self.get_password_button = ttk.Button(
            password_panel, text="Получить начальный пароль по SSH", command=self.get_initial_password, state="disabled"
        )
        self.get_password_button.grid(row=1, column=0, columnspan=3, sticky="w", pady=(9, 0))
        ttk.Label(
            password_panel,
            text="Нужны права чтения у SSH-пользователя (обычно root). После смены пароля в «Настройках» "
                 "начальный пароль уже не подойдёт.",
            wraplength=470,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(7, 0))
        theme_row = ttk.Frame(frame)
        theme_row.grid(row=len(fields) + 3, column=0, columnspan=4, sticky="w", pady=(12, 0))
        ttk.Label(theme_row, text="Тема интерфейса:").pack(side="left")
        theme_value = tk.StringVar(value=LABELS[self.theme.current])
        theme_choice = ttk.Combobox(theme_row, textvariable=theme_value, values=tuple(CHOICES),
                                    state="readonly", width=13)
        theme_choice.pack(side="left", padx=(10, 0))
        ttk.Button(theme_row, text="О программе", command=self.open_about).pack(side="left", padx=(14, 0))
        management_row = ttk.Frame(frame)
        management_row.grid(row=len(fields) + 4, column=0, columnspan=4, sticky="w", pady=(12, 0))
        self.enrollment_button = ttk.Button(management_row, text="Добавить другой сервер…", command=self.open_enrollment,
                                            state="disabled")
        self.enrollment_button.pack(side="left")
        self.public_web_button = ttk.Button(management_row, text="Веб-доступ с телефона…", command=self.open_public_web)
        self.public_web_button.pack(side="left", padx=(10, 0))
        self.remote_features_button = ttk.Button(management_row, text="Функции другого сервера…",
                                                 command=self.open_remote_features, state="disabled")
        self.remote_features_button.pack(side="left", padx=(10, 0))
        hub_update_row = ttk.Frame(frame)
        hub_update_row.grid(row=len(fields) + 5, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.hub_only_update_button = ttk.Button(
            hub_update_row, text="Обновить собственный локальный Hub…", command=self.open_hub_only_update)
        self.hub_only_update_button.pack(side="left")
        self.local_container_inventory_button = ttk.Button(
            hub_update_row, text="Docker-мониторинг своего Hub…",
            command=self.open_local_container_inventory)
        self.local_container_inventory_button.pack(side="left", padx=(8, 0))
        local_operations_row = ttk.Frame(frame)
        local_operations_row.grid(row=len(fields) + 6, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.local_operations_button = ttk.Button(
            local_operations_row, text="Терминал и файлы своего Hub…", command=self.open_local_operations)
        self.local_operations_button.pack(side="left")
        self.local_commands_button = ttk.Button(
            local_operations_row, text="Разрешить команды своего Hub…", command=self.open_local_commands)
        self.local_commands_button.pack(side="left", padx=(8, 0))
        self.release_feed_button = ttk.Button(
            local_operations_row, text="Подписанные обновления…", command=self.open_release_feed)
        self.release_feed_button.pack(side="left", padx=(8, 0))
        service_row = ttk.Frame(frame)
        service_row.grid(row=len(fields) + 7, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.service_setup_button = ttk.Button(
            service_row, text="Доступ к системным службам…", command=self.open_service_setup)
        self.service_setup_button.pack(side="left")
        self.container_action_setup_button = ttk.Button(
            service_row, text="Действия с контейнерами…", command=self.open_container_action_setup)
        self.container_action_setup_button.pack(side="left", padx=(8, 0))
        self.routing_button = ttk.Button(
            service_row, text="Полный маршрут WireGuard…", command=self.open_routing)
        self.routing_button.pack(side="left", padx=(8, 0))
        self.amnezia_button = ttk.Button(
            service_row, text="Управление Amnezia…", command=self.open_amnezia)
        self.amnezia_button.pack(side="left", padx=(8, 0))
        backup_row = ttk.Frame(frame)
        backup_row.grid(row=len(fields) + 8, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.hub_backup_button = ttk.Button(
            backup_row, text="Резервные копии Hub…", command=self.open_hub_backup)
        self.hub_backup_button.pack(side="left")
        self.host_backup_button = ttk.Button(
            backup_row, text="Полные копии сервера…", command=self.open_host_backup)
        self.host_backup_button.pack(side="left", padx=(8, 0))

        def select_theme(_event=None) -> None:
            selected = CHOICES.get(theme_value.get())
            if selected is not None and not self.theme.apply(selected):
                messagebox.showwarning("Тема SovaGrid Connect", "Тема применена, но не удалось сохранить выбор.",
                                       parent=self.root)

        theme_choice.bind("<<ComboboxSelected>>", select_theme)
        root.update_idletasks()
        available_width = max(360, root.winfo_screenwidth() - 80)
        available_height = max(320, root.winfo_screenheight() - 140)
        width = min(1000, available_width, max(740, frame.winfo_reqwidth() + 55))
        height = min(available_height, frame.winfo_reqheight() + self.main_footer.winfo_reqheight() + 36)
        root.minsize(min(740, available_width), min(420, available_height))
        root.geometry(f"{width}x{height}")
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self.pump)
        root.after(60000, self._auto_update_tick)

    def _scroll_main(self, event) -> None:
        if self.main_canvas.yview() != (0.0, 1.0):
            direction = -1 if getattr(event, "num", None) == 4 or getattr(event, "delta", 0) > 0 else 1
            self.main_canvas.yview_scroll(direction * 3, "units")

    def _reveal_main_focus(self, event) -> None:
        widget = event.widget
        ancestor = widget
        while ancestor is not None and ancestor is not self.main_body:
            ancestor = getattr(ancestor, "master", None)
        if ancestor is None:
            return
        top = widget.winfo_rooty() - self.main_body.winfo_rooty()
        bottom = top + widget.winfo_height()
        visible_top = self.main_canvas.canvasy(0)
        visible_bottom = visible_top + self.main_canvas.winfo_height()
        target = top - 5 if top < visible_top else bottom - self.main_canvas.winfo_height() + 5
        if top < visible_top or bottom > visible_bottom:
            self.main_canvas.yview_moveto(max(0, target) / max(1, self.main_body.winfo_height()))

    def choose_key(self, key: str) -> None:
        selected = filedialog.askopenfilename(
            parent=self.root,
            title="Выберите приватный SSH-ключ",
        )
        if selected:
            self.values[key].set(selected)

    def open_enrollment(self) -> None:
        if self._lift_management_window():
            return
        if self.public_web_window is not None:
            self.public_web_window.window.lift()
            return
        if self.enrollment_window is not None:
            self.enrollment_window.window.lift()
            return
        if self.installing or self.connecting or self.tunnel is None or not self.tunnel.alive:
            return
        self.enrollment_window = EnrollmentDialog(self.root, self.theme, self.tunnel, self.enrollment_closed)

    def enrollment_closed(self) -> None:
        self.enrollment_window = None
        if self.closing:
            self.on_close()

    def open_public_web(self) -> None:
        if self._lift_management_window():
            return
        if self.public_web_window is not None:
            self.public_web_window.window.lift()
            return
        if self.enrollment_window is not None:
            self.enrollment_window.window.lift()
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self.tunnel.options if self.tunnel is not None and self.tunnel.alive else self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Веб-доступ SovaGrid", str(error), parent=self.root)
            return
        self.public_web_window = PublicWebDialog(self.root, self.theme, options, self.public_web_closed)

    def public_web_closed(self) -> None:
        self.public_web_window = None
        if self.closing:
            self.on_close()

    def _lift_management_window(self) -> bool:
        for name in ("promotion_window", "hub_only_update_window", "local_operations_window",
                     "local_container_inventory_window",
                     "service_setup_window", "container_action_setup_window",
                     "hub_backup_window", "host_backup_window",
                     "routing_window", "amnezia_window",
                     "local_commands_window", "release_feed_window",
                     "remote_features_window",
                     "enrollment_window", "public_web_window",
                     "install_window", "feature_window", "update_window"):
            existing = getattr(self, name, None)
            if existing is not None:
                getattr(existing, "window", existing).lift()
                return True
        return False

    def open_promotion(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Локальный Hub", str(error), parent=self.root)
            return
        self.promotion_window = PromotionDialog(
            self.root, self.theme, options, self.promotion_closed,
            self.promotion_ready, approved_sha256=_APPROVED_PROMOTION_BUNDLE_SHA256,
        )

    def promotion_closed(self) -> None:
        self.promotion_window = None
        if self.closing:
            self.on_close()

    def open_hub_only_update(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Обновление локального Hub", str(error), parent=self.root)
            return
        self.hub_only_update_window = HubOnlyUpdateDialog(
            self.root, self.theme, options, self.hub_only_update_closed,
            approved_sha256=_APPROVED_HUB_ONLY_UPDATE_BUNDLE_SHA256,
        )

    def hub_only_update_closed(self) -> None:
        self.hub_only_update_window = None
        if self.closing:
            self.on_close()

    def open_local_operations(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Локальный Agent", str(error), parent=self.root)
            return
        self.local_operations_window = LocalOperationsDialog(
            self.root, self.theme, options, self.local_operations_closed,
            approved_manifest_sha256=_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256,
        )

    def local_operations_closed(self) -> None:
        self.local_operations_window = None
        if self.closing:
            self.on_close()

    def open_local_container_inventory(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Docker своего Hub", str(error), parent=self.root)
            return
        self.local_container_inventory_window = LocalContainerInventoryDialog(
            self.root, self.theme, options, self.local_container_inventory_closed,
            approved_manifest_sha256=_APPROVED_LOCAL_CONTAINER_INVENTORY_MANIFEST_SHA256,
        )

    def local_container_inventory_closed(self) -> None:
        self.local_container_inventory_window = None
        if self.closing:
            self.on_close()

    def open_local_commands(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Команды локального Agent", str(error), parent=self.root)
            return
        self.local_commands_window = LocalCommandsDialog(
            self.root, self.theme, options, self.local_commands_closed,
            approved_manifest_sha256=_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256,
        )

    def local_commands_closed(self) -> None:
        self.local_commands_window = None
        if self.closing:
            self.on_close()

    def open_release_feed(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Подписанные обновления", str(error), parent=self.root)
            return
        self.release_feed_window = ReleaseFeedDialog(
            self.root, self.theme, options, self.release_feed_closed,
            approved_manifest_sha256=_APPROVED_RELEASE_FEED_MANIFEST_SHA256,
        )

    def release_feed_closed(self) -> None:
        self.release_feed_window = None
        if self.closing:
            self.on_close()

    def open_service_setup(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Службы Agent", str(error), parent=self.root)
            return
        self.service_setup_window = ServiceSetupDialog(
            self.root, self.theme, options, self.service_setup_closed,
            approved_manifest_sha256=_APPROVED_SERVICE_SETUP_MANIFEST_SHA256,
        )

    def service_setup_closed(self) -> None:
        self.service_setup_window = None
        if self.closing:
            self.on_close()

    def open_container_action_setup(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Контейнеры Agent", str(error), parent=self.root)
            return
        self.container_action_setup_window = ContainerActionSetupDialog(
            self.root, self.theme, options, self.container_action_setup_closed,
            approved_manifest_sha256=_APPROVED_CONTAINER_ACTION_MANIFEST_SHA256,
        )

    def container_action_setup_closed(self) -> None:
        self.container_action_setup_window = None
        if self.closing:
            self.on_close()

    def open_hub_backup(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Резервные копии Hub", str(error), parent=self.root)
            return
        self.hub_backup_window = HubBackupDialog(
            self.root, self.theme, options, self.hub_backup_closed,
            approved_manifest_sha256=_APPROVED_HUB_BACKUP_MANIFEST_SHA256,
        )

    def hub_backup_closed(self) -> None:
        self.hub_backup_window = None
        if self.closing:
            self.on_close()

    def open_host_backup(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Полные копии сервера", str(error), parent=self.root)
            return
        self.host_backup_window = HostBackupDialog(
            self.root, self.theme, options, self.host_backup_closed,
            approved_manifest_sha256=_APPROVED_HOST_BACKUP_MANIFEST_SHA256,
        )

    def host_backup_closed(self) -> None:
        self.host_backup_window = None
        if self.closing:
            self.on_close()

    def open_routing(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Полный маршрут WireGuard", str(error), parent=self.root)
            return
        self.routing_window = RoutingDialog(
            self.root, self.theme, options, self.routing_closed,
            approved_manifest_sha256=_APPROVED_VPN_SETUP_MANIFEST_SHA256,
        )

    def routing_closed(self) -> None:
        self.routing_window = None
        if self.closing:
            self.on_close()

    def open_amnezia(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            self.status.set("Дождитесь завершения текущей операции с сервером.")
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as error:
            messagebox.showerror("Управление Amnezia", str(error), parent=self.root)
            return
        self.amnezia_window = AmneziaDialog(
            self.root, self.theme, options, self.amnezia_closed,
            approved_manifest_sha256=_APPROVED_VPN_SETUP_MANIFEST_SHA256,
        )

    def amnezia_closed(self) -> None:
        self.amnezia_window = None
        if self.closing:
            self.on_close()

    def promotion_ready(self, options: ConnectionOptions, state) -> None:
        """Open only after a separate SSH health and local Agent metric proof."""
        if self.connecting or self.installing or state.local_server_id is None:
            return
        if self.promotion_window is not None:
            self.promotion_window.close()
        self.disconnect()
        try:
            tunnel = Tunnel(options, gui_prompts=True)
        except (ValueError, OSError) as exc:
            messagebox.showerror("Локальный Hub", str(exc), parent=self.root)
            return
        self.tunnel = tunnel
        self.connecting = True
        self.connect_button.configure(state="disabled")
        self.status.set("Проверка локального Hub и свежих метрик через SSH…")

        def worker() -> None:
            try:
                tunnel.start(timeout=180)
                verify_promoted_panel(tunnel, state.local_server_id)
                if self.closing:
                    tunnel.close()
                    return
                self.events.put(("connected", (tunnel, self._prepare_browser_login(tunnel))))
            except InstallError as exc:
                tunnel.close()
                self.events.put(("error", exc))
            except Exception:
                tunnel.close()
                self.events.put(("error", InstallError(
                    "Локальный Hub или свежие метрики не подтвердились. Повторите проверку мастера.")))

        threading.Thread(target=worker, daemon=True).start()

    def open_remote_features(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting or self.tunnel is None or not self.tunnel.alive:
            return
        self.remote_features_window = RemoteFeaturesDialog(
            self.root, self.theme, self.tunnel, self.remote_features_closed)

    def remote_features_closed(self) -> None:
        self.remote_features_window = None
        if self.closing:
            self.on_close()

    def open_key_generation(self, target: str) -> None:
        if target not in ("identity", "jump_identity"):
            return
        if self.key_window is not None:
            self.key_window.window.lift()
            self.key_window.window.focus_force()
            return
        self.key_window = KeyGenerationDialog(self.root, self.theme, target,
                                               self.key_created, self.key_window_closed)

    def key_created(self, target: str, result: GeneratedKey) -> None:
        if target in ("identity", "jump_identity"):
            self.values[target].set(str(result.private_path))
            if self.key_window is not None and self.key_window.close_requested:
                self.closing = False
                self.status.set(f"SSH-ключ успел сохраниться до отмены: {result.private_path}. Открытый ключ показан в окне создания.")
            else:
                self.status.set(f"Новый SSH-ключ сохранён: {result.private_path}")

    def key_window_closed(self) -> None:
        self.key_window = None
        if self.closing and not self.connecting:
            self.disconnect()
            self.root.destroy()

    def open_about(self) -> None:
        from . import __version__
        window = tk.Toplevel(self.root)
        self.theme.style_window(window)
        window.title("О программе · SovaGrid Connect")
        window.geometry("720x520")
        window.transient(self.root)
        body = ttk.Frame(window, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=f"SovaGrid Connect {__version__}").pack(anchor="w", pady=(0, 8))
        ttk.Label(body, text=ATTRIBUTION, wraplength=660).pack(anchor="w")
        ttk.Label(body, text="Программа предоставляется без гарантий. Копирование, изменение и "
                  "распространение разрешены по GNU AGPLv3 с сохранением авторства.",
                  wraplength=660).pack(anchor="w", pady=(8, 12))
        ttk.Button(body, text="Открыть исходный код", command=lambda: webbrowser.open(SOURCE_URL)).pack(anchor="w")
        notebook = ttk.Notebook(body)
        notebook.pack(fill="both", expand=True, pady=12)
        for title, filename in (("Лицензия", "LICENSE"), ("Авторство", "ATTRIBUTION.md"), ("Уведомления", "NOTICE")):
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=title)
            text = tk.Text(frame, wrap="word", state="normal", padx=10, pady=10)
            self.theme.style_text(text)
            scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scroll.set)
            text.pack(side="left", fill="both", expand=True)
            scroll.pack(side="right", fill="y")
            text.insert("1.0", document(filename))
            text.configure(state="disabled")
        third_party = ttk.Frame(notebook, padding=8)
        notebook.add(third_party, text="Сторонние лицензии")
        available = third_party_documents()
        selected = tk.StringVar(value="INDEX.md" if "INDEX.md" in available else available[0])
        chooser = ttk.Combobox(third_party, textvariable=selected, values=available, state="readonly")
        chooser.pack(fill="x", pady=(0, 8))
        reader = ttk.Frame(third_party)
        reader.pack(fill="both", expand=True)
        third_text = tk.Text(reader, wrap="word", state="normal", padx=10, pady=10)
        self.theme.style_text(third_text)
        third_scroll = ttk.Scrollbar(reader, orient="vertical", command=third_text.yview)
        third_text.configure(yscrollcommand=third_scroll.set)
        third_text.pack(side="left", fill="both", expand=True)
        third_scroll.pack(side="right", fill="y")

        def show_notice(_event=None) -> None:
            third_text.configure(state="normal")
            third_text.delete("1.0", "end")
            third_text.insert("1.0", third_party_document(selected.get()))
            third_text.configure(state="disabled")

        chooser.bind("<<ComboboxSelected>>", show_notice)
        show_notice()
        ttk.Button(body, text="Закрыть", command=window.destroy).pack(anchor="e")

    def open_ssh_profiles(self) -> None:
        """Let the user review an alias before copying its supported fields."""
        if self.connecting or self.installing:
            return
        window = tk.Toplevel(self.root)
        self.theme.style_window(window)
        window.title("SovaGrid · Импорт SSH-хоста")
        window.resizable(False, False)
        window.transient(self.root)
        body = ttk.Frame(window, padding=18)
        body.grid(sticky="nsew")
        path = tk.StringVar(value=str(Path.home() / ".ssh" / "config"))
        ttk.Label(body, text="Локальный SSH config:").grid(row=0, column=0, sticky="w")
        ttk.Entry(body, textvariable=path, state="readonly", width=53).grid(
            row=1, column=0, sticky="ew", pady=(5, 10)
        )
        alias = tk.StringVar()
        ttk.Label(body, text="Сохранённый Host:").grid(row=2, column=0, sticky="w")
        chooser = ttk.Combobox(body, textvariable=alias, state="readonly", width=40)
        chooser.grid(row=3, column=0, sticky="w", pady=(5, 10))
        preview_frame = ttk.Frame(body)
        preview_frame.grid(row=4, column=0, columnspan=2, sticky="ew")
        preview = tk.Text(preview_frame, width=68, height=13, wrap="word", state="disabled")
        self.theme.style_text(preview)
        preview.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(preview_frame, orient="vertical", command=preview.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        preview.configure(yscrollcommand=scrollbar.set)
        ttk.Label(body, text="Connect читает файл как текст. Команды Match exec и ProxyCommand не запускаются.",
                  wraplength=520).grid(row=5, column=0, columnspan=2, sticky="w", pady=(9, 0))
        controls = ttk.Frame(body)
        controls.grid(row=6, column=0, columnspan=2, sticky="w", pady=(12, 0))
        apply_button = ttk.Button(controls, text="Заполнить поля", state="disabled")
        apply_button.pack(side="left")
        ttk.Button(controls, text="Закрыть", command=window.destroy).pack(side="left", padx=(8, 0))
        catalog: OpenSSHProfiles | None = None
        selected_profile = None

        def show(text: str) -> None:
            preview.configure(state="normal")
            preview.delete("1.0", "end")
            preview.insert("1.0", text)
            preview.configure(state="disabled")

        def select(_event=None) -> None:
            nonlocal selected_profile
            selected_profile = None
            apply_button.configure(state="disabled")
            if catalog is None or not alias.get():
                return
            selected_profile = catalog.profile(alias.get())
            profile = selected_profile
            lines = [f"Host {profile.alias}"]
            options = profile.connection
            if options:
                lines.extend([f"Сервер: {options.host}:{options.port}", f"Пользователь: {options.user}",
                              f"Ключ: {options.identity or 'OpenSSH / агент'}"])
                if options.host_key_alias:
                    lines.append(f"Имя ключа сервера: {options.host_key_alias}")
                if options.jump_host:
                    lines.extend([f"Переход: {options.jump_user}@{options.jump_host}:{options.jump_port}",
                                  f"Ключ перехода: {options.jump_identity or 'OpenSSH / агент'}"])
                    if options.jump_host_key_alias:
                        lines.append(f"Имя ключа перехода: {options.jump_host_key_alias}")
            if profile.errors:
                lines.extend(["", "Нельзя импортировать автоматически:", *profile.errors])
            if profile.warnings:
                lines.extend(["", "Отличия и неподдерживаемые настройки:", *profile.warnings])
            if not profile.errors:
                lines.extend(["", "Ключи серверов проверяются строго, пароли вводятся в окнах Connect."])
                apply_button.configure(state="normal")
            show("\n".join(lines))

        def load(selected: Path) -> None:
            nonlocal catalog, selected_profile
            catalog = None
            selected_profile = None
            alias.set("")
            chooser.configure(values=())
            apply_button.configure(state="disabled")
            path.set(str(selected))
            try:
                catalog = OpenSSHProfiles(selected)
            except ProfileImportError as exc:
                show(f"{exc}\n\nВыберите существующий SSH config или заполните поля Connect вручную.")
                return
            if not catalog.aliases:
                show("В этом файле нет именованных Host. Проверьте Include или выберите другой SSH config.")
                return
            chooser.configure(values=catalog.aliases)
            alias.set(catalog.aliases[0])
            select()

        def choose_file() -> None:
            selected = filedialog.askopenfilename(parent=window, title="Выберите SSH config")
            if selected:
                load(Path(selected))

        ttk.Button(body, text="Другой файл…", command=choose_file).grid(row=1, column=1, padx=(8, 0), pady=(5, 10))
        chooser.bind("<<ComboboxSelected>>", select)

        def apply() -> None:
            profile = selected_profile
            if profile is None or profile.connection is None or profile.errors:
                return
            if profile.warnings and not messagebox.askyesno(
                "Импорт SSH-хоста",
                "Некоторые настройки SSH config не переносятся и показаны в окне импорта. "
                "Применить только поддерживаемые поля?", parent=window,
            ):
                return
            options = profile.connection
            for key in ("host", "user", "port", "jump_host", "jump_user", "jump_port",
                        "identity", "jump_identity", "host_key_alias", "jump_host_key_alias"):
                self.values[key].set(str(getattr(options, key) or "") if key not in ("port", "jump_port")
                                     else str(getattr(options, key)))
            self.status.set(f"Поля заполнены из Host {profile.alias}. Проверьте адрес и подключитесь.")
            window.destroy()

        apply_button.configure(command=apply)
        load(Path(path.get()))

    def _options(self) -> ConnectionOptions:
        value = lambda key: self.values[key].get().strip()
        return ConnectionOptions(
            host=value("host"),
            user=value("user"),
            port=int(value("port")),
            jump_host=value("jump_host") or None,
            jump_user=value("jump_user") or None,
            jump_port=int(value("jump_port")),
            identity=value("identity") or None,
            jump_identity=value("jump_identity") or None,
            host_key_alias=value("host_key_alias") or None,
            jump_host_key_alias=value("jump_host_key_alias") or None,
            local_port=int(value("local_port")),
        )

    def connect(self) -> None:
        if self._lift_management_window():
            return
        if self.installing:
            return
        try:
            tunnel = Tunnel(self._options(), gui_prompts=True)
        except (ValueError, OSError) as exc:
            messagebox.showerror("SovaGrid Connect", str(exc))
            return
        self.tunnel = tunnel
        self.connecting = True
        self.status.set("Подключение… ответьте на запросы SSH в появляющихся окнах")
        self.connect_button.configure(state="disabled")
        self.install_button.configure(state="disabled")
        self.feature_button.configure(state="disabled")
        self.update_button.configure(state="disabled")

        def worker() -> None:
            try:
                server_status = ServerInstaller(tunnel.options).probe_status()
                if server_status.kind in ("managed", "unknown"):
                    tunnel.start(timeout=180 if server_status.kind == "managed" else 45)
                    if self.closing:
                        tunnel.close()
                    self.events.put(("connected", (tunnel, self._prepare_browser_login(tunnel))))
                else:
                    self.events.put(("server_status", (tunnel, server_status)))
            except Exception as exc:
                self.events.put(("error", exc))

        threading.Thread(target=worker, daemon=True).start()

    def _auto_install_and_connect(self, tunnel: Tunnel, source: Path | None) -> None:
        self.status.set("Подготовка проверенного пакета для пустого Ubuntu-сервера…")
        self.installing = True
        manager = ServerInstaller(tunnel.options, progress=lambda line: self.events.put(("auto_install_progress", line)))
        self.installer = manager

        def worker() -> None:
            try:
                # Keep the private downloaded file alive until install() has
                # copied and verified it again, before its first SSH action.
                context = (downloaded_server_bundle(
                    progress=lambda line: self.events.put(("auto_install_progress", line))
                ) if source is None else nullcontext(source))
                with context as bundle:
                    manager.install(bundle, expected_sha256=_APPROVED_SERVER_SOURCE_SHA256)
                if self.closing:
                    return
                tunnel.start(timeout=180)
                if self.closing:
                    tunnel.close()
                self.events.put(("connected", (tunnel, self._prepare_browser_login(tunnel))))
            except Exception as exc:
                self.events.put(("error", exc))
            finally:
                self.events.put(("auto_install_end", manager))

        threading.Thread(target=worker, daemon=True).start()

    @staticmethod
    def _prepare_browser_login(tunnel: Tunnel) -> LoopbackGrantBroker | None:
        try:
            grant = tunnel.request_ssh_grant()
            origin = tunnel.url.rstrip("/")
            if not tunnel.panel_url.startswith(origin + "/"):
                return None
            return LoopbackGrantBroker(grant, panel_origin=origin,
                                       panel_path=tunnel.panel_url[len(origin):])
        except (OSError, ValueError, RuntimeError):
            # Older Hubs and SSH users without host-admin authority retain
            # the ordinary per-server Hub login form.
            return None

    def open_browser(self) -> None:
        if self.tunnel is not None and self.tunnel.alive:
            broker = self.grant_broker
            url = broker.browser_url(self.tunnel.panel_url) if broker and broker.available else self.tunnel.panel_url
            webbrowser.open(url, new=2)

    def get_initial_password(self) -> None:
        tunnel = self.tunnel
        if tunnel is None or not tunnel.alive or self.fetching_password:
            return
        self._clear_initial_password()
        self.fetching_password = True
        self.get_password_button.configure(state="disabled")
        self.status.set("Чтение начального пароля через SSH…")

        def worker() -> None:
            try:
                password = tunnel.read_bootstrap_password()
                self.events.put(("initial_password", (tunnel, password)))
            except Exception as exc:
                self.events.put(("initial_password_error", (tunnel, exc)))

        threading.Thread(target=worker, daemon=True).start()

    def copy_initial_password(self) -> None:
        if self.tunnel is None or not self.tunnel.alive:
            return
        password = self._initial_secret
        if not password:
            return
        self._clear_copied_password()
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self._copied_password = password
        self._clipboard_timer = self.root.after(60000, self._clear_copied_password)
        self.status.set("Начальный пароль скопирован. Буфер обмена очистится через минуту.")

    def _clear_copied_password(self) -> None:
        if self._clipboard_timer is not None:
            self.root.after_cancel(self._clipboard_timer)
            self._clipboard_timer = None
        if self._copied_password is not None:
            try:
                if self.root.clipboard_get() == self._copied_password:
                    self.root.clipboard_clear()
            except tk.TclError:
                pass
        self._copied_password = None

    def _clear_initial_password(self) -> None:
        self._clear_copied_password()
        self._initial_secret = None
        self.initial_password.set("")
        self.copy_password_button.configure(state="disabled")

    def disconnect(self) -> None:
        # Keep the verified panel tunnel alive until the child worker has
        # stopped and revoked its temporary Hub session.
        if self.enrollment_window is not None or getattr(self, "remote_features_window", None) is not None:
            return
        self._clear_initial_password()
        self.fetching_password = False
        if self.grant_broker is not None:
            self.grant_broker.close()
            self.grant_broker = None
        if self.tunnel is not None:
            self.tunnel.close()
            self.tunnel = None
        self.browser_button.configure(state="disabled")
        self.disconnect_button.configure(state="disabled")
        self.get_password_button.configure(state="disabled")
        self.enrollment_button.configure(state="disabled")
        self.remote_features_button.configure(state="disabled")
        self.connect_button.configure(state="normal")
        if not self.installing:
            self.install_button.configure(state="normal")
            self.feature_button.configure(state="normal")
            self.update_button.configure(state="normal")
        self.status.set("Отключено")

    def open_install(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            return
        if self.feature_window is not None:
            self.feature_window.lift()
            return
        if self.update_window is not None:
            self.update_window.lift()
            return
        if self.install_window is not None:
            self.install_window.lift()
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as exc:
            messagebox.showerror("Установка SovaGrid", f"Сначала заполните SSH-адрес и пользователя: {exc}")
            return
        if options.user != "root":
            messagebox.showerror("Установка SovaGrid", "Для первой установки укажите SSH-пользователя root.")
            return
        window = tk.Toplevel(self.root)
        self.theme.style_window(window)
        window.title("SovaGrid · Первая установка")
        window.resizable(False, False)
        window.transient(self.root)
        self.install_window = window
        body = ttk.Frame(window, padding=20)
        body.grid(sticky="nsew")
        ttk.Label(body, text=f"Новый Ubuntu-сервер: {options.host}", font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )
        ttk.Label(
            body,
            text="Скачайте проверенный выпуск SovaGrid прямо в приложении или выберите свой архив. "
                 "Исходный код и run.sh будут выполнены на сервере от root. "
                 "Установка откажет, если SovaGrid уже развёрнут.",
            wraplength=540,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))
        suggested = nearby_server_bundle()
        bundle = tk.StringVar(value=str(suggested[0]) if suggested else "")
        displayed_bundle = tk.StringVar()
        pinned_nearby = suggested is not None and suggested[1] == _APPROVED_SERVER_SOURCE_SHA256
        source_mode = tk.StringVar(value="local" if pinned_nearby else "release")
        ttk.Entry(body, textvariable=displayed_bundle, width=53, state="readonly").grid(
            row=2, column=0, columnspan=2, sticky="ew"
        )
        bundle_info = tk.StringVar()

        def show_source() -> None:
            if source_mode.get() == "release":
                displayed_bundle.set("Автоматически с GitHub")
                bundle_info.set("Серверный выпуск 0.11.0: скачивание, проверка SHA-256 и структуры до SSH-передачи.")
            elif bundle.get() and pinned_nearby and Path(bundle.get()).resolve() == suggested[0]:
                displayed_bundle.set(bundle.get())
                bundle_info.set("Проверенный пакет рядом с приложением · SHA-256 закреплён в Connect")
            elif bundle.get():
                displayed_bundle.set(bundle.get())
                bundle_info.set("Свой архив: источник не закреплён в Connect. Проверьте, откуда он получен.")
            else:
                displayed_bundle.set("")
                bundle_info.set("Для своего архива выберите локальный файл.")

        def choose_bundle() -> None:
            if self.installing:
                return
            selected = filedialog.askopenfilename(
                parent=window, title="Выберите SovaGrid-server-source.tar.gz",
                filetypes=[("Пакет SovaGrid", "*.tar.gz"), ("Все файлы", "*.*")],
            )
            if selected:
                bundle.set(selected)
                source_mode.set("local")
                show_source()

        ttk.Button(body, text="Выбрать свой архив…", command=choose_bundle).grid(row=2, column=2, padx=(8, 0))
        ttk.Radiobutton(body, text="Скачать проверенный выпуск", value="release", variable=source_mode,
                        command=show_source).grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Radiobutton(body, text="Свой архив", value="local", variable=source_mode,
                        command=show_source).grid(row=3, column=2, sticky="w", pady=(8, 0))
        show_source()
        ttk.Label(body, textvariable=bundle_info, wraplength=540).grid(
            row=4, column=0, columnspan=3, sticky="w", pady=(7, 0)
        )
        wireguard = tk.BooleanVar(value=False)
        terminal = tk.BooleanVar(value=False)
        files = tk.BooleanVar(value=False)
        journal = tk.BooleanVar(value=False)
        ttk.Checkbutton(body, text="Добавить управление WireGuard", variable=wireguard).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(14, 0)
        )
        ttk.Checkbutton(body, text="Добавить терминал в панели", variable=terminal).grid(
            row=6, column=0, columnspan=3, sticky="w"
        )
        ttk.Checkbutton(body, text="Добавить файловый раздел", variable=files).grid(
            row=7, column=0, columnspan=3, sticky="w"
        )
        ttk.Checkbutton(body, text="Читать журналы выбранных systemd-служб", variable=journal).grid(
            row=8, column=0, columnspan=3, sticky="w", pady=(8, 0)
        )
        ttk.Label(body, text="Точные имена .service, по одному в строке (1–16):", wraplength=540).grid(
            row=9, column=0, columnspan=3, sticky="w", pady=(5, 0)
        )
        journal_text = tk.Text(body, width=56, height=3)
        self.theme.style_text(journal_text)
        journal_text.grid(row=10, column=0, columnspan=3, sticky="ew")
        journal_text.insert("1.0", "ssh.service\n")
        ttk.Label(
            body, text="SSH-пароль, 2FA и отпечаток нового хоста появятся в отдельных окнах. "
                       "Во время установки не закрывайте приложение.", wraplength=540,
        ).grid(row=11, column=0, columnspan=3, sticky="w", pady=(10, 10))
        status = tk.StringVar(value="Готово к скачиванию и установке" if source_mode.get() == "release" else "Ожидание пакета")
        self.install_status = status
        ttk.Label(body, textvariable=status, wraplength=540).grid(row=12, column=0, columnspan=3, sticky="w", pady=(0, 12))
        controls = ttk.Frame(body)
        controls.grid(row=13, column=0, columnspan=3, sticky="w")

        def begin() -> None:
            if self.installing:
                return
            selected = bundle.get() if source_mode.get() == "local" else None
            if source_mode.get() == "local" and not selected:
                messagebox.showerror("Установка SovaGrid", "Сначала выберите пакет SovaGrid.", parent=window)
                return
            try:
                units = parse_journal_units(journal_text.get("1.0", "end")) if journal.get() else ()
            except InstallError as exc:
                messagebox.showerror("Установка SovaGrid", str(exc), parent=window)
                return
            journal_detail = ("\n\nЖурналы: " + ", ".join(units) + ". "
                              "Разрешение ограничено этими службами в отдельном broker.") if units else ""
            local_pinned = (selected is not None and pinned_nearby and
                            Path(selected).resolve() == suggested[0])
            if selected is None:
                source_detail = "Скачать закреплённый выпуск с GitHub и установить его на новый Ubuntu-сервер от имени root?"
            elif local_pinned:
                source_detail = "Установить проверенный архив рядом с приложением на новый Ubuntu-сервер от имени root?"
            else:
                source_detail = (
                    "Установить выбранный архив на новый Ubuntu-сервер от имени root? "
                    "Источник архива не закреплён в Connect. Убедитесь, что доверяете его происхождению."
                )
            if not messagebox.askyesno(
                "Установка SovaGrid",
                source_detail + journal_detail, parent=window,
            ):
                return
            self.installing = True
            self.install_start_button.configure(state="disabled")
            self.install_button.configure(state="disabled")
            self.feature_button.configure(state="disabled")
            self.update_button.configure(state="disabled")
            self.connect_button.configure(state="disabled")
            features = InstallFeatures(wireguard.get(), terminal.get(), files.get(), units)
            installer = ServerInstaller(options, progress=lambda line: self.events.put(("install_progress", line)))
            self.installer = installer

            def worker() -> None:
                try:
                    if selected is None:
                        with downloaded_server_bundle(progress=lambda line: self.events.put(("install_progress", line))) as path:
                            summary = installer.install(path, features, expected_sha256=_APPROVED_SERVER_SOURCE_SHA256)
                    else:
                        expected = _APPROVED_SERVER_SOURCE_SHA256 if local_pinned else None
                        summary = installer.install(Path(selected), features, expected_sha256=expected)
                    self.events.put(("install_done", summary))
                except Exception as exc:
                    self.events.put(("install_error", exc))

            threading.Thread(target=worker, daemon=True).start()

        self.install_start_button = ttk.Button(controls, text="Установить", command=begin)
        self.install_start_button.pack(side="left")
        ttk.Button(controls, text="Закрыть", command=self.close_install).pack(side="left", padx=(8, 0))
        window.protocol("WM_DELETE_WINDOW", self.close_install)

    def close_install(self) -> None:
        if self.installing:
            messagebox.showinfo(
                "Установка SovaGrid", "Дождитесь результата. Прерывание может оставить сервер частично настроенным.",
                parent=self.install_window,
            )
            return
        if self.install_window is not None:
            self.install_window.destroy()
        self.install_window = None
        self.install_status = None
        self.install_start_button = None

    def open_features(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            return
        if self.install_window is not None:
            self.install_window.lift()
            return
        if self.update_window is not None:
            self.update_window.lift()
            return
        if self.feature_window is not None:
            self.feature_window.lift()
            return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as exc:
            messagebox.showerror("Функции SovaGrid", f"Сначала заполните SSH-адрес и пользователя: {exc}")
            return
        if options.user != "root":
            messagebox.showerror("Функции SovaGrid", "Для включения функций укажите SSH-пользователя root.")
            return
        window = tk.Toplevel(self.root)
        self.theme.style_window(window)
        window.title("SovaGrid · Дополнительные функции")
        window.resizable(True, True)
        window.transient(self.root)
        window.geometry(f"{min(620, window.winfo_screenwidth() - 60)}x"
                        f"{min(720, max(430, window.winfo_screenheight() - 120))}")
        self.feature_window = window
        shell = ttk.Frame(window, padding=12)
        shell.grid(sticky="nsew")
        window.columnconfigure(0, weight=1)
        window.rowconfigure(0, weight=1)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)
        canvas = tk.Canvas(shell, highlightthickness=0, borderwidth=0,
                           background=window.cget("background"))
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(shell, orient="vertical", command=canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        canvas.configure(yscrollcommand=scroll.set)
        body = ttk.Frame(canvas, padding=(8, 8, 12, 12))
        body_item = canvas.create_window((0, 0), window=body, anchor="nw")
        body.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(body_item, width=event.width))
        canvas.bind("<<ThemeChanged>>", lambda _event: canvas.configure(
            background=window.cget("background")))
        ttk.Label(body, text=f"Установленный сервер: {options.host}", font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 10)
        )
        ttk.Label(
            body,
            text="Connect сначала без изменений проверит Hub, Agent и исходники в /opt/sovagrid-src. "
                 "Затем покажет уже включённые функции и спросит подтверждение.",
            wraplength=510,
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))
        wireguard = tk.BooleanVar(value=False)
        terminal = tk.BooleanVar(value=False)
        files = tk.BooleanVar(value=False)
        journal = tk.BooleanVar(value=False)
        journal_disable = tk.BooleanVar(value=False)
        containers = tk.BooleanVar(value=False)
        containers_disable = tk.BooleanVar(value=False)
        self.feature_checks = [
            ttk.Checkbutton(body, text="Управление WireGuard", variable=wireguard),
            ttk.Checkbutton(body, text="Терминал и команды", variable=terminal),
            ttk.Checkbutton(body, text="Файловый раздел", variable=files),
            ttk.Checkbutton(body, text="Журналы конкретных systemd-служб", variable=journal),
            ttk.Checkbutton(body, text="Полностью выключить журналы", variable=journal_disable),
            ttk.Checkbutton(body, text="Просмотр контейнеров Docker/Podman", variable=containers),
            ttk.Checkbutton(body, text="Полностью выключить просмотр контейнеров", variable=containers_disable),
        ]
        for row, checkbox in enumerate(self.feature_checks, start=2):
            checkbox.grid(row=row, column=0, sticky="w")
        ttk.Label(body, text="Полный разрешённый список .service, по одному в строке (1–16):",
                  wraplength=510).grid(row=9, column=0, sticky="w", pady=(9, 0))
        journal_text = tk.Text(body, width=54, height=4)
        self.theme.style_text(journal_text)
        journal_text.grid(row=10, column=0, sticky="ew")
        journal_text.insert("1.0", "ssh.service\n")
        self.feature_journal_text = journal_text
        ttk.Label(
            body,
            text="Контейнеры: отдельный сборщик запускается от root и получает доступ к Docker/Podman Engine socket. "
                 "Agent читает только ограниченный снимок; клиент Connect к Engine socket не подключается.",
            wraplength=510,
        ).grid(row=11, column=0, sticky="w", pady=(10, 0))
        ttk.Label(
            body,
            text="При включении run.sh пересобирает Hub/Web и перезапускает Agent. "
                 "Текущие сеансы могут прерваться. Обновление исходников здесь не выполняется.",
            wraplength=510,
        ).grid(row=12, column=0, sticky="w", pady=(12, 10))
        self.feature_status = tk.StringVar(value="Выберите изменения")
        ttk.Label(body, textvariable=self.feature_status, wraplength=510).grid(
            row=13, column=0, sticky="w", pady=(0, 12)
        )
        controls = ttk.Frame(shell)
        controls.grid(row=1, column=0, sticky="w", pady=(10, 0))

        def begin() -> None:
            if self.installing:
                return
            try:
                units = parse_journal_units(journal_text.get("1.0", "end")) if journal.get() else ()
                selected = InstallFeatures(wireguard.get(), terminal.get(), files.get(), units,
                                           journal_disable.get(), containers.get(), containers_disable.get())
            except InstallError as exc:
                messagebox.showerror("Функции SovaGrid", str(exc), parent=window)
                return
            if not selected.any_enabled():
                messagebox.showerror("Функции SovaGrid", "Выберите хотя бы одну функцию.", parent=window)
                return
            self.installing = True
            self.feature_start_button.configure(state="disabled")
            self.feature_button.configure(state="disabled")
            self.install_button.configure(state="disabled")
            self.update_button.configure(state="disabled")
            self.connect_button.configure(state="disabled")
            for checkbox in self.feature_checks:
                checkbox.configure(state="disabled")
            journal_text.configure(state="disabled")
            manager = ServerInstaller(options, progress=lambda line: self.events.put(("feature_progress", line)))
            self.feature_manager = manager

            def worker() -> None:
                try:
                    state = manager.preflight_features()
                    self.events.put(("feature_preflight", (manager, selected, state)))
                except Exception as exc:
                    self.events.put(("feature_error", exc))

            threading.Thread(target=worker, daemon=True).start()

        self.feature_start_button = ttk.Button(controls, text="Проверить сервер", command=begin)
        self.feature_start_button.pack(side="left")
        ttk.Button(controls, text="Закрыть", command=self.close_features).pack(side="left", padx=(8, 0))
        window.protocol("WM_DELETE_WINDOW", self.close_features)

    def close_features(self) -> None:
        if self.installing:
            messagebox.showinfo(
                "Функции SovaGrid", "Дождитесь результата. Прерывание может оставить настройку незавершённой.",
                parent=self.feature_window,
            )
            return
        if self.feature_window is not None:
            self.feature_window.destroy()
        self.feature_window = None
        self.feature_status = None
        self.feature_start_button = None
        self.feature_manager = None
        self.feature_checks = []
        self.feature_journal_text = None

    def _end_feature_work(self) -> None:
        self.installing = False
        self.feature_manager = None
        self.install_button.configure(state="normal" if self.tunnel is None else "disabled")
        self.feature_button.configure(state="normal")
        self.update_button.configure(state="normal")
        self.connect_button.configure(state="normal" if self.tunnel is None else "disabled")
        if self.feature_start_button is not None:
            self.feature_start_button.configure(state="normal")
        for checkbox in self.feature_checks:
            checkbox.configure(state="normal")
        if self.feature_journal_text is not None:
            self.feature_journal_text.configure(state="normal")

    def open_update(self) -> None:
        if self._lift_management_window():
            return
        if self.installing or self.connecting:
            return
        for existing in (self.install_window, self.feature_window, self.update_window):
            if existing is not None:
                existing.lift()
                return
        try:
            options = self._options().validated()
        except (ValueError, OSError) as exc:
            messagebox.showerror("Обновление SovaGrid", f"Сначала заполните SSH-адрес и пользователя: {exc}")
            return
        if options.user != "root":
            messagebox.showerror("Обновление SovaGrid", "Для подготовки обновления укажите SSH-пользователя root.")
            return
        window = tk.Toplevel(self.root)
        self.theme.style_window(window)
        window.title("SovaGrid · Обновление сервера")
        window.resizable(False, False)
        window.transient(self.root)
        self.update_window = window
        self.update_options = options
        body = ttk.Frame(window, padding=20)
        body.grid(sticky="nsew")
        ttk.Label(body, text=f"Установленный сервер: {options.host}", font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", pady=(0, 10)
        )
        ttk.Label(
            body,
            text="Сначала Connect проверит пакет и действующую версию, затем передаст пакет на сервер. "
                 "Кнопка «Применить» появится после подготовки. Перед запуском версия и SHA-256 "
                 "проверяются снова; работающие службы могут кратко прерваться.",
            wraplength=540,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 12))
        suggested = nearby_server_bundle()
        bundle = tk.StringVar(value=str(suggested[0]) if suggested else "")
        ttk.Entry(body, textvariable=bundle, width=53, state="readonly").grid(
            row=2, column=0, columnspan=2, sticky="ew"
        )
        detail = tk.StringVar(value=(
            f"Пакет рядом с приложением · SHA-256 {suggested[1]}" if suggested else "Выберите локальный пакет SovaGrid"
        ))
        ttk.Label(body, textvariable=detail, wraplength=540).grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(7, 0)
        )

        def choose_bundle() -> None:
            if self.installing:
                return
            selected = filedialog.askopenfilename(
                parent=window, title="Выберите SovaGrid-server-source.tar.gz",
                filetypes=[("Пакет SovaGrid", "*.tar.gz"), ("Все файлы", "*.*")],
            )
            if selected:
                bundle.set(selected)
                detail.set(f"Выбран файл: {Path(selected).name} · SHA-256 будет показан после проверки")
                self.update_preview = None
                self.update_prepared = None
                if self.update_apply_button is not None:
                    self.update_apply_button.configure(state="disabled")
                if self.update_auto_button is not None:
                    self.update_auto_button.configure(state="disabled")
                if self.update_server_auto_button is not None:
                    self.update_server_auto_button.configure(state="disabled")

        ttk.Button(body, text="Выбрать пакет…", command=choose_bundle).grid(row=2, column=2, padx=(8, 0))
        ttk.Label(
            body,
            text="При применении Connect сохраняет предыдущие образы, исходники, настройки и данные Hub, "
                 "проверяет службы и при ошибке пытается восстановить их. Дополнительные пакеты ОС и "
                 "учётные записи, созданные установщиком, автоматически не удаляются.",
            wraplength=540,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(14, 10))
        self.update_status = tk.StringVar(value="Ожидание проверки")
        ttk.Label(body, textvariable=self.update_status, wraplength=540).grid(
            row=5, column=0, columnspan=3, sticky="w", pady=(0, 12)
        )
        controls = ttk.Frame(body)
        controls.grid(row=6, column=0, columnspan=3, sticky="w")

        def begin() -> None:
            if self.installing:
                return
            selected = bundle.get()
            if not selected:
                messagebox.showerror("Обновление SovaGrid", "Сначала выберите пакет SovaGrid.", parent=window)
                return
            self.update_preview = None
            self.update_prepared = None
            if self.update_apply_button is not None:
                self.update_apply_button.configure(state="disabled")
            if self.update_auto_button is not None:
                self.update_auto_button.configure(state="disabled")
            if self.update_server_auto_button is not None:
                self.update_server_auto_button.configure(state="disabled")
            for button in (self.update_server_status_button, self.update_server_disarm_button):
                if button is not None:
                    button.configure(state="disabled")
            self.installing = True
            self.update_start_button.configure(state="disabled")
            self.install_button.configure(state="disabled")
            self.feature_button.configure(state="disabled")
            self.update_button.configure(state="disabled")
            self.connect_button.configure(state="disabled")
            self.update_status.set("Проверка пакета и сервера без изменений…")
            manager = ServerInstaller(options, progress=lambda line: self.events.put(("update_progress", line)))
            self.update_manager = manager

            def worker() -> None:
                try:
                    expected = suggested[1] if suggested and Path(selected).resolve() == suggested[0] else None
                    preview = manager.preview_update(Path(selected), expected_sha256=expected)
                    self.events.put(("update_preview", (manager, Path(selected), preview)))
                except Exception as exc:
                    self.events.put(("update_error", exc))

            threading.Thread(target=worker, daemon=True).start()

        self.update_start_button = ttk.Button(controls, text="Проверить пакет и сервер", command=begin)
        self.update_start_button.pack(side="left")

        def apply_prepared() -> None:
            preview, prepared = self.update_preview, self.update_prepared
            if self.installing or preview is None or prepared is None or preview.sha256 != prepared.sha256:
                return
            active = ", ".join(name for enabled, name in (
                (preview.features.wireguard, "WireGuard"),
                (preview.features.terminal, "терминал"),
                (preview.features.files, "файлы"),
                (preview.features.journal, "журнал"),
            ) if enabled) or "нет"
            if not messagebox.askyesno(
                "Применить обновление SovaGrid",
                f"Сервер: {options.host}\nSHA-256 пакета: {prepared.sha256}\n"
                f"Текущие функции: {active}\n\n"
                "Hub и веб-панель будут остановлены на время резервной копии. Затем новая версия "
                "запустится и пройдёт проверки. При ошибке будет выполнен откат. "
                "Изменения APT и системных пользователей не откатываются. Применить?",
                parent=window,
            ):
                return
            self.installing = True
            self.update_apply_button.configure(state="disabled")
            self.update_start_button.configure(state="disabled")
            for button in (self.update_auto_button, self.update_server_auto_button,
                           self.update_server_status_button, self.update_server_disarm_button):
                if button is not None:
                    button.configure(state="disabled")
            self.install_button.configure(state="disabled")
            self.feature_button.configure(state="disabled")
            self.update_button.configure(state="disabled")
            self.connect_button.configure(state="disabled")
            self.update_status.set("Повторная проверка SHA-256 и версии на сервере…")
            manager = ServerInstaller(options, progress=lambda line: self.events.put(("update_progress", line)))
            self.update_manager = manager

            def worker() -> None:
                try:
                    manager.apply_update(prepared, expected_current_manifest=preview.current_manifest_sha256)
                    self.events.put(("update_applied", None))
                except Exception as exc:
                    self.events.put(("update_error", exc))

            threading.Thread(target=worker, daemon=True).start()

        self.update_apply_button = ttk.Button(controls, text="Применить обновление", command=apply_prepared,
                                              state="disabled")
        self.update_apply_button.pack(side="left", padx=(8, 0))

        def approve_automatic() -> None:
            preview, prepared = self.update_preview, self.update_prepared
            if self.installing or preview is None or prepared is None or preview.sha256 != prepared.sha256:
                return
            if not messagebox.askyesno(
                "Применить при простое",
                f"Этот сервер: {options.host}\nSHA-256 пакета: {prepared.sha256}\n\n"
                "Разрешить Connect применить только этот пакет, если нет активных сеансов и заданий? "
                "Connect должен оставаться открытым с выбранным SSH-сервером. "
                "После успешного применения разрешение выключится. Работа Hub кратко прервётся.",
                parent=window,
            ):
                return
            try:
                policy = AutoUpdatePolicy.approve(
                    options, Path(bundle.get()).resolve(), prepared.sha256,
                    preview.current_manifest_sha256, enabled=True,
                )
                self._auto_policy_store().save(policy)
            except (OSError, ValueError, AutoUpdateError) as exc:
                messagebox.showerror("Применить при простое", str(exc), parent=window)
                return
            self.update_auto_button.configure(state="disabled")
            self.update_apply_button.configure(state="disabled")
            self.update_status.set("Точный пакет одобрен; Connect попробует применить его при простое сервера")
            messagebox.showinfo(
                "Применить при простое",
                "Одобрение сохранено только для этого SSH-сервера и точного SHA-256. "
                "Закройте это окно и оставьте Connect открытым; проверка запускается каждые пять минут.",
                parent=window,
            )

        self.update_auto_button = ttk.Button(
            controls, text="Применить при простое", command=approve_automatic, state="disabled",
        )
        self.update_auto_button.pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Закрыть", command=self.close_update).pack(side="left", padx=(8, 0))

        server_controls = ttk.LabelFrame(body, text="Автообновление на самом сервере", padding=10)
        server_controls.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(14, 0))
        ttk.Label(
            server_controls,
            text="Разрешите один подготовленный пакет. Сервер проверит простой и выполнит обновление "
                 "даже после закрытия Connect. Нужна версия сервера с таймером.",
            wraplength=520,
        ).pack(anchor="w", pady=(0, 8))
        server_buttons = ttk.Frame(server_controls)
        server_buttons.pack(anchor="w")

        def start_server_action(action, success_event: str, message: str) -> None:
            if self.installing:
                return
            self.installing = True
            for button in (self.update_start_button, self.update_apply_button,
                           self.update_auto_button, self.update_server_auto_button,
                           self.update_server_status_button, self.update_server_disarm_button,
                           self.install_button, self.feature_button, self.update_button,
                           self.connect_button):
                if button is not None:
                    button.configure(state="disabled")
            self.update_status.set(message)
            manager = ServerInstaller(options)
            self.update_manager = manager

            def worker() -> None:
                try:
                    self.events.put((success_event, action(manager)))
                except Exception as exc:
                    self.events.put(("server_timer_error", exc))

            threading.Thread(target=worker, daemon=True).start()

        def arm_server_timer() -> None:
            preview, prepared = self.update_preview, self.update_prepared
            if self.installing or preview is None or prepared is None or preview.sha256 != prepared.sha256:
                return
            if not messagebox.askyesno(
                "Разрешить на сервере",
                f"SSH-сервер: {options.host}\nSHA-256 пакета: {prepared.sha256}\n"
                f"Манифест текущей версии: {preview.current_manifest_sha256}\n\n"
                "Разрешить серверу установить только этот подготовленный пакет в течение 14 дней, "
                "когда нет активных сеансов и заданий? Connect можно закрыть. "
                "Работа панели может кратко прерваться. Другие версии не будут скачаны автоматически.",
                parent=window,
            ):
                return
            start_server_action(
                lambda manager: manager.arm_server_timer(
                    prepared, expected_current_manifest=preview.current_manifest_sha256),
                "server_timer_armed", "Проверяем пакет и разрешаем его на выбранном сервере…",
            )

        def show_server_timer() -> None:
            start_server_action(lambda manager: manager.server_timer_status(),
                                "server_timer_status", "Читаем состояние таймера на сервере…")

        def disarm_server_timer() -> None:
            if not messagebox.askyesno(
                "Отключить автообновление на сервере",
                f"Снять разрешение на подготовленный пакет на SSH-сервере {options.host}? "
                "Уже начатое обновление это действие не прерывает.", parent=window,
            ):
                return
            start_server_action(lambda manager: manager.disarm_server_timer(),
                                "server_timer_disarmed", "Снимаем разрешение на сервере…")

        self.update_server_auto_button = ttk.Button(
            server_buttons, text="Разрешить на сервере", command=arm_server_timer, state="disabled",
        )
        self.update_server_auto_button.pack(side="left")
        self.update_server_status_button = ttk.Button(
            server_buttons, text="Состояние", command=show_server_timer,
        )
        self.update_server_status_button.pack(side="left", padx=(8, 0))
        self.update_server_disarm_button = ttk.Button(
            server_buttons, text="Отключить", command=disarm_server_timer,
        )
        self.update_server_disarm_button.pack(side="left", padx=(8, 0))
        window.protocol("WM_DELETE_WINDOW", self.close_update)

    def close_update(self) -> None:
        if self.installing:
            messagebox.showinfo(
                "Обновление SovaGrid", "Дождитесь результата текущего действия.", parent=self.update_window,
            )
            return
        if self.update_window is not None:
            self.update_window.destroy()
        self.update_window = None
        self.update_options = None
        self.update_status = None
        self.update_start_button = None
        self.update_apply_button = None
        self.update_manager = None
        self.update_preview = None
        self.update_prepared = None
        self.update_auto_button = None
        self.update_server_auto_button = None
        self.update_server_status_button = None
        self.update_server_disarm_button = None
        if not self.closing:
            self.root.after(500, self._auto_update_check)

    @staticmethod
    def _auto_policy_store() -> AutoUpdatePolicyStore:
        if os.name == "nt":
            base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return AutoUpdatePolicyStore(base / "sovagrid-connect" / "auto-updates")

    def _auto_update_tick(self) -> None:
        if not self.closing:
            self.root.after(300000, self._auto_update_tick)
        self._auto_update_check()

    def _auto_update_check(self) -> None:
        if (self.closing or self._auto_update_inflight or self.installing or self.connecting or
                any(window is not None for window in (
                    self.install_window, self.feature_window, self.update_window,
                    self.enrollment_window, self.public_web_window,
                    self.remote_features_window, getattr(self, "hub_only_update_window", None),
                    getattr(self, "local_operations_window", None),
                    getattr(self, "local_container_inventory_window", None),
                    getattr(self, "local_commands_window", None),
                    getattr(self, "service_setup_window", None),
                    getattr(self, "container_action_setup_window", None),
                    getattr(self, "hub_backup_window", None), self.key_window,
                    getattr(self, "host_backup_window", None),
                    getattr(self, "routing_window", None), getattr(self, "amnezia_window", None),
                )) or (self.tunnel is not None and self.tunnel.alive)):
            return
        if time.monotonic() - self._auto_last_check < 300:
            return
        try:
            options = self._options().validated()
            if options.user != "root":
                return
            store = self._auto_policy_store()
            policy = store.load(target_id(options))
            if policy is None or not policy.due(time.time()):
                return
        except (ValueError, OSError, AutoUpdateError):
            return
        self._auto_last_check = time.monotonic()
        self._auto_update_inflight = True
        # An unattended apply still changes the server. Keep the parent open
        # and block other management actions until the transaction finishes.
        self.installing = True
        self.install_button.configure(state="disabled")
        self.feature_button.configure(state="disabled")
        self.update_button.configure(state="disabled")
        self.connect_button.configure(state="disabled")
        self.status.set("Одобренное обновление: проверка пакета и простоя сервера…")
        manager = ServerInstaller(options)
        self.update_manager = manager

        def worker() -> None:
            try:
                outcome = run_pinned_update(policy, options, manager, now=time.time())
                if outcome.status == "applied":
                    store.save(replace(policy, enabled=False))
                self.events.put(("auto_update_result", (outcome.status, None)))
            except AutoUpdateError as exc:
                try:
                    store.save(replace(policy, enabled=False))
                except (OSError, AutoUpdateError):
                    pass
                self.events.put(("auto_update_result", ("needs_review", str(exc))))
            except Exception as exc:
                self.events.put(("auto_update_result", ("deferred", str(exc))))

        threading.Thread(target=worker, daemon=True).start()

    def _end_update_work(self) -> None:
        self.installing = False
        self.update_manager = None
        self.install_button.configure(state="normal" if self.tunnel is None else "disabled")
        self.feature_button.configure(state="normal")
        self.update_button.configure(state="normal")
        self.connect_button.configure(state="normal" if self.tunnel is None else "disabled")
        if self.update_start_button is not None:
            self.update_start_button.configure(state="normal")
        self._restore_update_dialog_controls()

    def _restore_update_dialog_controls(self) -> None:
        if self.update_window is None or self.installing:
            return
        ready = (self.update_preview is not None and self.update_prepared is not None and
                 self.update_preview.sha256 == self.update_prepared.sha256)
        for button in (self.update_apply_button, self.update_auto_button,
                       self.update_server_auto_button):
            if button is not None:
                button.configure(state="normal" if ready else "disabled")
        for button in (self.update_server_status_button, self.update_server_disarm_button):
            if button is not None:
                button.configure(state="normal")

    def on_close(self) -> None:
        if getattr(self, "host_backup_window", None) is not None:
            if self.host_backup_window.busy:
                self.host_backup_window.close()
                return
            self.closing = True
            self.host_backup_window.close()
            return
        if getattr(self, "hub_backup_window", None) is not None:
            if self.hub_backup_window.busy:
                self.hub_backup_window.close()
                return
            self.closing = True
            self.hub_backup_window.close()
            return
        for name in ("routing_window", "amnezia_window"):
            vpn_window = getattr(self, name, None)
            if vpn_window is not None:
                if vpn_window.busy:
                    vpn_window.close()
                    return
                self.closing = True
                vpn_window.close()
                return
        if getattr(self, "service_setup_window", None) is not None:
            if self.service_setup_window.busy:
                self.service_setup_window.close()
                return
            self.closing = True
            self.service_setup_window.close()
            return
        if getattr(self, "container_action_setup_window", None) is not None:
            if self.container_action_setup_window.busy:
                self.container_action_setup_window.close()
                return
            self.closing = True
            self.container_action_setup_window.close()
            return
        if getattr(self, "release_feed_window", None) is not None:
            if self.release_feed_window.busy:
                self.release_feed_window.close()
                return
            self.closing = True
            self.release_feed_window.close()
            return
        if getattr(self, "local_commands_window", None) is not None:
            if self.local_commands_window.busy:
                self.local_commands_window.close()
                return
            self.closing = True
            self.local_commands_window.close()
            return
        if getattr(self, "local_operations_window", None) is not None:
            if self.local_operations_window.busy:
                self.local_operations_window.close()
                return
            self.closing = True
            self.local_operations_window.close()
            return
        if getattr(self, "local_container_inventory_window", None) is not None:
            if self.local_container_inventory_window.busy:
                self.local_container_inventory_window.close()
                return
            self.closing = True
            self.local_container_inventory_window.close()
            return
        if getattr(self, "hub_only_update_window", None) is not None:
            if self.hub_only_update_window.busy:
                self.hub_only_update_window.close()
                return
            self.closing = True
            self.hub_only_update_window.close()
            return
        if getattr(self, "promotion_window", None) is not None:
            if self.promotion_window.busy:
                self.promotion_window.close()
                return
            self.closing = True
            self.promotion_window.close()
            return
        if getattr(self, "remote_features_window", None) is not None:
            self.closing = True
            self.status.set("Останавливаем настройку удалённого Agent перед выходом…")
            self.remote_features_window.close()
            return
        if self.public_web_window is not None:
            self.closing = True
            self.status.set("Останавливаем настройку HTTPS перед выходом…")
            self.public_web_window.close()
            return
        if self.enrollment_window is not None:
            self.closing = True
            self.status.set("Останавливаем мастер добавления сервера перед выходом…")
            self.enrollment_window.close()
            return
        if self.installing:
            messagebox.showinfo(
                "Установка SovaGrid", "Дождитесь результата. Прерывание может оставить сервер частично настроенным.",
                parent=self.root,
            )
            return
        if self.key_window is not None and self.key_window.busy:
            self.closing = True
            self.key_window.close()
            self.status.set("Отменяем создание SSH-ключа перед выходом…")
            return
        if self.key_window is not None:
            self.closing = True
            self.key_window.close()
            return
        self.closing = True
        if self.connecting:
            self.status.set("Отключение после завершения SSH-подключения…")
            return
        self.disconnect()
        self.root.destroy()

    def pump(self) -> None:
        while not self.events.empty():
            event, payload = self.events.get()
            if event in ("connected", "error", "server_status"):
                self.connecting = False
            if event == "connected" and not self.closing:
                tunnel, broker = payload
                if tunnel is not self.tunnel or not tunnel.alive:
                    broker and broker.close()
                    continue
                self.grant_broker = broker
                self.status.set(
                    f"Подключено: {self.tunnel.url}" +
                    (" · вход по SSH готов" if broker else " · используйте местный аккаунт Hub")
                )
                self.install_button.configure(state="disabled")
                self.feature_button.configure(state="normal")
                self.update_button.configure(state="normal")
                self.browser_button.configure(state="normal")
                self.disconnect_button.configure(state="normal")
                self.get_password_button.configure(state="normal")
                self.enrollment_button.configure(state="normal")
                self.remote_features_button.configure(state="normal")
                self.open_browser()
            elif event == "server_status" and not self.closing:
                tunnel, server_status = payload
                if tunnel is not self.tunnel:
                    continue
                assert isinstance(server_status, ServerStatus)
                self.status.set(f"Проверка сервера: {server_status.kind}")
                if server_status.kind == "missing":
                    nearby = nearby_server_bundle()
                    approved = nearby is not None and nearby[1] == _APPROVED_SERVER_SOURCE_SHA256
                    if tunnel.options.user == "root":
                        if messagebox.askyesno(
                            "Установить SovaGrid",
                            "На этом Ubuntu-сервере SovaGrid ещё нет. "
                            + ("Установить проверенный пакет рядом с приложением" if approved else
                               "Скачать и проверить серверный пакет с GitHub")
                            + " и сразу открыть панель?",
                            parent=self.root,
                        ):
                            self._auto_install_and_connect(tunnel, nearby[0] if approved else None)
                            continue
                    else:
                        messagebox.showinfo(
                            "Установка SovaGrid",
                            "Сервер пуст. Для автоматической установки выберите SSH-пользователя root "
                            "и нажмите «Подключиться» ещё раз.", parent=self.root,
                        )
                elif server_status.kind == "agent_only":
                    if _APPROVED_PROMOTION_BUNDLE_SHA256 is not None:
                        open_promotion = messagebox.askyesno(
                            "SovaGrid Agent",
                            "На сервере работает Agent другого Hub. Создать отдельный локальный Hub "
                            "через мастер с проверкой пакета и сохранением существующего Agent и туннеля? "
                            "Нужен вход root или действующее sudo без запроса пароля.",
                            parent=self.root,
                        )
                    else:
                        open_promotion = False
                        messagebox.showinfo(
                            "SovaGrid Agent",
                            "На сервере работает удалённый Agent без локальной панели. Его данные доступны "
                            "через Hub, к которому он подключён. Для собственного Hub нужен отдельный "
                            "проверенный пакет и SSH-вход root либо действующее sudo без пароля; "
                            "мастер находится в кнопке «Свой Hub на сервере с Agent…». "
                            "Обычная первая установка сохраняет запрет, чтобы не затронуть Agent и туннель.",
                            parent=self.root,
                        )
                elif server_status.kind == "conflict":
                    messagebox.showwarning(
                        "Установка SovaGrid",
                        "Найдены файлы или службы SovaGrid, но управляемая установка не подтверждена. "
                        "Автоматическая установка ничего не меняла. Проверьте этот сервер вручную.",
                        parent=self.root,
                    )
                elif server_status.kind == "unsupported":
                    messagebox.showinfo(
                        "SovaGrid Connect", "Автоматическая установка сервера сейчас поддерживает Ubuntu.",
                        parent=self.root,
                    )
                self.disconnect()
                if server_status.kind == "agent_only" and open_promotion:
                    self.open_promotion()
            elif event == "auto_install_progress":
                if self.installing:
                    self.status.set(str(payload))
            elif event == "auto_install_end":
                if payload is self.installer:
                    self.installing = False
                    self.installer = None
            elif event == "auto_update_result":
                self._auto_update_inflight = False
                self._end_update_work()
                outcome, detail = payload
                if outcome == "applied":
                    self.status.set("Одобренное обновление установлено; Hub и Agent проверены")
                elif outcome == "needs_review":
                    self.status.set("Автообновление требует нового подтверждения пакета или версии сервера")
                elif outcome == "deferred":
                    self.status.set("Автообновление отложено; Connect проверит сервер позже")
            elif event == "initial_password":
                tunnel, password = payload
                if tunnel is self.tunnel and tunnel.alive and not self.closing:
                    self.fetching_password = False
                    self._initial_secret = password
                    self.initial_password.set("●" * 12)
                    self.copy_password_button.configure(state="normal")
                    self.get_password_button.configure(state="normal")
                    self.status.set("Начальный пароль получен. Нажмите «Копировать» для входа в панель.")
            elif event == "initial_password_error":
                tunnel, error = payload
                if tunnel is self.tunnel and not self.closing:
                    self.fetching_password = False
                    self.get_password_button.configure(state="normal" if tunnel.alive else "disabled")
                    self.status.set("Не удалось получить начальный пароль")
                    messagebox.showerror("SovaGrid Connect", str(error))
            elif event == "error":
                self.disconnect()
                if not self.closing:
                    messagebox.showerror("SovaGrid Connect", str(payload))
            elif event == "install_progress":
                if self.install_status is not None:
                    self.install_status.set(str(payload))
            elif event in ("install_done", "install_error"):
                self.installing = False
                self.installer = None
                self.install_button.configure(state="normal")
                self.feature_button.configure(state="normal")
                self.update_button.configure(state="normal")
                self.connect_button.configure(state="normal" if self.tunnel is None else "disabled")
                if self.install_start_button is not None:
                    self.install_start_button.configure(state="normal" if event == "install_error" else "disabled")
                if event == "install_done":
                    if self.install_status is not None:
                        self.install_status.set("Установка завершена. Теперь нажмите «Подключиться».")
                    messagebox.showinfo("Установка SovaGrid", "SovaGrid установлен. Теперь подключитесь к панели.", parent=self.install_window)
                else:
                    if self.install_status is not None:
                        self.install_status.set("Установка не завершена")
                    messagebox.showerror("Установка SovaGrid", str(payload), parent=self.install_window)
            elif event == "feature_progress":
                if self.feature_status is not None:
                    self.feature_status.set(str(payload))
            elif event == "feature_preflight":
                manager, selected, state = payload
                if manager is self.feature_manager and self.feature_window is not None:
                    active = ", ".join(name for value, name in (
                        (state.wireguard, "WireGuard"), (state.terminal, "терминал"),
                        (state.files, "файлы"), (state.journal, "журналы"),
                        (state.containers, "контейнеры")
                    ) if value) or "нет"
                    if state.journal_configured and not state.journal:
                        active += "; журналы настроены, но broker недоступен"
                    if state.containers_configured and not state.containers:
                        active += "; просмотр контейнеров настроен, но сборщик недоступен"
                    current_units = ", ".join(state.journal_units) if state.journal_units else "нет"
                    container_state = ("включён" if state.containers else
                                       "настроен, но не работает" if state.containers_configured else "выключен")
                    self.feature_status.set(
                        f"Сервер проверен. Уже включены: {active}. Журнальные службы: {current_units}. "
                        f"Просмотр контейнеров: {container_state}."
                    )
                    if (selected.journal_units or selected.journal_disable) and not state.journal_supported:
                        self._end_feature_work()
                        messagebox.showerror(
                            "Функции SovaGrid",
                            "Активный исходный код сервера ещё не поддерживает защищённый просмотр журналов. "
                            "Подготовка пакета обновления не включает его в работу; сначала нужна установка "
                            "новой версии серверных компонентов.", parent=self.feature_window,
                        )
                    elif (selected.containers or selected.containers_disable) and not state.containers_supported:
                        self._end_feature_work()
                        messagebox.showerror(
                            "Функции SovaGrid",
                            "Установленные исходники сервера ещё не поддерживают просмотр контейнеров. "
                            "Сначала установите новую версию серверных компонентов.", parent=self.feature_window,
                        )
                    elif (selected.containers or selected.containers_disable) and not state.cas_sha256:
                        self._end_feature_work()
                        messagebox.showerror(
                            "Функции SovaGrid", "Не удалось подтвердить состояние исходников. Повторите проверку.",
                            parent=self.feature_window,
                        )
                    elif state.covers(selected):
                        self._end_feature_work()
                        messagebox.showinfo("Функции SovaGrid", "Выбранные функции уже включены; сервер не изменён.", parent=self.feature_window)
                    else:
                        wanted = ", ".join(name for value, name in (
                            (selected.wireguard, "WireGuard"), (selected.terminal, "терминал"),
                            (selected.files, "файлы"), (bool(selected.journal_units), "журналы"),
                            (selected.journal_disable, "выключение журналов"),
                            (selected.containers, "просмотр контейнеров"),
                            (selected.containers_disable, "выключение просмотра контейнеров")
                        ) if value)
                        journal_detail = (
                            f"\n\nРазрешённые журналы после изменения: {', '.join(selected.journal_units)}. "
                            "Этот список целиком заменит прежний. Доступ даётся через отдельный broker; "
                            "пользователь Agent не получает доступ ко всем журналам ОС."
                        ) if selected.journal_units else (
                            "\n\nЖурналы будут полностью выключены: Agent перестанет принимать запросы, "
                            "socket и отдельная policy удалятся. Другие функции сохранятся."
                        ) if selected.journal_disable else ""
                        container_detail = (
                            "\n\nПросмотр контейнеров включит root-сборщик с доступом к Docker/Podman "
                            "Engine socket. Agent получит только ограниченный снимок."
                        ) if selected.containers else (
                            "\n\nПросмотр контейнеров будет выключен; таймер и снимок удалятся. "
                            "Другие функции сохранятся."
                        ) if selected.containers_disable else ""
                        confirmed = messagebox.askyesno(
                            "Настроить функции SovaGrid",
                            f"Уже включены: {active}. Применить: {wanted}?\n\n"
                            "run.sh пересоберёт Hub/Web и перезапустит Agent; текущие сеансы могут прерваться."
                            + journal_detail + container_detail,
                            parent=self.feature_window,
                        )
                        if confirmed:
                            def worker() -> None:
                                try:
                                    manager.enable_features(selected, expected_state=state)
                                    self.events.put(("feature_done", None))
                                except Exception as exc:
                                    self.events.put(("feature_error", exc))
                            threading.Thread(target=worker, daemon=True).start()
                        else:
                            self._end_feature_work()
                            self.feature_status.set("Изменения отменены")
            elif event == "feature_done":
                self._end_feature_work()
                if self.feature_status is not None:
                    self.feature_status.set("Настройка функций завершена; проверьте состояние в панели")
                messagebox.showinfo("Функции SovaGrid", "Настройка завершена. Обновите или откройте панель снова.", parent=self.feature_window)
            elif event == "feature_error":
                self._end_feature_work()
                if self.feature_status is not None:
                    self.feature_status.set("Настройка не завершена")
                messagebox.showerror("Функции SovaGrid", str(payload), parent=self.feature_window)
            elif event == "update_progress":
                if self.update_status is not None:
                    self.update_status.set(str(payload))
            elif event == "update_preview":
                manager, source, preview = payload
                if manager is self.update_manager and self.update_window is not None:
                    self.update_preview = preview
                    active = ", ".join(name for enabled, name in (
                        (preview.features.wireguard, "WireGuard"),
                        (preview.features.terminal, "терминал"),
                        (preview.features.files, "файлы"),
                        (preview.features.journal, "журнал"),
                    ) if enabled) or "нет"
                    versions = "\n".join(
                        f"{name}: {preview.current_commits[name][:12]} → {commit[:12]}"
                        for name, commit in sorted(preview.bundle.commits.items())
                    )
                    confirmed = messagebox.askyesno(
                        "Подготовить обновление SovaGrid",
                        f"Сервер проверен. Включены: {active}.\n\n"
                        f"Пакет: {preview.bundle.files} файлов, {preview.bundle.size // 1024} КиБ\n"
                        f"SHA-256: {preview.sha256}\n\n"
                        f"Текущие → новые версии:\n{versions}\n\n"
                        "Передать и проверить этот пакет на сервере? Работающие службы и активные исходники "
                        "не изменятся. Commit ID показывают состав пакета, но не доказывают, что он новее. "
                        "Проверьте, что пакет получен из доверенного источника.",
                        parent=self.update_window,
                    )
                    if confirmed:
                        def worker() -> None:
                            try:
                                result = manager.prepare_update(source, expected_sha256=preview.sha256)
                                self.events.put(("update_done", result))
                            except Exception as exc:
                                self.events.put(("update_error", exc))
                        threading.Thread(target=worker, daemon=True).start()
                    else:
                        self._end_update_work()
                        self.update_status.set("Передача отменена; сервер не изменён")
            elif event == "update_done":
                self._end_update_work()
                self.update_prepared = payload
                if self.update_apply_button is not None:
                    self.update_apply_button.configure(state="normal")
                if self.update_auto_button is not None:
                    self.update_auto_button.configure(state="normal")
                if self.update_server_auto_button is not None:
                    self.update_server_auto_button.configure(state="normal")
                if self.update_status is not None:
                    self.update_status.set("Пакет проверен и готов. Для установки нажмите «Применить обновление».")
                messagebox.showinfo(
                    "Обновление SovaGrid",
                    "Пакет уже был подготовлен." if payload.already_prepared else
                    "Пакет подготовлен и проверен на сервере. Действующая версия продолжает работать. "
                    "Для установки нажмите «Применить обновление».",
                    parent=self.update_window,
                )
            elif event == "update_applied":
                self._end_update_work()
                self.update_prepared = None
                self.update_preview = None
                if self.update_apply_button is not None:
                    self.update_apply_button.configure(state="disabled")
                if self.update_auto_button is not None:
                    self.update_auto_button.configure(state="disabled")
                if self.update_server_auto_button is not None:
                    self.update_server_auto_button.configure(state="disabled")
                if self.update_status is not None:
                    self.update_status.set("Обновление завершено; Hub, веб-панель и Agent отвечают")
                messagebox.showinfo("Обновление SovaGrid", "Новая версия установлена и прошла проверки.",
                                    parent=self.update_window)
            elif event == "update_error":
                self._end_update_work()
                self.update_prepared = None
                if self.update_apply_button is not None:
                    self.update_apply_button.configure(state="disabled")
                if self.update_auto_button is not None:
                    self.update_auto_button.configure(state="disabled")
                if self.update_server_auto_button is not None:
                    self.update_server_auto_button.configure(state="disabled")
                if self.update_status is not None:
                    self.update_status.set("Обновление не завершено; прочитайте сообщение и проверьте сервер")
                messagebox.showerror("Обновление SovaGrid", str(payload), parent=self.update_window)
            elif event == "server_timer_armed":
                self._end_update_work()
                self._restore_update_dialog_controls()
                local_warning = ""
                if self.update_options is not None:
                    try:
                        store = self._auto_policy_store()
                        existing = store.load(target_id(self.update_options))
                        if existing is not None and existing.enabled:
                            store.save(replace(existing, enabled=False))
                    except (OSError, ValueError, AutoUpdateError):
                        local_warning = " Проверьте также локальное разрешение Connect."
                already_armed = payload == "already_armed"
                if self.update_status is not None:
                    self.update_status.set((
                        "Этот пакет уже разрешён на сервере; нажмите «Состояние» для срока действия"
                        if already_armed else "Пакет разрешён на самом сервере; Connect можно закрыть"
                    ) + local_warning)
                messagebox.showinfo(
                    "Автообновление на сервере",
                    ("Этот пакет уже был разрешён на сервере. Срок не продлён; нажмите «Состояние», "
                     "чтобы увидеть его. " if already_armed else
                     "Сервер сам попробует применить этот пакет при простое. Разрешение действует "
                     "до 14 дней. ") + "Другие пакеты не скачиваются." + local_warning,
                    parent=self.update_window,
                )
            elif event == "server_timer_status":
                self._end_update_work()
                self._restore_update_dialog_controls()
                if payload.armed:
                    expiry = time.strftime("%d.%m.%Y %H:%M", time.localtime(payload.expires_at))
                    summary = f"На сервере разрешён пакет {payload.archive_sha256[:16]}… до {expiry}."
                else:
                    summary = "На сервере нет разрешённого пакета."
                state_labels = {
                    "armed": "Ожидает простоя", "disabled": "Отключено",
                    "deferred_busy": "Отложено: сервер занят", "applied": "Применено",
                    "expired": "Срок разрешения истёк", "needs_attention": "Нужна проверка ошибки",
                }
                if payload.last_state is not None:
                    summary += " Последний результат: " + state_labels[payload.last_state] + "."
                if self.update_status is not None:
                    self.update_status.set(summary)
                messagebox.showinfo("Автообновление на сервере", summary, parent=self.update_window)
            elif event == "server_timer_disarmed":
                self._end_update_work()
                self._restore_update_dialog_controls()
                if self.update_status is not None:
                    self.update_status.set("Разрешение на автообновление снято на выбранном сервере")
                messagebox.showinfo("Автообновление на сервере", "Разрешение снято.",
                                    parent=self.update_window)
            elif event == "server_timer_error":
                self._end_update_work()
                self._restore_update_dialog_controls()
                if self.update_status is not None:
                    self.update_status.set("Действие с серверным таймером не подтверждено")
                messagebox.showerror("Автообновление на сервере", str(payload),
                                     parent=self.update_window)
            if (self.closing and self.enrollment_window is None and self.public_web_window is None
                    and getattr(self, "remote_features_window", None) is None
                    and getattr(self, "hub_only_update_window", None) is None
                    and getattr(self, "local_operations_window", None) is None
                    and getattr(self, "local_container_inventory_window", None) is None
                    and getattr(self, "local_commands_window", None) is None
                    and getattr(self, "release_feed_window", None) is None
                    and getattr(self, "service_setup_window", None) is None
                    and getattr(self, "container_action_setup_window", None) is None
                    and getattr(self, "hub_backup_window", None) is None
                    and getattr(self, "host_backup_window", None) is None
                    and getattr(self, "routing_window", None) is None
                    and getattr(self, "amnezia_window", None) is None
                    and not (self.key_window is not None and self.key_window.busy)):
                self.disconnect()
                self.root.destroy()
                return
        if self.tunnel is not None and not self.connecting and not self.tunnel.alive:
            if getattr(self, "remote_features_window", None) is not None:
                self.remote_features_window.close()
                self.status.set("SSH-соединение завершилось. Проверяем завершение мастера функций…")
                self.root.after(100, self.pump)
                return
            if self.enrollment_window is not None:
                self.enrollment_window.close()
                self.status.set("SSH-соединение завершилось. Сохраняем состояние мастера…")
                self.root.after(100, self.pump)
                return
            self.disconnect()
            self.status.set("SSH-соединение завершилось")
        self.root.after(100, self.pump)


def main() -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"SovaGrid Connect GUI unavailable: {exc}", file=sys.stderr)
        return 2
    Launcher(root)
    root.mainloop()
    return 0
