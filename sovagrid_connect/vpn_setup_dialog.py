# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Separate graphical consent for owned WG routing and Amnezia targets."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .vpn_setup import (AmneziaEnrollmentPreview, AmneziaSettingsAccess, AmneziaSettingsPlan,
                        AmneziaSettingsPreview, AmneziaState, NftablesState,
                        RoutingState, VpnSetupController, awg_settings_patch)


TARGET_LABELS = {"awg2": "AmneziaWG AWG2", "wireguard": "Amnezia WireGuard"}
AWG_FORM_FIELDS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
PLAN_BLOCKER_LABELS = {
    "CLIENT_PROFILES_REQUIRE_REISSUE": "Нужно перевыпустить существующие профили клиентов.",
    "RUNTIME_PARAMETERS_UNVERIFIED": "Сервер пока не может проверить параметры работающего AWG после переключения.",
}
SETTINGS_ACCESS_REASONS = {
    "INSTALL_NOT_CURRENT": "Установите проверенный выпуск broker.",
    "TARGET_UNAVAILABLE": "Проверьте и примите контейнер AWG2.",
    "CLIENTS_PRESENT": "В контейнере уже есть клиенты; для них потребуется миграция профилей.",
    "AWG3_INCOMPLETE": "В конфигурации нет полного набора параметров AWG3.",
    "RUNTIME_UNVERIFIED": "Работающие параметры AWG3 не подтвердились.",
    "POLICY_NOT_READY": "Сначала включите обычное управление профилями AWG2.",
    "POLICY_UNSAFE": "Настройки разрешения изменены вне SovaGrid; нужна проверка администратора.",
    "ALREADY_ARMED": "Изменение AWG3 уже разрешено.",
}


class _Dialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256,
                 title, heading, description):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: VpnSetupController | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            "Проверьте сервер без изменений перед действием."
            if approved_manifest_sha256 else "Функция ждёт общий проверенный серверный выпуск."
        ))
        self.window = tk.Toplevel(root)
        self.window.title(title + " · SovaGrid Connect")
        self.window.transient(root)
        self.window.geometry("780x520")
        self.window.minsize(640, 430)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        self.body = ttk.Frame(self.window, padding=16)
        self.body.grid(sticky="nsew")
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(4, weight=1)
        ttk.Label(self.body, text=heading, font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, sticky="w")
        route = f"{options.user}@{options.host}:{options.port}"
        if options.jump_host:
            route += f" через {options.jump_user}@{options.jump_host}:{options.jump_port}"
        ttk.Label(self.body, text="SSH-маршрут: " + route, wraplength=730).grid(
            row=1, column=0, sticky="w", pady=(7, 0))
        ttk.Label(self.body, text=description, wraplength=730).grid(
            row=2, column=0, sticky="w", pady=(9, 5))
        self.choice_row = ttk.Frame(self.body)
        self.choice_row.grid(row=3, column=0, sticky="ew", pady=(7, 5))
        self.details = tk.Text(self.body, height=10, wrap="word", state="disabled")
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky="nsew", pady=(8, 7))
        ttk.Label(self.body, textvariable=self.status, wraplength=730).grid(
            row=5, column=0, sticky="w")
        self.buttons = ttk.Frame(self.body)
        self.buttons.grid(row=6, column=0, sticky="ew", pady=(10, 0))
        self.close_button = ttk.Button(self.buttons, text="Закрыть", command=self.close)
        self.close_button.pack(side="right")
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> VpnSetupController:
        if self.controller is None:
            self.controller = VpnSetupController(
                self.options, approved_manifest_sha256=self.approved_manifest_sha256,
                progress=lambda value: self.events.put(("progress", value)))
        return self.controller

    def _show(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def _run(self, kind: str, operation) -> None:
        self.busy = True
        self._controls()
        def worker():
            try:
                self.events.put((kind, operation()))
            except Exception as exc:
                self.events.put(("error", exc))
        threading.Thread(target=worker, daemon=True).start()

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
            if event == "error":
                self._invalidate()
                message = str(payload) if isinstance(payload, InstallError) else (
                    "Сервер не подтвердил VPN-операцию. Проверьте состояние перед повтором.")
                self.status.set(message)
                messagebox.showerror(self.window.title(), message, parent=self.window)
            else:
                self._result(event, payload)
            self._controls()
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo(self.window.title(), "Дождитесь ответа сервера.", parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()


class RoutingDialog(_Dialog):
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256):
        super().__init__(root, theme, options, on_closed,
                         approved_manifest_sha256=approved_manifest_sha256,
                         title="Полный маршрут WireGuard",
                         heading="Полный маршрут через собственный WireGuard",
                         description=("Это отдельная настройка NAT для одного управляемого VPN-инстанса. "
                                      "Нужен nftables. После включения проверьте внешний IP и доступность сайтов "
                                      "на телефоне: другие firewall-правила и IPv6 остаются отдельными проверками."))
        self.state: RoutingState | None = None
        self.dependency: NftablesState | None = None
        self.name = tk.StringVar()
        ttk.Label(self.choice_row, text="VPN-инстанс:").pack(side="left")
        self.choice = ttk.Combobox(self.choice_row, textvariable=self.name,
                                   state="readonly", width=34)
        self.choice.pack(side="left", padx=(9, 0))
        self.choice.bind("<<ComboboxSelected>>", self._changed)
        self.check_button = ttk.Button(self.buttons, text="Проверить", command=self.check)
        self.check_button.pack(side="left")
        self.install_button = ttk.Button(self.buttons, text="Установить nftables", command=self.install_nftables)
        self.install_button.pack(side="left", padx=(8, 0))
        self.arm_button = ttk.Button(self.buttons, text="Включить маршрут", command=self.arm)
        self.arm_button.pack(side="left", padx=(8, 0))
        self.disarm_button = ttk.Button(self.buttons, text="Выключить маршрут", command=self.disarm)
        self.disarm_button.pack(side="left", padx=(8, 0))
        self._controls()

    def _invalidate(self) -> None:
        self.state = None
        self.dependency = None
        self._show("")

    def _changed(self, _event=None) -> None:
        self._invalidate()
        self.status.set("Инстанс изменён. Проверьте его снова.")
        self._controls()

    def _controls(self) -> None:
        ready = not self.busy and self.approved_manifest_sha256 is not None
        self.choice.configure(state="readonly" if ready else "disabled")
        self.check_button.configure(state="normal" if ready else "disabled")
        installable = (self.dependency is not None and self.dependency.nft_version is None and
                       self.dependency.package in ("absent", "not-installed") and
                       self.dependency.service_enabled == "not-found" and
                       self.dependency.service_active in ("inactive", "not-found", "unknown"))
        self.install_button.configure(state="normal" if ready and installable else "disabled")
        self.arm_button.configure(state="normal" if ready and self.state is not None and
                                  not self.state.configured and not self.state.recovery_required else "disabled")
        self.disarm_button.configure(state="normal" if ready and self.state is not None and
                                     self.state.armed else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        selected = self.name.get()
        self._invalidate()
        self.status.set("Проверяем Ubuntu, nftables, инстансы и состояние маршрута…")
        controller = self._controller()
        def operation():
            names = controller.instances()
            name = selected if selected in names else names[0] if names else ""
            dependency = controller.nftables_status()
            state = controller.routing_preview(name) if name and dependency.nft_version else None
            return names, dependency, state
        self._run("checked", operation)

    def install_nftables(self) -> None:
        dependency = self.dependency
        if self.busy or dependency is None or dependency.nft_version is not None:
            return
        if not messagebox.askyesno("Установить nftables?",
                                   f"Ubuntu {dependency.ubuntu_version}. Через APT обновить список пакетов "
                                   "и установить nftables без дополнительных рекомендуемых пакетов? "
                                   "Этот шаг не включает nftables.service и не записывает правила firewall. "
                                   "После установки мастер проверит версию nft и выключенное состояние службы.",
                                   parent=self.window):
            return
        name = self.name.get()
        self.status.set("APT устанавливает nftables; правила firewall не меняются этим шагом…")
        controller = self._controller()
        def operation():
            installed = controller.nftables_install(dependency)
            state = controller.routing_preview(name) if name else None
            return installed, state
        self._run("dependency", operation)

    def arm(self) -> None:
        state = self.state
        if self.busy or state is None or state.configured or state.recovery_required:
            return
        if not messagebox.askyesno("Включить полный маршрут?",
                                   f"Инстанс: {state.name}\n\nСоздать отдельное правило NAT и включить "
                                   "IPv4-пересылку? Это может повлиять на сетевые политики сервера. "
                                   "Доступность с телефона нужно проверить отдельно.",
                                   parent=self.window):
            return
        self.status.set("Включаем точную собственную таблицу NAT…")
        self._run("state", lambda: self._controller().routing_arm(state))

    def disarm(self) -> None:
        state = self.state
        if self.busy or state is None or not state.armed:
            return
        if not messagebox.askyesno("Выключить полный маршрут?",
                                   f"Инстанс: {state.name}\n\nУдалить его правило NAT? "
                                   "Клиентские профили с полным маршрутом потеряют доступ к Интернету.",
                                   parent=self.window):
            return
        self.status.set("Отключаем только правило этого инстанса…")
        self._run("state", lambda: self._controller().routing_disarm(state))

    def _result(self, event: str, payload: object) -> None:
        if event == "checked":
            names, dependency, state = payload
            self.choice.configure(values=names)
            self.dependency = dependency
            self.name.set(state.name if state else names[0] if names else "")
            if dependency.nft_version is None:
                self._show(f"Ubuntu {dependency.ubuntu_version}. Пакет nftables отсутствует. "
                           "Нажмите «Установить nftables», затем проверьте маршрут.")
                self.status.set("Для полного маршрута сначала установите nftables.")
                return
            if state is None:
                self._show("Управляемых инстансов WireGuard пока нет. Создайте VPN в панели.")
                self.status.set("Нет VPN-инстансов для настройки маршрута.")
                return
        elif event == "dependency":
            dependency, state = payload
            self.dependency = dependency
            if state is None:
                self._show(f"{dependency.nft_version} установлен. Создайте VPN-инстанс в панели.")
                self.status.set("nftables установлен; VPN-инстансов пока нет.")
                return
        else:
            state = payload
        if isinstance(state, RoutingState):
            self.state = state
            self._show("\n".join((
                f"Инстанс: {state.name}",
                f"Полный маршрут: {'настроен' if state.configured else 'не настроен'}",
                f"Политика включена: {'да' if state.armed else 'нет'}",
                f"IPv4-пересылка: {'включена' if state.forwarding else 'выключена'}",
                f"Своё NAT-правило: {'есть' if state.nat else 'нет'}",
                f"Требуется восстановление: {'да' if state.recovery_required else 'нет'}",
                "Связь телефона с Интернетом и правила других firewall здесь не проверяются.",
            )))
            self.status.set("Состояние проверено." if not state.recovery_required else
                            "Обнаружено неполное состояние; автоматическое включение остановлено.")


class AmneziaSettingsPlanForm:
    """Public numeric inputs only; checking the plan never writes VPN settings."""

    def __init__(self, owner: "AmneziaDialog", preview: AmneziaSettingsPreview):
        self.owner, self.preview = owner, preview
        self.window = tk.Toplevel(owner.window)
        self.window.title("План параметров AWG3 · SovaGrid Connect")
        self.window.transient(owner.window)
        self.window.geometry("710x640")
        self.window.minsize(620, 570)
        self.window.columnconfigure(0, weight=1)
        owner.theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky="nsew")
        body.columnconfigure(2, weight=1)
        ttk.Label(body, text="План параметров AWG3", font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(body, text=(
            "Введите предлагаемые числовые значения. Проверка построит план на сервере "
            "по точному хешу конфигурации и поколению. Настройки и клиенты не меняются."
        ), wraplength=660).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 10))
        ttk.Label(body, text=f"Поколение: {preview.generation}; SHA-256 текущей конфигурации:").grid(
            row=2, column=0, columnspan=3, sticky="w")
        digest = ttk.Entry(body, width=68)
        digest.insert(0, preview.config_sha256)
        digest.configure(state="readonly")
        digest.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(3, 12))
        for col, title in enumerate(("Поле", "Сейчас", "Предложение")):
            ttk.Label(body, text=title, font=("TkDefaultFont", 10, "bold")).grid(
                row=4, column=col, sticky="w", padx=(0, 12))
        current = dict(preview.awg_parameters)
        self.values: dict[str, tk.StringVar] = {}
        for index, name in enumerate(AWG_FORM_FIELDS, 5):
            ttk.Label(body, text=name).grid(row=index, column=0, sticky="w", pady=3)
            ttk.Label(body, text=current[name]).grid(row=index, column=1, sticky="w", padx=(0, 20))
            variable = tk.StringVar(value=current[name])
            self.values[name] = variable
            ttk.Entry(body, textvariable=variable, width=25).grid(
                row=index, column=2, sticky="ew", pady=3)
        ttk.Label(body, text=(
            "Jc, Jmin, Jmax: 0–65535; S1–S4: 12–65535; "
            "H1–H4: 0–4294967295 или диапазон «начало-конец»."
        ), wraplength=660).grid(row=16, column=0, columnspan=3, sticky="w", pady=(10, 4))
        self.status = tk.StringVar(value="Измените хотя бы одно поле, затем проверьте план.")
        ttk.Label(body, textvariable=self.status, wraplength=660).grid(
            row=17, column=0, columnspan=3, sticky="w", pady=(0, 9))
        buttons = ttk.Frame(body)
        buttons.grid(row=18, column=0, columnspan=3, sticky="ew")
        ttk.Button(buttons, text="Проверить план", command=self.submit).pack(side="left")
        ttk.Button(buttons, text="Закрыть", command=self.close).pack(side="right")
        self.window.protocol("WM_DELETE_WINDOW", self.close)

    def submit(self) -> None:
        proposal = {name: value.get().strip() for name, value in self.values.items()}
        try:
            awg_settings_patch(self.preview, proposal)
        except InstallError as exc:
            self.status.set(str(exc))
            return
        if self.owner.request_settings_plan(self.preview, proposal):
            self.close()
        else:
            self.status.set("Состояние AWG2 изменилось. Проверьте контейнер и настройки заново.")

    def close(self) -> None:
        self.owner.plan_form = None
        self.window.destroy()


class AmneziaDialog(_Dialog):
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256):
        super().__init__(root, theme, options, on_closed,
                         approved_manifest_sha256=approved_manifest_sha256,
                         title="Amnezia peer broker",
                         heading="Управление клиентами Amnezia",
                         description=("Выберите AWG2 или WireGuard. Сначала можно просмотреть и принять "
                                      "точный работающий контейнер без ввода Docker ID. Затем мастер "
                                      "устанавливает отдельный broker и по подтверждению включает доступ. "
                                      "Просмотр и принятие не меняют клиентов или настройки VPN."))
        self.window.geometry("820x570")
        self.state: AmneziaState | None = None
        self.enrollment_preview: AmneziaEnrollmentPreview | None = None
        self.settings_preview: AmneziaSettingsPreview | None = None
        self.settings_plan: AmneziaSettingsPlan | None = None
        self.settings_access: AmneziaSettingsAccess | None = None
        self.plan_form: AmneziaSettingsPlanForm | None = None
        self.target = tk.StringVar(value="awg2")
        ttk.Label(self.choice_row, text="Цель:").pack(side="left")
        self.choice = ttk.Combobox(self.choice_row, textvariable=self.target,
                                   values=("awg2", "wireguard"), state="readonly", width=16)
        self.choice.pack(side="left", padx=(9, 0))
        self.choice.bind("<<ComboboxSelected>>", self._changed)
        self.target_label = ttk.Label(self.choice_row, text=TARGET_LABELS["awg2"])
        self.target_label.pack(side="left", padx=(9, 0))
        self.check_button = ttk.Button(self.buttons, text="Проверить", command=self.check)
        self.check_button.pack(side="left")
        self.settings_button = ttk.Button(self.buttons, text="Показать настройки", command=self.show_settings)
        self.settings_button.pack(side="left", padx=(8, 0))
        self.enroll_preview_button = ttk.Button(
            self.choice_row, text="Посмотреть контейнер", command=self.preview_enrollment)
        self.enroll_preview_button.pack(side="left", padx=(8, 0))
        self.enroll_button = ttk.Button(
            self.choice_row, text="Принять контейнер…", command=self.enroll)
        self.enroll_button.pack(side="left", padx=(8, 0))
        self.plan_button = ttk.Button(self.choice_row, text="План AWG3…", command=self.open_plan)
        self.plan_button.pack(side="left", padx=(8, 0))
        self.install_button = ttk.Button(self.buttons, text="Установить broker", command=self.install)
        self.install_button.pack(side="left", padx=(8, 0))
        self.arm_button = ttk.Button(self.buttons, text="Включить доступ", command=self.arm)
        self.arm_button.pack(side="left", padx=(8, 0))
        self.disarm_button = ttk.Button(self.buttons, text="Выключить доступ", command=self.disarm)
        self.disarm_button.pack(side="left", padx=(8, 0))
        self.settings_actions = ttk.Frame(self.body)
        self.settings_actions.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(self.settings_actions, text="Параметры AWG3:").pack(side="left")
        self.settings_check_button = ttk.Button(
            self.settings_actions, text="Проверить разрешение", command=self.check_settings_access)
        self.settings_check_button.pack(side="left", padx=(8, 0))
        self.settings_arm_button = ttk.Button(
            self.settings_actions, text="Разрешить изменение…", command=self.arm_settings)
        self.settings_arm_button.pack(side="left", padx=(8, 0))
        self.settings_disarm_button = ttk.Button(
            self.settings_actions, text="Запретить изменение", command=self.disarm_settings)
        self.settings_disarm_button.pack(side="left", padx=(8, 0))
        self._controls()

    def _invalidate(self) -> None:
        if self.plan_form is not None:
            self.plan_form.close()
        self.state = None
        self.enrollment_preview = None
        self.settings_preview = None
        self.settings_plan = None
        self.settings_access = None
        self._show("")

    def _changed(self, _event=None) -> None:
        self._invalidate()
        self.target_label.configure(text=TARGET_LABELS.get(self.target.get(), ""))
        self.status.set("Цель изменилась. Проверьте её снова.")
        self._controls()

    def _controls(self) -> None:
        ready = not self.busy and self.approved_manifest_sha256 is not None
        state = self.state
        self.choice.configure(state="readonly" if ready else "disabled")
        self.check_button.configure(state="normal" if ready else "disabled")
        self.settings_button.configure(state="normal" if ready and state is not None and
                                       state.target_ready else "disabled")
        preview = self.settings_preview
        self.plan_button.configure(state="normal" if ready and state is not None and
                                   state.target == "awg2" and state.target_ready and
                                   preview is not None and preview.awg3_required_parameters_present and
                                   preview.header_protection_key_present else "disabled")
        self.enroll_preview_button.configure(state="normal" if ready and
                                             (state is None or not state.target_ready) else "disabled")
        self.enroll_button.configure(state="normal" if ready and
                                     self.enrollment_preview is not None and
                                     self.enrollment_preview.target == self.target.get() and
                                     (state is None or not state.target_ready) else "disabled")
        installable = (state is not None and state.installer_ready and not state.installed_current and
                       state.marker == state.other_marker == "absent" and
                       not state.socket_active and not state.service_active)
        self.install_button.configure(state="normal" if ready and installable else "disabled")
        self.arm_button.configure(state="normal" if ready and state is not None and state.can_arm else "disabled")
        self.disarm_button.configure(state="normal" if ready and state is not None and
                                     state.marker == "valid" else "disabled")
        access = self.settings_access
        self.settings_check_button.configure(state="normal" if ready and
                                             self.target.get() == "awg2" else "disabled")
        self.settings_arm_button.configure(state="normal" if ready and access is not None and
                                           access.can_arm and state is not None and
                                           state.target == "awg2" and state.marker == "valid" and
                                           state.container_id == access.container_id else "disabled")
        self.settings_disarm_button.configure(state="normal" if ready and access is not None and
                                              access.settings_marker == "valid" and
                                              self.target.get() == "awg2" else "disabled")
        self.close_button.configure(state="disabled" if self.busy else "normal")

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        target = self.target.get()
        self._invalidate()
        self.status.set("Проверяем исходники, broker и выбранный контейнер без изменений…")
        self._run("state", lambda: self._controller().amnezia_preview(target))

    def preview_enrollment(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        target = self.target.get()
        self._invalidate()
        self.status.set("Проверяем работающий контейнер и его конфигурацию без изменений…")
        self._run("enrollment_preview",
                  lambda: self._controller().amnezia_enroll_preview(target))

    def show_settings(self) -> None:
        state = self.state
        if self.busy or state is None or not state.target_ready:
            return
        if self.plan_form is not None:
            self.plan_form.close()
        self.settings_preview = None
        self.settings_plan = None
        self.status.set("Сверяем закреплённый контейнер и читаем безопасный обзор настроек…")
        self._run("settings_preview", lambda: self._controller().amnezia_settings_preview(state))

    def open_plan(self) -> None:
        preview = self.settings_preview
        state = self.state
        if (self.busy or state is None or not state.target_ready or state.target != "awg2" or
                preview is None or not preview.awg3_required_parameters_present or
                not preview.header_protection_key_present):
            return
        if self.plan_form is not None:
            self.plan_form.window.lift()
            return
        self.plan_form = AmneziaSettingsPlanForm(self, preview)

    def request_settings_plan(self, preview: AmneziaSettingsPreview,
                              proposal: dict[str, str]) -> bool:
        state = self.state
        if (self.busy or state is None or state.target != "awg2" or
                self.settings_preview is not preview or not state.target_ready):
            return False
        self.settings_plan = None
        self.status.set("Проверяем план AWG3 по текущему хешу и поколению без изменений сервера…")
        self._run("settings_plan", lambda: self._controller().amnezia_settings_plan(
            state, preview, proposal))
        return True

    def check_settings_access(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None or self.target.get() != "awg2":
            return
        self.settings_access = None
        self.status.set("Проверяем отдельное разрешение на изменение AWG3 без записи на сервер…")
        self._run("settings_access", self._controller().amnezia_settings_access)

    def arm_settings(self) -> None:
        access, state = self.settings_access, self.state
        if (self.busy or access is None or not access.can_arm or
                state is None or state.target != "awg2" or state.marker != "valid" or
                access.container_id is None or state.container_id != access.container_id):
            return
        if not messagebox.askyesno(
                "Разрешить изменение AWG3?",
                f"Контейнер: {access.container_id}\n"
                "Клиентов: 0; работающие параметры AWG3 проверены.\n\n"
                "Разрешить отдельные числовые изменения AWG3 в панели? "
                "Только администратор сможет применять проверенный план, "
                "без смены порта и ключей. Этот шаг только включает разрешение "
                "и не меняет настройки VPN. Подтвердите, что последующее "
                "применение настроек выполните в окно обслуживания: оно может "
                "кратко прервать VPN.",
                parent=self.window):
            return
        self.status.set("Повторно сверяем контейнер и включаем только разрешение AWG3…")
        self._run("settings_armed", lambda: self._controller().amnezia_settings_arm(access))

    def disarm_settings(self) -> None:
        access = self.settings_access
        if self.busy or access is None or access.settings_marker != "valid":
            return
        if not messagebox.askyesno(
                "Запретить изменение AWG3?",
                "Снять отдельное разрешение на изменение параметров AWG3? "
                "Контейнер, профили клиентов и текущее VPN-соединение сохранятся.",
                parent=self.window):
            return
        self.status.set("Снимаем отдельное разрешение AWG3…")
        self._run("settings_disarmed", lambda: self._controller().amnezia_settings_disarm(access))

    def enroll(self) -> None:
        preview = self.enrollment_preview
        if (self.busy or preview is None or preview.target != self.target.get() or
                self.state is not None and self.state.target_ready):
            return
        if not messagebox.askyesno("Принять контейнер Amnezia?", (
                f"Цель: {TARGET_LABELS[preview.target]}\n"
                f"Контейнер: {preview.container_id}\n"
                f"Образ: {preview.image_id}\n"
                f"Конфигурация SHA-256: {preview.config_sha256}\n"
                f"Таблица клиентов SHA-256: {preview.table_sha256}\n"
                f"Порт: {preview.listen_port}; подсеть: {preview.server_subnet}\n"
                f"Существующих клиентов: {preview.configured_clients}\n\n"
                "Закрепить этот контейнер для SovaGrid? Клиенты и VPN-настройки не меняются. "
                "Broker и доступ к управлению включаются отдельно."
        ), parent=self.window):
            return
        self.status.set("Повторно сверяем контейнер и закрепляем его. Не повторяйте действие при потере связи…")
        self._run("enrolled", lambda: self._controller().amnezia_enroll(preview))

    def install(self) -> None:
        state = self.state
        if self.busy or state is None or state.installed_current:
            return
        if not messagebox.askyesno("Установить Amnezia broker?",
                                   "Установить только файлы собственного broker и systemd units? "
                                   "Контейнер Amnezia останется без изменений, доступ ещё не включится.",
                                   parent=self.window):
            return
        self.status.set("Устанавливаем точные файлы broker…")
        self._run("state", lambda: self._controller().amnezia_install(state))

    def arm(self) -> None:
        state = self.state
        if self.busy or state is None or not state.can_arm or not state.container_id:
            return
        if not messagebox.askyesno("Включить доступ к Amnezia?",
                                   f"Цель: {TARGET_LABELS[state.target]}\n"
                                   f"Контейнер: {state.container_id}\n\n"
                                   "Включить управление клиентами этого контейнера? "
                                   "Выберите окно обслуживания: дальнейшие операции с клиентами могут "
                                   "повлиять на их VPN-соединения.",
                                   parent=self.window):
            return
        self.status.set("Включаем доступ только к подтверждённому контейнеру…")
        self._run("state", lambda: self._controller().amnezia_arm(state))

    def disarm(self) -> None:
        state = self.state
        if self.busy or state is None or state.marker != "valid":
            return
        if not messagebox.askyesno("Выключить доступ к Amnezia?",
                                   f"Цель: {TARGET_LABELS[state.target]}\n\n"
                                   "Отключить управление клиентами? Контейнер и VPN-подключения не удаляются.",
                                   parent=self.window):
            return
        self.status.set("Снимаем разрешение выбранной цели…")
        self._run("state", lambda: self._controller().amnezia_disarm(state))

    def _result(self, event: str, payload: object) -> None:
        if event in ("settings_access", "settings_armed", "settings_disarmed"):
            if (not isinstance(payload, AmneziaSettingsAccess) or
                    payload.options != self.options or
                    payload.manifest_sha256 != self.approved_manifest_sha256):
                self._invalidate()
                self.status.set("Сервер прислал неверное разрешение AWG3. Повторите проверку.")
                return
            self.settings_access = payload
            if event != "settings_access":
                self.settings_plan = None
            reason = SETTINGS_ACCESS_REASONS.get(payload.reason, "Проверка завершена.")
            self._show("\n".join((
                "ОТДЕЛЬНОЕ РАЗРЕШЕНИЕ НА ИЗМЕНЕНИЕ AWG3",
                f"Контейнер: {payload.container_id or 'не подтверждён'}",
                f"Клиентов: {payload.configured_clients if payload.configured_clients is not None else '—'}",
                f"Управление профилями: {payload.peer_marker}",
                f"Разрешение настроек: {payload.settings_marker}",
                f"Broker socket: {'активен' if payload.socket_active else 'неактивен'}",
                f"Работающие параметры AWG3: {'проверены' if payload.awg3_runtime_verified else 'не подтверждены'}",
                "Можно включить разрешение." if payload.can_arm else reason,
            )))
            self.status.set("Разрешение AWG3 включено. Изменения выполняются отдельно в Web."
                            if event == "settings_armed" else
                            "Разрешение AWG3 выключено; VPN не менялся."
                            if event == "settings_disarmed" else
                            "Разрешение AWG3 проверено без изменений сервера.")
            return
        if event == "settings_plan" and isinstance(payload, AmneziaSettingsPlan):
            preview = self.settings_preview
            if (preview is None or payload.target != "awg2" or
                    payload.container_id != preview.container_id or
                    payload.config_sha256 != preview.config_sha256 or
                    payload.generation != preview.generation or
                    payload.apply_supported != (payload.configured_clients == 0)):
                self._invalidate()
                self.status.set("Настройки AWG2 изменились. Прочитайте их заново.")
                return
            self.settings_plan = payload
            current = dict(payload.current_awg_parameters)
            proposed = dict(payload.proposed_awg_parameters)
            rows = [
                "ПЛАН AWG3 — только предпросмотр, настройки не применены.",
                f"Цель: {TARGET_LABELS[payload.target]}; поколение: {payload.generation}",
                f"Клиентов: {payload.configured_clients}",
                "Изменения:",
            ]
            rows.extend(f"  {name}: {current[name]} → {proposed[name]}"
                        for name in payload.changed_fields)
            rows.extend((
                f"SHA-256 текущей конфигурации: {payload.config_sha256}",
                f"SHA-256 предлагаемой конфигурации: {payload.proposed_config_sha256}",
                "Применение в Web поддерживается после отдельного разрешения AWG3."
                if payload.apply_supported else "Применение недоступно при существующих клиентах.",
            ))
            if payload.apply_blockers:
                rows.append("Причины блокировки:")
                rows.extend("  • " + PLAN_BLOCKER_LABELS.get(code, code) for code in payload.apply_blockers)
            self._show("\n".join(rows))
            self.status.set("План проверен без изменений контейнера. Применение доступно в Web после отдельного разрешения."
                            if payload.apply_supported else
                            "План проверен без изменений контейнера. Нужна миграция профилей клиентов.")
            return
        if event == "settings_preview" and isinstance(payload, AmneziaSettingsPreview):
            if self.state is None or payload.target != self.state.target or \
                    payload.container_id != self.state.container_id:
                self._invalidate()
                self.status.set("Контейнер изменился. Повторите проверку.")
                return
            self.settings_preview = payload
            self.settings_plan = None
            rows = [
                f"Цель: {TARGET_LABELS[payload.target]}",
                f"Интерфейс: {payload.interface}; протокол: {payload.protocol}",
                f"Адрес сервера: {payload.server_address}; подсеть: {payload.server_subnet}",
                f"Порт интерфейса: {payload.listen_port}/UDP (публикация наружу не проверена)",
                f"Клиенты: {payload.configured_clients} всего, "
                f"{payload.managed_clients} SovaGrid, {payload.external_clients} внешних",
                f"Поколение: {payload.generation}",
            ]
            if payload.target == "awg2":
                rows.append("Параметры AWG: " + (", ".join(
                    f"{name}={value}" for name, value in payload.awg_parameters) or "не заданы"))
                rows.append("Ключ защиты заголовка: " + (
                    "присутствует" if payload.header_protection_key_present else "не задан"))
                rows.append("Набор AWG 3.1: " + (
                    "полный" if payload.awg3_required_parameters_present else "неполный"))
                rows.append("Этот обзор не проверяет работающие параметры; план AWG3 сверяет их отдельно.")
                if payload.awg3_required_parameters_present:
                    rows.append("Для числовых параметров доступен проверяемый план AWG3.")
            rows.extend((
                "При существующих клиентах изменение настроек требует миграции их профилей. "
                "Смена порта требует отдельной сетевой миграции."
                if payload.configured_clients else
                "Числовые параметры можно изменить только после проверки плана и "
                "отдельного включения разрешения AWG3.",
                f"Образ: {payload.image_id}",
                f"SHA-256 конфигурации: {payload.config_sha256}",
                f"SHA-256 таблицы клиентов: {payload.table_sha256}",
            ))
            self._show("\n".join(rows))
            self.status.set("Настройки прочитаны без изменения контейнера и клиентов.")
            return
        if event == "enrollment_preview" and isinstance(payload, AmneziaEnrollmentPreview):
            self.enrollment_preview = payload
            self._show("\n".join((
                f"Цель: {TARGET_LABELS[payload.target]}",
                f"Контейнер: {payload.container_id}",
                f"Образ: {payload.image_id}",
                f"Протокол: {payload.protocol}; интерфейс: {payload.interface}",
                f"Порт: {payload.listen_port}; подсеть: {payload.server_subnet}",
                f"Клиентов: {payload.configured_clients}",
                f"Конфигурация SHA-256: {payload.config_sha256}",
                f"Таблица клиентов SHA-256: {payload.table_sha256}",
                "Проверьте данные и подтвердите принятие. Секреты не показаны.",
            )))
            self.status.set("Контейнер проверен без изменений. Можно принять его для SovaGrid.")
            return
        if event not in ("state", "enrolled") or not isinstance(payload, AmneziaState):
            self._invalidate()
            self.status.set("Сервер прислал неверное состояние Amnezia.")
            return
        self.enrollment_preview = None
        self.settings_preview = None
        self.settings_access = None
        self.state = payload
        self._show("\n".join((
            f"Цель: {TARGET_LABELS[payload.target]}",
            f"Контейнер: {payload.container_id if payload.container_id else 'не закреплён или не готов'}",
            f"Клиентов в контейнере: {payload.configured_clients if payload.target_ready else '—'}",
            f"Файлы broker: {'установлены' if payload.installed_current else 'не установлены'}",
            f"Разрешение цели: {payload.marker}",
            f"Разрешение другой цели: {payload.other_marker}",
            f"Socket broker: {'активен' if payload.socket_active else 'неактивен'}",
            "Цель готова к включению." if payload.can_arm else
            "Для включения нужна закреплённая и проверенная цель, точные файлы broker и безопасное состояние socket.",
        )))
        self.status.set("Контейнер принят. Broker и доступ включаются отдельно."
                        if event == "enrolled" else "Состояние проверено.")
