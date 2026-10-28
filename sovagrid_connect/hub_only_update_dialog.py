# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Graphical review and one-candidate updater for a promoted local Hub."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .hub_only_update import (HubOnlyPrepared, HubOnlyPreview, HubOnlyUpdateController)
from .installer import InstallError, nearby_server_bundle
from .server_timer import ServerTimerStatus


class HubOnlyUpdateDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_sha256 = approved_sha256
        self.controller: HubOnlyUpdateController | None = None
        self.preview_result: HubOnlyPreview | None = None
        self.prepared: HubOnlyPrepared | None = None
        self.busy = False
        self.closed = False
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        nearby = nearby_server_bundle()
        suggested = str(nearby[0]) if nearby and nearby[1] == approved_sha256 else ''
        self.source = tk.StringVar(value=suggested)
        self.status = tk.StringVar(value=(
            'Выберите пакет и проверьте собственный Hub без изменений.' if approved_sha256 else
            'Мастер ждёт проверенный серверный выпуск для обновления локального Hub.'
        ))
        self.window = tk.Toplevel(root)
        self.window.title('Обновить собственный Hub · SovaGrid Connect')
        self.window.transient(root)
        self.window.geometry('780x560')
        self.window.minsize(610, 440)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky='nsew')
        body.columnconfigure(0, weight=1)
        body.rowconfigure(5, weight=1)
        ttk.Label(body, text='Обновление собственного локального Hub',
                  font=('TkDefaultFont', 14, 'bold')).grid(row=0, column=0, sticky='w')
        route = f'{options.user}@{options.host}:{options.port}'
        if options.jump_host:
            route += f' через {options.jump_user}@{options.jump_host}:{options.jump_port}'
        self.route_label = ttk.Label(body, text='SSH-маршрут: ' + route, wraplength=730)
        self.route_label.grid(row=1, column=0, sticky='w', pady=(8, 0))
        ttk.Label(body, text=(
            'Проверка не изменяет сервер. Подготовка сохранит один пакет под точным SHA-256, '
            'сверит архив, каждый файл и версии Git на сервере, затем выполнит read-only preflight. '
            'Применение сохраняет исходники, локальный Hub и Agent с откатом при ошибке. '
            'Внешний Agent и его обратный туннель остаются под прежним управлением. '
            'Нужен root либо действующее sudo без запроса пароля.'
        ), wraplength=730).grid(row=2, column=0, sticky='w', pady=(10, 12))
        chooser = ttk.Frame(body)
        chooser.grid(row=3, column=0, sticky='ew')
        chooser.columnconfigure(0, weight=1)
        ttk.Entry(chooser, textvariable=self.source, state='readonly').grid(row=0, column=0, sticky='ew')
        ttk.Button(chooser, text='Выбрать пакет…', command=self._choose).grid(row=0, column=1, padx=(8, 0))
        self.source.trace_add('write', lambda *_args: self._invalidate())
        self.details = tk.Text(body, height=10, wrap='word', state='disabled')
        theme.style_text(self.details)
        self.details.grid(row=5, column=0, sticky='nsew', pady=(12, 8))
        ttk.Label(body, textvariable=self.status, wraplength=730).grid(row=6, column=0, sticky='w', pady=(2, 8))
        first = ttk.Frame(body)
        first.grid(row=7, column=0, sticky='w')
        self.check_button = ttk.Button(first, text='Проверить без изменений', command=self.check,
                                       state='normal' if approved_sha256 else 'disabled')
        self.check_button.pack(side='left')
        self.stage_button = ttk.Button(first, text='Подготовить и проверить', command=self.stage,
                                       state='disabled')
        self.stage_button.pack(side='left', padx=(8, 0))
        self.apply_button = ttk.Button(first, text='Применить обновление', command=self.apply,
                                       state='disabled')
        self.apply_button.pack(side='left', padx=(8, 0))
        second = ttk.Frame(body)
        second.grid(row=8, column=0, sticky='w', pady=(10, 0))
        self.arm_button = ttk.Button(second, text='Разрешить один пакет', command=self.arm, state='disabled')
        self.arm_button.pack(side='left')
        self.status_button = ttk.Button(second, text='Состояние таймера', command=self.timer_status)
        self.status_button.pack(side='left', padx=(8, 0))
        self.disarm_button = ttk.Button(second, text='Снять разрешение', command=self.disarm)
        self.disarm_button.pack(side='left', padx=(8, 0))
        ttk.Button(second, text='Закрыть', command=self.close).pack(side='left', padx=(8, 0))
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self.window.after(100, self._pump)

    def _show(self, text: str) -> None:
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        self.details.insert('1.0', text)
        self.details.configure(state='disabled')

    def _invalidate(self) -> None:
        self.preview_result = self.prepared = None
        self._set_busy(self.busy)
        self._show('')

    def _choose(self) -> None:
        if self.busy:
            return
        selected = filedialog.askopenfilename(parent=self.window, title='Проверенный пакет SovaGrid',
                                               filetypes=[('Архив SovaGrid', '*.tar.gz'), ('Все файлы', '*')])
        if selected:
            self.source.set(selected)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.check_button.configure(state='disabled' if busy or not self.approved_sha256 else 'normal')
        self.stage_button.configure(state='disabled' if busy or self.preview_result is None else 'normal')
        self.apply_button.configure(state='disabled' if busy or self.prepared is None else 'normal')
        self.arm_button.configure(state='disabled' if busy or self.prepared is None or
                                  not self.prepared.preview.installed.native_updater else 'normal')
        for button in (self.status_button, self.disarm_button):
            button.configure(state='disabled' if busy else 'normal')

    def _controller(self) -> HubOnlyUpdateController:
        if self.controller is None:
            self.controller = HubOnlyUpdateController(
                self.options, approved_archive_sha256=self.approved_sha256,
                progress=lambda text: self.events.put(('progress', text)))
        return self.controller

    def _start(self, operation: str, action) -> None:
        if self.busy:
            return
        self._set_busy(True)
        self.status.set(operation)

        def worker() -> None:
            try:
                self.events.put(('result', (operation, action())))
            except Exception as exc:
                self.events.put(('error', exc))

        threading.Thread(target=worker, daemon=True).start()

    def check(self) -> None:
        if not self.approved_sha256 or not self.source.get():
            return
        self._invalidate()
        selected = Path(self.source.get())
        self._start('Проверка пакета и локального Hub без изменений…',
                    lambda: self._controller().preview(selected))

    def stage(self) -> None:
        preview = self.preview_result
        if self.busy or preview is None:
            return
        selected = Path(self.source.get())
        self._start('Подготовка пакета и read-only preflight на сервере…',
                    lambda: self._controller().stage(selected, preview))

    def apply(self) -> None:
        prepared = self.prepared
        if self.busy or prepared is None:
            return
        preview = prepared.preview
        if not messagebox.askyesno(
            'Применить обновление локального Hub',
            f'SSH: {preview.options.user}@{preview.options.host}:{preview.options.port}\n'
            f'Архив SHA-256: {preview.archive_sha256}\n'
            f'Манифест SHA-256: {preview.manifest_sha256}\n'
            f'Текущая версия: {preview.installed.manifest_sha256}\n\n'
            'Работа локального Hub кратко прервётся. Внешний Agent и его туннель будут сохранены. '
            'Применить только этот проверенный пакет?', parent=self.window,
        ):
            return
        self._start('Применение пакета с резервной копией и проверкой…',
                    lambda: self._controller().apply(prepared))

    def arm(self) -> None:
        prepared = self.prepared
        if self.busy or prepared is None:
            return
        preview = prepared.preview
        if not messagebox.askyesno(
            'Разрешить автообновление локального Hub',
            f'SSH: {preview.options.user}@{preview.options.host}:{preview.options.port}\n'
            f'Единственный пакет SHA-256: {preview.archive_sha256}\n'
            f'Текущая версия: {preview.installed.manifest_sha256}\n\n'
            'Разрешить серверу применить этот пакет при простое в течение 14 дней? '
            'Connect можно закрыть; другие версии сервер не скачает.', parent=self.window,
        ):
            return
        self._start('Сервер проверяет и разрешает один пакет…',
                    lambda: self._controller().arm(prepared))

    def timer_status(self) -> None:
        self._start('Чтение состояния таймера локального Hub…', self._controller().timer_status)

    def disarm(self) -> None:
        if self.busy or not messagebox.askyesno(
            'Отключить автообновление локального Hub',
            f'Снять разрешение на подготовленный пакет на {self.options.host}? '
            'Уже начатое обновление это действие не прерывает.', parent=self.window,
        ):
            return
        self._start('Отключение разрешения на сервере…', self._controller().disarm)

    def _pump(self) -> None:
        if self.closed:
            return
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == 'progress':
                self.status.set(str(payload))
            elif event == 'result':
                operation, result = payload
                if isinstance(result, HubOnlyPreview):
                    self.preview_result = result
                    self._show(
                        f'SSH: {result.options.user}@{result.options.host}:{result.options.port}\n'
                        f'Архив SHA-256: {result.archive_sha256}\n'
                        f'Манифест пакета: {result.manifest_sha256}\n'
                        f'Текущий манифест: {result.installed.manifest_sha256}\n'
                        f'Локальный Agent: {result.installed.promotion.local_server_id}\n'
                        f'Файлов в пакете: {result.bundle.files}\n'
                        'Внешний Agent и туннель подтверждены.'
                    )
                    self.status.set('Проверка завершена. Сверьте SSH-маршрут и SHA-256 перед подготовкой.')
                elif isinstance(result, HubOnlyPrepared):
                    self.prepared = result
                    self.status.set('Архив, исходники, версии Git и совместимость проверены на сервере.')
                elif operation.startswith('Применение'):
                    self.preview_result = self.prepared = None
                    self.status.set('Локальный Hub обновлён; внешний Agent и отдельный локальный Agent сохранены.')
                elif isinstance(result, ServerTimerStatus):
                    expiry = (datetime.fromtimestamp(result.expires_at, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                              if result.expires_at else 'нет')
                    self.status.set('Разрешённый пакет: ' + (result.archive_sha256 or 'нет') +
                                    '. Действует до: ' + expiry + '. Последний результат: ' +
                                    (result.last_state or 'нет') + '.')
                elif result is None and operation.startswith('Чтение'):
                    self.status.set('Таймер обновления локального Hub ещё не установлен.')
                elif operation.startswith('Отключение'):
                    self.status.set('Разрешение на автообновление снято на сервере.')
                else:
                    self.status.set('Разрешён только выбранный пакет; сервер проверит простой перед обновлением.')
                self._set_busy(False)
            elif event == 'error':
                self._set_busy(False)
                self.prepared = None
                self.apply_button.configure(state='disabled')
                self.arm_button.configure(state='disabled')
                message = str(payload) if isinstance(payload, InstallError) else (
                    'Действие не завершено. Повторно проверьте сервер; вывод SSH и секреты скрыты.'
                )
                self.status.set(message)
                messagebox.showerror('Локальный Hub', message, parent=self.window)
        self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo('Локальный Hub', 'Дождитесь результата текущего действия; '
                                'повторная проверка покажет состояние.', parent=self.window)
            return
        self.closed = True
        self.window.destroy()
        self.on_closed()
