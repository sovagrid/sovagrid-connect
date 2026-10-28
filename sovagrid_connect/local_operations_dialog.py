# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Graphical opt-in for PTY and files on the separate local Hub Agent."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from .installer import InstallError
from .local_operations import LocalOperationsController, LocalOperationsState


class LocalOperationsDialog:
    def __init__(self, root, theme, options, on_closed, *, approved_manifest_sha256: str | None):
        self.root, self.theme, self.options, self.on_closed = root, theme, options, on_closed
        self.approved_manifest_sha256 = approved_manifest_sha256
        self.controller: LocalOperationsController | None = None
        self.state: LocalOperationsState | None = None
        self.events: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.busy = self.closed = False
        self.status = tk.StringVar(value=(
            'Проверьте состояние своего локального Agent без изменений сервера.'
            if approved_manifest_sha256 else
            'Функция ждёт проверенный серверный выпуск с безопасным управлением локальным Agent.'
        ))
        self.window = tk.Toplevel(root)
        self.window.title('Локальный терминал и файлы · SovaGrid Connect')
        self.window.transient(root)
        self.window.geometry('760x510')
        self.window.minsize(620, 430)
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        theme.style_window(self.window)
        body = ttk.Frame(self.window, padding=16)
        body.grid(sticky='nsew')
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1)
        ttk.Label(body, text='Терминал и файлы собственного локального Hub',
                  font=('TkDefaultFont', 14, 'bold')).grid(row=0, column=0, sticky='w')
        route = f'{options.user}@{options.host}:{options.port}'
        if options.jump_host:
            route += f' через {options.jump_user}@{options.jump_host}:{options.jump_port}'
        self.route_label = ttk.Label(body, text='SSH-маршрут: ' + route, wraplength=710)
        self.route_label.grid(row=1, column=0, sticky='w', pady=(8, 0))
        ttk.Label(body, text=(
            'Функции относятся только ко второму Agent вашего локального Hub. Нужны уже разрешённые '
            'команды для него и SSH-доступ root либо действующее sudo без запроса пароля. '
            'Терминал использует отдельного пользователя и локальный broker; файлы ограничены '
            'его рабочей папкой. Внешний Agent и его обратный туннель сохраняются. '
            'Каждое включение и выключение подтверждается отдельно.'
        ), wraplength=710).grid(row=2, column=0, sticky='w', pady=(10, 10))
        ttk.Label(body, text=(
            'Проверка только читает состояние. Изменение перезапустит второй Agent и может прервать '
            'открытый терминал или передачу файла. Если команды второго Agent пока выключены, '
            'мастер сообщит об обязательном разрешении и не будет менять сервер. '
            'После сбоя сначала выполните восстановление.'
        ), wraplength=710).grid(row=3, column=0, sticky='w')
        self.details = tk.Text(body, height=10, wrap='word', state='disabled')
        theme.style_text(self.details)
        self.details.grid(row=4, column=0, sticky='nsew', pady=(12, 8))
        ttk.Label(body, textvariable=self.status, wraplength=710).grid(row=5, column=0, sticky='w')
        actions = ttk.Frame(body)
        actions.grid(row=6, column=0, sticky='w', pady=(12, 0))
        self.check_button = ttk.Button(actions, text='Проверить без изменений', command=self.check,
                                       state='normal' if approved_manifest_sha256 else 'disabled')
        self.check_button.pack(side='left')
        self.terminal_button = ttk.Button(actions, text='Включить терминал',
                                          command=lambda: self.change('terminal'), state='disabled')
        self.terminal_button.pack(side='left', padx=(8, 0))
        self.files_button = ttk.Button(actions, text='Включить файлы',
                                       command=lambda: self.change('files'), state='disabled')
        self.files_button.pack(side='left', padx=(8, 0))
        self.recover_button = ttk.Button(actions, text='Восстановить', command=self.recover,
                                         state='disabled')
        self.recover_button.pack(side='left', padx=(8, 0))
        ttk.Button(actions, text='Закрыть', command=self.close).pack(side='left', padx=(8, 0))
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self._pump_after = self.window.after(100, self._pump)

    def _controller(self) -> LocalOperationsController:
        if self.controller is None:
            self.controller = LocalOperationsController(
                self.options, approved_manifest_sha256=self.approved_manifest_sha256,
                progress=lambda value: self.events.put(('progress', value)),
            )
        return self.controller

    def _show(self, value: str) -> None:
        self.details.configure(state='normal')
        self.details.delete('1.0', 'end')
        self.details.insert('1.0', value)
        self.details.configure(state='disabled')

    def _controls(self) -> None:
        state = self.state
        ready = state is not None and state.phase == 'ready'
        self.check_button.configure(state='disabled' if self.busy or not self.approved_manifest_sha256 else 'normal')
        self.terminal_button.configure(state='normal' if ready and not self.busy else 'disabled',
                                       text=('Выключить терминал' if state and state.terminal else 'Включить терминал'))
        self.files_button.configure(state='normal' if ready and not self.busy else 'disabled',
                                    text=('Выключить файлы' if state and state.files else 'Включить файлы'))
        self.recover_button.configure(state=('normal' if state is not None and
                                             state.phase == 'recovery_required' and not self.busy else 'disabled'))

    def _render(self, state: LocalOperationsState) -> None:
        self.state = state
        lines = [
            f'SSH: {state.options.user}@{state.options.host}:{state.options.port}',
            f'Проверенный манифест: {state.manifest_sha256}',
            f'Локальный Agent: {state.local_server_id}',
            'Терминал: ' + ('включён' if state.terminal else 'выключен'),
            'Файлы: ' + ('включены' if state.files else 'выключены'),
        ]
        if state.phase == 'recovery_required':
            lines.extend((
                '', 'Незавершённая операция: изменения функций заблокированы.',
                'Запрашивалось: терминал ' + ('включить' if state.requested_terminal else 'выключить') +
                ', файлы ' + ('включить' if state.requested_files else 'выключить') + '.',
                'Восстановление вернёт прежние настройки после отдельного подтверждения.',
            ))
            self.status.set('Требуется восстановление прерванной операции.')
        else:
            lines.append('Ревизия настроек: ' + str(state.state_revision))
            lines.append('Внешний Agent и его туннель подтверждены.')
            self.status.set('Проверка завершена. Каждая функция меняется отдельным действием.')
        self._show('\n'.join(lines))
        self._controls()

    def _start(self, label: str, action) -> None:
        if self.busy:
            return
        self.busy = True
        self._controls()
        self.status.set(label)

        def worker() -> None:
            try:
                self.events.put(('result', action()))
            except Exception as exc:
                self.events.put(('error', exc))

        threading.Thread(target=worker, daemon=True).start()

    def check(self) -> None:
        if self.busy or self.approved_manifest_sha256 is None:
            return
        self.state = None
        self._controls()
        self._start('Проверка локального Agent и внешнего туннеля без изменений…',
                    self._controller().preview)

    def change(self, feature: str) -> None:
        state = self.state
        if self.busy or state is None or state.phase != 'ready' or feature not in ('terminal', 'files'):
            return
        enabled = not getattr(state, feature)
        label = 'терминал' if feature == 'terminal' else 'файлы'
        action = 'Включить' if enabled else 'Выключить'
        if not messagebox.askyesno(
            'Подтвердить изменение локального Agent',
            f'{action} {label} на {state.options.user}@{state.options.host}:{state.options.port}?\n'
            f'Манифест: {state.manifest_sha256}\n'
            f'Локальный Agent: {state.local_server_id}\n\n'
            f'Ревизия настроек: {state.state_revision}\n'
            'Второй Agent будет перезапущен. Внешний Agent и обратный туннель сохраняются.',
            parent=self.window,
        ):
            return
        self._start(f'{action} {label}: сервер проверяет состояние и сохраняет результат…',
                    lambda: self._controller().change(feature, enabled, state))

    def recover(self) -> None:
        state = self.state
        if self.busy or state is None or state.phase != 'recovery_required':
            return
        if not messagebox.askyesno(
            'Восстановить локальный Agent',
            f'Вернуть прежние настройки на {state.options.user}@{state.options.host}:{state.options.port}?\n'
            f'Манифест: {state.manifest_sha256}\n'
            f'Локальный Agent: {state.local_server_id}\n\n'
            'Сервер проверит исходники и внешний Agent перед восстановлением. '
            'Прерванное действие повторно запускаться не будет.', parent=self.window,
        ):
            return
        self._start('Восстановление прежних настроек локального Agent…',
                    lambda: self._controller().recover(state))

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
                self.busy = False
                if isinstance(payload, LocalOperationsState):
                    self._render(payload)
                else:
                    self.state = None
                    self._controls()
                    self.status.set('Сервер прислал неверный результат; повторите проверку.')
            elif event == 'error':
                self.busy = False
                self.state = None
                self._controls()
                message = str(payload) if isinstance(payload, InstallError) else (
                    'Действие не подтверждено. Повторите проверку сервера; вывод SSH скрыт.'
                )
                self.status.set(message)
                messagebox.showerror('Локальный Agent', message, parent=self.window)
        self._pump_after = self.window.after(100, self._pump)

    def close(self) -> None:
        if self.busy:
            messagebox.showinfo('Локальный Agent', 'Дождитесь результата действия или повторной проверки.',
                                parent=self.window)
            return
        self.closed = True
        self.window.after_cancel(self._pump_after)
        self.window.destroy()
        self.on_closed()
