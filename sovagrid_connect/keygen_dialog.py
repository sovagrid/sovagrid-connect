# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Nonblocking desktop flow for an explicitly saved local SSH key pair."""

from __future__ import annotations

from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from .keygen import GeneratedKey, KeyGenerationError, KeyGenerator, default_key_path


class KeyGenerationDialog:
    def __init__(self, root, theme, target: str, on_created, on_closed):
        self.root, self.target = root, target
        self.on_created, self.on_closed = on_created, on_closed
        self.busy = False
        self.close_requested = False
        self.closed = False
        self.generator = None
        self.result: GeneratedKey | None = None
        self.events = queue.SimpleQueue()
        self.window = tk.Toplevel(root)
        self.window.title("Создать SSH-ключ · SovaGrid Connect")
        self.window.transient(root)
        self.window.resizable(True, False)
        theme.style_window(self.window)
        self.path = tk.StringVar(value=str(default_key_path(target)))
        self.encrypted = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="Выберите место сохранения и нажмите «Создать ключ».")
        self.fingerprint = tk.StringVar(value="")
        frame = ttk.Frame(self.window, padding=18)
        frame.grid(sticky="nsew")
        frame.columnconfigure(0, weight=1)
        self.window.columnconfigure(0, weight=1)
        title = "Ключ промежуточного хоста" if target == "jump_identity" else "Ключ конечного сервера"
        ttk.Label(frame, text=title, font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(frame, text="Будет создана новая пара Ed25519. Существующие ключи не перезаписываются.",
                  wraplength=530).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 12))
        ttk.Label(frame, text="Приватный ключ — сохранить на этом компьютере").grid(
            row=2, column=0, columnspan=2, sticky="w")
        self.path_entry = ttk.Entry(frame, textvariable=self.path, width=57)
        self.path_entry.grid(row=3, column=0, sticky="ew", pady=(5, 12))
        self.choose_button = ttk.Button(frame, text="Сохранить как…", command=self.choose_path)
        self.choose_button.grid(row=3, column=1, padx=(8, 0), pady=(5, 12))
        self.protect_check = ttk.Checkbutton(frame, text="Защитить ключ парольной фразой", variable=self.encrypted)
        self.protect_check.grid(row=4, column=0, columnspan=2, sticky="w")
        ttk.Label(frame, text="Если защита включена, OpenSSH попросит фразу в отдельных скрытых окнах. "
                  "Приватный ключ без фразы защищён правами вашей учётной записи; его нельзя передавать другим.",
                  wraplength=530).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 12))
        ttk.Label(frame, textvariable=self.status, wraplength=530).grid(
            row=6, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(frame, textvariable=self.fingerprint, wraplength=530, font=("TkFixedFont", 10)).grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(frame, text="Открытый ключ — можно передать администратору сервера").grid(
            row=8, column=0, columnspan=2, sticky="w")
        self.public_text = tk.Text(frame, height=4, width=65, wrap="char", state="disabled")
        self.public_text.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(5, 8))
        theme.style_text(self.public_text)
        self.copy_button = ttk.Button(frame, text="Копировать открытый ключ", command=self.copy_public, state="disabled")
        self.copy_button.grid(row=10, column=0, sticky="w")
        ttk.Label(frame, text="Чтобы использовать новый ключ, добавьте открытый ключ в доступы SSH на сервере "
                  "через панель провайдера или администратора. Это окно не меняет сервер.", wraplength=530).grid(
            row=11, column=0, columnspan=2, sticky="w", pady=(10, 12))
        buttons = ttk.Frame(frame)
        buttons.grid(row=12, column=0, columnspan=2, sticky="e")
        self.create_button = ttk.Button(buttons, text="Создать ключ", command=self.begin)
        self.create_button.pack(side="left", padx=(0, 8))
        self.close_button = ttk.Button(buttons, text="Закрыть", command=self.close)
        self.close_button.pack(side="left")
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.window.after(100, self.pump)

    def choose_path(self) -> None:
        if self.busy or self.result:
            return
        suggested = Path(self.path.get()).expanduser()
        selected = filedialog.asksaveasfilename(parent=self.window, title="Сохранить новый приватный SSH-ключ",
            initialdir=str(suggested.parent if suggested.parent.is_dir() else Path.home()),
            initialfile=suggested.name, confirmoverwrite=False)
        if selected:
            self.path.set(selected)

    def begin(self) -> None:
        if self.busy or self.result:
            return
        value = self.path.get().strip()
        if not value:
            self.status.set("Выберите место сохранения приватного ключа.")
            return
        destination, protected = Path(value).expanduser(), bool(self.encrypted.get())
        self.generator = KeyGenerator()
        generator = self.generator
        self.busy = True
        self.close_requested = False
        for control in (self.path_entry, self.choose_button, self.protect_check, self.create_button):
            control.configure(state="disabled")
        self.close_button.configure(text="Отменить")
        self.status.set("Создаём ключ. Введите парольную фразу в окнах OpenSSH…" if protected else "Создаём ключ…")

        def worker() -> None:
            try:
                result = generator.generate(destination, encrypted=protected)
                self.events.put((generator, result))
            except Exception as error:
                # Unexpected errors may carry implementation details. Only
                # the deliberately safe exception text reaches the interface.
                message = str(error) if isinstance(error, KeyGenerationError) else "Не удалось создать SSH-ключ. Проверьте место сохранения и OpenSSH."
                self.events.put((generator, message))

        threading.Thread(target=worker, daemon=True, name="sovagrid-key-generator").start()

    def copy_public(self) -> None:
        if not self.result or self.busy:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result.public_key)
        self.status.set("Открытый ключ скопирован. Приватный ключ остаётся в выбранном файле.")

    def close(self) -> None:
        if self.closed:
            return
        if self.busy:
            self.close_requested = True
            self.generator.cancel()
            self.status.set("Отменяем создание ключа…")
            self.close_button.configure(state="disabled")
            return
        self.closed = True
        self.window.destroy()
        self.on_closed()

    def pump(self) -> None:
        if self.closed:
            return
        while not self.events.empty():
            generator, result = self.events.get()
            if generator is not self.generator:
                continue
            self.busy = False
            self.generator = None
            self.close_button.configure(state="normal", text="Закрыть")
            if isinstance(result, GeneratedKey):
                self.result = result
                self.on_created(self.target, result)
                self.fingerprint.set(result.fingerprint)
                self.status.set("Ключ успел сохраниться до отмены. Он выбран для подключения; открытый ключ можно скопировать ниже."
                                if self.close_requested else
                                "Ключ сохранён и выбран для подключения. Открытый ключ находится рядом в .pub.")
                self.public_text.configure(state="normal")
                self.public_text.delete("1.0", "end")
                self.public_text.insert("1.0", result.public_key)
                self.public_text.configure(state="disabled")
                self.copy_button.configure(state="normal")
                # A completed export cannot honestly be presented as a
                # cancelled operation. Keep its public key/path visible.
                self.close_requested = False
            else:
                self.status.set(result)
                for control in (self.path_entry, self.choose_button, self.protect_check, self.create_button):
                    control.configure(state="normal")
            if self.close_requested:
                self.close()
                return
        self.window.after(100, self.pump)
