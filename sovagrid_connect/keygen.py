# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Generate a staged OpenSSH Ed25519 pair and publish it without overwriting.

Passphrases travel directly from the existing Askpass helper to OpenSSH.
They are never arguments, environment values, Python parameters, or logs.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass

from .askpass import helper_path
from .core import TunnelError


MAX_KEY_BYTES = 64 * 1024
COMMENT = "sovagrid-connect"


class KeyGenerationError(TunnelError):
    """A secret-free, user-readable failure."""


@dataclass(frozen=True)
class GeneratedKey:
    private_path: Path
    public_path: Path
    public_key: str
    fingerprint: str
    encrypted: bool


def default_key_path(target: str = "identity") -> Path:
    name = "id_sovagrid_jump_ed25519" if target == "jump_identity" else "id_sovagrid_ed25519"
    return Path.home() / ".ssh" / name


def _windows_tool(name: str) -> str:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / name
    if not path.is_file():
        raise KeyGenerationError("Не найдены средства Windows для защиты файла ключа.")
    return str(path)


def _protect_windows_directory(path: Path) -> str:
    """Restrict the fresh staging directory before private material is created."""
    options = {"stdin": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
               "timeout": 10, "creationflags": subprocess.CREATE_NO_WINDOW}
    try:
        identity = subprocess.run([_windows_tool("whoami.exe"), "/user", "/fo", "csv", "/nh"],
                                  stdout=subprocess.PIPE, **options)
        rows = list(csv.reader(io.StringIO(identity.stdout.decode("utf-8", errors="replace"))))
        if identity.returncode or len(identity.stdout) > 4096 or len(rows) != 1 or len(rows[0]) != 2:
            raise ValueError()
        sid = rows[0][1]
        if not re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", sid):
            raise ValueError()
        # Reset while the new directory is empty, then remove inherited
        # entries. This also eliminates unexpected explicit default ACEs.
        reset = subprocess.run([_windows_tool("icacls.exe"), str(path), "/reset"],
                               stdout=subprocess.DEVNULL, **options)
        if reset.returncode:
            raise ValueError()
        result = subprocess.run([_windows_tool("icacls.exe"), str(path), "/inheritance:r",
                                 "/grant:r", "*" + sid + ":(OI)(CI)F"],
                                stdout=subprocess.DEVNULL, **options)
        if result.returncode:
            raise ValueError()
        return sid
    except (OSError, subprocess.SubprocessError, ValueError):
        raise KeyGenerationError("Не удалось ограничить доступ к ключу вашей учётной записью Windows.") from None


def _protect_windows_private_file(path: Path, sid: str) -> None:
    # OpenSSH implementations may adjust a generated file's ACL. Reapply
    # the current-user-only DACL before linking it outside the private stage.
    try:
        for options in (("/reset",), ("/inheritance:r", "/grant:r", "*" + sid + ":F")):
            result = subprocess.run([_windows_tool("icacls.exe"), str(path), *options],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:
                raise ValueError()
    except (OSError, subprocess.SubprocessError, ValueError):
        raise KeyGenerationError("Не удалось защитить приватный ключ правами Windows. Ключ не сохранён.") from None


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.offset = data, 0

    def uint32(self) -> int:
        return struct.unpack(">I", self.bytes(4))[0]

    def bytes(self, length: int) -> bytes:
        if length < 0 or length > len(self.data) - self.offset:
            raise ValueError()
        result = self.data[self.offset:self.offset + length]
        self.offset += length
        return result

    def string(self, maximum: int) -> bytes:
        size = self.uint32()
        if size > maximum:
            raise ValueError()
        return self.bytes(size)


def _inspect_pair(private: Path, public: Path, encrypted: bool) -> tuple[str, str]:
    """Check type, public binding, and requested encryption before publication."""
    for path in (private, public):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_KEY_BYTES:
            raise KeyGenerationError("OpenSSH не создал корректную пару ключей.")
    try:
        text = public.read_text(encoding="ascii").strip()
        parts = text.split()
        if len(parts) != 3 or parts[0] != "ssh-ed25519" or parts[2] != COMMENT:
            raise ValueError()
        blob = base64.b64decode(parts[1], validate=True)
        public_reader = _Reader(blob)
        if (public_reader.string(64) != b"ssh-ed25519" or len(public_reader.string(32)) != 32 or
                public_reader.offset != len(blob)):
            raise ValueError()
        pem = private.read_bytes().splitlines()
        if (len(pem) < 3 or pem[0] != b"-----BEGIN OPENSSH PRIVATE KEY-----" or
                pem[-1] != b"-----END OPENSSH PRIVATE KEY-----"):
            raise ValueError()
        data = base64.b64decode(b"".join(pem[1:-1]), validate=True)
        reader = _Reader(data)
        if reader.bytes(15) != b"openssh-key-v1\0":
            raise ValueError()
        cipher, kdf, options = reader.string(64), reader.string(64), reader.string(4096)
        if reader.uint32() != 1 or reader.string(256) != blob or not reader.string(MAX_KEY_BYTES):
            raise ValueError()
        if reader.offset != len(data):
            raise ValueError()
        protected = cipher != b"none" and kdf == b"bcrypt" and bool(options)
        if encrypted and not protected:
            # OpenSSH can exit successfully with an unencrypted key even
            # when an Askpass window was cancelled. Never silently publish it.
            raise KeyGenerationError("Парольная фраза не задана или ввод отменён. Ключ не сохранён.")
        if not encrypted and (cipher, kdf, options) != (b"none", b"none", b""):
            raise ValueError()
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
        return text, "SHA256:" + digest
    except (OSError, UnicodeError, ValueError, struct.error):
        raise KeyGenerationError("OpenSSH не создал корректную пару ключей.") from None


def _unlink_same(path: Path, source: Path) -> None:
    try:
        current, original = path.lstat(), source.lstat()
        if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
            path.unlink()
    except FileNotFoundError:
        pass


class KeyGenerator:
    def __init__(self, *, ssh_keygen: str = "ssh-keygen", popen=subprocess.Popen,
                 askpass=helper_path):
        self.ssh_keygen = ssh_keygen
        self._popen, self._askpass = popen, askpass
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        # The worker owns process termination; the GUI thread never waits.
        self._cancelled.set()

    @staticmethod
    def _stop(process) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                subprocess.run([_windows_tool("taskkill.exe"), "/PID", str(process.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            process.kill()
            process.wait(timeout=2)

    def _run(self, argv: list[str], env: dict[str, str], timeout: float) -> None:
        options = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
                   "stderr": subprocess.DEVNULL, "env": env}
        if os.name == "nt":
            options["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        process = self._popen(argv, **options)
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                if self._cancelled.is_set():
                    raise KeyGenerationError("Создание ключа отменено.")
                if time.monotonic() >= deadline:
                    raise KeyGenerationError("Время создания ключа истекло. Повторите попытку.")
                self._cancelled.wait(0.05)
            if process.returncode:
                raise KeyGenerationError("OpenSSH не создал ключ. Ввод мог быть отменён или парольные фразы не совпали.")
        finally:
            self._stop(process)

    def generate(self, destination: Path, *, encrypted: bool = True, timeout: float = 180) -> GeneratedKey:
        if (not isinstance(encrypted, bool) or isinstance(timeout, bool) or
                not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 3600):
            raise ValueError("Invalid key generation options")
        if self._cancelled.is_set():
            raise KeyGenerationError("Создание ключа отменено.")
        executable = shutil.which(self.ssh_keygen)
        if executable is None:
            raise KeyGenerationError("Не найден ssh-keygen. Установите компонент OpenSSH Client и повторите.")
        destination = Path(destination).expanduser().absolute()
        if any(not character.isprintable() for character in str(destination)):
            raise KeyGenerationError("Путь ключа не должен содержать переносы строки или управляющие символы.")
        if destination.name in ("", ".", "..") or destination.name.endswith(".pub"):
            raise KeyGenerationError("Выберите имя приватного ключа без окончания .pub.")
        public_destination = destination.with_name(destination.name + ".pub")
        if any(os.path.lexists(path) for path in (destination, public_destination)):
            raise KeyGenerationError("Такой ключ или его .pub уже существует. Выберите другое имя; файлы не изменены.")
        parent = destination.parent
        # Only the customary .ssh directory is created automatically. Other
        # parents must be explicitly chosen as existing directories.
        if not parent.exists() and parent == Path.home() / ".ssh":
            parent.mkdir(mode=0o700, exist_ok=True)
        if not parent.is_dir():
            raise KeyGenerationError("Выберите существующий каталог для ключа.")
        published = []
        try:
            with tempfile.TemporaryDirectory(prefix=".sovagrid-keygen-", dir=parent) as directory:
                stage = Path(directory)
                stage.chmod(0o700)
                windows_sid = _protect_windows_directory(stage) if os.name == "nt" else None
                private, public = stage / "id_ed25519", stage / "id_ed25519.pub"
                env = os.environ.copy()
                env["LC_ALL"] = "C"
                argv = [executable, "-q", "-t", "ed25519", "-a", "64", "-C", COMMENT, "-f", str(private)]
                if encrypted:
                    env["SSH_ASKPASS"] = self._askpass(directory)
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["SOVAGRID_KEYGEN"] = "1"
                else:
                    env["SSH_ASKPASS_REQUIRE"] = "never"
                    env.pop("SOVAGRID_KEYGEN", None)
                    argv.extend(["-N", ""])
                self._run(argv, env, timeout)
                text, fingerprint = _inspect_pair(private, public, encrypted)
                if windows_sid is not None:
                    _protect_windows_private_file(private, windows_sid)
                private.chmod(0o600)
                public.chmod(0o644)
                for path in (private, public):
                    # Windows FlushFileBuffers needs a writable handle, even
                    # when the completed file bytes are not being changed.
                    with path.open("r+b") as stream:
                        os.fsync(stream.fileno())
                if self._cancelled.is_set():
                    raise KeyGenerationError("Создание ключа отменено.")
                try:
                    # Hard links publish complete bytes atomically and refuse
                    # any existing path, including a dangling symlink. Both
                    # staged files are on the destination filesystem.
                    for source, target in ((public, public_destination), (private, destination)):
                        os.link(source, target)
                        published.append((target, source))
                    if os.name != "nt":
                        fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                except BaseException:
                    for target, source in reversed(published):
                        _unlink_same(target, source)
                    raise
                return GeneratedKey(destination, public_destination, text, fingerprint, encrypted)
        except KeyGenerationError:
            raise
        except FileExistsError:
            raise KeyGenerationError("Имя ключа занято другим файлом. Выберите другое; существующие файлы не изменены.") from None
        except OSError:
            raise KeyGenerationError("Не удалось безопасно сохранить ключ. Выберите другой локальный каталог с доступом на запись.") from None
