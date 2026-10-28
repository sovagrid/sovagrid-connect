# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Download the one published first-install source bundle into a private file."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import time
from contextlib import contextmanager
from typing import Callable, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .installer import InstallError, MAX_ARCHIVE_BYTES, verify_bundle


PUBLISHED_SERVER_SOURCE_URL = (
    "https://github.com/sovagrid/sovagrid-blueprint/releases/download/"
    "v0.10.0-preview/SovaGrid-server-source-0.10.0-preview.tar.gz"
)
PUBLISHED_SERVER_SOURCE_SHA256 = "275c5f03c30b1a924b1fcb48067a41f7b76481cd4c249589a7c8b5098db749fb"
_ASSET_HOST = "release-assets.githubusercontent.com"
_ASSET_PREFIX = "/github-production-release-asset/"
_CHUNK_BYTES = 256 * 1024
_TRANSFER_SECONDS = 180


def _approved_url(url: str, *, asset: bool = False) -> bool:
    """Inspect redirect targets without printing their signed query strings."""
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.username or parts.password or
                parts.port not in (None, 443) or parts.fragment):
            return False
    except ValueError:
        return False
    if parts.hostname == _ASSET_HOST:
        return parts.path.startswith(_ASSET_PREFIX) and len(parts.path) > len(_ASSET_PREFIX)
    return not asset and url == PUBLISHED_SERVER_SOURCE_URL


class _ReleaseRedirectHandler(HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self._redirects = 0

    def redirect_request(self, request, response, code, message, headers, new_url):
        self._redirects += 1
        if self._redirects > 2 or not _approved_url(new_url, asset=True):
            raise InstallError("GitHub перенаправил скачивание на неподтверждённый адрес")
        return super().redirect_request(request, response, code, message, headers, new_url)


def _download_into(destination: Path, *, progress: Callable[[str], None] | None = None,
                   opener=None) -> None:
    opener = opener or build_opener(_ReleaseRedirectHandler())
    request = Request(PUBLISHED_SERVER_SOURCE_URL, headers={
        "User-Agent": "SovaGrid-Connect/0.10.0-preview",
        "Accept-Encoding": "identity",
    })
    digest = hashlib.sha256()
    received = 0
    deadline = time.monotonic() + _TRANSFER_SECONDS
    if progress:
        progress("Скачивание проверенного выпуска SovaGrid с GitHub…")
    try:
        with opener.open(request, timeout=20) as response:
            if not _approved_url(response.geturl()):
                raise InstallError("Сервер загрузки ответил с неподтверждённого адреса")
            raw_length = response.headers.get("Content-Length")
            try:
                content_length = int(raw_length) if raw_length is not None else None
            except ValueError as exc:
                raise InstallError("Сервер загрузки передал неверный размер пакета") from exc
            if content_length is not None and not 0 < content_length <= MAX_ARCHIVE_BYTES:
                raise InstallError("Пакет на GitHub превышает лимит 64 МиБ")
            encoding = response.headers.get("Content-Encoding")
            if encoding and encoding.lower() != "identity":
                raise InstallError("Сервер загрузки передал пакет с неподдерживаемым сжатием")
            descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                next_progress = 2 * 1024 * 1024
                while True:
                    if time.monotonic() >= deadline:
                        raise InstallError("Скачивание пакета заняло слишком много времени")
                    chunk = response.read(min(_CHUNK_BYTES, MAX_ARCHIVE_BYTES - received + 1))
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_ARCHIVE_BYTES:
                        raise InstallError("Пакет на GitHub превышает лимит 64 МиБ")
                    digest.update(chunk)
                    output.write(chunk)
                    if progress and received >= next_progress:
                        progress(f"Скачано {received // (1024 * 1024)} МиБ пакета SovaGrid…")
                        next_progress = received + 2 * 1024 * 1024
        if received == 0 or (content_length is not None and received != content_length):
            raise InstallError("Загрузка пакета SovaGrid завершилась раньше времени")
    except HTTPError as exc:
        raise InstallError(f"Не удалось скачать выпуск SovaGrid: GitHub ответил HTTP {exc.code}") from None
    except (URLError, OSError, TimeoutError) as exc:
        raise InstallError("Не удалось скачать выпуск SovaGrid. Проверьте доступ к GitHub и повторите попытку") from exc
    if digest.hexdigest() != PUBLISHED_SERVER_SOURCE_SHA256:
        raise InstallError("SHA-256 скачанного пакета не совпадает с опубликованным выпуском")
    if progress:
        progress("SHA-256 совпал; проверяем структуру серверного пакета…")
    verify_bundle(destination)
    if progress:
        progress("Серверный пакет проверен; начинаем установку по SSH…")


@contextmanager
def downloaded_server_bundle(*, progress: Callable[[str], None] | None = None,
                             opener=None) -> Iterator[Path]:
    """Keep the checked archive alive until ``ServerInstaller.install`` returns."""
    with tempfile.TemporaryDirectory(prefix="sovagrid-release-") as directory:
        destination = Path(directory) / "server-source.tar.gz"
        _download_into(destination, progress=progress, opener=opener)
        yield destination
