#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Package verified Connect CI GUIs with one selected server source bundle.

Run after rebuilding SovaGrid-server-source.tar.gz. The same trusted bundle is
placed next to each GUI; the GUI itself comes unchanged from successful CI.
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
from pathlib import Path, PurePosixPath
import sys
import tarfile
import zipfile


KITS = (
    ("macOS-arm64", "SovaGrid-Connect-macOS-arm64.zip", ("dist/SovaGrid-Connect-GUI.app/",)),
    ("Windows-X64", "SovaGrid-Connect-Windows-X64.zip", ("dist/SovaGrid-Connect-GUI/",)),
    ("Linux-X64", "SovaGrid-Connect-Linux-X64.zip", ("dist/SovaGrid-Connect-GUI/",)),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def approved_release_pins() -> dict[str, str]:
    """Read every Starter-related GUI pin without importing Tk."""
    source = Path(__file__).resolve().parents[1] / "sovagrid_connect" / "gui.py"
    module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names = {"_APPROVED_SERVER_SOURCE_SHA256", "_APPROVED_PROMOTION_BUNDLE_SHA256",
             "_APPROVED_HUB_ONLY_UPDATE_BUNDLE_SHA256",
             "_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256"}
    pins: dict[str, str] = {}
    for node in module.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else [])
        for target in targets:
            if isinstance(target, ast.Name) and target.id in names:
                if (target.id in pins or not isinstance(node.value, ast.Constant) or
                        not isinstance(node.value.value, str) or
                        len(node.value.value) != 64 or
                        any(c not in "0123456789abcdef" for c in node.value.value)):
                    raise RuntimeError("Connect GUI has an invalid release pin")
                pins[target.id] = node.value.value
    if set(pins) != names:
        raise RuntimeError("Connect GUI is missing a Starter release pin")
    return pins


def instructions(platform: str, bundle_hash: str) -> bytes:
    if platform.startswith("macOS"):
        launch = "Откройте SovaGrid-Connect-GUI.app. Это предварительная сборка без подписи издателя и нотариального удостоверения macOS."
    elif platform.startswith("Windows"):
        launch = "Откройте SovaGrid-Connect-GUI/SovaGrid-Connect-GUI.exe. Сохраните всю папку GUI вместе с _internal и Askpass."
    else:
        launch = "Откройте SovaGrid-Connect-GUI/SovaGrid-Connect-GUI (для файла должны сохраняться права на запуск)."
    text = f"""SovaGrid — быстрый старт ({platform})

1. Распакуйте весь этот ZIP в отдельную папку. Не запускайте программу прямо из архива.
2. {launch}
3. Укажите SSH-адрес Ubuntu-сервера, пользователя root и при необходимости ключ / промежуточный хост. Для SSH-пароля используйте системный запрос Connect; пароль Hub отдельный.
4. Нажмите «Подключиться». Connect проверит сервер. Если установка отсутствует, он предложит поставить лежащий рядом проверенный пакет и затем откроет панель.
5. В отдельных окнах ответьте на запросы SSH и сверьте SHA256-отпечаток нового хоста по независимому источнику. Дождитесь сообщения об успехе.
6. Для управляемого Hub Connect откроет панель с одноразовым входом администратора через тот же SSH-маршрут. Если автоматический вход недоступен, используйте местный аккаунт Hub; начальный пароль можно получить кнопкой Connect и затем сменить в настройках панели.

Если SovaGrid уже установлен, кнопка «Подключиться» откроет существующую панель. Если найден только Agent другого Hub, Connect предложит мастер «Свой Hub на сервере с Agent…». Он принимает пакет этого выпуска, показывает SSH-маршрут и SHA-256, затем создаёт отдельный локальный Hub и Agent, сохраняя прежний Agent и его обратный туннель. Нужен вход root или уже настроенное sudo без запроса пароля; вводить пароль sudo и менять sudoers мастер не будет. Для существующей неполной установки автоматическое продолжение закрыто.
Для собственного локального Hub рядом с внешним Agent используйте «Обновить собственный локальный Hub…». Сначала проверьте пакет и подготовьте кандидат; службы изменяются только после отдельного «Применить обновление». После первого ручного перехода с версии 0.3.9 можно разрешить серверу ровно одно обновление при простое. «Снять разрешение» удаляет политику; timer без неё ничего не применяет.
Новое создание собственного Hub оставляет команды второго Agent выключенными. Чтобы включить их без консоли, откройте отдельную кнопку «Разрешить команды своего Hub…», проверьте сервер и подтвердите действие. Затем «Терминал и файлы своего Hub…» позволит включать или выключать эти функции по отдельности. Оба мастера откажут при параллельном изменении настроек. Выключение команд пока не предлагается без отдельного проверенного серверного контракта.
Новый SSH-ключ можно создать через «Создать…» рядом с ключом сервера или перехода. Выберите место сохранения; парольная фраза вводится в скрытых окнах. Путь заполнится автоматически, открытую часть можно скопировать. Добавьте её в SSH-доступы через панель провайдера или администратора перед входом новым ключом.
Для уже установленного исправного сервера откройте «Обновить сервер…». Connect проверит пакет и текущую версию без изменений сервера, затем после подтверждения передаст и повторно проверит пакет. Действующие службы продолжат работать, пока вы не нажмёте отдельную кнопку «Применить обновление» и не подтвердите действие. При ошибке Connect попытается восстановить предыдущую версию и покажет результат отката. Обновления пакетов ОС и системных пользователей не откатываются.
Для заранее проверенного пакета можно нажать «Применить при простое». Connect запомнит только этот SHA-256, текущую версию и SSH-сервер и попробует применить пакет, пока приложение открыто и на Hub нет активной работы. После успешного обновления одобрение выключится. На сервере с таймером доступно отдельное «Разрешить на сервере»: один пакет и текущая версия проверяются повторно, затем сервер сам обновится при простое даже после закрытия Connect. Кнопки «Состояние» и «Отключить» позволяют управлять этим разрешением без консоли.
Чтобы пользоваться панелью с телефона, включите HTTPS для публичного IPv4 или домена через «Веб-доступ с телефона…». В веб-панели есть кнопка «Сделать приложением» для установки PWA на домашний экран. Нативные Android и Apple клиенты доступны отдельно.
Пакет содержит исходный код, выполняемый от root. Используйте этот ZIP только из доверенного источника.
SHA-256 SovaGrid-server-source.tar.gz: {bundle_hash}
Пароли и Telegram-токены в консоль для этой процедуры вводить не нужно.
"""
    return text.encode("utf-8")


def build(platform: str, source_zip: Path, prefixes: tuple[str, ...],
          server_bundle: Path, destination_dir: Path, bundle_hash: str) -> Path:
    if not source_zip.is_file():
        raise RuntimeError(f"Missing successful CI archive: {source_zip}")
    destination = destination_dir / f"SovaGrid-Starter-{platform}.zip"
    temporary = destination_dir / f".{destination.name}.tmp"
    selected = 0
    legal_selected = 0
    with zipfile.ZipFile(source_zip) as source, zipfile.ZipFile(temporary, "w", allowZip64=True) as output:
        if "dist/legal/third-party/INDEX.md" not in source.namelist():
            raise RuntimeError(f"CI archive has no third-party notices: {source_zip}")
        for entry in source.infolist():
            is_gui = any(entry.filename.startswith(prefix) for prefix in prefixes)
            is_notice = entry.filename.startswith("dist/legal/third-party/")
            if not is_gui and not is_notice:
                continue
            target = entry.filename.removeprefix("dist/")
            pure = PurePosixPath(target)
            if target.startswith("/") or ".." in pure.parts or not target or "/".join(pure.parts) != target.rstrip("/"):
                raise RuntimeError(f"Unsafe CI archive path: {entry.filename}")
            clone = copy.copy(entry)
            clone.filename = target
            output.writestr(clone, source.read(entry))
            if is_gui:
                selected += 1
            if is_notice:
                legal_selected += 1
        if selected < 5:
            raise RuntimeError(f"GUI files missing from {source_zip}")
        if legal_selected < 5:
            raise RuntimeError(f"Third-party notices incomplete in {source_zip}")
        info = zipfile.ZipInfo("SovaGrid-server-source.tar.gz")
        info.compress_type = zipfile.ZIP_STORED
        info.external_attr = 0o600 << 16
        output.writestr(info, server_bundle.read_bytes())
        for name in ("LICENSE", "ATTRIBUTION.md", "NOTICE"):
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            output.writestr(info, (Path(__file__).resolve().parents[1] / name).read_bytes())
        info = zipfile.ZipInfo("START-HERE.txt")
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        output.writestr(info, instructions(platform, bundle_hash))
    with zipfile.ZipFile(temporary) as check:
        if check.testzip() is not None:
            raise RuntimeError(f"Corrupt starter ZIP: {destination}")
        if hashlib.sha256(check.read("SovaGrid-server-source.tar.gz")).hexdigest() != bundle_hash:
            raise RuntimeError("The embedded server bundle changed")
        if not check.read("legal/third-party/INDEX.md").startswith(b"# Third-party licenses"):
            raise RuntimeError("The starter ZIP has no readable third-party inventory")
    temporary.replace(destination)
    print(f"{destination}  sha256={sha256(destination)}  gui_entries={selected}  notice_entries={legal_selected}")
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", type=Path, help="Directory with server bundle and three Connect CI ZIP files")
    parser.add_argument("--output-dir", type=Path, help="Destination for the three starter ZIP files (default: source_dir)")
    args = parser.parse_args()
    source_dir = args.source_dir.expanduser().resolve()
    destination_dir = (args.output_dir or source_dir).expanduser().resolve()
    destination_dir.mkdir(parents=True, exist_ok=True)
    server_bundle = source_dir / "SovaGrid-server-source.tar.gz"
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from sovagrid_connect.installer import verify_bundle

    summary = verify_bundle(server_bundle)
    if summary.files < 100:
        raise RuntimeError("Unexpectedly small server bundle")
    bundle_hash = sha256(server_bundle)
    with tarfile.open(server_bundle, "r:gz") as archive:
        manifest_hash = hashlib.sha256(archive.extractfile("sovagrid-bundle.json").read()).hexdigest()
    pins = approved_release_pins()
    if (any(pins[name] != bundle_hash for name in
            ("_APPROVED_SERVER_SOURCE_SHA256", "_APPROVED_PROMOTION_BUNDLE_SHA256",
             "_APPROVED_HUB_ONLY_UPDATE_BUNDLE_SHA256")) or
            pins["_APPROVED_LOCAL_OPERATIONS_MANIFEST_SHA256"] != manifest_hash):
        raise RuntimeError("Starter server bundle and all Connect GUI pins must match")
    print(f"Server bundle verified: {summary.files} files, sha256={bundle_hash}")
    for platform, filename, prefixes in KITS:
        build(platform, source_dir / filename, prefixes, server_bundle, destination_dir, bundle_hash)


if __name__ == "__main__":
    main()
