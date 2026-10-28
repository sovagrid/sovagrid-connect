# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Review-first SSH update of a promoted Hub-only Ubuntu host.

The first update uses the helper in an exact approved bundle. Fixed client
code verifies the remote archive and extracted Git source bytes before that
helper runs. The original external Agent is outside this transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import tarfile
import tempfile
from typing import Callable
import subprocess

from .core import ConnectionOptions
from .installer import (BundleSummary, COMPONENTS, InstallError,
                        _STAGE_CANDIDATE_BODY, _snapshot_with_digest)
from .promotion import PromotionController
from .promotion_protocol import PromotionState, parse_promotion_state
from .server_timer import ServerTimerStatus, parse_server_timer_status


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GIT = re.compile(r"[0-9a-f]{40}\Z")
_HELPER = "sovagrid-blueprint/deploy/hub_only_update.py"
_AUTO = "sovagrid-blueprint/deploy/hub_only_auto_update.py"
_REQUIRED = frozenset({
    _HELPER, _AUTO, "sovagrid-blueprint/deploy/promote_agent_only.py",
    "sovagrid-blueprint/deploy/remote_update_worker.py",
    "sovagrid-blueprint/deploy/sovagrid-hub-only-update.service",
    "sovagrid-blueprint/deploy/sovagrid-hub-only-update.timer",
})
_STAGE_SCRIPT = ("set -Eeuo pipefail\numask 077\n"
                 "refuse() { printf 'SG_HUB_ONLY_REFUSE:%s\\n' \"$1\"; exit 30; }\n"
                 "[[ $(id -u) == 0 ]] || refuse ROOT\n"
                 + _STAGE_CANDIDATE_BODY.replace("SG_UPDATE_STAGE:", "SG_HUB_ONLY_STAGE:"))

# This read-only probe executes only the already installed promotion inspector.
# It verifies the on-disk manifest digest independently and returns no secrets.
_INSTALLED_SCRIPT = r'''
import hashlib, json, os, pathlib, re, stat, subprocess
root = pathlib.Path('/opt/sovagrid-src')
manifest = root / 'sovagrid-bundle.json'
helper = root / 'sovagrid-blueprint/deploy/promote_agent_only.py'
for item, directory in ((root, True), (root / 'sovagrid-blueprint', True),
                        (root / 'sovagrid-blueprint/deploy', True), (manifest, False),
                        (helper, False)):
    info = item.lstat()
    assert info.st_uid == 0 and not info.st_mode & 0o022
    assert stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
assert 0 < manifest.stat().st_size <= 524288
raw = manifest.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
data = json.loads(raw)
assert isinstance(data, dict) and set(data) == {'format', 'components', 'sha256'} and data['format'] == 1
commits = {}
for name, record in data['components'].items():
    assert name in {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
    assert isinstance(record, dict) and set(record) == {'commit', 'file_count'}
    assert re.fullmatch('[0-9a-f]{40}', record['commit'])
    commits[name] = record['commit']
assert len(commits) == 5
result = subprocess.run(['/usr/bin/python3', '-I', str(helper), 'inspect'],
                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=90, check=True)
assert len(result.stdout) <= 4096
state = json.loads(result.stdout)
native = root / 'sovagrid-blueprint/deploy/hub_only_auto_update.py'
native_available = native.is_file() and not native.is_symlink() and \
    'sovagrid-blueprint/deploy/hub_only_auto_update.py' in data['sha256']
print(json.dumps({'protocol': 1, 'manifest_sha256': digest, 'state': state,
                  'commits': commits, 'native_updater': native_available}, separators=(',', ':')))
'''

# Never import or run candidate Python for this check. It verifies the exact
# archive, root-owned extraction, manifest hash map and every component Git ID.
_VERIFY_CANDIDATE_SCRIPT = r'''
import hashlib, json, os, pathlib, re, stat, sys
expected, expected_manifest = sys.argv[1:]
assert re.fullmatch('[0-9a-f]{64}', expected) and re.fullmatch('[0-9a-f]{64}', expected_manifest)
root = pathlib.Path('/opt/sovagrid-candidates')
candidate = root / expected
for item in (root, candidate):
    info = item.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
for name in ('bundle.tar.gz', '.ready'):
    info = (candidate / name).lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
assert (candidate / '.ready').read_text().strip() == expected
archive = candidate / 'bundle.tar.gz'
assert 0 < archive.stat().st_size <= 67108864
def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()
assert sha(archive) == expected
source = candidate / 'source'
info = source.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) in (0o700, 0o755)
manifest = source / 'sovagrid-bundle.json'
info = manifest.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o644
assert 0 < info.st_size <= 524288 and sha(manifest) == expected_manifest
data = json.loads(manifest.read_bytes())
components = {'sovagrid-blueprint', 'sovagrid-hub', 'sovagrid-web', 'sovagrid-agent', 'sovagrid-vpn'}
assert isinstance(data, dict) and set(data) == {'format', 'components', 'sha256'} and type(data['format']) is int and data['format'] == 1
assert set(data['components']) == components and isinstance(data['sha256'], dict)
assert {item.name for item in source.iterdir()} == components | {'sovagrid-bundle.json'}
hashes = data['sha256']
seen = set()
for parent, dirs, files in os.walk(source, followlinks=False):
    for name in dirs + files:
        item = pathlib.Path(parent) / name
        relative = item.relative_to(source).as_posix()
        info = item.lstat()
        assert info.st_uid == 0
        if name in dirs:
            assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o755
        else:
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            assert stat.S_IMODE(info.st_mode) in (0o644, 0o755)
            if relative == 'sovagrid-bundle.json':
                continue
            assert relative in hashes and re.fullmatch('[0-9a-f]{64}', hashes[relative])
            assert sha(item) == hashes[relative]
            seen.add(relative)
assert seen == set(hashes)
commits = {}
for name, record in data['components'].items():
    assert isinstance(record, dict) and set(record) == {'commit', 'file_count'}
    assert re.fullmatch('[0-9a-f]{40}', record['commit'])
    assert type(record['file_count']) is int and record['file_count'] == sum(value.startswith(name + '/') for value in hashes)
    commits[name] = record['commit']
print(json.dumps({'protocol': 1, 'archive_sha256': expected,
                  'manifest_sha256': expected_manifest, 'commits': commits}, separators=(',', ':')))
'''

# Status and disarm must remain usable if Hub health is degraded. Only these
# operations use this smaller proof of the installed timer helper's bytes.
_TIMER_HELPER_CHECK = r'''
import hashlib, json, pathlib, stat
root = pathlib.Path('/opt/sovagrid-src')
relative = 'sovagrid-blueprint/deploy/hub_only_auto_update.py'
manifest = root / 'sovagrid-bundle.json'
for item in (root, root / 'sovagrid-blueprint', root / 'sovagrid-blueprint/deploy'):
    info = item.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
info = manifest.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and \
    not info.st_mode & 0o022 and 0 < info.st_size <= 524288
data = json.loads(manifest.read_bytes())
hashes = data['sha256']
if relative not in hashes:
    print('SG_HUB_ONLY_TIMER:ABSENT')
else:
    helper = root / relative
    info = helper.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o022
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    assert digest == hashes[relative]
    print('SG_HUB_ONLY_TIMER:AVAILABLE')
'''


@dataclass(frozen=True)
class HubOnlyInstalled:
    manifest_sha256: str
    promotion: PromotionState
    commits: dict[str, str]
    native_updater: bool


@dataclass(frozen=True)
class HubOnlyPreview:
    options: ConnectionOptions
    bundle: BundleSummary
    archive_sha256: str
    manifest_sha256: str
    installed: HubOnlyInstalled


@dataclass(frozen=True)
class HubOnlyPrepared:
    preview: HubOnlyPreview


def _json(raw: bytes, keys: set[str]) -> dict:
    if len(raw) > 4096:
        raise InstallError('Сервер прислал слишком большой ответ об обновлении локального Hub')
    try:
        value = json.loads(raw.decode('utf-8'))
    except (UnicodeError, ValueError) as exc:
        raise InstallError('Сервер прислал неверный ответ об обновлении локального Hub') from exc
    if (not isinstance(value, dict) or set(value) != keys or
            type(value.get('protocol')) is not int or value['protocol'] != 1):
        raise InstallError('Сервер прислал неподдерживаемый ответ об обновлении локального Hub')
    return value


def _commits(value: object) -> dict[str, str]:
    if (not isinstance(value, dict) or set(value) != COMPONENTS or
            any(not isinstance(item, str) or not _GIT.fullmatch(item) for item in value.values())):
        raise InstallError('Сервер прислал неверные версии компонентов')
    return value


def _manifest(bundle: Path) -> str:
    try:
        with tarfile.open(bundle, 'r:gz') as archive:
            names = set(archive.getnames())
            if not _REQUIRED <= names:
                raise InstallError('В пакете нет обновления и таймера локального Hub')
            member = archive.getmember('sovagrid-bundle.json')
            if not member.isfile() or member.size > 512 * 1024:
                raise InstallError('Манифест пакета локального Hub неверен')
            stream = archive.extractfile(member)
            if stream is None:
                raise InstallError('Манифест пакета локального Hub не читается')
            return hashlib.sha256(stream.read()).hexdigest()
    except (KeyError, OSError, tarfile.TarError) as exc:
        raise InstallError('Пакет локального Hub повреждён') from exc


class HubOnlyUpdateController:
    def __init__(self, options: ConnectionOptions, *, approved_archive_sha256: str | None,
                 popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                 progress: Callable[[str], None] | None = None,
                 transport: PromotionController | None = None) -> None:
        if approved_archive_sha256 is not None and _SHA.fullmatch(approved_archive_sha256) is None:
            raise InstallError('SHA-256 разрешённого пакета локального Hub неверен')
        self.transport = transport or PromotionController(
            options, approved_archive_sha256=approved_archive_sha256 or '0' * 64,
            popen=popen, progress=progress,
        )
        self.options = self.transport.options
        self.approved_archive_sha256 = approved_archive_sha256
        self.progress = progress or (lambda _message: None)

    def _run(self, command: str, *, source: Path | None = None,
             timeout: float = 180) -> bytes:
        code, raw = self.transport._execute(self.transport._privileged + command,
                                            source=source, timeout=timeout)
        if code != 0:
            raise InstallError('Сервер отклонил действие с локальным Hub; проверьте состояние перед повтором')
        return raw

    def inspect(self) -> HubOnlyInstalled:
        self.transport._verify_root_access()
        raw = self._run('/usr/bin/python3 -I -c ' + shlex.quote(_INSTALLED_SCRIPT), timeout=180)
        value = _json(raw, {'protocol', 'manifest_sha256', 'state', 'commits', 'native_updater'})
        manifest = value['manifest_sha256']
        if not isinstance(manifest, str) or _SHA.fullmatch(manifest) is None:
            raise InstallError('Манифест локального Hub повреждён')
        promotion = parse_promotion_state(json.dumps(value['state']).encode())
        if (promotion.phase != 'activated' or promotion.external_agent_preserved is not True or
                promotion.source_manifest_sha256 != manifest or
                promotion.pinned_manifest_sha256 != manifest or promotion.local_server_id is None):
            raise InstallError('Внешний Agent или локальный Hub изменился; обновление остановлено')
        if type(value['native_updater']) is not bool:
            raise InstallError('Сервер прислал неверный статус таймера')
        return HubOnlyInstalled(manifest, promotion, _commits(value['commits']), value['native_updater'])

    def preview(self, source: Path) -> HubOnlyPreview:
        if self.approved_archive_sha256 is None:
            raise InstallError('Для обновления локального Hub пока нет проверенного серверного пакета')
        with tempfile.TemporaryDirectory(prefix='sovagrid-hub-only-preview-') as directory:
            snapshot = Path(directory) / 'bundle.tar.gz'
            self.progress('Проверка точного серверного пакета…')
            summary, digest = _snapshot_with_digest(source, snapshot, self.approved_archive_sha256)
            manifest = _manifest(snapshot)
        self.progress('Проверка собственного Hub и внешнего Agent без изменений…')
        installed = self.inspect()
        if summary.commits == installed.commits:
            raise InstallError('В пакете те же версии всех серверных компонентов')
        return HubOnlyPreview(self.options, summary, digest, manifest, installed)

    def _check_preview(self, preview: HubOnlyPreview) -> None:
        if (preview.options != self.options or preview.archive_sha256 != self.approved_archive_sha256 or
                self.inspect() != preview.installed):
            raise InstallError('SSH-сервер или установленная версия изменились; повторите проверку')

    def _verify_remote_candidate(self, preview: HubOnlyPreview) -> None:
        raw = self._run('/usr/bin/python3 -I -c ' + shlex.quote(_VERIFY_CANDIDATE_SCRIPT) + ' ' +
                        preview.archive_sha256 + ' ' + preview.manifest_sha256, timeout=240)
        value = _json(raw, {'protocol', 'archive_sha256', 'manifest_sha256', 'commits'})
        if (value['archive_sha256'] != preview.archive_sha256 or
                value['manifest_sha256'] != preview.manifest_sha256 or
                _commits(value['commits']) != preview.bundle.commits):
            raise InstallError('Переданный пакет или версии Git на сервере не совпали с выбранными')

    def _candidate_command(self, preview: HubOnlyPreview, action: str) -> str:
        if action not in {'preflight', 'apply'}:
            raise ValueError('unsupported action')
        helper = '/opt/sovagrid-candidates/' + preview.archive_sha256 + '/source/' + _HELPER
        return ('/usr/bin/python3 -IB ' + shlex.quote(helper) + ' ' + action + ' ' +
                preview.archive_sha256 + ' ' + preview.installed.manifest_sha256)

    def _preflight(self, preview: HubOnlyPreview) -> None:
        raw = self._run(self._candidate_command(preview, 'preflight'), timeout=240)
        if raw.strip() != b'SG_HUB_ONLY_CANDIDATE:OK':
            raise InstallError('Пакет локального Hub не прошёл проверку установленного сервера')

    def stage(self, source: Path, preview: HubOnlyPreview) -> HubOnlyPrepared:
        self._check_preview(preview)
        with tempfile.TemporaryDirectory(prefix='sovagrid-hub-only-stage-') as directory:
            snapshot = Path(directory) / 'bundle.tar.gz'
            summary, digest = _snapshot_with_digest(source, snapshot, preview.archive_sha256)
            if summary.commits != preview.bundle.commits or _manifest(snapshot) != preview.manifest_sha256:
                raise InstallError('Пакет изменился после проверки; выберите его заново')
            self.progress('Передача пакета под точным SHA-256…')
            command = 'bash -c ' + shlex.quote(_STAGE_SCRIPT) + ' sovagrid ' + digest
            raw = self._run(command, source=snapshot, timeout=900)
            if b'SG_HUB_ONLY_STAGE:DONE' not in raw.splitlines():
                raise InstallError('Сервер не подтвердил подготовку пакета')
        self.progress('Независимая сверка архива, файлов и версий Git на сервере…')
        self._verify_remote_candidate(preview)
        self._check_preview(preview)
        self._preflight(preview)
        return HubOnlyPrepared(preview)

    def apply(self, prepared: HubOnlyPrepared) -> HubOnlyInstalled:
        preview = prepared.preview
        self._check_preview(preview)
        self._verify_remote_candidate(preview)
        self._preflight(preview)
        self.progress('Обновление локального Hub с защищённым откатом…')
        code, raw = self.transport._execute(
            self.transport._privileged + self._candidate_command(preview, 'apply'), timeout=3900)
        markers = raw.splitlines()
        if code != 0:
            if b'SG_HUB_ONLY_STAGE:ROLLBACK_FAILED' in markers:
                raise InstallError('Обновление не завершено, автоматический откат не удался. '
                                   'Сохранённую резервную копию нужно проверить на сервере')
            if b'SG_HUB_ONLY_STAGE:ROLLED_BACK' in markers:
                raise InstallError('Новая версия не прошла проверку; предыдущий локальный Hub восстановлен')
            raise InstallError('Сервер отклонил обновление локального Hub до завершения операции')
        if b'SG_HUB_ONLY_STAGE:DONE' not in markers:
            raise InstallError('Локальный Hub не подтвердил обновление')
        installed = self.inspect()
        if (installed.manifest_sha256 != preview.manifest_sha256 or
                installed.commits != preview.bundle.commits or
                installed.promotion.local_server_id != preview.installed.promotion.local_server_id):
            raise InstallError('После обновления сервер не подтвердил точный пакет и прежний локальный Agent')
        return installed

    def timer_status(self) -> ServerTimerStatus | None:
        self.transport._verify_root_access()
        if not self._timer_available():
            return None
        raw = self._run('/usr/bin/python3 -I /opt/sovagrid-src/' + _AUTO + ' status', timeout=60)
        try:
            return parse_server_timer_status(raw)
        except ValueError as exc:
            raise InstallError(str(exc)) from exc

    def arm(self, prepared: HubOnlyPrepared) -> str:
        preview = prepared.preview
        self._check_preview(preview)
        if not preview.installed.native_updater:
            raise InstallError('Сначала примените первое обновление локального Hub; таймер ещё не установлен')
        self._verify_remote_candidate(preview)
        self._preflight(preview)
        raw = self._run('/usr/bin/python3 -I /opt/sovagrid-src/' + _AUTO + ' arm ' +
                        preview.archive_sha256 + ' ' + preview.installed.manifest_sha256, timeout=240)
        marker = raw.strip().decode('ascii', errors='ignore')
        if marker not in {'SG_HUB_ONLY_AUTO_UPDATE:ARMED', 'SG_HUB_ONLY_AUTO_UPDATE:ALREADY_ARMED'}:
            raise InstallError('Сервер не подтвердил разрешение автообновления')
        return marker

    def disarm(self) -> None:
        self.transport._verify_root_access()
        if not self._timer_available():
            raise InstallError('Таймер локального Hub ещё не установлен')
        raw = self._run('/usr/bin/python3 -I /opt/sovagrid-src/' + _AUTO + ' disarm', timeout=120)
        if raw.strip() != b'SG_HUB_ONLY_AUTO_UPDATE:DISABLED':
            raise InstallError('Сервер не подтвердил отключение автообновления')

    def _timer_available(self) -> bool:
        raw = self._run('/usr/bin/python3 -I -c ' + shlex.quote(_TIMER_HELPER_CHECK), timeout=60)
        if raw.strip() == b'SG_HUB_ONLY_TIMER:ABSENT':
            return False
        if raw.strip() != b'SG_HUB_ONLY_TIMER:AVAILABLE':
            raise InstallError('Исходники таймера локального Hub не подтверждены')
        return True
