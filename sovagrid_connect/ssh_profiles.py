# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Read a small, explicit subset of OpenSSH config without running SSH or Match exec.

The selected profile is copied into Connect's own strict temporary SSH config.
Unknown settings are reported to the user; commands and ambiguous routes block
the import instead of being silently inherited from a user's ssh_config.
"""

from __future__ import annotations

from dataclasses import dataclass
import getpass
import glob
from pathlib import Path
import re

from .core import ConnectionOptions


class ProfileImportError(ValueError):
    """The local SSH config could not be read or represented safely."""


_ALIASES = re.compile(r"[A-Za-z0-9_.-]+\Z")
_JUMP = re.compile(r"(?:(?P<user>[^@:,\s]+)@)?(?P<host>\[[^\]]+\]|[^:,\s]+)(?::(?P<port>[0-9]+))?\Z")
_TOKENS = re.compile(r"%([%hdnpru])")
_SUPPORTED = {"hostname", "user", "port", "identityfile", "proxyjump", "hostkeyalias", "identitiesonly"}
_ROUTE_BLOCKERS = {"proxycommand", "canonicalizehostname", "canonicaldomains", "canonicalizepermittedcnames"}
_MAX_FILE_BYTES = 1024 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_FILES = 128
_MAX_DEPTH = 8


def _config_words(line: str) -> list[str]:
    """Tokenize OpenSSH arguments without treating a Windows path as shell text."""
    words: list[str] = []
    token: list[str] = []
    quote: str | None = None
    started = False
    index = 0
    while index < len(line):
        character = line[index]
        if character == "\\" and index + 1 < len(line):
            following = line[index + 1]
            if following in "\\\"'" or (quote is None and following.isspace()):
                token.append(following)
                started = True
                index += 2
                continue
        if quote is not None:
            if character == quote:
                quote = None
            else:
                token.append(character)
        elif character in "\"'":
            quote = character
            started = True
        elif character.isspace():
            if started:
                words.append("".join(token))
                token = []
                started = False
        elif character == "#" and not started:
            break
        else:
            token.append(character)
            started = True
        index += 1
    if quote is not None:
        raise ValueError("Незакрытая кавычка")
    if started:
        words.append("".join(token))
    return words


@dataclass(frozen=True)
class _Entry:
    patterns: tuple[str, ...] | None
    guards: tuple[tuple[str, ...], ...]
    key: str
    value: str
    source: str
    line: int

    @property
    def location(self) -> str:
        return f"{Path(self.source).name}:{self.line}"


@dataclass(frozen=True)
class ImportedProfile:
    alias: str
    connection: ConnectionOptions | None
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class _Node:
    host: str
    user: str
    port: int
    identity: str | None
    proxyjump: str | None
    host_key_alias: str | None
    warnings: tuple[str, ...]
    errors: tuple[str, ...]


def _matches(patterns: tuple[str, ...] | None, alias: str) -> bool:
    if patterns is None:
        return True
    def matches(pattern: str) -> bool:
        # OpenSSH Host patterns use * and ?; fnmatch's [] character classes
        # would give a different answer for some literal SSH host names.
        expression = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        return re.fullmatch(expression, alias, flags=re.IGNORECASE) is not None
    positive = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if matches(pattern[1:]):
                return False
        elif matches(pattern):
            positive = True
    return positive


def _expand(value: str, *, alias: str, host: str, user: str, port: int) -> str:
    replacements = {"%": "%", "h": host, "n": alias, "d": str(Path.home()),
                    "r": user, "p": str(port), "u": getpass.getuser()}
    if re.search(r"%(?![%hdnpru])", value):
        raise ProfileImportError("неподдерживаемый %-токен в настройке SSH")
    return _TOKENS.sub(lambda match: replacements[match.group(1)], value)


class OpenSSHProfiles:
    """A read-only catalog of literal Host aliases from a local config file."""

    def __init__(self, path: Path | None = None) -> None:
        try:
            self.path = (path or Path.home() / ".ssh" / "config").expanduser()
        except RuntimeError as exc:
            raise ProfileImportError("Не удалось раскрыть путь к SSH config") from exc
        self._entries: list[_Entry] = []
        self._aliases: list[str] = []
        self._global_errors: list[str] = []
        self._total_bytes = 0
        self._file_count = 0
        self._read(self.path, None, (), ())

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(self._aliases)

    def _read(self, path: Path, initial_patterns: tuple[str, ...] | None,
              guards: tuple[tuple[str, ...], ...], ancestors: tuple[Path, ...]) -> None:
        try:
            resolved = path.resolve(strict=True)
            size = resolved.stat().st_size
        except OSError as exc:
            raise ProfileImportError(f"Не удалось открыть SSH config: {path}") from exc
        if resolved in ancestors:
            raise ProfileImportError(f"Циклический Include в SSH config: {resolved.name}")
        if len(ancestors) >= _MAX_DEPTH or self._file_count >= _MAX_FILES:
            raise ProfileImportError("Слишком много вложенных SSH-конфигураций")
        self._file_count += 1
        if size > _MAX_FILE_BYTES or self._total_bytes + size > _MAX_TOTAL_BYTES:
            raise ProfileImportError("SSH config слишком большой для импорта")
        try:
            with resolved.open("rb") as stream:
                data = stream.read(_MAX_FILE_BYTES + 1)
            contents = data.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ProfileImportError(f"Не удалось прочитать SSH config: {resolved.name}") from exc
        self._total_bytes += len(data)
        if len(data) > _MAX_FILE_BYTES or self._total_bytes > _MAX_TOTAL_BYTES:
            raise ProfileImportError("SSH config слишком большой для импорта")
        if "\x00" in contents:
            raise ProfileImportError(f"Недопустимый символ в SSH config: {resolved.name}")
        patterns = initial_patterns
        for line_number, raw in enumerate(contents.splitlines(), 1):
            try:
                words = _config_words(raw)
            except ValueError as exc:
                raise ProfileImportError(f"Ошибка синтаксиса {resolved.name}:{line_number}: {exc}") from exc
            if not words:
                continue
            first = words[0]
            if "=" in first:
                keyword, first_value = first.split("=", 1)
                values = ([first_value] if first_value else []) + words[1:]
            else:
                keyword = first
                values = words[1:]
                if values and values[0].startswith("="):
                    first_value = values[0][1:]
                    values = ([first_value] if first_value else []) + values[1:]
            key = keyword.lower()
            if not key or not values:
                raise ProfileImportError(f"Пустая настройка SSH в {resolved.name}:{line_number}")
            if key == "host":
                patterns = tuple(values)
                for alias in values:
                    if (_ALIASES.fullmatch(alias) and alias not in self._aliases and
                            all(_matches(guard, alias) for guard in guards)):
                        self._aliases.append(alias)
                continue
            if key == "match":
                self._global_errors.append(
                    f"Match ({resolved.name}:{line_number}) требует ручной настройки: Connect не выполняет Match exec"
                )
                patterns = ()  # Do not accidentally inherit options from a Match block.
                continue
            if key == "include":
                for value in values:
                    if "%" in value:
                        raise ProfileImportError(
                            f"Include с %-токеном не поддерживается ({resolved.name}:{line_number})"
                        )
                    try:
                        include = Path(value).expanduser()
                    except RuntimeError as exc:
                        raise ProfileImportError(
                            f"Не удалось раскрыть Include ({resolved.name}:{line_number})"
                        ) from exc
                    if not include.is_absolute():
                        include = resolved.parent / include
                    for name in sorted(glob.glob(str(include))):
                        child_guards = guards + ((patterns,) if patterns is not None else ())
                        self._read(Path(name), patterns, child_guards, ancestors + (resolved,))
                continue
            self._entries.append(_Entry(patterns, guards, key, " ".join(values), str(resolved), line_number))

    def _node(self, alias: str) -> _Node:
        selected: dict[str, _Entry] = {}
        identities: list[_Entry] = []
        warnings: list[str] = []
        errors: list[str] = list(self._global_errors)
        for entry in self._entries:
            if not _matches(entry.patterns, alias) or not all(_matches(guard, alias) for guard in entry.guards):
                continue
            if entry.key == "identityfile":
                identities.append(entry)
            elif entry.key in _SUPPORTED:
                selected.setdefault(entry.key, entry)
            elif entry.key in _ROUTE_BLOCKERS:
                errors.append(f"{entry.key} ({entry.location}) меняет маршрут; заполните соединение вручную")
            else:
                warnings.append(f"{entry.key} ({entry.location}) не переносится в Connect")
        if len(identities) > 1:
            errors.append("Несколько IdentityFile не поддерживаются; выберите один ключ вручную")
        identity_policy = (selected["identitiesonly"].value.strip().lower()
                           if "identitiesonly" in selected else "no")
        if identity_policy not in {"yes", "no"}:
            errors.append("IdentitiesOnly должен быть yes или no")
        elif identities and identity_policy != "yes":
            warnings.append("Connect использует только выбранный IdentityFile и не перебирает другие ключи агента")
        elif not identities and identity_policy == "yes":
            warnings.append("IdentitiesOnly yes без IdentityFile не переносится в Connect")
        def value(key: str, default: str) -> str:
            return selected[key].value if key in selected else default
        host = value("hostname", alias)
        user = value("user", getpass.getuser())
        port_text = value("port", "22")
        try:
            # HostName can refer to the original alias. Other fields use the
            # resulting destination, matching the useful subset of SSH tokens.
            host = _expand(host, alias=alias, host=alias, user=user, port=22)
            user = _expand(user, alias=alias, host=host, user=user, port=22)
            port = int(_expand(port_text, alias=alias, host=host, user=user, port=22))
            identity = (_expand(identities[0].value, alias=alias, host=host, user=user, port=port)
                        if len(identities) == 1 else None)
            host_key_alias = (_expand(selected["hostkeyalias"].value, alias=alias, host=host,
                                      user=user, port=port) if "hostkeyalias" in selected else None)
            proxyjump = value("proxyjump", "") or None
            if proxyjump:
                proxyjump = _expand(proxyjump, alias=alias, host=host, user=user, port=port)
        except (ValueError, ProfileImportError) as exc:
            errors.append(f"Некорректная настройка Host {alias}: {exc}")
            port, identity, host_key_alias, proxyjump = 22, None, None, None
        if identity == "none":
            errors.append("IdentityFile none нельзя точно перенести; выберите ключ вручную")
            identity = None
        return _Node(host, user, port, identity, proxyjump, host_key_alias,
                     tuple(dict.fromkeys(warnings)), tuple(dict.fromkeys(errors)))

    def profile(self, alias: str) -> ImportedProfile:
        if alias not in self._aliases:
            raise ProfileImportError(f"Неизвестный Host: {alias}")
        target = self._node(alias)
        warnings = list(target.warnings)
        errors = list(target.errors)
        jump_host = jump_user = jump_identity = jump_host_key_alias = None
        jump_port = 22
        if target.proxyjump and target.proxyjump.lower() != "none":
            if "," in target.proxyjump:
                errors.append("Цепочка ProxyJump из нескольких хостов пока не поддерживается")
            else:
                match = _JUMP.fullmatch(target.proxyjump)
                if match is None:
                    errors.append("ProxyJump имеет неподдерживаемый формат")
                else:
                    jump_name = match.group("host")
                    node = self._node(jump_name)
                    warnings.extend(f"Переход: {warning}" for warning in node.warnings)
                    errors.extend(f"Переход: {error}" for error in node.errors)
                    if node.proxyjump and node.proxyjump.lower() != "none":
                        errors.append("Вложенный ProxyJump пока не поддерживается")
                    jump_host = node.host
                    jump_user = match.group("user") or node.user
                    jump_port = int(match.group("port")) if match.group("port") else node.port
                    jump_identity = node.identity
                    jump_host_key_alias = node.host_key_alias
        connection = None
        if not errors:
            try:
                connection = ConnectionOptions(
                    host=target.host, user=target.user, port=target.port,
                    identity=target.identity, host_key_alias=target.host_key_alias,
                    jump_host=jump_host, jump_user=jump_user, jump_port=jump_port,
                    jump_identity=jump_identity, jump_host_key_alias=jump_host_key_alias,
                ).validated()
            except (ValueError, OSError) as exc:
                errors.append(f"Профиль нельзя применить: {exc}")
        return ImportedProfile(alias, connection, tuple(dict.fromkeys(warnings)),
                               tuple(dict.fromkeys(errors)))
