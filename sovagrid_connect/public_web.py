# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Fixed, source-verified HTTPS administration over the existing SSH transport."""
from __future__ import annotations

import ipaddress
import json
import re
import time

from .agent_rpc import AgentRPC, RPCError, _REMOTE_COMMON

MAX_WIRE = 4096
HELPER = "sovagrid-blueprint/deploy/public_web.py"
DEFAULT_PANEL_PATH = "/sovagrid/monitoring/"
ROOT_BEHAVIORS = frozenset(("untouched", "panel", "redirect", "not_found"))
_PANEL_PATH = re.compile(r"/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/){1,3}\Z")
ERRORS = {
    "INVALID_REQUEST": "Проверьте IP или домен без протокола и порта, а путь панели укажите отдельно в виде /sovagrid/monitoring/.",
    "UNMANAGED": "Нужна исправная установка SovaGrid под управлением установщика.",
    "SOURCE_UNTRUSTED": "Не удалось подтвердить HTTPS-установщик. Обновите Hub проверенным серверным пакетом.",
    "SOURCE_CHANGED": "Серверный пакет изменился. Повторите проверку; при необходимости обновите Hub.",
    "STALE_PREVIEW": "Серверный пакет изменился после проверки. Повторите проверку HTTPS.",
    "STATE_UNTRUSTED": "Настройки публичного доступа изменены вне SovaGrid. Автоматическое изменение остановлено.",
    "STATE_CHANGED": "Настройки изменились. Повторите предварительную проверку HTTPS.",
    "ADDRESS_NOT_LOCAL": "IP должен принадлежать этому серверу; DNS домена должен указывать на его публичный IP.",
    "IPV6_UNAVAILABLE": "Публичный доступ этой установки работает по IPv4. Используйте IPv4 или домен без AAAA.",
    "PORT_BUSY": "Порт 80 или 443 занят другой службой. Изменение настроек остановлено.",
    "COMMAND_FAILED": "Не удалось проверить или применить настройки Web. Повторите проверку состояния.",
    "LOCAL_UNHEALTHY": "Локальные каналы Web или Agent не отвечают. Повторите проверку состояния.",
    "PUBLIC_UNHEALTHY": "Не удалось подтвердить публичную панель и сертификат. Проверьте DNS и доступность портов 80 и 443.",
    "ROLLBACK_FAILED": "Не удалось подтвердить восстановление Web. Повторите проверку перед дальнейшими действиями.",
    "ROOT_REQUIRED": "Нужен SSH-вход root или пользователь с sudo без запроса пароля.",
    "UNSUPPORTED_PLATFORM": "Нужен Ubuntu 22.04, 24.04 или 26.04 с Python 3.10 или новее.",
    "UNSUPPORTED_SYSTEMD": "На сервере недоступна необходимая служба systemd.",
    "INVALID_REPLY": "Не удалось подтвердить ответ сервера. Повторите проверку HTTPS.",
    "SSH_FAILED": "SSH-соединение не подтвердило действие. Повторите проверку состояния.",
    "TIMEOUT": "Сервер не ответил вовремя. Изменение могло завершиться; повторите проверку состояния.",
    "CANCELLED": "Действие прервано. Изменение на сервере могло завершиться; повторите проверку состояния.",
    "CLEANUP_REQUIRED": "Завершение SSH-подключения не подтверждено. Повторите проверку состояния.",
    "BUSY": "Дождитесь завершения текущего действия HTTPS.",
}
REMOTE_ERRORS = frozenset(("INVALID_REQUEST", "UNMANAGED", "SOURCE_UNTRUSTED", "SOURCE_CHANGED",
    "STALE_PREVIEW", "STATE_UNTRUSTED", "STATE_CHANGED", "ADDRESS_NOT_LOCAL", "IPV6_UNAVAILABLE", "PORT_BUSY",
    "COMMAND_FAILED", "LOCAL_UNHEALTHY", "PUBLIC_UNHEALTHY", "ROLLBACK_FAILED", "BUSY", "ROOT_REQUIRED"))


class PublicWebError(RuntimeError):
    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in ERRORS else "INVALID_REPLY"
        super().__init__(ERRORS[self.code])


def _require(condition, code="INVALID_REPLY"):
    if not condition:
        raise PublicWebError(code)


def _hash(value, *, nullable=False, code="INVALID_REPLY"):
    _require(nullable and value is None or isinstance(value, str)
             and re.fullmatch(r"[0-9a-f]{64}", value) is not None, code)
    return value


def validate_config(value, *, code="INVALID_REQUEST", allow_staging=False):
    required = {"mode", "address", "acme_environment"}
    _require(isinstance(value, dict) and required <= set(value)
             and set(value) <= required | {"panel_path", "root_behavior"}, code)
    mode, address = value["mode"], value["address"]
    panel_path = value.get("panel_path", DEFAULT_PANEL_PATH)
    root_behavior = value.get("root_behavior", "panel")
    _require(isinstance(panel_path, str) and len(panel_path) <= 96
             and _PANEL_PATH.fullmatch(panel_path) is not None
             and panel_path.split("/")[1] not in ("api", "healthz")
             and isinstance(root_behavior, str) and root_behavior in ROOT_BEHAVIORS, code)
    _require(isinstance(mode, str) and mode in ("ip", "dns") and isinstance(address, str)
             and 1 <= len(address) <= 253 and isinstance(value["acme_environment"], str)
             and value["acme_environment"] in (("production", "staging") if allow_staging else ("production",)), code)
    if mode == "ip":
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise PublicWebError(code) from None
        _require(ip.is_global and not ip.is_multicast and not getattr(ip, "ipv4_mapped", None)
                 and "%" not in address and ip.compressed == address, code)
    else:
        labels = address.split(".")
        _require(address.isascii() and address == address.lower() and len(labels) >= 2
                 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
                 and re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1]) is not None
                 and not address.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".example")), code)
    return {"mode": mode, "address": address, "acme_environment": value["acme_environment"],
            "panel_path": panel_path, "root_behavior": root_behavior}


def config_for_address(address, *, panel_path=DEFAULT_PANEL_PATH, root_behavior="untouched"):
    """Normalize only a user's address field, never an untrusted reply."""
    _require(isinstance(address, str), "INVALID_REQUEST")
    address = address.strip()
    try:
        address = ipaddress.ip_address(address).compressed
        mode = "ip"
    except ValueError:
        mode, address = "dns", address.lower()
    return validate_config({"mode": mode, "address": address, "acme_environment": "production",
                            "panel_path": panel_path, "root_behavior": root_behavior})


def public_url(config):
    # Saved diagnostic state can be shown and explicitly disabled. Accepting
    # its address here does not authorize a staging preview or apply request.
    config = validate_config(config, allow_staging=True)
    address = config["address"]
    return "https://" + ("[" + address + "]" if ":" in address else address)


def public_panel_url(config):
    config = validate_config(config, allow_staging=True)
    return public_url(config) + config["panel_path"]


def _request(action, payload):
    fields = {"status": set(), "preview": {"config"},
        "apply": {"config", "expected_state_sha256", "source_manifest_sha256"},
        "disable": {"expected_state_sha256"}}
    _require(isinstance(action, str) and action in fields and isinstance(payload, dict)
             and set(payload) == fields[action], "INVALID_REQUEST")
    clean = {}
    if "config" in payload:
        clean["config"] = validate_config(payload["config"])
    if "expected_state_sha256" in payload:
        clean["expected_state_sha256"] = _hash(payload["expected_state_sha256"], nullable=True, code="INVALID_REQUEST")
    if "source_manifest_sha256" in payload:
        clean["source_manifest_sha256"] = _hash(payload["source_manifest_sha256"], code="INVALID_REQUEST")
    return clean


# Reuse the trusted bootstrap shipped inside Connect. source() verifies the
# complete root-owned five-component tree before ANY remote helper is compiled.
# Keep a manifest snapshot across that verification and bind the exact bytes
# being compiled to its hash, including during a concurrent managed update.
_PUBLIC_SCRIPT = _REMOTE_COMMON + r'''
# SOVAGRID_PUBLIC_WEB_RPC_V1
def public_failure(code):
    emit({'protocol':1,'ok':False,'error':{'code':code,'message':''}})
try:
    root()
    incoming=sys.stdin.buffer.read(4097); need(len(incoming)<=4096,'INVALID_REQUEST')
    request=parse(incoming); exact(request,{'action','payload'})
    operation=request['action']; payload=request['payload']
    need(isinstance(operation,str) and operation in ('status','preview','apply','disable'),'INVALID_REQUEST')
    fields={'status':set(),'preview':{'config'},'apply':{'config','expected_state_sha256','source_manifest_sha256'},'disable':{'expected_state_sha256'}}
    exact(payload,fields[operation])
    source_root='/opt/sovagrid-src'
    manifest_raw=read(source_root+'/sovagrid-bundle.json',524288)
    pins=manifest(manifest_raw); manifest_sha=hashlib.sha256(manifest_raw).hexdigest()
    source(source_root,expected_manifest=manifest_sha,caller_manifest=payload.get('source_manifest_sha256'))
    relative='sovagrid-blueprint/deploy/public_web.py'
    need(relative in pins['sha256'])
    fixed=source_root+'/'+relative
    verified=read(fixed,1048576)
    need(hashlib.sha256(verified).hexdigest()==pins['sha256'][relative],'SOURCE_CHANGED')
    need(hashlib.sha256(read(source_root+'/sovagrid-bundle.json',524288)).hexdigest()==manifest_sha,'SOURCE_CHANGED')
    namespace={'__name__':'sovagrid_verified_public_web','__file__':fixed}
    exec(compile(verified,fixed,'exec'),namespace)
    sys.argv=[fixed,operation]
    sys.stdin=io.TextIOWrapper(io.BytesIO(json.dumps(payload,separators=(',',':')).encode()))
    sys.exit(namespace['main']())
except Stop as error: public_failure(error.code); sys.exit(1)
except SystemExit: raise
except Exception: public_failure('SOURCE_UNTRUSTED'); sys.exit(1)
'''


def _decode(action, raw, status, request):
    try:
        def pairs(items):
            value = {}
            for key, item in items:
                _require(key not in value)
                value[key] = item
            return value
        _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_WIRE)
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _value: (_ for _ in ()).throw(PublicWebError("INVALID_REPLY")))
        _require(isinstance(value, dict) and type(value.get("protocol")) is int and value["protocol"] == 1
                 and type(value.get("ok")) is bool)
        if value["ok"] is False:
            _require(set(value) == {"protocol", "ok", "error"} and isinstance(value["error"], dict)
                     and set(value["error"]) == {"code", "message"})
            error = value["error"]
            _require(isinstance(error["code"], str) and error["code"] in REMOTE_ERRORS
                     and isinstance(error["message"], str))
            raise PublicWebError(error["code"])
        _require(status == 0)
        common = {"protocol", "ok", "expected_state_sha256"}
        if action == "status":
            _require(set(value) == common | {"enabled", "config"} and type(value["enabled"]) is bool)
            if value["enabled"]:
                validate_config(value["config"], code="INVALID_REPLY", allow_staging=True)
                _hash(value["expected_state_sha256"])
            else:
                _require(value["config"] is None and value["expected_state_sha256"] is None)
        elif action in ("preview", "apply"):
            fields = common | {"config", "source_manifest_sha256", "changed", "url", "certificate_verified"}
            _require(set(value) == fields | ({"enabled"} if action == "apply" else set()))
            config = validate_config(value["config"], code="INVALID_REPLY")
            _require(config == request["config"] and type(value["changed"]) is bool
                     and value["url"] == public_url(config)
                     and type(value["certificate_verified"]) is bool
                     and value["certificate_verified"] == (action == "apply"))
            _hash(value["source_manifest_sha256"])
            _hash(value["expected_state_sha256"], nullable=action == "preview")
            if action == "apply":
                _require(value["enabled"] is True and value["source_manifest_sha256"] == request["source_manifest_sha256"])
        elif action == "disable":
            _require(set(value) == common | {"enabled", "changed"} and value["enabled"] is False
                     and type(value["changed"]) is bool and value["expected_state_sha256"] is None)
        else:
            raise PublicWebError("INVALID_REPLY")
        return value
    except (ValueError, UnicodeError, RecursionError, TypeError, KeyError):
        raise PublicWebError("INVALID_REPLY") from None


class PublicWebRPC:
    """Compatibility adapter over AgentRPC's bounded, cancellable SSH channel.

    Only the private transport lifecycle is shared. AgentRPC.call() and its
    enrollment action gates are unchanged; HTTPS has its own fixed script and
    strict four-action public-only protocol.
    """
    def __init__(self, options, *, progress=None, transport=None):
        self._progress = progress or (lambda _text: None)
        self._transport = transport if transport is not None else AgentRPC(options, role="hub", progress=self._progress)

    def cancel(self):
        self._transport.cancel()

    def _call(self, action, payload):
        payload = _request(action, payload)
        transport = self._transport
        try:
            with transport._operation():
                raw = json.dumps({"action": action, "payload": payload}, separators=(",", ":"), ensure_ascii=True).encode()
                _require(len(raw) <= MAX_WIRE, "INVALID_REQUEST")
                budget = {"status": 90, "preview": 90, "apply": 600, "disable": 300}[action]
                deadline = time.monotonic() + budget
                transport._ready()
                remaining = min(budget, deadline - time.monotonic())
                _require(remaining > 0, "TIMEOUT")
                result, status = transport._exchange(_PUBLIC_SCRIPT, (raw,), remaining)
                value = _decode(action, result, status, payload)
                transport._check_cancelled()
                return value
        except RPCError as error:
            raise PublicWebError(error.code) from None

    def status(self):
        self._progress("Проверяем текущий публичный доступ по SSH…")
        return self._call("status", {})

    def preview(self, config):
        config = validate_config(config)
        self._progress("Проверяем адрес, порты и установленный серверный пакет…")
        return self._call("preview", {"config": config})

    def apply(self, config, *, expected_state_sha256, source_manifest_sha256):
        payload = {"config": validate_config(config),
            "expected_state_sha256": _hash(expected_state_sha256, nullable=True, code="INVALID_REQUEST"),
            "source_manifest_sha256": _hash(source_manifest_sha256, code="INVALID_REQUEST")}
        self._progress("Настраиваем HTTPS и ждём подтверждения публичного сертификата. Это может занять несколько минут…")
        return self._call("apply", payload)

    def disable(self, *, expected_state_sha256):
        payload = {"expected_state_sha256": _hash(expected_state_sha256, nullable=True, code="INVALID_REQUEST")}
        self._progress("Отключаем публичный адрес и проверяем локальный доступ…")
        return self._call("disable", payload)
