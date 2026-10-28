# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Reviewed, recoverable feature changes on a separately enrolled Ubuntu Agent."""
from __future__ import annotations

from contextlib import contextmanager
import copy
import tarfile
import threading
import time
import uuid

from .agent_enrollment import source_bundle, _connection, EnrollmentError
from .agent_rpc import AgentRPC, RPCError
from .core import ConnectionOptions
from .enrollment_api import EnrollmentAPIError
from .enrollment_journal import EnrollmentJournalError
from .enrollment_protocol import canonical_uuid, validate_features, ProtocolError
from .remote_feature_api import RemoteFeatureAPI
from .remote_feature_journal import FeatureJournal

MODULE = "sovagrid-blueprint/deploy/agent_features.py"
MARKER = b"SOVAGRID_REMOTE_AGENT_FEATURES_V1"


class FeatureError(RuntimeError):
    pass


class FeatureCancelled(FeatureError):
    pass


def feature_bundle(path):
    selected, summary = source_bundle(path)
    try:
        with tarfile.open(selected["path"], "r:gz") as archive:
            member = archive.getmember(MODULE)
            if not member.isfile() or member.size > 256 * 1024:
                raise ValueError
            with archive.extractfile(member) as stream:
                if MARKER not in stream.read(32768):
                    raise ValueError
    except (KeyError, ValueError, OSError, tarfile.TarError):
        raise FeatureError("Выберите новый проверенный пакет с мастером функций удалённого Agent.") from None
    return selected, summary


def stable_connection(value):
    return {key: item for key, item in value.items() if key not in ("identity", "jump_identity", "local_port")}


class RemoteAgentFeatures:
    def __init__(self, tunnel, *, progress=None, api_factory=RemoteFeatureAPI, rpc_factory=AgentRPC, journal=None):
        self.tunnel = tunnel
        self.progress = progress or (lambda _message: None)
        self.api = api_factory(tunnel)
        self.rpc_factory = rpc_factory
        self.journal = journal if journal is not None else FeatureJournal()
        self._stop = threading.Event()
        self._operation_lock = threading.RLock()
        self._logged_in = False
        self._servers = []
        self._reviewed = False
        self.record = None
        self.target = self.stage = self.status = self.policy = self.registration = None
        self._summary = None
        self._pending_desired = None

    def _guard(self):
        if self._stop.is_set():
            raise FeatureCancelled("Действие остановлено. Изменения могли завершиться; проверьте обе машины заново.")
        if not self.tunnel.alive:
            raise FeatureError("SSH-соединение с Hub закрыто. Подключитесь снова и проверьте состояние.")

    @contextmanager
    def _operation(self, credentials=None):
        if not self._operation_lock.acquire(blocking=False):
            if isinstance(credentials, dict):
                credentials.clear()
            raise FeatureError("Дождитесь завершения текущего действия Agent.")
        try:
            self._guard()
            yield
        except (EnrollmentAPIError, EnrollmentError, EnrollmentJournalError, RPCError) as error:
            # These classes expose only fixed local messages, never raw SSH/API.
            raise FeatureError(str(error)) from None
        except ProtocolError:
            raise FeatureError("Не удалось подтвердить параметры функций Agent.") from None
        finally:
            if isinstance(credentials, dict):
                credentials.clear()
            self._operation_lock.release()

    def _login(self, username, password, credentials):
        if credentials is not None:
            if type(credentials) is not dict or set(credentials) != {"username", "password"}:
                raise FeatureError("Введите логин и пароль администратора Hub.")
            username = credentials.pop("username"); password = credentials.pop("password")
        try:
            if username is not None or password is not None:
                self.api.login(username, password)
                self._logged_in = True
            elif not self._logged_in:
                raise FeatureError("Войдите в Hub, чтобы получить список удалённых Agent.")
        finally:
            password = None
            if credentials is not None:
                credentials.clear()

    def list_servers(self, username=None, password=None, credentials=None):
        with self._operation(credentials):
            self._login(username, password, credentials)
            self._servers = self.api.list_servers()
            self._guard()
            return copy.deepcopy(self._servers)

    def _save(self, **changes):
        self.record = self.journal.update(self.record["request_id"], changes, expected_revision=self.record["revision"])

    def _cleanup_record(self, record):
        if record["stage"] is not None:
            try:
                owned = self.target.recover_stage(record["stage"], for_cleanup=True)
                self.target.cleanup_stage(owned)
            except RPCError as error:
                if error.code != "STAGE_NOT_FOUND":
                    raise
        self.journal.remove(record["request_id"], record["revision"])

    def _previous(self, target_connection, server_id):
        selected_hub = stable_connection(_connection(self.tunnel.options))
        records = [record for record in self.journal.list()
                   if record["server_id"] == server_id
                   and stable_connection(record["hub_connection"]) == selected_hub
                   and stable_connection(record["target_connection"]) == stable_connection(target_connection)]
        for record in sorted(records, key=lambda row: (row["updated_at"], row["request_id"])):
            if (record["recovery_intent"] or record["phase"] not in ("prepared", "completed")) and record["features"] is not None:
                self._pending_desired = dict(record["features"])
        return records

    def _checkpoint(self, descriptor):
        self._save(stage=descriptor)

    def _call(self, action, **payload):
        self._guard()
        result = self.target.call(action, {"protocol": 1, "server_id": self.record["server_id"], **payload}, stage=self.stage)
        self._guard()
        if result["source_manifest_sha256"] != self.stage.source_manifest_sha256:
            raise FeatureError("Временный проверенный пакет изменился. Подготовьте план заново.")
        identity = result["identity"]
        if self.record["identity"] is not None and identity != self.record["identity"]:
            raise FeatureError("На целевом сервере найден другой Agent. Продолжение остановлено.")
        return result

    def _bind_hub(self, status, policy, registration):
        identity = status["identity"]
        if (any(policy[key] != identity[key] for key in ("server_id", "enrollment_id", "agent_token_sha256"))
                or registration is None or registration["state"] != "active"
                or registration["id"] != identity["enrollment_id"] or registration["server_id"] != identity["server_id"]):
            raise FeatureError("Hub и SSH-сервер не подтвердили одну и ту же активную установку Agent.")

    def _info(self, desired=None, *, changed=None):
        desired = desired if desired is not None else self.status["current"]
        name = next((row["name"] for row in self._servers if row["id"] == self.record["server_id"]), self.registration["name"])
        return copy.deepcopy({"server_id": self.record["server_id"], "name": name,
            "current": self.status["current"], "desired": desired,
            "hub": {"enabled": self.policy["enabled"], "revision": self.policy["revision"]},
            "identity": self.status["identity"], "bundle": self.record["bundle"],
            "source_commits": self._summary.commits, "platform": self._platform,
            "change_required": bool(changed) if changed is not None else
                self.status["current"] != desired or self.policy["enabled"] != desired["commands"] or self.status["recovery_required"],
            "recovery_required": self.status["recovery_required"] or self._pending_desired is not None})

    def prepare(self, *, target_options, server_id, bundle, username=None, password=None, credentials=None):
        with self._operation(credentials):
            self._reviewed = False
            canonical_uuid(server_id)
            selected, summary = feature_bundle(bundle)
            connection = _connection(target_options)
            self._login(username, password, credentials); password = None
            policy = self.api.management(server_id)
            if self.target is not None:
                self.target.cancel()
            self.target = self.rpc_factory(ConnectionOptions(**connection), role="target", progress=self.progress)
            self.progress("Проверяем SSH и установленный удалённый Agent…")
            self._platform = self.target.preflight()
            self._pending_desired = None
            previous = self._previous(connection, server_id)
            self.record = None; self.stage = None
            self.record = self.journal.create({"protocol": 1, "request_id": str(uuid.uuid4()), "server_id": server_id,
                "hub_connection": _connection(self.tunnel.options), "target_connection": connection,
                "bundle": selected, "stage": None, "identity": None, "features": self._pending_desired,
                "phase": "prepared", "hub_revision": None, "recovery_intent": self._pending_desired is not None})
            # An interrupted disabling intent must survive another read-only
            # prepare/cancel. Adopt it durably before removing its old record.
            for record in previous:
                self._cleanup_record(record)  # Only a verified, owned temporary source.
            self.progress("Передаём проверенный временный пакет для проверки функций…")
            self.stage = self.target.stage_target(selected["path"], selected["sha256"], checkpoint=self._checkpoint)
            self._summary = summary
            status = self._call("target-features-status")
            registration = self.api.get(status["identity"]["enrollment_id"])
            self._bind_hub(status, policy, registration)
            self._save(identity=status["identity"])
            self.status, self.policy, self.registration = status, policy, registration
            self._guard()
            desired = status["pending_features"] or self._pending_desired or status["current"]
            return self._info(desired)

    def preview(self, features):
        with self._operation():
            self._reviewed = False
            if self.record is None or self.stage is None:
                raise FeatureError("Сначала проверьте SSH-сервер и выберите пакет.")
            if self.record["phase"] != "prepared":
                raise FeatureError("После прерванного изменения сначала повторите проверку SSH-сервера.")
            desired = validate_features(features)
            policy = self.api.management(self.record["server_id"])
            status = self._call("target-features-preview", features=desired)
            registration = self.api.get(status["identity"]["enrollment_id"])
            self._bind_hub(status, policy, registration)
            self.status, self.policy, self.registration = status, policy, registration
            self._save(features=desired)
            self._guard(); self._reviewed = True
            return self._info(desired, changed=status["changed"] or policy["enabled"] != desired["commands"]
                              or self._pending_desired is not None)

    def apply(self):
        with self._operation():
            if not self._reviewed or self.record is None or self.record["features"] is None:
                raise FeatureError("Сначала проверьте план изменения функций Agent.")
            self._reviewed = False
            desired = dict(self.record["features"])
            policy, status = copy.deepcopy(self.policy), copy.deepcopy(self.status)
            try:
                # Recheck both sides against the exact reviewed snapshots.
                current_policy = self.api.management(self.record["server_id"])
                current_status = self._call("target-features-preview", features=desired)
                if current_policy != policy or current_status != status:
                    raise FeatureError("Настройки Agent изменились после просмотра плана. Повторите проверку.")
                registration = self.api.get(status["identity"]["enrollment_id"])
                self._bind_hub(status, policy, registration)
                self._save(phase="gate_closing", hub_revision=policy["revision"])
                self.progress("Закрываем управление в Hub на время изменения Agent…")
                closed = self.api.set_management(policy, False)
                self._save(phase="gate_closed", hub_revision=closed["revision"])
                self._guard()
                self._save(phase="target_applying")
                self.progress("Применяем подтверждённые функции и проверяем службы Agent…")
                applied = self._call("target-features-apply", features=desired, expected=status["expected"],
                    enrollment_id=status["identity"]["enrollment_id"], agent_token_sha256=status["identity"]["agent_token_sha256"])
                self._save(phase="target_applied")
                self._guard()
                baseline = self.api.get(applied["identity"]["enrollment_id"])
                self._bind_hub(applied, closed, baseline)
                old_seen = baseline["last_seen"] or 0
                self._save(phase="gate_opening")
                policy = self.api.set_management(closed, desired["commands"])
                self._save(hub_revision=policy["revision"])
                self.progress("Ждём новое измерение, чтобы подтвердить связь после изменения…")
                deadline = time.monotonic() + 120
                while True:
                    self._guard()
                    row = self.api.get(applied["identity"]["enrollment_id"])
                    self._bind_hub(applied, policy, row)
                    if row["last_seen"] is not None and row["last_seen"] > old_seen:
                        break
                    if time.monotonic() >= deadline:
                        raise FeatureError("Настройки применены, но новое измерение ещё не подтверждено. Проверьте состояние заново.")
                    self._stop.wait(1)
                confirmed = self._call("target-features-status")
                final_policy = self.api.management(self.record["server_id"])
                self._bind_hub(confirmed, final_policy, row)
                if final_policy != policy or any(confirmed[key] != applied[key] for key in (
                        "identity", "current", "expected", "source_manifest_sha256", "recovery_required", "pending_features", "services")):
                    raise FeatureError("Функции или разрешения изменились при итоговой проверке. Проверьте фактическое состояние заново.")
                self.status, self.policy, self.registration = confirmed, final_policy, row
                self._pending_desired = None
                self._save(phase="completed", recovery_intent=False)
            except BaseException:
                try:
                    if self.record["phase"] != "prepared":
                        self._save(phase="uncertain")
                except EnrollmentJournalError:
                    pass
                raise
            cleanup_required = False
            try:
                self.target.cleanup_stage(self.stage)
                self._save(stage=None)
                self.journal.remove(self.record["request_id"], self.record["revision"])
                self.stage = None
            except (RPCError, EnrollmentJournalError):
                cleanup_required = True
            result = self._info(desired, changed=False)
            result.update(applied=True, fresh_metric_verified=True, cleanup_required=cleanup_required)
            self.progress("Функции Agent подтверждены. Пользовательские файлы и служебный туннель сохранены.")
            return result

    def cancel(self):
        self._stop.set()
        if self.target is not None:
            self.target.cancel()

    def close(self):
        self.cancel()
        self.api.logout()
