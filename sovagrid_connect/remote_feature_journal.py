# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Nonsecret feature-operation checkpoints using the private enrollment store."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import time

from . import enrollment_journal as storage
from .enrollment_protocol import (validate_feature_identity, validate_features,
                                  validate_stage_descriptor, ProtocolError)
from .theme import preference_file

FIELDS = {"protocol", "request_id", "server_id", "hub_connection", "target_connection", "bundle",
          "stage", "identity", "features", "phase", "hub_revision", "recovery_intent"}
PHASES = {"prepared", "gate_closing", "gate_closed", "target_applying", "target_applied", "gate_opening", "completed", "uncertain"}


def record(value):
    storage._exact(value, FIELDS | {"revision", "created_at", "updated_at"})
    storage._require(type(value["protocol"]) is int and value["protocol"] == 1)
    storage._uuid(value["request_id"]); storage._uuid(value["server_id"])
    storage._connection(value["hub_connection"]); storage._connection(value["target_connection"])
    storage._exact(value["bundle"], {"path", "sha256"})
    storage._path(value["bundle"]["path"])
    storage._require(isinstance(value["bundle"]["sha256"], str) and storage.SHA.fullmatch(value["bundle"]["sha256"]))
    storage._require(isinstance(value["phase"], str) and value["phase"] in PHASES)
    storage._require(type(value["recovery_intent"]) is bool)
    storage._require(not value["recovery_intent"] or value["features"] is not None)
    for key in ("revision", "created_at", "updated_at"):
        storage._require(type(value[key]) is int and 1 <= value[key] <= 2**63 - 1)
    storage._require(value["updated_at"] >= value["created_at"])
    storage._require(value["hub_revision"] is None or type(value["hub_revision"]) is int and 0 <= value["hub_revision"] <= 2**63 - 1)
    try:
        if value["stage"] is not None:
            validate_stage_descriptor(value["stage"])
        if value["identity"] is not None:
            validate_feature_identity(value["identity"])
            storage._require(value["identity"]["server_id"] == value["server_id"])
        if value["features"] is not None:
            validate_features(value["features"])
        if value["phase"] not in ("prepared", "uncertain"):
            storage._require(value["identity"] is not None and value["features"] is not None)
    except ProtocolError:
        storage._require(False)
    storage._encoded(value)
    return copy.deepcopy(value)


class FeatureJournal(storage.EnrollmentJournal):
    """Independent namespace; no existing enrollment record is edited."""
    def __init__(self, root: Path | None = None):
        super().__init__(root if root is not None else preference_file().parent / "agent-features")

    def _read(self, request_id):
        path = self.root / (storage._uuid(request_id) + ".json")
        try:
            fd = self._open(path)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as stream:
            storage._require(os.fstat(stream.fileno()).st_size <= storage.MAX_BYTES)
            raw = stream.read(storage.MAX_BYTES + 1)
        storage._require(len(raw) <= storage.MAX_BYTES)
        try:
            value = record(json.loads(raw, object_pairs_hook=storage._object))
        except (ValueError, UnicodeError, RecursionError, KeyError, TypeError):
            storage._require(False)
        storage._require(value["request_id"] == request_id)
        return value

    def create(self, details):
        storage._exact(details, FIELDS)
        now = max(1, int(time.time()))
        value = record(dict(details, revision=1, created_at=now, updated_at=now))
        with self._locked():
            if self._read(value["request_id"]) is not None or len(self._ids()) >= storage.MAX_RECORDS:
                raise storage.EnrollmentJournalConflict("Журнал действий Agent заполнен или действие уже сохранено.")
            self._write(value)
        return copy.deepcopy(value)

    def update(self, request_id, changes, expected_revision):
        storage._uuid(request_id); self._revision(expected_revision)
        storage._require(type(changes) is dict and set(changes) <= FIELDS)
        with self._locked():
            previous = self._read(request_id)
            if previous is None or previous["revision"] != expected_revision:
                raise storage.EnrollmentJournalConflict("Сохранённое действие Agent изменилось. Повторите проверку.")
            current = record(dict(previous, **changes, revision=expected_revision + 1,
                                  updated_at=max(previous["updated_at"], int(time.time()))))
            for key in ("protocol", "request_id", "server_id", "hub_connection", "target_connection", "bundle"):
                storage._require(current[key] == previous[key])
            if previous["identity"] is not None:
                storage._require(current["identity"] == previous["identity"])
            if previous["phase"] != "prepared" and previous["features"] is not None:
                storage._require(current["features"] == previous["features"])
            self._write(current)
        return copy.deepcopy(current)
