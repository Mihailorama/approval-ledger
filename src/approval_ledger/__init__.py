"""Hash-bound approval and idempotent dispatch primitives."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4


class ApprovalError(ValueError):
    """An action cannot advance through the required approval state."""


def _normalise(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\r\n", "\n").replace("\r", "\n")
    if isinstance(value, Mapping):
        return {str(key): _normalise(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    if isinstance(value, tuple):
        return [_normalise(item) for item in value]
    return value


@dataclass(frozen=True)
class CanonicalPayload:
    payload: dict[str, Any]
    json_text: str
    digest: str


def canonicalize(payload: Mapping[str, Any]) -> CanonicalPayload:
    """Normalise JSON data and derive its stable SHA-256 digest."""

    normalised = _normalise(dict(payload))
    if not isinstance(normalised, dict):
        raise TypeError("action payload must be a mapping")
    try:
        json_text = json.dumps(
            normalised,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("action payload must be JSON serialisable") from exc
    return CanonicalPayload(
        payload=normalised,
        json_text=json_text,
        digest=hashlib.sha256(json_text.encode("utf-8")).hexdigest(),
    )


@dataclass(frozen=True)
class Action:
    id: str
    digest: str
    payload: dict[str, Any]
    required_gates: tuple[str, ...]


@dataclass(frozen=True)
class ApprovalReceipt:
    action_id: str
    digest: str
    approver: str
    approved_at: str


@dataclass(frozen=True)
class DispatchReceipt:
    action_id: str
    digest: str
    idempotency_key: str
    status: str
    external_id: str | None


Dispatch = Callable[[dict[str, Any], str], str]


def _now() -> str:
    return datetime.now(UTC).isoformat()


class SQLiteLedger:
    """A durable ledger with explicit gates and dispatch reservations."""

    def __init__(self, path: str | Path) -> None:
        self._connection = sqlite3.connect(str(path), isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def close(self) -> None:
        self._connection.close()

    def _migrate(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                digest TEXT NOT NULL CHECK(length(digest) = 64),
                payload_json TEXT NOT NULL,
                required_gates_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS gates (
                action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
                digest TEXT NOT NULL,
                gate_name TEXT NOT NULL,
                passed INTEGER NOT NULL CHECK(passed IN (0, 1)),
                recorded_at TEXT NOT NULL,
                PRIMARY KEY(action_id, digest, gate_name)
            );
            CREATE TABLE IF NOT EXISTS approvals (
                action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
                digest TEXT NOT NULL,
                approver TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                PRIMARY KEY(action_id, digest)
            );
            CREATE TABLE IF NOT EXISTS dispatches (
                action_id TEXT NOT NULL REFERENCES actions(id) ON DELETE RESTRICT,
                digest TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK(status IN ('running', 'completed', 'indeterminate')),
                external_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(action_id, digest)
            );
            """
        )

    def create_action(
        self,
        payload: Mapping[str, Any],
        *,
        required_gates: tuple[str, ...] | list[str] = (),
    ) -> Action:
        canonical = canonicalize(payload)
        gates = tuple(required_gates)
        if len(set(gates)) != len(gates) or any(not gate.strip() for gate in gates):
            raise ValueError("required gate names must be unique, non-empty strings")
        action = Action(uuid4().hex, canonical.digest, canonical.payload, gates)
        self._connection.execute(
            "INSERT INTO actions(id, digest, payload_json, required_gates_json, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                action.id,
                action.digest,
                canonical.json_text,
                json.dumps(gates, separators=(",", ":")),
                _now(),
            ),
        )
        return action

    def record_gate(
        self,
        action_id: str,
        digest: str,
        gate_name: str,
        *,
        passed: bool,
    ) -> None:
        action = self._action(action_id)
        self._require_digest(action, digest)
        if gate_name not in action.required_gates:
            raise ApprovalError(f"gate is not required for this action: {gate_name}")
        self._connection.execute(
            "INSERT INTO gates(action_id, digest, gate_name, passed, recorded_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(action_id, digest, gate_name) DO UPDATE SET "
            "passed = excluded.passed, recorded_at = excluded.recorded_at",
            (action_id, digest, gate_name, int(passed), _now()),
        )

    def approve(self, action_id: str, digest: str, *, approver: str) -> ApprovalReceipt:
        action = self._action(action_id)
        self._require_digest(action, digest)
        if not approver.strip():
            raise ApprovalError("approver is required")
        missing = self._missing_gates(action)
        if missing:
            raise ApprovalError(f"required gates are not passing: {', '.join(missing)}")
        now = _now()
        try:
            self._connection.execute(
                "INSERT INTO approvals(action_id, digest, approver, approved_at) VALUES (?, ?, ?, ?)",
                (action_id, digest, approver, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ApprovalError("action digest is already approved") from exc
        return ApprovalReceipt(action_id, digest, approver, now)

    def dispatch(self, action_id: str, dispatch: Dispatch) -> DispatchReceipt:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            action = self._action(action_id)
            approved = self._connection.execute(
                "SELECT 1 FROM approvals WHERE action_id = ? AND digest = ?",
                (action.id, action.digest),
            ).fetchone()
            if approved is None:
                raise ApprovalError("action requires exact-digest approval before dispatch")
            existing = self._connection.execute(
                "SELECT * FROM dispatches WHERE action_id = ? AND digest = ?",
                (action.id, action.digest),
            ).fetchone()
            if existing is not None:
                self._connection.execute("COMMIT")
                return self._receipt(existing)
            idempotency_key = hashlib.sha256(
                f"approval-ledger:v1:{action.id}:{action.digest}".encode("utf-8")
            ).hexdigest()
            now = _now()
            self._connection.execute(
                "INSERT INTO dispatches(action_id, digest, idempotency_key, status, external_id, created_at, updated_at) "
                "VALUES (?, ?, ?, 'running', NULL, ?, ?)",
                (action.id, action.digest, idempotency_key, now, now),
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

        try:
            external_id = dispatch(dict(action.payload), idempotency_key)
        except Exception:
            self._connection.execute(
                "UPDATE dispatches SET status = 'indeterminate', updated_at = ? "
                "WHERE action_id = ? AND digest = ?",
                (_now(), action.id, action.digest),
            )
            raise

        self._connection.execute(
            "UPDATE dispatches SET status = 'completed', external_id = ?, updated_at = ? "
            "WHERE action_id = ? AND digest = ?",
            (str(external_id), _now(), action.id, action.digest),
        )
        return self._receipt(
            self._connection.execute(
                "SELECT * FROM dispatches WHERE action_id = ? AND digest = ?",
                (action.id, action.digest),
            ).fetchone()
        )

    def _action(self, action_id: str) -> Action:
        row = self._connection.execute("SELECT * FROM actions WHERE id = ?", (action_id,)).fetchone()
        if row is None:
            raise KeyError(action_id)
        return Action(
            id=row["id"],
            digest=row["digest"],
            payload=json.loads(row["payload_json"]),
            required_gates=tuple(json.loads(row["required_gates_json"])),
        )

    @staticmethod
    def _require_digest(action: Action, digest: str) -> None:
        if action.digest != digest:
            raise ApprovalError("digest does not match the current action")

    def _missing_gates(self, action: Action) -> list[str]:
        rows = self._connection.execute(
            "SELECT gate_name, passed FROM gates WHERE action_id = ? AND digest = ?",
            (action.id, action.digest),
        ).fetchall()
        passed = {row["gate_name"] for row in rows if row["passed"]}
        return [gate for gate in action.required_gates if gate not in passed]

    @staticmethod
    def _receipt(row: sqlite3.Row) -> DispatchReceipt:
        return DispatchReceipt(
            action_id=row["action_id"],
            digest=row["digest"],
            idempotency_key=row["idempotency_key"],
            status=row["status"],
            external_id=row["external_id"],
        )


__all__ = [
    "Action",
    "ApprovalError",
    "ApprovalReceipt",
    "CanonicalPayload",
    "DispatchReceipt",
    "SQLiteLedger",
    "canonicalize",
]
