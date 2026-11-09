"""Durable state: received events, pending deliveries, and dedup.

SQLite on a mounted volume, so the relay runs anywhere without other
infrastructure. One relay process owns the file; run a single replica.

Semgrep sends each webhook once and doesn't retry, so an accepted request is
committed here before the relay answers 200. Delivery to destinations happens
afterwards, from this table, with retries.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from semgrep_relay.envelope import Envelope

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    received_at REAL NOT NULL,
    envelope TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_received_at ON events (received_at);

CREATE TABLE IF NOT EXISTS deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events (event_id) ON DELETE CASCADE,
    connector TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL,
    last_error TEXT,
    updated_at REAL NOT NULL,
    UNIQUE (event_id, connector)
);
CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries (status, next_attempt_at);

-- Links a Semgrep subject (such as an issue) to the record a connector created
-- for it in another tool (such as a ticket). No v1 connector writes here; it's
-- what a future stateful connector would use to update or close what it made.
CREATE TABLE IF NOT EXISTS correlations (
    connector TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    external_id TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (connector, subject_key)
);
"""

_ERROR_MAX_CHARS = 500


@dataclass(frozen=True)
class AcceptResult:
    new_events: int
    duplicate_events: int
    deliveries_created: int


@dataclass(frozen=True)
class DeliveryJob:
    id: int
    event_id: str
    connector: str
    attempts: int
    envelope: Envelope


class Store:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        # FULL so a 200 to Semgrep means the event survives a crash.
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def ping(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1").fetchone() == (1,)

    def accept(
        self, routed: Sequence[tuple[Envelope, Sequence[str]]], now: float | None = None
    ) -> AcceptResult:
        """Record events and queue a delivery per target connector, atomically.

        An event whose ID is already stored is a duplicate: it's skipped and
        queues nothing.
        """
        now = time.time() if now is None else now
        new = duplicate = created = 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for envelope, connectors in routed:
                    cursor = self._conn.execute(
                        "INSERT OR IGNORE INTO events (event_id, kind, received_at, envelope) "
                        "VALUES (?, ?, ?, ?)",
                        (
                            envelope.event_id,
                            envelope.kind,
                            envelope.received_at.timestamp(),
                            envelope.model_dump_json(),
                        ),
                    )
                    if cursor.rowcount == 0:
                        duplicate += 1
                        continue
                    new += 1
                    for connector in connectors:
                        self._conn.execute(
                            "INSERT INTO deliveries "
                            "(event_id, connector, status, next_attempt_at, updated_at) "
                            "VALUES (?, ?, 'pending', ?, ?)",
                            (envelope.event_id, connector, now, now),
                        )
                        created += 1
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return AcceptResult(new, duplicate, created)

    def due_deliveries(
        self, limit: int, exclude_ids: Iterable[int] = (), now: float | None = None
    ) -> list[DeliveryJob]:
        now = time.time() if now is None else now
        excluded = set(exclude_ids)
        # Over-fetch by the number of excluded (in-flight) rows, then skip them.
        with self._lock:
            rows = self._conn.execute(
                "SELECT d.id, d.event_id, d.connector, d.attempts, e.envelope "
                "FROM deliveries d JOIN events e ON e.event_id = d.event_id "
                "WHERE d.status = 'pending' AND d.next_attempt_at <= ? "
                "ORDER BY d.next_attempt_at, d.id LIMIT ?",
                (now, limit + len(excluded)),
            ).fetchall()
        rows = [row for row in rows if row[0] not in excluded][:limit]
        return [
            DeliveryJob(
                id=row[0],
                event_id=row[1],
                connector=row[2],
                attempts=row[3],
                envelope=Envelope.model_validate_json(row[4]),
            )
            for row in rows
        ]

    def mark_delivered(self, delivery_id: int, attempts: int) -> None:
        self._update(delivery_id, "delivered", attempts, None, None)

    def mark_retry(
        self, delivery_id: int, attempts: int, next_attempt_at: float, error: str | None
    ) -> None:
        self._update(delivery_id, "pending", attempts, next_attempt_at, error)

    def mark_dead(self, delivery_id: int, attempts: int, error: str | None) -> None:
        self._update(delivery_id, "dead", attempts, None, error)

    def _update(
        self,
        delivery_id: int,
        status: str,
        attempts: int,
        next_attempt_at: float | None,
        error: str | None,
    ) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "UPDATE deliveries SET status = ?, attempts = ?, "
                "next_attempt_at = COALESCE(?, next_attempt_at), last_error = ?, updated_at = ? "
                "WHERE id = ?",
                (
                    status,
                    attempts,
                    next_attempt_at,
                    error[:_ERROR_MAX_CHARS] if error else None,
                    now,
                    delivery_id,
                ),
            )

    def retry_dead(self, connector: str | None = None) -> int:
        """Requeue dead deliveries, e.g. after fixing a destination's credentials."""
        now = time.time()
        query = (
            "UPDATE deliveries SET status = 'pending', attempts = 0, next_attempt_at = ?, "
            "updated_at = ? WHERE status = 'dead'"
        )
        params: tuple[object, ...] = (now, now)
        if connector:
            query += " AND connector = ?"
            params = (*params, connector)
        with self._lock:
            return self._conn.execute(query, params).rowcount

    def status_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) FROM deliveries GROUP BY status"
            ).fetchall()
        counts = {"pending": 0, "delivered": 0, "dead": 0}
        counts.update(dict(rows))
        return counts

    def prune(self, older_than: float) -> int:
        """Delete events, and their deliveries, received before ``older_than``.

        Pending deliveries are kept, so a destination that's down for longer
        than the retention window doesn't lose events.
        """
        with self._lock:
            return self._conn.execute(
                "DELETE FROM events WHERE received_at < ? AND NOT EXISTS ("
                "SELECT 1 FROM deliveries d WHERE d.event_id = events.event_id "
                "AND d.status = 'pending')",
                (older_than,),
            ).rowcount

    def get_correlation(self, connector: str, subject_key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT external_id FROM correlations WHERE connector = ? AND subject_key = ?",
                (connector, subject_key),
            ).fetchone()
        return row[0] if row else None

    def put_correlation(self, connector: str, subject_key: str, external_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO correlations (connector, subject_key, external_id, updated_at) "
                "VALUES (?, ?, ?, ?) ON CONFLICT (connector, subject_key) DO UPDATE SET "
                "external_id = excluded.external_id, updated_at = excluded.updated_at",
                (connector, subject_key, external_id, time.time()),
            )
