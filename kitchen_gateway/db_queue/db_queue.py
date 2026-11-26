from __future__ import annotations

import ast
import datetime as dt
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sqlite_database_client_integrated")

KEY_FIELDS = {
    "action": "action_id",
    "hygiene_check": "check_id",
    "sanitary_event": "event_id",
    "process_event": "event_id",
    "data_quality_event": "event_id",
    "environment_state": "state_id",
    "audit_clip": "clip_id",
}

OLD_EVENT_TYPE_TO_KIND = {
    "action_event": "action",
    "hygiene_check": "hygiene_check",
    "sanitary_event": "sanitary_event",
    "process_event": "process_event",
    "data_quality_event": "data_quality_event",
    "environment_state": "environment_state",
    "audit_clip": "audit_clip",
}


def retry_on_lock(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        max_retries = 3
        retry_delay = 0.1
        for attempt in range(max_retries):
            try:
                return func(self, *args, **kwargs)
            except sqlite3.OperationalError as exc:
                if "database is locked" in str(exc) and attempt < max_retries - 1:
                    logger.warning("database locked, retry %s/%s", attempt + 1, max_retries)
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                raise
        return None

    return wrapper


class DBQueue:
    def __init__(self, db_path: str = "./db_queue.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._lock = threading.RLock()
        self._init_database()

    def _init_database(self) -> None:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='event_queue'"
            )
            exists = cur.fetchone()
            legacy = False

            if exists:
                cur.execute("PRAGMA table_info(event_queue)")
                cols = {row[1] for row in cur.fetchall()}
                if cols and "kind" not in cols:
                    cur.execute("ALTER TABLE event_queue RENAME TO event_queue_legacy")
                    legacy = True

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS event_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('pending', 'completed', 'rejected'))
                        DEFAULT 'pending',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at TEXT,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(kind, idempotency_key)
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_event_queue_pending "
                "ON event_queue(status, next_attempt_at, id)"
            )

            if legacy:
                self._migrate_legacy(conn)

    def _migrate_legacy(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute(
            "SELECT id, event_type, json_content, status, timestamp_added "
            "FROM event_queue_legacy"
        ).fetchall()
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        for old_id, old_type, old_json, old_status, old_ts in rows:
            kind = OLD_EVENT_TYPE_TO_KIND.get(str(old_type).lower(), str(old_type).lower())
            try:
                payload = ast.literal_eval(old_json)
                if not isinstance(payload, dict):
                    payload = {}
            except Exception:
                payload = {}
            key_field = KEY_FIELDS.get(kind, "event_id")
            key = str(payload.get(key_field) or f"legacy-{old_id}")
            status = "pending"
            if old_status == "b_completed":
                status = "completed"
            elif old_status == "c_failed":
                status = "rejected"
            conn.execute(
                """
                INSERT OR IGNORE INTO event_queue
                    (kind, payload_json, idempotency_key, status, attempts,
                     next_attempt_at, created_at, updated_at)
                VALUES (?, ?, ?, ?, 0, ?, ?, ?)
                """,
                (
                    kind,
                    json.dumps(payload, ensure_ascii=False),
                    key,
                    status,
                    now,
                    old_ts or now,
                    now,
                ),
            )
        logger.info("legacy event_queue migrated: %s rows", len(rows))

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            logger.exception("database error")
            raise
        finally:
            conn.close()

    @retry_on_lock
    def add_database_event(self, pkt: dict) -> Optional[int]:
        kind = str(pkt["kind"]).lower()
        payload = pkt["payload"]
        key = str(pkt.get("idempotency_key") or payload.get(KEY_FIELDS.get(kind, "event_id")))
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO event_queue
                    (kind, payload_json, idempotency_key, status,
                     next_attempt_at, created_at, updated_at)
                VALUES (?, ?, ?, 'pending', ?, ?, ?)
                """,
                (
                    kind,
                    json.dumps(payload, ensure_ascii=False),
                    key,
                    now,
                    now,
                    now,
                ),
            )
            if cur.rowcount:
                return int(cur.lastrowid)
            row = cur.execute(
                "SELECT id FROM event_queue WHERE kind = ? AND idempotency_key = ?",
                (kind, key),
            ).fetchone()
            return int(row["id"]) if row else None

    @retry_on_lock
    def get_event(self, event_id: int) -> Optional[sqlite3.Row]:
        with self._get_connection() as conn:
            return conn.execute(
                "SELECT * FROM event_queue WHERE id = ?", (event_id,)
            ).fetchone()

    @retry_on_lock
    def get_database_events(self, limit: int = 20) -> List[sqlite3.Row]:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        with self._get_connection() as conn:
            return conn.execute(
                """
                SELECT * FROM event_queue
                WHERE status = 'pending'
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
                ORDER BY id
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()

    @retry_on_lock
    def complete_event(self, event_id: int) -> None:
        # После accepted/duplicate событие больше не нужно держать в очереди.
        with self._get_connection() as conn:
            conn.execute("DELETE FROM event_queue WHERE id = ?", (event_id,))

    @retry_on_lock
    def reject_event(self, event_id: int, reason: str) -> None:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE event_queue
                SET status = 'rejected', last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                (reason[:2000], now, event_id),
            )

    @retry_on_lock
    def retry_event(self, event_id: int, error: str) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT attempts FROM event_queue WHERE id = ?", (event_id,)
            ).fetchone()
            attempts = int(row["attempts"]) + 1 if row else 1
            # Рост паузы без ограничения числа попыток.
            delay = min(300, 2 ** min(attempts, 8))
            next_at = (now + dt.timedelta(seconds=delay)).isoformat()
            conn.execute(
                """
                UPDATE event_queue
                SET status = 'pending',
                    attempts = ?,
                    next_attempt_at = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (attempts, next_at, error[:2000], now.isoformat(), event_id),
            )

    @retry_on_lock
    def check_size_and_cleanup(self, max_size_mb: float = 5000) -> None:
        """
        Не удаляет pending по возрасту и не ограничивает попытки.
        Может удалить только rejected/completed, чтобы не терять неотправленное.
        """
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()"
            )
            size_mb = (cur.fetchone()[0] or 0) / (1024 * 1024)
            logger.info("queue size: %.2f MB", size_mb)
            if size_mb > max_size_mb:
                cur.execute(
                    "DELETE FROM event_queue WHERE status IN ('completed', 'rejected')"
                )
                deleted = cur.rowcount
                conn.commit()
                cur.execute("VACUUM")
                logger.warning("queue cleanup removed %s completed/rejected rows", deleted)

    def cleanup_thread_connection(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None
            self._local.cursor = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup_thread_connection()