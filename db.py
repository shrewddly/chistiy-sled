from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

_conn: sqlite3.Connection | None = None
_lock = threading.Lock()


def init(path: Path) -> None:
    global _conn
    path.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(path, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    with _lock:
        _conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                consent INTEGER NOT NULL DEFAULT 0,
                last_email TEXT,
                last_breaches INTEGER,
                last_risk TEXT,
                last_sources INTEGER,
                last_check_at TEXT
            );
            CREATE TABLE IF NOT EXISTS checklist (
                user_id INTEGER NOT NULL,
                item_id TEXT NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT,
                PRIMARY KEY (user_id, item_id)
            );
            """
        )
        columns = {row[1] for row in _conn.execute("PRAGMA table_info(users)")}
        if "last_risk" not in columns:
            _conn.execute("ALTER TABLE users ADD COLUMN last_risk TEXT")
        if "last_sources" not in columns:
            _conn.execute("ALTER TABLE users ADD COLUMN last_sources INTEGER")
        _conn.execute("UPDATE users SET last_email = NULL WHERE last_email IS NOT NULL")
        _conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def ensure_user(user_id: int) -> None:
    with _lock:
        _conn.execute("INSERT OR IGNORE INTO users(user_id) VALUES (?)", (user_id,))
        _conn.commit()


def get_user(user_id: int) -> sqlite3.Row | None:
    with _lock:
        return _conn.execute("SELECT * FROM users WHERE user_id = ?", (user_id,)).fetchone()


def set_consent(user_id: int, value: bool) -> None:
    ensure_user(user_id)
    with _lock:
        _conn.execute("UPDATE users SET consent = ? WHERE user_id = ?", (1 if value else 0, user_id))
        _conn.commit()


def save_email_check(user_id: int, breaches: int, risk: str | None = None, sources: int = 0) -> None:
    ensure_user(user_id)
    with _lock:
        _conn.execute(
            """
            UPDATE users
            SET last_email = NULL, last_breaches = ?, last_risk = ?, last_sources = ?, last_check_at = ?
            WHERE user_id = ?
            """,
            (breaches, risk, sources, _now(), user_id),
        )
        _conn.commit()


def delete_user(user_id: int) -> None:
    with _lock:
        _conn.execute("DELETE FROM checklist WHERE user_id = ?", (user_id,))
        _conn.execute("DELETE FROM users WHERE user_id = ?", (user_id,))
        _conn.commit()


def done_items(user_id: int) -> set[str]:
    with _lock:
        rows = _conn.execute(
            "SELECT item_id FROM checklist WHERE user_id = ? AND done = 1", (user_id,)
        ).fetchall()
    return {row["item_id"] for row in rows}


def toggle_item(user_id: int, item_id: str) -> bool:
    new_state = item_id not in done_items(user_id)
    with _lock:
        _conn.execute(
            """
            INSERT INTO checklist(user_id, item_id, done, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id, item_id) DO UPDATE
                SET done = excluded.done, updated_at = excluded.updated_at
            """,
            (user_id, item_id, 1 if new_state else 0, _now()),
        )
        _conn.commit()
    return new_state
