"""SQLite database management and deterministic synthetic seed data.

Part of securefix-vuln-lab. Uses Python's standard-library sqlite3.
"""

import os
import sqlite3
from contextlib import contextmanager
from typing import Generator

from app.config import settings

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS owners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK(status IN ('pending', 'in_progress', 'completed', 'cancelled')),
    owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES owners(id)
);
"""

# Deterministic synthetic seed data (strictly fake, non-sensitive records)
SEED_OWNERS = [
    ("owner_1", "Synthetic Alice", "alice@synthetic.local"),
    ("owner_2", "Synthetic Bob", "bob@synthetic.local"),
]

SEED_TASKS = [
    (1, "Review Security Policies", "Audit synthetic access control rules.", "completed", "owner_1", "2026-10-19T09:00:00Z"),
    (2, "Configure Local Firewalls", "Verify loopback-only packet filtering.", "in_progress", "owner_1", "2026-10-19T09:30:00Z"),
    (3, "Database Index Optimization", "Profile task query execution plans.", "pending", "owner_2", "2026-10-19T10:00:00Z"),
    (4, "Prepare Quarterly Report", "Aggregate compliance metrics for synthetic lab.", "completed", "owner_2", "2026-10-19T10:30:00Z"),
]


def get_db_path(db_path: str | None = None) -> str:
    """Resolve the SQLite database path."""
    return db_path if db_path is not None else settings.DATABASE_PATH


def get_db_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Create and return a raw SQLite connection with Row factory enabled."""
    resolved_path = get_db_path(db_path)
    conn = sqlite3.connect(resolved_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_db(db_path: str | None = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for safe database connections and transaction management."""
    conn = get_db_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | None = None) -> None:
    """Initialize database schema and seed deterministic records idempotently."""
    resolved_path = get_db_path(db_path)
    with get_db(resolved_path) as conn:
        cursor = conn.cursor()
        cursor.executescript(SCHEMA_SQL)

        # Idempotently seed owners
        cursor.executemany(
            """
            INSERT OR REPLACE INTO owners (id, name, email)
            VALUES (?, ?, ?)
            """,
            SEED_OWNERS,
        )

        # Idempotently seed tasks (INSERT OR IGNORE preserves stable IDs without duplicate rows)
        cursor.executemany(
            """
            INSERT OR IGNORE INTO tasks (id, title, description, status, owner_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            SEED_TASKS,
        )
