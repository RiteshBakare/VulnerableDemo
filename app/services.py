"""Task and reporting business services.

Part of securefix-vuln-lab. Contains designated security fixtures SFV-002 and SFV-003.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.db import get_db


def list_tasks(
    owner_id: Optional[str] = None,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List tasks with optional owner filtering using parameterized SQL."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        if owner_id:
            cursor.execute(
                """
                SELECT id, title, description, status, owner_id, created_at
                FROM tasks
                WHERE owner_id = ?
                ORDER BY id ASC
                """,
                (owner_id,),
            )
        else:
            cursor.execute(
                """
                SELECT id, title, description, status, owner_id, created_at
                FROM tasks
                ORDER BY id ASC
                """
            )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_task_by_id(
    task_id: int,
    db_path: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Fetch a single task by its stable ID using parameterized SQL."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, description, status, owner_id, created_at
            FROM tasks
            WHERE id = ?
            """,
            (task_id,),
        )
        row = cursor.fetchone()
        return dict(row) if row else None


def search_tasks(
    search_term: str,
    db_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Search tasks by title keyword.

    # SFV-002: SQL query concatenation pattern.
    # Builds a read-only query by concatenating search input directly into the query string
    # rather than binding parameters. Restricted to read-only local SELECT queries.
    """
    with get_db(db_path) as conn:
        cursor = conn.cursor()
        # Vulnerable query construction: direct string concatenation
        sql_query = (
            f"SELECT id, title, description, status, owner_id, created_at "
            f"FROM tasks WHERE title LIKE '%{search_term}%' ORDER BY id ASC"
        )
        cursor.execute(sql_query)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def create_task(
    title: str,
    description: str,
    status: str,
    owner_id: str,
    created_at: Optional[str] = None,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new task with parameterized SQL."""
    if created_at is None:
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    with get_db(db_path) as conn:
        cursor = conn.cursor()
        # Verify owner exists
        cursor.execute("SELECT id FROM owners WHERE id = ?", (owner_id,))
        if not cursor.fetchone():
            raise ValueError(f"Owner '{owner_id}' does not exist in synthetic owners table.")

        cursor.execute(
            """
            INSERT INTO tasks (title, description, status, owner_id, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (title, description, status, owner_id, created_at),
        )
        new_id = cursor.lastrowid

        cursor.execute(
            """
            SELECT id, title, description, status, owner_id, created_at
            FROM tasks
            WHERE id = ?
            """,
            (new_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise RuntimeError("Failed to retrieve newly created task.")
        return dict(row)


def evaluate_report_filter(
    summary: Dict[str, Any],
    filter_expr: str,
) -> bool:
    """Evaluate a dynamic filter expression on report metrics.

    # SFV-003: Unsafe dynamic evaluation.
    # Uses eval() to evaluate report-filter expressions dynamically against metrics.
    # Tested strictly with harmless boolean expressions (e.g., 'completed > 0').
    """
    # Context contains metric variables from report summary
    context = dict(summary.get("by_status", {}))
    context["total"] = summary.get("total_tasks", 0)
    # Intentionally vulnerable dynamic eval call
    result = eval(filter_expr, {"__builtins__": {}}, context)
    return bool(result)


def get_report_summary(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Compute aggregate task statistics using parameterized queries."""
    with get_db(db_path) as conn:
        cursor = conn.cursor()

        # Total count
        cursor.execute("SELECT COUNT(*) AS total FROM tasks")
        total_tasks = cursor.fetchone()["total"]

        # Counts by status
        cursor.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM tasks
            GROUP BY status
            """
        )
        by_status = {"pending": 0, "in_progress": 0, "completed": 0, "cancelled": 0}
        for row in cursor.fetchall():
            by_status[row["status"]] = row["count"]

        # Counts by owner
        cursor.execute(
            """
            SELECT owner_id, COUNT(*) AS count
            FROM tasks
            GROUP BY owner_id
            ORDER BY owner_id ASC
            """
        )
        by_owner: Dict[str, int] = {}
        for row in cursor.fetchall():
            by_owner[row["owner_id"]] = row["count"]

        return {
            "total_tasks": total_tasks,
            "by_status": by_status,
            "by_owner": by_owner,
        }
