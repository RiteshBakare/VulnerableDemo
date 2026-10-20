"""Functional tests for database operations and task/report API endpoints.

Part of securefix-vuln-lab Phase B test suite.
All tests run against isolated temporary SQLite databases.
"""

import sqlite3
import pytest
from fastapi.testclient import TestClient

from app.db import get_db, init_db
from app.main import app, get_database_path


@pytest.fixture
def test_db_path(tmp_path):
    """Create and initialize an isolated temporary SQLite database for testing."""
    db_file = tmp_path / "test_securefix_lab.db"
    init_db(str(db_file))
    return str(db_file)


@pytest.fixture
def client(test_db_path):
    """Provide a TestClient with dependency override pointing to isolated temporary database."""
    app.dependency_overrides[get_database_path] = lambda: test_db_path
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_database_initialization_schema(test_db_path):
    """1. Verify that database initialization creates the expected schema."""
    with get_db(test_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        assert "owners" in tables
        assert "tasks" in tables

        # Verify columns in tasks table
        cursor.execute("PRAGMA table_info(tasks);")
        columns = {row["name"]: row["type"] for row in cursor.fetchall()}
        assert "id" in columns
        assert "title" in columns
        assert "description" in columns
        assert "status" in columns
        assert "owner_id" in columns
        assert "created_at" in columns


def test_repeated_initialization_idempotency(test_db_path):
    """2. Verify that repeated initialization does not duplicate seed records."""
    # Re-run init_db on the same database
    init_db(test_db_path)
    init_db(test_db_path)

    with get_db(test_db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS count FROM owners;")
        assert cursor.fetchone()["count"] == 2

        cursor.execute("SELECT COUNT(*) AS count FROM tasks;")
        assert cursor.fetchone()["count"] == 4


def test_seed_data_owners_and_relationships(test_db_path):
    """3. Verify seed data includes multiple owners and tasks associated with correct owners."""
    with get_db(test_db_path) as conn:
        cursor = conn.cursor()

        # Check owners
        cursor.execute("SELECT id, name, email FROM owners ORDER BY id ASC;")
        owners = cursor.fetchall()
        assert len(owners) == 2
        assert owners[0]["id"] == "owner_1"
        assert owners[1]["id"] == "owner_2"

        # Check tasks for owner_1
        cursor.execute("SELECT id, title, owner_id FROM tasks WHERE owner_id = 'owner_1' ORDER BY id ASC;")
        owner_1_tasks = cursor.fetchall()
        assert len(owner_1_tasks) == 2
        assert [t["id"] for t in owner_1_tasks] == [1, 2]

        # Check tasks for owner_2
        cursor.execute("SELECT id, title, owner_id FROM tasks WHERE owner_id = 'owner_2' ORDER BY id ASC;")
        owner_2_tasks = cursor.fetchall()
        assert len(owner_2_tasks) == 2
        assert [t["id"] for t in owner_2_tasks] == [3, 4]


def test_get_tasks_returns_documented_structure(client):
    """4. Verify GET /tasks returns the documented response structure."""
    response = client.get("/tasks")
    assert response.status_code == 200
    tasks = response.json()
    assert isinstance(tasks, list)
    assert len(tasks) == 4

    # Validate structure of each task
    first_task = tasks[0]
    assert first_task["id"] == 1
    assert first_task["title"] == "Review Security Policies"
    assert first_task["status"] == "completed"
    assert first_task["owner_id"] == "owner_1"
    assert "created_at" in first_task

    # Validate filtering by owner_id
    response_filtered = client.get("/tasks?owner_id=owner_1")
    assert response_filtered.status_code == 200
    filtered_tasks = response_filtered.json()
    assert len(filtered_tasks) == 2
    assert all(t["owner_id"] == "owner_1" for t in filtered_tasks)


def test_get_task_by_id_returns_existing_task(client):
    """5. Verify GET /tasks/{task_id} returns an existing synthetic task."""
    response = client.get("/tasks/1")
    assert response.status_code == 200
    task = response.json()
    assert task["id"] == 1
    assert task["title"] == "Review Security Policies"
    assert task["owner_id"] == "owner_1"


def test_get_task_by_id_not_found(client):
    """6. Verify GET /tasks/{unknown_id} returns 404 not found."""
    response = client.get("/tasks/9999")
    assert response.status_code == 404
    error_data = response.json()
    assert "detail" in error_data
    assert "9999 not found" in error_data["detail"]


def test_post_tasks_creates_valid_task(client):
    """7. Verify POST /tasks creates a valid synthetic task."""
    payload = {
        "title": "Synthetic Audit Task",
        "description": "Validate synthetic access boundaries in test lab.",
        "status": "pending",
        "owner_id": "owner_2",
    }
    response = client.post("/tasks", json=payload)
    assert response.status_code == 201
    created = response.json()
    assert created["id"] > 4
    assert created["title"] == payload["title"]
    assert created["description"] == payload["description"]
    assert created["status"] == payload["status"]
    assert created["owner_id"] == payload["owner_id"]
    assert "created_at" in created

    # Verify task is now retrievable
    get_res = client.get(f"/tasks/{created['id']}")
    assert get_res.status_code == 200
    assert get_res.json()["title"] == payload["title"]


def test_post_tasks_rejects_invalid_input(client):
    """8. Verify invalid task input is rejected with appropriate HTTP error codes."""
    # Invalid status value -> 422 Unprocessable Entity
    invalid_status_payload = {
        "title": "Bad Status Task",
        "status": "unsupported_status_xyz",
        "owner_id": "owner_1",
    }
    response = client.post("/tasks", json=invalid_status_payload)
    assert response.status_code == 422

    # Missing required title -> 422 Unprocessable Entity
    missing_title_payload = {
        "description": "Missing title",
        "owner_id": "owner_1",
    }
    response = client.post("/tasks", json=missing_title_payload)
    assert response.status_code == 422

    # Empty title string -> 422 Unprocessable Entity
    empty_title_payload = {
        "title": "",
        "owner_id": "owner_1",
    }
    response = client.post("/tasks", json=empty_title_payload)
    assert response.status_code == 422

    # Non-existent owner_id -> 400 Bad Request
    unknown_owner_payload = {
        "title": "Unknown Owner Task",
        "owner_id": "non_existent_owner_999",
    }
    response = client.post("/tasks", json=unknown_owner_payload)
    assert response.status_code == 400
    assert "does not exist in synthetic owners" in response.json()["detail"]


def test_get_reports_summary_deterministic_counts(client):
    """9. Verify GET /reports/summary returns deterministic counts consistent with seed data."""
    response = client.get("/reports/summary")
    assert response.status_code == 200
    summary = response.json()
    assert summary["total_tasks"] == 4
    assert summary["by_status"]["completed"] == 2
    assert summary["by_status"]["in_progress"] == 1
    assert summary["by_status"]["pending"] == 1
    assert summary["by_status"]["cancelled"] == 0
    assert summary["by_owner"]["owner_1"] == 2
    assert summary["by_owner"]["owner_2"] == 2


def test_db_connection_cleanup_on_error(test_db_path):
    """10. Verify that database connections are cleaned up appropriately when operations fail."""
    conn_ref = None
    try:
        with get_db(test_db_path) as conn:
            conn_ref = conn
            # Execute invalid SQL to trigger an exception
            conn.execute("INSERT INTO non_existent_table VALUES (1);")
    except sqlite3.OperationalError:
        pass

    # The connection should be closed after exiting the context manager
    assert conn_ref is not None
    with pytest.raises(sqlite3.ProgrammingError, match="Cannot operate on a closed database"):
        conn_ref.execute("SELECT 1;")
