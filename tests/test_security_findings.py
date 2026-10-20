"""Safe local verification tests for the eight planted intentional security findings.

Covers:
- SFV-001 (High): Broken object-level authorization (IDOR)
- SFV-002 (High): SQL query concatenation in search helper
- SFV-003 (High): Unsafe dynamic evaluation in report filter helper
- SFV-004 (Medium): Permissive CORS configuration
- SFV-005 (Medium): Verbose error response with diagnostic text
- SFV-006 (Medium): Missing defensive security headers
- SFV-007 (Low): Hardcoded fake credential marker
- SFV-008 (Low): Version metadata disclosure in /health

All tests run locally using synthetic data and benign inputs only.
No external network requests, real credentials, or destructive payloads are used.
"""

import inspect
import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.db import init_db
from app.main import app, get_database_path
from app.services import evaluate_report_filter, search_tasks


@pytest.fixture
def test_db_path(tmp_path):
    """Create and initialize an isolated temporary SQLite database for testing."""
    db_file = tmp_path / "test_findings_lab.db"
    init_db(str(db_file))
    return str(db_file)


@pytest.fixture
def client(test_db_path):
    """Provide a TestClient configured with isolated database path."""
    app.dependency_overrides[get_database_path] = lambda: test_db_path
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ==============================================================================
# SFV-001 (High): Broken Object-Level Authorization (IDOR)
# ==============================================================================
def test_sfv_001_broken_object_authorization_idor(client):
    """Verify that a task belonging to owner_2 is returned to a caller simulating owner_1."""
    # Task 3 belongs to synthetic owner_2 ('Synthetic Bob')
    # Caller simulates identity as owner_1 ('Synthetic Alice')
    headers = {"X-User-Id": "owner_1"}
    response = client.get("/tasks/3", headers=headers)

    assert response.status_code == 200
    task = response.json()
    assert task["id"] == 3
    assert task["owner_id"] == "owner_2"
    # Documenting the intentional defect: owner scope is not enforced against caller header
    assert task["owner_id"] != headers["X-User-Id"]


# ==============================================================================
# SFV-002 (High): SQL Query Concatenation
# ==============================================================================
def test_sfv_002_sql_query_concatenation_benign_search(client, test_db_path):
    """Verify that search_tasks searches by title using benign query terms."""
    # 1. API endpoint search
    response = client.get("/tasks/search?q=Firewalls")
    assert response.status_code == 200
    results = response.json()
    assert len(results) == 1
    assert results[0]["id"] == 2
    assert "Firewalls" in results[0]["title"]

    # 2. Service-level helper execution with benign search input
    service_results = search_tasks("Security", test_db_path)
    assert len(service_results) == 1
    assert service_results[0]["id"] == 1
    assert "Security" in service_results[0]["title"]

    # 3. Static query construction inspection verifying string concatenation pattern
    src = inspect.getsource(search_tasks)
    assert 'f"SELECT id, title, description, status, owner_id, created_at' in src
    assert "WHERE title LIKE '%{search_term}%'" in src


# ==============================================================================
# SFV-003 (High): Unsafe Dynamic Evaluation
# ==============================================================================
def test_sfv_003_unsafe_dynamic_evaluation_harmless(client):
    """Verify dynamic evaluation of benign boolean filter expressions."""
    # In seeded data: completed=2, in_progress=1, pending=1, cancelled=0, total=4

    # Test harmless expression returning True
    res_true = client.get("/reports/summary?filter_expr=completed > 0")
    assert res_true.status_code == 200
    data_true = res_true.json()
    assert data_true["filter_applied"] == "completed > 0"
    assert data_true["filter_matched"] is True

    # Test harmless expression returning False
    res_false = client.get("/reports/summary?filter_expr=completed == 0")
    assert res_false.status_code == 200
    data_false = res_false.json()
    assert data_false["filter_applied"] == "completed == 0"
    assert data_false["filter_matched"] is False

    # Direct helper test with benign expression
    summary = {"total_tasks": 4, "by_status": {"completed": 2, "pending": 1}}
    assert evaluate_report_filter(summary, "completed == 2") is True
    assert evaluate_report_filter(summary, "pending > 5") is False

    # Static inspection verifying eval usage
    src = inspect.getsource(evaluate_report_filter)
    assert "eval(filter_expr" in src


# ==============================================================================
# SFV-004 (Medium): Permissive CORS
# ==============================================================================
def test_sfv_004_permissive_cors_wildcard(client):
    """Verify CORS middleware responds with wildcard allow-origin header."""
    headers = {
        "Origin": "http://random-client.local",
        "Access-Control-Request-Method": "GET",
    }
    response = client.options("/tasks", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"


# ==============================================================================
# SFV-005 (Medium): Verbose Error Responses
# ==============================================================================
def test_sfv_005_verbose_error_response(client):
    """Verify controlled error response includes synthetic diagnostic and exception class."""
    response = client.get("/debug/controlled-error")
    assert response.status_code == 500
    error_body = response.json()
    assert error_body["error"] == "Internal demo processing failure"
    assert error_body["diagnostic"] == "Synthetic internal diagnostic: operation failed in task processor"
    assert error_body["exception_type"] == "ControlledDemoException"

    # Verify no real secrets, environment variables, or private paths leaked
    assert "password" not in str(error_body).lower()
    assert "api_key" not in str(error_body).lower()


# ==============================================================================
# SFV-006 (Medium): Missing Defensive Security Headers
# ==============================================================================
def test_sfv_006_missing_defensive_security_headers(client):
    """Verify standard defensive headers are intentionally omitted in responses."""
    health_res = client.get("/health")
    assert "x-content-type-options" not in health_res.headers
    assert "content-security-policy" not in health_res.headers
    assert "strict-transport-security" not in health_res.headers

    tasks_res = client.get("/tasks")
    assert "x-content-type-options" not in tasks_res.headers
    assert "content-security-policy" not in tasks_res.headers


# ==============================================================================
# SFV-007 (Low): Hardcoded Fake Credential
# ==============================================================================
def test_sfv_007_hardcoded_fake_credential_presence_and_isolation():
    """Verify presence of nonfunctional fake credential marker and that it is unused."""
    assert settings.DEMO_API_KEY == "demo-only-not-a-real-secret"

    # Confirm it is nonfunctional and unused for route authorization
    client_local = TestClient(app)
    res_no_auth = client_local.get("/health")
    assert res_no_auth.status_code == 200

    # Confirm passing it or not passing it does not affect any authentication
    res_with_auth = client_local.get("/health", headers={"Authorization": f"Bearer {settings.DEMO_API_KEY}"})
    assert res_with_auth.status_code == 200


# ==============================================================================
# SFV-008 (Low): Version Disclosure
# ==============================================================================
def test_sfv_008_version_metadata_disclosure(client):
    """Verify GET /health discloses demo application version metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "version" in data
    assert data["version"] == "1.0.0-demo"
