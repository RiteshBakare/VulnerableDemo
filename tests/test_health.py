import socket
import pytest
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.main import app

client = TestClient(app)


def test_health_endpoint_returns_200():
    """Verify that GET /health returns 200 OK and expected status payload."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["app"] == "securefix-vuln-lab"
    assert data["version"] == "1.0.0-demo"
    assert data["environment"] == "local_demo"


def test_default_configuration_binds_to_loopback():
    """Verify default host is strictly loopback (127.0.0.1)."""
    assert settings.HOST == "127.0.0.1"
    assert settings.PORT == 8000
    assert settings.validate_loopback() is True


def test_loopback_validation_rejects_public_and_external_hosts():
    """Verify that non-loopback host values are rejected by safety validator."""
    unsafe_settings = Settings(HOST="0.0.0.0")
    assert unsafe_settings.validate_loopback() is False

    unsafe_settings_lan = Settings(HOST="192.168.1.100")
    assert unsafe_settings_lan.validate_loopback() is False

    unsafe_settings_public = Settings(HOST="203.0.113.1")
    assert unsafe_settings_public.validate_loopback() is False


def test_no_outbound_network_calls(monkeypatch):
    """Verify test execution and health check do not attempt any non-loopback outbound network connections."""
    orig_connect = socket.socket.connect

    def guarded_connect(self, address, *args, **kwargs):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else address
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError(f"External outbound socket connection blocked: {host}")
        return orig_connect(self, address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
