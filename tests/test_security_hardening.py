"""
tests/test_security_hardening.py

Validates Phase 3 security hardening:
1. API key is restricted strictly to X-API-Key HTTP header.
2. Query parameter (?api_key=...) authentication is strictly disallowed and rejected with HTTP 401.
3. Header authentication remains fully functional.
"""

import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from api.main import app
from api.auth import get_configured_api_key
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from db.database import Base, get_db

# In-memory SQLite DB for isolation
SQLALCHEMY_DATABASE_URL = "sqlite://"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_query_param_api_key_is_rejected_with_401():
    """Security Hardening: Query parameter API key must be rejected to prevent log/history leakage."""
    valid_key = get_configured_api_key()

    # Attempt access using query parameter ?api_key=...
    res = client.get(f"/scans?api_key={valid_key}", headers={"skip-auto-auth": "true"})
    assert res.status_code == 401, f"Expected 401 Unauthorized for query param API key, got {res.status_code}"
    assert "Unauthorized" in res.json().get("detail", "")


def test_header_api_key_is_accepted_with_200():
    """Valid X-API-Key header must authenticate successfully."""
    valid_key = get_configured_api_key()

    res = client.get("/scans", headers={"X-API-Key": valid_key})
    assert res.status_code == 200


def test_invalid_header_api_key_is_rejected_with_401():
    """Invalid X-API-Key header must be rejected with 401."""
    res = client.get("/scans", headers={"X-API-Key": "completely-invalid-key", "skip-auto-auth": "true"})
    assert res.status_code == 401


def test_fail_closed_when_no_api_key_env_var_set(monkeypatch):
    """The application must refuse to start (fail-closed) if no API key env var is set."""
    monkeypatch.delenv("ATTACKGRAPH_API_KEY", raising=False)
    monkeypatch.delenv("API_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        get_configured_api_key()
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)

    # Verify lifespan startup also raises RuntimeError
    with pytest.raises(RuntimeError) as lifespan_exc:
        with TestClient(app):
            pass
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(lifespan_exc.value)


