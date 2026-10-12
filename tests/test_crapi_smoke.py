import os
import sys
import pytest
import requests
from typing import Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from api.allowlist import allowlist_validator


from pathlib import Path

CRAPI_BASE_URL = os.environ.get("CRAPI_BASE_URL", "http://localhost:8888")

# Load crAPI credentials dynamically from git-ignored .env.crapi if present
_env_crapi = Path(__file__).resolve().parent.parent / ".env.crapi"
if _env_crapi.exists():
    with open(_env_crapi, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line.startswith("CRAPI_USER_A_EMAIL="):
                os.environ.setdefault("CRAPI_USER_A_EMAIL", _line.split("=", 1)[1].strip())
            elif _line.startswith("CRAPI_USER_B_EMAIL="):
                os.environ.setdefault("CRAPI_USER_B_EMAIL", _line.split("=", 1)[1].strip())

USER_A_EMAIL = os.environ.get("CRAPI_USER_A_EMAIL", "crapi_user_a")
USER_A_PASSWORD = os.environ.get("CRAPI_USER_A_PASSWORD", "UserA!Secure123")
USER_B_EMAIL = os.environ.get("CRAPI_USER_B_EMAIL", "crapi_user_b")
USER_B_PASSWORD = os.environ.get("CRAPI_USER_B_PASSWORD", "UserB!Secure123")


def is_crapi_running() -> bool:
    """Checks whether crAPI target container is currently active."""
    try:
        resp = requests.get(f"{CRAPI_BASE_URL.rstrip('/')}/identity/api/auth/login", timeout=2)
        return True
    except Exception:
        try:
            resp = requests.get(CRAPI_BASE_URL, timeout=2)
            return True
        except Exception:
            return False


def test_crapi_allowlist_registered():
    """Validates that crAPI is properly configured in config/allowlist.yaml."""
    assert allowlist_validator.is_target_allowed("http://localhost:8888") is True
    assert allowlist_validator.is_target_allowed("http://127.0.0.1:8888") is True


@pytest.mark.skipif(not is_crapi_running(), reason="crAPI target lab container is not running on http://localhost:8888")
def test_crapi_users_can_authenticate():
    """
    Smoke test: Validates that both User A and User B can authenticate against
    a running crAPI instance and obtain valid JWT tokens.
    Automatically skipped if the crAPI container is offline.
    """
    login_url = f"{CRAPI_BASE_URL.rstrip('/')}/identity/api/auth/login"
    signup_url = f"{CRAPI_BASE_URL.rstrip('/')}/identity/api/auth/signup"

    def ensure_user_and_login(name: str, email: str, phone: str, password: str) -> str:
        # Attempt signup (idempotent)
        try:
            requests.post(
                signup_url,
                json={"name": name, "email": email, "number": phone, "password": password},
                timeout=5
            )
        except Exception:
            pass

        # Login
        resp = requests.post(
            login_url,
            json={"email": email, "password": password},
            timeout=5
        )
        assert resp.status_code == 200, f"Login failed for {email}: {resp.text}"
        data = resp.json()
        assert "token" in data, f"Token missing from login response for {email}"
        return data["token"]

    token_a = ensure_user_and_login("User Alpha", USER_A_EMAIL, "+15550000001", USER_A_PASSWORD)
    token_b = ensure_user_and_login("User Beta", USER_B_EMAIL, "+15550000002", USER_B_PASSWORD)

    assert token_a and len(token_a) > 20, "User A token is invalid or empty"
    assert token_b and len(token_b) > 20, "User B token is invalid or empty"
    assert token_a != token_b, "User A and User B received identical tokens"

    # Verify token access to protected endpoint
    vehicles_url = f"{CRAPI_BASE_URL.rstrip('/')}/identity/api/v2/vehicle/vehicles"
    v_resp_a = requests.get(vehicles_url, headers={"Authorization": f"Bearer {token_a}"}, timeout=5)
    assert v_resp_a.status_code == 200, f"Protected endpoint access failed for User A: {v_resp_a.text}"

    v_resp_b = requests.get(vehicles_url, headers={"Authorization": f"Bearer {token_b}"}, timeout=5)
    assert v_resp_b.status_code == 200, f"Protected endpoint access failed for User B: {v_resp_b.text}"
