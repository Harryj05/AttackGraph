"""
api/credentials.py

Server-side credential registry for authenticated scan execution.
Stores sensitive tokens/cookies per scan_id under abstract handles (e.g. 'user_a', 'user_b').
The LLM, prompt templates, state summaries, and agent logs only ever see handle names.
Tools resolve handles to real tokens at execution time immediately before issuing requests.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List

REPO_ROOT = Path(__file__).resolve().parent.parent

# In-memory server-side credential registry: scan_id -> {handle_name: token_or_secret}
_SCAN_CREDENTIALS: Dict[str, Dict[str, str]] = {}


def register_scan_credentials(scan_id: str, credentials: Dict[str, str]) -> None:
    """
    Registers credential handles for a scan session.
    Example: credentials = {"user_a": "jwt_token_user_a...", "user_b": "jwt_token_user_b..."}
    """
    if not scan_id:
        return
    if scan_id not in _SCAN_CREDENTIALS:
        _SCAN_CREDENTIALS[scan_id] = {}
    _SCAN_CREDENTIALS[scan_id].update(credentials)


def get_scan_credential(scan_id: str, handle: str) -> Optional[str]:
    """Resolves an abstract credential handle to its real token/secret at tool execution time."""
    if not scan_id or not handle:
        return None
    scan_creds = _SCAN_CREDENTIALS.get(scan_id, {})
    return scan_creds.get(handle)


def get_scan_credential_handles(scan_id: str) -> List[str]:
    """Returns list of available abstract handle names (never exposing secret values)."""
    return sorted(list(_SCAN_CREDENTIALS.get(scan_id, {}).keys()))


def clear_scan_credentials(scan_id: str) -> None:
    """Clears registered credentials when scan terminates."""
    _SCAN_CREDENTIALS.pop(scan_id, None)


def auto_load_lab_credentials(scan_id: str, target_url: str) -> List[str]:
    """
    Automatically initializes credential handles for local lab targets
    from .env.crapi or local lab environments.
    Returns list of registered handle names (e.g. ['user_a', 'user_b']).
    """
    handles_registered = []

    # 1. crAPI targets (port 8888)
    if ":8888" in target_url:
        env_crapi = REPO_ROOT / ".env.crapi"
        token_a = os.environ.get("CRAPI_USER_A_TOKEN", "")
        token_b = os.environ.get("CRAPI_USER_B_TOKEN", "")

        if env_crapi.exists():
            with open(env_crapi, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("CRAPI_USER_A_TOKEN="):
                        token_a = line.split("=", 1)[1].strip()
                    elif line.startswith("CRAPI_USER_B_TOKEN="):
                        token_b = line.split("=", 1)[1].strip()

        creds = {}
        if token_a:
            creds["user_a"] = token_a
        if token_b:
            creds["user_b"] = token_b

        if creds:
            register_scan_credentials(scan_id, creds)
            handles_registered = list(creds.keys())

    return handles_registered
