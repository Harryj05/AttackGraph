import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)


def get_configured_api_key() -> str:
    """
    Retrieves the configured API key from environment.
    Enforces a strict fail-closed security policy: if neither ATTACKGRAPH_API_KEY nor
    API_KEY is set, the application refuses to start with default or missing credentials.
    """
    key = os.getenv("ATTACKGRAPH_API_KEY") or os.getenv("API_KEY")
    if not key:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: No API key environment variable set. "
            "Either ATTACKGRAPH_API_KEY or API_KEY must be defined in the environment. "
            "The application refuses to start with missing or default credentials (fail-closed)."
        )
    return key


def verify_api_key(
    key_from_header: str = Security(api_key_header)
) -> str:
    """
    Validates X-API-Key HTTP header against the configured key.
    Enforces strict header-only authentication to prevent token leakage in URL access logs.
    Rejects unauthorized or query-parameter access with HTTP 401.
    """
    configured_key = get_configured_api_key()

    if not key_from_header or key_from_header != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing or invalid X-API-Key authentication header."
        )
    return key_from_header
