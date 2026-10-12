import os
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader, APIKeyQuery

API_KEY_HEADER_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)


def get_configured_api_key() -> str:
    """Retrieves the configured API key from environment, with a default development key."""
    return (
        os.getenv("ATTACKGRAPH_API_KEY")
        or os.getenv("API_KEY")
        or "attackgraph-insecure-dev-key"
    )


def verify_api_key(
    key_from_header: str = Security(api_key_header),
    key_from_query: str = Security(api_key_query)
) -> str:
    """
    Validates X-API-Key header or api_key query parameter against the configured key.
    Rejects unauthorized access with HTTP 401.
    """
    configured_key = get_configured_api_key()
    provided_key = key_from_header or key_from_query

    if not provided_key or provided_key != configured_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid or missing X-API-Key authentication."
        )
    return provided_key
