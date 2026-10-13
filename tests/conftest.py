import os
import pytest
from starlette.testclient import TestClient

os.environ.setdefault("ATTACKGRAPH_API_KEY", "attackgraph-insecure-dev-key")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

_orig_request = TestClient.request

def _patched_request(self, method, url, *args, **kwargs):
    headers = kwargs.get("headers")
    if headers is None:
        kwargs["headers"] = {"X-API-Key": "attackgraph-insecure-dev-key"}
    else:
        # If headers was explicitly passed, attach default key only if no explicit
        # auth header (or skip flag) is present.
        if "skip-auto-auth" in headers:
            headers_copy = dict(headers)
            headers_copy.pop("skip-auto-auth")
            kwargs["headers"] = headers_copy
        elif not any(k.lower() == "x-api-key" for k in headers):
            headers_copy = dict(headers)
            headers_copy["X-API-Key"] = "attackgraph-insecure-dev-key"
            kwargs["headers"] = headers_copy
    return _orig_request(self, method, url, *args, **kwargs)

TestClient.request = _patched_request
