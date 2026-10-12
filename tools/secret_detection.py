import base64
import json
import re
import hashlib
from typing import List, Dict, Any, Tuple

# Documented Validation Rule:
# Secret pattern regex matches produce state 'HYPOTHESIS' by default.
# Only secrets whose internal structure can be decoded and verified offline
# (e.g., JWT header/payload base64url decode into valid JSON objects with 'alg' or 'typ')
# are promoted to 'CONFIRMED'. Unvalidated regex matches (e.g. AWS access key ID format,
# database URLs, API key assignments) remain 'HYPOTHESIS' until actively verified.

class SecretPattern:
    def __init__(self, key: str, name: str, pattern: str, confidence: float, description: str):
        self.key = key
        self.name = name
        self.pattern = re.compile(pattern, re.MULTILINE)
        self.confidence = confidence
        self.description = description

# Documented pattern list covered in secret detection
# Scope: Structural signatures for high-value secrets (AWS keys, JWTs, DB connection URLs, API keys, password assignments).
SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        key="aws_access_key",
        name="AWS Access Key ID",
        pattern=r"\b(AKIA[0-9A-Z]{16})\b",
        confidence=0.95,
        description="Matched structural AWS Access Key ID format (AKIA + 16 alphanumeric characters)"
    ),
    SecretPattern(
        key="jwt_token",
        name="JWT Authentication Token",
        pattern=r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b",
        confidence=0.90,
        description="Matched JSON Web Token (JWT) three-part dot-separated base64url format"
    ),
    SecretPattern(
        key="database_url",
        name="Database Connection String",
        pattern=r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[A-Za-z0-9_.~%-]+:[^@\s'\"]+@[A-Za-z0-9_.-]+(?::\d+)?/[A-Za-z0-9_.~%-]+)\b",
        confidence=0.85,
        description="Matched Database Connection URL scheme with embedded credentials"
    ),
    SecretPattern(
        key="api_key_assignment",
        name="API Key Assignment",
        pattern=r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
        confidence=0.75,
        description="Matched API key or access token key-value assignment in JS/JSON"
    ),
    SecretPattern(
        key="generic_secret_assignment",
        name="Password/Secret Assignment",
        pattern=r"(?i)\b(?:password|passwd|pwd|db_pass)\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']",
        confidence=0.70,
        description="Matched password or secret key-value assignment in JS/JSON"
    )
]


def validate_secret_structure(val: str, pattern_key: str) -> Tuple[bool, str]:
    """
    Validates internal structure of a secret candidate beyond regex matching.
    Rule: Regex pattern matches alone produce state 'HYPOTHESIS'.
    Only secrets whose internal structure can be decoded and verified offline
    (e.g., JWT header/payload base64url decode into valid JSON objects with 'alg' or 'typ')
    are promoted to 'CONFIRMED'.
    """
    if pattern_key == "jwt_token":
        parts = val.split(".")
        if len(parts) == 3:
            try:
                def b64url_decode(s: str) -> bytes:
                    rem = len(s) % 4
                    if rem > 0:
                        s += "=" * (4 - rem)
                    return base64.urlsafe_b64decode(s.encode("ascii"))

                header_bytes = b64url_decode(parts[0])
                payload_bytes = b64url_decode(parts[1])
                header = json.loads(header_bytes.decode("utf-8", errors="strict"))
                payload = json.loads(payload_bytes.decode("utf-8", errors="strict"))
                if isinstance(header, dict) and isinstance(payload, dict):
                    if "alg" in header or "typ" in header:
                        return True, "Valid JWT structure: header and payload decoded as JSON"
            except Exception:
                pass
        return False, "Unvalidated JWT format: failed base64url or JSON payload decode"

    # Regex matches without offline verifiable structural checksum remain HYPOTHESIS
    return False, f"Regex pattern match for '{pattern_key}' without offline verifiable structural checksum"


def redact_secret_value(val: str, secret_type: str) -> Dict[str, Any]:
    """
    Computes redacted secret metadata: type, first 4 characters, length, and SHA-256 hash.
    The full secret value is never retained.
    """
    prefix = val[:4] if len(val) >= 4 else val
    val_len = len(val)
    sha256_hash = hashlib.sha256(val.encode("utf-8")).hexdigest()
    placeholder = f"[REDACTED_{secret_type.upper()}:prefix={prefix}:len={val_len}:sha256={sha256_hash[:8]}]"
    return {
        "type": secret_type,
        "prefix": prefix,
        "length": val_len,
        "sha256": sha256_hash,
        "placeholder": placeholder,
    }


def extract_secrets_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Scans response body text against documented secret patterns.
    Returns list of match metadata dictionaries containing ONLY:
    type, first 4 chars (prefix), length, SHA-256 hash, and structural validation state.
    Never returns or stores the full secret value.
    """
    if not text:
        return []

    results: List[Dict[str, Any]] = []
    seen_matches = set()

    for p in SECRET_PATTERNS:
        for match in p.pattern.finditer(text):
            val = match.group(1) if match.groups() else match.group(0)
            if not val or val in seen_matches:
                continue

            seen_matches.add(val)
            meta = redact_secret_value(val, p.key)
            preview = f"{meta['prefix']}... (len={meta['length']}, sha256={meta['sha256'][:8]})"
            is_validated, val_reason = validate_secret_structure(val, p.key)
            state = "CONFIRMED" if is_validated else "HYPOTHESIS"

            results.append({
                "type": p.key,
                "pattern_key": p.key,
                "name": p.name,
                "prefix": meta["prefix"],
                "length": meta["length"],
                "sha256": meta["sha256"],
                "match_preview": preview,
                "confidence": p.confidence,
                "description": p.description,
                "is_validated": is_validated,
                "state": state,
                "validation_reason": val_reason,
            })

    return results


def sanitize_text_secrets(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Redacts all secrets within text at storage time, replacing every instance with
    [REDACTED_{TYPE}:prefix={first 4}:len={length}:sha256={hash[:8]}].
    Returns the sanitized text and the list of redacted secret metadata dicts.
    """
    if not text:
        return "", []

    detected_secrets = extract_secrets_from_text(text)
    sanitized = text

    # Replace each matched pattern occurrence with its placeholder
    for p in SECRET_PATTERNS:
        for match in p.pattern.finditer(sanitized):
            val = match.group(1) if match.groups() else match.group(0)
            if val:
                meta = redact_secret_value(val, p.key)
                sanitized = sanitized.replace(val, meta["placeholder"])

    # Secondary redaction for common Authorization / Bearer tokens and cookies
    sanitized = re.sub(
        r"Bearer\s+[A-Za-z0-9\-_.]+",
        lambda m: f"[REDACTED_BEARER:prefix={m.group(0)[:10]}:len={len(m.group(0))}:sha256={hashlib.sha256(m.group(0).encode()).hexdigest()[:8]}]",
        sanitized,
        flags=re.IGNORECASE
    )

    return sanitized, detected_secrets
