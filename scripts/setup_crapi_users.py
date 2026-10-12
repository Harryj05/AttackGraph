#!/usr/bin/env python3
"""
Setup script for OWASP crAPI lab users.
1. Waits for crAPI gateway (and identity service) to become healthy and ready.
2. Registers User A and User B (idempotently).
3. Logs both users in and retrieves authentication JWT tokens.
4. Registers or retrieves User B's vehicle resource ID.
5. Saves tokens and resource ID to a git-ignored local file (.env.crapi).
"""

import os
import sys
import time
import json
import re
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, Tuple


CRAPI_BASE_URL = os.environ.get("CRAPI_BASE_URL", "http://localhost:8888")
MAILHOG_BASE_URL = os.environ.get("MAILHOG_BASE_URL", "http://localhost:8025")

USER_A_EMAIL = os.environ.get("CRAPI_USER_A_EMAIL", "user_a@example.com")
USER_A_PASSWORD = os.environ.get("CRAPI_USER_A_PASSWORD", "UserA!Secure123")
USER_A_NAME = "User Alpha"
USER_A_PHONE = "+15550000001"

USER_B_EMAIL = os.environ.get("CRAPI_USER_B_EMAIL", "user_b@example.com")
USER_B_PASSWORD = os.environ.get("CRAPI_USER_B_PASSWORD", "UserB!Secure123")
USER_B_NAME = "User Beta"
USER_B_PHONE = "+15550000002"


def _http_request(url: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None, timeout: int = 10) -> Tuple[int, Dict[str, Any], str]:
    """Helper to perform HTTP requests without external dependencies."""
    req_headers = {"Accept": "application/json"}
    if headers:
        req_headers.update(headers)

    body_bytes = None
    if data is not None:
        req_headers["Content-Type"] = "application/json"
        body_bytes = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = resp.status
            raw_text = resp.read().decode("utf-8", errors="replace")
            try:
                json_data = json.loads(raw_text)
            except Exception:
                json_data = {}
            return status_code, json_data, raw_text
    except urllib.error.HTTPError as e:
        status_code = e.code
        raw_text = e.read().decode("utf-8", errors="replace")
        try:
            json_data = json.loads(raw_text)
        except Exception:
            json_data = {}
        return status_code, json_data, raw_text
    except Exception as e:
        return 0, {}, str(e)


def wait_for_readiness(base_url: str = CRAPI_BASE_URL, timeout: int = 120, poll_interval: int = 2) -> bool:
    """Polls crAPI gateway and identity service until responsive."""
    print(f"[*] Waiting for crAPI to be ready at {base_url} (timeout: {timeout}s)...")
    start = time.time()
    login_url = f"{base_url.rstrip('/')}/identity/api/auth/login"

    while time.time() - start < timeout:
        status, _, raw = _http_request(login_url, method="POST", data={"email": "probe@check.local", "password": "probe"}, timeout=4)
        # Identity service is up if it returns 400 or 401 or 500 (meaning endpoint handled the payload)
        if status in (200, 400, 401, 500):
            print(f"[+] crAPI is ready! (HTTP status {status} on auth endpoint)")
            return True
        time.sleep(poll_interval)

    print(f"[-] Timed out waiting for crAPI readiness at {base_url}")
    return False


def register_user(base_url: str, name: str, email: str, phone: str, password: str) -> bool:
    """Registers user via POST /identity/api/auth/signup."""
    signup_url = f"{base_url.rstrip('/')}/identity/api/auth/signup"
    payload = {
        "name": name,
        "email": email,
        "number": phone,
        "password": password
    }
    status, data, raw = _http_request(signup_url, method="POST", data=payload)
    if status in (200, 201):
        print(f"[+] Successfully registered user: {email}")
        return True
    if (status in (400, 403)) and ("already" in raw.lower() or "duplicate" in raw.lower()):
        print(f"[*] User already registered: {email}")
        return True

    print(f"[!] Warning: registration returned status {status}: {raw[:150]}")
    return False


def login_user(base_url: str, email: str, password: str) -> Optional[str]:
    """Authenticates user via POST /identity/api/auth/login and returns JWT token."""
    login_url = f"{base_url.rstrip('/')}/identity/api/auth/login"
    payload = {
        "email": email,
        "password": password
    }
    status, data, raw = _http_request(login_url, method="POST", data=payload)
    if status == 200 and "token" in data:
        token = data["token"]
        masked = token[:10] + "..." + token[-6:] if len(token) > 20 else "***"
        print(f"[+] Logged in {email} -> token: {masked}")
        return token

    print(f"[-] Failed to login {email} (status {status}): {raw[:150]}")
    return None


def fetch_vehicle_credentials_from_mailhog(mailhog_url: str, target_email: str) -> Optional[Tuple[str, str]]:
    """Polls MailHog for the signup email containing VIN and pincode for target_email."""
    messages_url = f"{mailhog_url.rstrip('/')}/api/v2/messages"
    print(f"[*] Checking MailHog at {messages_url} for welcome email to {target_email}...")

    for _ in range(6):
        status, data, raw = _http_request(messages_url, method="GET")
        if status == 200 and "items" in data:
            for item in data.get("items", []):
                recipients = [to.get("Mailbox", "") + "@" + to.get("Domain", "") for to in item.get("To", [])]
                raw_recipients = str(item.get("To", []))
                if target_email.lower() in raw_recipients.lower() or any(target_email.lower() in r.lower() for r in recipients):
                    body = item.get("Content", {}).get("Body", "")
                    clean_body = re.sub(r"<[^>]+>", " ", body)
                    vin_match = re.search(r"VIN:\s*([A-Za-z0-9]+)", clean_body, re.IGNORECASE)
                    pin_match = re.search(r"pin(?:code)?:\s*(\d+)", clean_body, re.IGNORECASE)
                    if vin_match and pin_match:
                        vin = vin_match.group(1).strip()
                        pin = pin_match.group(1).strip()
                        print(f"[+] Found vehicle info in MailHog email: VIN={vin}, PIN={pin}")
                        return vin, pin
        time.sleep(2)

    return None


def get_or_create_user_vehicle(base_url: str, mailhog_url: str, email: str, token: str) -> Optional[str]:
    """Retrieves or adds a vehicle for User B, returning the vehicle's UUID."""
    vehicles_url = f"{base_url.rstrip('/')}/identity/api/v2/vehicle/vehicles"
    auth_header = {"Authorization": f"Bearer {token}"}

    # 1. Check if user already has registered vehicles
    status, data, raw = _http_request(vehicles_url, method="GET", headers=auth_header)
    if status == 200 and isinstance(data, list) and len(data) > 0:
        v = data[0]
        vehicle_id = v.get("uuid") or str(v.get("id"))
        print(f"[+] User {email} already owns vehicle: {vehicle_id}")
        return vehicle_id

    # 2. If not, inspect MailHog to get VIN & pincode and call add_vehicle
    creds = fetch_vehicle_credentials_from_mailhog(mailhog_url, email)
    if creds:
        vin, pincode = creds
        add_vehicle_url = f"{base_url.rstrip('/')}/identity/api/v2/vehicle/add_vehicle"
        add_status, _, add_raw = _http_request(
            add_vehicle_url,
            method="POST",
            data={"vin": vin, "pincode": pincode},
            headers=auth_header
        )
        if add_status in (200, 201):
            print(f"[+] Successfully added vehicle via add_vehicle")
            # Query vehicles again to obtain the UUID
            status, data, _ = _http_request(vehicles_url, method="GET", headers=auth_header)
            if status == 200 and isinstance(data, list) and len(data) > 0:
                vehicle_id = data[0].get("uuid") or str(data[0].get("id"))
                print(f"[+] Retrieved vehicle UUID: {vehicle_id}")
                return vehicle_id

    # 3. Fallback: check dashboard or community posts
    dashboard_url = f"{base_url.rstrip('/')}/identity/api/v2/user/dashboard"
    status, d_data, _ = _http_request(dashboard_url, method="GET", headers=auth_header)
    if status == 200 and isinstance(d_data, dict):
        available_vehicles = d_data.get("available_vehicles") or d_data.get("vehicles") or []
        if isinstance(available_vehicles, list) and len(available_vehicles) > 0:
            vehicle_id = available_vehicles[0].get("uuid") or str(available_vehicles[0].get("id"))
            return vehicle_id

    print(f"[!] Note: Could not retrieve a vehicle for {email}. Using placeholder identifier.")
    return "00000000-0000-0000-0000-000000000001"


def save_environment(
    base_url: str,
    user_a_email: str,
    user_a_token: str,
    user_b_email: str,
    user_b_token: str,
    user_b_vehicle_id: str,
    output_filename: str = ".env.crapi"
) -> str:
    """Writes tokens and vehicle ID into a git-ignored configuration file."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target_path = os.path.join(repo_root, output_filename)

    lines = [
        f"# OWASP crAPI Local Session Configuration (Generated: {time.strftime('%Y-%m-%d %H:%M:%S')})",
        f"# This file is git-ignored and contains active authentication tokens.",
        f"CRAPI_BASE_URL={base_url}",
        f"CRAPI_USER_A_EMAIL={user_a_email}",
        f"CRAPI_USER_A_TOKEN={user_a_token}",
        f"CRAPI_USER_B_EMAIL={user_b_email}",
        f"CRAPI_USER_B_TOKEN={user_b_token}",
        f"CRAPI_USER_B_VEHICLE_ID={user_b_vehicle_id}",
        ""
    ]

    with open(target_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"[+] Credentials written to git-ignored file: {target_path}")
    return target_path


def main() -> int:
    print("=" * 60)
    print("OWASP crAPI Automated Setup & Session Generation")
    print("=" * 60)

    # 1. Readiness check
    if not wait_for_readiness(CRAPI_BASE_URL, timeout=120):
        print("[-] crAPI is not reachable. Ensure containers are running with:")
        print("    docker compose -f docker-compose.crapi.yml up -d")
        return 1

    # 2. Register users
    print("\n[*] Registering test users...")
    register_user(CRAPI_BASE_URL, USER_A_NAME, USER_A_EMAIL, USER_A_PHONE, USER_A_PASSWORD)
    register_user(CRAPI_BASE_URL, USER_B_NAME, USER_B_EMAIL, USER_B_PHONE, USER_B_PASSWORD)

    # 3. Log both in
    print("\n[*] Authenticating users...")
    token_a = login_user(CRAPI_BASE_URL, USER_A_EMAIL, USER_A_PASSWORD)
    token_b = login_user(CRAPI_BASE_URL, USER_B_EMAIL, USER_B_PASSWORD)

    if not token_a or not token_b:
        print("[-] Authentication failed for one or both users.")
        return 1

    # 4. Get User B vehicle
    print("\n[*] Resolving User B vehicle resource ID...")
    vehicle_id_b = get_or_create_user_vehicle(CRAPI_BASE_URL, MAILHOG_BASE_URL, USER_B_EMAIL, token_b) or "unknown"

    # 5. Save to gitignored .env.crapi
    print("\n[*] Saving session tokens...")
    save_environment(
        base_url=CRAPI_BASE_URL,
        user_a_email=USER_A_EMAIL,
        user_a_token=token_a,
        user_b_email=USER_B_EMAIL,
        user_b_token=token_b,
        user_b_vehicle_id=vehicle_id_b,
        output_filename=".env.crapi"
    )

    print("\n[+] crAPI user setup completed successfully!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
