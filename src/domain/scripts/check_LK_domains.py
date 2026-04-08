#!/usr/bin/env python3
"""Helpers for reading .lk domain expiration dates from register.domains.lk."""

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "https://register.domains.lk"
SEARCH_URL = f"{BASE_URL}/domains-search"
API_URL = f"{BASE_URL}/proxy/domains/single-search"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Referer": SEARCH_URL,
    "Accept": "application/json, text/plain, */*",
}

REQUEST_DELAY_SECONDS = float(os.getenv("LK_CHECK_DELAY_SEC", "0.8"))
MAX_RETRIES = int(os.getenv("LK_CHECK_MAX_RETRIES", "3"))

_RATE_LIMIT_LOCK = threading.Lock()
_LAST_REQUEST_TS = 0.0


def _throttle_request() -> None:
    """Throttle outbound LK API calls across worker threads/process imports."""
    global _LAST_REQUEST_TS
    if REQUEST_DELAY_SECONDS <= 0:
        return

    with _RATE_LIMIT_LOCK:
        now = time.monotonic()
        elapsed = now - _LAST_REQUEST_TS
        wait_for = REQUEST_DELAY_SECONDS - elapsed
        if wait_for > 0:
            time.sleep(wait_for)
        _LAST_REQUEST_TS = time.monotonic()


def _normalize_lk_domain(domain: str) -> str:
    value = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/")[0].strip(" .")
    if value.startswith("www."):
        value = value[4:]
    return value


def get_expiry_date(domain: str, verbose: bool = False) -> str:
    """
    Query register.domains.lk and return expiry date as YYYY-MM-DD when available.
    Returns human-readable status text when expiry cannot be determined.
    """
    lookup_domain = _normalize_lk_domain(domain)
    if not lookup_domain:
        return "[ERROR] Invalid domain"

    if verbose:
        print(f"[*] Connecting to {BASE_URL} ...")
        print(f"[*] Searching for: {lookup_domain}")

    query = urllib.parse.urlencode({"keyword": lookup_domain})
    url = f"{API_URL}?{query}"
    req = urllib.request.Request(url, headers=HEADERS, method="GET")

    payload = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            _throttle_request()
            with urllib.request.urlopen(req, timeout=15) as response:
                payload = json.loads(response.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < MAX_RETRIES:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                try:
                    wait_seconds = float(retry_after) if retry_after else min(2 ** attempt, 8)
                except ValueError:
                    wait_seconds = min(2 ** attempt, 8)
                time.sleep(max(wait_seconds, REQUEST_DELAY_SECONDS))
                continue
            return f"[ERROR] LK API HTTP error: {exc.code}"
        except urllib.error.URLError as exc:
            if attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 8))
                continue
            return f"[ERROR] LK API connection error: {exc.reason}"
        except (ValueError, json.JSONDecodeError):
            return "[ERROR] LK API returned invalid JSON"

    if payload is None:
        return "[ERROR] LK API request failed after retries"

    availability = {}
    if isinstance(payload, dict):
        availability = payload.get("result", {}).get("domainAvailability", {}) or {}

    if not availability:
        return "[INFO] Domain information not available from LK API."

    if availability.get("isAvailable") is True:
        return "[INFO] Domain is NOT registered (available for registration)."

    domain_info = availability.get("domainInfo") or {}
    expiry = domain_info.get("expireDate")
    if isinstance(expiry, str) and expiry.strip():
        return expiry.strip()

    message = availability.get("message", "")
    if isinstance(message, str) and message.strip():
        return f"[INFO] {message.strip()}"

    return "[INFO] Domain is registered, but expiry date is not exposed by API."