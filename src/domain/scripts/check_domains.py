#!/usr/bin/env python3
"""
Automatic domain expiration checker.

- Reads domains from domains.conf (domain-only list)
- Uses RDAP for global domains
- Uses register.domains.lk API helper for .lk domains
- Writes domain_results.json in the same schema used by index.html
"""

import concurrent.futures
import datetime
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

try:
    from check_LK_domains import get_expiry_date as get_lk_expiry_date
except ModuleNotFoundError:
    from .check_LK_domains import get_expiry_date as get_lk_expiry_date

DOMAIN_FILE = "domains.conf"
LEGACY_DOMAIN_FILE = "ssl.conf"
OUTPUT_FILE = "domain_results.json"
TIMEOUT = 20
MAX_WORKERS = 20
REQUEST_DELAY_SECONDS = float(os.getenv("DOMAIN_CHECK_DELAY_SEC", "0.35"))

RDAP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (DomainExpiryChecker/1.0)",
    "Accept": "application/rdap+json, application/json;q=0.9, */*;q=0.8",
}

WHOIS_EXPIRY_PATTERNS = (
    r"Registry Expiry Date:\s*(.+)",
    r"Registrar Registration Expiration Date:\s*(.+)",
    r"Expiry Date:\s*(.+)",
    r"Expiration Date:\s*(.+)",
    r"paid-till:\s*(.+)",
    r"renewal date:\s*(.+)",
    r"expire-date:\s*(.+)",
    r"domain_datebilleduntil:\s*(.+)",
    r"Record expires on\s*(.+)",
    r"Expires On:\s*(.+)",
)

WHOIS_REGISTRAR_PATTERNS = (
    r"Registrar:\s*(.+)",
    r"Sponsoring Registrar:\s*(.+)",
    r"registrar-name:\s*(.+)",
    r"Registrar Name:\s*(.+)",
)

_RATE_LIMIT_LOCK = threading.Lock()
_LAST_REQUEST_TS = 0.0


def throttle_request() -> None:
    """Throttle outbound network calls across all worker threads."""
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


# Registrar reseller → canonical name mapping.
# Some registrars wholesale through backend providers; map them to the
# brand the customer actually purchased from.
REGISTRAR_ALIASES: dict[str, str] = {
    "godaddy.com, llc":                          "GoDaddy",
    "godaddy":                                   "GoDaddy",
    "go daddy llc":                              "GoDaddy",
    "csl computer service langenbach gmbh":      "GoDaddy",
    "cscsl computer service langenbach":         "GoDaddy",
    "joker.com":                                 "GoDaddy",
    "nameaction":                                "GoDaddy",
    "wild west domains":                         "GoDaddy",
    "namecheap, inc.":                           "Namecheap",
    "namecheap":                                 "Namecheap",
    "cloudflare, inc.":                          "Cloudflare",
    "cloudflare":                                "Cloudflare",
    "name.com, inc.":                            "Name.com",
    "name.com":                                  "Name.com",
    "network solutions":                         "Network Solutions",
    "web commerce communications":               "Domainnameshop",
    "enom":                                      "eNom",
}


def normalize_registrar(raw: str) -> str:
    """Map raw WHOIS registrar strings to a clean canonical name."""
    if not raw or raw == "N/A":
        return raw
    lower = raw.lower()
    for pattern, canonical in REGISTRAR_ALIASES.items():
        if pattern in lower:
            return canonical
    return raw


def normalize_domain(value: str) -> str:
    domain = value.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].strip(" .")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def load_domains(filepath: str) -> list[str]:
    seen = set()
    domains = []
    with open(filepath, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            first_token = line.split()[0]
            domain = normalize_domain(first_token)
            if not domain:
                continue
            if "_" in domain and not domain.startswith("_"):
                continue
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains


def parse_date(value: str) -> datetime.datetime | None:
    text = (value or "").strip()
    if not text:
        return None

    # WHOIS values may include timezone names or extra prose.
    text = re.sub(r"\s+UTC$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+GMT$", "", text, flags=re.IGNORECASE)
    text = text.strip(" .")

    # register.domains.lk can return values like: "Tuesday, 8th December, 2026"
    ordinal_match = re.match(
        r"^[A-Za-z]+,\s+(\d{1,2})(?:st|nd|rd|th)\s+([A-Za-z]+),\s+(\d{4})$",
        text,
    )
    if ordinal_match:
        day = int(ordinal_match.group(1))
        month_name = ordinal_match.group(2)
        year = int(ordinal_match.group(3))
        try:
            month = datetime.datetime.strptime(month_name, "%B").month
            return datetime.datetime(year, month, day)
        except ValueError:
            pass

    formats = (
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%Y.%m.%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%d.%m.%Y",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%b %d %Y",
        "%B %d %Y",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y.%m.%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
        "%d-%B-%Y %H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.datetime.strptime(text, fmt)
        except ValueError:
            continue

    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            return parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return parsed
    except ValueError:
        return None


def days_to_status(days_left: int | None) -> str:
    if days_left is None:
        return "unknown"
    if days_left <= 0:
        return "expired"
    if days_left <= 7:
        return "urgent"
    if days_left <= 30:
        return "warning"
    return "active"


def extract_registrar(rdap: dict) -> str:
    entities = rdap.get("entities") if isinstance(rdap, dict) else []
    if not isinstance(entities, list):
        return "N/A"

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles") or []
        if "registrar" not in [str(role).lower() for role in roles]:
            continue
        vcard_array = entity.get("vcardArray")
        if not isinstance(vcard_array, list) or len(vcard_array) < 2:
            continue
        fields = vcard_array[1]
        if not isinstance(fields, list):
            continue
        for field in fields:
            if not isinstance(field, list) or len(field) < 4:
                continue
            key = str(field[0]).lower()
            value = field[3]
            if key in ("fn", "org") and isinstance(value, str) and value.strip():
                return value.strip()

    return "N/A"


def extract_expiry_from_rdap(rdap: dict) -> datetime.datetime | None:
    if not isinstance(rdap, dict):
        return None

    events = rdap.get("events") or []
    best_match = None
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).lower()
            if "expir" not in action:
                continue
            parsed = parse_date(str(event.get("eventDate", "")))
            if parsed is None:
                continue
            if best_match is None or parsed > best_match:
                best_match = parsed
    if best_match is not None:
        return best_match

    for key in ("expirationDate", "expiryDate", "expires"):
        value = rdap.get(key)
        if isinstance(value, str):
            parsed = parse_date(value)
            if parsed is not None:
                return parsed

    return None


def lookup_global_domain(domain: str) -> tuple[str, str, str | None]:
    # Try generic RDAP gateway first.
    registrar, err, expiry = lookup_global_domain_rdap(domain, base_url="https://rdap.org/")
    if expiry is not None:
        return registrar, "", expiry

    # Fallback 1: ask IANA bootstrap for authoritative RDAP service.
    rdap_base = get_rdap_base_url_for_domain(domain)
    if rdap_base:
        reg2, err2, exp2 = lookup_global_domain_rdap(domain, base_url=rdap_base)
        if exp2 is not None:
            return reg2, "", exp2
        if reg2 != "N/A":
            registrar = reg2
        if err2 and err == "":
            err = err2

    # Fallback 2: raw WHOIS query over port 43.
    reg3, err3, exp3 = lookup_global_domain_whois(domain)
    if exp3 is not None:
        return reg3, "", exp3
    if reg3 != "N/A":
        registrar = reg3

    combined_err = "; ".join(part for part in (err, err3) if part)
    return registrar, combined_err or "No expiry in RDAP/WHOIS", None


def lookup_global_domain_rdap(domain: str, base_url: str) -> tuple[str, str, str | None]:
    base = base_url.rstrip("/") + "/"
    url = urllib.parse.urljoin(base, f"domain/{urllib.parse.quote(domain)}")
    req = urllib.request.Request(url, headers=RDAP_HEADERS, method="GET")

    try:
        throttle_request()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except TimeoutError:
        return "N/A", "RDAP timeout", None
    except urllib.error.HTTPError as exc:
        return "N/A", f"RDAP HTTP error: {exc.code}", None
    except urllib.error.URLError as exc:
        return "N/A", f"RDAP connection error: {exc.reason}", None
    except (ValueError, json.JSONDecodeError):
        return "N/A", "RDAP returned invalid JSON", None

    registrar = extract_registrar(payload)
    expiry_dt = extract_expiry_from_rdap(payload)
    if expiry_dt is None:
        return registrar, "Expiration date not found in RDAP", None

    return registrar, "", expiry_dt.strftime("%Y-%m-%d")


def get_rdap_base_url_for_domain(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    bootstrap_url = "https://data.iana.org/rdap/dns.json"
    req = urllib.request.Request(bootstrap_url, headers=RDAP_HEADERS, method="GET")

    try:
        throttle_request()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None

    services = payload.get("services") if isinstance(payload, dict) else None
    if not isinstance(services, list):
        return None

    for service in services:
        if not isinstance(service, list) or len(service) < 2:
            continue
        tlds = service[0]
        urls = service[1]
        if not isinstance(tlds, list) or not isinstance(urls, list):
            continue
        if tld in [str(item).lower() for item in tlds]:
            for item in urls:
                if isinstance(item, str) and item.startswith("http"):
                    return item

    return None


def get_whois_server_for_domain(domain: str) -> str | None:
    tld = domain.rsplit(".", 1)[-1].lower()
    response = query_whois_server("whois.iana.org", tld)
    if not response:
        return None

    for line in response.splitlines():
        if line.lower().startswith("whois:"):
            server = line.split(":", 1)[1].strip()
            if server:
                return server
    return None


def query_whois_server(server: str, query: str) -> str | None:
    try:
        throttle_request()
        with socket.create_connection((server, 43), timeout=TIMEOUT) as sock:
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
    except OSError:
        return None

    try:
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return None


def parse_registrar_from_whois(text: str) -> str:
    for pattern in WHOIS_REGISTRAR_PATTERNS:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if not match:
            continue
        value = match.group(1).strip()
        if value:
            return value
    return "N/A"


def parse_expiry_from_whois(text: str) -> str | None:
    candidates = []
    for pattern in WHOIS_EXPIRY_PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            raw = match.group(1).strip()
            # Keep date-like token if additional comments appear on line.
            raw = raw.split(" (", 1)[0].strip()
            parsed = parse_date(raw)
            if parsed is not None:
                candidates.append(parsed)

    if not candidates:
        return None
    return max(candidates).strftime("%Y-%m-%d")


def lookup_global_domain_whois(domain: str) -> tuple[str, str, str | None]:
    server = get_whois_server_for_domain(domain)
    if not server:
        return "N/A", "WHOIS server not found", None

    response = query_whois_server(server, domain)
    if not response:
        return "N/A", f"WHOIS query failed ({server})", None

    lowered = response.lower()
    if "no match" in lowered or "not found" in lowered or "available" in lowered:
        return "N/A", "Domain appears unregistered in WHOIS", None

    registrar = parse_registrar_from_whois(response)
    expiry = parse_expiry_from_whois(response)
    if expiry is None:
        return registrar, "Expiry not found in WHOIS", None

    return registrar, "", expiry


def check_domain(domain: str) -> dict:
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    result = {
        "domain": domain,
        "registrar": "N/A",
        "purchase_date": "N/A",
        "expiry_date": "N/A",
        "days_left": None,
        "status": "unknown",
    }

    if domain.endswith(".lk"):
        result["registrar"] = "domains.lk"
        throttle_request()
        lk_value = get_lk_expiry_date(domain, verbose=False)
        expiry_dt = parse_date(lk_value)
        if expiry_dt is None:
            if "not registered" in lk_value.lower():
                result["status"] = "unknown"
            else:
                result["status"] = "unknown"
            return result

        result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
        result["days_left"] = (expiry_dt - now).days
        result["status"] = days_to_status(result["days_left"])
        return result

    registrar, err, expiry_value = lookup_global_domain(domain)
    result["registrar"] = normalize_registrar(registrar)
    if expiry_value is None:
        if err:
            result["status"] = "unknown"
        return result

    expiry_dt = parse_date(expiry_value)
    if expiry_dt is None:
        return result

    result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
    result["days_left"] = (expiry_dt - now).days
    result["status"] = days_to_status(result["days_left"])
    return result


def choose_domain_file() -> str:
    if os.path.exists(DOMAIN_FILE):
        return DOMAIN_FILE
    return LEGACY_DOMAIN_FILE


def main() -> None:
    domain_file = choose_domain_file()
    print(f"Loading domains from {domain_file}...")
    domains = load_domains(domain_file)
    print(f"Found {len(domains)} unique domains. Checking expirations...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_domain, domain): domain for domain in domains}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            results.append(result)
            completed += 1
            days = result["days_left"]
            days_text = f"{days}d" if days is not None else "N/A"
            print(
                f"[{completed:3d}/{len(domains)}] {result['domain']:<45} "
                f"{result['registrar']:<20} expires: {result['expiry_date']} ({days_text})"
            )

    status_rank = {
        "unknown": 0,
        "expired": 1,
        "urgent": 2,
        "warning": 3,
        "active": 4,
    }
    results.sort(
        key=lambda row: (
            status_rank.get(row.get("status", "unknown"), 4),
            row["days_left"] if row["days_left"] is not None else 99999,
            row.get("domain", ""),
        )
    )

    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
    output = {
        "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
        "total_domains": len(results),
        "active": sum(1 for row in results if row["status"] == "active"),
        "warning": sum(1 for row in results if row["status"] == "warning"),
        "urgent": sum(1 for row in results if row["status"] == "urgent"),
        "expired": sum(1 for row in results if row["status"] == "expired"),
        "results": results,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)

    print(f"\nResults saved to {OUTPUT_FILE}")
    print(f"  Active:  {output['active']}")
    print(f"  Warning: {output['warning']}")
    print(f"  Urgent:  {output['urgent']}")
    print(f"  Expired: {output['expired']}")


if __name__ == "__main__":
    main()
