#!/usr/bin/env python3
"""
SSL Certificate Checker
Reads domains from domain.conf and checks SSL certificate details:
- Provider/Issuer (Let's Encrypt, Cloudflare, 12SSL, etc.)
- Issue date
- Expiry date
- Days remaining
Outputs results to ssl_results.json
"""

import ssl
import socket
import json
import datetime
import concurrent.futures
from cryptography import x509
from cryptography.hazmat.backends import default_backend

DOMAIN_FILE = "ssl.conf"
OUTPUT_FILE = "ssl_results.json"
TIMEOUT = 15
MAX_WORKERS = 20


def detect_provider(issuer: dict) -> str:
    """Detect SSL provider from certificate issuer fields."""
    org = issuer.get("organizationName", "").lower()
    cn = issuer.get("commonName", "").lower()
    combined = f"{org} {cn}"

    if "let's encrypt" in combined or "letsencrypt" in combined:
        return "Let's Encrypt"
    elif "cloudflare" in combined:
        return "Cloudflare SSL"
    elif "sectigo" in combined or "comodo" in combined:
        return "Sectigo / Comodo"
    elif "digicert" in combined:
        return "DigiCert"
    elif "geotrust" in combined:
        return "GeoTrust"
    elif "globalsign" in combined:
        return "GlobalSign"
    elif "godaddy" in combined:
        return "GoDaddy"
    elif "rapidssl" in combined:
        return "RapidSSL"
    elif "thawte" in combined:
        return "Thawte"
    elif "amazon" in combined or "aws" in combined:
        return "Amazon / AWS"
    elif "google" in combined:
        return "Cloudflare SSL"
    elif "zerossl" in combined:
        return "ZeroSSL"
    elif "ssl.com" in combined:
        return "SSL.com"
    elif "12ssl" in combined or "twelve" in combined:
        return "12SSL"
    elif "entrust" in combined:
        return "Entrust"
    elif "buypass" in combined:
        return "Buypass"
    elif "identrust" in combined:
        return "IdenTrust"
    elif "microsoft" in combined:
        return "Microsoft"
    raw_org = issuer.get("organizationName", "")
    raw_cn = issuer.get("commonName", "")
    if raw_org:
        return raw_org
    elif raw_cn:
        return raw_cn
    return "Unknown"


def _issuer_from_crypto(cert_obj) -> dict:
    """Extract issuer fields from a cryptography x509 cert object."""
    issuer = {}
    try:
        from cryptography.x509.oid import NameOID
        attrs = {
            "organizationName": NameOID.ORGANIZATION_NAME,
            "commonName":       NameOID.COMMON_NAME,
        }
        for key, oid in attrs.items():
            try:
                issuer[key] = cert_obj.issuer.get_attributes_for_oid(oid)[0].value
            except (IndexError, Exception):
                pass
    except Exception:
        pass
    return issuer


def fetch_and_parse(hostname: str, result: dict, verify: bool) -> bool:
    """
    Connect to hostname:443, read TLS cert, and populate result dict.
    If verify=False, uses binary cert via cryptography library.
    Returns True on success.
    """
    if verify:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = {}
        for item in cert.get("issuer", []):
            for key, value in item:
                issuer[key] = value
        result["provider"] = detect_provider(issuer)

        fmt = "%b %d %H:%M:%S %Y %Z"
        not_before = cert.get("notBefore", "")
        not_after  = cert.get("notAfter",  "")
        if not_before:
            result["issued_on"] = datetime.datetime.strptime(not_before, fmt).strftime("%Y-%m-%d")
        if not_after:
            dt_after = datetime.datetime.strptime(not_after, fmt)
            result["expires_on"] = dt_after.strftime("%Y-%m-%d")
            now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
            days_left = (dt_after - now).days
            result["days_left"] = days_left
            result["status"] = "valid" if days_left > 0 else "expired"
        return True

    else:
        # CERT_NONE: getpeercert() returns {} — read binary DER instead
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)

        if not der:
            return False

        cert_obj = x509.load_der_x509_certificate(der, default_backend())
        issuer = _issuer_from_crypto(cert_obj)
        result["provider"] = detect_provider(issuer)

        # Support both old (<42) and new (>=42) cryptography API
        try:
            not_before = cert_obj.not_valid_before_utc.replace(tzinfo=None)
            not_after  = cert_obj.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:
            not_before = cert_obj.not_valid_before
            not_after  = cert_obj.not_valid_after
        result["issued_on"]  = not_before.strftime("%Y-%m-%d")
        result["expires_on"] = not_after.strftime("%Y-%m-%d")
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        days_left = (not_after - now).days
        result["days_left"] = days_left
        # Status set by caller based on the original verification error
        return True


def _try_fetch(hostname: str, result: dict) -> bool:
    """
    Try full verification, then unverified on cert error.
    Returns True if SSL data was populated, False otherwise.
    Raises socket/OS exceptions for the caller to handle.
    """
    try:
        fetch_and_parse(hostname, result, verify=True)
        return True
    except ssl.SSLCertVerificationError as e:
        original_error = str(e)
        err_lower = original_error.lower()
        try:
            ok = fetch_and_parse(hostname, result, verify=False)
            if ok:
                if "expired" in err_lower or (result["days_left"] is not None and result["days_left"] <= 0):
                    result["status"] = "expired"
                    result["error"] = "Certificate has expired"
                elif "hostname mismatch" in err_lower or "not valid for" in err_lower:
                    result["status"] = "invalid"
                    result["error"] = "Hostname mismatch"
                elif "self-signed" in err_lower:
                    result["status"] = "invalid"
                    result["error"] = "Self-signed certificate"
                else:
                    result["status"] = "invalid"
                    result["error"] = original_error[:120]
            else:
                result["status"] = "invalid"
                result["error"] = original_error[:120]
        except Exception:
            result["status"] = "invalid"
            result["error"] = original_error[:120]
        return True


def check_ssl(domain: str) -> dict:
    """Check SSL certificate for a single domain."""
    hostname = domain.strip().lower()

    result = {
        "domain": hostname,
        "status": "error",
        "provider": "N/A",
        "issued_on": "N/A",
        "expires_on": "N/A",
        "days_left": None,
        "error": None,
        "checked_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC"),
    }

    try:
        _try_fetch(hostname, result)
        return result

    except ssl.SSLError as e:
        # Retry once — transient TLS handshake failures are common
        try:
            _try_fetch(hostname, result)
            return result
        except Exception:
            pass
        result["status"] = "ssl_error"
        result["error"] = f"SSL error: {str(e)[:120]}"
    except (socket.timeout, TimeoutError):
        # Retry with www. prefix on timeout
        www_host = f"www.{hostname}"
        try:
            _try_fetch(www_host, result)
            result["error"] = f"Direct timeout; resolved via {www_host}"
            return result
        except Exception:
            pass
        result["status"] = "timeout"
        result["error"] = "Connection timed out"
    except socket.gaierror as e:
        # Retry with www. prefix on DNS error
        www_host = f"www.{hostname}"
        try:
            _try_fetch(www_host, result)
            result["error"] = f"DNS error on bare domain; resolved via {www_host}"
            return result
        except Exception:
            pass
        result["status"] = "dns_error"
        result["error"] = f"DNS error: {str(e)[:120]}"
    except ConnectionRefusedError:
        result["status"] = "no_https"
        result["error"] = "Port 443 refused"
    except OSError as e:
        result["status"] = "error"
        result["error"] = str(e)[:120]

    return result


def load_domains(filepath: str) -> list[str]:
    """Load and deduplicate domains from config file."""
    seen = set()
    domains = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.lower() == "website":
                continue
            # Normalize: lowercase, strip trailing dots/spaces
            domain = line.lower().strip(" .")
            # Remove http:// or https:// if present
            for prefix in ("https://", "http://"):
                if domain.startswith(prefix):
                    domain = domain[len(prefix):]
            # Remove path component
            domain = domain.split("/")[0]
            # Skip obviously invalid entries (underscore in non-subdomain position)
            if "_" in domain and not domain.startswith("_"):
                continue
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
    return domains


def main():
    print(f"Loading domains from {DOMAIN_FILE}...")
    domains = load_domains(DOMAIN_FILE)
    print(f"Found {len(domains)} unique domains. Checking SSL certificates...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_ssl, d): d for d in domains}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_domain):
            result = future.result()
            results.append(result)
            completed += 1
            status_icon = {
                "valid": "✓",
                "expired": "✗",
                "error": "!",
                "timeout": "?",
                "dns_error": "?",
                "ssl_error": "!",
                "invalid": "!",
                "no_https": "-",
            }.get(result["status"], "?")
            days = result["days_left"]
            days_str = f"{days}d" if days is not None else "N/A"
            print(
                f"[{completed:3d}/{len(domains)}] {status_icon} {result['domain']:<45} "
                f"{result['provider']:<25} expires: {result['expires_on']}  ({days_str})"
            )

    # Sort: dns_error first, timeout second, expired, then valid by days_left
    STATUS_RANK = {
        "dns_error": 0,
        "timeout":   1,
        "expired":   2,
        "ssl_error": 3,
        "no_https":  3,
        "error":     3,
        "invalid":   4,
        "valid":     5,
    }

    def sort_key(r):
        rank = STATUS_RANK.get(r["status"], 3)
        days = r["days_left"] if r["days_left"] is not None else 9999
        return (rank, days)

    results.sort(key=sort_key)

    output = {
        "generated_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "total_domains": len(domains),
        "valid": sum(1 for r in results if r["status"] == "valid"),
        "expired": sum(1 for r in results if r["status"] == "expired"),
        "errors": sum(1 for r in results if r["status"] not in ("valid", "expired")),
        "results": results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to {OUTPUT_FILE}")
    print(f"  Valid:   {output['valid']}")
    print(f"  Expired: {output['expired']}")
    print(f"  Errors:  {output['errors']}")


if __name__ == "__main__":
    main()
