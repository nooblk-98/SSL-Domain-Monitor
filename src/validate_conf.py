#!/usr/bin/env python3
"""
validate_conf.py — Pre-run validator + auto-fixer for domains.conf and ssl.conf

Checks for:
  1. Malformed entries   (invalid characters, missing TLD, underscore, etc.)
  2. Duplicates          (case-insensitive, www-normalised)
  3. DNS reachability    (parallel A/AAAA lookups, optional — skipped with --no-dns)

Auto-fix (always on):
  - Removes malformed entries
  - Removes duplicate entries (keeps first occurrence)
  - Strips www. prefix and lowercases all entries
  - Rewrites the file in-place with clean entries

Exit codes:
  0  — files clean (or fixed successfully)
  1  — file not found or unrecoverable error

Usage:
  python3 src/validate_conf.py              # fix both files + DNS check
  python3 src/validate_conf.py --no-dns    # fix both files, skip DNS
  python3 src/validate_conf.py ssl.conf    # fix one file only
"""

import argparse
import concurrent.futures
import re
import socket
import sys
from pathlib import Path

# ── Colours ────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[31m"
YELLOW = "\033[33m"
GREEN  = "\033[32m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def c(colour, text): return f"{colour}{text}{RESET}"

# ── Domain regex ───────────────────────────────────────────────────────────────
LABEL_RE = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')

DNS_TIMEOUT = 5
DNS_WORKERS = 30


# ── Normalise ──────────────────────────────────────────────────────────────────

def normalise(raw: str) -> str:
    domain = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].strip(" .")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


# ── Validation ─────────────────────────────────────────────────────────────────

def is_valid(domain: str) -> tuple[bool, str]:
    """Return (valid, reason). domain should already be normalised."""
    if not domain:
        return False, "empty after normalisation"
    if "_" in domain:
        return False, f"contains underscore (malformed: '{domain}')"
    labels = domain.split(".")
    if len(labels) < 2:
        return False, f"missing TLD ('{domain}')"
    for label in labels:
        if not label:
            return False, f"empty label / double dot ('{domain}')"
        if not LABEL_RE.match(label):
            return False, f"invalid label '{label}' in '{domain}'"
    if len(labels[-1]) < 2:
        return False, f"TLD too short in '{domain}'"
    return True, ""


# ── DNS check ─────────────────────────────────────────────────────────────────

def dns_check(domain: str) -> tuple[str, bool, str]:
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        socket.getaddrinfo(domain, None)
        return domain, True, ""
    except socket.gaierror as e:
        return domain, False, str(e)
    except Exception as e:
        return domain, False, str(e)


# ── Process one file ───────────────────────────────────────────────────────────

def process_file(path: Path, check_dns: bool) -> bool:
    """
    Validate, auto-fix, and rewrite path in-place.
    Returns True if file is clean after fixing.
    """
    print(f"\n{c(CYAN, f'Processing {path}…')}")

    if not path.exists():
        print(f"  {c(RED, 'ERROR:')} File not found: {path}")
        return False

    raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()

    removed_malformed: list[tuple[int, str, str]] = []  # (lineno, raw, reason)
    removed_duplicates: list[tuple[int, str]] = []      # (lineno, norm)
    kept: list[str] = []                                 # normalised, clean, unique
    seen: dict[str, int] = {}                            # norm → original lineno

    for lineno, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        raw = stripped.split()[0]
        norm = normalise(raw)

        valid, reason = is_valid(norm)
        if not valid:
            removed_malformed.append((lineno, raw, reason))
            continue

        if norm in seen:
            removed_duplicates.append((lineno, norm))
        else:
            seen[norm] = lineno
            kept.append(norm)

    # DNS check on kept domains
    dns_unreachable: list[tuple[str, str]] = []
    if check_dns and kept:
        print(f"  {c(DIM, f'Checking DNS for {len(kept)} domains…')}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
            futures = {pool.submit(dns_check, d): d for d in kept}
            for fut in concurrent.futures.as_completed(futures):
                domain, ok, err = fut.result()
                if not ok:
                    dns_unreachable.append((domain, err))
        dns_unreachable.sort()

    # ── Print summary ──────────────────────────────────────────────────────────
    total_removed = len(removed_malformed) + len(removed_duplicates)

    if removed_malformed:
        print(f"\n  {c(RED + BOLD, f'Removed malformed ({len(removed_malformed)}):')}")
        for lineno, raw, reason in removed_malformed:
            print(f"    Line {lineno:4d}: {c(RED, raw):<40}  {reason}")

    if removed_duplicates:
        print(f"\n  {c(YELLOW + BOLD, f'Removed duplicates ({len(removed_duplicates)}):')}")
        for lineno, norm in removed_duplicates:
            print(f"    Line {lineno:4d}: {c(YELLOW, norm)}")

    if dns_unreachable:
        print(f"\n  {c(YELLOW + BOLD, f'DNS unreachable ({len(dns_unreachable)}) — kept in file:')}")
        for domain, err in dns_unreachable:
            print(f"    {c(YELLOW, domain):<45}  {err}")

    # ── Rewrite file ───────────────────────────────────────────────────────────
    if total_removed > 0:
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
        print(f"\n  {c(GREEN, '✓')} Rewrote {path.name}: "
              f"{len(raw_lines)} lines → {len(kept)} clean entries "
              f"({total_removed} removed)")
    else:
        print(f"\n  {c(GREEN, '✓')} {path.name} is already clean "
              f"({len(kept)} entries, nothing removed)")

    return True


# ── Entry point ────────────────────────────────────────────────────────────────

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FILES = [str(ROOT_DIR / "ssl.conf"), str(ROOT_DIR / "domains.conf")]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and auto-fix domains.conf / ssl.conf."
    )
    parser.add_argument(
        "files",
        nargs="*",
        default=DEFAULT_FILES,
        help="Config files to process (default: ssl.conf domains.conf)",
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS reachability checks (faster)",
    )
    args = parser.parse_args()

    paths = [Path(f) for f in args.files]
    check_dns = not args.no_dns

    print(c(BOLD, "\n=== webLankan conf validator + auto-fixer ==="))
    print(f"  {c(DIM, 'DNS checks ' + ('disabled' if not check_dns else 'enabled (--no-dns to skip)'))}")

    ok = all(process_file(p, check_dns) for p in paths)

    print(f"\n{'─' * 55}")
    if ok:
        print(c(GREEN + BOLD, "  Done. Config files are clean.\n"))
        return 0
    else:
        print(c(RED + BOLD, "  One or more files could not be processed.\n"))
        return 1


if __name__ == "__main__":
    sys.exit(main())
