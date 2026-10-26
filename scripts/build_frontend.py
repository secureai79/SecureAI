#!/usr/bin/env python3
"""Build the static frontend for Cloudflare Pages (or any static host).

    python scripts/build_frontend.py --api https://api.example.com            # writes ./dist
    SECUREAI_API_URL=https://api.example.com python scripts/build_frontend.py  # same, for CI / Pages build settings

What it does
  * copies frontend/ into dist/, leaving out backups and editor leftovers
  * writes dist/config.js so every page talks to your API
  * writes dist/_headers (Cloudflare Pages format): HSTS, CSP limited to your API origin, clickjacking and
    MIME-sniffing protection, no caching of config.js
  * writes dist/robots.txt that keeps the signed-in pages out of search engines
  * fills the {{PLACEHOLDERS}} in privacy.html and terms.html from the options below (or SECUREAI_* environment variables)
Refuses an http:// API URL unless it points at localhost (production traffic must use TLS).
With --strict the build FAILS if any legal placeholder is still unfilled, so draft text cannot reach production.
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SKIP_SUFFIXES = (".bak", ".orig", ".step1-backup", ".tmp", ".map")
SKIP_PARTS = ("backup",)


def api_origin(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise SystemExit(f"--api must be an absolute URL such as https://api.example.com (got {url!r})")
    local = p.hostname in ("localhost", "127.0.0.1", "::1") or p.hostname.endswith(".test")
    if p.scheme != "https" and not local:
        raise SystemExit("--api must use https:// (plain http is only allowed for localhost and *.test)")
    if p.path not in ("", "/") or p.query or p.fragment:
        raise SystemExit("--api must be a bare origin without a path, e.g. https://api.example.com")
    return f"{p.scheme}://{p.netloc}"


def headers_file(api: str) -> str:
    csp = "; ".join([
        "default-src 'self'",
        # The pages use inline scripts and inline event handlers; moving them to files and hashing them would let this drop 'unsafe-inline'.
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com data:",
        "img-src 'self' data: blob:",
        f"connect-src 'self' {api}",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "object-src 'none'",
    ])
    return f"""/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
  Cross-Origin-Opener-Policy: same-origin
  Content-Security-Policy: {csp}

/config.js
  Cache-Control: no-cache

/*.js
  Cache-Control: public, max-age=300

/*.html
  Cache-Control: no-cache
"""


LEGAL_FIELDS = {
    "COMPANY": ("--company", "SECUREAI_COMPANY", "legal name of the company or person operating the service"),
    "SUPPORT_EMAIL": ("--support-email", "SECUREAI_SUPPORT_EMAIL", "address people can write to about privacy and support"),
    "ADDRESS": ("--address", "SECUREAI_ADDRESS", "postal address of the operator"),
    "JURISDICTION": ("--jurisdiction", "SECUREAI_JURISDICTION", "governing law, e.g. 'India (courts of Bengaluru)'"),
    "HOSTING_REGION": ("--hosting-region", "SECUREAI_HOSTING_REGION", "where data is hosted, e.g. 'the EU (Frankfurt)'"),
    "BACKEND_HOST": ("--backend-host", "SECUREAI_BACKEND_HOST", "who hosts the API, e.g. 'Hetzner' or 'Render'"),
    "BACKUP_RETENTION": ("--backup-retention", "SECUREAI_BACKUP_RETENTION", "how long backups are kept, e.g. '30 days'"),
    "LIABILITY_CAP": ("--liability-cap", "SECUREAI_LIABILITY_CAP", "minimum liability amount, e.g. 'USD 100'"),
}


def fill_legal(out: Path, values: dict[str, str]) -> list[str]:
    """Replace {{FIELD}} placeholders in the legal pages. Returns the names that are still unfilled."""
    values = {**values, "DATE": dt.date.today().strftime("%d %B %Y").lstrip("0")}
    missing: set[str] = set()
    for name in ("privacy.html", "terms.html"):
        page = out / name
        if not page.exists():
            continue
        text = page.read_text(encoding="utf-8")

        def repl(m):
            key = m.group(1)
            val = values.get(key, "")
            if not val:
                missing.add(key)
                return m.group(0)
            return html.escape(val, quote=True)
        page.write_text(re.sub(r"\{\{([A-Z_]+)\}\}", repl, text), encoding="utf-8")
    return sorted(missing)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.environ.get("SECUREAI_API_URL", ""), help="API origin, e.g. https://api.example.com")
    ap.add_argument("--src", default=str(ROOT / "frontend"))
    ap.add_argument("--out", default=str(ROOT / "dist"))
    ap.add_argument("--strict", action="store_true", help="fail if any privacy/terms placeholder is unfilled")
    for key, (flag, env, help_) in LEGAL_FIELDS.items():
        ap.add_argument(flag, default=os.environ.get(env, ""), help=help_)
    args = ap.parse_args()
    if not args.api:
        raise SystemExit("Set --api https://api.example.com (or the SECUREAI_API_URL environment variable).")
    api = api_origin(args.api)
    src, out = Path(args.src), Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    copied = 0
    for f in sorted(src.rglob("*")):
        if f.is_dir():
            continue
        rel = f.relative_to(src)
        low = str(rel).lower()
        if low.endswith(SKIP_SUFFIXES) or any(p in low for p in SKIP_PARTS):
            continue
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out / rel)
        copied += 1
    (out / "config.js").write_text(f"window.SECUREAI_API_BASE = {json.dumps(api)};\n", encoding="utf-8")
    (out / "_headers").write_text(headers_file(api), encoding="utf-8")
    (out / "robots.txt").write_text(
        "User-agent: *\nDisallow: /dashboard.html\nDisallow: /history.html\nDisallow: /settings.html\n"
        "Disallow: /accept-invite.html\nDisallow: /reset-password.html\nDisallow: /verify-email.html\n", encoding="utf-8")
    legal_values = {key: getattr(args, flag.lstrip("-").replace("-", "_")) for key, (flag, _, _) in LEGAL_FIELDS.items()}
    missing = fill_legal(out, legal_values)
    print(f"Built {copied} files into {out}  (API = {api})")
    if missing:
        names = ", ".join(f"{LEGAL_FIELDS[k][0]}" for k in missing if k in LEGAL_FIELDS)
        print(f"\n{'ERROR' if args.strict else 'WARNING'}: privacy.html / terms.html still contain placeholders for: {', '.join(missing)}\n"
              f"  Provide: {names}  (or the SECUREAI_* environment variables).")
        if args.strict:
            raise SystemExit(1)


if __name__ == "__main__":
    sys.exit(main())
