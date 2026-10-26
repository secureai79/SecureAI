#!/usr/bin/env python3
"""Create / check .env for SecureAI.

  python scripts/init_env.py                     create .env from .env.example if missing, fill blank secrets, then check
  python scripts/init_env.py --check             only check (changes nothing)
  python scripts/init_env.py --production        same for .env.production (Cloudflare Pages + API + Neon), from .env.production.example
  python scripts/init_env.py --file X --example Y   any other pair

Existing values are never overwritten. Secrets are printed nowhere.
"""
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent.parent
ENV, EXAMPLE = ROOT / ".env", ROOT / ".env.example"
LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")


def parse(text):
    values, seen = {}, {}
    for n, line in enumerate(text.splitlines(), 1):
        m = LINE.match(line)
        if m and not line.lstrip().startswith("#"):
            k, v = m.group(1), m.group(2).strip().strip("'\"")
            seen.setdefault(k, []).append(n)
            values[k] = v
    return values, seen


def fernet():
    try:
        from cryptography.fernet import Fernet
        return Fernet.generate_key().decode()
    except ImportError:
        sys.exit("Install cryptography first:  pip install cryptography")


def generate(key):
    return {
        "JWT_SECRET": lambda: secrets.token_urlsafe(48),
        "POSTGRES_PASSWORD": lambda: secrets.token_hex(24),
        "GITHUB_TOKEN_ENCRYPTION_KEY": fernet,
        "SOURCE_EVIDENCE_ENCRYPTION_KEY": fernet,
        "MFA_ENCRYPTION_KEY": fernet,
    }.get(key)


def fill(text):
    out, filled = [], []
    for line in text.splitlines():
        m = LINE.match(line)
        if m and not line.lstrip().startswith("#") and not m.group(2).strip() and generate(m.group(1)):
            out.append(f"{m.group(1)}={generate(m.group(1))()}")
            filled.append(m.group(1))
        else:
            out.append(line)
    return "\n".join(out) + "\n", filled


def check(text):
    v, seen = parse(text)
    problems, warns = [], []
    for k, lines in seen.items():
        if len(lines) > 1:
            warns.append(f"{k} appears {len(lines)} times (lines {', '.join(map(str, lines))}); the LAST one wins - delete the others")
    prod = v.get("ENVIRONMENT", "development").lower() == "production"
    if len(v.get("JWT_SECRET", "")) < 32:
        problems.append("JWT_SECRET is missing or shorter than 32 characters")
    uses_compose_db = "POSTGRES_PASSWORD" in v or "POSTGRES_USER" in v
    if uses_compose_db and not v.get("POSTGRES_PASSWORD"):
        problems.append("POSTGRES_PASSWORD is empty")
    if not uses_compose_db:
        dburl = v.get("DATABASE_URL", "")
        if not dburl:
            problems.append("DATABASE_URL is empty (paste the connection string from Neon > Connection details)")
        elif not re.match(r"postgres(ql)?(\+psycopg)?://", dburl):
            problems.append("DATABASE_URL must be a PostgreSQL URL (postgresql://user:password@host/dbname?sslmode=require)")
        elif re.search(r"@(localhost|127\.0\.0\.1)[:/]", dburl) and prod:
            problems.append("DATABASE_URL points at localhost; production should use the Neon host")
        elif ".neon.tech" in dburl and "sslmode=" not in dburl:
            warns.append("DATABASE_URL has no sslmode; the app adds sslmode=require for Neon, but keep Neon's own string unchanged")
        elif "pooler" in dburl:
            warns.append("DATABASE_URL uses Neon's pooled host: fine for running, but use the direct host for the very first start (creates tables)")
    try:
        from cryptography.fernet import Fernet
        for k in ("GITHUB_TOKEN_ENCRYPTION_KEY", "SOURCE_EVIDENCE_ENCRYPTION_KEY", "MFA_ENCRYPTION_KEY"):
            if v.get(k):
                try:
                    for part in v[k].split(","):
                        Fernet(part.strip().encode())
                except Exception:
                    problems.append(f"{k} is not a valid Fernet key")
            elif k == "GITHUB_TOKEN_ENCRYPTION_KEY" and (v.get("GITHUB_APP_ID") or v.get("GITHUB_APP_SLUG")):
                problems.append("GITHUB_TOKEN_ENCRYPTION_KEY is required when a GitHub App is configured")
    except ImportError:
        warns.append("cryptography not installed here; Fernet keys were not validated")
    pw = v.get("POSTGRES_PASSWORD", "")
    if uses_compose_db and pw and not re.fullmatch(r"[A-Za-z0-9_\-]+", pw):
        warns.append("POSTGRES_PASSWORD has special characters (/ = + @ ...) that break DATABASE_URL; use hex (python -c \"import secrets;print(secrets.token_hex(24))\")")
    if uses_compose_db and v.get("DATABASE_URL"):
        try:
            if unquote(urlparse(v["DATABASE_URL"]).password or "") != pw:
                problems.append("DATABASE_URL's password does not match POSTGRES_PASSWORD (remove DATABASE_URL; compose derives it)")
        except ValueError:
            problems.append("DATABASE_URL is not a valid URL")
    if prod and v.get("ALLOW_LOCAL_REPOS", "false").lower() in {"1", "true", "yes", "on"}:
        warns.append("ALLOW_LOCAL_REPOS=true is ignored in the container (forced false in production)")
    if v.get("TRUSTED_PROXY_COUNT", "0").strip() not in {"", "0"}:
        warns.append("TRUSTED_PROXY_COUNT is above 0: only keep it if a real reverse proxy sits in front of the API; "
                     "otherwise anyone can spoof X-Forwarded-For and bypass the per-IP rate limits (set it to 0)")
    recommended = {"MAX_SCAN_FILES": 20000, "MAX_SCAN_BYTES": 209715200, "GIT_CLONE_TIMEOUT_SECONDS": 600,
                   "SCAN_WORKER_TIMEOUT_SECONDS": 780, "SCAN_WORKER_CPU_SECONDS": 700, "SCAN_WORKER_MEMORY_MB": 1536}
    low = [f"{k}={v[k]} (now {want})" for k, want in recommended.items()
           if v.get(k, "").isdigit() and int(v[k]) < want]
    if low:
        warns.append("old, small scan limits in .env override the new large-repository defaults: " + ", ".join(low))
    fe = v.get("FRONTEND_URL", "")
    if prod and fe.startswith("http://") and not re.match(r"http://(127\.0\.0\.1|localhost)(:|/|$)", fe):
        problems.append("FRONTEND_URL must be https:// unless it is localhost")
    origin = re.match(r"(https?://[^/]+)", fe)
    if origin and origin.group(1) not in [o.strip() for o in v.get("CORS_ALLOWED_ORIGINS", "").split(",")]:
        warns.append(f"CORS_ALLOWED_ORIGINS does not include {origin.group(1)} (browser calls from your pages will be blocked)")
    if not v.get("CORS_ALLOWED_ORIGINS"):
        problems.append("CORS_ALLOWED_ORIGINS is empty")
    if v.get("EMAIL_BACKEND", "").lower() == "smtp":
        for k in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD", "EMAIL_FROM"):
            if not v.get(k):
                problems.append(f"{k} is empty (EMAIL_BACKEND=smtp)")
        host, user, sender = v.get("SMTP_HOST", ""), v.get("SMTP_USERNAME", ""), v.get("EMAIL_FROM", "")
        if "brevo" in host and user and "@" not in user:
            warns.append("SMTP_USERNAME looks cut off; Brevo logins look like  xxxxxx@smtp-brevo.com  (Brevo > SMTP & API)")
        if re.search(r"@(gmail|yahoo|outlook|hotmail)\.", sender, re.I) and "gmail" not in host:
            warns.append("EMAIL_FROM is a free-mail address sent through another provider; it will likely be rejected or spam-foldered. Verify a sender/domain with your provider")
    elif v.get("REQUIRE_EMAIL_VERIFICATION", "true" if prod else "false").lower() in {"1", "true", "yes", "on"} and prod:
        problems.append("REQUIRE_EMAIL_VERIFICATION is on but EMAIL_BACKEND is not smtp")
    key = v.get("GITHUB_APP_PRIVATE_KEY_PATH", "")
    if v.get("GITHUB_APP_ID") and key:
        p = Path(key) if Path(key).is_absolute() else ROOT / key
        if not p.is_file():
            problems.append(f"GITHUB_APP_PRIVATE_KEY_PATH does not exist on this machine: {key}")
    return problems, warns


def main():
    global ENV, EXAMPLE
    args = sys.argv[1:]
    if "--production" in args:
        ENV, EXAMPLE = ROOT / ".env.production", ROOT / ".env.production.example"
    if "--file" in args:
        ENV = Path(args[args.index("--file") + 1]).resolve()
    if "--example" in args:
        EXAMPLE = Path(args[args.index("--example") + 1]).resolve()
    only_check = "--check" in sys.argv
    if not only_check:
        if not ENV.exists() or not ENV.read_text(encoding="utf-8").strip():
            ENV.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
            print("Created .env from .env.example")
        text, filled = fill(ENV.read_text(encoding="utf-8"))
        if filled:
            ENV.write_text(text, encoding="utf-8")
            print("Generated:", ", ".join(filled))
    elif not ENV.exists():
        sys.exit(".env not found")
    problems, warns = check(ENV.read_text(encoding="utf-8"))
    for w in warns:
        print("  warning:", w)
    for p in problems:
        print("  PROBLEM:", p)
    if problems:
        sys.exit(f"\n{len(problems)} problem(s) to fix in .env")
    print("\n.env looks good.  Next:  docker compose up --build -d")


if __name__ == "__main__":
    main()
