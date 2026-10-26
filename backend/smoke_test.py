#!/usr/bin/env python3
"""Deployment smoke test for AI Safety Checkup (standard library only).

    python smoke_test.py http://localhost:8001
    python smoke_test.py https://api.yourdomain.com --production --repo https://github.com/octocat/Hello-World.git

Creates two throw-away organisations, exercises the security-relevant behaviour, scans a public
repository end to end, then deletes everything it created. Exit code 0 = all checks passed.
Use --production on a real deployment: it additionally requires docs to be off and HSTS/CSP to be set.
"""
import argparse
import json
import secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

PASS, FAIL, WARN = "PASS", "FAIL", "WARN"
results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️ "}[status]
    print(f"  {icon} {name}" + (f"  — {detail}" if detail else ""), flush=True)


def check(cond: bool, name: str, detail: str = "", warn_only: bool = False) -> bool:
    record(PASS if cond else (WARN if warn_only else FAIL), name, "" if cond else detail)
    return cond


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def call(self, method, path, body=None, token=None, headers=None, timeout=60):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json", **(headers or {})}
        if token:
            h["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, dict(r.headers), raw
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()
        except Exception as e:                                    # network failure
            return 0, {}, str(e).encode()

    def json(self, *a, **k):
        status, headers, raw = self.call(*a, **k)
        try:
            return status, headers, json.loads(raw or b"{}")
        except ValueError:
            return status, headers, {}


def lower(h: dict) -> dict:
    return {k.lower(): v for k, v in h.items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--production", action="store_true", help="enforce production-only expectations")
    ap.add_argument("--repo", default="https://github.com/octocat/Hello-World.git", help="public repo for the end-to-end scan")
    ap.add_argument("--skip-scan", action="store_true")
    ap.add_argument("--skip-ratelimit", action="store_true")
    ap.add_argument("--origin", default="https://evil.example", help="origin that must NOT be allowed by CORS")
    ap.add_argument("--verify-cmd", default="",
                    help='command that marks a test account verified, e.g. "docker compose exec -T app python -m app.manage verify-email {email}". '
                         "Needed only when the server requires e-mail verification.")
    args = ap.parse_args()
    c = Client(args.base_url)
    run = secrets.token_hex(4)
    pw = "Smoke-" + secrets.token_urlsafe(18)
    print(f"\nAI Safety Checkup smoke test → {c.base}  (run {run})\n")

    print("Availability")
    s, _, b = c.json("GET", "/health")
    if not check(s == 200, "health endpoint answers", f"status {s} — is the server reachable? {b}"):
        print("\nServer unreachable; aborting.")
        return 1
    s, _, b = c.json("GET", "/ready")
    check(s == 200 and b.get("status") == "ready", "readiness (database reachable)", f"status {s} body {b}")

    print("\nHardening")
    s, h, _ = c.call("GET", "/health")
    h = lower(h)
    check(h.get("x-content-type-options") == "nosniff", "X-Content-Type-Options: nosniff")
    check(h.get("x-frame-options", "").upper() == "DENY", "X-Frame-Options: DENY")
    check("referrer-policy" in h, "Referrer-Policy set")
    check("strict-transport-security" in h, "HSTS set (only in production)", "missing", warn_only=not args.production)
    check("content-security-policy" in h, "API Content-Security-Policy set", "missing", warn_only=not args.production)
    s, _, _ = c.call("GET", "/docs")
    check(s == 404, "interactive API docs are disabled", f"/docs returned {s}", warn_only=not args.production)
    s, _, _ = c.call("GET", "/openapi.json")
    check(s == 404, "OpenAPI schema is hidden", f"/openapi.json returned {s}", warn_only=not args.production)
    s, h, _ = c.call("OPTIONS", "/repositories", headers={"Origin": args.origin, "Access-Control-Request-Method": "GET",
                                                          "Access-Control-Request-Headers": "authorization"})
    acao = lower(h).get("access-control-allow-origin", "")
    check(acao not in {args.origin, "*"}, "CORS rejects an untrusted origin", f"allowed origin: {acao!r}",
          warn_only=not args.production)
    s, _, _ = c.call("GET", "/repositories")
    check(s in (401, 403), "protected endpoint rejects anonymous callers", f"status {s}")

    print("\nAccounts")
    s, _, b = c.json("POST", "/auth/signup", {"email": f"weak-{run}@example.com", "password": "short", "organization_name": "x"})
    check(s in (400, 422), "weak password is rejected", f"status {s}")
    tokens = {}
    for tag in ("a", "b"):
        s, _, b = c.json("POST", "/auth/signup", {"email": f"smoke-{tag}-{run}@example.com", "password": pw,
                                                    "organization_name": f"Smoke {tag.upper()} {run}"})
        if not check(s == 200 and "access_token" in b, f"signup org {tag.upper()}", f"status {s} {b}"):
            print("\nCannot continue without accounts."); return 1
        tokens[tag] = b["access_token"]
    s, _, b = c.json("POST", "/auth/login", {"email": f"smoke-a-{run}@example.com", "password": pw})
    check(s == 200 and "access_token" in b, "login works")
    s, _, _ = c.json("POST", "/auth/login", {"email": f"smoke-a-{run}@example.com", "password": "definitely-wrong-1"})
    check(s == 401, "wrong password → 401", f"status {s}")
    s, _, _ = c.json("POST", "/auth/login", {"email": f"nobody-{run}@example.com", "password": "definitely-wrong-1"})
    check(s == 401, "unknown email → same 401 (no account enumeration)", f"status {s}")

    print("\nE-mail verification and password reset")
    s, _, me = c.json("GET", "/auth/me", token=tokens["a"])
    check(s == 200 and "email_verified" in me, "/auth/me reports the verification state", f"status {s} {me}")
    skip_repo_checks = False
    if me.get("verification_required"):
        check(me.get("email_verified") is False, "new accounts start unverified")
        s, _, b = c.json("POST", "/repositories", {"repo_url": args.repo, "repo_name": "smoke"}, token=tokens["a"])
        check(s == 403 and "verify" in str(b.get("detail", "")).lower(), "unverified accounts are blocked from adding repositories", f"status {s} {b}")
        if args.verify_cmd:
            for tag in ("a", "b"):
                cmd = shlex.split(args.verify_cmd.format(email=f"smoke-{tag}-{run}@example.com"))
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                    check(out.returncode == 0, f"verified test account {tag.upper()} with the operator command", (out.stdout + out.stderr)[-200:])
                except Exception as exc:
                    check(False, f"verified test account {tag.upper()} with the operator command", str(exc))
            s, _, me = c.json("GET", "/auth/me", token=tokens["a"])
            check(me.get("email_verified") is True, "verification takes effect immediately")
        else:
            record(WARN, "repository/scan checks skipped", "server requires verified e-mail; re-run with --verify-cmd (see --help)")
            skip_repo_checks = True
    else:
        record(PASS, "e-mail verification is not required on this server (development or e-mail disabled)")
    sk, _, bk = c.json("POST", "/auth/forgot-password", {"email": f"smoke-a-{run}@example.com"})
    su, _, bu = c.json("POST", "/auth/forgot-password", {"email": f"nobody-{run}@example.com"})
    if sk == 503:
        record(WARN, "password reset unavailable", "e-mail is not configured (EMAIL_BACKEND); users cannot reset passwords yet")
    else:
        check(sk == su == 200 and bk == bu, "password reset answers identically for known and unknown addresses", f"{sk} {bk} vs {su} {bu}")

    print("\nTenant isolation")
    s, _, repo = ((200, {}, {"id": "skipped"}) if skip_repo_checks else
                  c.json("POST", "/repositories", {"repo_url": args.repo, "repo_name": "smoke"}, token=tokens["a"]))
    if skip_repo_checks:
        args.skip_scan = True
    if not skip_repo_checks:
        check(s == 200 and "id" in repo, "org A can add a repository", f"status {s} {repo}")
    repo_id = repo.get("id", "missing")
    if not skip_repo_checks:
        s, _, lst = c.json("GET", "/repositories", token=tokens["b"])
        check(s == 200 and not any(r.get("id") == repo_id for r in (lst if isinstance(lst, list) else [])), "org B cannot list org A's repository")
        s, _, _ = c.json("POST", f"/repositories/{repo_id}/scan?async=true", token=tokens["b"])
        check(s == 404, "org B cannot scan org A's repository", f"status {s}")
        s, _, _ = c.json("DELETE", f"/repositories/{repo_id}", token=tokens["b"])
        check(s == 404, "org B cannot delete org A's repository", f"status {s}")

    scan_id = None
    if not args.skip_scan:
        print("\nEnd-to-end scan (clone → sandbox → score)")
        t0 = time.time()
        s, h, scan = c.json("POST", f"/repositories/{repo_id}/scan?async=true", token=tokens["a"])
        check(s == 202 and scan.get("status") == "queued", "async scan is accepted (202, queued)", f"status {s} {scan}")
        scan_id = scan.get("id")
        final = {}
        while scan_id and time.time() - t0 < 300:
            s, _, final = c.json("GET", f"/scans/{scan_id}", token=tokens["a"])
            if final.get("status") in ("completed", "failed"):
                break
            time.sleep(2)
        ok = check(final.get("status") == "completed", "scan completes",
                   f"status {final.get('status')!r}: {final.get('error')}")
        if ok:
            record(PASS, f"scan finished in {time.time() - t0:.0f}s, score {final.get('score')}")
            s, _, fnd = c.json("GET", f"/scans/{scan_id}/findings", token=tokens["a"])
            check(s == 200 and isinstance(fnd, list), "findings endpoint works")
            s, h, raw = c.call("GET", f"/scans/{scan_id}/report.pdf", token=tokens["a"])
            check(s == 200 and raw[:4] == b"%PDF", "PDF report downloads", f"status {s}")
            s, _, _ = c.json("GET", f"/scans/{scan_id}", token=tokens["b"])
            check(s == 404, "org B cannot read org A's scan", f"status {s}")

    print("\nAudit trail")
    s, _, ev = c.json("GET", "/auth/audit", token=tokens["a"])
    actions = {e.get("action") for e in ev} if isinstance(ev, list) else set()
    expected = {"auth.signup"} if skip_repo_checks else {"auth.signup", "repo.created"}
    check(expected <= actions, "audit log records signup and repository events", f"saw {sorted(actions)}")

    if not args.skip_ratelimit:
        print("\nAbuse protection (uses a throw-away account)")
        victim = f"lock-{run}@example.com"
        c.json("POST", "/auth/signup", {"email": victim, "password": pw, "organization_name": f"Lock {run}"})
        codes = [c.json("POST", "/auth/login", {"email": victim, "password": "wrong-password-9"})[0] for _ in range(8)]
        check(429 in codes, "repeated bad logins are throttled or the account locks", f"status codes {codes}")
        s, h, _ = c.json("POST", "/auth/login", {"email": victim, "password": pw})
        check(s == 429, "locked account refuses even the correct password", f"status {s}")
        check("retry-after" in lower(h), "429 carries Retry-After", "header missing")

    print("\nCleanup")
    for tag, tok in tokens.items():
        s, _, _ = c.json("DELETE", "/auth/data", {"confirmation": "DELETE"}, token=tok)
        check(s == 200, f"test organisation {tag.upper()} deleted", f"status {s}", warn_only=True)

    fails = [r for r in results if r[0] == FAIL]
    warns = [r for r in results if r[0] == WARN]
    print(f"\n{len(results) - len(fails) - len(warns)} passed, {len(warns)} warnings, {len(fails)} failed")
    for status, name, detail in fails:
        print(f"  ❌ {name}: {detail}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())