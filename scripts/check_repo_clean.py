#!/usr/bin/env python3
"""Pre-push safety net: refuse to continue if the repository contains secrets, database dumps, backups or other
files that must never reach GitHub. Run it before the first push and in CI.

    python scripts/check_repo_clean.py            # checks what git would commit (tracked + new, minus .gitignore)
    python scripts/check_repo_clean.py --all      # checks every file on disk, ignored or not (use before zipping/sharing)

Exit code 0 = clean, 1 = findings. It never prints a secret, only the file, line and kind of finding.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORBIDDEN_NAME = [
    (re.compile(r"(^|/)\.env($|\.)(?!.*example)"), "environment file"),
    (re.compile(r"\.(pem|key|p12|pfx|crt)$", re.I), "key or certificate"),
    (re.compile(r"\.(sql|dump|sqlite3?|db)(\.gz)?$", re.I), "database file or dump"),
    (re.compile(r"(^|/)(backups?|_local_backups)/", re.I), "backup folder"),
    (re.compile(r"(\.bak|\.orig|\.step1-backup)$|backup", re.I), "backup copy"),
    (re.compile(r"(^|/)secrets/(?!README)"), "secrets folder"),
    (re.compile(r"(^|/)(\.venv|venv|node_modules|__pycache__)/"), "dependency or cache folder"),
    (re.compile(r"\.(zip|tar\.gz|tgz|7z|rar)$", re.I), "archive"),
]
ALLOWED_NAME = re.compile(r"\.env(\.production)?\.example$|(^|/)secrets/README")

CONTENT = [
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|github_pat_[A-Za-z0-9_]{30,}"), "GitHub token"),
    (re.compile(r"\bxkeysib-[A-Za-z0-9-]{20,}"), "Brevo API key"),
    (re.compile(r"\bre_[A-Za-z0-9]{20,}\b"), "Resend API key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{30,}\b"), "AI provider API key"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}"), "Slack token"),
    (re.compile(r"^[ \t]*(JWT_SECRET|SMTP_PASSWORD|POSTGRES_PASSWORD)[ \t]*=[ \t]*['\"]?(?!replace|changeme|your|example|<|\$|['\"]?[ \t]*$)[^\s]{8,}", re.M), "secret assigned in a file"),
    (re.compile(r"^[ \t]*\w*ENCRYPTION_KEY[ \t]*=[ \t]*['\"]?[A-Za-z0-9_-]{43}=", re.M), "encryption key"),
    (re.compile(r"postgres(ql)?(\+\w+)?://[^:/@\s]+:(?!password|pass|pw|your|changeme|<|\$|\{|%s|x{3,}|\*{3,})[^@\s]{6,}@(?!db[:/]|localhost|127\.0\.0\.1|example)[A-Za-z0-9.-]+"), "database URL with a password"),
]
# Deliberately vulnerable sample code and test fixtures may contain fake keys.
CONTENT_EXEMPT = re.compile(r"(^|/)(demo_repo|examples|docs|backend/test_[^/]*|backend/app/scanner/.*)/?")
TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".json", ".yml", ".yaml", ".md", ".txt", ".html", ".css", ".toml", ".cfg", ".ini",
                 ".sh", ".ps1", ".env", ".example", ".conf", ".csv", ""}
MAX_BYTES = 5 * 1024 * 1024


def files(everything: bool) -> list[str]:
    if not everything:
        try:
            out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
            return [l for l in out.splitlines() if l and (ROOT / l).is_file()]
        except (OSError, subprocess.CalledProcessError):
            pass
    skip = {".git"}
    return [str(p.relative_to(ROOT)).replace("\\", "/") for p in ROOT.rglob("*")
            if p.is_file() and not (set(p.relative_to(ROOT).parts) & skip)]


def scan(paths: list[str]) -> list[tuple[str, int, str]]:
    findings = []
    for rel in paths:
        norm = rel.replace("\\", "/")
        if not ALLOWED_NAME.search(norm):
            for rx, label in FORBIDDEN_NAME:
                if rx.search(norm):
                    findings.append((norm, 0, label))
                    break
        full = ROOT / rel
        try:
            size = full.stat().st_size
        except OSError:
            continue
        if size > MAX_BYTES:
            findings.append((norm, 0, f"file larger than {MAX_BYTES // (1024 * 1024)} MB"))
            continue
        if full.suffix.lower() not in TEXT_SUFFIXES or CONTENT_EXEMPT.search(norm):
            continue
        try:
            text = full.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rx, label in CONTENT:
            for m in rx.finditer(text):
                findings.append((norm, text.count("\n", 0, m.start()) + 1, label))
                break
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--all", action="store_true", help="check every file on disk, not only what git would commit")
    ap.add_argument("--root", help="project root (default: the folder above scripts/)")
    args = ap.parse_args()
    global ROOT
    if args.root:
        ROOT = Path(args.root).resolve()
    paths = files(args.all)
    findings = scan(paths)
    if not findings:
        print(f"Clean: {len(paths)} files checked, no secrets, dumps or backups found.")
        return 0
    print(f"{len(findings)} problem(s) in {len(paths)} files:\n")
    for path, line, label in sorted(findings):
        print(f"  {path}{':' + str(line) if line else ''}  ->  {label}")
    print("\nFix: remove the file, or add it to .gitignore. If it was ever committed, ROTATE the secret as well; deleting a file does not delete history.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
