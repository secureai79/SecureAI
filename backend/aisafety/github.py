"""GitHub Actions integration using only the standard library."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from .reports import MARKER

MAX_ANNOTATIONS = 40


def _esc_data(s: str) -> str:
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def annotation(level: str, file: str, line: int, title: str, message: str) -> str:
    """A workflow command. Content comes from scanned code, so it is escaped exactly as GitHub
    specifies - otherwise a crafted file name or function name could inject extra commands."""
    assert level in {"error", "warning", "notice"}
    return (f"::{level} file={_esc_prop(file)},line={int(line) or 1},title={_esc_prop(title[:120])}"
            f"::{_esc_data(message[:500])}")


def emit_annotations(decision, out=print) -> int:
    n = 0
    for e in decision.evaluated:
        if e.status not in {"blocking", "warning"} or n >= MAX_ANNOTATIONS:
            continue
        f = e.finding
        level = "error" if e.status == "blocking" else "warning"
        out(annotation(level, f["file_path"], f.get("line", 1), f"{f['severity']}: {f['title']}", f["recommendation"]))
        n += 1
    return n


def write_step_summary(markdown: str) -> bool:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown + "\n")
    return True


def pr_number_from_event() -> int | None:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        n = (data.get("pull_request") or {}).get("number") or data.get("number")
        return int(n) if n else None
    except (ValueError, OSError, TypeError):
        return None


def _request(method: str, url: str, token: str, body: dict | None = None):
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ValueError("unsupported URL scheme")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "ai-safety-checkup"})
    with urllib.request.urlopen(req, timeout=20) as resp:      # noqa: S310 - scheme validated above
        raw = resp.read()
        return json.loads(raw) if raw else None


def post_or_update_comment(repo: str, pr: int, body: str, token: str, api_base: str | None = None) -> str:
    """Create the PR comment, or update our previous one ("sticky" comment).

    Returns 'created', 'updated' or 'skipped: <reason>'. Never raises for permission problems:
    PRs from forks get a read-only token and must not fail the check because of that.
    """
    api = (api_base or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    base = f"{api}/repos/{repo}/issues/{pr}/comments"
    try:
        existing = None
        page = 1
        while existing is None and page <= 10:
            batch = _request("GET", f"{base}?per_page=100&page={page}", token) or []
            existing = next((c for c in batch if MARKER in (c.get("body") or "")), None)
            if len(batch) < 100:
                break
            page += 1
        if existing:
            _request("PATCH", f"{api}/repos/{repo}/issues/comments/{existing['id']}", token, {"body": body})
            return "updated"
        _request("POST", base, token, {"body": body})
        return "created"
    except urllib.error.HTTPError as exc:
        return f"skipped: GitHub returned {exc.code} (fork PRs and read-only tokens cannot comment)"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"skipped: {type(exc).__name__}"