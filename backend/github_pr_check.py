#!/usr/bin/env python3
"""
AI Safety Check for GitHub Pull Requests.

Meant to run as a GitHub Action step on `pull_request` events. Scans the
Python files changed in the PR (at both the base and head commit), compares
findings, and posts a summary comment on the PR. Exits non-zero if the PR
introduces a new HIGH/CRITICAL finding, so it can gate merges as a required
check.

Usage (in CI):
    export GITHUB_TOKEN=...            # provided automatically by Actions
    export GITHUB_REPOSITORY=owner/repo
    export PR_NUMBER=123
    python3 github_pr_check.py

Usage (local dry run against any public PR, no token needed for public repos):
    python3 github_pr_check.py --repo owner/repo --pr 123 --dry-run

Example GitHub Actions workflow (.github/workflows/ai-safety-check.yml):

    name: AI Safety Check
    on: [pull_request]
    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: actions/setup-python@v5
            with: { python-version: '3.12' }
          - run: pip install -r backend/requirements.txt
          - run: python3 backend/github_pr_check.py
            env:
              GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
              PR_NUMBER: ${{ github.event.pull_request.number }}
"""
import argparse
import base64
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(__file__))
from app.scanner import ast_detector, risk_engine  # noqa: E402

API_BASE = "https://api.github.com"
SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def gh_headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def get_pr(client: httpx.Client, repo: str, pr_number: int, token: str | None) -> dict:
    r = client.get(f"{API_BASE}/repos/{repo}/pulls/{pr_number}", headers=gh_headers(token))
    r.raise_for_status()
    return r.json()


def get_pr_files(client: httpx.Client, repo: str, pr_number: int, token: str | None) -> list[dict]:
    files = []
    page = 1
    while True:
        r = client.get(
            f"{API_BASE}/repos/{repo}/pulls/{pr_number}/files",
            headers=gh_headers(token), params={"per_page": 100, "page": page},
        )
        r.raise_for_status()
        batch = r.json()
        files.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return files


def get_file_content(client: httpx.Client, repo: str, path: str, ref: str, token: str | None) -> str | None:
    r = client.get(
        f"{API_BASE}/repos/{repo}/contents/{path}",
        headers=gh_headers(token), params={"ref": ref},
    )
    if r.status_code == 404:
        return None  # file deleted in this PR
    r.raise_for_status()
    data = r.json()
    if data.get("encoding") == "base64":
        return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    return None


def scan_files(client: httpx.Client, repo: str, paths: list[str], ref: str, token: str | None) -> list[dict]:
    findings = []
    repo_has_ai = False
    file_results = []
    for path in paths:
        if not path.endswith(".py"):
            continue
        content = get_file_content(client, repo, path, ref, token)
        if content is None:
            continue
        result = ast_detector.analyze_python_ast(path, content)
        if result.ai_providers:
            repo_has_ai = True
        file_results.append((path, result))

    for path, result in file_results:
        from app.scanner.capability_extractor import FileAnalysis
        analysis = FileAnalysis(
            file_path=path, ai_providers=result.ai_providers, dangerous_libraries=[],
            dangerous_calls=[], ast_findings=result.findings, used_ast=True, raw_text="",
        )
        findings.extend(risk_engine.build_findings_for_file(analysis, repo_has_ai))
    return findings


def diff_findings(base_findings: list[dict], head_findings: list[dict]) -> dict:
    """A finding counts as "new" for PR-check purposes if its fingerprint
    didn't exist on the base branch, OR if it did but became more severe
    (e.g. the same call site went from ai_controlled=False to True after the
    PR wires an AI decision into the argument — same fingerprint, worse
    finding, and exactly the kind of change this check exists to catch)."""
    base_by_fp = {risk_engine.compute_fingerprint(f): f for f in base_findings if f.get("scored", True)}
    head_by_fp = {risk_engine.compute_fingerprint(f): f for f in head_findings if f.get("scored", True)}

    changed = []
    for fp, head_f in head_by_fp.items():
        base_f = base_by_fp.get(fp)
        if base_f is None:
            changed.append(head_f)
        else:
            base_rank = risk_engine.SEVERITY_ORDER.index(base_f["severity"])
            head_rank = risk_engine.SEVERITY_ORDER.index(head_f["severity"])
            if head_rank > base_rank:
                changed.append(head_f)

    changed.sort(key=lambda f: -risk_engine.SEVERITY_POINTS[f["severity"]])
    return {"new_findings": changed}


def build_comment(base_score: dict, head_score: dict, new_findings: list[dict]) -> str:
    delta = head_score["score"] - base_score["score"]
    arrow = "📉" if delta < 0 else ("📈" if delta > 0 else "➡️")
    lines = [
        "## 🛡️ AI Safety Check",
        "",
        f"**Score:** {base_score['score']} → {head_score['score']} / 100 {arrow}",
        "",
    ]
    if new_findings:
        lines.append(f"### {len(new_findings)} new finding(s) introduced by this PR")
        lines.append("")
        for f in new_findings:
            lines.append(f"{SEV_ICON.get(f['severity'], '')} **{f['severity']}** — {f['title']}")
            lines.append(f"`{f['file_path']}:{f['line']}` · {f['recommendation']}")
            lines.append("")
        blocking = any(f["severity"] in ("CRITICAL", "HIGH") for f in new_findings)
        if blocking:
            lines.append("❌ **This PR introduces a new HIGH or CRITICAL risk finding.**")
        else:
            lines.append("⚠️ New findings introduced, but none are HIGH/CRITICAL.")
    else:
        lines.append("✅ No new AI safety findings introduced by this PR.")
    return "\n".join(lines)


def post_comment(client: httpx.Client, repo: str, pr_number: int, body: str, token: str) -> None:
    r = client.post(
        f"{API_BASE}/repos/{repo}/issues/{pr_number}/comments",
        headers=gh_headers(token), json={"body": body},
    )
    r.raise_for_status()


def _make_client() -> httpx.Client:
    """Factory so tests can monkeypatch this to a mocked transport."""
    return httpx.Client(timeout=30.0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--pr", type=int, default=int(os.environ.get("PR_NUMBER", 0) or 0))
    parser.add_argument("--dry-run", action="store_true", help="Print the comment instead of posting it")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not args.repo or not args.pr:
        print("Usage: github_pr_check.py --repo owner/repo --pr 123 [--dry-run]")
        sys.exit(2)

    with _make_client() as client:
        pr = get_pr(client, args.repo, args.pr, token)
        base_ref, head_ref = pr["base"]["sha"], pr["head"]["sha"]

        files = get_pr_files(client, args.repo, args.pr, token)
        paths = [f["filename"] for f in files if f["status"] != "removed"]

        print(f"Scanning {len(paths)} changed Python-relevant file(s) against base {base_ref[:7]} and head {head_ref[:7]}...")

        base_findings = scan_files(client, args.repo, paths, base_ref, token)
        head_findings = scan_files(client, args.repo, paths, head_ref, token)

        base_score = risk_engine.calculate_score(base_findings)
        head_score = risk_engine.calculate_score(head_findings)
        diff = diff_findings(base_findings, head_findings)

        comment = build_comment(base_score, head_score, diff["new_findings"])
        print("\n" + comment + "\n")

        if args.dry_run:
            print("[dry-run] Comment not posted.")
        else:
            if not token:
                print("GITHUB_TOKEN not set — cannot post comment. Use --dry-run to preview only.")
                sys.exit(2)
            post_comment(client, args.repo, args.pr, comment, token)
            print("Comment posted.")

        blocking = any(f["severity"] in ("CRITICAL", "HIGH") for f in diff["new_findings"])
        sys.exit(1 if blocking else 0)


if __name__ == "__main__":
    main()
