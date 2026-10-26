"""Command line: ``python -m aisafety scan [PATH] [options]``.

Exit codes: 0 = policy passed, 1 = policy failed, 2 = usage/policy error, 3 = scan error.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, github, policy as policy_mod, reports, scan as scan_mod


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text if text.endswith("\n") else text + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aisafety", description="AI Safety Checkup: offline scanner with policy-as-code.")
    p.add_argument("--version", action="version", version=f"aisafety {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a checkout and apply the policy")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--policy", help="policy file (default: .aisafety.yml in PATH, else built-in defaults)")
    s.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], help="override policy fail_on")
    s.add_argument("--min-score", type=int, help="override policy min_score")
    s.add_argument("--base-ref", help="git ref to compare against (PR mode): only new findings can block")
    s.add_argument("--baseline", help="baseline JSON from --write-baseline (alternative to --base-ref)")
    s.add_argument("--write-baseline", metavar="FILE", help="save current findings as a baseline and exit 0")
    s.add_argument("--format", choices=sorted(reports.RENDERERS), default="text", help="stdout format")
    s.add_argument("--json", metavar="FILE", dest="json_out")
    s.add_argument("--sarif", metavar="FILE", dest="sarif_out")
    s.add_argument("--markdown", metavar="FILE", dest="markdown_out")
    s.add_argument("--github-annotations", action="store_true", help="print ::error/::warning workflow commands")
    s.add_argument("--comment", action="store_true", help="post/update a PR comment (needs GITHUB_TOKEN)")
    s.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    s.add_argument("--pr", type=int, default=None)

    v = sub.add_parser("policy-check", help="validate a policy file")
    v.add_argument("file")
    return p


def cmd_policy_check(args) -> int:
    try:
        pol = policy_mod.load_policy(args.file)
    except policy_mod.PolicyError as exc:
        print(f"policy invalid: {exc}", file=sys.stderr)
        return 2
    print(f"policy OK: fail_on={pol.fail_on}, min_score={pol.min_score}, {len(pol.rules)} rule(s), "
          f"{len(pol.suppressions)} suppression(s)")
    return 0


def cmd_scan(args) -> int:
    root = os.path.abspath(args.path)
    try:
        policy_path = args.policy or (policy_mod.find_policy_file(root) if os.path.isdir(root) else None)
        pol = policy_mod.load_policy(policy_path)
        if args.fail_on:
            pol.fail_on = None if args.fail_on == "none" else args.fail_on.upper()
        if args.min_score is not None:
            pol.min_score = args.min_score
    except policy_mod.PolicyError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2

    try:
        head = scan_mod.scan_directory(root)
        if args.write_baseline:
            scan_mod.write_baseline(args.write_baseline, head)
            print(f"baseline written: {args.write_baseline} ({len(head.fingerprints)} finding(s), score {head.score['score']})")
            return 0
        base = None
        base_fps = None
        if args.base_ref and args.baseline:
            print("use either --base-ref or --baseline, not both", file=sys.stderr)
            return 2
        if args.base_ref:
            b = scan_mod.scan_git_ref(root, args.base_ref)
            base, base_fps = {"score": b.score["score"]}, b.fingerprints
        elif args.baseline:
            data = scan_mod.read_baseline(args.baseline)
            base, base_fps = {"score": data["score"]}, data["fingerprints"]
    except scan_mod.ScanError as exc:
        print(f"scan error: {exc}", file=sys.stderr)
        return 3

    existing = scan_mod.existing_fingerprints(head, base_fps) if base_fps is not None else None
    decision = policy_mod.evaluate(pol, head.findings, score=head.score["score"], base_fingerprints=existing)

    renderer = reports.RENDERERS[args.format]
    print(renderer(head, decision, pol, base))
    if args.json_out:
        _write(args.json_out, reports.render_json(head, decision, pol, base))
    if args.sarif_out:
        _write(args.sarif_out, reports.render_sarif(head, decision, pol, base))
    markdown = None
    if args.markdown_out or args.comment or os.environ.get("GITHUB_STEP_SUMMARY"):
        markdown = reports.render_markdown(head, decision, pol, base)
    if args.markdown_out:
        _write(args.markdown_out, markdown)
    if args.github_annotations:
        github.emit_annotations(decision)
    if markdown:
        github.write_step_summary(markdown)
    if args.comment:
        token = os.environ.get("GITHUB_TOKEN")
        pr = args.pr or github.pr_number_from_event()
        if not (token and args.repo and pr):
            print("comment skipped: needs GITHUB_TOKEN, GITHUB_REPOSITORY and a pull request number", file=sys.stderr)
        else:
            print("PR comment:", github.post_or_update_comment(args.repo, pr, markdown, token), file=sys.stderr)
    return 0 if decision.passed else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "policy-check": cmd_policy_check}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())