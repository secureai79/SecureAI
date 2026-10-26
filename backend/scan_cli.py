#!/usr/bin/env python3
"""
Zero-setup way to see the scanner work: no DB, no API server, no network.

Usage:
    python3 scan_cli.py <path-to-repo>
    python3 scan_cli.py ../demo_repo
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import file_selector, capability_extractor, risk_engine  # noqa: E402

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def main(root: str):
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}")
        sys.exit(1)

    files = file_selector.select_files(root)
    repo_has_ai = False
    analyses = []
    for rel in files:
        try:
            with open(os.path.join(root, rel), "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        a = capability_extractor.analyze_file(rel, text)
        if a.has_ai:
            repo_has_ai = True
        if a.has_ai or a.dangerous_calls:
            analyses.append(a)

    all_findings = []
    for a in analyses:
        all_findings.extend(risk_engine.build_findings_for_file(a, repo_has_ai))

    result = risk_engine.calculate_score(all_findings)

    print("=" * 56)
    print(f"  AI SAFETY CHECKUP — {os.path.basename(root)}")
    print("=" * 56)
    print(f"\n  {result['score']} / 100   {result['label']}\n")
    c = result["counts"]
    print(f"  {c['CRITICAL']} Critical   {c['HIGH']} High   {c['MEDIUM']} Medium   {c['LOW']} Low\n")
    print("-" * 56)

    for f in sorted(all_findings, key=lambda x: -risk_engine.SEVERITY_POINTS[x["severity"]]):
        print(f"\n{SEV_ICON.get(f['severity'], '')} {f['severity']}  {f['title']}")
        print(f"   {f['file_path']}:{f['line']}  (confidence {f['confidence']:.0%})")
        for e in f["evidence"]:
            print(f"   - {e}")
        print(f"   → {f['recommendation']}")

    if not all_findings:
        print("\nNo AI-connected risky capabilities detected.")

    print("\n" + "-" * 56)
    hypothetical = risk_engine.calculate_score(
        [{**f, "status": "resolved"} for f in all_findings]
    )
    print(f"Fix everything above → potential score: {hypothetical['score']} / 100\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "../demo_repo"
    main(target)
