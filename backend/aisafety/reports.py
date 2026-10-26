"""Report writers: text, markdown (PR comment), JSON and SARIF 2.1.0.

Everything rendered here is derived from the code under review - in a pull request that may be a
stranger's fork - so output is treated as untrusted: markdown is neutralised (no HTML, links,
@mentions or code-fence breakouts) and workflow commands are escaped per GitHub's rules.
"""
from __future__ import annotations

import json
import re

from . import __version__

MARKER = "<!-- ai-safety-check -->"
ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
MAX_COMMENT_ITEMS = 25


def md_escape(value, limit: int = 300) -> str:
    s = str(value if value is not None else "")
    s = s.replace("\r", " ").replace("\n", " ")[:limit]
    s = re.sub(r"[<>&`|\[\]()*_~#!\\]", lambda m: "\\" + m.group(0) if m.group(0) not in "<>&" else
               {"<": "&lt;", ">": "&gt;", "&": "&amp;"}[m.group(0)], s)
    s = s.replace("@", "@\u200b")                  # never ping people from scanned content
    return s.replace("://", ":\u200b//").replace("www.", "www\u200b.")   # no auto-linked URLs


def _loc(f: dict) -> str:
    return f"{md_escape(f['file_path'], 200)}:{int(f.get('line') or 0)}"


def _counts(decision) -> dict:
    c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in decision.evaluated:
        if e.status in {"blocking", "warning", "existing"}:
            c[e.finding["severity"]] += 1
    return c


# --------------------------------------------------------------------- text
def render_text(result, decision, policy, base=None) -> str:
    c = result.score["counts"]
    lines = ["=" * 60, "  AI SAFETY CHECKUP", "=" * 60,
             f"  Score {result.score['score']}/100 ({result.score['label']})"
             + (f"   base: {base['score']}" if base and base.get("score") is not None else ""),
             f"  {c['CRITICAL']} critical · {c['HIGH']} high · {c['MEDIUM']} medium · {c['LOW']} low",
             f"  Policy: {policy.source}", "-" * 60]
    for status, title in (("blocking", "BLOCKING"), ("warning", "WARNINGS"), ("existing", "EXISTING (not blocking)"),
                          ("suppressed", "SUPPRESSED"), ("ignored", "IGNORED")):
        items = decision.by_status(status)
        if not items:
            continue
        lines.append(f"\n{title} ({len(items)})")
        for e in items:
            f = e.finding
            lines.append(f"  {ICON[f['severity']]} {f['severity']:<8} {f['title']}")
            lines.append(f"      {f['file_path']}:{f.get('line', 0)}   fingerprint {f['fingerprint'][:16]}")
            if status in {"blocking", "warning"}:
                if e.reason:
                    lines.append(f"      why: {e.reason}")
                if f.get("capability_chain"):
                    lines.append("      path: " + "  →  ".join(f["capability_chain"]))
                lines.append(f"      fix: {f['recommendation']}")
    for note in decision.notes:
        lines.append(f"\nnote: {note}")
    lines.append("\n" + "-" * 60)
    lines.append("RESULT: " + ("PASSED ✅" if decision.passed else "FAILED ❌ — " + "; ".join(decision.reasons)))
    return "\n".join(lines)


# ----------------------------------------------------------------- markdown
def render_markdown(result, decision, policy, base=None) -> str:
    c = result.score["counts"]
    head = [MARKER, "## 🛡️ AI Safety Check", ""]
    delta = ""
    if base and base.get("score") is not None:
        d = result.score["score"] - base["score"]
        delta = f" ({'📉' if d < 0 else '📈' if d > 0 else '➡️'} base {base['score']})"
    head.append(f"**Score:** {result.score['score']}/100 — {md_escape(result.score['label'])}{delta}")
    head.append(f"**Findings:** {c['CRITICAL']} critical · {c['HIGH']} high · {c['MEDIUM']} medium · {c['LOW']} low")
    head.append("")
    head.append("**Result:** " + ("✅ passed" if decision.passed else "❌ failed — " + md_escape("; ".join(decision.reasons), 500)))
    head.append("")
    body: list[str] = []
    blocking = decision.by_status("blocking")
    if blocking:
        body.append(f"### ❌ Blocking ({len(blocking)})")
        for e in blocking[:MAX_COMMENT_ITEMS]:
            f = e.finding
            body.append(f"- {ICON[f['severity']]} **{f['severity']}** — {md_escape(f['title'])}  ")
            body.append(f"  `{_loc(f)}` · _{md_escape(e.reason, 200)}_")
            if f.get("capability_chain"):
                body.append("  Path: " + " → ".join(md_escape(s, 80) for s in f["capability_chain"][:6]))
            body.append(f"  Fix: {md_escape(f['recommendation'], 500)}")
            body.append(f"  Suppress (with justification): `{f['fingerprint']}`")
        if len(blocking) > MAX_COMMENT_ITEMS:
            body.append(f"- … and {len(blocking) - MAX_COMMENT_ITEMS} more (see the job log or SARIF results)")
        body.append("")
    warnings = decision.by_status("warning")
    if warnings:
        body.append(f"<details><summary>⚠️ Warnings ({len(warnings)})</summary>\n")
        for e in warnings[:MAX_COMMENT_ITEMS]:
            f = e.finding
            body.append(f"- {ICON[f['severity']]} {f['severity']} — {md_escape(f['title'])} (`{_loc(f)}`)")
        body.append("\n</details>\n")
    extra = []
    for status, label in (("existing", "existing"), ("suppressed", "suppressed"), ("ignored", "ignored")):
        n = len(decision.by_status(status))
        if n:
            extra.append(f"{n} {label}")
    if extra:
        body.append("_Not counted against this PR: " + ", ".join(extra) + "._")
    for note in decision.notes:
        body.append(f"\n> ⚠️ {md_escape(note, 300)}")
    if not blocking and not warnings:
        body.append("No new AI safety findings. 🎉")
    body.append(f"\n<sub>Policy: {md_escape(policy.source)} · ai-safety-checkup {__version__}</sub>")
    return "\n".join(head + body)[:60000]


# --------------------------------------------------------------------- json
def render_json(result, decision, policy, base=None) -> str:
    def item(e):
        f = e.finding
        return {"status": e.status, "reason": e.reason, "rule": e.rule_id, "fingerprint": f["fingerprint"],
                "severity": f["severity"], "category": f["category"], "capability": f["capability"],
                "domain": f.get("finding_domain"), "title": f["title"], "file": f["file_path"],
                "line": f.get("line", 0), "confidence": f.get("confidence"),
                "evidence": f.get("evidence", []), "recommendation": f.get("recommendation"),
                "path": f.get("capability_chain", [])}
    return json.dumps({
        "version": 1, "tool": "ai-safety-checkup", "tool_version": __version__,
        "passed": decision.passed, "reasons": decision.reasons, "policy": policy.source,
        "score": result.score["score"], "label": result.score["label"], "counts": result.score["counts"],
        "domain_scores": {k: v["score"] for k, v in result.domain_scores.items() if isinstance(v, dict) and "score" in v},
        "base_score": (base or {}).get("score"), "notes": decision.notes,
        "findings": [item(e) for e in decision.evaluated],
    }, indent=2)


# -------------------------------------------------------------------- sarif
def render_sarif(result, decision, policy, base=None) -> str:
    rules: dict[str, dict] = {}
    results = []
    for e in decision.evaluated:
        f = e.finding
        rid = f"{f['category']}/{f['capability']}"
        rules.setdefault(rid, {
            "id": rid, "name": rid.replace("/", "_"),
            "shortDescription": {"text": f"{f['category']} — {f['capability']}"},
            "fullDescription": {"text": str(f.get("consequence") or f.get("recommendation") or f["title"])[:1000]},
            "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "properties": {"tags": ["ai-safety", str(f.get("finding_domain", "")).lower()]},
        })
        res = {
            "ruleId": rid,
            "level": SARIF_LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}. {f['recommendation']}"[:2000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file_path"], "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "partialFingerprints": {"aiSafetyFingerprint/v1": f["fingerprint"]},
            "properties": {"severity": f["severity"], "confidence": f.get("confidence"),
                           "domain": f.get("finding_domain"), "policyStatus": e.status,
                           "path": f.get("capability_chain", [])},
        }
        if e.status in {"suppressed", "ignored"}:
            res["suppressions"] = [{"kind": "external", "justification": e.reason or e.status}]
        results.append(res)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AI Safety Checkup", "version": __version__,
                                       "informationUri": "https://github.com/", "rules": list(rules.values())}},
                  "results": results}],
    }, indent=1)


RENDERERS = {"text": render_text, "markdown": render_markdown, "json": render_json, "sarif": render_sarif}