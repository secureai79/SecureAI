import hashlib
import re

from . import detectors, file_selector
from .capability_extractor import FileAnalysis

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_POINTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 2}

# Risk-tiered scoring with diminishing returns and a per-tier cap.
#
# The flat model (score -= 25/15/7/2 per finding, unbounded) let sheer
# finding *volume* zero out the score on large repos even with zero
# CRITICAL/HIGH findings -- a real product-trust problem found in
# validation (VALIDATION_REPORT.md): 4 of 10 real repos hit 0/100 purely
# from MEDIUM-finding count, which reads as "totally broken" to a founder
# even when nothing severe was found.
#
# Each tier's first few findings cost close to the flat-model amount (so a
# repo with 1-2 real findings scores almost identically to before), but
# each additional finding in that tier costs less, and the tier's *total*
# contribution is capped -- so 50 mediocre MEDIUM findings can never do
# more damage than a handful of genuinely well-differentiated ones would.
# The exact numbers are a starting calibration, not load-bearing precision;
# what matters is the shape (diminishing + capped), not these specific values.
SEVERITY_SCHEDULE = {
    "CRITICAL": {"steps": [25, 20, 15], "floor": 10, "cap": 60},
    "HIGH":     {"steps": [15, 12, 9],  "floor": 6,  "cap": 40},
    "MEDIUM":   {"steps": [7, 5, 3, 2], "floor": 1,  "cap": 25},
    "LOW":      {"steps": [2, 2],       "floor": 1,  "cap": 10},
}


def _tier_deduction(count: int, schedule: dict) -> int:
    """Total point deduction for `count` findings in one severity tier,
    applying the diminishing-returns schedule then the tier cap."""
    if count <= 0:
        return 0
    steps = schedule["steps"]
    total = sum(steps[:count])
    if count > len(steps):
        total += (count - len(steps)) * schedule["floor"]
    return min(total, schedule["cap"])

# Base severity per dangerous-function category/keyword.
BASE_SEVERITY = {
    ("DATA", "delete"): "CRITICAL",
    ("DATA", "drop"): "CRITICAL",
    ("DATA", "truncate"): "CRITICAL",
    ("DATA", "export"): "MEDIUM",
    ("DATA", "remove"): "MEDIUM",
    ("DATA", "update"): "MEDIUM",
    ("FINANCIAL", "refund"): "HIGH",
    ("FINANCIAL", "charge"): "HIGH",
    ("FINANCIAL", "transfer"): "HIGH",
    ("FINANCIAL", "payout"): "HIGH",
    ("INFRASTRUCTURE", "execute"): "HIGH",
    ("INFRASTRUCTURE", "shell execution"): "HIGH",
    ("INFRASTRUCTURE", "deploy"): "MEDIUM",
    ("INFRASTRUCTURE", "terminate"): "HIGH",
    ("COMMUNICATION", "send"): "MEDIUM",
    ("CODE", "merge"): "LOW",
    ("CODE", "push"): "LOW",
}

RECOMMENDATIONS = {
    "FINANCIAL": "Require human approval above a defined dollar threshold before executing this action.",
    "DATA": "Require human approval for destructive database operations, or restrict the AI's DB role to read-only.",
    "COMMUNICATION": "Add a review step or rate limit before AI-triggered outbound messages are sent.",
    "INFRASTRUCTURE": "Require human approval before shell/cloud/deploy operations triggered by AI output.",
    "CODE": "Require review/approval before AI-initiated merges or pushes to protected branches.",
}

CONSEQUENCE_MAP = {
    ("FINANCIAL", "refund"): "Financial loss / customer account impact",
    ("FINANCIAL", "charge"): "Financial loss / customer charge",
    ("FINANCIAL", "transfer"): "Financial transfer / monetary loss",
    ("FINANCIAL", "payout"): "Financial payout",
    ("DATA", "delete"): "Permanent data loss",
    ("DATA", "drop"): "Permanent database destruction",
    ("DATA", "truncate"): "Permanent data loss",
    ("DATA", "export"): "Sensitive-data disclosure",
    ("COMMUNICATION", "send"): "External communication / reputation impact",
    ("INFRASTRUCTURE", "execute"): "Arbitrary system or infrastructure execution",
    ("INFRASTRUCTURE", "deploy"): "Production deployment impact",
    ("INFRASTRUCTURE", "terminate"): "Infrastructure availability impact",
    ("CODE", "merge"): "Unauthorized code change",
    ("CODE", "push"): "Unauthorized code publication/change",
}

IMPACT_LEVEL_MAP = {
    ("FINANCIAL", "refund"): "HIGH",
    ("FINANCIAL", "charge"): "HIGH",
    ("FINANCIAL", "transfer"): "CRITICAL",
    ("FINANCIAL", "payout"): "HIGH",

    ("DATA", "delete"): "CRITICAL",
    ("DATA", "drop"): "CRITICAL",
    ("DATA", "truncate"): "CRITICAL",
    ("DATA", "export"): "HIGH",

    ("COMMUNICATION", "send"): "MEDIUM",

    ("INFRASTRUCTURE", "execute"): "CRITICAL",
    ("INFRASTRUCTURE", "deploy"): "HIGH",
    ("INFRASTRUCTURE", "terminate"): "CRITICAL",

    ("CODE", "merge"): "MEDIUM",
    ("CODE", "push"): "MEDIUM",
}

def _control_status(
    approval_detected: bool,
    limit_detected: bool,
) -> str:
    if approval_detected and limit_detected:
        return "CONTROLLED"
    if approval_detected or limit_detected:
        return "PARTIALLY_CONTROLLED"
    return "UNCONTROLLED"

def _downgrade(severity: str, steps: int) -> str:
    idx = SEVERITY_ORDER.index(severity)
    idx = max(0, idx - steps)
    return SEVERITY_ORDER[idx]


def build_findings_for_file(analysis: FileAnalysis, repo_has_ai: bool) -> list[dict]:
    """Produce raw (pre-LLM) findings for one file.

    Every finding then passes through a uniform "is this trustworthy enough
    to affect the Safety Score" gate (see _apply_scoring_gate below) —
    real-repo validation (VALIDATION_REPORT.md) found the regex fallback
    for non-Python files and test/tooling-path noise were the two biggest
    sources of false positives, badly damaging trust on real repos even
    though the underlying Python AST/taint engine held up well.
    """
    if analysis.used_ast:
        raw = _build_findings_ast(analysis, repo_has_ai)
    else:
        raw = _build_findings_regex(analysis, repo_has_ai)
    return [_apply_scoring_gate(f, analysis) for f in raw]


def _apply_scoring_gate(finding: dict, analysis: FileAnalysis) -> dict:
    """Decide whether a finding is trustworthy enough to affect the Safety
    Score. Two disqualifiers, either one is enough:

    1. It came from the regex fallback (no real data-flow tracing available
       -- ai_controlled is unknown, not verified).
    2. It's in a non-runtime path (tests/scripts/docs/examples/fixtures/mocks)
       -- almost never a real agent capability, validated against real repos.

    Findings that fail the gate are still returned (nothing is hidden) but:
    - are excluded from calculate_score()'s point deductions entirely
    - have their severity capped at LOW (never present as a misleading
      CRITICAL/HIGH when the tool has this little confidence in them)
    - get a leading evidence line explaining why, and a reframed title
    - have potential_points forced to 0 (resolving them doesn't move the
      score, so "Fix My Score" shouldn't imply it would)
    """
    non_runtime = file_selector.is_non_runtime_path(finding["file_path"])
    scored = analysis.used_ast and not non_runtime

    finding["scored"] = scored
    if scored:
        return finding

    reasons = []
    if not analysis.used_ast:
        reasons.append("regex/keyword match, no data-flow verification available for this file type")
    if non_runtime:
        reasons.append("path looks like test/tooling/docs/examples code, not agent runtime code")
    reason_text = "; ".join(reasons)

    finding["severity"] = "LOW"
    finding["potential_points"] = 0
    finding["title"] = f"Potential capability detected: {finding['title']}"
    finding["evidence"] = [
        f"⚠️ Not scored ({reason_text}) — treat as a lead to verify manually, not a confirmed finding."
    ] + finding["evidence"]
    return finding


def _build_findings_ast(analysis: FileAnalysis, repo_has_ai: bool) -> list[dict]:
    """AST path: severity now factors in whether AI output actually reaches
    the dangerous call (analysis.ast_findings[i].ai_controlled), not just
    whether an AI SDK is merely present somewhere in the file."""
    findings = []
    file_ai_provider = analysis.ai_providers[0] if analysis.ai_providers else None

    # Same call, multiple sub-signals (e.g. a call matched under two rules)
    # shouldn't double-count; dedupe by (operation, line).
    seen = set()
    # Two distinct call sites for the same operation in the same function
    # (e.g. one AI-controlled refund call and one hardcoded-amount refund
    # call, both in the same function) must NOT collapse into one
    # fingerprint — track an occurrence index per (function, category,
    # operation) group, in source order, and fold it into the fingerprint.
    occurrence_counters: dict[tuple, int] = {}

    for f in analysis.ast_findings:
        key = (f.operation, f.line)
        if key in seen:
            continue
        seen.add(key)

        occ_key = (f.function_name, f.category, f.operation)
        occurrence_counters[occ_key] = occurrence_counters.get(occ_key, 0) + 1
        occurrence_index = occurrence_counters[occ_key]

        base = BASE_SEVERITY.get((f.category, f.operation), "MEDIUM")
        severity = base
        downgrade_steps = int(f.approval_detected) + int(f.limit_detected)
        if not f.ai_controlled:
            # The dangerous call exists, but no traced data-flow shows AI
            # output reaching it — much lower priority than a confirmed
            # AI-controlled action.
            downgrade_steps += 1
        if downgrade_steps:
            severity = _downgrade(severity, downgrade_steps)

        evidence = []
        if file_ai_provider:
            evidence.append(f"{file_ai_provider} SDK / agent detected in this file")
        if f.ai_controlled:
            evidence.append("Data-flow trace: AI-generated value reaches this call's argument(s)")
        else:
            evidence.append("No traced data-flow from AI output to this call's argument(s)")
        evidence.append(f"Capability chain: {' → '.join(f.capability_chain)}")
        evidence.append(
            "Human-approval guard detected in an enclosing branch" if f.approval_detected
            else "No human-approval guard detected"
        )
        evidence.append(
            "Threshold/limit comparison detected in an enclosing branch" if f.limit_detected
            else "No threshold/limit check detected"
        )

        findings.append({
            "title": _title_for(f.category, f.operation, file_ai_provider, f.ai_controlled),
            "severity": severity,
            "category": f.category,
            "file_path": analysis.file_path,
            "line": f.line,
            "capability": f.operation,
            "ai_provider": file_ai_provider,
            "confidence": f.control_confidence,
            "evidence": evidence,
            "recommendation": RECOMMENDATIONS.get(f.category, "Add a human review step before this action executes."),
            "consequence": CONSEQUENCE_MAP.get((f.category, f.operation),"Potential real-world impact"),
            "impact_level": IMPACT_LEVEL_MAP.get((f.category, f.operation),"MEDIUM",),
            "control_status": _control_status(f.approval_detected,f.limit_detected,),
            "ai_connected": bool(file_ai_provider) or repo_has_ai,
            "ai_controlled": f.ai_controlled,
            "control_confidence": f.control_confidence,
            "capability_chain": f.capability_chain,
            "function_name": f.function_name,
            "call_chain": f.chain,
            "occurrence_index": occurrence_index,
            "human_approval_detected": f.approval_detected,
            "limit_detected": f.limit_detected,
            "snippet": f.snippet_line,
        })

    return findings


def _title_for(category: str, label: str, provider: str | None, ai_controlled: bool = True) -> str:
    who = f"AI ({provider})" if provider else "AI-connected code"
    if not ai_controlled:
        who = f"Code near {provider} usage" if provider else "Code"
    labels = {
        "refund": f"{who} may issue unlimited refunds" if ai_controlled else f"{who} contains an unguarded refund call",
        "charge": f"{who} may trigger unreviewed charges",
        "transfer": f"{who} may trigger fund transfers",
        "payout": f"{who} may trigger payouts",
        "delete": f"{who} may execute destructive DELETE operations" if ai_controlled else f"{who} contains a destructive DELETE operation",
        "drop": f"{who} may DROP database tables",
        "truncate": f"{who} may TRUNCATE database tables",
        "export": f"{who} may export data without review",
        "send": f"{who} may send external communications autonomously" if ai_controlled else f"{who} contains an unguarded send operation",
        "execute": f"{who} may execute shell commands",
        "deploy": f"{who} may trigger deployments",
        "terminate": f"{who} may terminate infrastructure",
        "merge": f"{who} may merge code without review",
        "push": f"{who} may push code without review",
    }
    return labels.get(label, f"{who} may perform a risky '{label}' operation")


FUNC_DEF_LINE_RE = re.compile(
    r"^\s*(?:def|function|const|let|var|async function)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)", re.MULTILINE
)


def _nearest_enclosing_function(text: str, line: int) -> str:
    """Best-effort: scan backwards from `line` for the nearest def/function
    declaration, for fingerprint grouping in the regex fallback path (no
    real AST scope available for non-Python files)."""
    lines = text.splitlines()
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = FUNC_DEF_LINE_RE.match(lines[i])
        if m:
            return m.group(1)
    return "module"


def _build_findings_regex(analysis: FileAnalysis, repo_has_ai: bool) -> list[dict]:
    """Legacy regex/keyword path — used only for non-Python files (JS/TS) or
    Python that failed to parse. No data-flow tracing available here, so
    every finding is conservatively marked ai_controlled=None (unknown)."""
    findings = []
    text = analysis.raw_text
    file_ai_provider = analysis.ai_providers[0] if analysis.ai_providers else None

    dangerous_lib_names = {d["name"] for d in analysis.dangerous_libraries}

    # A wrapper function's call-site and its `def` line both match the same
    # keyword (e.g. `refund_customer(...)` and `def refund_customer(...)`).
    # Collapse those into a single finding per keyword, keeping the earliest
    # (most upstream / most likely to be the actual triggering point) line.
    seen_keywords: dict[str, dict] = {}
    for call in analysis.dangerous_calls:
        kw = call["keyword"]
        if kw not in seen_keywords or call["line"] < seen_keywords[kw]["line"]:
            seen_keywords[kw] = call
    deduped_calls = list(seen_keywords.values())

    occurrence_counters: dict[tuple, int] = {}

    for call in deduped_calls:
        category = call["category"]
        keyword = call["keyword"]
        label = call["label"]
        line = call["line"]
                # Generic capability words in non-Python files are too ambiguous
        # to surface as potential leads without stronger contextual evidence.
        # Keep library-backed operations visible because the library provides
        # additional evidence that the capability is real.
        GENERIC_CAPABILITIES = {
            ("DATA", "remove"),
            ("DATA", "update"),
            ("DATA", "export"),
            ("COMMUNICATION", "send"),
            ("CODE", "push"),
        }

        if (
            (category, keyword) in GENERIC_CAPABILITIES
            and not dangerous_lib_names
            and file_selector.is_non_runtime_path(analysis.file_path)
        ):
            continue

        function_name = _nearest_enclosing_function(text, line)
        occ_key = (function_name, category, keyword)
        occurrence_counters[occ_key] = occurrence_counters.get(occ_key, 0) + 1
        occurrence_index = occurrence_counters[occ_key]

        base = BASE_SEVERITY.get((category, keyword), "MEDIUM")

        has_approval = detectors.nearby_has_approval_guard(text, line)
        has_limit = detectors.nearby_has_limit_guard(text, line)

        severity = base
        downgrade_steps = int(has_approval) + int(has_limit)
        if downgrade_steps:
            severity = _downgrade(severity, downgrade_steps)

        confidence = 0.5  # capped lower than the AST path — no data-flow proof available
        ai_connected = bool(file_ai_provider)
        if ai_connected:
            confidence += 0.2
        elif repo_has_ai:
            confidence += 0.05
        if category == "FINANCIAL" and "stripe" in dangerous_lib_names:
            confidence += 0.1
        if category == "DATA" and any(x in dangerous_lib_names for x in ("psycopg", "psycopg2", "sqlalchemy", "pymongo")):
            confidence += 0.1
        if category == "COMMUNICATION" and any(x in dangerous_lib_names for x in ("smtplib", "sendgrid", "twilio")):
            confidence += 0.1
        if category == "INFRASTRUCTURE" and "subprocess" in dangerous_lib_names:
            confidence += 0.1
        confidence = round(min(confidence, 0.9), 2)

        if not repo_has_ai and confidence < 0.55:
            continue

        evidence = []
        if file_ai_provider:
            evidence.append(f"{file_ai_provider} SDK detected in this file")
        elif repo_has_ai:
            evidence.append("AI SDK detected elsewhere in repository")
        for lib in dangerous_lib_names:
            evidence.append(f"{lib} usage detected")
        evidence.append(f"'{label}' capability detected at line {line} (keyword match — no AST available for this file type)")
        evidence.append(
            "Human approval guard detected nearby" if has_approval
            else "No explicit human-approval check detected"
        )
        evidence.append(
            "Limit/threshold check detected nearby" if has_limit
            else "No explicit limit/threshold detected"
        )

        findings.append({
            "title": _title_for(category, label, file_ai_provider, ai_controlled=True),
            "severity": severity,
            "category": category,
            "file_path": analysis.file_path,
            "line": line,
            "capability": f"{keyword}",
            "ai_provider": file_ai_provider,
            "confidence": confidence,
            "evidence": evidence,
            "recommendation": RECOMMENDATIONS.get(category, "Add a human review step before this action executes."),
            "consequence": CONSEQUENCE_MAP.get((category, keyword),"Potential real-world impact",),
            "impact_level": IMPACT_LEVEL_MAP.get((category, keyword),"MEDIUM",),
            "control_status": _control_status(has_approval,has_limit,),
            "ai_connected": ai_connected or repo_has_ai,
            "ai_controlled": None,
            "control_confidence": confidence,
            "capability_chain": [analysis.file_path, label.upper()],
            "function_name": function_name,
            "call_chain": keyword,
            "occurrence_index": occurrence_index,
            "human_approval_detected": has_approval,
            "limit_detected": has_limit,
            "snippet": detectors.snippet_around(text, line),
        })

    return findings


def compute_fingerprint(finding: dict) -> str:
    """Stable identity for a finding across scans/line-shifts, used for
    baseline/regression diffing.

    category + capability + file_path alone can collapse two distinct call
    sites in the same file into one fingerprint (e.g. one AI-controlled
    refund call and one hardcoded-amount refund call in the same function).
    Adding function_name + call_chain + occurrence_index (the call's
    ordinal position within that function/category/operation group, in
    source order) disambiguates them while staying stable across unrelated
    edits elsewhere in the file that merely shift line numbers.
    """
    key = (
        f"{finding['category']}::{finding['capability']}::{finding['file_path']}::"
        f"{finding.get('function_name', 'module')}::{finding.get('call_chain', '')}::"
        f"{finding.get('occurrence_index', 1)}"
    )
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def calculate_score(findings: list[dict]) -> dict:
    """`scored=False` findings (regex-fallback and/or non-runtime paths --
    see _apply_scoring_gate) are excluded entirely: they don't subtract
    points and don't appear in `counts`. They're still visible in the
    findings list as "potential capability detected" leads, just not
    treated as confirmed risk for score purposes.

    Deductions use the diminishing-returns, per-tier-capped schedule above
    rather than flat per-finding points -- see SEVERITY_SCHEDULE for why."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    unscored_count = 0
    for f in findings:
        if f.get("status") == "resolved":
            continue
        if not f.get("scored", True):
            unscored_count += 1
            continue
        counts[f["severity"]] += 1

    tier_deductions = {
        sev: _tier_deduction(counts[sev], SEVERITY_SCHEDULE[sev]) for sev in counts
    }
    score = max(0, 100 - sum(tier_deductions.values()))

    if score >= 90:
        label = "LOW RISK"
    elif score >= 80:
        label = "MEDIUM RISK"
    elif score >= 50:
        label = "HIGH RISK"
    else:
        label = "CRITICAL RISK"

    return {
        "score": score, "label": label, "counts": counts,
        "unscored_count": unscored_count, "tier_deductions": tier_deductions,
    }

def calculate_domain_scores(findings: list[dict]) -> dict:
    """Calculate separate scores for AI Safety and Project Security.

    The existing calculate_score() remains the source of truth for the
    overall score. This helper applies the same scoring algorithm independently
    to each finding domain.
    """
    ai_findings = [
        f for f in findings
        if f.get("finding_domain") == "AI_SAFETY"
    ]

    project_findings = [
        f for f in findings
        if f.get("finding_domain") == "PROJECT_SECURITY"
    ]

    ai_score = calculate_score(ai_findings)
    project_score = calculate_score(project_findings)

    return {
        "ai_safety": ai_score,
        "project_security": project_score,
    }
