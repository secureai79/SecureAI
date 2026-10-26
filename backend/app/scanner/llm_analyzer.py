
"""
Optional LLM refinement for findings already detected by static analysis.

The LLM may provide additional triage information, but its false-positive
judgment must not silently remove a deterministic finding.
"""

import json
import os

from ..privacy import external_llm_enabled, redact_text

SYSTEM_PROMPT = """You are a precise security triage assistant. You will be given
a short code snippet that was flagged by static analysis as a possible
AI-triggerable financial/destructive/external action.

Decide whether the snippet plausibly allows an AI-generated decision to
trigger that action, and whether guardrails (human approval or a hard limit)
are visible in the snippet.

Respond with ONLY a JSON object, no prose, no markdown fences, in this exact shape:
{"ai_connected": bool, "human_approval_detected": bool, "limit_detected": bool,
"confidence": number between 0 and 1, "false_positive": bool}
"""


def _client():
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key or not external_llm_enabled():
        return None

    try:
        import anthropic
    except ImportError:
        return None

    return anthropic.Anthropic(api_key=api_key)


def refine_finding(finding: dict) -> dict:
    """Refine a finding without allowing an LLM to suppress it."""
    client = _client()
    if client is None:
        return finding

    capability = redact_text(str(finding.get("capability", "unknown")))
    category = redact_text(str(finding.get("category", "unknown")))
    file_path = redact_text(str(finding.get("file_path", "unknown")))
    snippet = redact_text(finding.get("snippet")) or "[source snippet withheld]"

    user_prompt = (
        f"Capability: {capability or 'unknown'}\n"
        f"Category: {category or 'unknown'}\n"
        f"File: {file_path or 'unknown'}\n"
        f"Snippet:\n{snippet}\n"
    )


    try:
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=200,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        text = "".join(
            block.text
            for block in resp.content
            if getattr(block, "type", None) == "text"
        ).strip()

        text = text.replace("```json", "").replace("```", "").strip()
        data = json.loads(text)

        if not isinstance(data, dict):
            return finding

        confidence = float(data.get("confidence", finding.get("confidence", 0.0)))
        if not 0.0 <= confidence <= 1.0:
            return finding

    except (Exception,):
        # Keep the original deterministic finding if the LLM fails.
        return finding

    refined = dict(finding)
    refined["confidence"] = round(confidence, 2)
    refined["ai_connected"] = bool(
        data.get("ai_connected", finding.get("ai_connected", False))
    )
    refined["human_approval_detected"] = bool(
        data.get(
            "human_approval_detected",
            finding.get("human_approval_detected", False),
        )
    )
    refined["limit_detected"] = bool(
        data.get("limit_detected", finding.get("limit_detected", False))
    )

    # This is advisory metadata only. Do not filter the finding based on it.
    refined["_llm_suggested_false_positive"] = bool(
        data.get("false_positive", False)
    )

    return refined


def refine_findings(findings: list[dict]) -> list[dict]:
    """Return every finding, optionally enriched with LLM triage metadata."""
    if not os.environ.get("ANTHROPIC_API_KEY") or not external_llm_enabled():
        return findings

    return [refine_finding(finding) for finding in findings]
