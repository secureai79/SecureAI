"""Customer-data minimisation and secret redaction helpers."""
import json
import os
import re
from typing import Any

# Deliberately broad: this is a last line of defence before persistence or
# optional external processing. It is not the secret detector itself.
SECRET_PATTERNS = [
    re.compile(r"(?i)(sk-[A-Za-z0-9_-]{16,})"),
    re.compile(r"(?i)(sk_(?:live|test)_[A-Za-z0-9]{12,})"),
    re.compile(r"(?i)(gh[pors]_[A-Za-z0-9]{20,})"),
    re.compile(r"(?i)(github_pat_[A-Za-z0-9_]{20,})"),
    re.compile(r"(?i)(xox[baprs]-[A-Za-z0-9-]{10,})"),
    re.compile(r"(?i)(AIza[0-9A-Za-z_-]{20,})"),
    re.compile(r"(?i)(AKIA[0-9A-Z]{16})"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.S),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(r"(?i)(password|passwd|api[_-]?key|secret|token|private[_-]?key|access[_-]?token)\s*[:=]\s*(['\"])[^'\"\n]{8,}\2"),
]


def external_llm_enabled() -> bool:
    return os.environ.get("ENABLE_EXTERNAL_LLM_REFINEMENT", "false").lower() in {"1", "true", "yes", "on"}


def store_source_snippets() -> bool:
    # Privacy-first default. Customers explicitly opt in if they want stored
    # source excerpts in the dashboard/PDF.
    return os.environ.get("STORE_SOURCE_SNIPPETS", "false").lower() in {"1", "true", "yes", "on"}


def retention_days() -> int:
    value = int(os.environ.get("SCAN_RETENTION_DAYS", "30"))
    if value < 1 or value > 3650:
        raise ValueError("SCAN_RETENTION_DAYS must be between 1 and 3650")
    return value


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    out = value
    for pattern in SECRET_PATTERNS:
        def repl(m: re.Match) -> str:
            # Preserve a useful key/name prefix where possible, never the secret.
            text = m.group(0)
            if text.lower().startswith("bearer"):
                return text.split()[0] + " [REDACTED]"
            if "=" in text or ":" in text:
                prefix = re.split(r"[:=]", text, maxsplit=1)[0]
                return prefix + "=[REDACTED]"
            return "[REDACTED]"
        out = pattern.sub(repl, out)
    return out


def redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_json(v) for v in value]
    if isinstance(value, dict):
        return {k: redact_json(v) for k, v in value.items()}
    return value



def prepare_finding_for_storage(finding: dict) -> dict:
    """Return a recursively redacted copy of a finding before persistence.

    All string values are redacted, not just evidence and snippets.
    Source snippets remain disabled unless explicitly opted in.
    """
    # Redact strings in every field, including descriptions, recommendations,
    # paths, function names, call chains, and nested metadata.
    out = redact_json(finding)

    evidence = out.get("evidence")
    if isinstance(evidence, list):
        safe_evidence = []
        for item in evidence[:8]:
            text = redact_text(str(item)) or ""
            # Avoid persisting likely source-code excerpts as evidence.
            if text.lower().startswith(
                ("line:", "code:", "snippet:", "evidence:")
            ):
                continue
            safe_evidence.append(text[:600])
        out["evidence"] = safe_evidence
    else:
        out["evidence"] = redact_json(evidence)

    # Snippets are not stored by default, even after redaction.
    if store_source_snippets():
        out["snippet"] = redact_text(out.get("snippet"))
    else:
        out["snippet"] = None

    return out


def sanitize_error(message: str | None) -> str:
    if not message:
        return "Scan failed. Check the repository URL and scan limits, then try again."
    clean = redact_text(message) or "Scan failed."
    # Do not return git stderr, filesystem paths, stack traces, or provider
    # responses to customers.
    return "Scan failed. Check the repository URL and scan limits, then try again." if len(clean) > 500 else clean
