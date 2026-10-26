"""
Priority 6 from feedback: "Fix My Score" should generate an actual code
patch, not just a text recommendation.

Deliberately simple, per the feedback ("keep it simple"): template-based
guard-clause insertion per category, built from the single-line snippet
already captured at scan time (no need to re-clone the repo). This is NOT
a general program-repair system — it inserts a standard guard pattern
appropriate to the category and lets the developer adjust the threshold /
approval function to match their codebase.

Flow this supports:
    Finding -> generate_fix() -> unified diff + explanation -> developer
    reviews -> (optionally) apply_fix() writes it to a local/file:// repo
    on disk -> rescan -> score improves.

Applying to a real remote GitHub repo (opening a branch + PR) requires
GitHub OAuth *write* access, which isn't implemented in this MVP — see
README. apply_fix() only works against local/file:// repositories, which
is enough to demonstrate the full loop end-to-end.
"""
from __future__ import annotations

import difflib
import re

VAR_HINT_RE = re.compile(r"(\w+)\s*=\s*(\w+)\s*[,)]")


def _guess_amount_var(snippet: str) -> str:
    """Best-effort: pull the keyword-argument name most likely to represent
    a dollar amount out of the flagged call, e.g. `amount=decision["amount"]`
    -> "amount". Falls back to a generic name if nothing matches."""
    for kw in ("amount", "total", "value", "sum"):
        m = re.search(rf"{kw}\s*=\s*([\w\[\]\"'\.]+)", snippet)
        if m:
            return kw
    return "amount"


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _build_guard_lines(category: str, capability: str, snippet: str, indent: str) -> list[str]:
    if category == "FINANCIAL":
        var = _guess_amount_var(snippet)
        return [
            f"{indent}MAX_AUTO_{capability.upper()}_AMOUNT = 100  # TODO: set the real business threshold",
            f"{indent}if {var} > MAX_AUTO_{capability.upper()}_AMOUNT:",
            f"{indent}    return require_human_approval({var})",
            f"{indent}",
        ]
    if category == "DATA":
        return [
            f"{indent}if not is_approved_by_human():  # TODO: wire up your real approval mechanism",
            f"{indent}    return require_human_approval(operation={capability!r})",
            f"{indent}",
        ]
    if category == "COMMUNICATION":
        return [
            f"{indent}if not is_approved_by_human():  # TODO: wire up your real approval mechanism",
            f"{indent}    return queue_for_human_review(message)",
            f"{indent}",
        ]
    if category == "INFRASTRUCTURE":
        return [
            f"{indent}if not is_approved_by_human():  # TODO: wire up your real approval mechanism",
            f"{indent}    return require_human_approval(operation={capability!r})",
            f"{indent}",
        ]
    if category == "CODE":
        return [
            f"{indent}if not is_approved_by_human():  # TODO: wire up your real approval mechanism",
            f"{indent}    return require_human_approval(operation={capability!r})",
            f"{indent}",
        ]
    return [
        f"{indent}if not is_approved_by_human():  # TODO: wire up your real approval mechanism",
        f"{indent}    return require_human_approval()",
        f"{indent}",
    ]


def generate_fix(finding) -> dict:
    """finding: a models.Finding (or any object/dict with the same attrs).
    Returns {explanation, inserted_code, diff, before, after}."""
    category = finding.category if hasattr(finding, "category") else finding["category"]
    capability = finding.capability if hasattr(finding, "capability") else finding["capability"]
    file_path = finding.file_path if hasattr(finding, "file_path") else finding["file_path"]
    line_number = finding.line_number if hasattr(finding, "line_number") else finding["line"]
    snippet = (finding.snippet if hasattr(finding, "snippet") else finding.get("snippet")) or ""

    if category == "PROMPT_INJECTION":
        # There is no safe one-line patch for injection: the mitigation is a design
        # change (isolate untrusted content, least-privilege tools, approvals).
        return {
            "file_path": file_path, "line": line_number,
            "explanation": (
                "Prompt injection cannot be fixed by one inserted line. Recommended changes: "
                "(1) wrap the untrusted content in clear delimiters and tell the model it is data, not instructions; "
                "(2) run an injection classifier or guardrail on it before it reaches the model; "
                "(3) remove tools this agent does not strictly need and require human approval for money, "
                "infrastructure, data-changing and outbound actions; "
                "(4) never give one agent untrusted content, private data and an outbound channel at the same time."
            ),
            "inserted_code": "", "diff": "", "before": "", "after": "",
            "note": "Guidance only: no automatic patch is generated for prompt-injection findings.",
        }

    if not snippet:
        return {
            "file_path": file_path, "line": line_number,
            "explanation": "A suggested guard is available, but privacy mode did not retain the source excerpt needed to generate a safe line-level patch.",
            "inserted_code": "", "diff": "", "before": "", "after": "",
            "note": "Source snippets are disabled by default. Review the recommendation in the dashboard or enable encrypted evidence snippets explicitly if your organization wants line-level patch previews.",
        }

    indent = _indent_of(snippet)
    guard_lines = _build_guard_lines(category, capability, snippet, indent)
    inserted_code = "\n".join(l.rstrip() for l in guard_lines if l.strip() or l == f"{indent}")

    before_lines = [snippet]
    after_lines = guard_lines + [snippet]

    diff = "\n".join(difflib.unified_diff(
        before_lines, after_lines,
        fromfile=f"a/{file_path}", tofile=f"b/{file_path}",
        fromfiledate=f"line {line_number}", tofiledate=f"line {line_number}",
        lineterm="",
    ))

    explanations = {
        "FINANCIAL": "Adds a dollar-amount threshold: anything above it is routed to a human reviewer instead of executing automatically.",
        "DATA": "Adds a human-approval gate before the destructive database operation runs.",
        "COMMUNICATION": "Adds a review step before the AI-drafted message is sent externally.",
        "INFRASTRUCTURE": "Adds a human-approval gate before the shell/cloud/deploy operation runs.",
        "CODE": "Adds a human-approval gate before the AI-initiated merge/push runs.",
    }

    return {
        "file_path": file_path,
        "line": line_number,
        "explanation": explanations.get(category, "Adds a human-approval gate before this action runs."),
        "inserted_code": inserted_code,
        "diff": diff,
        "before": snippet,
        "after": inserted_code + ("\n" + snippet if snippet else ""),
        "note": "Template-generated guard clause — review the threshold and wire `require_human_approval`/`is_approved_by_human` to your real approval mechanism before merging.",
    }



def apply_fix_to_local_file(root_dir: str, fix: dict) -> dict:
    """Safely insert generated guard lines into a file within a local checkout."""
    import os
    import tempfile
    from pathlib import Path

    try:
        root = Path(root_dir).resolve(strict=True)
        if not root.is_dir():
            raise FileNotFoundError("Repository root is not a directory")

        relative = Path(fix["file_path"])
        if relative.is_absolute() or not fix["file_path"] or "\x00" in fix["file_path"]:
            raise FileNotFoundError("Invalid repository-relative file path")

        # Resolve symlinks in parent components and reject anything outside root.
        target = (root / relative).resolve(strict=True)
        if not target.is_relative_to(root) or not target.is_file():
            raise FileNotFoundError("Refusing to modify a file outside the local repository checkout")

        # Do not follow a symlink at the final path.
        if (root / relative).is_symlink():
            raise FileNotFoundError("Refusing to modify a symbolic link")

        line_number = fix.get("line")
        inserted_code = fix.get("inserted_code")

        if not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1:
            raise ValueError("Fix line must be a positive integer")
        if not isinstance(inserted_code, str) or not inserted_code.strip():
            raise ValueError("Fix must contain non-empty inserted code")
        if "\x00" in inserted_code:
            raise ValueError("Fix contains invalid null characters")

        # Preserve newline style and mode where possible.
        original_bytes = target.read_bytes()
        try:
            original_text = original_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Refusing to modify a file that is not valid UTF-8") from exc

        lines = original_text.splitlines(keepends=True)
        if line_number > len(lines) + 1:
            raise ValueError("Fix line is beyond the end of the file")

        # Refuse stale fixes: the finding's original snippet must still match
        # the line at which the fix is being inserted, when supplied.
        expected_before = fix.get("before")
        if expected_before is not None:
            if line_number > len(lines) or lines[line_number - 1].rstrip("\r\n") != expected_before.rstrip("\r\n"):
                raise ValueError("Source line changed since the fix was generated; rescan before applying")

        newline = "\r\n" if "\r\n" in original_text else "\n"
        guard_lines = inserted_code.splitlines()
        if not guard_lines:
            raise ValueError("Fix contains no insertable lines")
        guard_text = "".join(line + newline for line in guard_lines)

        insert_at = line_number - 1
        new_text = "".join(lines[:insert_at]) + guard_text + "".join(lines[insert_at:])

        # Write a temporary file in the same directory, then atomically replace.
        # Recheck symlinks immediately before replacement to reduce race exposure.
        mode = target.stat().st_mode
        fd, temp_name = tempfile.mkstemp(prefix=".ai-safety-fix-", dir=str(target.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
                fh.write(new_text)
                fh.flush()
                os.fsync(fh.fileno())

            if (root / relative).is_symlink():
                raise FileNotFoundError("Refusing to replace a symbolic link")
            os.chmod(temp_name, mode)
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

        return {
            "applied": True,
            "file_path": fix["file_path"],
            "lines_inserted": len(guard_lines),
        }

    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid fix payload") from exc