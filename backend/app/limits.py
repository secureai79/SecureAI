"""Scan limits, scaled by the organisation's plan.

Today every organisation is on the "pilot" plan, whose limits are generous on purpose. Large
repositories are scanned as far as the limits allow and the result says exactly what was and was
not covered (see Scan.coverage). When billing exists, moving an organisation to a bigger plan is a
one-line change (``organization.plan = "team"``); nothing else in the scanner needs to change.

All base values come from environment variables so an operator can tune them for the host's RAM/CPU.
"""
import os

# Multipliers applied to the base limits. Add a plan here and set organization.plan to use it.
PLAN_MULTIPLIERS = {"pilot": 1, "team": 2, "business": 5}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def multiplier(plan: str | None) -> int:
    return PLAN_MULTIPLIERS.get((plan or "pilot").lower(), 1)


def for_plan(plan: str | None) -> dict:
    """Effective limits for a plan, as plain ints."""
    m = multiplier(plan)
    return {
        "max_files": _int("MAX_SCAN_FILES", 20000) * m,                 # files analysed per scan (soft cap)
        "max_bytes": _int("MAX_SCAN_BYTES", 200 * 1024 * 1024) * m,     # source bytes analysed per scan (soft cap)
        "max_file_bytes": _int("MAX_SCAN_FILE_BYTES", 2 * 1024 * 1024),  # one file larger than this is skipped
        "time_budget": _int("SCAN_TIME_BUDGET_SECONDS", 540) * m,       # analysis stops (partial result) after this
        "worker_timeout": _int("SCAN_WORKER_TIMEOUT_SECONDS", 780) + (m - 1) * 540,
        "worker_cpu": _int("SCAN_WORKER_CPU_SECONDS", 700) + (m - 1) * 540,
        "clone_timeout": _int("GIT_CLONE_TIMEOUT_SECONDS", 600),
        "max_clone_mb": _int("MAX_CLONE_MB", 1024),
        "max_members": _int("MAX_MEMBERS_PER_ORG", 10) * m,             # members + pending invitations
    }


def worker_env(plan: str | None) -> dict[str, str]:
    """Environment variables handed to the sandboxed analysis worker for this plan."""
    lim = for_plan(plan)
    return {
        "MAX_SCAN_FILES": str(lim["max_files"]),
        "MAX_SCAN_BYTES": str(lim["max_bytes"]),
        "MAX_SCAN_FILE_BYTES": str(lim["max_file_bytes"]),
        "SCAN_TIME_BUDGET_SECONDS": str(lim["time_budget"]),
        "SCAN_WORKER_CPU_SECONDS": str(lim["worker_cpu"]),
    }
