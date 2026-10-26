"""Validation of the sandbox worker's output.

The worker processes attacker-controlled repositories, so its output is attacker-influenced
data. The parent therefore accepts ONLY plain JSON (never pickle/eval/exec), enforces size
and shape limits, and rebuilds findings from a strict schema before anything touches the
database. Anything unexpected raises ``WorkerOutputError`` and the scan fails safely.
"""
import os

RESULT_VERSION = 1
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
MAX_STR = 5000
MAX_PATH = 500
MAX_LIST = 200
MAX_DEPTH = 5
MAX_ITEMS_PER_LIST = 5000


class WorkerOutputError(ValueError):
    pass


def max_output_bytes() -> int:
    try:
        return int(os.environ.get("MAX_WORKER_OUTPUT_BYTES", str(20 * 1024 * 1024)))
    except ValueError:
        return 20 * 1024 * 1024


def _safe_relpath(value, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_PATH or "\x00" in value:
        raise WorkerOutputError(f"invalid {field}")
    norm = value.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":") or ".." in norm.split("/"):
        raise WorkerOutputError(f"unsafe {field}")
    return value


def _check_json(value, depth: int = 0):
    """Allow only bounded JSON primitives/containers."""
    if depth > MAX_DEPTH:
        raise WorkerOutputError("value nested too deeply")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) > MAX_STR:
            return value[:MAX_STR]
        return value
    if isinstance(value, list):
        if len(value) > MAX_LIST:
            raise WorkerOutputError("list too long")
        return [_check_json(v, depth + 1) for v in value]
    if isinstance(value, dict):
        if len(value) > 60:
            raise WorkerOutputError("object too large")
        out = {}
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > 100:
                raise WorkerOutputError("invalid key")
            out[k] = _check_json(v, depth + 1)
        return out
    raise WorkerOutputError("non-JSON value")


def _str(d: dict, key: str, limit: int, required: bool = True):
    v = d.get(key)
    if v is None:
        if required:
            raise WorkerOutputError(f"missing {key}")
        return None
    if not isinstance(v, str) or len(v) > limit:
        raise WorkerOutputError(f"invalid {key}")
    return v


def validate_finding(f) -> dict:
    if not isinstance(f, dict):
        raise WorkerOutputError("finding is not an object")
    clean = _check_json(f)
    if clean.get("severity") not in SEVERITIES:
        raise WorkerOutputError("invalid severity")
    _str(clean, "title", 500)
    _str(clean, "category", 64)
    _str(clean, "capability", 128)
    _safe_relpath(clean.get("file_path"), "file_path")
    line = clean.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or not 0 <= line <= 10_000_000:
        raise WorkerOutputError("invalid line")
    conf = clean.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        raise WorkerOutputError("invalid confidence")
    for key in ("evidence", "capability_chain"):
        v = clean.get(key)
        if v is not None and (not isinstance(v, list) or any(not isinstance(x, str) for x in v)):
            raise WorkerOutputError(f"invalid {key}")
    if "scored" in clean and not isinstance(clean["scored"], bool):
        raise WorkerOutputError("invalid scored")
    pp = clean.get("potential_points")
    if pp is not None and (isinstance(pp, bool) or not isinstance(pp, int) or not 0 <= pp <= 100):
        raise WorkerOutputError("invalid potential_points")
    return clean


def validate_result(data) -> dict:
    """Return a sanitised result dict, or raise WorkerOutputError.

    A result of the form {"version": 1, "error": "<message>"} reports an expected
    limit violation (too many files, repository too large).
    """
    if not isinstance(data, dict) or data.get("version") != RESULT_VERSION:
        raise WorkerOutputError("unexpected result format")
    if "error" in data:
        msg = data["error"]
        if not isinstance(msg, str) or len(msg) > 300:
            raise WorkerOutputError("invalid error message")
        return {"version": RESULT_VERSION, "error": msg}

    out = {"version": RESULT_VERSION}
    agents = data.get("agents")
    if not isinstance(agents, list) or len(agents) > MAX_ITEMS_PER_LIST:
        raise WorkerOutputError("invalid agents")
    out["agents"] = []
    for a in agents:
        if not isinstance(a, dict):
            raise WorkerOutputError("invalid agent")
        fw = a.get("framework")
        if fw is not None and (not isinstance(fw, str) or len(fw) > 100):
            raise WorkerOutputError("invalid framework")
        out["agents"].append({
            "file_path": _safe_relpath(a.get("file_path"), "agent file_path"),
            "framework": fw,
            "model_provider": _str(a, "model_provider", 100),
        })
    total = 0
    for key in ("ai_findings", "injection_findings", "security_findings"):
        items = data.get(key)
        if not isinstance(items, list) or len(items) > MAX_ITEMS_PER_LIST:
            raise WorkerOutputError(f"invalid {key}")
        total += len(items)
        out[key] = [validate_finding(f) for f in items]
    if total > 2 * MAX_ITEMS_PER_LIST:
        raise WorkerOutputError("too many findings")
    stats = data.get("stats")
    out["stats"] = {
        "files": int(stats.get("files", 0)) if isinstance(stats, dict) and isinstance(stats.get("files", 0), int) else 0,
        "bytes": int(stats.get("bytes", 0)) if isinstance(stats, dict) and isinstance(stats.get("bytes", 0), int) else 0,
        "repo_has_ai": bool(stats.get("repo_has_ai")) if isinstance(stats, dict) else False,
    }
    if isinstance(stats, dict):
        def _count(key):
            v = stats.get(key, 0)
            return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 10_000_000 else 0
        out["stats"].update({
            "files_total": _count("files_total"),
            "skipped_large": _count("skipped_large"),
            "skipped_over_limit": _count("skipped_over_limit"),
            "time_limited": bool(stats.get("time_limited")),
            "unscanned_examples": [],
        })
        examples = stats.get("unscanned_examples")
        if isinstance(examples, list):
            for ex in examples[:20]:
                try:
                    out["stats"]["unscanned_examples"].append(_safe_relpath(ex, "unscanned example"))
                except WorkerOutputError:
                    continue
    return out