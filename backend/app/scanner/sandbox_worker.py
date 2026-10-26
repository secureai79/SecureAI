"""Secret-free analysis worker.

Usage: python -m app.scanner.sandbox_worker REPO_DIR OUT_JSON

It receives a directory that the (trusted) parent already cloned, runs the static
analyzers from ``pipeline`` and writes plain JSON. It never sees DATABASE_URL, GitHub
tokens, encryption keys or the ORM: the parent builds its environment from an allow-list
(see ``scan_service._sandbox_env``) and ``pipeline`` imports none of those modules.

Defence in depth applied here: CPU/memory/file-size rlimits and, when the kernel permits
it, a fresh network namespace (``SANDBOX_NO_NETWORK=true``) so even a compromised parser
cannot call out. Network isolation is best-effort and reported in the result.
"""
import json
import os
import sys


def _apply_limits() -> None:
    try:
        import resource

        cpu = int(os.environ.get("SCAN_WORKER_CPU_SECONDS", "700"))
        memory_mb = int(os.environ.get("SCAN_WORKER_MEMORY_MB", "1536"))
        disk_mb = int(os.environ.get("SCAN_WORKER_FILE_MB", "256"))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024, memory_mb * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (disk_mb * 1024 * 1024, disk_mb * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, AttributeError, ValueError, OSError):
        pass


def _isolate_network() -> bool:
    """Drop network access by entering new user+network namespaces (Linux, best effort)."""
    if os.environ.get("SANDBOX_NO_NETWORK", "false").lower() not in {"1", "true", "yes", "on"}:
        return False
    try:
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)  # type: ignore[attr-defined]
        return True
    except (AttributeError, OSError):
        return False


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: sandbox_worker REPO_DIR OUT_JSON", file=sys.stderr)
        return 2
    root, out_path = argv[1], argv[2]
    _apply_limits()
    isolated = _isolate_network()

    from .pipeline import analyze_directory

    try:
        result = analyze_directory(root)
        result["sandbox"] = {"network_isolated": isolated}
    except ValueError as exc:                    # expected limit violations only
        result = {"version": 1, "error": str(exc)[:300]}

    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(result, fh, default=str)
    os.replace(tmp, out_path)                    # atomic: parent never reads a partial file
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))