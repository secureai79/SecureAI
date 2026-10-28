import os
import re

INCLUDE_EXTENSIONS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".yaml", ".yml",
}
INCLUDE_NAMES = {
    ".env.example", "requirements.txt", "pyproject.toml", "package.json", "Dockerfile",
}
IGNORE_DIRS = {
    "node_modules", ".git", "venv", ".venv", "dist", "build", "coverage", "__pycache__",
}
MAX_FILE_BYTES = 2_000_000  # default for a single file; override with MAX_SCAN_FILE_BYTES (see app/limits.py)

# Generated / vendored files: never worth analysing even when small enough.
SKIP_SUFFIXES = (".min.js", ".min.css", ".bundle.js", ".map")
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "composer.lock"}

# Paths that most likely hold the AI/agent behaviour: scanned first when a limit forces a choice.
_HINT_PARTS = ("agent", "llm", "ai", "tool", "mcp", "chain", "prompt", "model", "assistant", "bot", "chat", "rag")


def max_file_bytes() -> int:
    try:
        return int(os.environ.get("MAX_SCAN_FILE_BYTES", "").strip() or MAX_FILE_BYTES)
    except ValueError:
        return MAX_FILE_BYTES


def priority(rel_path: str) -> int:
    """0 = likely AI/agent runtime code, 1 = other runtime code, 2 = tests/docs/examples/scripts."""
    low = rel_path.lower()
    if is_non_runtime_path(low):
        return 2
    segments = re.split(r"[/_.\-]", low)
    return 0 if any(h in segments for h in _HINT_PARTS) else 1

# Paths that are almost never real agent runtime capabilities: test suites,
# CI/build tooling, docs, examples, fixtures. A `subprocess.run(...)` inside
# `tests/test_cli.py` spawning a test server is not an AI agent capability —
# real-repo validation (see VALIDATION_REPORT.md) showed this was a major
# noise source. Findings here still get reported (so nothing is silently
# hidden) but are excluded from the Safety Score and severity-capped — see
# risk_engine.py.
NON_RUNTIME_PATH_PATTERNS = [
    re.compile(r"(^|/)tests?(/|$)"),
    re.compile(r"(^|/)test_[^/]+\.py$"),
    re.compile(r"(^|/)[^/]+_test\.py$"),
    re.compile(r"(^|/)__tests__(/|$)"),          # common JS/TS test dir convention
    re.compile(r"\.(test|spec)\.[jt]sx?$"),        # foo.test.ts, foo.spec.tsx
    re.compile(r"(^|/)scripts?(/|$)"),
    re.compile(r"(^|/)docs?(/|$)"),
    re.compile(r"(^|/)examples?(/|$)"),
    re.compile(r"(^|/)fixtures?(/|$)"),
    re.compile(r"(^|/)mocks?(/|$)"),
    re.compile(r"(^|/)benchmarks?(/|$)"),
    re.compile(r"(^|/)samples?(/|$)"),
    re.compile(r"(^|/)demos?(/|$)"),
    re.compile(r"(^|/)demo[_-][^/]+(/|$)"),
    re.compile(r"(^|/)(testdata|test_data|e2e|cypress)(/|$)"),
    re.compile(r"(^|/)[^/]*[._-](backup|bak|orig)[^/]*$"),    # editor/backup leftovers, e.g. foo.84pass.backup.py
    # Deliberately NOT excluding a bare "tools/" directory: in agent
    # frameworks that's frequently where the agent's actual callable
    # capabilities live (e.g. agency-swarm's tools/built_in/PersistentShellTool.py
    # is a real, important finding, not build tooling) — validated by hand
    # against real repos rather than assumed.
]


def is_non_runtime_path(file_path: str) -> bool:
    """True if this path looks like test/tooling/docs/examples code rather
    than something that runs as part of the actual agent at runtime."""
    normalized = file_path.replace("\\", "/")
    return any(p.search(normalized) for p in NON_RUNTIME_PATH_PATTERNS)


def select_files(root: str) -> list[str]:
    """Walk the repo root and return a list of relative paths worth scanning."""
    return select_files_ex(root)[0]


def select_files_ex(root: str, file_limit: int | None = None) -> tuple[list[str], list[str]]:
    """Like select_files, but also returns the files skipped for being larger than the per-file limit.

    Returns (selected, skipped_large). Nothing is dropped silently: callers report skipped files.
    """
    limit = file_limit if file_limit is not None else max_file_bytes()
    skipped_large: list[str] = []
    selected = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            _, ext = os.path.splitext(fname)
            if fname in SKIP_NAMES or fname.endswith(SKIP_SUFFIXES):
                continue
            if ext in INCLUDE_EXTENSIONS or fname in INCLUDE_NAMES:
                full = os.path.join(dirpath, fname)
                if os.path.islink(full):
                    continue
                try:
                    if os.path.getsize(full) > limit:
                        skipped_large.append(os.path.relpath(full, root).replace(os.sep, "/"))
                        continue
                except OSError:
                    continue
                # Always use forward slashes, regardless of OS. On Windows,
                # os.path.relpath returns backslash-separated paths
                # (e.g. "agents\refund_agent.py"), which breaks anything
                # downstream that assumes forward slashes -- path-based
                # regexes in is_non_runtime_path (already normalized
                # defensively below, but better to fix at the source),
                # capability_chain/evidence text, the PR-check script, and
                # tests that compare against literal "agents/foo.py" paths
                # (this was reported as a real StopIteration test failure
                # on Windows). Store paths the way git/GitHub always shows
                # them: forward slashes, cross-platform, no OS-dependent
                # branching needed anywhere else in the codebase.
                rel_path = os.path.relpath(full, root).replace(os.sep, "/")
                selected.append(rel_path)
    selected.sort(key=lambda r: (priority(r), r))   # most relevant first, deterministic
    return selected, skipped_large
