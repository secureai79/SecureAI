"""Pure repository analysis: directory in, JSON-serialisable result out.
This module is deliberately isolated. It imports only the static analyzers - never the
database, ORM models, crypto/key handling or the GitHub client - so the sandbox worker that
runs it holds no credentials and cannot reach application state, even if a parser bug is
exploited by a malicious repository. ``test_sandbox.py`` asserts that guarantee.
"""
import os
import time
import re
from types import SimpleNamespace
from . import (agent_frameworks, capability_extractor, file_selector, injection_analyzer, mcp_analyzer, risk_engine,
               security_analyzer)
from .language_registry import analyzer_for
RESULT_VERSION = 1
_OPENAI_AGENTS_IMPORT = re.compile(r"^\s*from\s+agents\s+import\b", re.MULTILINE)
def _is_openai_agents_sdk(text: str) -> bool:
    """`agents` is also a common local package name, so require SDK-specific usage as well."""
    return bool(_OPENAI_AGENTS_IMPORT.search(text)) and ("Runner.run" in text or "function_tool" in text)
def _safe_file_path(root: str, rel_path: str) -> str:
    """Resolve a scan file without following a symlink outside the clone."""
    full = os.path.abspath(os.path.join(root, rel_path))
    root_abs = os.path.abspath(root)
    if os.path.commonpath([root_abs, full]) != root_abs:
        raise ValueError("Unsafe repository path")
    current = full
    while current != root_abs:
        try:
            if os.path.islink(current):
                raise ValueError("Symlinked repository files are not scanned")
        except OSError:
            raise ValueError("Repository file could not be inspected")
        current = os.path.dirname(current)
    return full
def _scan_debug(message: str) -> None:
    """Scan-stage timing diagnostic. Off unless SCAN_DEBUG_LOG=true because it
    records customer repository file paths to disk."""
    if os.environ.get("SCAN_DEBUG_LOG", "false").lower() not in {"1", "true", "yes", "on"}:
        return
    try:
        with open("/tmp/ai-safety-scan-debug.log", "a", encoding="utf-8") as fh:
            fh.write(f"{time.monotonic():.3f} {message}\n")
    except OSError:
        pass
def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
def analyze_directory(root: str) -> dict:
    """Run every static-analysis stage over ``root`` and return plain data.
    Raises ValueError for expected, customer-facing limit violations (too many files,
    repository too large); any other exception means a bug or a hostile input.
    """
    # Stage 1: file selection. Big repositories are scanned as far as the limits allow (most relevant
    # files first) and the result records exactly what was left out; only an absurdly large repository
    # (more than 20x the file limit) is refused outright.
    started = time.monotonic()
    budget = _env_float("SCAN_TIME_BUDGET_SECONDS", 540.0)
    files, skipped_large = file_selector.select_files_ex(root)
    found = len(files)
    max_files = int(os.environ.get("MAX_SCAN_FILES", "20000"))
    max_bytes = int(os.environ.get("MAX_SCAN_BYTES", str(200 * 1024 * 1024)))
    if found > max_files * 20:
        raise ValueError(f"Repository contains too many scannable files ({found} > {max_files * 20}).")
    unscanned_examples: list[str] = list(skipped_large[:10])
    over_limit = 0
    if found > max_files:
        over_limit += found - max_files
        unscanned_examples += files[max_files:max_files + 10]
        files = files[:max_files]
    total_bytes = 0
    bounded_files = []
    for rel_path in files:
        full = _safe_file_path(root, rel_path)
        try:
            size = os.path.getsize(full)
        except OSError:
            continue
        if total_bytes + size > max_bytes:
            over_limit += 1
            if len(unscanned_examples) < 20:
                unscanned_examples.append(rel_path)
            continue
        total_bytes += size
        bounded_files.append(rel_path)
    files = bounded_files
    _scan_debug(f"STAGE file_selection_complete files={len(files)} bytes={total_bytes}")
    # Stage 2 + 3: static analysis + capability extraction
    analyses = []
    repo_has_ai = False
    mcp_candidates: list[tuple[str, str, str]] = []     # MCP configs / servers
    framework_candidates: list[tuple[str, str]] = []     # agent frameworks with code-execution switches
    extra_ai_files = []                                  # AI files the library table does not recognise
    processed: list[str] = []
    time_limited = False
    for rel_path in files:
        if time.monotonic() - started > budget:
            time_limited = True
            break
        processed.append(rel_path)
        _scan_debug(f"FILE_START {rel_path}")
        full = _safe_file_path(root, rel_path)
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            _scan_debug(f"FILE_READ_FAILED {rel_path}")
            continue
        _scan_debug(f"FILE_READ_COMPLETE {rel_path} bytes={len(text)}")
        kind = mcp_analyzer.wants_file(rel_path, text)
        if kind:
            mcp_candidates.append((rel_path, text, kind))
        if rel_path.endswith(".py") and any(h in text for h in agent_frameworks.HINTS):
            framework_candidates.append((rel_path, text))
        language_analyzer = analyzer_for(rel_path)
        if language_analyzer is not None:
            _scan_debug(
                f"ANALYZER_START {rel_path} analyzer={type(language_analyzer).__name__}"
            )
            language_result = language_analyzer.analyze(rel_path, text)
            _scan_debug(
                f"ANALYZER_COMPLETE {rel_path} analyzer={type(language_analyzer).__name__}"
            )
            analysis = language_result.file_analysis
        else:
            _scan_debug(f"CAPABILITY_START {rel_path}")
            analysis = capability_extractor.analyze_file(rel_path, text)
            _scan_debug(f"CAPABILITY_COMPLETE {rel_path}")
        if analysis is None:
            _scan_debug(f"ANALYSIS_NONE {rel_path}")
            continue
        if analysis.has_ai:
            repo_has_ai = True
        if analysis.has_ai or analysis.dangerous_calls:
            analyses.append(analysis)
        if rel_path.endswith(".py") and not analysis.has_ai and _is_openai_agents_sdk(text):
            extra_ai_files.append(SimpleNamespace(file_path=rel_path, raw_text=text, has_ai=True,
                                                  ai_providers=["OpenAI Agents SDK"], used_ast=True))
            repo_has_ai = True
        _scan_debug(f"FILE_COMPLETE {rel_path}")
    if time_limited:
        unscanned_examples += [f for f in files[len(processed):len(processed) + 10]][: max(0, 20 - len(unscanned_examples))]
    files = processed
    _scan_debug(f"STAGE static_analysis_complete analyses={len(analyses)} repo_has_ai={repo_has_ai}")
    # One "agent" per file that imports an AI SDK (persisted by the caller).
    agents = [
        {
            "file_path": analysis.file_path,
            "framework": capability_extractor.infer_framework(analysis.raw_text),
            "model_provider": analysis.ai_providers[0],
        }
        for analysis in analyses
        if analysis.has_ai
    ]
    # Stage 4: AI capability risk findings (raw, deterministic)
    raw_findings = []
    for analysis in analyses:
        raw_findings.extend(risk_engine.build_findings_for_file(analysis, repo_has_ai))
    # Stage 4b: application-security checks. These run on runtime files,
    # including repositories with no AI, and remain deterministic.
    security_findings = []
    for rel_path in files:
        if file_selector.is_non_runtime_path(rel_path):
            continue
        if time.monotonic() - started > budget:
            time_limited = True
            break
        full = _safe_file_path(root, rel_path)
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        security_findings.extend(security_analyzer.analyze_security(rel_path, text))
    _scan_debug(f"STAGE security_analysis_complete findings={len(security_findings)}")
    # Stage 4c: deterministic AI-safety findings that are never sent to the LLM refiner:
    #   - prompt-injection reachability (untrusted content -> model -> tools)
    #   - MCP configuration + server analysis
    #   - framework switches that run model-written code on the host
    # (Reported under the "injection_findings" key of the worker protocol.)
    # An analyzer bug must never fail the whole scan, so each stage is isolated.
    injection_findings: list[dict] = []
    for stage, run in (
        ("injection", lambda: injection_analyzer.analyze_analyses(analyses + extra_ai_files, risk_engine._apply_scoring_gate)),
        ("mcp", lambda: mcp_analyzer.analyze_candidates(mcp_candidates, risk_engine._apply_scoring_gate)),
        ("frameworks", lambda: agent_frameworks.analyze_files(framework_candidates, risk_engine._apply_scoring_gate)),
    ):
        try:
            injection_findings.extend(run())
        except Exception:
            _scan_debug(f"STAGE {stage}_analysis_failed")
    _scan_debug(f"STAGE injection_analysis_complete findings={len(injection_findings)}")
    return {
        "version": RESULT_VERSION,
        "agents": agents,
        "ai_findings": raw_findings,
        "injection_findings": injection_findings,
        "security_findings": security_findings,
        "stats": {
            "files": len(files), "bytes": total_bytes, "repo_has_ai": repo_has_ai,
            # Coverage: lets the report say honestly what was and was not analysed.
            "files_total": found + len(skipped_large),
            "skipped_large": len(skipped_large),
            "skipped_over_limit": over_limit,
            "time_limited": time_limited,
            "unscanned_examples": unscanned_examples[:20],
        },
    }
