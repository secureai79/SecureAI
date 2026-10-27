from __future__ import annotations

import atexit
import json
import os
import queue
import subprocess
import threading
from dataclasses import asdict
from pathlib import Path


from ...capability_extractor import FileAnalysis
from ...ast_detector import RawFinding
from ..base import LanguageAnalyzer, LanguageAnalysis

_BRIDGE = Path(__file__).with_name("ts_ast_bridge.js")
# Cheap pre-filter: only invoke the expensive TypeScript AST bridge when
# the file contains patterns relevant to AI capability or dangerous actions.
# Files that do not match fall back to the lightweight existing extractor.
_AST_RELEVANCE_RE = __import__("re").compile(
    r"""
    # AI SDK/package usage
    (?:from|import)\s+['"]?(?:openai|anthropic|autogen|langchain|crewai|llamaindex|llama_index|mcp)\b
    |(?:require|import)\s*\(\s*['"](?:openai|anthropic|autogen|langchain|crewai|llamaindex|llama_index|mcp)

    # AI constructors / model APIs
    \b(?:OpenAI|AsyncOpenAI|Anthropic|AsyncAnthropic|GoogleGenerativeAI|GenerativeModel)\s*\(
    |\b(?:ChatOpenAI|ChatAnthropic|createChatCompletion|generateContent|GenerativeModel)\s*\(

    # AI endpoint/provider references
    \b(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com)\b

    # Direct dangerous operations
    |stripe\s*\.\s*(?:refund|charge)\s*\(
    |\.\s*(?:execute|exec|execSync|spawn|spawnSync|Popen|check_output|system)\s*\(
    |\.\s*(?:transfer|payout)\s*\(
    |\.\s*(?:send|sendmail|sendEmail|sendMessage)\s*\(
    | \b(?:boto3|ec2|ecs|eks|cloudformation|kubernetes|k8s|docker|terraform|helm)\w*
  \s*\.\s*(?:deploy|terminate|terminateInstances|terminate_instances)\s*\(
| \b(?:git|gitClient|simpleGit|octokit)\s*\.\s*(?:push|merge)\s*\(
    """,
    __import__("re").IGNORECASE | __import__("re").VERBOSE,
)

def _node_command() -> str:
    return os.environ.get("AI_SAFETY_NODE_BIN", "node")


_AST_WORKER = None
_AST_WORKER_LOCK = threading.Lock()


class _AstWorker:
    def __init__(self):
        self.proc = subprocess.Popen(
            [_node_command(), str(_BRIDGE)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=os.environ.copy(),
        )
        self._stderr_lines = queue.Queue()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            daemon=True,
        )
        self._stderr_thread.start()

    def _drain_stderr(self):
        if self.proc.stderr is None:
            return
        for line in self.proc.stderr:
            self._stderr_lines.put(line.rstrip())

    def request(self, file_path: str, text: str, timeout: float) -> dict:
        if self.proc.poll() is not None:
            raise RuntimeError("JavaScript/TypeScript AST bridge worker exited")

        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("JavaScript/TypeScript AST bridge worker pipes unavailable")

        payload = json.dumps({
            "filePath": file_path,
            "text": text,
        })

        self.proc.stdin.write(payload + "\n")
        self.proc.stdin.flush()

        result_queue = queue.Queue(maxsize=1)

        def read_result():
            try:
                line = self.proc.stdout.readline()
                result_queue.put(("ok", line))
            except Exception as exc:
                result_queue.put(("error", exc))

        reader = threading.Thread(target=read_result, daemon=True)
        reader.start()

        try:
            status, result = result_queue.get(timeout=timeout)
        except queue.Empty:
            self.close()
            raise subprocess.TimeoutExpired(
                [_node_command(), str(_BRIDGE)],
                timeout,
            )

        if status == "error":
            self.close()
            raise result

        if not result:
            stderr = []
            while not self._stderr_lines.empty():
                stderr.append(self._stderr_lines.get_nowait())
            self.close()
            raise RuntimeError(
                "\n".join(stderr) or
                "JavaScript/TypeScript AST bridge worker exited"
            )

        response = json.loads(result)

        if "error" in response:
            raise RuntimeError(response["error"])

        return response

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()

        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _get_ast_worker() -> _AstWorker:
    global _AST_WORKER

    with _AST_WORKER_LOCK:
        if _AST_WORKER is None:
            _AST_WORKER = _AstWorker()
        elif _AST_WORKER.proc.poll() is not None:
            _AST_WORKER = _AstWorker()

        return _AST_WORKER


def _run_bridge(file_path: str, text: str) -> dict:
    timeout = float(os.environ.get("JS_AST_TIMEOUT_SECONDS", "8"))

    worker = _get_ast_worker()

    try:
        return worker.request(file_path, text, timeout)
    except Exception:
        global _AST_WORKER
        with _AST_WORKER_LOCK:
            if _AST_WORKER is worker:
                worker.close()
                _AST_WORKER = None
        raise


def _shutdown_ast_worker():
    global _AST_WORKER

    with _AST_WORKER_LOCK:
        if _AST_WORKER is not None:
            _AST_WORKER.close()
            _AST_WORKER = None


atexit.register(_shutdown_ast_worker)


class JavaScriptAnalyzer(LanguageAnalyzer):
    """AST-backed JavaScript/TypeScript analyzer.

    Uses the TypeScript compiler API through a small Node bridge. The analyzer
    produces the same RawFinding shape consumed by the existing risk engine,
    including local taint propagation and one-hop/fixed-point function
    parameter propagation. If the parser/runtime is unavailable, it fails
    closed rather than silently turning regex findings into scored findings.
    """
    language = "javascript"
    extensions = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

    def analyze(self, file_path: str, text: str) -> LanguageAnalysis:
    # Most JS/TS files do not contain AI or dangerous-action patterns.
    # Avoid starting a Node + TypeScript compiler process for those files.
        if not _AST_RELEVANCE_RE.search(text):
            from ...capability_extractor import analyze_file

            fallback = analyze_file(file_path, text)
            return LanguageAnalysis(
                self.language,
                False,
                file_path,
                [],
                fallback,
            )

        try:
            result = _run_bridge(file_path, text)
        except Exception:
            # Preserve the existing safe behavior: unavailable AST support is
            # represented as unsupported, so the caller can retain unscored
            # fallback findings if desired rather than claiming deep analysis.
            from ...capability_extractor import analyze_file
            fallback = analyze_file(file_path, text)
            return LanguageAnalysis(self.language, False, file_path, [], fallback)

        findings = []
        for f in result.get("findings", []):
            findings.append(RawFinding(
                category=f["category"],
                operation=f["operation"],
                chain=f["chain"],
                line=int(f["line"]),
                ai_controlled=bool(f["ai_controlled"]),
                control_confidence=float(f["control_confidence"]),
                approval_detected=bool(f["approval_detected"]),
                limit_detected=bool(f["limit_detected"]),
                capability_chain=list(f["capability_chain"]),
                snippet_line=f.get("snippet_line", ""),
                function_name=f.get("function_name", "module"),
            ))

        analysis = FileAnalysis(
            file_path=file_path,
            ai_providers=list(result.get("ai_providers", [])),
            dangerous_libraries=[],
            dangerous_calls=[],
            ast_findings=findings,
            used_ast=bool(result.get("supported")),
            raw_text=text,
        )
        return LanguageAnalysis(self.language, bool(result.get("supported")), file_path, [], analysis)