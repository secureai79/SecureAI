from dataclasses import dataclass, field


from . import detectors, ast_detector


@dataclass
class FileAnalysis:
    file_path: str
    ai_providers: list[str] = field(default_factory=list)
    dangerous_libraries: list[dict] = field(default_factory=list)
    dangerous_calls: list[dict] = field(default_factory=list)
    ast_findings: list[ast_detector.RawFinding] = field(default_factory=list)
    used_ast: bool = False
    raw_text: str = ""

    @property
    def has_ai(self) -> bool:
        return len(self.ai_providers) > 0


def analyze_file(file_path: str, text: str) -> FileAnalysis:
    is_python = file_path.endswith(".py")

    if is_python:
        ast_result = ast_detector.analyze_python_ast(file_path, text)

        if ast_result.parse_ok:
            # Run the lightweight detector as well so HTTP-based AI
            # providers are detected even when the Python AST pass succeeds.
            imports = detectors.detect_imports(text)
            ai_http = detectors.detect_ai_http_endpoints(text)

            dangerous_libraries = [
                i for i in imports
                if i["kind"] == "dangerous_library"
            ]

            ai_providers = sorted(
                set(ast_result.ai_providers)
                | {i["name"] for i in ai_http}
            )

            return FileAnalysis(
                file_path=file_path,
                ai_providers=ai_providers,
                dangerous_libraries=dangerous_libraries,
                dangerous_calls=[],
                ast_findings=ast_result.findings,
                used_ast=True,
                raw_text=text,
            )

        # Syntax error (e.g. a template file with `.py` extension that isn't
        # valid Python) — fall through to the regex path below.

    # Regex/keyword fallback: non-Python files, or Python that failed to parse.
    imports = detectors.detect_imports(text)
    ai_http = detectors.detect_ai_http_endpoints(text)

    dangerous_libraries = [
        i for i in imports
        if i["kind"] == "dangerous_library"
    ]

    ai_providers = sorted(
        {i["name"] for i in imports if i["kind"] == "ai_library"}
        | {i["name"] for i in ai_http}
    )

    dangerous_calls = detectors.detect_dangerous_functions(text)

    return FileAnalysis(
        file_path=file_path,
        ai_providers=ai_providers,
        dangerous_libraries=dangerous_libraries,
        dangerous_calls=dangerous_calls,
        ast_findings=[],
        used_ast=False,
        raw_text=text,
    )

    # Regex/keyword fallback: non-Python files, or Python that failed to parse.
    imports = detectors.detect_imports(text)
    ai_http = detectors.detect_ai_http_endpoints(text)

    dangerous_libraries = [
    i for i in imports
    if i["kind"] == "dangerous_library"
    ]

    ai_providers = sorted(
    set(ast_result.ai_providers)
    | {i["name"] for i in ai_http}
    )

    return FileAnalysis(
        file_path=file_path,
        ai_providers=ai_providers,
        dangerous_libraries=dangerous_libraries,
        dangerous_calls=dangerous_calls,
        ast_findings=[],
        used_ast=False,
        raw_text=text,
    )


def infer_framework(text: str) -> str | None:
    lowered = text.lower()
    for fw in ("langchain", "crewai", "autogen", "llama_index", "mcp"):
        if fw in lowered:
            return fw
    return None