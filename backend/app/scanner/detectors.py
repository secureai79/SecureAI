import re

# --- Signal dictionaries (deliberately simple + auditable) -----------------

AI_LIBRARIES = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "google.generativeai": "Gemini",
    "google-generativeai": "Gemini",
    "langchain": "LangChain",
    "crewai": "CrewAI",
    "mcp": "MCP",
    "autogen": "AutoGen",
    "llama_index": "LlamaIndex",
    "langgraph": "LangGraph",
    "pydantic_ai": "PydanticAI",
    "smolagents": "smolagents",
    "semantic_kernel": "Semantic Kernel",
    "haystack": "Haystack",
    "dspy": "DSPy",
    "google.genai": "Gemini",
    "google.adk": "Google ADK",
    "vertexai": "Vertex AI",
    "mistralai": "Mistral",
    "cohere": "Cohere",
    "groq": "Groq",
    "ollama": "Ollama",
    "litellm": "LiteLLM",
    "agno": "Agno",
    "fastmcp": "MCP",
}

AI_HTTP_ENDPOINTS = {
    "api.groq.com": "Groq",
    "api.openai.com": "OpenAI",
    "api.anthropic.com": "Anthropic",
    "generativelanguage.googleapis.com": "Gemini",
    "generativelanguage.googleapis.com/v1beta": "Gemini",
}

DANGEROUS_LIBRARIES = {
    "stripe": "payments",
    "boto3": "cloud",
    "subprocess": "shell",
    "os.system": "shell",
    "smtplib": "email",
    "sendgrid": "email",
    "psycopg": "database",
    "psycopg2": "database",
    "sqlalchemy": "database",
    "pymongo": "database",
    "twilio": "sms",
    "github": "code",
    "pygithub": "code",
    "paramiko": "shell",
    "requests": "network",
}

# operation -> (category, human label)
DANGEROUS_FUNCTIONS = {
    "delete":   ("DATA", "delete"),
    "drop":     ("DATA", "drop"),
    "truncate": ("DATA", "truncate"),
    "export":   ("DATA", "export"),
    "refund":   ("FINANCIAL", "refund"),
    "charge":   ("FINANCIAL", "charge"),
    "transfer": ("FINANCIAL", "transfer"),
    "payout":   ("FINANCIAL", "payout"),
    "execute":  ("INFRASTRUCTURE", "execute"),
    "system":   ("INFRASTRUCTURE", "shell execution"),
    "deploy":   ("INFRASTRUCTURE", "deploy"),
    "terminate":("INFRASTRUCTURE", "terminate"),
    "send":     ("COMMUNICATION", "send"),
    "merge":    ("CODE", "merge"),
    "push":     ("CODE", "push"),
    "remove":   ("DATA", "remove"),
    "update":   ("DATA", "update"),
}

# Phrases that suggest a human-in-the-loop / limit guardrail is present nearby.
APPROVAL_HINTS = re.compile(
    r"(require[_\s]?approval|human[_\s]?approval|needs?_approval|manual[_\s]?review|"
    r"confirm(ation)?[_\s]?required|approved_by|pending_approval)",
    re.IGNORECASE,
)
LIMIT_HINTS = re.compile(
    r"(max_amount|max_refund|refund_limit|amount_limit|\blimit\b|\bthreshold\b|"
    r"amount\s*[<>]=?\s*\d)",
    re.IGNORECASE,
)

IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))", re.MULTILINE
)
JS_IMPORT_RE = re.compile(
    r"""(?:require\(\s*['"]([\w\-\./@]+)['"]\s*\)|from\s+['"]([\w\-\./@]+)['"])"""
)

FUNC_CALL_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
DEF_NAME_RE = re.compile(r"\b(?:def|function|const|async function)\s+([a-zA-Z_][a-zA-Z0-9_]*)")
SQL_KEYWORD_RE = re.compile(r"\b(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE)\b", re.IGNORECASE)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1

def detect_ai_http_endpoints(text: str) -> list[dict]:
    """Detect known AI providers accessed directly over HTTP.

    This is intentionally limited to known provider endpoints so ordinary
    HTTP/network usage is not classified as AI merely because it uses
    requests/fetch/axios.
    """
    found = []
    seen = set()

    for endpoint, provider in AI_HTTP_ENDPOINTS.items():
        pattern = re.compile(re.escape(endpoint), re.IGNORECASE)

        for match in pattern.finditer(text):
            line = _line_of(text, match.start())
            key = (provider, line)

            if key in seen:
                continue

            seen.add(key)
            found.append({
                "name": provider,
                "raw": endpoint,
                "line": line,
                "kind": "ai_http_endpoint",
            })

    return found

def detect_imports(text: str) -> list[dict]:
    """Return list of {name, line, kind} for AI + dangerous library imports."""
    found = []
    for m in IMPORT_RE.finditer(text):
        mod = m.group(1) or m.group(2)
        if not mod:
            continue
        top = mod.split(".")[0]
        line = _line_of(text, m.start())
        for lib, label in AI_LIBRARIES.items():
            # Dotted entries (google.generativeai) must match as a module path. The old
            # `top == lib.split(".")[0]` test treated ANY `google.*` import (protobuf, cloud
            # storage...) as Gemini.
            if "." in lib:
                hit = mod == lib or mod.startswith(lib + ".")
            else:
                hit = mod.startswith(lib) or top == lib
            if hit:
                found.append({"name": label, "raw": mod, "line": line, "kind": "ai_library"})
        for lib, category in DANGEROUS_LIBRARIES.items():
            if mod == lib or top == lib.split(".")[0] or mod.startswith(lib):
                found.append({"name": lib, "raw": mod, "line": line, "kind": "dangerous_library",
                              "category": category})
    for m in JS_IMPORT_RE.finditer(text):
        mod = m.group(1) or m.group(2)
        if not mod:
            continue
        line = _line_of(text, m.start())
        for lib, label in AI_LIBRARIES.items():
            if mod == lib or mod.startswith(lib + "/"):
                found.append({"name": label, "raw": mod, "line": line, "kind": "ai_library"})
        for lib, category in DANGEROUS_LIBRARIES.items():
            if mod == lib or mod.startswith(lib + "/"):
                found.append({"name": lib, "raw": mod, "line": line, "kind": "dangerous_library",
                              "category": category})
    return found


def detect_dangerous_functions(text: str) -> list[dict]:
    """Scan function/call names and raw SQL for potentially dangerous operations."""
    found = []
    seen = set()

    # Function/method calls.
    #
    # For dotted calls such as:
    #   stripe.refund(...)
    #   os.remove(...)
    #   db.execute(...)
    #
    # capture the object and method separately so we can use context.
    call_re = re.compile(
        r"\b(?:(?P<object>[a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*)?"
        r"(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)\s*\("
    )

    for m in call_re.finditer(text):
        name = m.group("name")
        obj = (m.group("object") or "").lower()
        lname = name.lower()

        for keyword, (category, label) in DANGEROUS_FUNCTIONS.items():
            exact_match = lname == keyword
            custom_capability_name = (
                lname.startswith(keyword)
                and len(lname) > len(keyword)
                and name[len(keyword)].isupper()
            )
            # Common frontend/API methods that should not inherit a dangerous
            # capability merely because their name starts with a dangerous keyword.
            NON_DANGEROUS_METHODS = {
                "removeitem",
                "removeeventlistener",
                "sendmessage",
            }

            if lname in NON_DANGEROUS_METHODS:
                continue

            if not exact_match and not custom_capability_name:
                continue

            # Ignore common frontend collection/UI operations that happen
            # to use security-sensitive English words.
                        # Ignore common frontend collection/UI operations that happen
            # to use security-sensitive English words.
            if keyword == "remove" and exact_match:
                if obj in {
                    "",
                    "array",
                    "arrays",
                    "list",
                    "items",
                    "history",
                    "state",
                    "set",
                }:
                    continue

                # Browser/DOM cleanup is not destructive data deletion.
                if obj in {
                    "window",
                    "document",
                    "element",
                    "node",
                    "anchor",
                    "link",
                    "listener",
                    "a",
                }:
                    continue

            # Array/list push is not a repository/code push.
            if keyword == "push" and exact_match:
                if obj in {
                    "",
                    "array",
                    "arrays",
                    "list",
                    "items",
                    "parts",
                    "messages",
                    "history",
                    "state",
                }:
                    continue

            # Generic application messaging is not automatically
            # outbound communication.
            if keyword == "send" and exact_match:
                if obj in {
                    "",
                    "message",
                    "messages",
                    "chat",
                    "agent",
                    "client",
                }:
                    continue

            if keyword == "drop" and obj in {
                "",
                "event",
                "drag",
                "dragdata",
                "dataTransfer".lower(),
            }:
                continue

            line = _line_of(text, m.start())
            key = (keyword, line, obj)

            if key in seen:
                continue

            seen.add(key)

            found.append({
                "keyword": keyword,
                "category": category,
                "label": label,
                "line": line,
                "matched_name": name,
                "object": obj or None,
            })

    # Function definitions.
    for m in DEF_NAME_RE.finditer(text):
        name = m.group(1)
        lname = name.lower()

        for keyword, (category, label) in DANGEROUS_FUNCTIONS.items():
            # Exact name only. Do not classify handleDrop as DROP.
            if lname != keyword:
                continue

            line = _line_of(text, m.start())
            key = ("def", keyword, line)

            if key in seen:
                continue

            seen.add(key)

            found.append({
                "keyword": keyword,
                "category": category,
                "label": label,
                "line": line,
                "matched_name": name,
                "object": None,
            })

    # Explicit raw SQL remains useful because this is much stronger
    # evidence than an arbitrary JavaScript function name.
    for m in SQL_KEYWORD_RE.finditer(text):
        kw = m.group(1).split()[0].lower()
        category, label = DANGEROUS_FUNCTIONS.get(
            kw,
            ("DATA", kw),
        )

        line = _line_of(text, m.start())

        found.append({
            "keyword": kw,
            "category": category,
            "label": f"raw SQL {label.upper()}",
            "line": line,
            "matched_name": m.group(0),
            "object": None,
        })

    return found


def nearby_has_approval_guard(text: str, line: int, window: int = 8) -> bool:
    lines = text.splitlines()
    lo = max(0, line - window)
    hi = min(len(lines), line + window)
    chunk = "\n".join(lines[lo:hi])
    return bool(APPROVAL_HINTS.search(chunk))


def nearby_has_limit_guard(text: str, line: int, window: int = 8) -> bool:
    lines = text.splitlines()
    lo = max(0, line - window)
    hi = min(len(lines), line + window)
    chunk = "\n".join(lines[lo:hi])
    return bool(LIMIT_HINTS.search(chunk))


def snippet_around(text: str, line: int, window: int = 8) -> str:
    lines = text.splitlines()
    lo = max(0, line - window)
    hi = min(len(lines), line + window)
    return "\n".join(lines[lo:hi])