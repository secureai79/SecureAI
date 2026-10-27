from __future__ import annotations
import re

SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
SECRET_ASSIGNMENT = re.compile(r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']")
SENSITIVE_NAME = re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|customer[_-]?data|user[_-]?data|personal[_-]?data|pii|credit[_-]?card|ssn)\b")
NETWORK_SINK = re.compile(r"(?i)\b(?:requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.request|fetch\s*\(|axios(?:\.[A-Za-z]+)?\s*\(|got\s*\()")
AUTH_MARKERS = re.compile(r"(?i)(?:requireAuth|authenticate|isAuthenticated|authorize|authorization|current_user|Depends\s*\(\s*get_current_user|verifyToken|verifyJwt|checkPermission|requirePermission|requireRole|isAdmin|adminOnly|authMiddleware)")
SENSITIVE_PATH = re.compile(r"(?i)(?:^|/)(?:admin|user|users|account|accounts|payment|payments|refund|billing|transfer|delete|remove|credentials|secrets)(?:/|$)")
ROUTE_DECL = re.compile(r"(?i)(?:@(?:app|router)\.(?:post|put|patch|delete)|(?:app|router)\.(?:post|put|patch|delete))\s*\(")
SHELL_SINK = re.compile(r"(?i)\b(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_call|check_output)|child_process\.(?:exec|execSync|spawn|spawnSync))\b")
# Only treat calls that look like real database clients as SQL sinks. A generic
# `.query()` in a frontend component is not evidence of SQL injection.
SQL_SINK = re.compile(r"(?i)\b(?:db|database|conn|connection|cursor|session|engine|pool|sequelize|knex|prisma|client)\s*\.\s*(?:execute|executemany|query|raw|\$queryRaw|\$executeRaw)\s*\(")
SQL_TEXT = re.compile(r"(?i)\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b")
UNTRUSTED = re.compile(r"(?i)(?:req\.|request\.|params\b|query\b|body\b|user[_-]?input|input\(|form\b|message\b|prompt\b|model[_-]?output|ai[_-]?output|llm)")


def _line(text, n):
    lines = text.splitlines()
    return lines[n - 1].strip()[:500] if 0 < n <= len(lines) else ""


def _placeholder(v):
    v = v.lower()
    return any(x in v for x in ("example", "changeme", "replace", "your_", "your-", "dummy", "sample", "xxxx", "<secret>"))



def _f(title, severity, category, description, recommendation, path, line, confidence, evidence, capability, snippet):
    consequence_by_capability = {
        "exposed_secret": "Credential compromise and unauthorized access",
        "hardcoded_credential": "Credential compromise and unauthorized access",
        "data_exfiltration": "Potential exposure of sensitive or personal data",
        "unguarded_endpoint": "Unauthorized access to sensitive operations or resources",
        "sql_injection": "Potential unauthorized database access or data modification",
        "command_injection": "Potential unauthorized command execution",
    }

    impact_by_capability = {
        "exposed_secret": "CRITICAL",
        "hardcoded_credential": "HIGH",
        "data_exfiltration": "HIGH",
        "unguarded_endpoint": "HIGH",
        "sql_injection": "HIGH",
        "command_injection": "CRITICAL",
    }

    return dict(
        title=title,
        severity=severity,
        category=category,
        description=description,
        recommendation=recommendation,
        file_path=path,
        line=line,
        confidence=confidence,
        evidence=evidence,
        capability=capability,
        ai_controlled=None,
        control_confidence=None,
        capability_chain=None,
        snippet=snippet,
        scored=True,
        consequence=consequence_by_capability.get(
            capability, "Potential security impact requiring review"
        ),
        impact_level=impact_by_capability.get(capability, "MEDIUM"),
        control_status="UNKNOWN",
    )

def detect_secrets(path, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "/*", "<!--")):
            continue
        for name, pat in SECRET_PATTERNS:
            m = pat.search(line)
            if m and not _placeholder(m.group(0)):
                sev = "CRITICAL" if "Private key" in name or "secret key" in name.lower() else "HIGH"
                out.append(_f(f"Exposed {name}", sev, "SECRETS",
                    f"A credential that appears to be a real {name.lower()} is present in source code.",
                    "Remove it from source control, rotate it immediately, and load it from a secure secret manager or environment variable.",
                    path, i, .97, ["A value matched a known credential format."], "exposed_secret", _line(text, i)))
                break
        else:
            m = SECRET_ASSIGNMENT.search(line)
            if m:
                if not _placeholder(line) and not re.search(r"(?i)(getenv|env\[|process\.env|os\.environ|secretmanager|vault)", line):
                    out.append(_f(f"Hardcoded credential: {m.group(1).replace('_',' ').lower()}", "HIGH", "SECRETS",
                        "A value that looks like a credential is hardcoded in source code.",
                        "Move the credential to a secret manager or environment variable and rotate it if it has ever been committed.",
                        path, i, .88, ["The variable name indicates a credential and the value is hardcoded."], "hardcoded_credential", _line(text, i)))
    return out


def detect_data_leak(path, text):
    lines = text.splitlines()
    out = []
    # A sensitive word in a broad window is not proof of data flow. Require the
    # actual outbound call's arguments to reference a sensitive identifier, or
    # a nearby payload assignment to do so. This reduces cross-function noise.
    for i, line in enumerate(lines, 1):
        if not NETWORK_SINK.search(line):
            continue
        window = lines[max(0, i - 3):min(len(lines), i + 2)]
        context = "\n".join(window)
        sink_args = line[line.find("(") + 1:] if "(" in line else line
        payload_assignment = any(
            re.search(r"(?i)\b(?:json|data|payload|body|params)\s*=", x)
            and SENSITIVE_NAME.search(x)
            for x in window
        )
        if SENSITIVE_NAME.search(sink_args) or payload_assignment:
            out.append(_f("Sensitive data may be sent outside the application", "HIGH", "DATA_EXPOSURE",
                "The outbound request arguments or an adjacent payload assignment reference a sensitive identifier; actual runtime contents are not proven.",
                "Verify the destination and payload. Minimize data, redact secrets/PII, validate destinations, and authorize sensitive exports.",
                path, i, .78, ["Sensitive identifier appears in the request arguments or explicit payload assignment; runtime data flow is not confirmed."], "data_exfiltration", _line(text, i)))
    return out

def detect_auth(path, text):
    lines = text.splitlines()
    out = []
    route_indexes = [i for i, line in enumerate(lines) if ROUTE_DECL.search(line)]
    for pos, idx in enumerate(route_indexes):
        line_no = idx + 1
        line = lines[idx]
        quoted = re.findall(r"['\"]([^'\"]+)['\"]", line)
        route = next((q for q in quoted if q.startswith("/")), None)
        if not route or not SENSITIVE_PATH.search(route):
            continue
        # Never borrow an auth marker from an adjacent endpoint. Inspect only
        # this route's declaration, middleware arguments and immediate handler
        # signature/body before the next route declaration (bounded to 12 lines).
        next_route = route_indexes[pos + 1] if pos + 1 < len(route_indexes) else len(lines)
        end = min(next_route, idx + 12)
        context = "\n".join(lines[idx:end])
        if not AUTH_MARKERS.search(context):
            out.append(_f("Sensitive endpoint may be missing authentication or authorization", "HIGH", "AUTHENTICATION",
                f"A sensitive HTTP endpoint ({route}) has no recognized authentication/authorization marker in its own route declaration or immediate handler context. Custom dependencies or framework-level guards may not be recognized.",
                "Verify authentication and explicit authorization, including role and resource ownership checks. Confirm global middleware and custom dependencies before treating this as a confirmed vulnerability.",
                path, line_no, .68, [f"Sensitive route detected: {route}", "No recognized auth marker found within this route's bounded context; global/framework guards may be outside static analysis."], "unguarded_endpoint", _line(text, line_no)))
    return out

def _is_parameterized_sql(line: str, context: str) -> bool:
    """Return True for common parameterized/prepared SQL patterns.

    This is deliberately conservative: parameter binding is strong evidence
    against SQL injection for values, while identifiers still need allowlists.
    """
    low = (line + "\n" + context).lower()
    # DB-API / sqlite / psycopg placeholders and a separate parameter argument.
    if re.search(r"(?:execute|executemany|query)\s*\(\s*[^,]+,\s*(?:\(|\[|\{|[a-z_]\w*)", low):
        if re.search(r"(?:%s|%\([^)]+\)s|\?|:[a-z_]\w*|\$[0-9]+)", low):
            return True
    # Explicit ORM parameter binding / prepared statements.
    if re.search(r"\b(?:prepare|preparedstatement|parameterizedquery)\b", low):
        return True
    return False


def detect_injection(path, text):
    lines = text.splitlines()
    out = []
    # Track dynamic SQL assignments, but only report when the tracked variable
    # reaches a recognized SQL sink. Avoid broad nearby-line heuristics: they
    # incorrectly label unrelated SQL calls in the same function as injectable.
    dynamic_queries = {}
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue

        m = re.search(r"(?i)^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", line)
        if m and re.search(r"(?i)(sql|query|statement)", m.group(1)):
            rhs = m.group(2)
            if SQL_TEXT.search(rhs) and (UNTRUSTED.search(rhs) or "{" in rhs or "`" in rhs or re.search(r"\s\+\s|\.format\(|%\s", rhs)):
                dynamic_queries[m.group(1)] = i
            elif re.search(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\b", rhs) and not re.search(r"[`${}]|\s\+\s|\.format\(|%\s", rhs):
                dynamic_queries.pop(m.group(1), None)

        sink = SQL_SINK.search(line)
        if sink:
            # Only inspect the sink's own call and explicit query variable
            # assignments; never infer taint merely from unrelated nearby text.
            call_tail = line[sink.end():]
            call_prefix = line[:sink.start()]
            referenced_dynamic = any(
                re.search(rf"\b{re.escape(name)}\b", call_tail)
                for name in dynamic_queries
            )
            direct_dynamic = bool(
                SQL_TEXT.search(line)
                and (UNTRUSTED.search(line) or re.search(r"[`${}]|\s\+\s|\.format\(", line))
            )
            context = "\n".join(lines[max(0, i - 4):i])
            parameterized = _is_parameterized_sql(line, context)
            if (referenced_dynamic or direct_dynamic) and not parameterized:
                out.append(_f("SQL query may contain untrusted input", "HIGH", "INJECTION",
                    "A recognized database SQL sink receives a query expression that appears dynamically constructed from untrusted input. Parameter binding and identifier validation should be verified.",
                    "Use parameterized queries or prepared statements for values. For dynamic table/column names, use a strict allowlist; never concatenate untrusted values into SQL syntax.",
                    path, i, .82, ["Dynamic SQL construction and a recognized database sink were detected; verify the source-to-sink path and parameter binding."], "sql_injection", _line(text, i)))

        if SHELL_SINK.search(line):
            # Require an untrusted source in the command argument or a directly
            # assigned command variable; nearby unrelated mentions are not enough.
            call = line[line.find("(") + 1:] if "(" in line else ""
            context = "\n".join(lines[max(0, i - 3):i])
            source_names = re.findall(r"(?i)([A-Za-z_]\w*)\s*=.*(?:request\.|req\.|model[_-]?output|ai[_-]?output|user[_-]?input)", context)
            has_tainted_arg = bool(UNTRUSTED.search(call)) or any(
                re.search(rf"\b{re.escape(name)}\b", call) for name in source_names
            )
            if has_tainted_arg:
                out.append(_f("User or AI-controlled data may reach a shell command", "CRITICAL", "INJECTION",
                    "A command-execution function appears to receive an argument linked to user input or AI output.",
                    "Prefer APIs that accept structured arguments without a shell. Apply allowlists and strict validation, and require approval for AI-triggered operations.",
                    path, i, .82, ["The command argument references a potentially untrusted source; confirm the data flow and shell configuration."], "command_injection", _line(text, i)))
    return out


def analyze_security(file_path, text):
    p = file_path.replace("\\", "/").lower()
    if any(x in p for x in (".min.js", ".map", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")):
        return []
    out = detect_secrets(file_path, text) + detect_data_leak(file_path, text) + detect_auth(file_path, text) + detect_injection(file_path, text)
    seen = set()
    result = []
    for f in out:
        key = (f["file_path"], f["line"], f["capability"])
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
