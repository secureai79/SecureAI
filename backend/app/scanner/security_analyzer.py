from __future__ import annotations
import re

SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{20,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]
SECRET_ASSIGNMENT = re.compile(r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_]*)\b\s*[:=]\s*[\"'][^\"'\n]{8,}[\"']")
SENSITIVE_NAME = re.compile(r"(?i)\b(?:\w+[_-])?(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|customer[_-]?data|user[_-]?data|personal[_-]?data|pii|credit[_-]?card|ssn)\b")  # prefix allowed: client_secret, db_password
NETWORK_SINK = re.compile(r"(?i)\b(?:requests\.(?:get|post|put|patch|delete|request)|httpx\.(?:get|post|put|patch|delete|request)|urllib\.request|fetch\s*\(|axios(?:\.[A-Za-z]+)?\s*\(|got\s*\()")
AUTH_MARKERS = re.compile(r"(?i)(?:requireAuth|authenticate|isAuthenticated|authorize|authorization|current_user|login_required|require_admin|requires_auth|auth_required|jwt_required|permission_required|Depends\s*\(\s*get_current_user|verifyToken|verifyJwt|checkPermission|requirePermission|requireRole|isAdmin|adminOnly|authMiddleware)")
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

_NAME_LIKE = re.compile(r"^[a-z0-9]+(?:_[a-z0-9]+)+$")
_NAME_SUFFIX = ("_token", "_key", "_id", "_secret", "_password", "_session", "_user", "_org", "_name")


def _not_a_credential_value(line, ident, text):
    """True when the quoted value is an identifier/key NAME rather than a secret."""
    m = re.search(r"[:=]\s*[\"']([^\"'\n]+)[\"']", line[line.lower().find(ident.lower()):])
    val = m.group(1) if m else ""
    if val.lower() == ident.lower() or val.lower().replace("_", "") == ident.lower().replace("_", ""):
        return True
    storage_use = rf"(?:[Ss]torage|[Cc]ookies?|[Hh]eaders?|[Ee]nv|[Cc]onfig)\w*\s*[.\[]\s*(?:getItem|setItem|removeItem|get|set|pop|delete)?\s*\(?\s*{re.escape(ident)}\b"
    if re.search(storage_use, text):
        return True
    if _NAME_LIKE.match(val) and val.endswith(_NAME_SUFFIX) and not re.search(r"\d", val):
        return True
    return False


_COMMENT_START = re.compile(r"^\s*(#|//|/\*|\*|<!--|--\s)")


def _is_comment(line):
    return bool(_COMMENT_START.match(line))


def _has_sequence(s, n=8):
    """True for runs like abcdefgh or 12345678 (typical made-up example keys)."""
    for i in range(len(s) - n + 1):
        if all(ord(s[i + j + 1]) - ord(s[i + j]) == 1 for j in range(n - 1)):
            return True
    return False


def _looks_fake(value, line=""):
    """Used ONLY for keys inside comments: an obviously invented example key is documentation,
    but a real-looking key pasted into a comment is still a leaked key and stays flagged."""
    body = re.sub(r"^(?:sk-(?:ant-)?|sk_(?:live|test)_|(?:ghp|gho|ghs|ghr)_|github_pat_|xox[baprs]-|AIza|AKIA)", "", value)
    if _has_sequence(body.lower()) or len(set(body.lower())) <= 6:
        return True
    return bool(re.search(r"(?i)\b(example|sample|e\.g\.|dummy|fake|placeholder|redacted)\b", line))


def detect_secrets(path, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for name, pat in SECRET_PATTERNS:
            m = pat.search(line)
            if m and not _placeholder(m.group(0)) and not (_is_comment(line) and _looks_fake(m.group(0), line)):
                sev = "CRITICAL" if "Private key" in name or "secret key" in name.lower() else "HIGH"
                out.append(_f(f"Exposed {name}", sev, "SECRETS",
                    f"A credential that appears to be a real {name.lower()} is present in source code.",
                    "Remove it from source control, rotate it immediately, and load it from a secure secret manager or environment variable.",
                    path, i, .97, ["A value matched a known credential format."], "exposed_secret", _line(text, i)))
                break
        else:
            m = SECRET_ASSIGNMENT.search(line)
            if m and not _not_a_credential_value(line, m.group(1), text):
                if not _placeholder(line) and not re.search(r"(?i)(getenv|env\[|process\.env|os\.environ|secretmanager|vault)", line):
                    out.append(_f(f"Hardcoded credential: {m.group(1).replace('_',' ').lower()}", "HIGH", "SECRETS",
                        "A value that looks like a credential is hardcoded in source code.",
                        "Move the credential to a secret manager or environment variable and rotate it if it has ever been committed.",
                        path, i, .88, ["The variable name indicates a credential and the value is hardcoded."], "hardcoded_credential", _line(text, i)))
    return out


def _leak_finding(path, text, i):
    return _f("Sensitive data may be sent outside the application", "HIGH", "DATA_EXPOSURE",
        "Sensitive information appears in the arguments of an outbound network request.",
        "Verify the destination and data being sent. Minimize the data, redact secrets/PII, validate the destination, and require authorization for sensitive exports.",
        path, i, .84, ["Sensitive data is referenced in the arguments of an outbound network call."], "data_exfiltration", _line(text, i))


def detect_data_leak(path, text):
    if path.lower().endswith(".py"):
        try:
            from .sql_flow import find_sensitive_network_calls
            return [_leak_finding(path, text, i) for i in find_sensitive_network_calls(text, SENSITIVE_NAME)]
        except SyntaxError:
            pass
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")) or re.search(r"re\.compile\(|RegExp\(", line):
            continue                                   # comments and regex definitions are not calls
        if not NETWORK_SINK.search(line):
            continue
        context = "\n".join(lines[max(0, i - 4):min(len(lines), i + 3)])
        if SENSITIVE_NAME.search(context):
            out.append(_leak_finding(path, text, i))
    return out


def _route_window(lines, i):
    """Lines that belong to the route declared on 1-based line ``i``: its stacked decorators above,
    then its function up to the next route's decorators (max 14 lines). Never the previous route."""
    start = i - 1
    while start - 1 >= 0 and lines[start - 1].lstrip().startswith("@") and not ROUTE_DECL.search(lines[start - 1]):
        start -= 1
    end, seen_def = min(len(lines), i + 14), False
    for k in range(i, min(len(lines), i + 14)):
        stripped = lines[k].lstrip()
        if stripped.startswith(("def ", "async def ", "function ", "export ")):
            seen_def = True
        elif seen_def and stripped.startswith("@"):
            end = k                                  # decorators of the NEXT route start here
            break
        if ROUTE_DECL.search(lines[k]):
            end = k
            break
    return lines[start:end]


def detect_auth(path, text):
    lines = text.splitlines()
    out = []
    for i, line in enumerate(lines, 1):
        if not ROUTE_DECL.search(line):
            continue
        quoted = re.findall(r"['\"]([^'\"]+)['\"]", line)
        route = next((q for q in quoted if q.startswith("/")), None)
        if not route or not SENSITIVE_PATH.search(route):
            continue
        context = "\n".join(_route_window(lines, i))
        if not AUTH_MARKERS.search(context):
            out.append(_f("Sensitive endpoint may be missing authentication or authorization", "HIGH", "AUTHENTICATION",
                f"A sensitive HTTP endpoint ({route}) appears without a recognized authentication or authorization check nearby.",
                "Require authentication and an explicit authorization check. Verify role or resource ownership before the sensitive action.",
                path, i, .78, [f"Sensitive route detected: {route}", "No recognized authentication/authorization guard found nearby."], "unguarded_endpoint", _line(text, i)))
    return out


def _sql_hits(path, text):
    """Data-flow hits, or None when this file type/parse is unsupported (then the old heuristic runs)."""
    low = path.lower()
    if low.endswith(".py"):
        try:
            from .sql_flow import find_sql_injection
            return find_sql_injection(text)
        except SyntaxError:
            return None
    if low.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        from .js_sql_flow import find_js_sql_injection
        return find_js_sql_injection(text)
    return None


def _sql_findings(path, text, hits):
    out = []
    for h in hits:
        i = h["line"]
        if h["level"] == "TAINTED":
            f = _f("SQL query is built from untrusted input", "HIGH", "INJECTION",
                   "The query string passed to the database is built from request input or AI output.",
                   "Use parameterized queries (placeholders + bound values). Never concatenate or interpolate request or AI-generated values into SQL.",
                   path, i, .90, ["Query text is constructed from request/AI-controlled data (data-flow traced)."], "sql_injection", _line(text, i))
        elif h["level"] == "PARAM":
            f = _f("SQL query is built from a function argument", "MEDIUM", "INJECTION",
                   "The query string is built by string formatting from a function parameter, so any caller can inject SQL.",
                   "Use bound parameters instead of formatting values into the query. Allowlist identifiers (table/column names).",
                   path, i, .60, ["Query text is constructed from a function parameter; callers were not traced."], "sql_injection", _line(text, i))
            f["impact_level"] = "MEDIUM"
        else:
            f = _f("Dynamic SQL needs review", "LOW", "INJECTION",
                   "The query is built dynamically, but we could not show it comes from user or AI input.",
                   "Confirm every interpolated value is a constant or an allowlisted identifier; prefer bound parameters.",
                   path, i, .35, ["Dynamic SQL string; origin of interpolated values could not be proven."], "sql_injection", _line(text, i))
            f["scored"] = False
            f["impact_level"] = "LOW"
        out.append(f)
    return out


def detect_injection(path, text):
    lines = text.splitlines()
    out = []
    dynamic_queries = {}
    flow = _sql_hits(path, text)
    py_flow = flow is not None
    if py_flow:
        out.extend(_sql_findings(path, text, flow))
    for i, line in enumerate(lines, 1):
        # Track only variables whose names strongly indicate SQL/query text.
        m = re.search(r"(?i)^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", line)
        if m and re.search(r"(?i)(sql|query|statement)", m.group(1)):
            rhs = m.group(2)
            if SQL_TEXT.search(rhs) and (UNTRUSTED.search(rhs) or "{" in rhs or "`" in rhs or "+" in rhs or ".format(" in rhs or "%" in rhs):
                dynamic_queries[m.group(1)] = i

        sink = SQL_SINK.search(line) if not py_flow else None
        if sink:
            local = "\n".join(lines[max(0, i - 8):min(len(lines), i + 2)])
            referenced_dynamic = any(re.search(rf"\b{re.escape(v)}\b", line) for v in dynamic_queries)
            direct_dynamic = SQL_TEXT.search(local) and (UNTRUSTED.search(local) or re.search(r"[`${}]|\+|\.format\(|%[sd]", local))
            if referenced_dynamic or direct_dynamic:
                out.append(_f("SQL query may contain untrusted input", "HIGH", "INJECTION",
                    "A database SQL execution path appears to combine query text with untrusted or interpolated input.",
                    "Use parameterized queries or prepared statements and validate inputs. Do not build SQL by concatenating request or AI-generated values.",
                    path, i, .90, ["A recognized database SQL sink is near dynamically constructed or untrusted query data."], "sql_injection", _line(text, i)))

        if SHELL_SINK.search(line):
            context = "\n".join(lines[max(0, i - 6):i + 1])
            if UNTRUSTED.search(context):
                out.append(_f("User or AI-controlled data may reach a shell command", "CRITICAL", "INJECTION",
                    "A command-execution function appears to receive data that may originate from user input or AI output.",
                    "Avoid shell=True and string-built commands. Use an allowlist, structured arguments, strict validation, and an approval boundary for AI-triggered operations.",
                    path, i, .86, ["Command-execution sink detected near a potentially untrusted source."], "command_injection", _line(text, i)))
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
