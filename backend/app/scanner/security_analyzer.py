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
    for i, line in enumerate(lines, 1):
        if not NETWORK_SINK.search(line):
            continue
        context_lines = lines[max(0, i - 10):min(len(lines), i + 3)]
        context = "\n".join(context_lines)
        # Require a sensitive identifier/expression in the same small local
        # context rather than carrying variables across unrelated functions.
        if SENSITIVE_NAME.search(context):
            out.append(_f("Sensitive data may be sent outside the application", "HIGH", "DATA_EXPOSURE",
                "Sensitive information appears in the local data flow of an outbound network request.",
                "Verify the destination and data being sent. Minimize the data, redact secrets/PII, validate the destination, and require authorization for sensitive exports.",
                path, i, .84, ["Sensitive data is referenced near an outbound network request."], "data_exfiltration", _line(text, i)))
    return out


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
        context = "\n".join(lines[max(0, i - 4):min(len(lines), i + 14)])
        if not AUTH_MARKERS.search(context):
            out.append(_f("Sensitive endpoint may be missing authentication or authorization", "HIGH", "AUTHENTICATION",
                f"A sensitive HTTP endpoint ({route}) appears without a recognized authentication or authorization check nearby.",
                "Require authentication and an explicit authorization check. Verify role or resource ownership before the sensitive action.",
                path, i, .78, [f"Sensitive route detected: {route}", "No recognized authentication/authorization guard found nearby."], "unguarded_endpoint", _line(text, i)))
    return out


def detect_injection(path, text):
    lines = text.splitlines()
    out = []
    dynamic_queries = {}
    for i, line in enumerate(lines, 1):
        # Track only variables whose names strongly indicate SQL/query text.
        m = re.search(r"(?i)^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", line)
        if m and re.search(r"(?i)(sql|query|statement)", m.group(1)):
            rhs = m.group(2)
            if SQL_TEXT.search(rhs) and (UNTRUSTED.search(rhs) or "{" in rhs or "`" in rhs or "+" in rhs or ".format(" in rhs or "%" in rhs):
                dynamic_queries[m.group(1)] = i

        sink = SQL_SINK.search(line)
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
