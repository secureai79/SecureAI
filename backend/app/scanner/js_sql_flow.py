"""Lightweight JS/TS SQL-injection check (no AST available): template literals and string concatenation
passed to a database client. Tagged templates (sql`...`, prisma.$queryRaw`...`) are parameterized by
the library and are never reported. Same levels as sql_flow: TAINTED (scored) / UNKNOWN (review lead)."""
from __future__ import annotations

import re

SINK = re.compile(r"\b(db|pool|client|conn|connection|knex|sequelize|prisma|database|pg|mysql|trx|tx)\s*\.\s*"
                  r"(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(")
SQL_WORD = re.compile(r"(?i)\b(select|insert|update|delete|drop|alter|create|truncate)\b")
UNTRUSTED = re.compile(r"\b(req|request|params|body|query|input|ctx|event|payload|args|llm|completion|aiOutput|modelOutput)\b")
SAFE_WRAP = re.compile(r"\b(Number|parseInt|parseFloat|escape|escapeId|escapeLiteral|format|quote)\s*\(")


def _first_arg(src: str, start: int) -> str:
    depth, i, in_q = 0, start, None
    while i < len(src) and i - start < 1200:
        ch = src[i]
        if in_q:
            if ch == "\\":
                i += 2
                continue
            if ch == in_q:
                in_q = None
        elif ch in "'\"`":
            in_q = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return src[start:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return src[start:i]
        i += 1
    return src[start:i]


def _classify(arg: str, src: str, depth: int = 0):
    arg = arg.strip()
    if re.fullmatch(r"[A-Za-z_$][\w$]*", arg) and depth < 2:          # variable: look at its assignment
        m = re.search(rf"\b(?:const|let|var)\s+{re.escape(arg)}\s*=\s*(.+?);", src, re.S)
        return _classify(m.group(1), src, depth + 1) if m else None
    if arg.startswith("`"):
        if "${" not in arg:
            return None
        exprs = re.findall(r"\$\{([^}]*)\}", arg)
        text_part = re.sub(r"\$\{[^}]*\}", " ", arg)
    elif re.search(r"['\"]\s*\+|\+\s*['\"]", arg):
        text_part = " ".join(re.findall(r"""(['"])(.*?)\1""", arg) and [m[1] for m in re.findall(r"""(['"])(.*?)\1""", arg)])
        exprs = [t for t in re.split(r"\+", re.sub(r"""(['"]).*?\1""", "", arg)) if t.strip()]
    else:
        return None
    if not SQL_WORD.search(text_part):
        return None
    dynamic = [e for e in exprs if e.strip() and not re.fullmatch(r"\s*[\d.]+\s*", e) and not SAFE_WRAP.search(e)]
    if not dynamic:
        return None
    return "TAINTED" if any(UNTRUSTED.search(e) for e in dynamic) else "UNKNOWN"


def find_js_sql_injection(text: str):
    hits = []
    for m in SINK.finditer(text):
        before = text[max(0, m.start() - 1):m.start()]
        arg = _first_arg(text, m.end())
        level = _classify(arg, text)
        if level:
            hits.append({"line": text.count("\n", 0, m.start()) + 1, "level": level})
    return hits
