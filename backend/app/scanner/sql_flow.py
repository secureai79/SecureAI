"""Data-flow based SQL injection detection for Python.

Replaces the old "SQL keyword + brace/plus/%s within 8 lines of a variable called db/conn/cursor"
heuristic. A query is reported only when the string handed to ``.execute()`` is *built* from a
value whose origin we can name:

  TAINTED  request/input()/AI output reaches the query            -> scored, HIGH, confirmed
  PARAM    a function parameter reaches the query (caller-controlled) -> scored, MEDIUM
  UNKNOWN  dynamic, but origin not provable                       -> unscored review lead
  CONST    literals, constant-derived names, int(), quoted idents -> not reported

ORM/Core calls (``session.query(...).filter(...)``, ``db.execute(update(...))``) pass no string,
so they never reach this logic. The sink is any ``<anything>.execute/executemany/executescript``
call, so a cursor called ``cur`` is covered, not just ``cursor``.
"""
from __future__ import annotations

import ast
import re

CONST, SAFE, UNKNOWN, PARAM, TAINTED = 0, 0, 1, 2, 3   # CONST and SAFE rank equally

SINK_ATTRS = {"execute", "executemany", "executescript"}
REQUEST_ROOTS = {"request", "req", "flask_request"}
AI_ROOT_NAMES = re.compile(r"(?i)^(llm|ai|model|openai|anthropic|client|agent|chain)")
AI_CALL_ATTRS = {"create", "invoke", "generate", "predict", "complete", "run", "chat", "ainvoke", "stream"}
AI_VAR = re.compile(r"(?i)^(completion|llm_?(output|response|reply|result)|ai_?(output|response|reply|result)|"
                    r"model_?(output|response|reply|result)|agent_?(output|reply|result))$")
SANITIZER = re.compile(r"(?i)(^|\.)(quote|quote_identifier|escape|escape_string|identifier|literal|"
                       r"Identifier|Literal|quote_ident|format_identifier)$")
PROPAGATE = {"str", "sorted", "list", "tuple", "set", "frozenset", "reversed", "enumerate", "zip",
             "strip", "lstrip", "rstrip", "lower", "upper", "title", "join", "replace", "format",
             "casefold", "removeprefix", "removesuffix", "dict", "items", "keys", "values", "get"}
NUMERIC_CASTS = {"int", "float", "bool", "len", "uuid", "UUID", "Decimal"}
WRAPPERS = {"text", "SQL", "sql", "TextClause", "Composed"}   # text("..."), psycopg sql.SQL("...")


def _chain(node):
    """Dotted names of an attribute/call chain: request.args.get -> ['request','args','get']."""
    out = []
    while True:
        if isinstance(node, ast.Attribute):
            out.append(node.attr); node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Name):
            out.append(node.id); break
        else:
            break
    return list(reversed(out))


class _Scope:
    """Assignments and parameters visible to one function (or the module)."""

    def __init__(self, fn, parent):
        self.fn, self.parent = fn, parent
        self.assigns: dict[str, list] = {}      # name -> [("value", expr) | ("iter", expr)]
        self.params: set[str] = set()
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = fn.args
            names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
            names += [x.arg for x in (a.vararg, a.kwarg) if x]
            self.params = {n for n in names if n not in ("self", "cls")}
        self._collect(fn)

    def _bind(self, target, kind, expr):
        if isinstance(target, ast.Name):
            self.assigns.setdefault(target.id, []).append((kind, expr))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self._bind(t, "iter" if kind == "iter" else "value", expr)

    def _collect(self, fn):
        body = fn.body if hasattr(fn, "body") else []
        stack = list(body)
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue                                        # nested scopes get their own _Scope
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    self._bind(t, "value", n.value)
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                self._bind(n.target, "value", n.value)
            elif isinstance(n, ast.AugAssign):
                self._bind(n.target, "value", n.value)
            elif isinstance(n, (ast.For, ast.AsyncFor)):
                self._bind(n.target, "iter", n.iter)
            elif isinstance(n, ast.With):
                for item in n.items:
                    if item.optional_vars is not None:
                        self._bind(item.optional_vars, "value", item.context_expr)
            elif isinstance(n, ast.NamedExpr):
                self._bind(n.target, "value", n.value)
            stack.extend(ast.iter_child_nodes(n))


class _Analyzer:
    def __init__(self, scope):
        self.scope = scope
        self._busy: set[str] = set()

    # -- name resolution ------------------------------------------------------------
    def name(self, ident):
        sc = self.scope
        while sc is not None:
            if ident in sc.assigns:
                if ident in self._busy:
                    return CONST                                 # cycle (x = x + "..."): contributes nothing new
                self._busy.add(ident)
                try:
                    worst = CONST
                    for kind, expr in sc.assigns[ident]:
                        worst = max(worst, self.expr(expr, sc))
                    # a parameter that is re-assigned from a constant is still caller-controlled only
                    # if some assignment is not constant; handled by the max() above
                    if ident in sc.params:
                        worst = max(worst, PARAM)
                    return worst
                finally:
                    self._busy.discard(ident)
            if ident in sc.params:
                return PARAM
            sc = sc.parent
        if AI_VAR.match(ident):
            return TAINTED
        return UNKNOWN                                           # import / global we cannot see

    # -- expression classification ----------------------------------------------------
    def expr(self, node, sc=None):
        if node is None:
            return CONST
        t = type(node)
        if t is ast.Constant:
            return CONST
        if t is ast.Name:
            if node.id in REQUEST_ROOTS:
                return TAINTED
            return self.name(node.id)
        if t is ast.JoinedStr:
            worst = CONST
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    worst = max(worst, self._formatted(v))
            return worst
        if t is ast.BinOp:
            if isinstance(node.op, ast.Sub):                     # {"a","b"} - cols  is a subset of the left side
                return self.expr(node.left)
            return max(self.expr(node.left), self.expr(node.right))
        if t in (ast.BoolOp,):
            return max((self.expr(v) for v in node.values), default=CONST)
        if t is ast.IfExp:
            return max(self.expr(node.body), self.expr(node.orelse))
        if t in (ast.Set, ast.List, ast.Tuple):
            return max((self.expr(e) for e in node.elts), default=CONST)
        if t is ast.Dict:
            return max((self.expr(v) for v in node.values if v is not None), default=CONST)
        if t is ast.Starred:
            return self.expr(node.value)
        if t is ast.Compare:
            return CONST
        if t is ast.Subscript:
            return max(self.expr(node.value), self.expr(node.slice) if not isinstance(node.slice, ast.Constant) else CONST)
        if t is ast.Slice:
            return CONST
        if t is ast.Attribute:
            ch = _chain(node)
            if ch and ch[0] in REQUEST_ROOTS:
                return TAINTED
            inner = self.expr(node.value)
            # Reading an attribute off a parameter object (table.name, models.Base.metadata...) is
            # not proof the value is caller-controlled: report it as a review lead, not a finding.
            return UNKNOWN if inner == PARAM else inner
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp):
            return self._comp(node, node.elt)
        if t is ast.DictComp:
            return self._comp(node, node.value)
        if t is ast.Call:
            return self._call(node)
        if t in (ast.Await,):
            return self.expr(node.value)
        return UNKNOWN

    def _comp(self, node, elt):
        worst = CONST
        for g in node.generators:
            worst = max(worst, self.expr(g.iter))
        return max(worst, self.expr(elt)) if worst == CONST else worst

    def _formatted(self, fv):
        v = fv.value
        if isinstance(v, ast.Call):
            nm = ".".join(_chain(v.func)) if isinstance(v.func, (ast.Attribute, ast.Name)) else ""
            if SANITIZER.search(nm):
                return SAFE
        return self.expr(v)

    def _call(self, node):
        f = node.func
        ch = _chain(f) if isinstance(f, (ast.Attribute, ast.Name)) else []
        last = ch[-1] if ch else ""
        dotted = ".".join(ch)
        if ch and ch[0] in REQUEST_ROOTS:
            return TAINTED
        if last == "input" and len(ch) == 1:
            return TAINTED
        if SANITIZER.search(dotted):
            return SAFE
        if last in NUMERIC_CASTS and not (isinstance(f, ast.Attribute) and last in PROPAGATE):
            return SAFE
        if last in AI_CALL_ATTRS and ch and AI_ROOT_NAMES.match(ch[0]):
            return TAINTED
        args = [self.expr(a) for a in node.args] + [self.expr(k.value) for k in node.keywords]
        if last in PROPAGATE:
            recv = self.expr(f.value) if isinstance(f, ast.Attribute) else CONST
            return max([recv] + args)
        return max([UNKNOWN] + args)


def _unwrap(arg):
    """text("..."), sql.SQL("...") -> the inner expression."""
    if isinstance(arg, ast.Call) and arg.args:
        nm = _chain(arg.func)[-1:] or [""]
        if nm[0] in WRAPPERS:
            return _unwrap(arg.args[0])
    return arg


def _builds_string(node):
    """True when the expression constructs text from parts (vs. passing an opaque object)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, (ast.Add, ast.Mod))
    if isinstance(node, ast.Call):
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("format", "join")
    return isinstance(node, ast.Name)                            # resolved through its assignments


SQL_WORD = re.compile(r"(?i)\b(select|insert|update|delete|drop|alter|create|truncate|replace|merge|call|exec|with)\b")


def _const_text(node, scope, depth=0):
    """All literal string fragments that make up the expression (follows names a few levels)."""
    if node is None or depth > 3:
        return ""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else ""
    if isinstance(node, ast.Name):
        sc, out = scope, ""
        while sc is not None:
            if node.id in sc.assigns:
                for _, e in sc.assigns[node.id]:
                    out += " " + _const_text(e, sc, depth + 1)
                return out
            sc = sc.parent
        return ""
    return " ".join(_const_text(c, scope, depth + 1) for c in ast.iter_child_nodes(node))


def _is_bare_param_or_import(arg, scope):
    """`conn.execute(sql)` where sql is just a parameter/import: nothing is built here."""
    if not isinstance(arg, ast.Name):
        return False
    sc = scope
    while sc is not None:
        if arg.id in sc.assigns:
            return False
        if arg.id in sc.params:
            return True
        sc = sc.parent
    return True


def find_sql_injection(text: str):
    """Return [{'line', 'level', 'reason'}]. level: 'TAINTED' | 'PARAM' | 'UNKNOWN'. Raises SyntaxError."""
    tree = ast.parse(text)
    hits = []

    def walk(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                walk(child, _Scope(child, scope))
                continue
            if isinstance(child, ast.ClassDef):
                walk(child, _Scope(child, scope))
                continue
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) \
                    and child.func.attr in SINK_ATTRS and child.args:
                arg = _unwrap(child.args[0])
                if (_builds_string(arg) and not _is_bare_param_or_import(arg, scope)
                        and SQL_WORD.search(_const_text(arg, scope))):
                    rank = _Analyzer(scope).expr(arg)
                    if rank >= UNKNOWN:
                        hits.append({"line": child.lineno,
                                     "level": {TAINTED: "TAINTED", PARAM: "PARAM", UNKNOWN: "UNKNOWN"}[rank]})
            walk(child, scope)

    module_scope = _Scope(tree, None)
    walk(tree, module_scope)
    return hits


# ----------------------------------------------------------------------------------------------
# Outbound network calls that carry sensitive data (used by the data-exfiltration check)
# ----------------------------------------------------------------------------------------------
NET_CALL = re.compile(r"^(requests|httpx)\.(get|post|put|patch|delete|request)$|^urllib\.request\.\w+$|"
                      r"^(aiohttp|session|client|http_client)\.(post|put|patch|request)$", re.I)


# Sending an app's own client_secret / API key / token to the provider that issued it is how
# OAuth and API clients work (GitHub token exchange, Stripe, OpenAI...). That is not exfiltration.
# Personal/customer data (PII) to a third party still is, so PII keeps the finding even here.
PROVIDER_HOSTS = ("github.com", "githubusercontent.com", "gitlab.com", "googleapis.com", "google.com",
                  "stripe.com", "slack.com", "openai.com", "anthropic.com", "microsoftonline.com",
                  "microsoft.com", "twilio.com", "sendgrid.com", "atlassian.com", "atlassian.net")
PII_NAME = re.compile(r"(?i)\b(customer[_-]?data|user[_-]?data|personal[_-]?data|pii|credit[_-]?card|ssn)\b")


def _url_prefix(node, scope, depth=0):
    """The literal beginning of a URL expression: a constant, a name assigned once from a constant, or
    the constant head of an f-string / 'prefix' + x. None when it cannot be determined."""
    if node is None or depth > 3:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        head = ""
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                head += v.value
            else:
                break
        return head or None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _url_prefix(node.left, scope, depth + 1)
    if isinstance(node, ast.Name):
        sc = scope
        while sc is not None:
            if node.id in sc.assigns:
                values = [e for _, e in sc.assigns[node.id]]
                return _url_prefix(values[0], sc, depth + 1) if len(values) == 1 else None
            sc = sc.parent
    return None


def _credential_to_own_provider(call: ast.Call, blob: str, scope=None) -> bool:
    """True when the destination is an https URL on a known provider host and nothing in the call
    is personal data (credentials only). The URL may be a literal, a constant variable
    (token_url = "https://github.com/..."), or an f-string whose host part is literal."""
    if PII_NAME.search(blob):
        return False
    url = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "url"), None)
    prefix = _url_prefix(url, scope)
    if not (prefix and prefix.startswith("https://")):
        return False
    rest = prefix[len("https://"):]
    if "/" not in rest and not isinstance(url, ast.Constant) and not isinstance(url, ast.Name):
        return False                                     # host may be cut off mid-way (f"https://{sub}.x.com")
    host = rest.split("/", 1)[0].split(":", 1)[0].lower()
    return any(host == h or host.endswith("." + h) for h in PROVIDER_HOSTS)


def find_sensitive_network_calls(text: str, sensitive: "re.Pattern"):
    """Lines of real HTTP *calls* whose arguments (or the values assigned to those arguments)
    mention sensitive data. A regex defined in a string, or a comment, is not a call."""
    tree = ast.parse(text)
    hits = []

    def walk(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                walk(child, _Scope(child, scope))
                continue
            if isinstance(child, ast.Call) and isinstance(child.func, (ast.Attribute, ast.Name)):
                if NET_CALL.match(".".join(_chain(child.func))):
                    parts = list(child.args) + [k.value for k in child.keywords]
                    blob = " ".join(ast.unparse(p) for p in parts)
                    for p in parts:                                   # one level of assignment lookup
                        for n in ast.walk(p):
                            if isinstance(n, ast.Name):
                                sc = scope
                                while sc is not None:
                                    if n.id in sc.assigns:
                                        blob += " " + " ".join(ast.unparse(e) for _, e in sc.assigns[n.id])
                                        break
                                    sc = sc.parent
                    if sensitive.search(blob) and not _credential_to_own_provider(child, blob, scope):
                        hits.append(child.lineno)
            walk(child, scope)

    walk(tree, _Scope(tree, None))
    return hits
