"""
AST-based Python analysis.

Replaces "keyword appears in file" with "does an AI-influenced value actually
reach a dangerous call's argument". This is the fix for the false-positive
class described in feedback: a docstring or comment containing the word
"refund" no longer matches (only real ast.Call nodes matter), and — the more
important fix — a dangerous call using a *literal* value (`amount=100`) is
distinguished from one using an *AI-derived* value (`amount=decision["amount"]`).

Approach (intentionally not a full points-to/interprocedural framework —
that's a research project. This is a pragmatic, two-pass approximation that
handles the common patterns: wrapper functions around an SDK call, dict/attr
access on the AI response, and one hop of interprocedural propagation through
local function calls):

  Pass 0: find AI-client variables (`client = OpenAI()`) and AI-agent
          variables (`agent = initialize_agent(...)`).
  Pass 1: find "AI-returning" local functions — functions whose body calls
          the AI client/agent directly.
  Pass 2: per-function intraprocedural forward taint pass: a variable is
          tainted if assigned from an AI call, an AI-returning function call,
          or derived (subscript/attribute/f-string/binop) from a tainted
          variable.
  Pass 3: one hop of interprocedural seeding — if a local function is called
          with a tainted actual argument, the corresponding formal parameter
          is seeded as tainted, and pass 2 is re-run (fixed point, capped).
  Pass 4: walk all ast.Call nodes; match against dangerous-capability
          patterns; for each match, check whether any argument expression
          references a tainted name -> ai_controlled. Check for nearby
          guard clauses (approval / threshold) -> control detected.
"""
from __future__ import annotations

import ast
import copy
from platform import node
import re
from dataclasses import dataclass, field

AI_CLIENT_CONSTRUCTORS = {
    "OpenAI": "OpenAI", "AsyncOpenAI": "OpenAI",
    "Anthropic": "Anthropic", "AsyncAnthropic": "Anthropic",
    "ChatOpenAI": "OpenAI", "ChatAnthropic": "Anthropic",
    "GenerativeModel": "Gemini",
}
AI_AGENT_CONSTRUCTORS = {
    "initialize_agent": "LangChain", "AgentExecutor": "LangChain",
    "Crew": "CrewAI", "Agent": "CrewAI",
}
GENERIC_AGENT_NAMES = {"Crew", "Agent"}


_ORM_MODULE_HINT = re.compile(r"(?i)(^|\.)(models?|schemas?|orm|db|database|entities|domain)(\.|$)")


def _generic_agent_is_ai(tree: ast.AST, func: ast.AST, ctor: str) -> bool:
    """Is a call to a generically-named class (`Agent`, `Crew`) an AI-framework agent?

    - `crewai.Agent(...)`            -> yes when crewai is imported
    - `Agent(...)` after `from pydantic_ai / agents / crewai / ... import Agent` -> yes
    - `models.Agent(...)`, or `Agent` imported from a relative / models / schema / db module -> no
    """
    if isinstance(func, ast.Attribute):
        root = func.value
        while isinstance(root, ast.Attribute):
            root = root.value
        return isinstance(root, ast.Name) and root.id == "crewai" and _imports_package(tree, "crewai")
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and any((a.asname or a.name) == ctor for a in n.names):
            if n.level or not n.module or _ORM_MODULE_HINT.search(n.module):
                return False
            return True
    return False            # defined locally or unknown origin: not provably an AI framework class


def _imports_package(tree: ast.AST, package: str) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Import) and any(a.name == package or a.name.startswith(package + ".") for a in n.names):
            return True
        if isinstance(n, ast.ImportFrom) and n.module and (n.module == package or n.module.startswith(package + ".")):
            return True
    return False


# Methods that, called on an AI client/agent variable, count as "the AI call".
AI_CALL_METHOD_SUFFIXES = {
    "create", "generate", "generate_content", "run", "invoke", "complete",
    "chat", "predict", "kickoff",
}

APPROVAL_NAME_HINTS = re.compile(
    r"(require_approval|human_approval|needs_approval|manual_review|"
    r"queue_for_human_approval|pending_approval|confirm)",
    re.IGNORECASE,
)

SQL_DANGEROUS_RE = re.compile(r"\b(DELETE\s+FROM|DROP\s+TABLE|TRUNCATE\s+TABLE)\b", re.IGNORECASE)

# (chain_suffix_regex, category, operation)
# chain = dotted string built from the call target, e.g. "stripe.Refund.create"
DANGEROUS_CHAIN_RULES = [
    (re.compile(r"stripe\..*\brefund\b", re.IGNORECASE), "FINANCIAL", "refund"),
    (re.compile(r"stripe\..*\bcharge\b", re.IGNORECASE), "FINANCIAL", "charge"),
    (re.compile(r"\btransfer\b", re.IGNORECASE), "FINANCIAL", "transfer"),
    (re.compile(r"\bpayout\b", re.IGNORECASE), "FINANCIAL", "payout"),
    (re.compile(r"\b(cursor|cur|conn|connection|cnx|session|db|dbh|database|engine)\..*\bexecute(many|script)?\b", re.IGNORECASE), "DATA", "execute_sql"),
    (re.compile(r"\bsendmail\b", re.IGNORECASE), "COMMUNICATION", "send"),
    (re.compile(r"\bsend(_email|_message)?\b", re.IGNORECASE), "COMMUNICATION", "send"),
    # \b: `subprocess.CalledProcessError` (an exception class) must not match `call`.
    (re.compile(r"subprocess\.(run|call|Popen|check_output|check_call)\b", re.IGNORECASE), "INFRASTRUCTURE", "execute"),
    (re.compile(r"os\.system", re.IGNORECASE), "INFRASTRUCTURE", "execute"),
    (re.compile(r"\bterminate_instances\b|\bterminate\b", re.IGNORECASE), "INFRASTRUCTURE", "terminate"),
    # NOT a bare `\bdeploy\b`: real-repo validation (VALIDATION_REPORT.md)
    # found this matched OpenAI's own `swarm.deploy()` -- a method that
    # just means "run the swarm", nothing to do with infrastructure.
    # Require the call chain to actually mention a known infra tool/SDK
    # right before `.deploy` (e.g. `ec2_client.deploy`, `k8s.deploy`).
    (re.compile(r"(boto3|ec2|ecs|eks|cloudformation|kubernetes|k8s|docker|terraform|helm)\w*\.deploy",
                re.IGNORECASE), "INFRASTRUCTURE", "deploy"),
    (re.compile(r"\.merge\(", re.IGNORECASE), "CODE", "merge"),
    (re.compile(r"\bpush\b", re.IGNORECASE), "CODE", "push"),
]

CATEGORY_RECOMMENDATIONS = {
    "FINANCIAL": "Require human approval above a defined dollar threshold before executing this action.",
    "DATA": "Require human approval for destructive database operations, or restrict the AI's DB role to read-only.",
    "COMMUNICATION": "Add a review step or rate limit before AI-triggered outbound messages are sent.",
    "INFRASTRUCTURE": "Require human approval before shell/cloud/deploy operations triggered by AI output.",
    "CODE": "Require review/approval before AI-initiated merges or pushes to protected branches.",
}


def _chain_str(node: ast.AST) -> str:
    """Best-effort dotted string for a Call's func, e.g. 'stripe.Refund.create'."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _sql_string_literal(node: ast.AST) -> str | None:
    """Extract a literal or f-string's static text pieces for SQL keyword matching."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
    return None


DEPLOYMENT_TOOL_KEYWORDS = re.compile(
    r"\b(kubectl|terraform|helm|docker|dockerd|aws|gcloud|az|serverless|cdk|"
    r"eb\s+deploy|sam\s+deploy)\b",
    re.IGNORECASE,
)


def _subprocess_command_text(call_node: ast.Call) -> str | None:
    """Best-effort: flatten a subprocess.run(["docker", "deploy", ...]) or
    subprocess.run("docker deploy ...") first argument into a plain string
    for keyword matching, so a generic shell-execute call can be recognized
    as a specific deployment-tool invocation rather than lumped in with
    every other subprocess call."""
    if not call_node.args:
        return None
    arg = call_node.args[0]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, (ast.List, ast.Tuple)):
        parts = [el.value for el in arg.elts if isinstance(el, ast.Constant) and isinstance(el.value, str)]
        return " ".join(parts) if parts else None
    return None


def _is_shell_like(call_node: ast.Call, chain: str) -> bool:
    """True when the call runs a command *string* through a shell."""
    last = chain.split(".")[-1] if chain else ""
    if last in ("system", "popen"):
        return True
    for kw in call_node.keywords:
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
            return True
    first = call_node.args[0] if call_node.args else None
    return first is not None and not isinstance(first, (ast.List, ast.Tuple))


@dataclass
class RawFinding:
    category: str
    operation: str
    chain: str
    line: int
    ai_controlled: bool
    control_confidence: float
    approval_detected: bool
    limit_detected: bool
    capability_chain: list[str]
    snippet_line: str
    data_flow_path: list[str] = field(default_factory=list)
    function_name: str = "module"


@dataclass
class FileASTAnalysis:
    file_path: str
    ai_providers: list[str] = field(default_factory=list)
    ai_functions: set[str] = field(default_factory=set)  # local function names that produce AI output
    findings: list[RawFinding] = field(default_factory=list)
    parse_ok: bool = True


class _FunctionTaintVisitor(ast.NodeVisitor):
    """Intraprocedural forward taint pass for one function body."""

    def __init__(self, ai_client_vars: dict, ai_functions: set, seeded_tainted_params: set):
        self.ai_client_vars = ai_client_vars       # var name -> provider
        self.ai_functions = ai_functions            # names of local AI-returning functions
        self.tainted: set[str] = set(seeded_tainted_params)
        self.taint_paths: dict[str, list[str]] = {
            name: [name] for name in seeded_tainted_params
        }
        self.dangerous_calls: list[tuple[ast.Call, bool, str]] = []

    def _expr_is_ai_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        chain = _chain_str(node.func)
        if not chain:
            return False
        base = chain.split(".")[0]
        last = chain.split(".")[-1]
        if base in self.ai_client_vars and last in AI_CALL_METHOD_SUFFIXES:
            return True
        if base in self.ai_functions:
            return True
        # direct call to a local AI-returning function without attribute chain
        if isinstance(node.func, ast.Name) and node.func.id in self.ai_functions:
            return True
        return False

    def _expr_tainted(self, node: ast.AST) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.tainted
        if self._expr_is_ai_call(node):
            return True
        # subscript/attribute derived from tainted base: decision["amount"], decision.amount
        if isinstance(node, (ast.Subscript, ast.Attribute)):
            base = node.value if isinstance(node, ast.Subscript) else node.value
            return self._expr_tainted(base)
        if isinstance(node, ast.JoinedStr):  # f-strings
            return any(
                isinstance(v, ast.FormattedValue) and self._expr_tainted(v.value)
                for v in node.values
            )
        if isinstance(node, ast.BinOp):
            return self._expr_tainted(node.left) or self._expr_tainted(node.right)

        if isinstance(node, ast.Dict):
    # A dictionary preserves taint when any of its values are AI-derived.
            return any(self._expr_tainted(value) for value in node.values if value is not None)

        if isinstance(node, ast.Call):
    # value derived by calling *something* with a tainted arg, e.g. str(decision)
            return (any(self._expr_tainted(a) for a in node.args)
                    or any(self._expr_tainted(k.value) for k in node.keywords))

        # ["sh", "-c", ai_text], (a, b), {a, b}, *ai_args: a container is tainted if any element is.
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_tainted(e) for e in node.elts)
        if isinstance(node, ast.Starred):
            return self._expr_tainted(node.value)

        return False

    def _expr_path(self, node: ast.AST) -> list[str]:
        if node is None:
            return []

        if isinstance(node, ast.Name):
            return list(self.taint_paths.get(node.id, [node.id]))

        if self._expr_is_ai_call(node):
            chain = _chain_str(node.func)
            return [f"{chain}()"] if chain else ["AI response"]

        if isinstance(node, ast.Subscript):
            base_path = self._expr_path(node.value)
            if base_path:
                try:
                    key = ast.unparse(node.slice)
                except Exception:
                    key = "..."

            # Keep string dictionary keys in the evidence path using
            # double quotes so the path is stable and human-readable.
                if (
                    isinstance(node.slice, ast.Constant)
                    and isinstance(node.slice.value, str)
                ):
                    key = f'"{node.slice.value}"'

                return base_path + [f"{base_path[-1]}[{key}]"]
            return []

            if isinstance(node, ast.Attribute):
                base_path = self._expr_path(node.value)
                if base_path:
                    return base_path + [f"{base_path[-1]}.{node.attr}"]
                return []

            if isinstance(node, ast.Dict):
                paths = []
                for value in node.values:
                    if value is not None:
                        paths.extend(self._expr_path(value))
                return paths

            if isinstance(node, ast.BinOp):
                return self._expr_path(node.left) + self._expr_path(node.right)

            if isinstance(node, ast.JoinedStr):
                paths = []
                for value in node.values:
                    if isinstance(value, ast.FormattedValue):
                        paths.extend(self._expr_path(value.value))
                return paths

        if isinstance(node, ast.Call):
            paths = []
            for arg in node.args:
                paths.extend(self._expr_path(arg))
            for keyword in node.keywords:
                paths.extend(self._expr_path(keyword.value))
            return paths

        return []

    def visit_Assign(self, node: ast.Assign):
        tainted = self._expr_tainted(node.value)
        path = self._expr_path(node.value)

        for target in node.targets:
            if isinstance(target, ast.Name):
                if tainted:
                    self.tainted.add(target.id)

                    assignment_path = list(path)

                    # Preserve the source variable/expression in the flow.
                    if isinstance(node.value, ast.Name):
                        source_name = node.value.id
                        if not assignment_path or assignment_path[-1] != source_name:
                            assignment_path.append(source_name)

                    # Record the new variable receiving the tainted value.
                    if not assignment_path or assignment_path[-1] != target.id:
                        assignment_path.append(target.id)

                    self.taint_paths[target.id] = assignment_path
                else:
                    self.tainted.discard(target.id)
                    self.taint_paths.pop(target.id, None)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        chain = _chain_str(node.func)
        if chain:
            for pattern, category, operation in DANGEROUS_CHAIN_RULES:
                if pattern.search(chain):
                    self.dangerous_calls.append((node, category, operation, chain))
                    break
        self.generic_visit(node)


def _find_call_ancestor_blocks(stmts: list, target_call: ast.Call, path: list | None = None) -> list | None:
    """Returns the ancestor chain of (block, index_in_block) pairs, from
    outermost to innermost, for the statement block(s) that structurally
    contain `target_call` — used so guard detection only looks at ifs that
    actually sit on the path to the call, not anywhere else in the function."""
    if path is None:
        path = []
    for idx, stmt in enumerate(stmts):
        if target_call is stmt or target_call in ast.walk(stmt):
            new_path = path + [(stmts, idx)]
            nested_blocks = []
            for field in ("body", "orelse", "finalbody"):
                val = getattr(stmt, field, None)
                if isinstance(val, list) and val and isinstance(val[0], ast.stmt):
                    nested_blocks.append(val)
            for handler in getattr(stmt, "handlers", []) or []:
                nested_blocks.append(handler.body)
            for nb in nested_blocks:
                deeper = _find_call_ancestor_blocks(nb, target_call, new_path)
                if deeper is not None:
                    return deeper
            return new_path
    return None


def _find_guards(func_node, call_node: ast.Call) -> tuple[bool, bool]:
    """Look for an approval-hint call or a threshold comparison in an `if`
    that structurally guards call_node: an `if` with an early return that
    appears *before* the call, in the same block or an enclosing block on
    the path down to the call — not just anywhere in the whole function
    (a guard in an unrelated sibling branch must NOT count).

    The threshold check additionally requires the comparison to reference a
    variable name that also appears in the dangerous call's own arguments —
    `if amount > 100` only counts as guarding `stripe.Refund.create(amount=x)`
    if `amount`/`x` actually overlaps; a guard checking an unrelated
    variable shouldn't be credited just because it happens to precede the
    call textually."""
    approval = False
    limit = False

    chain = _find_call_ancestor_blocks(func_node.body, call_node)
    if chain is None:
        return approval, limit

    call_arg_names = set()
    for a in list(call_node.args) + [kw.value for kw in call_node.keywords]:
        call_arg_names |= {n.id for n in ast.walk(a) if isinstance(n, ast.Name)}

    for block, idx in chain:
        for stmt in block[:idx]:
            if not isinstance(stmt, ast.If):
                continue
            has_early_return = any(isinstance(s, (ast.Return, ast.Raise)) for s in stmt.body)
            if not has_early_return:
                continue
            # threshold-style comparison: `if amount > 100:` — only counts if
            # it shares a variable with the call it's supposedly guarding.
            if isinstance(stmt.test, ast.Compare):
                compare_names = {n.id for n in ast.walk(stmt.test) if isinstance(n, ast.Name)}
                if compare_names & call_arg_names:
                    limit = True
            # approval-style call inside the guarded branch
            for n in ast.walk(stmt):
                if isinstance(n, ast.Call):
                    fn_name = _chain_str(n.func)
                    if fn_name and APPROVAL_NAME_HINTS.search(fn_name):
                        approval = True
    return approval, limit


def analyze_python_ast(file_path: str, source: str) -> FileASTAnalysis:
    result = FileASTAnalysis(file_path=file_path)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        result.parse_ok = False
        return result

    source_lines = source.splitlines()

    # Pass 0: AI client / agent variable bindings (module + function level, best effort)
    ai_client_vars: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            ctor = None
            if isinstance(node.value.func, ast.Name):
                ctor = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                ctor = node.value.func.attr
            if ctor in AI_CLIENT_CONSTRUCTORS:
                provider = AI_CLIENT_CONSTRUCTORS[ctor]
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        ai_client_vars[t.id] = provider
                        if provider not in result.ai_providers:
                            result.ai_providers.append(provider)
            elif ctor in AI_AGENT_CONSTRUCTORS and not (
                    ctor in GENERIC_AGENT_NAMES and not _generic_agent_is_ai(tree, node.value.func, ctor)):
                # `Agent` / `Crew` are common class names (an ORM model called Agent is not an AI
                # agent), so they only count when imported from an AI-framework-looking module.
                provider = AI_AGENT_CONSTRUCTORS[ctor]
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        ai_client_vars[t.id] = provider
                        if provider not in result.ai_providers:
                            result.ai_providers.append(provider)

    # Also detect bare imports of AI SDKs even with no client var yet (still
    # counts as "AI SDK present" for repo-level context).
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = (node.module or "") if isinstance(node, ast.ImportFrom) else ""
            names = [mod] + [a.name for a in node.names]
            for n in names:
                if n.startswith("openai") and "OpenAI" not in result.ai_providers:
                    result.ai_providers.append("OpenAI")
                if n.startswith("anthropic") and "Anthropic" not in result.ai_providers:
                    result.ai_providers.append("Anthropic")
                if n.startswith("langchain") and "LangChain" not in result.ai_providers:
                    result.ai_providers.append("LangChain")
                if n.startswith("crewai") and "CrewAI" not in result.ai_providers:
                    result.ai_providers.append("CrewAI")

    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    # Module-level code (outside any function) was previously invisible to
    # this analyzer entirely — a real blind spot (feedback item #2): agent
    # setup code sometimes calls the AI SDK and a dangerous capability
    # directly at import time / module scope, not inside a function. Treat
    # module scope as one more "function" named "<module>", built from a
    # pruned copy of the tree with all nested function/class bodies removed
    # (they're already covered individually via `functions` above — pruning
    # avoids double-counting their contents here).
    class _StripNestedDefs(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            return None

        def visit_AsyncFunctionDef(self, node):
            return None

        def visit_ClassDef(self, node):
            return None

    module_tree = copy.deepcopy(tree)
    module_scope = _StripNestedDefs().visit(module_tree)
    ast.fix_missing_locations(module_scope)
    module_scope.name = "<module>"
    functions.append(module_scope)

    # Pass 1: which local functions are "AI-returning" (their body calls the AI client/agent)
    ai_functions: set[str] = set()
    for fn in functions:
        if fn.name == "<module>":
            continue  # nothing can call a name literally "<module>"
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                chain = _chain_str(node.func)
                if not chain:
                    continue
                base, last = chain.split(".")[0], chain.split(".")[-1]
                if base in ai_client_vars and last in AI_CALL_METHOD_SUFFIXES:
                    ai_functions.add(fn.name)
                    break
    result.ai_functions = ai_functions

    # Pass 3 (interprocedural seeding), fixed point capped at 3 rounds.
    seeded_params: dict[str, set[str]] = {fn.name: set() for fn in functions}
    func_by_name = {fn.name: fn for fn in functions}

    for _round in range(3):
        # Run intraprocedural pass per function with current seeding
        visitors: dict[str, _FunctionTaintVisitor] = {}
        for fn in functions:
            v = _FunctionTaintVisitor(ai_client_vars, ai_functions, seeded_params[fn.name])
            for stmt in fn.body:
                v.visit(stmt)
            visitors[fn.name] = v

        # Look for calls to local functions with tainted args -> seed callee params
        changed = False
        for fn in functions:
            v = visitors[fn.name]
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                    callee = func_by_name.get(callee_name)
                    if not callee:
                        continue
                    arg_names = [a.arg for a in callee.args.args]
                    for i, arg_expr in enumerate(node.args):
                        if i >= len(arg_names):
                            continue
                        if v._expr_tainted(arg_expr):
                            if arg_names[i] not in seeded_params[callee_name]:
                                seeded_params[callee_name].add(arg_names[i])
                                changed = True
                    for kw in node.keywords:
                        if kw.arg and kw.arg in arg_names and v._expr_tainted(kw.value):
                            if kw.arg not in seeded_params[callee_name]:
                                seeded_params[callee_name].add(kw.arg)
                                changed = True
        if not changed:
            break

    # Final pass: collect dangerous calls with final taint state
    for fn in functions:
        v = visitors[fn.name]
        for call_node, category, operation, chain in v.dangerous_calls:
            args_tainted = any(v._expr_tainted(a) for a in call_node.args) or any(
                v._expr_tainted(kw.value) for kw in call_node.keywords
            )

            # Special-case: DB `.execute("...")` is only DATA-dangerous if the
            # SQL text actually contains a destructive keyword.
            if operation == "execute_sql":
                sql_text = None
                if call_node.args:
                    sql_text = _sql_string_literal(call_node.args[0])
                if sql_text and SQL_DANGEROUS_RE.search(sql_text):
                    kw = SQL_DANGEROUS_RE.search(sql_text).group(1).split()[0].lower()
                    operation = kw
                else:
                    continue  # e.g. a harmless SELECT — not a finding

            # Special-case: a generic subprocess/shell "execute" is
            # reclassified as the more specific "deploy" if the command
            # itself is clearly a deployment tool invocation (docker,
            # kubectl, terraform, ...). This is narrower and more accurate
            # than matching bare `.deploy(` on any object.
            if operation == "execute" and category == "INFRASTRUCTURE":
                cmd_text = _subprocess_command_text(call_node)
                if cmd_text and DEPLOYMENT_TOOL_KEYWORDS.search(cmd_text):
                    operation = "deploy"

            # In a file with NO AI provider, an argv-list subprocess call (no shell) whose arguments
            # are not derived from AI output is ordinary program logic (e.g. `git clone` in a
            # backend service), not an AI capability. In a file that does use an AI provider we
            # keep reporting it (downgraded, since the AI does not control it): an agent's shell
            # tool is a real capability even with fixed arguments. Shell strings (shell=True,
            # os.system/popen) and anything linked to AI output are always kept.
            if (operation == "execute" and not args_tainted and not result.ai_providers
                    and not _is_shell_like(call_node, chain)):
                continue

            approval, limit = _find_guards(fn, call_node)
            line = call_node.lineno
            # Keep original indentation (don't .strip()) — fix_generator.py
            # needs it to insert a guard clause at the correct indent level.
            snippet_line = source_lines[line - 1].rstrip("\n") if 0 < line <= len(source_lines) else ""

            base_conf = 0.55
            if args_tainted:
                base_conf += 0.30
            elif result.ai_providers:
                base_conf += 0.05  # AI present in file, but not connected to this call
            confidence = round(min(base_conf, 0.97), 2)

            provider_label = ai_client_vars.get(chain.split(".")[0]) or (result.ai_providers[0] if result.ai_providers else None)

            chain_desc = [fn.name]
            if provider_label:
                chain_desc.append(provider_label)
            chain_desc.append("AI-generated decision" if args_tainted else "static/fixed value")
            chain_desc.append(f"{chain}()")
            chain_desc.append(operation.upper())

            result.findings.append(RawFinding(
                category=category,
                operation=operation,
                chain=chain,
                line=line,
                ai_controlled=args_tainted,
                control_confidence=confidence,
                approval_detected=approval,
                limit_detected=limit,
                capability_chain=chain_desc,
                snippet_line=snippet_line,
                function_name=fn.name,
                data_flow_path=(
    (
        (
            next(
                (
                    v._expr_path(arg)
                    for arg in call_node.args
                    if v._expr_tainted(arg)
                ),
                None,
            )
            or next(
                (
                    v._expr_path(keyword.value)
                    for keyword in call_node.keywords
                    if v._expr_tainted(keyword.value)
                ),
                [],
            )
        )
        + [f"{chain}()"]
    )
    if args_tainted
    else []
),
            ))

    return result
