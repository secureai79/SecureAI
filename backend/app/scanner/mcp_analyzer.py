"""Model Context Protocol (MCP) security analysis.

Two kinds of files matter:

* **Client configuration** (``mcp.json``, ``.mcp.json``, ``.cursor/mcp.json``, ``.vscode/mcp.json``,
  ``claude_desktop_config.json``, ...): which servers an agent connects to and how. Risks: plaintext
  credentials, unpinned packages fetched at launch (supply chain / "rug pull"), unencrypted remote
  servers, shell/filesystem servers, auto-approved tools, and server combinations that complete the
  lethal trifecta (untrusted content + private data + outbound channel) in one agent session.
* **Server code** (Python FastMCP / MCP SDK): every tool argument is model-controlled, and a
  prompt-injected model controls it too. Model-controlled values reaching a shell, ``eval``, SQL,
  file path or URL are exploitable; tools that do destructive things without (or contradicting) their
  MCP annotations, and tool descriptions that carry hidden instructions ("tool poisoning"), are flagged.

Deterministic static analysis, like the rest of the scanner: findings are labelled with confidence,
nothing is executed, and secrets are never echoed back.
"""
from __future__ import annotations

import ast
import json
import posixpath
import re
from types import SimpleNamespace

from .injection_analyzer import (
    TOOL_DECORATOR_RE, Taint, _Flow, _FileAnalysis, _chain, _names_and_strings,
)

CATEGORY = "MCP_SECURITY"
MAX_BYTES = 400_000
SEV = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

CONFIG_NAMES = {
    "mcp.json", ".mcp.json", "mcp_config.json", "mcp-config.json", "mcp_settings.json",
    "claude_desktop_config.json", "cline_mcp_settings.json", ".claude.json", "mcp_servers.json",
}
CONFIG_KEYS = ('"mcpServers"', '"mcp_servers"', '"mcpservers"', '"context_servers"')

# ---------------------------------------------------------------- vocabulary
EXEC_SERVER_RE = re.compile(
    r"(server[-_]shell|mcp[-_]?shell|shell[-_]?(mcp|server)|mcp[-_]server[-_](commands?|terminal|ssh|docker|kubernetes|k8s)|"
    r"desktop[-_]?commander|run[-_]?commands?|execute[-_]?commands?|terminal[-_]?(controller|mcp)|ssh[-_]mcp|"
    r"(python|code)[-_]?(repl|interpreter|runner|executor)|mcp[-_]?(python|code)[-_]?(exec|run)\w*|iterm[-_]?mcp|tmux[-_]?mcp)",
    re.IGNORECASE)
INGEST_RE = re.compile(r"(fetch|browser|puppeteer|playwright|browserbase|brave[-_]?search|tavily|\bexa\b|firecrawl|scrap\w*|"
                       r"web[-_]?search|crawl\w*|duckduckgo|serper|youtube|reddit|twitter|hacker[-_]?news|rss)", re.IGNORECASE)
COMM_RE = re.compile(r"(slack|gmail|e-?mail|smtp|sendgrid|twilio|discord|telegram|teams|whatsapp|mailgun|resend|"
                     r"github|gitlab|jira|linear|zapier|ifttt|n8n)", re.IGNORECASE)
PRIVATE_RE = re.compile(r"(filesystem|postgres|mysql|sqlite|mongo\w*|redis|supabase|neon|g?drive|google[-_]?drive|notion|obsidian|"
                        r"memory|gmail|slack|github|gitlab|1password|bitwarden|vault|aws|\bs3\b|kubernetes|k8s|stripe|salesforce|hubspot|"
                        r"airtable|sheets|calendar|contacts|\bsql\w*)", re.IGNORECASE)
FS_SERVER_RE = re.compile(r"(server-filesystem|mcp[-_]server[-_]filesystem|filesystem[-_]mcp|\bfilesystem\b)", re.IGNORECASE)
BROAD_PATH_RE = re.compile(r"^(/|~|~/|\$HOME|\$\{HOME\}|%USERPROFILE%|/home|/Users|/root|/etc|[A-Za-z]:\\?|[A-Za-z]:/)$")
SECRET_KEY_RE = re.compile(r"(token|secret|passw(or)?d|passwd|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential|authorization|bearer|cookie)", re.IGNORECASE)
TOKEN_PREFIX_RE = re.compile(r"^(ghp_|gho_|ghs_|github_pat_|glpat-|sk-|sk_live_|rk_live_|xox[abprs]-|AKIA|AIza|ya29\.|eyJ[A-Za-z0-9_-]{10,}\.|Bearer\s+\S{12,})")
PLACEHOLDER_RE = re.compile(r"(\$\{|\$[A-Za-z_]|%[A-Za-z_]+%|\{\{|<[^>]+>|^\$|your[-_ ]|xxx|changeme|placeholder|example|\*{3,}|\.\.\.|^env:|^secret:|^op://|^keychain:)", re.IGNORECASE)
CONN_CREDS_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]{3,}@", re.IGNORECASE)
DANGEROUS_TOOL_NAME_RE = re.compile(r"(exec|shell|bash|run|command|write|delete|remove|send|transfer|pay|refund|deploy|terminate|drop|push|merge|kill|rm\b)", re.IGNORECASE)
SKIP_PERMS_RE = re.compile(r"(dangerously[-_]skip[-_]permissions|--yolo\b|--no-confirm\b|--auto[-_]approve|--trust[-_]all)", re.IGNORECASE)
PIPE_SH_RE = re.compile(r"(curl|wget)[^|;&]*\|\s*(ba)?sh\b", re.IGNORECASE)

# tool-description poisoning
POISON_RES = [
    (re.compile(r"<\s*important\s*>|<\s*system\s*>|\[\s*system\s*\]", re.IGNORECASE), "pseudo-system tag"),
    (re.compile(r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|directions)", re.IGNORECASE), "override of prior instructions"),
    (re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify)\s+(the\s+)?user", re.IGNORECASE), "concealment from the user"),
    (re.compile(r"without\s+(telling|informing|notifying|alerting)\s+(the\s+)?user", re.IGNORECASE), "concealment from the user"),
    (re.compile(r"before\s+(using|calling|invoking)\s+this\s+tool[^.]{0,80}(read|open|cat|send|fetch|include)", re.IGNORECASE), "pre-call side-effect instruction"),
    (re.compile(r"(~/\.ssh|id_rsa|\.aws/credentials|/etc/passwd|\.env\b|mcp\.json|\.netrc)", re.IGNORECASE), "references secret files"),
    (re.compile(r"exfiltrat|send\s+(it|them|the\s+\w+)\s+to\s+(https?://|the\s+attacker)", re.IGNORECASE), "exfiltration wording"),
]
HIDDEN_CHARS_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")

# server-code sinks for model-controlled arguments
SHELL_RE = re.compile(r"(^|\.)(subprocess\.(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)|os\.(system|popen|spawn\w*|exec\w+)|"
                      r"asyncio\.create_subprocess_(shell|exec)|pty\.spawn|pexpect\.(spawn|run)|commands\.getoutput)$|^(Popen|check_output|check_call)$")
EVAL_RE = re.compile(r"^(eval|exec)$|(^|\.)(pickle\.loads?|marshal\.loads|dill\.loads|jsonpickle\.decode)$")
SQL_RE = re.compile(r"\.(execute|executemany|executescript|exec_driver_sql|raw)$|^text$")
FILE_READ_RE = re.compile(r"^open$|(^|\.)(read_text|read_bytes|open)$|os\.(listdir|scandir|walk)$|send_file$|FileResponse$")
FILE_WRITE_RE = re.compile(r"(^|\.)(write_text|write_bytes)$|os\.(remove|unlink|rmdir|rename|replace|makedirs|mkdir|chmod|chown)$|"
                           r"shutil\.(rmtree|copy\w*|move)$")
NET_RE = re.compile(r"^(requests|httpx|aiohttp|urllib\.request)\.(get|post|put|patch|delete|head|request|urlopen)$|^urlopen$")
# Hints that a path is confined to an allowed root ...
CONTAIN_RE = re.compile(r"(is_relative_to|commonpath|realpath|resolve|safe_join|secure_filename|"
                        r"allowed[_-]?(paths?|dirs?|roots?)|allow[_-]?list|whitelist|ALLOWED_\w+|base_dir|root_dir|startswith)", re.IGNORECASE)
# ... or that a URL's destination is validated (parsing a URL alone is NOT validation).
HOST_GUARD_RE = re.compile(r"(allowed[_-]?(hosts?|domains?|urls?)|allow[_-]?list|whitelist|ALLOWED_\w+|ipaddress|is_private|is_global|"
                           r"is_public|private[_-]?(ip|dest|addr)\w*|ssrf|blocklist|denylist)", re.IGNORECASE)
SHELL_GUARD_RE = re.compile(r"(shlex\.quote|allowed[_-]?commands?|allow[_-]?list|whitelist|ALLOWED_\w+)", re.IGNORECASE)
TOOLISH_DECORATOR_TAILS = {"tool", "resource", "call_tool", "tool_plain"}


def _finding(*, title, severity, capability, file_path, line, evidence, recommendation, consequence,
             confidence=0.8, chain=None, function="module", call_chain="", occurrence=1, snippet="",
             impact="HIGH", approval=False, ai_controlled=None, inferred=False) -> dict:
    return {
        "title": title, "severity": severity, "category": CATEGORY, "file_path": file_path, "line": int(line or 1),
        "capability": capability, "ai_provider": "MCP", "confidence": round(confidence, 2),
        "evidence": evidence, "recommendation": recommendation, "consequence": consequence,
        "impact_level": impact, "control_status": "Human approval present" if approval else "No guard detected",
        "ai_connected": True, "ai_controlled": ai_controlled, "control_confidence": round(confidence, 2),
        "capability_chain": chain or [], "function_name": function, "call_chain": call_chain or capability,
        "occurrence_index": occurrence, "human_approval_detected": approval, "limit_detected": False,
        "snippet": snippet, "inferred": inferred,
    }


def _mask(value: str) -> str:
    return (value[:4] + "…" + f"({len(value)} chars)") if len(value) > 6 else "…"


# ======================================================================= CONFIG
def is_config_path(path: str) -> bool:
    return posixpath.basename(path.replace("\\", "/")).lower() in CONFIG_NAMES


def looks_like_config(path: str, text: str) -> bool:
    if not path.lower().endswith(".json"):
        return False
    low = text.lower()
    if any(k in low for k in (k.lower() for k in CONFIG_KEYS)):
        return True
    return is_config_path(path) and '"command"' in low or (is_config_path(path) and '"url"' in low)


def _parse_json_lenient(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    cleaned = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    cleaned = re.sub(r"(?m)^\s*//.*$", "", cleaned)
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None


def _servers(data) -> dict:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "mcp_servers", "servers", "context_servers"):
        v = data.get(key)
        if isinstance(v, dict) and v and all(isinstance(x, dict) for x in v.values()):
            return v
    # nested (e.g. .claude.json projects -> mcpServers, or settings.json -> mcp.servers)
    for v in data.values():
        if isinstance(v, dict):
            inner = _servers(v)
            if inner:
                return inner
    return {}


def _line_of(text: str, needle: str) -> int:
    i = text.find(f'"{needle}"')
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def _pkg_pinned(cmd: str, args: list) -> tuple[bool, str] | None:
    """(pinned?, package) for npx/uvx/pipx/docker launchers, else None."""
    base = posixpath.basename(cmd.replace("\\", "/")).lower().removesuffix(".exe").removesuffix(".cmd")
    rest = [a for a in args if isinstance(a, str)]
    if base in {"npx", "bunx", "pnpx"} or (base in {"pnpm", "yarn", "bun"} and rest[:1] in (["dlx"], ["x"])):
        pk = next((a for a in rest if not a.startswith("-") and a not in {"dlx", "x"}), None)
        if not pk:
            return None
        name = pk[1:] if pk.startswith("@") else pk
        ver = name.split("@", 1)[1] if "@" in name else ""
        return bool(re.match(r"^\d", ver)), pk
    if base in {"uvx", "pipx"}:
        items = [a for a in rest if a not in {"run"}]
        pk = None
        for i, a in enumerate(items):
            if a == "--from" and i + 1 < len(items):
                pk = items[i + 1]; break
        pk = pk or next((a for a in items if not a.startswith("-")), None)
        if not pk:
            return None
        return bool(re.search(r"(==|@)\d", pk)), pk
    if base == "docker" and "run" in rest:
        imgs = [a for a in rest if not a.startswith("-") and a != "run" and ("/" in a or ":" in a or re.match(r"^[a-z0-9._-]+$", a))]
        img = imgs[-1] if imgs else None
        if not img:
            return None
        pinned = "@sha256:" in img or (":" in img.rsplit("/", 1)[-1] and not img.endswith(":latest"))
        return pinned, img
    return None


def analyze_config(path: str, text: str) -> list[dict]:
    data = _parse_json_lenient(text)
    servers = _servers(data)
    if not servers:
        return []
    out: list[dict] = []
    classes: dict[str, set] = {"ingest": set(), "private": set(), "comm": set(), "exec": set()}
    occ = 0

    def add(**kw):
        nonlocal occ
        occ += 1
        kw.setdefault("occurrence", occ)
        out.append(_finding(file_path=path, **kw))

    for name, cfg in servers.items():
        line = _line_of(text, name)
        cmd = cfg.get("command") if isinstance(cfg.get("command"), str) else ""
        args = [a for a in (cfg.get("args") or []) if isinstance(a, str)] if isinstance(cfg.get("args"), list) else []
        url = next((cfg[k] for k in ("url", "serverUrl", "httpUrl") if isinstance(cfg.get(k), str)), "")
        ident = " ".join([name, cmd, *args, url])
        chain = [f"MCP server '{name}'"]

        # classification for the trifecta
        if EXEC_SERVER_RE.search(ident):
            classes["exec"].add(name)
        if INGEST_RE.search(ident):
            classes["ingest"].add(name)
        if COMM_RE.search(ident):
            classes["comm"].add(name)
        if PRIVATE_RE.search(ident):
            classes["private"].add(name)

        # 1. plaintext credentials (never echoed)
        secret_sources = []
        for bag_name in ("env", "headers"):
            bag = cfg.get(bag_name)
            if isinstance(bag, dict):
                secret_sources += [(f"{bag_name}.{k}", k, v) for k, v in bag.items() if isinstance(v, str)]
        for label, key, v in secret_sources:
            if v and not PLACEHOLDER_RE.search(v) and (TOKEN_PREFIX_RE.search(v) or (SECRET_KEY_RE.search(key) and len(v) >= 12)):
                add(title=f"Plaintext credential in MCP config (server '{name}', {label})", severity="HIGH",
                    capability="mcp_plaintext_secret", line=line, function=name, call_chain=f"{name}.{label}",
                    evidence=[f"Value {_mask(v)} is stored in the file in clear text", "Anyone with repository access (or a leaked clone) gets this credential"],
                    recommendation="Remove the secret from the file and rotate it. Reference an environment variable or your secret manager instead (for example ${env:NAME} or a runtime prompt).",
                    consequence="A committed credential gives an attacker the same access the agent has.", chain=chain, confidence=0.9)
        for a in args:
            if CONN_CREDS_RE.search(a) or (re.match(r"^--?[\w-]*(token|secret|password|api[-_]?key)=\S{8,}", a, re.IGNORECASE) and not PLACEHOLDER_RE.search(a)):
                add(title=f"Credential embedded in MCP server arguments (server '{name}')", severity="HIGH",
                    capability="mcp_plaintext_secret", line=line, function=name, call_chain=f"{name}.args",
                    evidence=["A password/token appears in the command-line arguments (also visible in process listings)"],
                    recommendation="Pass secrets through environment variables or a secret manager and rotate the exposed value.",
                    consequence="Credentials in arguments leak through the repo, logs and `ps`.", chain=chain, confidence=0.85)
                break

        # 2. supply chain: unpinned launchers / pipe-to-shell
        pinned = _pkg_pinned(cmd, args) if cmd else None
        if pinned is not None and not pinned[0]:
            add(title=f"MCP server '{name}' is fetched unpinned at launch ({pinned[1]})", severity="MEDIUM",
                capability="mcp_unpinned_server", line=line, function=name, call_chain=f"{name}.launch",
                evidence=[f"Launcher resolves '{pinned[1]}' to whatever version is current each time it starts"],
                recommendation="Pin an exact version (package@1.2.3, pkg==1.2.3, or image@sha256:...) and review upgrades; a compromised or silently changed server can poison tool descriptions (a \"rug pull\").",
                consequence="An upstream change runs with your agent's permissions on next launch.", chain=chain, confidence=0.85)
        if PIPE_SH_RE.search(" ".join([cmd, *args])):
            add(title=f"MCP server '{name}' launches by piping a download into a shell", severity="HIGH",
                capability="mcp_unpinned_server", line=line, function=name, call_chain=f"{name}.pipe-to-shell",
                evidence=["Command line downloads and executes remote code"], recommendation="Install a pinned, verified package instead of executing a downloaded script.",
                consequence="Remote code runs unreviewed on every launch.", chain=chain, confidence=0.9)

        # 3. transport
        if url.lower().startswith("http://"):
            host = re.sub(r"^http://([^/:]+).*$", r"\1", url.lower())
            if host not in {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}:
                add(title=f"MCP server '{name}' is reached over unencrypted HTTP", severity="HIGH",
                    capability="mcp_insecure_transport", line=line, function=name, call_chain=f"{name}.url",
                    evidence=[f"Remote endpoint uses http:// ({host})"], recommendation="Use https:// (or a local stdio server) so tool calls, results and credentials cannot be read or altered in transit.",
                    consequence="Network attackers can read and rewrite tool traffic, including injected instructions.", chain=chain, confidence=0.9)

        # 4. dangerous server types
        if EXEC_SERVER_RE.search(ident):
            add(title=f"MCP server '{name}' gives the model shell or code execution", severity="HIGH",
                capability="mcp_dangerous_server", line=line, function=name, call_chain=f"{name}.exec",
                evidence=["Server name/package indicates command or code execution on the host"],
                recommendation="Remove it, or run it in a sandbox without credentials and require confirmation for every call.",
                consequence="Any prompt injection that reaches the model can run commands as you.", chain=chain + ["Shell / code execution"], confidence=0.7)
        if FS_SERVER_RE.search(ident):
            broad = [a for a in args if BROAD_PATH_RE.match(a.strip())]
            if broad:
                add(title=f"MCP filesystem server '{name}' is granted a very broad path ({broad[0]})", severity="HIGH",
                    capability="mcp_broad_filesystem", line=line, function=name, call_chain=f"{name}.fs",
                    evidence=[f"Allowed directory: {broad[0]}"], recommendation="Restrict it to the specific project directory the agent needs.",
                    consequence="The model can read (and usually write) keys, browser profiles and other users' files.", chain=chain + ["Filesystem access"], confidence=0.85)

        # 5. auto-approval / permission bypass
        auto = cfg.get("autoApprove") or cfg.get("alwaysAllow") or cfg.get("auto_approve") or cfg.get("always_allow")
        if isinstance(auto, list):
            risky = [t for t in auto if isinstance(t, str) and DANGEROUS_TOOL_NAME_RE.search(t)]
            if risky:
                add(title=f"Dangerous MCP tools are auto-approved for server '{name}'", severity="HIGH",
                    capability="mcp_auto_approve", line=line, function=name, call_chain=f"{name}.autoApprove",
                    evidence=["Auto-approved tools: " + ", ".join(risky[:6])], recommendation="Remove them from the auto-approve list so a human confirms each call.",
                    consequence="Prompt-injected instructions execute these tools with no human in the loop.", chain=chain + ["No confirmation"], confidence=0.85)
        if cfg.get("trust") is True:
            add(title=f"All tools of MCP server '{name}' run without confirmation (trust: true)", severity="HIGH",
                capability="mcp_auto_approve", line=line, function=name, call_chain=f"{name}.trust",
                evidence=["`trust: true` skips the client's tool-call confirmation prompts"], recommendation="Remove `trust: true` and approve sensitive tools individually.",
                consequence="Every tool this server exposes can be triggered by injected content silently.", chain=chain + ["No confirmation"], confidence=0.85)
        if SKIP_PERMS_RE.search(" ".join(args + [cmd])):
            add(title=f"MCP server '{name}' is launched with a permission-bypass flag", severity="HIGH",
                capability="mcp_auto_approve", line=line, function=name, call_chain=f"{name}.flags",
                evidence=["Arguments disable confirmation/permission checks"], recommendation="Remove the flag.",
                consequence="Safety prompts are disabled for this server.", chain=chain, confidence=0.8)

    # 6. combinations in one agent session
    names = lambda s: ", ".join(sorted(s)[:3])
    anchor = _line_of(text, "mcpServers") if '"mcpServers"' in text else 1
    if classes["ingest"] and classes["private"] and classes["comm"]:
        add(title="MCP config combines untrusted-content, private-data and outbound-communication servers (lethal trifecta)",
            severity="HIGH", capability="mcp_config_trifecta", line=anchor, function="mcpServers", call_chain="mcp.trifecta",
            evidence=[f"Untrusted content: {names(classes['ingest'])}", f"Private data: {names(classes['private'])}",
                      f"Outbound channel: {names(classes['comm'])}", "One agent session can use all three, so planted text can steer data out"],
            recommendation="Split these servers across separate agents/profiles, or remove one leg. Gate every outbound or write tool behind human approval.",
            consequence="A web page or message the agent reads can instruct it to leak private data through an outbound server.",
            chain=["Untrusted content server", "Model", "Private-data server", "Outbound server"], confidence=0.6)
    elif classes["ingest"] and classes["exec"]:
        add(title="MCP config lets untrusted content drive command execution (browser/fetch server + shell server)",
            severity="HIGH", capability="mcp_config_trifecta", line=anchor, function="mcpServers", call_chain="mcp.ingest-exec",
            evidence=[f"Untrusted content: {names(classes['ingest'])}", f"Execution: {names(classes['exec'])}"],
            recommendation="Do not give an agent that reads web/untrusted content a shell or code-execution server.",
            consequence="A malicious page can instruct the model to run commands on the host.",
            chain=["Untrusted content server", "Model", "Shell / code execution"], confidence=0.6)
    return out


# ================================================================= SERVER CODE
class _ToolFlow(_Flow):
    """Taint pass where tool arguments are the sources and dangerous calls are the sinks."""

    def __init__(self, fa, fn_name, params, hits):
        super().__init__(fa, fn_name, params)
        self.hits = hits

    HTTP_CLIENT_NAMES = {"client", "session", "http", "http_client", "httpx_client", "async_client", "aiohttp_session", "c"}

    def _http_client_call(self, chain: str) -> bool:
        parts = chain.split(".")
        if len(parts) != 2 or parts[1] not in {"get", "post", "put", "patch", "request", "head", "delete", "stream"}:
            return False
        if parts[0] in self.fa.http_vars:
            return True
        # client created by a helper (make_client()) or `async with ... as client`
        return parts[0] in self.HTTP_CLIENT_NAMES and bool(re.search(r"\b(httpx|aiohttp|requests|urllib3)\b", self.fa.source_text))

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        chain = _chain(node.func)
        if not chain:
            return
        bare = chain.split(".")[0]
        callee = chain if chain in self.fa.functions else (bare if bare in self.fa.functions and "." not in chain else "")
        if callee:
            self.local_calls.append((callee, node))
        arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
        t = self._union(arg_nodes)
        if isinstance(node.func, ast.Attribute):
            t = t + [x for x in self.taint(node.func.value) if x not in t]
        if not t:
            return
        first = node.args[0] if node.args else None
        first_t = self.taint(first) if first is not None else []
        line = node.lineno
        src = t[0]

        def hit(kind, **extra):
            self.hits.append({"kind": kind, "line": line, "chain": chain, "function": self.fn, "taint": src, **extra})

        if SHELL_RE.search(chain):
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            direct = bool(first_t) and not isinstance(first, (ast.List, ast.Tuple))
            hit("shell", severity="CRITICAL" if (shell_true or direct or "system" in chain or "popen" in chain) else "HIGH")
        elif EVAL_RE.search(chain):
            hit("eval", severity="CRITICAL")
        elif SQL_RE.search(chain) and first is not None and first_t:
            constant_first = isinstance(first, ast.Constant)
            if not constant_first:
                built = isinstance(first, (ast.JoinedStr, ast.BinOp)) or (isinstance(first, ast.Call) and _chain(first.func).endswith("format"))
                hit("sql", severity="HIGH" if built else "MEDIUM", built=built)
        elif FILE_WRITE_RE.search(chain) and (first_t or t):
            hit("file_write", severity="HIGH")
        elif FILE_READ_RE.search(chain) and (first_t or t):
            mode = ""
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = str(node.args[1].value)
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = str(kw.value.value)
            if chain == "open" and any(c in mode for c in "wax+"):
                hit("file_write", severity="HIGH")
            else:
                hit("file_read", severity="MEDIUM")
        elif (NET_RE.search(chain) or self._http_client_call(chain)) \
                and (first_t or any(self.taint(kw.value) for kw in node.keywords if kw.arg == "url")):
            hit("ssrf", severity="MEDIUM")


def _local_destructive(fn, approval: bool) -> list:
    """Destructive operations the shared capability rules do not know (file deletion/writes, shell, eval)."""
    from .injection_analyzer import Capability
    found = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        chain = _chain(node.func)
        if not chain:
            continue
        op = None
        if FILE_WRITE_RE.search(chain):
            op = ("DATA", "write")
        elif chain == "open" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) \
                and any(c in str(node.args[1].value) for c in "wax+"):
            op = ("DATA", "write")
        elif SHELL_RE.search(chain):
            op = ("INFRASTRUCTURE", "execute")
        elif EVAL_RE.search(chain):
            op = ("INFRASTRUCTURE", "execute")
        if op:
            found.append(Capability("DANGEROUS", op[0], op[1], node.lineno, chain, approval, f"tool:{fn.name}"))
    return found


def _decorator_info(fn) -> tuple[str | None, ast.Call | None]:
    for dec in fn.decorator_list:
        chain = _chain(dec.func if isinstance(dec, ast.Call) else dec)
        tail = chain.split(".")[-1]
        if tail in TOOLISH_DECORATOR_TAILS or TOOL_DECORATOR_RE.search(chain):
            return tail, dec if isinstance(dec, ast.Call) else None
    return None, None


def _annotations(dec: ast.Call | None) -> dict:
    found: dict = {}
    if dec is None:
        return found
    for node in ast.walk(dec):
        if isinstance(node, ast.keyword) and node.arg in {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}:
            if isinstance(node.value, ast.Constant):
                found[node.arg] = node.value.value
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value in {"readOnlyHint", "destructiveHint"} and isinstance(v, ast.Constant):
                    found[k.value] = v.value
    return found


def _description_texts(fn, dec: ast.Call | None) -> list[tuple[str, int]]:
    texts = []
    doc = ast.get_docstring(fn, clean=False)
    if doc:
        texts.append((doc, fn.lineno))
    if dec is not None:
        for kw in dec.keywords:
            if kw.arg in {"description", "title", "instructions"} and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                texts.append((kw.value.value, getattr(kw.value, "lineno", fn.lineno)))
    return texts


def analyze_server_code(path: str, text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError, ValueError):
        return []
    fa = _FileAnalysis(path, text, tree)
    fa.source_text = text
    tools = []
    for fn in fa.functions.values():
        kind, dec = _decorator_info(fn)
        if kind:
            tools.append((fn, kind, dec))
    if not tools:
        return []

    out: list[dict] = []
    classes = {"private": [], "comm": [], "ingest": []}
    occ = 0

    for fn, kind, dec in tools:
        occ += 1
        label = "resource" if kind == "resource" else "tool"
        name = fn.name
        chain = [f"MCP {label} '{name}'"]
        approval = fn.name in fa.approval_functions
        names_in_fn = _names_and_strings(fn)
        guarded_path = any(CONTAIN_RE.search(n) for n in names_in_fn)
        guarded_host = any(HOST_GUARD_RE.search(n) for n in names_in_fn)
        guarded_shell = any(SHELL_GUARD_RE.search(n) for n in names_in_fn)

        # --- model-controlled arguments reaching dangerous sinks
        params = {}
        for arg in fn.args.args + fn.args.kwonlyargs:
            if arg.arg in {"self", "cls", "ctx", "context", "session"}:
                continue
            ann = ast.unparse(arg.annotation) if arg.annotation is not None else ""
            if ann.endswith("Context") or ann.endswith("Session"):
                continue
            params[arg.arg] = [Taint("tool_argument", f"MCP {label} argument '{arg.arg}'", fn.lineno, True, 0.85)]
        if fn.args.vararg:
            params[fn.args.vararg.arg] = [Taint("tool_argument", "MCP tool arguments", fn.lineno, True, 0.8)]
        hits: list[dict] = []
        helper_names: set[str] = set()

        def run_flow(func, seeds, depth, visited):
            flow = _ToolFlow(fa, func.name, seeds, hits)
            before = len(hits)
            for stmt in func.body:
                flow.visit(stmt)
            if func is not fn:
                helper_names.update(_names_and_strings(func))
                for h in hits[before:]:
                    h["helper"] = func.name
            if depth >= 2:
                return
            for callee, call in flow.local_calls:
                target = fa.functions.get(callee)
                if target is None or target is fn or callee in visited:
                    continue
                plist = [a.arg for a in target.args.args if a.arg not in {"self", "cls"}]
                bound = {}
                for pname, argnode in zip(plist, call.args):
                    tt = flow.taint(argnode)
                    if tt:
                        bound[pname] = tt
                for kw in call.keywords:
                    if kw.arg in plist:
                        tt = flow.taint(kw.value)
                        if tt:
                            bound[kw.arg] = tt
                if bound:
                    run_flow(target, bound, depth + 1, visited | {callee})

        run_flow(fn, params, 0, set())
        guarded_path = guarded_path or any(CONTAIN_RE.search(n) for n in helper_names)
        guarded_host = guarded_host or any(HOST_GUARD_RE.search(n) for n in helper_names)
        guarded_shell = guarded_shell or any(SHELL_GUARD_RE.search(n) for n in helper_names)

        seen = set()
        for h in hits:
            key = (h["kind"], h["line"])
            if key in seen:
                continue
            seen.add(key)
            sev = h["severity"]
            arg = h["taint"].label
            mitig = []
            if h["kind"] == "shell" and guarded_shell:
                sev = SEV[max(0, SEV.index(sev) - 2)]; mitig.append("allow-list/quoting hint present")
            if (h["kind"] == "file_read" and guarded_path) or (h["kind"] == "ssrf" and guarded_host):
                continue            # path contained or destination validated: not a finding
            if h["kind"] == "file_write" and guarded_path:
                sev = SEV[max(0, SEV.index(sev) - 2)]; mitig.append("path containment hint present")
            if approval:
                sev = SEV[max(0, SEV.index(sev) - 1)]; mitig.append("human approval present")
            if label == "resource" and h["kind"] == "file_read" and not guarded_path:
                sev = "HIGH"
            cfg = {
                "shell": ("mcp_command_injection", f"MCP {label} '{name}' passes a model-controlled value to a shell command",
                          "Never build commands from tool arguments. Use a fixed program with an allow-list of subcommands and structured arguments (no shell=True), and require approval.",
                          "A prompt-injected model can run arbitrary commands with the server's permissions."),
                "eval": ("mcp_code_injection", f"MCP {label} '{name}' evaluates model-controlled input as code",
                         "Remove eval/exec/unpickling of tool input. Parse with a strict, data-only format.",
                         "A prompt-injected model can execute arbitrary code in the server process."),
                "sql": ("mcp_sql_injection",
                        f"MCP {label} '{name}' builds SQL from a model-controlled value" if h.get("built")
                        else f"MCP {label} '{name}' runs model-supplied SQL",
                        "Use parameterised queries, and give the server a read-only database role limited to the tables it needs.",
                        "A prompt-injected model can read or change data far beyond the tool's purpose."),
                "file_read": ("mcp_path_traversal", f"MCP {label} '{name}' reads a model-controlled file path without containment",
                              "Resolve the path and verify it stays inside an allowed root (Path.resolve().is_relative_to(root)); reject absolute paths and '..'.",
                              "A prompt-injected model can read SSH keys, tokens and other local files."),
                "file_write": ("mcp_path_traversal", f"MCP {label} '{name}' writes or deletes a model-controlled file path without containment",
                               "Confine writes to a dedicated directory, validate the resolved path, and require approval for destructive operations.",
                               "A prompt-injected model can overwrite or delete arbitrary files."),
                "ssrf": ("mcp_ssrf", f"MCP {label} '{name}' fetches a model-controlled URL without a host allow-list",
                         "Allow-list hosts/schemes and block private, loopback and link-local addresses (including after redirects).",
                         "A prompt-injected model can reach internal services and cloud metadata endpoints."),
            }[h["kind"]]
            evidence = [f"Source: {arg} (model-controlled; an attacker can steer it through any content the model reads)",
                        f"Sink: {h['chain']}() at line {h['line']}" + (f", reached through helper '{h['helper']}'" if h.get("helper") else "")]
            if h["kind"] == "sql" and not h.get("built"):
                evidence.append("The whole query comes from the model")
            evidence.append("Mitigation noted: " + ", ".join(mitig) if mitig else "No input validation or containment detected in this function")
            out.append(_finding(
                title=cfg[1], severity=sev, capability=cfg[0], file_path=path, line=h["line"],
                evidence=evidence, recommendation=cfg[2], consequence=cfg[3],
                confidence=0.8 if not mitig else 0.6, chain=chain + [h["chain"] + "()"], function=name,
                call_chain=f"tool_argument->{h['chain']}", occurrence=occ,
                snippet=text.splitlines()[h["line"] - 1].strip() if 0 < h["line"] <= len(text.splitlines()) else "",
                approval=approval, ai_controlled=True))

        # --- capabilities, annotations
        caps = fa.capabilities_of(fn, f"tool:{name}")
        caps += _local_destructive(fn, approval)
        danger = [c for c in caps if c.cls == "DANGEROUS"]
        live = [c for c in danger if not c.controlled]
        # A fixed command (e.g. `git status`) is not what the annotations are about: only report
        # execution when a model-controlled value reaches it.
        if not any(h["kind"] in {"shell", "eval"} for h in hits):
            live = [c for c in live if c.operation != "execute"]
        if any(c.cls == "PRIVATE_DATA" for c in caps):
            classes["private"].append(name)
        if any(c.cls == "EXTERNAL_COMM" for c in caps):
            classes["comm"].append(name)
        if any((s := fa.source_of_call(c)) and s.indirect for c in ast.walk(fn) if isinstance(c, ast.Call)):
            classes["ingest"].append(name)
        ann = _annotations(dec)
        if live and label == "tool":
            c0 = live[0]
            if ann.get("readOnlyHint") is True:
                out.append(_finding(
                    title=f"MCP tool '{name}' is declared read-only but performs {c0.category.lower()}/{c0.operation}",
                    severity="HIGH", capability="mcp_misleading_annotation", file_path=path, line=c0.line,
                    evidence=["Annotation readOnlyHint=True tells clients the tool is safe to auto-approve",
                              f"Body calls {c0.chain}() at line {c0.line}"],
                    recommendation="Correct the annotation (destructiveHint=True, readOnlyHint=False) so clients ask the user before calling it.",
                    consequence="Clients may skip confirmation because the tool claims to be read-only.", confidence=0.85,
                    chain=chain + [c0.chain + "()"], function=name, call_chain=f"{name}.annotations", occurrence=occ, ai_controlled=True))
            elif not ann:
                out.append(_finding(
                    title=f"MCP tool '{name}' performs {c0.category.lower()}/{c0.operation} but declares no destructive annotation",
                    severity="MEDIUM", capability="mcp_tool_annotations", file_path=path, line=c0.line,
                    evidence=[f"Body calls {c0.chain}() at line {c0.line}", "No readOnlyHint/destructiveHint annotation and no approval step in the tool"],
                    recommendation="Add annotations (destructiveHint=True) and an explicit confirmation step so clients can prompt the user.",
                    consequence="Clients cannot tell this tool is dangerous, so it may be auto-approved.", confidence=0.7,
                    chain=chain + [c0.chain + "()"], function=name, call_chain=f"{name}.annotations", occurrence=occ, ai_controlled=True))

        # --- hidden instructions in the tool's own description
        for desc, dline in _description_texts(fn, dec):
            reasons = [r for rx, r in POISON_RES if rx.search(desc)]
            hidden = HIDDEN_CHARS_RE.findall(desc)
            if hidden:
                reasons.append(f"{len(hidden)} invisible/bidirectional control character(s)")
            if reasons:
                out.append(_finding(
                    title=f"MCP {label} '{name}' description contains hidden or manipulative instructions (tool poisoning)",
                    severity="HIGH", capability="mcp_tool_poisoning", file_path=path, line=dline,
                    evidence=["Indicators: " + "; ".join(dict.fromkeys(reasons)), "The model reads this text as trusted instructions, but users rarely see it"],
                    recommendation="Remove instructions from tool descriptions; describe only what the tool does. Review third-party servers' descriptions before enabling them.",
                    consequence="Descriptions steer the model silently, enabling data theft and unwanted actions.",
                    confidence=0.7 if not hidden else 0.85, chain=chain, function=name, call_chain=f"{name}.description",
                    occurrence=occ, ai_controlled=True))
                break

    if classes["private"] and classes["comm"] and classes["ingest"]:
        out.append(_finding(
            title="This MCP server alone completes the lethal trifecta (untrusted content + private data + outbound channel)",
            severity="HIGH", capability="mcp_server_trifecta", file_path=path, line=tools[0][0].lineno,
            evidence=[f"Fetches untrusted content: {', '.join(classes['ingest'][:3])}", f"Reads private data: {', '.join(classes['private'][:3])}",
                      f"Sends data out: {', '.join(classes['comm'][:3])}"],
            recommendation="Split the server, or require approval on the outbound/write tools, so one connection cannot read private data and send it where injected content says.",
            consequence="Any client that connects exposes the full exfiltration path.", confidence=0.6,
            chain=["Untrusted content tool", "Model", "Private-data tool", "Outbound tool"], function="server",
            call_chain="server.trifecta", occurrence=occ + 1, ai_controlled=True))
    return out


# ------------------------------------------------------------- JS/TS (lead only)
JS_TOOL_RE = re.compile(r"""\b(?:server|mcp|mcpServer)\s*\.\s*(?:tool|registerTool)\s*\(\s*['"`]([\w\-.:/]+)['"`]""")
JS_DANGER_RE = re.compile(r"child_process|\bexecSync?\s*\(|\bspawnSync?\s*\(|\beval\s*\(|fs(?:\.promises)?\.(?:writeFile|unlink|rm|rmdir|appendFile)|"
                          r"\bfetch\s*\(\s*(?:args|input|params)\b|\bfetch\s*\(\s*`")


def analyze_js_server(path: str, text: str) -> list[dict]:
    out = []
    for i, m in enumerate(JS_TOOL_RE.finditer(text), 1):
        window = text[m.end(): m.end() + 2500]
        nxt = JS_TOOL_RE.search(window)
        if nxt:
            window = window[: nxt.start()]
        d = JS_DANGER_RE.search(window)
        if d:
            line = text.count("\n", 0, m.start()) + 1
            out.append(_finding(
                title=f"MCP tool '{m.group(1)}' appears to use a shell, file write or model-controlled fetch (heuristic)",
                severity="MEDIUM", capability="mcp_tool_heuristic", file_path=path, line=line,
                evidence=[f"Pattern '{d.group(0).strip()[:40]}' inside the tool handler; no data-flow verification for JS/TS"],
                recommendation="Verify whether tool arguments reach this call; validate and contain them, and require approval for destructive actions.",
                consequence="A prompt-injected model may control the arguments.", confidence=0.4,
                chain=[f"MCP tool '{m.group(1)}'"], function=m.group(1), call_chain="heuristic", occurrence=i, inferred=True))
    return out


# --------------------------------------------------------------- public API
MCP_CODE_HINTS = ("fastmcp", "mcp.server", "from mcp", "import mcp", "modelcontextprotocol", "McpServer", "FastMCP")


def wants_file(path: str, text: str) -> str | None:
    """Cheap pre-filter: which analysis (if any) applies to this file."""
    if len(text) > MAX_BYTES:
        return None
    p = path.lower()
    if p.endswith(".json") and looks_like_config(path, text):
        return "config"
    if p.endswith(".py") and any(h in text for h in MCP_CODE_HINTS):
        return "py"
    if p.endswith((".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx")) and "modelcontextprotocol" in text:
        return "js"
    return None


def analyze_candidates(candidates: list[tuple[str, str, str]], gate) -> list[dict]:
    """candidates: (path, text, kind). ``gate(finding, analysis)`` applies the shared scoring gate."""
    out: list[dict] = []
    for path, text, kind in candidates:
        try:
            if kind == "config":
                found, used_ast = analyze_config(path, text), True
            elif kind == "py":
                found, used_ast = analyze_server_code(path, text), True
            else:
                found, used_ast = analyze_js_server(path, text), False
        except Exception:                      # a parser bug must never fail the scan
            continue
        shim = SimpleNamespace(used_ast=used_ast, file_path=path)
        for f in found:
            f = gate(f, shim)
            if f.pop("inferred", False) and f.get("scored", True):
                f["scored"] = False
                f["severity"] = "LOW"
                f["potential_points"] = 0
                f["title"] = f"Potential capability detected: {f['title']}"
                f["evidence"] = ["⚠️ Not scored (heuristic, no data-flow verification for JavaScript/TypeScript)."] + f["evidence"]
            out.append(f)
    return out