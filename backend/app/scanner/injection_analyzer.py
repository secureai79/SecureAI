"""Prompt-injection reachability analysis.

The existing engine answers "can AI *output* reach a dangerous action?".
This module answers the question attackers actually exploit:

    can UNTRUSTED CONTENT reach the model, and what can the model then do?

For every Python file that uses an AI SDK it:

1. finds untrusted sources (HTTP request data, interactive input, fetched web
   pages, e-mail/chat messages, retrieved RAG documents, loaded files,
   third-party issue/ticket text);
2. traces them with an intraprocedural forward taint pass (plus one-hop
   interprocedural seeding) into the arguments of model calls;
3. resolves what the model is able to do at that call: the tools it is given
   (OpenAI-style ``tools=``, LangChain/CrewAI/MCP decorated tools, agent
   constructors) and any dangerous call that consumes the model's output;
4. classifies reachable capabilities as DANGEROUS (money, infra, destructive
   data, code), EXTERNAL_COMM (anything that sends data out) or PRIVATE_DATA;
5. reports the "lethal trifecta" -- untrusted content + private data +
   outbound channel reachable from one prompt -- as the top-severity case.

Like the rest of the scanner this is deterministic static analysis: it is an
approximation (no full points-to analysis), it never executes scanned code, and
results are labelled with confidence. It is meant to surface high-value leads
and to be conservative about severity, not to prove exploitability.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field, replace

from .ast_detector import (
    AI_AGENT_CONSTRUCTORS,
    AI_CALL_METHOD_SUFFIXES,
    AI_CLIENT_CONSTRUCTORS,
    APPROVAL_NAME_HINTS,
    DANGEROUS_CHAIN_RULES,
    SQL_DANGEROUS_RE,
)

MAX_SOURCE_BYTES = 400_000

# ----------------------------------------------------------------- vocab
KIND_META = {
    "http_request": ("HTTP request data", False),
    "user_input": ("interactive user input", False),
    "web_content": ("fetched web content", True),
    "email_or_message": ("email/chat message content", True),
    "retrieved_document": ("retrieved (RAG) document text", True),
    "loaded_document": ("loaded file/document text", True),
    "third_party_content": ("third-party issue/ticket/comment text", True),
}

AGENT_EXTRA = {
    "CodeAgent": "smolagents", "ToolCallingAgent": "smolagents", "LlmAgent": "Google ADK",
    "SequentialAgent": "Google ADK", "ParallelAgent": "Google ADK", "FunctionAgent": "LlamaIndex",
    "AgentWorkflow": "LlamaIndex", "ChatAgent": "CAMEL",
    "create_react_agent": "LangChain", "create_openai_functions_agent": "LangChain",
    "create_tool_calling_agent": "LangChain", "create_openai_tools_agent": "LangChain",
    "AssistantAgent": "AutoGen", "ReActAgent": "LlamaIndex", "FunctionAgent": "LlamaIndex",
    "OpenAIAgent": "LlamaIndex",
}
AI_METHODS = set(AI_CALL_METHOD_SUFFIXES) | {
    "print_response", "aprint_response", "run_async", "run_live", "achat", "astream_chat", "stream_chat",
    "ainvoke", "astream", "stream", "acreate", "send_message", "run_sync", "arun",
    "kickoff_async", "apredict", "chat_completion", "run_stream",
}
AI_CHAIN_RE = re.compile(
    r"(chat\.completions\.create|messages\.create|responses\.create|generate_content(_async)?|"
    r"litellm\.(a)?completion|ollama\.(chat|generate)|Runner\.run(_sync)?|"
    r"ChatCompletion\.(a)?create|\bCompletion\.(a)?create)$"
)
# kwargs that configure the call and are not part of the prompt
CONFIG_KWARGS = {
    "model", "temperature", "max_tokens", "max_completion_tokens", "top_p", "top_k", "stream",
    "n", "seed", "stop", "tools", "tool_choice", "functions", "function_call", "response_format",
    "timeout", "api_key", "user", "metadata", "frequency_penalty", "presence_penalty",
    "stream_options", "logprobs", "max_retries", "verbose", "memory",
}
TOOL_DECORATOR_RE = re.compile(
    r"(^|\.)(tool|tool_plain|function_tool|kernel_function|register_function|register_for_llm|"
    r"mcp_tool|agent_tool|structured_tool)$"
)
MCP_TOOL_RE = re.compile(r"\.tool$")
ROUTE_DECORATOR_RE = re.compile(r"\.(get|post|put|patch|delete|route|websocket|api_route|on_event)$")
NON_PROMPT_PARAMS = {"self", "cls", "request", "response", "req", "res", "db", "session", "background_tasks",
                     "current_user", "user", "background", "ctx", "context"}

HTTP_ATTR_RE = re.compile(
    r"^(flask\.)?(request|req)\.(json|args|form|data|values|files|headers|cookies|body|get_json|"
    r"query_params|path_params|stream|get_data)$"
)
WEB_CALL_RE = re.compile(
    r"(^|\.)(requests|httpx|aiohttp|urllib3|urllib\.request)\.(get|post|put|request|fetch|urlopen)$|"
    r"(^|\.)urlopen$|(^|\.)(WebBaseLoader|AsyncHtmlLoader|AsyncChromiumLoader|UnstructuredURLLoader|"
    r"SeleniumURLLoader|PlaywrightURLLoader|RecursiveUrlLoader)\.|(^|\.)trafilatura\.(fetch_url|extract)$|"
    r"(^|\.)feedparser\.parse$|(^|\.)BeautifulSoup$|(^|\.)page\.(content|inner_text|text_content|inner_html)$|"
    r"(^|\.)(tavily|serper|serpapi|duckduckgo|ddg|brave|exa|googlesearch)\w*\.(search|run|invoke|results|text)$"
)
EMAIL_CALL_RE = re.compile(
    r"imap|pop3|poplib|gmail|outlook|\.messages\.(get|list)$|conversations_(history|replies)|"
    r"message_from_(bytes|string|file)$|fetch_(emails?|messages?|inbox)|read_(emails?|inbox)|get_(emails?|inbox)",
    re.IGNORECASE,
)
RAG_METHODS = {
    "similarity_search", "similarity_search_with_score", "similarity_search_by_vector",
    "max_marginal_relevance_search", "get_relevant_documents", "aget_relevant_documents", "retrieve",
}
RAG_BASE_RE = re.compile(r"(retriever|vectorstore|vector_store|vectordb|vdb|chroma|pinecone|qdrant|faiss|"
                         r"weaviate|milvus|rag|knowledge|kb|index|docsearch)", re.IGNORECASE)
RAG_GENERIC_METHODS = {"query", "search", "invoke", "ainvoke", "run", "as_query_engine"}
DOC_LOADER_RE = re.compile(
    r"(PyPDFLoader|PyMuPDFLoader|PDFPlumberLoader|UnstructuredFileLoader|UnstructuredPDFLoader|TextLoader|"
    r"CSVLoader|DirectoryLoader|Docx2txtLoader|DocxLoader|UnstructuredWordDocumentLoader|S3FileLoader|"
    r"GCSFileLoader|NotionDBLoader|ConfluenceLoader|GitLoader|GithubFileLoader|SlackDirectoryLoader|"
    r"JSONLoader|SimpleDirectoryReader|PDFReader)\.(load|lazy_load|load_data|aload|load_and_split)$"
)
THIRD_PARTY_CALL_RE = re.compile(
    r"get_(issue|pull|pr|ticket|comments?|review|discussion|conversation)\b|list_(issues|comments|tickets|reviews)\b|"
    r"\b(jira|zendesk|intercom|freshdesk|helpscout|servicenow)\w*\.", re.IGNORECASE)
THIRD_PARTY_NAMES = {"issue", "pr", "pull_request", "ticket", "comment", "review", "email", "mail"}
THIRD_PARTY_ATTRS = {"body", "title", "text", "content", "description", "subject", "html", "plain"}

HTTP_CLIENT_CTORS = {"Session", "ClientSession", "Client", "AsyncClient", "PoolManager"}
SANITIZER_RE = re.compile(
    r"(sanitize|sanitise|escape_prompt|strip_injection|detect_injection|prompt_injection|injection_check|"
    r"guardrail|llm_guard|llm-guard|rebuff|lakera|nemoguardrails|promptguard|prompt_guard|"
    r"validate_(input|prompt|content)|check_(prompt|input|content)|moderat(e|ion)|"
    r"scan_prompt|content_filter|safe_prompt)",
    re.IGNORECASE,
)

EXTERNAL_COMM_RE = re.compile(
    r"smtplib|sendmail|send_(email|mail|message|sms|dm|tweet|webhook|notification)|post_message|"
    r"chat_postMessage|chat\.post|webhooks?|\b(requests|httpx|aiohttp|session|client|http)\.(post|put|patch|request)\b|"
    r"urlopen|tweet|twilio|sendgrid|ses\.send|sns\.publish|slack\w*\.|discord\w*\.|telegram\w*\.|"
    r"mailgun|postmark|messages\.create|create_comment|add_comment|create_issue|upload_file|put_object|"
    r"requests\.post|ftp\w*\.(storbinary|put)",
    re.IGNORECASE,
)
PRIVATE_DATA_RE = re.compile(
    r"\b(read_file|read_text|read_bytes|get_secret|get_customer|get_user|get_account|get_order|fetch_record|"
    r"list_(customers|users|accounts|orders|files)|query_(db|database|customers|users)|search_(customers|users|crm|database)|"
    r"os\.environ|os\.getenv|getenv|get_object|download_file|read_sheet|get_document|read_document)\b|"
    r"\.(find|find_one|fetchall|fetchone|fetchmany|read|get_item)$|(^|\.)open$|"
    r"(secretsmanager|ssm|vault|keyring)\w*\.|(crm|salesforce|hubspot|customer|patient|payroll)\w*\.",
    re.IGNORECASE,
)

ACTION_PHRASES = {
    ("FINANCIAL", "refund"): "issuing refunds", ("FINANCIAL", "charge"): "creating charges",
    ("FINANCIAL", "transfer"): "moving money", ("FINANCIAL", "payout"): "triggering payouts",
    ("DATA", "execute_sql"): "running database commands",
    ("DATA", "delete"): "deleting data", ("DATA", "write"): "writing or deleting files", ("DATA", "drop"): "dropping tables",
    ("INFRASTRUCTURE", "execute"): "running shell commands",
    ("INFRASTRUCTURE", "terminate"): "terminating infrastructure",
    ("INFRASTRUCTURE", "deploy"): "triggering deployments",
    ("CODE", "merge"): "merging code", ("CODE", "push"): "pushing code",
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Well-known framework tools. Agent frameworks wire these together internally, so the
# flow "web page -> model -> email" never appears as a variable in the user's code.
KNOWN_INGEST_TOOLS = re.compile(
    r"^(SerperDevTool|SerperScrapeWebsiteTool|ScrapeWebsiteTool|WebsiteSearchTool|ScrapeElementFromWebsiteTool|"
    r"FirecrawlScrapeWebsiteTool|FirecrawlSearchTool|FirecrawlCrawlWebsiteTool|SeleniumScrapingTool|BrowserbaseLoadTool|"
    r"TavilySearchResults|TavilySearch|TavilySearchResultsTool|TavilyExtractorTool|DuckDuckGoSearch\w*|GoogleSearch\w*|"
    r"GoogleSerper\w*|BraveSearch\w*|ExaSearch\w*|EXASearchTool|SerpApi\w*|RequestsGetTool|RequestsToolkit|"
    r"PlayWrightBrowserToolkit|NavigateTool|ExtractTextTool|ExtractHyperlinksTool|GetElementsTool|"
    r"GmailToolkit|GmailGetMessage|GmailGetThread|GmailSearch|SlackGetMessage|SlackGetChannel|"
    r"WikipediaQueryRun|ArxivQueryRun|PubmedQueryRun|YouTubeSearchTool|YoutubeVideoSearchTool|YoutubeChannelSearchTool|"
    r"LinkupSearchTool|GithubSearchTool|RagTool|PDFSearchTool|DOCXSearchTool|CSVSearchTool|MDXSearchTool|"
    r"TXTSearchTool|JSONSearchTool|DirectorySearchTool|XMLSearchTool|CodeDocsSearchTool|WebBaseLoader)$"
)
KNOWN_COMM_TOOLS = re.compile(
    r"^(GmailSendMessage|GmailCreateDraft|SlackSendMessage|RequestsPostTool|RequestsPatchTool|RequestsPutTool|"
    r"SendGrid\w*|Twilio\w*|GithubCreateComment|CreateIssueTool|ZapierNLA\w*|TwitterTool|DiscordTool|"
    r"EmailTool|SendEmailTool|SMTPTool|SlackTool|NotifyTool)$"
)
KNOWN_EXEC_TOOLS = re.compile(
    r"^(ShellTool|BashProcess|BashTool|TerminalTool|PythonREPLTool|PythonREPL|PythonAstREPLTool|CodeInterpreterTool|"
    r"ComputerTool|ComputerUseTool|DockerTool)$"
)
KNOWN_FILEWRITE_TOOLS = re.compile(
    r"^(WriteFileTool|FileWriterTool|DeleteFileTool|MoveFileTool|CopyFileTool|FileManagementToolkit)$"
)
# Tool definitions that live in another file can only be judged by name. Used for
# low-confidence, unscored leads -- never for scored findings.
INFER_INGEST_NAME = re.compile(
    r"(scrape|browse|browser|crawl|fetch_(url|page|web)|web_?search|search_(internet|web)|read_?(emails?|inbox)|"
    r"get_?(emails?|inbox)|read_?url|open_?url|http_?get)", re.IGNORECASE)
INFER_COMM_NAME = re.compile(r"^(send_?(email|mail|message|sms)|post_?(message|tweet|comment)|notify\w*|email_\w+)$", re.IGNORECASE)
INFER_DANGER_NAME = re.compile(
    r"^(execute\w*|run_?(command|shell|code|script)|shell\w*|transfer\w*|refund\w*|pay\w*|delete\w*|drop_?\w*|"
    r"deploy\w*|terminate\w*|write_?file|merge\w*|push\w*)$", re.IGNORECASE)
KNOWN_PRIVATE_TOOLS = re.compile(
    r"^(FileReadTool|DirectoryReadTool|ReadFileTool|ListDirectoryTool|SQLDatabaseToolkit|QuerySQLDataBaseTool|"
    r"QuerySQLDatabaseTool|InfoSQLDatabaseTool|DatabaseTool|NL2SQLTool|SQLTool|S3ReaderTool|"
    r"GmailGetMessage|GmailGetThread|GmailSearch|GmailToolkit|GithubToolkit|SalesforceTool|HubspotTool)$"
)
KNOWN_ROLE_LABELS = {
    ("DANGEROUS", "INFRASTRUCTURE"): "execute", ("DANGEROUS", "CODE"): "write",
}


# ------------------------------------------------------------- data types
@dataclass(frozen=True)
class Taint:
    kind: str
    label: str
    line: int
    indirect: bool
    confidence: float = 0.8
    via_model: bool = False
    via_tool: str = ""


@dataclass
class Capability:
    cls: str            # DANGEROUS | EXTERNAL_COMM | PRIVATE_DATA
    category: str
    operation: str
    line: int
    chain: str
    controlled: bool = False
    via: str = ""       # "tool:<name>" or "model-output"


@dataclass
class Sink:
    line: int
    function: str
    provider: str
    taints: list
    tools: list = field(default_factory=list)       # [(tool_name, [Capability])]
    tools_unresolved: bool = False
    chain: str = ""
    mitigated: bool = False
    base: str = ""          # variable the AI call was made on (agent / client)
    ctor_var: str = ""      # for constructor sinks: the variable the agent is assigned to


# ----------------------------------------------------------------- helpers
def framework_label(tree: ast.AST) -> str | None:
    """Best label for the agent framework a file imports (so a bare ``Agent(...)`` is not
    reported as CrewAI when it is PydanticAI, the OpenAI Agents SDK, Google ADK or Agno)."""
    mods: set[str] = set()
    imported: set[str] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods |= {a.name for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module:
            mods.add(n.module)
            imported |= {a.name for a in n.names}
    def has(prefix):
        return any(m == prefix or m.startswith(prefix + ".") or m.startswith(prefix + "_") for m in mods)
    if has("pydantic_ai"):
        return "PydanticAI"
    if "agents" in mods and imported & {"Runner", "function_tool", "Agent"}:
        return "OpenAI Agents SDK"
    for prefix, label in (("google.adk", "Google ADK"), ("agno", "Agno"), ("smolagents", "smolagents"),
                          ("crewai", "CrewAI"), ("autogen", "AutoGen"), ("llama_index", "LlamaIndex"),
                          ("semantic_kernel", "Semantic Kernel"), ("langgraph", "LangGraph"), ("langchain", "LangChain")):
        if any(m == prefix or m.startswith(prefix) for m in mods):
            return label
    return None


def _chain(node: ast.AST) -> str:
    """Dotted call chain that also steps through intermediate calls, e.g.
    ``PyPDFLoader(path).load`` -> ``PyPDFLoader.load``."""
    if isinstance(node, ast.Call):
        return _chain(node.func)
    if isinstance(node, ast.Attribute):
        base = _chain(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        return _chain(node.value)
    return ""


def _names_and_strings(node: ast.AST | None) -> set[str]:
    out: set[str] = set()
    if node is None:
        return out
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 80:
            out.add(n.value)
    return out


def _decorator_chain(dec: ast.AST) -> str:
    return _chain(dec.func if isinstance(dec, ast.Call) else dec)


def _classify_chain(chain: str) -> list[tuple[str, str, str]]:
    """(class, category, operation) triples for a call chain."""
    out: list[tuple[str, str, str]] = []
    for pattern, category, operation in DANGEROUS_CHAIN_RULES:
        if pattern.search(chain):
            if category == "COMMUNICATION":
                out.append(("EXTERNAL_COMM", category, operation))
            elif category == "DATA" and operation == "execute_sql":
                continue  # decided with the call arguments in _classify_call
            else:
                out.append(("DANGEROUS", category, operation))
    if not any(c[0] == "EXTERNAL_COMM" for c in out) and EXTERNAL_COMM_RE.search(chain):
        out.append(("EXTERNAL_COMM", "COMMUNICATION", "send"))
    if PRIVATE_DATA_RE.search(chain):
        out.append(("PRIVATE_DATA", "DATA", "read"))
    return out


def _source_phrase(taints: list[Taint]) -> str:
    kinds = []
    for t in sorted(taints, key=lambda t: (not t.indirect, t.line)):
        if t.kind not in kinds:
            kinds.append(t.kind)
    names = [KIND_META[k][0] for k in kinds[:2]]
    return " and ".join(names) if names else "untrusted content"


# --------------------------------------------------------- file analysis
class _FileAnalysis:
    def __init__(self, file_path: str, source: str, tree: ast.Module):
        self.file_path = file_path
        self.lines = source.splitlines()
        self.tree = tree
        self.functions: dict[str, ast.AST] = {}
        self.module_values: dict[str, ast.AST] = {}
        self.all_values: dict[str, ast.AST] = {}
        self.ai_vars: dict[str, str] = {}
        self.http_vars: set[str] = set()
        self.framework: str | None = framework_label(tree)
        self.decorated_tools: set[str] = set()
        self.route_functions: set[str] = set()
        self.ai_functions: set[str] = set()
        self.sinks: list[Sink] = []
        self.inferred_names: set[str] = set()
        self.steered: list[tuple[str, Capability]] = []      # (function, capability)
        self.seeds: dict[str, dict[str, list[Taint]]] = {}
        self.approval_functions: set[str] = set()
        self._collect()

    # -- discovery -----------------------------------------------------
    def _collect(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
                for dec in node.decorator_list:
                    dc = _decorator_chain(dec)
                    if TOOL_DECORATOR_RE.search(dc) or MCP_TOOL_RE.search(dc):
                        self.decorated_tools.add(node.name)
                    if ROUTE_DECORATOR_RE.search(dc):
                        self.route_functions.add(node.name)
                if any(APPROVAL_NAME_HINTS.search(n.id if isinstance(n, ast.Name) else n.attr)
                       for n in ast.walk(node) if isinstance(n, (ast.Name, ast.Attribute))):
                    self.approval_functions.add(node.name)
        for node in self.tree.body:
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.module_values[t.id] = node.value
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.all_values[t.id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                self.all_values[node.target.id] = node.value
        for node in ast.walk(self.tree):
            value, targets = None, []
            if isinstance(node, ast.Assign):
                value, targets = node.value, node.targets
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                value, targets = node.value, [node.target]
            elif isinstance(node, ast.With):
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        self._register_var(item.optional_vars.id, item.context_expr)
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    self._register_var(t.id, value)
        # LCEL chains: chain = prompt | llm | parser
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.BitOr):
                names = [n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)]
                provider = next((self.ai_vars[n] for n in names if n in self.ai_vars), None)
                if provider:
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            self.ai_vars[t.id] = provider
        for name, fn in self.functions.items():
            if any(isinstance(c, ast.Call) and self.is_ai_call(c) for c in ast.walk(fn)):
                self.ai_functions.add(name)

    def _register_var(self, name: str, value: ast.AST | None) -> None:
        if isinstance(value, ast.Await):
            value = value.value
        if not isinstance(value, ast.Call):
            return
        tail = _chain(value.func).split(".")[-1]
        if tail in AI_CLIENT_CONSTRUCTORS:
            self.ai_vars[name] = AI_CLIENT_CONSTRUCTORS[tail]
        elif tail in AI_AGENT_CONSTRUCTORS:
            self.ai_vars[name] = self.framework or AI_AGENT_CONSTRUCTORS[tail]
        elif tail in AGENT_EXTRA:
            self.ai_vars[name] = AGENT_EXTRA[tail]
        elif tail in HTTP_CLIENT_CTORS and re.search(r"(requests|httpx|aiohttp|urllib)", _chain(value.func)):
            self.http_vars.add(name)

    # -- predicates ----------------------------------------------------
    def is_ai_call(self, call: ast.Call) -> bool:
        chain = _chain(call.func)
        if not chain:
            return False
        parts = chain.split(".")
        if parts[0] in self.ai_vars and parts[-1] in AI_METHODS:
            return True
        if AI_CHAIN_RE.search(chain):
            return True
        return False

    def agent_base(self, call: ast.Call) -> str:
        """Variable holding the agent/client a model call runs on. For ``Runner.run(agent, ...)``
        style APIs the agent is an argument rather than the receiver."""
        base = _chain(call.func).split(".")[0]
        if base in self.ai_vars:
            return base
        for a in call.args:
            if isinstance(a, ast.Name) and a.id in self.ai_vars:
                return a.id
        return base

    def provider_for(self, call: ast.Call) -> str:
        chain = _chain(call.func)
        base = self.agent_base(call)
        if base in self.ai_vars:
            return self.ai_vars[base]
        if self.framework and re.match(r"^(Runner|runner)\.", chain):
            return self.framework
        for key, name in (("openai", "OpenAI"), ("anthropic", "Anthropic"), ("messages.create", "Anthropic"),
                          ("litellm", "LiteLLM"), ("ollama", "Ollama"), ("generate_content", "Gemini")):
            if key in chain.lower():
                return name
        return "an LLM"

    def source_of_call(self, call: ast.Call) -> Taint | None:
        chain = _chain(call.func)
        line = getattr(call, "lineno", 0)
        parts = chain.split(".")
        # input() / stdin
        if chain in {"input", "sys.stdin.read", "sys.stdin.readline"} or chain.endswith("stdin.read"):
            return Taint("user_input", "interactive input", line, False, 0.85)
        if HTTP_ATTR_RE.match(chain):
            return Taint("http_request", f"request data ({chain})", line, False, 0.85)
        if len(parts) >= 2 and parts[0] in self.http_vars and parts[-1] in {"get", "post", "request", "fetch"}:
            literal = bool(call.args) and isinstance(call.args[0], ast.Constant)
            return Taint("web_content", f"web content ({chain})", line, True, 0.6 if literal else 0.8)
        if WEB_CALL_RE.search(chain):
            literal = bool(call.args) and isinstance(call.args[0], ast.Constant)
            return Taint("web_content", f"web content ({chain})", line, True, 0.6 if literal else 0.8)
        if DOC_LOADER_RE.search(chain):
            return Taint("loaded_document", f"loaded document ({chain})", line, True, 0.65)
        if parts[-1] in RAG_METHODS or (
            parts[-1] in RAG_GENERIC_METHODS and len(parts) > 1 and RAG_BASE_RE.search(".".join(parts[:-1]))
            and parts[0] not in self.ai_vars
        ):
            return Taint("retrieved_document", f"retrieved documents ({chain})", line, True, 0.75)
        if EMAIL_CALL_RE.search(chain) and parts[0] not in self.ai_vars:
            return Taint("email_or_message", f"message content ({chain})", line, True, 0.7)
        if THIRD_PARTY_CALL_RE.search(chain) and parts[0] not in self.ai_vars:
            return Taint("third_party_content", f"third-party content ({chain})", line, True, 0.65)
        return None

    def source_of_attr(self, node: ast.AST) -> Taint | None:
        chain = _chain(node)
        line = getattr(node, "lineno", 0)
        if chain and HTTP_ATTR_RE.match(chain):
            return Taint("http_request", f"request data ({chain})", line, False, 0.85)
        if chain == "sys.argv":
            return Taint("user_input", "command-line arguments", line, False, 0.7)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id in THIRD_PARTY_NAMES and node.attr in THIRD_PARTY_ATTRS:
            return Taint("third_party_content", f"{node.value.id}.{node.attr}", line, True, 0.6)
        return None

    # -- tool resolution -----------------------------------------------
    def _expand(self, node: ast.AST | None, depth: int = 0) -> set[str]:
        names = _names_and_strings(node)
        if depth < 2:
            for n in list(names):
                if n in self.all_values and n not in self.functions:
                    names |= self._expand(self.all_values[n], depth + 1)
        return names

    def toolset_from(self, exprs: list, line: int) -> tuple[list, list[Taint], bool]:
        """Resolve tool expressions to (local tools with capabilities, untrusted-content
        ingesting tools, unresolved flag)."""
        names: set[str] = set()
        unresolved = False
        for e in exprs:
            names |= self._expand(e)
            if isinstance(e, ast.Name) and e.id not in self.all_values and e.id not in self.functions:
                unresolved = True
        names |= self.decorated_tools
        tools: list[tuple[str, list[Capability]]] = []
        ingest: list[Taint] = []
        for name in sorted(names):
            fn = self.functions.get(name)
            if fn is not None:
                caps = self.capabilities_of(fn, f"tool:{name}")
                for c in ast.walk(fn):
                    if isinstance(c, ast.Call):
                        src = self.source_of_call(c)
                        if src and src.indirect:
                            ingest.append(Taint(src.kind, f"content returned by tool '{name}' ({src.label})", line, True,
                                                src.confidence, via_tool=name))
                            # A fetcher's own HTTP/data calls are how it fetches, not an outbound channel.
                            caps = [x for x in caps if x.cls == "DANGEROUS"]
                            break
                tools.append((name, caps))
                continue
            caps = []
            known_ingest = bool(KNOWN_INGEST_TOOLS.match(name))
            if known_ingest:
                kind = "email_or_message" if re.search(r"Gmail|Slack", name) else \
                    ("retrieved_document" if re.search(r"PDF|DOCX|CSV|MDX|TXT|JSON|XML|Directory|Rag|Docs", name) else "web_content")
                ingest.append(Taint(kind, f"content returned by tool '{name}'", line, True,
                                    0.55 if kind == "retrieved_document" else 0.7, via_tool=name))
            if KNOWN_COMM_TOOLS.match(name):
                caps.append(Capability("EXTERNAL_COMM", "COMMUNICATION", "send", line, name, False, f"tool:{name}"))
            if KNOWN_EXEC_TOOLS.match(name):
                caps.append(Capability("DANGEROUS", "INFRASTRUCTURE", "execute", line, name, False, f"tool:{name}"))
            if KNOWN_FILEWRITE_TOOLS.match(name):
                caps.append(Capability("DANGEROUS", "DATA", "write", line, name, False, f"tool:{name}"))
            if KNOWN_PRIVATE_TOOLS.match(name) and not known_ingest:
                caps.append(Capability("PRIVATE_DATA", "DATA", "read", line, name, False, f"tool:{name}"))
            if known_ingest:
                caps = [c for c in caps if c.cls != "PRIVATE_DATA"]   # the reader is the ingest point itself
            inferred = False
            if not caps and not known_ingest and name not in self.all_values \
                    and name.isidentifier() and not name[0].isupper():
                if INFER_INGEST_NAME.search(name):
                    ingest.append(Taint("web_content", f"content returned by tool '{name}' (inferred from its name)",
                                        line, True, 0.45, via_tool=name))
                    inferred = True
                elif INFER_COMM_NAME.match(name):
                    caps.append(Capability("EXTERNAL_COMM", "COMMUNICATION", "send", line, name, False, f"tool:{name}"))
                    inferred = True
                elif INFER_DANGER_NAME.match(name):
                    caps.append(Capability("DANGEROUS", "INFRASTRUCTURE", "execute", line, name, False, f"tool:{name}"))
                    inferred = True
            if inferred:
                self.inferred_names.add(name)
            if caps or known_ingest or inferred:
                tools.append((name, caps))
        return tools, ingest, unresolved

    def tool_exprs_for_agent_var(self, base: str) -> list:
        exprs = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if any(isinstance(t, ast.Name) and t.id == base for t in node.targets):
                    exprs += self.ctor_tool_exprs(node.value)
        return exprs

    def ctor_tool_exprs(self, ctor: ast.Call) -> list:
        # constructors take tools positionally in different slots
        # (initialize_agent(tools, llm) vs create_react_agent(llm, tools, ...));
        # only names that resolve to local functions / known tools are used, so
        # including every positional argument is safe.
        return [kw.value for kw in ctor.keywords if kw.arg in {"tools", "functions", "toolkit"}] + list(ctor.args)

    def tools_for(self, call: ast.Call) -> tuple[list, list[Taint], bool]:
        exprs = [kw.value for kw in call.keywords if kw.arg in {"tools", "functions"}]
        base = self.agent_base(call)
        exprs += self.tool_exprs_for_agent_var(base)
        return self.toolset_from(exprs, getattr(call, "lineno", 0))

    def capabilities_of(self, fn: ast.AST, via: str) -> list[Capability]:
        controlled = fn.name in self.approval_functions
        caps: list[Capability] = []
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                caps.extend(self._classify_call(node, controlled, via, tainted_args=False))
        # de-duplicate on (class, operation, line)
        seen, out = set(), []
        for c in caps:
            k = (c.cls, c.operation, c.line)
            if k not in seen:
                seen.add(k)
                out.append(c)
        return out

    def _classify_call(self, call: ast.Call, controlled: bool, via: str, tainted_args: bool) -> list[Capability]:
        chain = _chain(call.func)
        if not chain:
            return []
        line = getattr(call, "lineno", 0)
        out = [Capability(c, cat, op, line, chain, controlled, via) for c, cat, op in _classify_chain(chain)]
        # SQL: destructive literal -> DANGEROUS; tainted free-form SQL -> DANGEROUS; else a read.
        if re.search(r"\b(cursor|conn|session|db|engine|connection)\w*\.(execute|executemany|exec_driver_sql|run_query)$",
                     chain, re.IGNORECASE):
            text = ""
            if call.args:
                a = call.args[0]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    text = a.value
                elif isinstance(a, ast.JoinedStr):
                    text = "".join(v.value for v in a.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if SQL_DANGEROUS_RE.search(text) or re.search(r"\b(UPDATE|INSERT|ALTER|GRANT)\b", text, re.IGNORECASE) \
                    or (tainted_args and not text):
                out.append(Capability("DANGEROUS", "DATA", "execute_sql", line, chain, controlled, via))
            else:
                out.append(Capability("PRIVATE_DATA", "DATA", "read", line, chain, controlled, via))
        return out


# --------------------------------------------------------------- taint pass
class _Flow(ast.NodeVisitor):
    def __init__(self, fa: _FileAnalysis, fn_name: str, params: dict[str, list[Taint]]):
        self.fa = fa
        self.fn = fn_name
        self.env: dict[str, list[Taint]] = {k: list(v) for k, v in params.items()}
        self.returns: list[Taint] = []
        self.sanitized_here = False
        self.local_calls: list[tuple[str, ast.Call]] = []
        self.current_targets: list[str] = []

    # -- expression taint ----------------------------------------------
    def taint(self, node: ast.AST | None) -> list[Taint]:
        if node is None or isinstance(node, ast.Constant):
            return []
        if isinstance(node, ast.Name):
            return list(self.env.get(node.id, []))
        if isinstance(node, ast.Await):
            return self.taint(node.value)
        src = self.fa.source_of_attr(node) if isinstance(node, (ast.Attribute, ast.Subscript)) else None
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            base = self.taint(node.value)
            return ([src] if src else []) + base
        if isinstance(node, ast.JoinedStr):
            return self._union(v.value for v in node.values if isinstance(v, ast.FormattedValue))
        if isinstance(node, ast.BinOp):
            return self._union([node.left, node.right])
        if isinstance(node, ast.BoolOp):
            return self._union(node.values)
        if isinstance(node, ast.IfExp):
            return self._union([node.body, node.orelse])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return self._union(node.elts)
        if isinstance(node, ast.Dict):
            return self._union(v for v in node.values if v is not None)
        if isinstance(node, ast.Starred):
            return self.taint(node.value)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            saved = dict(self.env)
            for gen in node.generators:
                self._bind(gen.target, self.taint(gen.iter))
            elt = node.value if isinstance(node, ast.DictComp) else node.elt
            result = self.taint(elt)
            self.env = saved
            return result
        if isinstance(node, ast.Call):
            return self._call_taint(node)
        return []

    def _union(self, nodes) -> list[Taint]:
        out: list[Taint] = []
        for n in nodes:
            for t in self.taint(n):
                if t not in out:
                    out.append(t)
        return out[:6]

    def _call_taint(self, call: ast.Call) -> list[Taint]:
        chain = _chain(call.func)
        src = self.fa.source_of_call(call)
        arg_nodes = list(call.args) + [kw.value for kw in call.keywords if kw.arg not in CONFIG_KWARGS]
        arg_taint = self._union(arg_nodes)
        if SANITIZER_RE.search(chain):
            # A sanitizer lowers severity but does not make the flow disappear:
            # filtering is rarely complete, so the path is still reported.
            self.sanitized_here = True
            return arg_taint
        if src:
            return [src]
        if self.fa.is_ai_call(call) or chain.split(".")[0] in self.fa.ai_functions or chain in self.fa.ai_functions:
            return [replace(t, via_model=True) for t in arg_taint]
        base_taint = self.taint(call.func.value) if isinstance(call.func, ast.Attribute) else []
        merged = arg_taint + [t for t in base_taint if t not in arg_taint]
        return merged[:6]

    # -- binding -------------------------------------------------------
    def _bind(self, target: ast.AST, taints: list[Taint]) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = list(taints)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self._bind(t, taints)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name) and taints:
                self.env[base.id] = list(dict.fromkeys(self.env.get(base.id, []) + taints))[:6]

    # -- statements ----------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        self.current_targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        self.visit(node.value)
        self.current_targets = []
        t = self.taint(node.value)
        for target in node.targets:
            self._bind(target, t)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value is not None:
            self.visit(node.value)
            self._bind(node.target, self.taint(node.value))

    def visit_AugAssign(self, node: ast.AugAssign):
        self.visit(node.value)
        t = self.taint(node.value) + self.taint(node.target)
        self._bind(node.target, list(dict.fromkeys(t))[:6])

    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.visit(node.value)
        self._bind(node.target, self.taint(node.value))

    def visit_For(self, node):
        self.visit(node.iter)
        self._bind(node.target, self.taint(node.iter))
        for s in node.body + node.orelse:
            self.visit(s)

    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind(item.optional_vars, self.taint(item.context_expr))
        for s in node.body:
            self.visit(s)

    visit_AsyncWith = visit_With

    def visit_Return(self, node: ast.Return):
        if node.value is not None:
            self.visit(node.value)
            self.returns.extend(self.taint(node.value))

    def visit_FunctionDef(self, node):   # nested defs are analysed on their own
        return

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    # -- calls ---------------------------------------------------------
    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        fa = self.fa
        chain = _chain(node.func)
        prompt_nodes = list(node.args) + [kw.value for kw in node.keywords if kw.arg not in CONFIG_KWARGS]
        prompt_taint = self._union(prompt_nodes)

        tail = chain.split(".")[-1] if chain else ""
        if fa.is_ai_call(node):
            tools, ingest, unresolved = fa.tools_for(node)
            taints = [t for t in prompt_taint if not t.via_model] or prompt_taint
            for t in ingest:
                if t not in taints:
                    taints = taints + [t]
            if taints:
                fa.sinks.append(Sink(
                    line=node.lineno, function=self.fn, provider=fa.provider_for(node), taints=taints,
                    tools=tools, tools_unresolved=unresolved, chain=chain, mitigated=self.sanitized_here,
                    base=fa.agent_base(node),
                ))
            return

        if tail in AI_AGENT_CONSTRUCTORS or tail in AGENT_EXTRA:
            tools, ingest, unresolved = fa.toolset_from(fa.ctor_tool_exprs(node), node.lineno)
            if ingest and any(caps for _, caps in tools):
                fa.sinks.append(Sink(
                    line=node.lineno, function=self.fn,
                    provider=fa.framework or AI_AGENT_CONSTRUCTORS.get(tail) or AGENT_EXTRA.get(tail, "an agent"),
                    taints=ingest, tools=tools, tools_unresolved=unresolved, chain=chain,
                    mitigated=self.sanitized_here, ctor_var=(self.current_targets or [""])[0],
                ))

        bare = chain.split(".")[0] if chain else ""
        callee = chain if chain in fa.functions else (bare if bare in fa.functions and "." not in chain else "")
        if callee:
            self.local_calls.append((callee, node))

        steered = [t for t in prompt_taint if t.via_model]
        if steered:
            controlled = self.fn in fa.approval_functions
            for cap in fa._classify_call(node, controlled, "model-output", tainted_args=True):
                fa.steered.append((self.fn, cap))
                fa.steered_taints.setdefault((self.fn, cap.line), steered)


def _analyse(fa: _FileAnalysis) -> None:
    fa.steered_taints = {}
    # seed route-handler parameters (direct HTTP input)
    base_seeds: dict[str, dict[str, list[Taint]]] = {}
    for name in fa.route_functions:
        fn = fa.functions[name]
        params: dict[str, list[Taint]] = {}
        defaults = [None] * (len(fn.args.args) - len(fn.args.defaults)) + list(fn.args.defaults)
        for arg, default in zip(fn.args.args, defaults):
            if arg.arg in NON_PROMPT_PARAMS:
                continue
            if isinstance(default, ast.Call) and _chain(default.func).split(".")[-1] in {"Depends", "Security"}:
                continue
            params[arg.arg] = [Taint("http_request", f"HTTP parameter '{arg.arg}'", fn.lineno, False, 0.8)]
        base_seeds[name] = params

    seeds = {k: dict(v) for k, v in base_seeds.items()}
    for _ in range(3):
        fa.sinks.clear()
        fa.steered.clear()
        fa.steered_taints.clear()
        changed = False
        units = [(name, fn) for name, fn in fa.functions.items()]
        module_unit = ast.Module(body=[s for s in fa.tree.body if not isinstance(
            s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], type_ignores=[])
        flows: list[tuple[str, _Flow]] = []
        for name, fn in units:
            flow = _Flow(fa, name, seeds.get(name, {}))
            for stmt in fn.body:
                flow.visit(stmt)
            flows.append((name, flow))
        mflow = _Flow(fa, "module", {})
        for stmt in module_unit.body:
            mflow.visit(stmt)
        flows.append(("module", mflow))
        # interprocedural seeding: tainted argument -> callee parameter
        for _, flow in flows:
            for callee, call in flow.local_calls:
                fn = fa.functions.get(callee)
                if fn is None:
                    continue
                params = [a.arg for a in fn.args.args if a.arg not in {"self", "cls"}]
                bound: dict[str, list[Taint]] = {}
                for p, a in zip(params, call.args):
                    t = flow.taint(a)
                    if t:
                        bound[p] = [x for x in t if not x.via_model] or t
                for kw in call.keywords:
                    if kw.arg in params:
                        t = flow.taint(kw.value)
                        if t:
                            bound[kw.arg] = t
                for p, t in bound.items():
                    cur = seeds.setdefault(callee, {}).get(p, [])
                    merged = list(dict.fromkeys(cur + t))[:6]
                    if merged != cur:
                        seeds[callee][p] = merged
                        changed = True
        if not changed:
            break


# ------------------------------------------------------------ finding build
def _downgrade(sev: str, steps: int) -> str:
    return SEVERITY_ORDER[max(0, SEVERITY_ORDER.index(sev) - steps)]


def _build_findings(fa: _FileAnalysis, ai_providers: list[str]) -> list[dict]:
    findings: list[dict] = []
    seen: set[tuple] = set()
    per_function: dict[str, int] = {}
    explicit_bases = {s.base for s in fa.sinks if s.base}
    for sink in fa.sinks:
        if sink.ctor_var and sink.ctor_var in explicit_bases:
            continue                      # reported at the agent.run()/invoke() call instead
        if (sink.line, sink.function) in seen:
            continue
        seen.add((sink.line, sink.function))
        caps: list[Capability] = []
        for _, tcaps in sink.tools:
            caps.extend(tcaps)
        caps.extend(c for f, c in fa.steered if f == sink.function)
        # steered actions in other functions still consume this model's output
        if not any(f == sink.function for f, _ in fa.steered):
            caps.extend(c for _, c in fa.steered)

        indirect = any(t.indirect for t in sink.taints)
        dangerous = [c for c in caps if c.cls == "DANGEROUS"]
        comm = [c for c in caps if c.cls == "EXTERNAL_COMM"]
        private = [c for c in caps if c.cls == "PRIVATE_DATA"]
        live_danger = [c for c in dangerous if not c.controlled]

        rank = 3 if live_danger else (2 if (comm or dangerous) else (1 if private else 0))
        trifecta = bool(indirect and private and comm)
        if not indirect and rank == 0:
            continue                      # plain chat with the user and no tools: not a finding
        if trifecta:
            severity = "CRITICAL"
        elif indirect:
            # private data with no outbound channel cannot reach the attacker: a lead, not a risk
            severity = ["LOW", "LOW", "HIGH", "CRITICAL"][rank]
        else:
            severity = {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}[rank]
        downgrades = 0
        if sink.mitigated:
            downgrades += 1
        if dangerous and not live_danger:
            downgrades += 1               # every dangerous action sits behind an approval guard
        if downgrades:
            severity = _downgrade(severity, downgrades)

        src = _source_phrase(sink.taints)
        first = sorted(sink.taints, key=lambda t: (not t.indirect, t.line))[0]
        if trifecta:
            capability, title = "lethal_trifecta", (
                f"Lethal trifecta: untrusted {src} can steer an AI that can read private data and send it out")
        elif dangerous:
            op = (live_danger or dangerous)[0]
            phrase = ACTION_PHRASES.get((op.category, op.operation), f"performing '{op.operation}'")
            capability, title = "injection_action", f"Untrusted {src} can steer AI ({sink.provider}) into {phrase}"
        elif comm:
            capability, title = "injection_exfiltration", (
                f"Untrusted {src} can steer AI ({sink.provider}) into sending data or messages externally")
        elif private:
            capability, title = "injection_data_access", (
                f"Untrusted {src} can steer AI ({sink.provider}) into reading private data")
        else:
            capability, title = "injection_surface", (
                f"Untrusted {src} is placed directly in an AI ({sink.provider}) prompt")

        evidence = [
            f"Untrusted source: {first.label} (line {first.line}) — "
            + ("third-party content an attacker can plant" if first.indirect else "supplied by the caller"),
            (f"Agent loop: the output of tool '{first.via_tool}' is fed back to the model ({sink.provider}) "
             f"that can also call the tools below (line {sink.line})") if first.via_tool else
            f"Data-flow trace: that value reaches the prompt of {sink.provider} at line {sink.line}",
        ]
        if len(sink.taints) > 1:
            evidence.append("Other sources reaching this prompt: " + ", ".join(
                sorted({t.label for t in sink.taints if t is not first})[:3]))
        if sink.tools:
            evidence.append("Tools available to the model: " + ", ".join(n for n, _ in sink.tools[:6]))
        elif sink.tools_unresolved:
            evidence.append("Tools are passed to the model but could not be resolved statically")
        for c in (live_danger or dangerous)[:2]:
            evidence.append(f"Reachable dangerous action: {c.category}/{c.operation} via {c.chain} (line {c.line})")
        if comm:
            evidence.append(f"Reachable outbound channel: {comm[0].chain} (line {comm[0].line})")
        if private:
            evidence.append(f"Reachable private-data access: {private[0].chain} (line {private[0].line})")
        if trifecta:
            evidence.append("All three legs present: untrusted content + private data + external communication")
        evidence.append("Injection mitigation detected near the prompt (sanitizer/guard)" if sink.mitigated
                        else "No prompt-injection mitigation detected (sanitizer, classifier or guardrail)")
        if dangerous:
            evidence.append("Human-approval guard detected in the tool/action" if not live_danger
                            else "No human-approval guard detected on the dangerous action")

        chain = [first.label, f"Prompt to {sink.provider}"]
        if sink.tools:
            chain.append("Tool: " + sink.tools[0][0])
        top = (live_danger or dangerous or comm or private or [None])[0]
        if top:
            chain.append(ACTION_PHRASES.get((top.category, top.operation), f"{top.category.title()}: {top.operation}"))
        if len(chain) < 3:
            chain.append("Model output")

        recs = ["Treat the untrusted content as data, never instructions: delimit it, strip or neutralise embedded instructions, and run an injection classifier or guardrail before it reaches the model."]
        if caps:
            recs.append("Give this agent least-privilege tools and require human approval for any action that moves money, changes infrastructure or data, or sends information out.")
        if trifecta:
            recs.append("Break the trifecta: do not let one agent combine untrusted content, private data and an outbound channel.")

        confidence = min(0.9, max(0.45, 0.78 * min(t.confidence for t in sink.taints) / 0.8
                                  - (0.1 if sink.tools_unresolved and not caps else 0)))
        per_function[sink.function] = per_function.get(sink.function, 0) + 1
        snippet = fa.lines[sink.line - 1].strip() if 0 < sink.line <= len(fa.lines) else ""
        approval = bool(dangerous) and not live_danger
        findings.append({
            "title": title, "severity": severity, "category": "PROMPT_INJECTION",
            "file_path": fa.file_path, "line": sink.line, "capability": capability,
            "ai_provider": sink.provider if sink.provider != "an LLM" else (ai_providers[0] if ai_providers else None),
            "confidence": round(confidence, 2), "evidence": evidence,
            "recommendation": " ".join(recs),
            "consequence": {
                "lethal_trifecta": "An attacker who can plant text where the AI reads it can make the AI exfiltrate private data.",
                "injection_action": "An attacker who controls that content can trigger privileged actions with your credentials.",
                "injection_exfiltration": "Planted instructions can make the AI send data or messages to attacker-chosen destinations.",
                "injection_data_access": "Planted instructions can make the AI read data the content's author should never see.",
                "injection_surface": "Planted instructions can change the AI's behaviour and answers.",
            }[capability],
            "impact_level": {3: "HIGH", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}[rank],
            "control_status": "Human approval present" if approval else "No guard detected",
            "ai_connected": True, "ai_controlled": True, "control_confidence": round(confidence, 2),
            "capability_chain": chain, "function_name": sink.function,
            "call_chain": f"{first.kind}->{sink.chain}", "occurrence_index": per_function[sink.function],
            "human_approval_detected": approval, "limit_detected": False, "snippet": snippet,
            "inferred": bool(fa.inferred_names & ({n for n, _ in sink.tools} | {t.via_tool for t in sink.taints})),
        })
    return findings


# ----------------------------------------------------------- JS/TS heuristic
JS_SOURCE_RE = re.compile(r"\b(req|request)\.(body|query|params)\b|\bfetch\(|\baxios\.(get|post)\b|"
                          r"\bgot\(|\bcheerio\.load\b|\bimap\b|\bgmail\b|similaritySearch|asRetriever|getRelevantDocuments",
                          re.IGNORECASE)
JS_TOOLS_RE = re.compile(r"\btools\s*:|\bfunctions\s*:|\bDynamicTool\b|\bDynamicStructuredTool\b|\btool\(\s*async|"
                         r"\bcreateReactAgent\b|\bAgentExecutor\b|server\.tool\(")


def _js_lead(analysis) -> list[dict]:
    text = analysis.raw_text or ""
    if not (analysis.has_ai and JS_SOURCE_RE.search(text) and JS_TOOLS_RE.search(text)):
        return []
    m = JS_SOURCE_RE.search(text)
    line = text[: m.start()].count("\n") + 1
    lines = text.splitlines()
    return [{
        "title": "Untrusted content may reach an AI agent that has tools (heuristic)",
        "severity": "MEDIUM", "category": "PROMPT_INJECTION", "file_path": analysis.file_path, "line": line,
        "capability": "injection_surface", "ai_provider": analysis.ai_providers[0] if analysis.ai_providers else None,
        "confidence": 0.4,
        "evidence": ["Keyword match: untrusted-input API and agent tools in the same file; no data-flow verification for JS/TS yet"],
        "recommendation": "Verify whether externally supplied content (requests, web pages, retrieved documents) reaches the model, and if so delimit/sanitise it and restrict the tools it can trigger.",
        "consequence": "Planted instructions can change what the agent does.", "impact_level": "MEDIUM",
        "control_status": "Unknown", "ai_connected": True, "ai_controlled": None, "control_confidence": 0.4,
        "capability_chain": ["Untrusted input", "Prompt to model", "Tools"], "function_name": "module",
        "call_chain": "heuristic", "occurrence_index": 1, "human_approval_detected": False, "limit_detected": False,
        "snippet": lines[line - 1].strip() if 0 < line <= len(lines) else "",
    }]


# --------------------------------------------------------------- public API
def analyze_file(analysis) -> list[dict]:
    """Findings for one FileAnalysis (from capability_extractor / language analyzers)."""
    path = analysis.file_path
    text = analysis.raw_text or ""
    if not analysis.has_ai or len(text) > MAX_SOURCE_BYTES:
        return []
    if not path.lower().endswith(".py"):
        return _js_lead(analysis) if path.lower().endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")) else []
    try:
        tree = ast.parse(text)
        fa = _FileAnalysis(path, text, tree)
        _analyse(fa)
        return _build_findings(fa, analysis.ai_providers)
    except (SyntaxError, RecursionError, ValueError):
        return []


def analyze_analyses(analyses, gate) -> list[dict]:
    """Run over every analysed file; `gate(finding, analysis)` applies the shared
    scoring gate (non-runtime paths / regex-only files are shown but not scored)."""
    out: list[dict] = []
    for analysis in analyses:
        for f in analyze_file(analysis):
            f = gate(f, analysis)
            if f.pop("inferred", False) and f.get("scored", True):
                # relies on tool names only (definition in another file): show it, don't score it
                f["scored"] = False
                f["severity"] = "LOW"
                f["potential_points"] = 0
                f["title"] = f"Potential capability detected: {f['title']}"
                f["evidence"] = ["⚠️ Not scored (tool behaviour inferred from names; definitions are in other files) — "
                                 "verify manually."] + f["evidence"]
            out.append(f)
    return out