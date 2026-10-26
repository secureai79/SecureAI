"""Framework-specific agent risks that no generic data-flow rule can see.

Several agent frameworks can run model-written code on the host with a single constructor
option. That is the most dangerous capability an agent can have, and it never appears as an
explicit ``subprocess`` call in the user's code, so it is recognised by the framework's own
switches:

* smolagents ``CodeAgent`` (local Python executor unless ``executor_type`` is docker/e2b/modal/wasm)
* AutoGen ``LocalCommandLineCodeExecutor`` / ``code_execution_config={"use_docker": False}``
* CrewAI ``code_execution_mode="unsafe"`` / ``CodeInterpreterTool(unsafe_mode=True)``
* LangChain ``allow_dangerous_code=True`` and Python/Shell REPL tools handed to an agent
* OpenAI Agents SDK ``LocalShellTool``

Findings reuse the existing ``INFRASTRUCTURE / execute`` category so policies such as
``match: {category: INFRASTRUCTURE, capability: execute}`` cover them.
"""
from __future__ import annotations

import ast
import re
from types import SimpleNamespace

from .injection_analyzer import _chain

HINTS = ("smolagents", "autogen", "crewai", "langchain", "agents", "CodeAgent", "LocalShellTool")
SANDBOXED_EXECUTORS = {"docker", "e2b", "modal", "wasm", "blaxel"}
DANGEROUS_IMPORTS = {"os", "subprocess", "sys", "shutil", "socket", "ctypes", "importlib", "builtins", "pty", "multiprocessing"}
REPL_TOOLS = {"PythonREPLTool", "PythonAstREPLTool", "PythonREPL", "ShellTool", "BashProcess", "LLMBashChain", "PALChain"}
AGENT_BUILDERS = {"initialize_agent", "AgentExecutor", "create_react_agent", "create_tool_calling_agent",
                  "create_openai_tools_agent", "create_openai_functions_agent", "create_structured_chat_agent", "Agent"}


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _kw(call: ast.Call, name: str):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _finding(path, line, framework, title, severity, evidence, recommendation, chain, snippet, confidence=0.85) -> dict:
    return {
        "title": title, "severity": severity, "category": "INFRASTRUCTURE", "file_path": path, "line": int(line),
        "capability": "execute", "ai_provider": framework, "confidence": confidence, "evidence": evidence,
        "recommendation": recommendation,
        "consequence": "Model-written code runs with the host's permissions, so a prompt injection becomes remote code execution.",
        "impact_level": "HIGH", "control_status": "No sandbox detected", "ai_connected": True, "ai_controlled": True,
        "control_confidence": confidence, "capability_chain": chain, "function_name": "module",
        "call_chain": f"{framework}.code_execution", "occurrence_index": 1, "human_approval_detected": False,
        "limit_detected": False, "snippet": snippet,
    }


def analyze_text(path: str, text: str) -> list[dict]:
    if not path.lower().endswith(".py") or not any(h in text for h in HINTS):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError, ValueError):
        return []
    lines = text.splitlines()
    snip = lambda n: lines[n - 1].strip() if 0 < n <= len(lines) else ""
    out: list[dict] = []
    seen: set = set()
    builds_agent = any(isinstance(n, ast.Call) and _chain(n.func).split(".")[-1] in AGENT_BUILDERS for n in ast.walk(tree))

    def add(f):
        key = (f["line"], f["ai_provider"])
        if key not in seen:
            seen.add(key)
            out.append(f)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        tail = _chain(node.func).split(".")[-1]
        line = node.lineno

        # ---- smolagents
        if tail == "CodeAgent":
            exe = _const(_kw(node, "executor_type"))
            if exe in SANDBOXED_EXECUTORS:
                continue
            imports = _kw(node, "additional_authorized_imports")
            names = [_const(e) for e in imports.elts] if isinstance(imports, (ast.List, ast.Tuple, ast.Set)) else []
            wide = "*" in names or bool(DANGEROUS_IMPORTS & {str(n).split(".")[0] for n in names if n})
            add(_finding(path, line, "smolagents",
                         "Agent (smolagents CodeAgent) runs model-written Python on the host"
                         + (" with dangerous imports authorised" if wide else ""),
                         "HIGH" if wide else "MEDIUM",
                         ["CodeAgent executes code the model writes", f"executor_type={exe!r}: local executor (not docker/e2b/modal/wasm)"]
                         + ([f"additional_authorized_imports allows {names}"] if wide else
                            ["Imports are restricted, but the local Python executor is not a security boundary"]),
                         "Use executor_type='docker', 'e2b', 'modal' or 'wasm' so generated code runs in an isolated sandbox without your credentials.",
                         ["Untrusted content / user request", "Model writes Python", "Local executor", "Host process"], snip(line)))

        # ---- AutoGen
        elif tail == "LocalCommandLineCodeExecutor":
            add(_finding(path, line, "AutoGen", "Agent (AutoGen) executes model-written code on the host (LocalCommandLineCodeExecutor)",
                         "HIGH", ["LocalCommandLineCodeExecutor runs generated code directly in the local environment"],
                         "Use DockerCommandLineCodeExecutor (or a remote sandbox) and keep credentials out of that environment.",
                         ["Model", "Generated code", "LocalCommandLineCodeExecutor", "Host"], snip(line)))
        elif tail in {"UserProxyAgent", "ConversableAgent", "AssistantAgent", "CodeExecutorAgent"}:
            cfg = _kw(node, "code_execution_config")
            if isinstance(cfg, ast.Dict):
                for k, v in zip(cfg.keys, cfg.values):
                    if _const(k) == "use_docker" and _const(v) is False:
                        add(_finding(path, line, "AutoGen", f"Agent (AutoGen {tail}) executes model-written code on the host (use_docker=False)",
                                     "HIGH", ["code_execution_config disables Docker, so generated code runs locally"],
                                     "Set use_docker=True (or use a Docker/remote executor) and never run generated code with your own credentials.",
                                     ["Model", "Generated code", "Local execution", "Host"], snip(line)))

        # ---- CrewAI
        elif tail == "Agent" and _const(_kw(node, "code_execution_mode")) == "unsafe":
            add(_finding(path, line, "CrewAI", "Agent (CrewAI) runs model-written code directly on the host (code_execution_mode='unsafe')",
                         "HIGH", ["code_execution_mode='unsafe' disables the Docker sandbox"],
                         "Use the default code_execution_mode='safe' (Docker).",
                         ["Model", "Generated code", "Unsandboxed execution", "Host"], snip(line)))
        elif tail == "CodeInterpreterTool" and _const(_kw(node, "unsafe_mode")) is True:
            add(_finding(path, line, "CrewAI", "CrewAI CodeInterpreterTool runs in unsafe mode (no Docker sandbox)",
                         "HIGH", ["unsafe_mode=True executes code in the host environment"],
                         "Remove unsafe_mode so the tool runs in Docker.", ["Model", "CodeInterpreterTool", "Host"], snip(line)))

        # ---- OpenAI Agents SDK
        elif tail == "LocalShellTool":
            add(_finding(path, line, "OpenAI Agents SDK", "Agent (OpenAI Agents SDK) can run shell commands on the host (LocalShellTool)",
                         "HIGH", ["LocalShellTool executes the commands the model requests"],
                         "Remove it, or execute commands in a sandbox with an allow-list and human approval.",
                         ["Model", "LocalShellTool", "Host shell"], snip(line)))

        # ---- LangChain
        if _const(_kw(node, "allow_dangerous_code")) is True:
            add(_finding(path, line, "LangChain", f"LangChain agent '{tail}' is allowed to execute model-written code (allow_dangerous_code=True)",
                         "HIGH", ["allow_dangerous_code=True is an explicit opt-in to running generated Python on the host"],
                         "Run generated code in a sandbox, or remove the opt-in and use a restricted tool.",
                         ["Model", "Generated code", "Host Python"], snip(line)))
        elif tail in REPL_TOOLS and builds_agent:
            add(_finding(path, line, "LangChain", f"Agent is given {tail}, which executes model-controlled input on the host",
                         "HIGH", [f"{tail} is available to an agent in this file"],
                         "Replace it with a sandboxed executor or a narrowly scoped tool, and require approval.",
                         ["Model", tail, "Host"], snip(line), confidence=0.75))
    return out


def analyze_files(candidates: list[tuple[str, str]], gate) -> list[dict]:
    out: list[dict] = []
    for path, text in candidates:
        try:
            found = analyze_text(path, text)
        except Exception:
            continue
        shim = SimpleNamespace(used_ast=True, file_path=path)
        out.extend(gate(f, shim) for f in found)
    return out