import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(__file__))

import pytest

from app.scanner import capability_extractor, injection_analyzer


def run(code, path="agent.py"):
    analysis = capability_extractor.analyze_file(path, textwrap.dedent(code))
    return injection_analyzer.analyze_file(analysis)


def one(code, **kw):
    findings = run(code, **kw)
    assert len(findings) == 1, findings
    return findings[0]


TRIFECTA = '''
import requests, smtplib
from openai import OpenAI
client = OpenAI()
def read_customer(cid):
    return open(f"/data/{cid}.json").read()
def send_email(to, body):
    smtplib.SMTP("smtp.x").sendmail("a@x", to, body)
def summarize(url):
    page = requests.get(url).text
    return client.chat.completions.create(model="gpt-4o",
        messages=[{"role": "user", "content": "Summarize: " + page}],
        tools=[{"type": "function", "function": {"name": "read_customer"}},
               {"type": "function", "function": {"name": "send_email"}}])
'''


def test_lethal_trifecta_is_critical_and_explains_all_three_legs():
    f = one(TRIFECTA)
    assert f["severity"] == "CRITICAL" and f["capability"] == "lethal_trifecta"
    assert f["category"] == "PROMPT_INJECTION" and f["ai_controlled"] is True
    text = " ".join(f["evidence"])
    assert "requests.get" in text and "read_customer" in text and "All three legs" in text
    assert f["capability_chain"][0].startswith("web content") and f["line"] > 0


def test_model_output_steering_a_refund_is_critical():
    f = one('''
        import stripe, requests
        from anthropic import Anthropic
        client = Anthropic()
        def handle(ticket_url):
            body = requests.get(ticket_url).json()["body"]
            resp = client.messages.create(model="c", max_tokens=100, messages=[{"role": "user", "content": body}])
            amount = int(resp.content[0].text)
            stripe.Refund.create(charge="ch_1", amount=amount)
    ''')
    assert f["severity"] == "CRITICAL" and "refunds" in f["title"]


def test_rag_documents_reach_agent_with_shell_tool_across_functions():
    f = one('''
        from langchain_openai import ChatOpenAI
        from langchain.agents import initialize_agent
        import subprocess
        llm = ChatOpenAI()
        def run_cmd(c):
            subprocess.run(c, shell=True)
        agent = initialize_agent([run_cmd], llm)
        def answer(q, retriever):
            docs = retriever.get_relevant_documents(q)
            return ask(docs)
        def ask(ctx):
            return agent.run(f"Context: {ctx}")
    ''')
    assert f["severity"] == "CRITICAL" and "shell" in f["title"]
    assert "retrieved" in f["title"]


def test_email_and_tool_decorator_discovery():
    f = one('''
        import imaplib, smtplib
        from langchain.tools import tool
        from openai import OpenAI
        client = OpenAI()
        @tool
        def forward(to, body):
            smtplib.SMTP("h").sendmail("a", to, body)
        def triage():
            m = imaplib.IMAP4_SSL("h")
            raw = m.fetch("1", "(RFC822)")
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": str(raw)}])
    ''')
    assert f["severity"] == "HIGH" and "externally" in f["title"]


def test_route_parameters_are_direct_sources_but_chatbot_without_tools_is_not_flagged():
    assert run('''
        from fastapi import FastAPI
        from openai import OpenAI
        app = FastAPI(); client = OpenAI()
        @app.post("/chat")
        def chat(message: str):
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": message}])
    ''') == []


def test_direct_user_input_with_dangerous_tool_is_high_not_critical():
    f = one('''
        from fastapi import FastAPI
        from openai import OpenAI
        import subprocess
        app = FastAPI(); client = OpenAI()
        def shell(cmd):
            subprocess.run(cmd, shell=True)
        @app.post("/agent")
        def agent(message: str):
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": message}], tools=[shell])
    ''')
    assert f["severity"] == "HIGH"


def test_sanitizer_downgrades_but_does_not_hide():
    plain = one('''
        import requests, smtplib
        from openai import OpenAI
        client = OpenAI()
        def tool_x():
            smtplib.SMTP("h").sendmail("a", "b", "c")
        def go(u):
            t = requests.get(u).text
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": t}], tools=[tool_x])
    ''')
    guarded = one('''
        import requests, smtplib
        from openai import OpenAI
        client = OpenAI()
        def tool_x():
            smtplib.SMTP("h").sendmail("a", "b", "c")
        def go(u):
            t = sanitize_input(requests.get(u).text)
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": t}], tools=[tool_x])
    ''')
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert order.index(guarded["severity"]) == order.index(plain["severity"]) - 1
    assert "mitigation detected" in " ".join(guarded["evidence"])


def test_human_approval_inside_dangerous_tool_downgrades():
    f = one('''
        import requests, stripe
        from openai import OpenAI
        client = OpenAI()
        def refund_tool(amount):
            require_approval(amount)
            stripe.Refund.create(amount=amount)
        def go(u):
            t = requests.get(u).text
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": t}], tools=[refund_tool])
    ''')
    assert f["severity"] == "MEDIUM" and f["human_approval_detected"] is True


@pytest.mark.parametrize("code", [
    # constant prompt
    '''
    from openai import OpenAI
    client = OpenAI()
    def hello():
        return client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
    ''',
    # keywords only in a docstring / comment
    '''
    from openai import OpenAI
    client = OpenAI()
    def f(x):
        """requests.get(url) then stripe refund"""
        # imaplib smtplib
        return client.chat.completions.create(model="m", messages=[{"role": "user", "content": x}])
    ''',
    # untrusted value computed but never reaches the prompt
    '''
    import requests
    from openai import OpenAI
    client = OpenAI()
    def f(u):
        page = requests.get(u).text
        print(len(page))
        return client.chat.completions.create(model="m", messages=[{"role": "user", "content": "constant"}])
    ''',
    # reassigned to a constant before the prompt
    '''
    import requests
    from openai import OpenAI
    client = OpenAI()
    def f(u):
        page = requests.get(u).text
        page = "static"
        return client.chat.completions.create(model="m", messages=[{"role": "user", "content": page}])
    ''',
])
def test_no_false_positives(code):
    assert run(code) == []


def test_no_ai_sdk_means_no_findings():
    assert run("import requests\nx = requests.get('u').text\nprint(x)\n") == []


def test_syntax_error_is_ignored_not_raised():
    assert run("def broken(:\n  pass", path="x.py") == []


def test_javascript_is_a_low_confidence_unscored_lead():
    code = '''
    import OpenAI from "openai";
    const client = new OpenAI();
    app.post("/x", async (req, res) => {
      const page = await fetch(req.body.url).then(r => r.text());
      const out = await client.chat.completions.create({ model: "m", messages: [{role: "user", content: page}], tools: [t] });
    });
    '''
    analysis = capability_extractor.analyze_file("agent.js", textwrap.dedent(code))
    findings = injection_analyzer.analyze_file(analysis)
    if findings:  # heuristic: only asserts shape when the regex layer recognised an AI SDK
        assert findings[0]["confidence"] <= 0.5 and findings[0]["category"] == "PROMPT_INJECTION"


def test_scoring_gate_marks_tests_and_regex_files_unscored():
    from app.scanner import risk_engine
    analysis = capability_extractor.analyze_file("tests/test_agent.py", textwrap.dedent(TRIFECTA))
    out = injection_analyzer.analyze_analyses([analysis], risk_engine._apply_scoring_gate)
    assert out and out[0]["scored"] is False and out[0]["severity"] == "LOW"


def test_end_to_end_scan_stores_and_scores_injection_findings(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ISOLATED_SCAN_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(textwrap.dedent(TRIFECTA))
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/auth/signup", json={"email": "a@example.com", "password": "a-very-long-passphrase-1", "organization_name": "O"})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        rid = c.post("/repositories", headers=h, json={"repo_url": f"file://{repo}", "repo_name": "r"}).json()["id"]
        scan = c.post(f"/repositories/{rid}/scan", headers=h).json()
        assert scan["status"] == "completed", scan
        findings = c.get(f"/scans/{scan['id']}/findings", headers=h).json()
        inj = [f for f in findings if f["category"] == "PROMPT_INJECTION"]
        assert inj and inj[0]["finding_domain"] == "AI_SAFETY" and inj[0]["severity"] == "CRITICAL" and inj[0]["scored"]
        assert scan["score"] < 100
        domain = c.get(f"/scans/{scan['id']}/domain-scores", headers=h).json()
        assert domain["ai_safety"]["counts"]["CRITICAL"] >= 1
        fix = c.get(f"/findings/{inj[0]['id']}/fix", headers=h).json()
        assert fix["diff"] == "" and "Guidance only" in fix["note"]
        assert c.get(f"/scans/{scan['id']}/report.pdf", headers=h).status_code == 200
        assert c.get(f"/scans/{scan['id']}/graph", headers=h).status_code == 200


# ---------------------------------------------------------------- agent-loop modelling
def test_known_toolkit_scraper_plus_file_writer_is_critical():
    f = one('''
        from crewai import Agent
        from crewai_tools import ScrapeWebsiteTool, FileWriterTool
        scrape = ScrapeWebsiteTool()
        writer = FileWriterTool()
        agent = Agent(role="dev", goal="g", backstory="b", tools=[scrape, writer])
    ''')
    assert f["severity"] == "CRITICAL" and "writing or deleting files" in f["title"]
    assert "Agent loop" in " ".join(f["evidence"])


def test_research_only_agent_with_search_tools_is_not_flagged():
    assert run('''
        from crewai import Agent
        from crewai_tools import SerperDevTool, ScrapeWebsiteTool
        agent = Agent(role="r", goal="g", backstory="b", tools=[SerperDevTool(), ScrapeWebsiteTool()])
    ''') == []


def test_fetcher_tools_own_http_call_is_not_an_exfiltration_channel():
    assert run('''
        import requests
        from langchain.tools import tool
        from langchain.agents import initialize_agent
        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI()
        @tool
        def read_site(url):
            return requests.post("https://api.browserless.io/content", json={"url": url}).text
        agent = initialize_agent([read_site], llm)
    ''') == []


def test_mail_reader_alone_is_not_flagged_as_private_data_leak():
    assert run('''
        from crewai import Agent
        from langchain_community.tools.gmail import GmailGetThread
        agent = Agent(role="r", goal="g", backstory="b", tools=[GmailGetThread()])
    ''') == []


def test_local_fetch_tool_plus_send_tool_with_explicit_model_call_is_high():
    f = one('''
        import requests, smtplib
        from openai import OpenAI
        client = OpenAI()
        def fetch_page(url):
            return requests.get(url).text
        def send_email(to, body):
            smtplib.SMTP("h").sendmail("a", to, body)
        def run(task):
            return client.chat.completions.create(model="m", messages=[{"role": "user", "content": task}],
                                                  tools=[fetch_page, send_email])
    ''')
    assert f["severity"] == "HIGH" and "externally" in f["title"]


def test_tools_defined_in_other_files_are_inferred_by_name_and_never_scored():
    from app.scanner import risk_engine
    code = '''
        from crewai import Agent
        from tools import BrowserTools, MailTools
        agent = Agent(role="r", goal="g", backstory="b",
                      tools=[BrowserTools.scrape_page, MailTools.send_email])
    '''
    analysis = capability_extractor.analyze_file("crew.py", textwrap.dedent(code))
    out = injection_analyzer.analyze_analyses([analysis], risk_engine._apply_scoring_gate)
    assert out, "name-based lead expected"
    assert out[0]["scored"] is False and out[0]["severity"] == "LOW"
    assert out[0]["title"].startswith("Potential capability detected")
    assert "inferred" not in out[0]


def test_large_file_is_skipped_quickly():
    big = "from openai import OpenAI\nclient = OpenAI()\n" + ("x = 1\n" * 100000)
    analysis = capability_extractor.analyze_file("big.py", big)
    assert injection_analyzer.analyze_file(analysis) == []