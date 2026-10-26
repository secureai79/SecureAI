import base64
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import httpx

import github_pr_check as prc
from mock_http import MockRouter

REPO = "acme/backend"
PR = 42

BASE_SHA = "base0000"
HEAD_SHA = "head1111"

# Base version: a refund call with a hardcoded amount (not AI-controlled).
BASE_CODE = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def refund_customer(payment_id, amount):
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)

def process(message):
    summary = ai_agent(message)
    return refund_customer("pi_123", 100)
'''

# Head version (this PR): the developer wires the AI decision straight into
# the refund amount — a new AI-controlled HIGH finding.
HEAD_CODE = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def refund_customer(payment_id, amount):
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)

def process(message):
    decision = ai_agent(message)
    return refund_customer(decision["payment_id"], decision["amount"])
'''


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _run(monkeypatch, router, capsys):
    monkeypatch.setattr(prc, "_make_client", router.client)
    prc.sys.argv = ["github_pr_check.py", "--repo", REPO, "--pr", str(PR), "--dry-run"]
    try:
        prc.main()
        exit_code = 0
    except SystemExit as e:
        exit_code = e.code
    return capsys.readouterr().out, exit_code


def test_pr_check_detects_new_ai_controlled_finding_and_blocks(monkeypatch, capsys):
    router = MockRouter()
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/pulls/{PR}",
               httpx.Response(200, json={"base": {"sha": BASE_SHA}, "head": {"sha": HEAD_SHA}}))
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/pulls/{PR}/files",
               httpx.Response(200, json=[{"filename": "agents/refund_agent.py", "status": "modified"}]))
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/contents/agents/refund_agent.py",
               httpx.Response(200, json={"encoding": "base64", "content": _b64(BASE_CODE)}),
               params={"ref": BASE_SHA})
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/contents/agents/refund_agent.py",
               httpx.Response(200, json={"encoding": "base64", "content": _b64(HEAD_CODE)}),
               params={"ref": HEAD_SHA})

    out, exit_code = _run(monkeypatch, router, capsys)

    assert "new finding" in out.lower()
    assert "HIGH" in out
    assert "This PR introduces a new HIGH or CRITICAL risk finding" in out
    assert exit_code == 1  # blocking


def test_pr_check_no_new_findings_passes(monkeypatch, capsys):
    router = MockRouter()
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/pulls/{PR}",
               httpx.Response(200, json={"base": {"sha": BASE_SHA}, "head": {"sha": HEAD_SHA}}))
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/pulls/{PR}/files",
               httpx.Response(200, json=[{"filename": "agents/refund_agent.py", "status": "modified"}]))
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/contents/agents/refund_agent.py",
               httpx.Response(200, json={"encoding": "base64", "content": _b64(BASE_CODE)}),
               params={"ref": BASE_SHA})
    router.add("GET", f"{prc.API_BASE}/repos/{REPO}/contents/agents/refund_agent.py",
               httpx.Response(200, json={"encoding": "base64", "content": _b64(BASE_CODE)}),  # unchanged
               params={"ref": HEAD_SHA})

    out, exit_code = _run(monkeypatch, router, capsys)

    assert "No new AI safety findings" in out
    assert exit_code == 0
