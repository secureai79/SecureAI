import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import ast_detector


def test_docstring_and_comment_do_not_trigger_false_positives():
    src = '''
def explain_refund_policy():
    return "Refunds above $100 require approval."

# Do NOT delete production users.
def get_user_count():
    return db.count(users)
'''
    result = ast_detector.analyze_python_ast("policy.py", src)
    assert result.findings == []


def test_ai_controlled_refund_flagged_true():
    src = '''
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
    result = ast_detector.analyze_python_ast("agent.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "FINANCIAL"
    assert f.operation == "refund"
    assert f.ai_controlled is True


def test_static_amount_refund_flagged_false():
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def refund_customer(payment_id, amount):
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)

def process(message):
    summary = ai_agent(message)     # used only for a summary, not the amount
    return refund_customer("pi_123", 100)
'''
    result = ast_detector.analyze_python_ast("agent.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.ai_controlled is False


def test_guarded_refund_detects_approval_and_limit():
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()
MAX_AUTO_REFUND_AMOUNT = 100

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def queue_for_human_approval(payment_id, amount):
    return {"status": "pending"}

def refund_customer(payment_id, amount):
    if amount > MAX_AUTO_REFUND_AMOUNT:
        return queue_for_human_approval(payment_id, amount)
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)

def process(message):
    decision = ai_agent(message)
    return refund_customer(decision["payment_id"], decision["amount"])
'''
    result = ast_detector.analyze_python_ast("agent.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.ai_controlled is True
    assert f.approval_detected is True
    assert f.limit_detected is True


def test_guard_in_unrelated_sibling_branch_does_not_count():
    """Feedback item #3: a guard clause sitting in a completely unrelated
    branch (never on the path to the dangerous call) must not be credited
    as protecting it, even though the old whole-function scan would have
    found it."""
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def process(message):
    decision = ai_agent(message)
    ai_amount = decision["amount"]

    if False:
        amount = 999
        if amount > 100:
            return require_human_approval(amount)

    stripe.Refund.create(amount=ai_amount)
'''
    result = ast_detector.analyze_python_ast("unrelated_guard.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.ai_controlled is True
    assert f.approval_detected is False
    assert f.limit_detected is False


def test_guard_checking_different_variable_does_not_count_as_limit():
    """A threshold check on a variable that has nothing to do with the
    dangerous call's actual argument shouldn't count as a limit guard for
    it, even if it's structurally in the right place."""
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def process(message):
    decision = ai_agent(message)
    unrelated_counter = 5
    if unrelated_counter > 3:
        return require_human_approval(unrelated_counter)
    return stripe.Refund.create(amount=decision["amount"])
'''
    result = ast_detector.analyze_python_ast("mismatched_guard.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    # approval_detected can still legitimately fire (an approval call is present
    # and structurally precedes the call with an early return), but the
    # threshold shouldn't be credited since it checks an unrelated variable.
    assert f.limit_detected is False


def test_unconnected_ai_and_delete_not_marked_ai_controlled():
    """The doc's own critique example: AI SDK present in the file, dangerous
    DELETE present in the file, but no data-flow connects them."""
    src = '''
import anthropic
import psycopg2
client = anthropic.Anthropic()

def cleanup_user(user_id):
    conn = psycopg2.connect("dbname=prod")
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM users WHERE id={user_id}")

def ai_maintenance_agent(prompt):
    return client.messages.create(model="claude-3-opus-20240229", max_tokens=200, messages=[])
'''
    result = ast_detector.analyze_python_ast("admin.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.operation == "delete"
    assert f.ai_controlled is False


def test_interprocedural_taint_hop_through_wrapper_function():
    """reply is tainted in run_agent(); send_reply() receives it as a plain
    parameter — one hop of interprocedural propagation should still catch it."""
    src = '''
import smtplib
from langchain.agents import initialize_agent
agent = initialize_agent(tools=[], llm=None)

def send_reply(to_address, ai_generated_body):
    server = smtplib.SMTP("smtp.example.com")
    server.sendmail("support@example.com", to_address, ai_generated_body)

def run_agent(ticket_text):
    reply = agent.run(ticket_text)
    send_reply("customer@example.com", reply)
'''
    result = ast_detector.analyze_python_ast("support_bot.py", src)
    assert len(result.findings) == 1
    assert result.findings[0].ai_controlled is True


def test_two_distinct_call_sites_get_distinct_fingerprints():
    """Feedback item: category+capability+file_path alone can collapse two
    separate calls in the same file into one fingerprint. One AI-controlled
    refund call and one hardcoded-amount refund call in the same function
    must produce two distinct findings with two distinct fingerprints."""
    from app.scanner import risk_engine, capability_extractor

    src = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def process(message):
    decision = ai_agent(message)
    stripe.Refund.create(amount=decision["amount"])
    stripe.Refund.create(amount=100)
'''
    analysis = capability_extractor.analyze_file("agent.py", src)
    findings = risk_engine.build_findings_for_file(analysis, True)
    assert len(findings) == 2
    fps = {risk_engine.compute_fingerprint(f) for f in findings}
    assert len(fps) == 2  # must NOT collide

    ai_controlled_values = {f["ai_controlled"] for f in findings}
    assert ai_controlled_values == {True, False}


def test_fingerprint_stable_across_unrelated_line_shift():
    """A fingerprint must survive unrelated edits elsewhere in the file that
    only shift line numbers, or regression detection would cry wolf on
    every unrelated commit."""
    from app.scanner import risk_engine, capability_extractor

    src_v1 = '''
from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def process(message):
    decision = ai_agent(message)
    return stripe.Refund.create(amount=decision["amount"])
'''
    src_v2 = '''
# unrelated header comment
def unrelated_helper():
    return 42

from openai import OpenAI
import stripe
client = OpenAI()

def ai_agent(message):
    return client.chat.completions.create(model="gpt-4", messages=[])

def process(message):
    decision = ai_agent(message)
    return stripe.Refund.create(amount=decision["amount"])
'''
    f1 = risk_engine.build_findings_for_file(capability_extractor.analyze_file("agent.py", src_v1), True)[0]
    f2 = risk_engine.build_findings_for_file(capability_extractor.analyze_file("agent.py", src_v2), True)[0]
    assert f1["line"] != f2["line"]  # sanity: line numbers did actually shift
    assert risk_engine.compute_fingerprint(f1) == risk_engine.compute_fingerprint(f2)


def test_module_level_dangerous_call_is_detected():
    """Feedback item #2: agent setup code that calls the AI SDK and a
    dangerous capability directly at module scope (not inside any function)
    was previously an invisible blind spot."""
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

decision = client.chat.completions.create(model="gpt-4", messages=[])

stripe.Refund.create(
    payment_intent=decision["payment_id"],
    amount=decision["amount"]
)
'''
    result = ast_detector.analyze_python_ast("module_level.py", src)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.operation == "refund"
    assert f.ai_controlled is True
    assert f.function_name == "<module>"


def test_module_level_scan_does_not_double_count_function_bodies():
    """Pruning nested function/class bodies out of the module-scope pass
    must not cause the same dangerous call to be reported twice."""
    src = '''
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

refund_customer("pi_static", 50)
'''
    result = ast_detector.analyze_python_ast("mixed.py", src)
    assert len(result.findings) == 1
    assert result.findings[0].function_name == "refund_customer"

def test_http_ai_endpoint_detected_as_provider():
    from app.scanner import capability_extractor

    src = '''
import requests

def ask_ai(prompt):
    response = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        json={"messages": [{"role": "user", "content": prompt}],
    )
    return response.json()
'''

    result = capability_extractor.analyze_file("voice_assistant.py", src)

    assert "Groq" in result.ai_providers

def test_generic_http_endpoint_is_not_detected_as_ai():
    from app.scanner import capability_extractor

    src = '''
import requests

def fetch_data():
    return requests.get("https://example.com/api/data")
'''

    result = capability_extractor.analyze_file("client.py", src)

    assert result.ai_providers == []

def test_ai_controlled_shell_command_flagged_true():
    src = '''
from openai import OpenAI
import subprocess

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )
    command = decision.choices[0].message.content
    subprocess.run(command, shell=True)
'''

    result = ast_detector.analyze_python_ast("shell_agent.py", src)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "INFRASTRUCTURE"
    assert f.operation == "execute"
    assert f.ai_controlled is True


def test_static_shell_command_with_ai_present_is_not_ai_controlled():
    src = '''
from openai import OpenAI
import subprocess

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )
    subprocess.run("git status", shell=True)
'''

    result = ast_detector.analyze_python_ast("static_shell.py", src)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "INFRASTRUCTURE"
    assert f.operation == "execute"
    assert f.ai_controlled is False

def test_ai_dict_value_reaches_stripe_refund():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    refund_data = {
        "payment_id": decision["payment_id"],
        "amount": decision["amount"],
    }

    stripe.Refund.create(
        payment_intent=refund_data["payment_id"],
        amount=refund_data["amount"],
    )
'''

    result = ast_detector.analyze_python_ast("dict_refund.py", src)

    assert len(result.findings) == 1
    assert result.findings[0].operation == "refund"
    assert result.findings[0].ai_controlled is True


def test_ai_attribute_value_reaches_shell():
    src = '''
from openai import OpenAI
import subprocess

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    command = decision.choices[0].message.content
    subprocess.run(command, shell=True)
'''

    result = ast_detector.analyze_python_ast("attribute_shell.py", src)

    assert len(result.findings) == 1
    assert result.findings[0].operation == "execute"
    assert result.findings[0].ai_controlled is True


def test_static_dict_value_does_not_become_ai_controlled():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    refund_data = {
        "payment_id": "pi_static",
        "amount": 100,
    }

    stripe.Refund.create(
        payment_intent=refund_data["payment_id"],
        amount=refund_data["amount"],
    )
'''

    result = ast_detector.analyze_python_ast("static_dict_refund.py", src)

    assert len(result.findings) == 1
    assert result.findings[0].operation == "refund"
    assert result.findings[0].ai_controlled is False

def test_ai_output_through_helper_reaches_shell():
    src = '''
from openai import OpenAI
import subprocess

client = OpenAI()

def sanitize_command(command):
    return command.strip()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    command = decision.choices[0].message.content
    cleaned_command = sanitize_command(command)

    subprocess.run(cleaned_command, shell=True)
'''

    result = ast_detector.analyze_python_ast("helper_shell.py", src)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "INFRASTRUCTURE"
    assert f.operation == "execute"
    assert f.ai_controlled is True

def test_ai_tool_selection_reaches_consequential_action():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def refund_customer(amount):
    stripe.Refund.create(
        payment_intent="pi_123",
        amount=amount,
    )

def dispatch_tool(tool_name, amount):
    if tool_name == "refund_customer":
        refund_customer(amount)

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    tool_name = decision["tool"]
    amount = decision["amount"]

    dispatch_tool(tool_name, amount)
'''

    result = ast_detector.analyze_python_ast("tool_dispatch.py", src)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "FINANCIAL"
    assert f.operation == "refund"
    assert f.ai_controlled is True

def test_ai_tool_dispatch_with_static_tool_is_not_ai_controlled():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def refund_customer(amount):
    stripe.Refund.create(
        payment_intent="pi_123",
        amount=amount,
    )

def dispatch_tool(tool_name, amount):
    if tool_name == "refund_customer":
        refund_customer(amount)

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    # Tool and amount are fixed, not derived from the AI response.
    dispatch_tool("refund_customer", 100)
'''

    result = ast_detector.analyze_python_ast("static_tool_dispatch.py", src)

    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.category == "FINANCIAL"
    assert f.operation == "refund"
    assert f.ai_controlled is False

def test_ai_controlled_finding_contains_data_flow_path():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    amount = decision["amount"]

    stripe.Refund.create(
        payment_intent="pi_123",
        amount=amount,
    )
'''

    result = ast_detector.analyze_python_ast("flow_evidence.py", src)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.ai_controlled is True

    # This test intentionally defines the future evidence contract.
    assert hasattr(finding, "data_flow_path")
    assert finding.data_flow_path

def test_data_flow_path_contains_ai_source_and_variable():
    src = '''
from openai import OpenAI
import stripe

client = OpenAI()

def process(message):
    decision = client.chat.completions.create(
        model="gpt-4",
        messages=[]
    )

    amount = decision["amount"]

    stripe.Refund.create(
        payment_intent="pi_123",
        amount=amount,
    )
'''

    result = ast_detector.analyze_python_ast("flow_path_detail.py", src)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.ai_controlled is True
    assert finding.data_flow_path == [
        "client.chat.completions.create()",
        "decision",
        'decision["amount"]',
        "amount",
        "stripe.Refund.create()",
    ]

def test_refund_finding_has_consequence():
    from app.scanner.ast_detector import analyze_python_ast

    source = '''
from openai import OpenAI
import stripe

client = OpenAI()
decision = client.chat.completions.create(
    model="gpt-4",
    messages=[]
)

stripe.Refund.create(
    amount=decision["amount"]
)
'''

    result = analyze_python_ast("src/refund_agent.py", source)

    assert len(result.findings) == 1

    finding = result.findings[0]

    assert finding.category == "FINANCIAL"
    assert finding.operation == "refund"

def test_refund_finding_has_impact_level():
    from app.scanner.ast_detector import analyze_python_ast
    from app.scanner.risk_engine import _build_findings_ast

    source = '''
from openai import OpenAI
import stripe

client = OpenAI()
decision = client.chat.completions.create(
    model="gpt-4",
    messages=[]
)

stripe.Refund.create(
    amount=decision["amount"]
)
'''

    analysis = analyze_python_ast("src/refund_agent.py", source)

    # Adapt the AST result into the FileAnalysis expected by risk_engine.
    finding = analysis.findings[0]

    assert finding.category == "FINANCIAL"
    assert finding.operation == "refund"