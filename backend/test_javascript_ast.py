from app.scanner.languages.javascript.analyzer import JavaScriptAnalyzer


def analyze(text, path="agent.ts"):
    return JavaScriptAnalyzer().analyze(path, text).file_analysis


def test_ai_value_reaches_stripe_refund():
    a = analyze('''
import OpenAI from "openai";
import Stripe from "stripe";
const ai = new OpenAI();
const stripe = new Stripe(process.env.STRIPE_KEY);
async function refund(userInput) {
  const decision = await ai.chat.completions.create({messages: [{role: "user", content: userInput}]});
  const amount = decision.amount;
  return stripe.refunds.create({amount});
}
''')
    assert a.used_ast is True
    assert a.has_ai
    assert len(a.ast_findings) == 1
    assert a.ast_findings[0].operation == "refund"
    assert a.ast_findings[0].ai_controlled is True


def test_unrelated_stripe_refund_is_not_ai_controlled():
    a = analyze('''
import OpenAI from "openai";
import Stripe from "stripe";
const ai = new OpenAI();
const stripe = new Stripe(process.env.STRIPE_KEY);
const fixedAmount = 5000;
async function run() {
  const decision = await ai.chat.completions.create({messages: []});
  return stripe.refunds.create({amount: fixedAmount});
}
''')
    assert len(a.ast_findings) == 1
    assert a.ast_findings[0].ai_controlled is False


def test_taint_propagates_through_local_function_parameter():
    a = analyze('''
import OpenAI from "openai";
import Stripe from "stripe";
const ai = new OpenAI();
const stripe = new Stripe(process.env.STRIPE_KEY);
function executeRefund(amount) {
  return stripe.refunds.create({amount});
}
async function run() {
  const response = await ai.responses.create({input: "refund"});
  return executeRefund(response.amount);
}
''')
    assert len(a.ast_findings) == 1
    assert a.ast_findings[0].ai_controlled is True


def test_typescript_syntax_and_non_ai_refund_are_supported():
    a = analyze('''
import OpenAI from "openai";
import Stripe from "stripe";
type Decision = { amount: number };
const ai = new OpenAI();
const stripe = new Stripe(process.env.STRIPE_KEY!);
const fixed: number = 100;
async function run(): Promise<void> {
  const decision: Decision = await ai.responses.create({input: "x"});
  stripe.refunds.create({amount: fixed});
}
''', "agent.ts")
    assert a.used_ast is True
    assert a.has_ai
    assert a.ast_findings[0].ai_controlled is False


def test_js_finding_enters_existing_risk_pipeline_as_scored():
    from app.scanner import risk_engine

    a = analyze("""
import OpenAI from 'openai';
import Stripe from 'stripe';
const ai = new OpenAI();
const stripe = new Stripe(process.env.STRIPE_KEY);
async function run() {
  const decision = await ai.responses.create({input: 'refund'});
  return stripe.refunds.create({amount: decision.amount});
}
""")
    findings = risk_engine.build_findings_for_file(a, True)
    assert len(findings) == 1
    assert findings[0]["scored"] is True
    assert findings[0]["ai_controlled"] is True
    assert findings[0]["severity"] == "HIGH"


def test_array_push_is_not_reported_as_code_push():
    a = analyze("""
import OpenAI from 'openai';
const ai = new OpenAI();
async function run(candidates) {
  const answer = await ai.responses.create({input: 'choose'});
  candidates.push(answer);
}
""")
    assert not any(f.operation == "push" for f in a.ast_findings)


def test_generic_socket_send_is_not_reported_as_outbound_message():
    a = analyze("""
import OpenAI from 'openai';
const ai = new OpenAI();
async function run(socket, message) {
  const answer = await ai.responses.create({input: message});
  socket.send(answer.output_text);
}
""")
    assert not any(f.operation == "send" for f in a.ast_findings)


def test_explicit_git_client_push_remains_detectable():
    a = analyze("""
import OpenAI from 'openai';
const ai = new OpenAI();
async function run(gitClient) {
  const answer = await ai.responses.create({input: 'choose'});
  gitClient.push(answer.output_text);
}
""")
    assert any(f.operation == "push" for f in a.ast_findings)
