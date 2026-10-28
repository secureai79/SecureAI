"""Regression tests for scanner behaviours that must keep working (kept in their own file so they never
collide with edits to test_security_analyzer.py)."""
from app.scanner.security_analyzer import analyze_security


def caps(findings):
    return {f["capability"] for f in findings}


def _fake(tail):                       # assembled at runtime: no key-shaped literal in this repo
    return "s" + "k-" + tail


def test_invented_example_key_in_comment_is_not_flagged():
    src = '# API_KEY = "' + _fake("abcdefghijklmnopqrstuvwxyz123456") + '"\n'
    assert "exposed_secret" not in caps(analyze_security("app/config.py", src))


def test_same_key_in_code_is_still_flagged():
    src = 'API_KEY = "' + _fake("abcdefghijklmnopqrstuvwxyz123456") + '"\n'
    assert "exposed_secret" in caps(analyze_security("app/config.py", src))


def test_real_looking_key_in_comment_is_still_flagged():
    src = '# old key: "' + _fake("proj-9fK2LmQx81ZtV7cRb4NwYd3HsJ6PaUe0") + '"\n'
    assert "exposed_secret" in caps(analyze_security("app/config.py", src))


def test_route_does_not_borrow_auth_marker_from_previous_route():
    src = '''@app.get("/profile")
def profile(current_user=Depends(get_current_user)):
    return current_user

@app.delete("/admin/users/{user_id}")
def delete_user(user_id):
    db.delete(user_id)
'''
    assert "unguarded_endpoint" in caps(analyze_security("app/routes.py", src))


def test_stacked_decorator_guard_above_route_still_counts():
    src = '''@require_admin
@app.delete("/admin/users/{user_id}")
def delete_user(user_id):
    db.delete(user_id)
'''
    assert "unguarded_endpoint" not in caps(analyze_security("app/routes.py", src))


def test_guard_inside_own_function_counts():
    src = '''@app.delete("/admin/users/{user_id}")
def delete_user(user_id, current_user=Depends(get_current_user)):
    db.delete(user_id)
'''
    assert "unguarded_endpoint" not in caps(analyze_security("app/routes.py", src))


def test_js_sql_module_is_importable_and_ignores_frontend_onclick():
    assert analyze_security("frontend/pages/intake.js", "onClick={() => select(val)}\n") == [] or \
        "sql_injection" not in caps(analyze_security("frontend/pages/intake.js", "onClick={() => select(val)}\n"))


def test_modern_openai_and_anthropic_key_formats_are_detected():
    openai = 'KEY = "' + _fake("proj-9fK2LmQx81ZtV7cRb4NwYd3HsJ6PaUe0") + '"\n'
    anthropic = 'KEY = "' + _fake("ant-api03-9fK2LmQx81ZtV7cRb4NwYd3HsJ6PaUe0xyz") + '"\n'
    for src in (openai, anthropic):
        found = analyze_security("app/config.py", src)
        assert any(f["capability"] == "exposed_secret" for f in found), src[:20]


def test_example_assignment_in_comment_is_not_flagged_as_hardcoded_credential():
    src = '# API_KEY = "' + _fake("abcdefghijklmnopqrstuvwxyz123456") + '"\n'
    found = caps(analyze_security("app/config.py", src))
    assert "hardcoded_credential" not in found and "exposed_secret" not in found


def test_real_looking_assignment_in_comment_is_still_flagged():
    src = '# DB_PASSWORD = "Xq7!rT9zLm2Vw8Kd4Hs"\n'
    found = caps(analyze_security("app/config.py", src))
    assert "hardcoded_credential" in found


# ---- data files are not code; guarded actions do not get "add an approval" advice ----
def test_json_data_file_does_not_produce_action_leads():
    from app.scanner import capability_extractor
    text = '{"why": "tool may execute and update records", "cmd": "subprocess.run(x)"}'
    a = capability_extractor.analyze_file("benchmark/manifest.json", text)
    assert a.dangerous_calls == [] and not a.has_ai


def test_package_json_is_not_skipped_like_other_data_files():
    """package.json keeps the normal text analysis (behaviour unchanged); other .json files are skipped."""
    from app.scanner import capability_extractor
    text = 'import OpenAI from "openai"'
    assert capability_extractor.analyze_file("package.json", text).has_ai
    assert not capability_extractor.analyze_file("manifest.json", text).has_ai


def test_guarded_refund_recommendation_does_not_ask_for_existing_controls():
    from app.scanner import capability_extractor, risk_engine
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()
MAX = 100
def handle(msg):
    d = client.chat.completions.create(model="m", messages=[{"role": "user", "content": msg}])
    amount = d["amount"]
    if amount > MAX:
        return queue_for_human_approval(d)
    return stripe.Refund.create(payment_intent=d["pid"], amount=amount)
def queue_for_human_approval(d):
    return {"status": "pending_approval"}
'''
    a = capability_extractor.analyze_file("agents/r.py", src)
    f = [x for x in risk_engine.build_findings_for_file(a, True) if x["capability"] == "refund"][0]
    assert f["control_status"] == "CONTROLLED"
    assert "were detected" in f["recommendation"] and "Require human approval above" not in f["recommendation"]


def test_unguarded_refund_keeps_original_recommendation():
    from app.scanner import capability_extractor, risk_engine
    src = '''
from openai import OpenAI
import stripe
client = OpenAI()
def handle(msg):
    d = client.chat.completions.create(model="m", messages=[{"role": "user", "content": msg}])
    return stripe.Refund.create(payment_intent=d["pid"], amount=d["amount"])
'''
    a = capability_extractor.analyze_file("agents/r.py", src)
    f = [x for x in risk_engine.build_findings_for_file(a, True) if x["capability"] == "refund"][0]
    assert f["control_status"] == "UNCONTROLLED" and "Require human approval" in f["recommendation"]
