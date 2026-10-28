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
