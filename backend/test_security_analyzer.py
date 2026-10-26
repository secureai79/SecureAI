from app.scanner.security_analyzer import analyze_security

def caps(findings):
    return {f["capability"] for f in findings}

def test_detects_known_api_key():
    findings = analyze_security("app/config.py", 'OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"\n')
    assert "exposed_secret" in caps(findings)
    assert any(f["severity"] in {"HIGH", "CRITICAL"} for f in findings)

def test_detects_hardcoded_password():
    findings = analyze_security("app/config.py", 'DB_PASSWORD = "super-secret-password"\n')
    assert "hardcoded_credential" in caps(findings)

def test_detects_sensitive_data_to_network():
    src = '''user_data = get_customer_data()
requests.post("https://example.com/collect", json=user_data)
'''
    findings = analyze_security("app/service.py", src)
    assert "data_exfiltration" in caps(findings)

def test_detects_unguarded_sensitive_endpoint():
    src = '''@app.delete("/admin/users/{user_id}")
def delete_user(user_id):
    db.delete(user_id)
'''
    findings = analyze_security("app/routes.py", src)
    assert "unguarded_endpoint" in caps(findings)

def test_does_not_flag_guarded_endpoint():
    src = '''@app.delete("/admin/users/{user_id}")
def delete_user(user_id, current_user=Depends(get_current_user)):
    db.delete(user_id)
'''
    findings = analyze_security("app/routes.py", src)
    assert "unguarded_endpoint" not in caps(findings)

def test_detects_command_injection_signal():
    src = '''command = request.args["command"]
os.system(command)
'''
    findings = analyze_security("app/run.py", src)
    assert "command_injection" in caps(findings)

def test_detects_sql_injection_signal():
    src = '''query = f"SELECT * FROM users WHERE id = {request.args['id']}"
cursor.execute(query)
'''
    findings = analyze_security("app/db.py", src)
    assert "sql_injection" in caps(findings)

def test_does_not_report_known_placeholder_secret():
    findings = analyze_security("app/config.py", 'OPENAI_API_KEY = "your_api_key_here"\n')
    assert not findings

def test_private_key_is_critical():
    findings = analyze_security("app/key.py", "PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----\\nsecret\\n-----END PRIVATE KEY-----'''")
    assert any(f["capability"] == "exposed_secret" and f["severity"] == "CRITICAL" for f in findings)

def test_ignores_lockfiles():
    findings = analyze_security("package-lock.json", '{"token":"ghp_abcdefghijklmnopqrstuvwxyz1234567890"}')
    assert findings == []
