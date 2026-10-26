import os
import sys
import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "hardening.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    from app.database import init_db
    init_db()
    with TestClient(app) as c:
        yield c



def test_privacy_default_does_not_store_source_snippet(monkeypatch):
    monkeypatch.delenv("STORE_SOURCE_SNIPPETS", raising=False)
    from app.privacy import prepare_finding_for_storage
    f = {"snippet": 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"', "evidence": ['secret sk-abcdefghijklmnopqrstuvwxyz123456'], "title":"x"}
    safe = prepare_finding_for_storage(f)
    assert safe["snippet"] is None
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in str(safe["evidence"])


def test_privacy_opt_in_stores_redacted_snippet(monkeypatch):
    monkeypatch.setenv("STORE_SOURCE_SNIPPETS", "true")
    from app.privacy import prepare_finding_for_storage
    f = {"snippet": 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"', "evidence": []}
    safe = prepare_finding_for_storage(f)
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in safe["snippet"]
    assert "REDACTED" in safe["snippet"]


def test_privacy_redacts_sensitive_values_across_finding_fields(monkeypatch):
    monkeypatch.delenv("STORE_SOURCE_SNIPPETS", raising=False)

    from app.privacy import prepare_finding_for_storage

    fake_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    finding = {
        "title": "Credential exposure",
        "description": f"Found key {fake_secret}",
        "recommendation": f"Rotate credential {fake_secret}",
        "file_path": f"config-{fake_secret}.py",
        "function_name": f"connect_{fake_secret}",
        "call_chain": [f"client uses {fake_secret}"],
        "capability_chain": {
            "details": f"Token found: {fake_secret}"
        },
        "evidence": [f"secret {fake_secret}"],
        "snippet": f'API_KEY = "{fake_secret}"',
        "metadata": {
            "nested": [f"another value: {fake_secret}"]
        },
    }

    safe = prepare_finding_for_storage(finding)

    # The original finding must remain unchanged.
    assert fake_secret in str(finding)

    # No field in the sanitized copy should retain the fake secret.
    assert fake_secret not in str(safe)

    # Snippet storage must remain disabled by default.
    assert safe["snippet"] is None


def test_external_llm_request_does_not_contain_fake_secret(monkeypatch):
    from types import SimpleNamespace
    from app.scanner import llm_analyzer

    fake_secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    captured = {}

    class FakeMessages:
        def create(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        type="text",
                        text=(
                            '{"ai_connected": true, '
                            '"human_approval_detected": false, '
                            '"limit_detected": false, '
                            '"confidence": 0.8, '
                            '"false_positive": false}'
                        ),
                    )
                ]
            )

    fake_client = SimpleNamespace(messages=FakeMessages())

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-not-a-real-key")
    monkeypatch.setenv("ENABLE_EXTERNAL_LLM_REFINEMENT", "true")
    monkeypatch.setattr(
        llm_analyzer, "_client", lambda: fake_client
    )

    finding = {
        "capability": f"token {fake_secret}",
        "category": "credential exposure",
        "file_path": f"config-{fake_secret}.py",
        "snippet": f'API_KEY = "{fake_secret}"',
        "confidence": 0.5,
    }

    result = llm_analyzer.refine_finding(finding)

    assert captured, "Expected the mocked LLM request to be made"
    assert fake_secret not in str(captured)
    assert result["confidence"] == 0.8
    assert result["_llm_suggested_false_positive"] is False



def test_external_llm_requires_explicit_enable(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret")
    monkeypatch.delenv("ENABLE_EXTERNAL_LLM_REFINEMENT", raising=False)
    from app.privacy import external_llm_enabled
    assert external_llm_enabled() is False


def test_logout_revokes_existing_token(client):
    signup = client.post("/auth/signup", json={"email":"logout@example.com","password":"strongpassword123","organization_name":"LogoutOrg"}).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    assert client.get("/repositories", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 200
    assert client.get("/repositories", headers=headers).status_code == 401


def test_delete_repository_removes_scans(client):
    demo_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "demo_repo"))
    signup = client.post("/auth/signup", json={"email":"delete@example.com","password":"strongpassword123","organization_name":"DeleteOrg"}).json()
    headers = {"Authorization": f"Bearer {signup['access_token']}"}
    repo = client.post("/repositories", json={"repo_url":f"file://{demo_path}"}, headers=headers).json()
    scan = client.post(f"/repositories/{repo['id']}/scan", headers=headers).json()
    assert scan["status"] == "completed"
    assert client.delete(f"/repositories/{repo['id']}", headers=headers).status_code == 200
    assert client.get(f"/scans/{scan['id']}", headers=headers).status_code == 404


def test_sql_analyzer_does_not_flag_frontend_onclick():
    from app.scanner.security_analyzer import analyze_security
    findings = analyze_security("frontend/pages/intake.js", 'onClick={() => select(val)}\n')
    assert not any(f["capability"] == "sql_injection" for f in findings)

def test_stored_source_snippet_is_encrypted(monkeypatch):
    monkeypatch.setenv("STORE_SOURCE_SNIPPETS", "true")
    monkeypatch.setenv("SOURCE_EVIDENCE_ENCRYPTION_KEY", "")
    # Use the model property; the mapped DB column must not contain plaintext.
    from app import models
    finding = models.Finding()
    finding.snippet = "proprietary_customer_logic()"
    assert finding._snippet_ciphertext != "proprietary_customer_logic()"
    assert finding.snippet == "proprietary_customer_logic()"


def test_fix_generator_rejects_path_traversal(tmp_path):
    from app.scanner.fix_generator import apply_fix_to_local_file
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n")
    root = tmp_path / "repo"
    root.mkdir()
    fix = {"file_path": "../outside.py", "line": 1, "inserted_code": "# unsafe"}
    with pytest.raises(FileNotFoundError):
        apply_fix_to_local_file(str(root), fix)


def test_fix_generator_rejects_symlink_escape(tmp_path):
    from app.scanner.fix_generator import apply_fix_to_local_file

    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    link = root / "linked.py"

    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is not permitted on this system")

    fix = {
        "file_path": "linked.py",
        "line": 1,
        "inserted_code": "# unsafe",
    }
    with pytest.raises(FileNotFoundError):
        apply_fix_to_local_file(str(root), fix)

    assert outside.read_text(encoding="utf-8") == "secret = True\n"


def test_fix_generator_rejects_stale_source_line(tmp_path):
    from app.scanner.fix_generator import apply_fix_to_local_file

    root = tmp_path / "repo"
    root.mkdir()
    source = root / "example.py"
    source.write_text("value = 2\n", encoding="utf-8")

    fix = {
        "file_path": "example.py",
        "line": 1,
        "before": "value = 1",
        "inserted_code": "# guard",
    }
    with pytest.raises(ValueError, match="Source line changed"):
        apply_fix_to_local_file(str(root), fix)

    assert source.read_text(encoding="utf-8") == "value = 2\n"


def test_fix_generator_rejects_invalid_line_number(tmp_path):
    from app.scanner.fix_generator import apply_fix_to_local_file

    root = tmp_path / "repo"
    root.mkdir()
    source = root / "example.py"
    source.write_text("value = 1\n", encoding="utf-8")

    fix = {
        "file_path": "example.py",
        "line": 0,
        "before": "value = 1",
        "inserted_code": "# guard",
    }
    with pytest.raises(ValueError, match="positive integer"):
        apply_fix_to_local_file(str(root), fix)

    assert source.read_text(encoding="utf-8") == "value = 1\n"
