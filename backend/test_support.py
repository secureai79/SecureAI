"""Help & Support contact endpoint."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 's.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("EMAIL_FROM", "SecureAI <founder@secureai.example>")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.delenv("SUPPORT_EMAIL", raising=False)
    monkeypatch.delenv("EMAIL_REPLY_TO", raising=False)
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        c.outbox = email_service.OUTBOX
        yield c


def auth_headers(client, email="user@acme.com"):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": "Acme"})
    client.outbox.clear()
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


BODY = {"category": "bug", "subject": "Scan stuck", "message": "My scan has been running for ten minutes."}


def test_request_reaches_support_with_reply_to_and_user_gets_confirmation(client):
    h = auth_headers(client)
    r = client.post("/support/requests", json=BODY, headers=h)
    assert r.status_code == 200 and r.json()["ticket"].startswith("SUP-")
    to_support, to_user = client.outbox
    assert to_support["to"] == "founder@secureai.example" and to_support["reply_to"] == "user@acme.com"
    assert r.json()["ticket"] in to_support["subject"] and "user@acme.com" in to_support["text"]
    assert "Scan stuck" in to_support["text"] and "ten minutes" in to_support["text"]
    assert to_user["to"] == "user@acme.com" and r.json()["ticket"] in to_user["subject"]


def test_support_address_prefers_support_email_setting(client, monkeypatch):
    monkeypatch.setenv("SUPPORT_EMAIL", "help@secureai.example")
    h = auth_headers(client)
    assert client.get("/support/info", headers=h).json()["email"] == "help@secureai.example"
    client.post("/support/requests", json=BODY, headers=h)
    assert client.outbox[0]["to"] == "help@secureai.example"


def test_validation_auth_and_header_injection(client):
    h = auth_headers(client)
    assert client.post("/support/requests", json=BODY).status_code in (401, 403)
    assert client.post("/support/requests", json={**BODY, "category": "spam"}, headers=h).status_code == 422
    assert client.post("/support/requests", json={**BODY, "message": "short"}, headers=h).status_code == 422
    assert client.post("/support/requests", json={**BODY, "message": "x" * 4001}, headers=h).status_code == 422
    r = client.post("/support/requests", json={**BODY, "subject": "Hi\r\nBcc: evil@x.com"}, headers=h)
    assert r.status_code == 200
    assert "\n" not in client.outbox[0]["subject"] and "\r" not in client.outbox[0]["subject"]


def test_html_in_message_is_escaped_in_the_html_part(client):
    h = auth_headers(client)
    client.post("/support/requests", json={**BODY, "message": "<script>alert(1)</script> please help me"}, headers=h)
    assert "<script>" not in client.outbox[0]["html"] and "&lt;script&gt;" in client.outbox[0]["html"]


def test_unconfigured_email_returns_clear_503(client, monkeypatch):
    h = auth_headers(client)
    monkeypatch.setenv("EMAIL_BACKEND", "disabled")
    assert client.post("/support/requests", json=BODY, headers=h).status_code == 503


def test_support_requests_are_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    from app.rate_limit import reset_rate_limits
    h = auth_headers(client)
    reset_rate_limits()
    codes = [client.post("/support/requests", json=BODY, headers=h).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]
