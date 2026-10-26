"""Sign-up must not reveal whether an e-mail address is already registered."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'p.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("FRONTEND_URL", "http://127.0.0.1:5500")
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "true")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        c.outbox = email_service.OUTBOX
        yield c


def signup(client, email="alice@acme.com", pw=PW, org="Acme"):
    return client.post("/auth/signup", json={"email": email, "password": pw, "organization_name": org})


def test_new_and_existing_addresses_get_the_same_answer(client):
    new = signup(client)
    again = signup(client, org="Other")
    assert new.status_code == again.status_code == 200
    assert new.json() == again.json() and "access_token" not in new.json()
    assert new.json()["check_email"] is True


def test_the_new_user_gets_a_confirmation_and_can_log_in_with_the_password(client):
    signup(client)
    assert len(client.outbox) == 1 and "Confirm your email" in client.outbox[0]["subject"]
    r = client.post("/auth/login", json={"email": "alice@acme.com", "password": PW})
    assert r.status_code == 200 and r.json()["access_token"]


def test_the_real_owner_is_told_by_email_and_the_message_carries_no_token(client):
    signup(client)
    client.outbox.clear()
    signup(client)
    assert len(client.outbox) == 1
    m = client.outbox[0]
    assert m["to"] == "alice@acme.com" and "already have" in m["subject"].lower()
    assert "token=" not in m["text"] and "login.html" in m["text"]


def test_notices_are_throttled_so_an_attacker_cannot_mail_bomb_a_victim(client):
    signup(client)
    client.outbox.clear()
    for _ in range(4):
        assert signup(client).status_code == 200
    assert len(client.outbox) == 1


def test_a_duplicate_signup_never_changes_the_existing_account(client):
    signup(client)
    signup(client, pw="a-totally-different-passphrase-9", org="Hijack")
    assert client.post("/auth/login", json={"email": "alice@acme.com", "password": PW}).status_code == 200
    assert client.post("/auth/login", json={"email": "alice@acme.com", "password": "a-totally-different-passphrase-9"}).status_code == 401


def test_validation_errors_do_not_depend_on_whether_the_address_exists(client):
    signup(client)
    for email in ("alice@acme.com", "fresh@acme.com"):
        r = signup(client, email=email, pw="short")
        assert r.status_code == 400 and "12" in r.json()["detail"]


def test_legacy_mode_still_available_for_development(client, monkeypatch):
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "false")
    first = signup(client)
    assert first.status_code == 200 and first.json()["access_token"]
    assert signup(client).status_code == 400
