"""E-mail verification, password reset, password change, SMTP delivery and production config checks."""
import datetime as dt
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

PW = "correct-horse-battery-1"
NEW_PW = "another-long-passphrase-2"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'e.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
    monkeypatch.setenv("FRONTEND_URL", "http://127.0.0.1:5500")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PASSWORD_RESET_COOLDOWN_SECONDS", "60")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        c.outbox = email_service.OUTBOX
        yield c


def signup(client, email="founder@acme.com"):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": "Acme"})
    assert r.status_code == 200, r.text
    return r.json(), {"Authorization": f"Bearer {r.json()['access_token']}"}


def token_from(msg, page):
    m = re.search(rf"/{page}\.html#token=([A-Za-z0-9_-]+)", msg["text"])
    assert m, msg["text"]
    return m.group(1)


# ------------------------------------------------------------ verification
def test_signup_sends_verification_link_and_me_reports_unverified(client):
    data, h = signup(client)
    assert data["verification_email_sent"] is True
    assert len(client.outbox) == 1 and client.outbox[0]["to"] == "founder@acme.com"
    me = client.get("/auth/me", headers=h).json()
    assert me["email"] == "founder@acme.com"
    assert me["email_verified"] is False and me["verification_required"] is True


def test_unverified_user_cannot_add_repo_or_scan_until_verified(client):
    _, h = signup(client)
    r = client.post("/repositories", json={"repo_url": "https://github.com/octo/demo"}, headers=h)
    assert r.status_code == 403 and "verify your email" in r.json()["detail"].lower()
    tok = token_from(client.outbox[0], "verify-email")
    assert client.post("/auth/verify-email", json={"token": tok}).status_code == 200
    assert client.get("/auth/me", headers=h).json()["email_verified"] is True
    r = client.post("/repositories", json={"repo_url": "https://github.com/octo/demo"}, headers=h)
    assert r.status_code == 200, r.text


def test_verification_token_is_single_use_and_garbage_rejected(client):
    signup(client)
    tok = token_from(client.outbox[0], "verify-email")
    assert client.post("/auth/verify-email", json={"token": tok}).status_code == 200
    r = client.post("/auth/verify-email", json={"token": tok})
    assert r.status_code == 400 and "invalid or has expired" in r.json()["detail"]
    assert client.post("/auth/verify-email", json={"token": "x" * 43}).status_code == 400
    assert client.post("/auth/verify-email", json={"token": "short"}).status_code == 422


def test_expired_token_rejected(client):
    signup(client)
    tok = token_from(client.outbox[0], "verify-email")
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        row = db.query(models.EmailToken).first()
        row.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
        db.commit()
    assert client.post("/auth/verify-email", json={"token": tok}).status_code == 400


def test_only_a_hash_of_the_token_is_stored(client):
    signup(client)
    tok = token_from(client.outbox[0], "verify-email")
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        row = db.query(models.EmailToken).first()
        assert tok not in row.token_hash and len(row.token_hash) == 64


def test_resend_verification_has_cooldown_and_new_link_replaces_old(client):
    _, h = signup(client)
    first = token_from(client.outbox[0], "verify-email")
    r = client.post("/auth/resend-verification", headers=h)
    assert r.status_code == 429 and r.headers["Retry-After"]
    # age the first token past the cooldown, then resend
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        for row in db.query(models.EmailToken).all():
            row.created_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=5)
        db.commit()
    assert client.post("/auth/resend-verification", headers=h).status_code == 200
    assert len(client.outbox) == 2
    assert client.post("/auth/verify-email", json={"token": first}).status_code == 400   # replaced
    second = token_from(client.outbox[1], "verify-email")
    assert client.post("/auth/verify-email", json={"token": second}).status_code == 200
    assert client.post("/auth/resend-verification", headers=h).json()["email_verified"] is True


def test_verification_not_enforced_when_disabled(client, monkeypatch):
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    _, h = signup(client)
    assert client.get("/auth/me", headers=h).json()["verification_required"] is False
    r = client.post("/repositories", json={"repo_url": "https://github.com/octo/demo"}, headers=h)
    assert r.status_code == 200


# ------------------------------------------------------------ password reset
def test_forgot_password_answers_identically_for_known_and_unknown(client):
    signup(client)
    client.outbox.clear()
    a = client.post("/auth/forgot-password", json={"email": "founder@acme.com"})
    b = client.post("/auth/forgot-password", json={"email": "nobody@acme.com"})
    assert a.status_code == b.status_code == 200 and a.json() == b.json()
    assert len(client.outbox) == 1 and client.outbox[0]["to"] == "founder@acme.com"


def test_forgot_password_cooldown_and_hourly_cap_are_silent(client, monkeypatch):
    monkeypatch.setenv("PASSWORD_RESET_COOLDOWN_SECONDS", "0")
    monkeypatch.setenv("PASSWORD_RESET_MAX_PER_HOUR", "2")
    signup(client)
    client.outbox.clear()
    for _ in range(5):
        assert client.post("/auth/forgot-password", json={"email": "founder@acme.com"}).status_code == 200
    assert len(client.outbox) == 2


def test_reset_flow_changes_password_logs_out_devices_and_is_single_use(client):
    _, h = signup(client)
    client.outbox.clear()
    client.post("/auth/forgot-password", json={"email": "founder@acme.com"})
    tok = token_from(client.outbox[0], "reset-password")
    # a weak password is refused WITHOUT burning the link
    assert client.post("/auth/reset-password", json={"token": tok, "new_password": "short"}).status_code == 400
    r = client.post("/auth/reset-password", json={"token": tok, "new_password": NEW_PW})
    assert r.status_code == 200
    assert client.get("/repositories", headers=h).status_code == 401              # old session revoked
    assert client.post("/auth/login", json={"email": "founder@acme.com", "password": PW}).status_code == 401
    assert client.post("/auth/login", json={"email": "founder@acme.com", "password": NEW_PW}).status_code == 200
    r = client.post("/auth/reset-password", json={"token": tok, "new_password": "yet-another-pass-3"})
    assert r.status_code == 400 and "invalid or has expired" in r.json()["detail"]
    assert any("password was changed" in m["subject"] for m in client.outbox)       # security notice sent


def test_reset_marks_email_verified_and_clears_lockout(client):
    signup(client)
    for _ in range(5):
        client.post("/auth/login", json={"email": "founder@acme.com", "password": "wrong-password-xyz"})
    assert client.post("/auth/login", json={"email": "founder@acme.com", "password": PW}).status_code == 429
    client.outbox.clear()
    client.post("/auth/forgot-password", json={"email": "founder@acme.com"})
    tok = token_from(client.outbox[0], "reset-password")
    assert client.post("/auth/reset-password", json={"token": tok, "new_password": NEW_PW}).status_code == 200
    r = client.post("/auth/login", json={"email": "founder@acme.com", "password": NEW_PW})
    assert r.status_code == 200
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/auth/me", headers=h).json()["email_verified"] is True


def test_reset_token_cannot_be_used_as_verification_token(client):
    signup(client)
    client.outbox.clear()
    client.post("/auth/forgot-password", json={"email": "founder@acme.com"})
    tok = token_from(client.outbox[0], "reset-password")
    assert client.post("/auth/verify-email", json={"token": tok}).status_code == 400


# ------------------------------------------------------------ change password
def test_change_password_rotates_session_and_notifies(client):
    _, h = signup(client)
    client.outbox.clear()
    r = client.post("/auth/change-password", headers=h, json={"current_password": PW, "new_password": NEW_PW})
    assert r.status_code == 200 and r.json()["access_token"]
    assert client.get("/auth/me", headers=h).status_code == 401
    new_h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert client.get("/auth/me", headers=new_h).status_code == 200
    assert any("password was changed" in m["subject"] for m in client.outbox)


def test_change_password_validation_and_bruteforce_protection(client):
    _, h = signup(client)
    body = lambda cur, new: {"current_password": cur, "new_password": new}  # noqa: E731
    assert client.post("/auth/change-password", headers=h, json=body(PW, PW)).status_code == 400
    assert client.post("/auth/change-password", headers=h, json=body(PW, "short")).status_code == 400
    for _ in range(5):
        assert client.post("/auth/change-password", headers=h, json=body("nope-nope-nope-1", NEW_PW)).status_code == 400
    assert client.post("/auth/change-password", headers=h, json=body(PW, NEW_PW)).status_code == 429
    assert client.post("/auth/change-password", json=body(PW, NEW_PW)).status_code in (401, 403)


def test_auth_endpoints_are_rate_limited(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    from app.rate_limit import reset_rate_limits
    reset_rate_limits()
    codes = [client.post("/auth/forgot-password", json={"email": "a@b.com"}).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]


# ------------------------------------------------------------ delivery
def test_links_point_at_frontend_and_keep_token_in_fragment(client, monkeypatch):
    monkeypatch.setenv("FRONTEND_URL", "https://app.example.com/")
    signup(client)
    link = re.search(r"https://\S+", client.outbox[0]["text"]).group(0)
    assert link.startswith("https://app.example.com/verify-email.html#token=")
    assert "?" not in link


def test_smtp_backend_uses_starttls_and_login(monkeypatch):
    sys.modules.pop("app.email_service", None)
    from app import email_service as mail
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, **kw): calls.append(("connect", host, port))
        def ehlo(self): calls.append(("ehlo",))
        def starttls(self, context=None): calls.append(("starttls", context is not None))
        def login(self, u, p): calls.append(("login", u, p))
        def send_message(self, msg): calls.append(("send", msg["To"], msg["Subject"], msg["From"]))
        def quit(self): calls.append(("quit",))

    monkeypatch.setattr(mail.smtplib, "SMTP", FakeSMTP)
    for k, v in {"EMAIL_BACKEND": "smtp", "SMTP_HOST": "smtp-relay.brevo.com", "SMTP_PORT": "587",
                 "SMTP_SECURITY": "starttls", "SMTP_USERNAME": "login@smtp-brevo.com",
                 "SMTP_PASSWORD": "key", "EMAIL_FROM": "SecureAI <no-reply@secureai.example>"}.items():
        monkeypatch.setenv(k, v)
    assert mail._send_now("u@x.com", "Hi", "text", "<p>html</p>") is True
    assert ("starttls", True) in calls and ("login", "login@smtp-brevo.com", "key") in calls
    assert ("send", "u@x.com", "Hi", "SecureAI <no-reply@secureai.example>") in calls
    assert calls[-1] == ("quit",)


def test_header_injection_is_rejected(monkeypatch):
    from app import email_service as mail
    monkeypatch.setenv("EMAIL_FROM", "App <no-reply@example.com>")
    with pytest.raises(ValueError):
        mail._build("a@b.com\r\nBcc: evil@x.com", "s", "t", "<p>t</p>")
    with pytest.raises(ValueError):
        mail._build("a@b.com", "subject\nBcc: evil@x.com", "t", "<p>t</p>")


def test_delivery_failure_never_breaks_signup(client, monkeypatch):
    from app import email_service as mail
    monkeypatch.setattr(mail, "_send_now", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("smtp down")))
    r = client.post("/auth/signup", json={"email": "a@b.com", "password": PW, "organization_name": "O"})
    assert r.status_code in (200,)


# ------------------------------------------------------------ production config
BASE = {
    "ENVIRONMENT": "production", "JWT_SECRET": "x" * 40, "CORS_ALLOWED_ORIGINS": "https://app.example.com",
    "DATABASE_URL": "postgresql://u:p@h/db", "FRONTEND_URL": "https://app.example.com",
    "EMAIL_BACKEND": "smtp", "SMTP_HOST": "smtp.example.com", "SMTP_USERNAME": "u", "SMTP_PASSWORD": "p",
    "EMAIL_FROM": "App <no-reply@example.com>",
}


def _prod(monkeypatch, **over):
    for k in ("GITHUB_APP_ID", "GITHUB_APP_SLUG", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_FILE",
              "GITHUB_CLIENT_ID", "REQUIRE_EMAIL_VERIFICATION", "ALLOW_LOCAL_REPOS"):
        monkeypatch.delenv(k, raising=False)
    for k, v in {**BASE, **over}.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    from app import config
    return config.validate_startup_config


def test_production_accepts_valid_email_config(monkeypatch):
    _prod(monkeypatch)()


@pytest.mark.parametrize("over,match", [
    ({"EMAIL_BACKEND": "console"}, "development/tests only"),
    ({"EMAIL_BACKEND": None}, "no e-mail delivery"),
    ({"SMTP_HOST": ""}, "SMTP_HOST"),
    ({"SMTP_PASSWORD": ""}, "SMTP_PASSWORD"),
    ({"SMTP_SECURITY": "plain"}, "SMTP_SECURITY"),
    ({"FRONTEND_URL": "http://app.example.com"}, "https"),
])
def test_production_rejects_bad_email_or_frontend_config(monkeypatch, over, match):
    with pytest.raises(RuntimeError, match=match):
        _prod(monkeypatch, **over)()


def test_production_allows_localhost_http_frontend_for_local_pilot(monkeypatch):
    _prod(monkeypatch, FRONTEND_URL="http://127.0.0.1:5500")()


def test_production_can_run_without_email_if_verification_disabled(monkeypatch):
    _prod(monkeypatch, EMAIL_BACKEND=None, REQUIRE_EMAIL_VERIFICATION="false")()
