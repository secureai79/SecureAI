"""Two-factor authentication: TOTP, replay and brute-force protection, recovery codes, token separation."""
import base64
import os
import sys
import time
import types

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"
EMAIL = "founder@acme.com"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'mfa.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        yield c


class Clock:
    """Controllable time for app.mfa so we can move between 30-second steps."""
    def __init__(self, mfa, monkeypatch):
        self.t = time.time()
        monkeypatch.setattr(mfa, "time", types.SimpleNamespace(time=lambda: self.t))
    def next_step(self, n=1):
        self.t += 30 * n


def headers(tok):
    return {"Authorization": f"Bearer {tok}"}


def signup(client):
    r = client.post("/auth/signup", json={"email": EMAIL, "password": PW, "organization_name": "Acme"})
    assert r.status_code == 200
    return r.json()["access_token"]


def enable(client, tok, mfa, clock):
    r = client.post("/auth/2fa/setup", headers=headers(tok), json={"password": PW})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    code = mfa._code_at(secret, int(clock.t // 30))
    r = client.post("/auth/2fa/enable", headers=headers(tok), json={"code": code})
    assert r.status_code == 200, r.text
    clock.next_step()                                  # the enable code's step is now burned
    return secret, r.json()


def code_now(mfa, secret, clock):
    return mfa._code_at(secret, int(clock.t // 30))


def login_start(client):
    r = client.post("/auth/login", json={"email": EMAIL, "password": PW})
    assert r.status_code == 200
    return r.json()


# ------------------------------------------------------------------ unit
def test_totp_matches_rfc6238_vectors():
    from app import mfa
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa._code_at(secret, 59 // 30) == "287082"
    assert mfa._code_at(secret, 1111111109 // 30) == "081804"
    assert mfa.match_step(secret, "287 082", now=59) == 59 // 30       # spaces tolerated
    assert mfa.match_step(secret, "287082", now=59 + 30) == 59 // 30   # one step of drift allowed
    assert mfa.match_step(secret, "287082", now=59 + 90) is None       # but not three
    assert mfa.match_step(secret, "12345", now=59) is None and mfa.match_step(secret, "abcdef", now=59) is None


# ------------------------------------------------------------------ setup / enable
def test_setup_needs_password_returns_qr_and_stores_seed_encrypted(client, monkeypatch):
    from app import mfa
    tok = signup(client)
    assert client.post("/auth/2fa/setup", headers=headers(tok), json={"password": "wrong-password-1"}).status_code == 400
    assert client.post("/auth/2fa/setup", json={"password": PW}).status_code in (401, 403)
    r = client.post("/auth/2fa/setup", headers=headers(tok), json={"password": PW}).json()
    assert r["otpauth_uri"].startswith("otpauth://totp/") and "secret=" + r["secret"] in r["otpauth_uri"]
    assert r["qr"].startswith("data:image/svg+xml")
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        stored = db.query(models.User).first().totp_secret_enc
    assert stored and r["secret"] not in stored                       # encrypted at rest
    st = client.get("/auth/2fa/status", headers=headers(tok)).json()
    assert st == {"enabled": False, "pending_setup": True, "recovery_codes_remaining": 0}


def test_enable_requires_a_valid_code_then_rotates_session_and_issues_codes(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    tok = signup(client)
    secret = client.post("/auth/2fa/setup", headers=headers(tok), json={"password": PW}).json()["secret"]
    assert client.post("/auth/2fa/enable", headers=headers(tok), json={"code": "000000"}).status_code == 400
    code = mfa._code_at(secret, int(clock.t // 30))
    r = client.post("/auth/2fa/enable", headers=headers(tok), json={"code": code})
    assert r.status_code == 200
    data = r.json()
    assert len(data["recovery_codes"]) == 10 and len(set(data["recovery_codes"])) == 10
    assert client.get("/auth/me", headers=headers(tok)).status_code == 401              # old session revoked
    new = headers(data["access_token"])
    assert client.get("/auth/me", headers=new).json()["two_factor_enabled"] is True
    assert client.get("/auth/2fa/status", headers=new).json() == {"enabled": True, "pending_setup": False, "recovery_codes_remaining": 10}
    assert client.post("/auth/2fa/setup", headers=new, json={"password": PW}).status_code == 400   # already on
    from app import email_service
    assert any("Two-factor authentication turned on" in m["subject"] for m in email_service.OUTBOX)


# ------------------------------------------------------------------ sign-in
def test_login_needs_second_step_and_challenge_is_not_an_access_token(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, _ = enable(client, signup(client), mfa, clock)
    first = login_start(client)
    assert first["mfa_required"] is True and "access_token" not in first
    assert client.get("/auth/me", headers=headers(first["mfa_token"])).status_code == 401   # token separation
    assert client.post("/auth/login/2fa", json={"mfa_token": first["mfa_token"], "code": "111111"}).status_code == 401
    ok = client.post("/auth/login/2fa", json={"mfa_token": first["mfa_token"], "code": code_now(mfa, secret, clock)})
    assert ok.status_code == 200 and client.get("/auth/me", headers=headers(ok.json()["access_token"])).status_code == 200
    assert client.post("/auth/login/2fa", json={"mfa_token": "x" * 40, "code": "123456"}).status_code == 401


def test_a_code_cannot_be_replayed(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, _ = enable(client, signup(client), mfa, clock)
    code = code_now(mfa, secret, clock)
    a = login_start(client)
    assert client.post("/auth/login/2fa", json={"mfa_token": a["mfa_token"], "code": code}).status_code == 200
    b = login_start(client)
    assert client.post("/auth/login/2fa", json={"mfa_token": b["mfa_token"], "code": code}).status_code == 401
    clock.next_step()
    assert client.post("/auth/login/2fa", json={"mfa_token": b["mfa_token"], "code": code_now(mfa, secret, clock)}).status_code == 200


def test_guessing_codes_locks_the_account_even_if_the_password_is_known(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, _ = enable(client, signup(client), mfa, clock)
    kept = login_start(client)                              # a challenge obtained before the attack
    for _ in range(5):
        challenge = login_start(client)                    # password is correct every time
        client.post("/auth/login/2fa", json={"mfa_token": challenge["mfa_token"], "code": "000000"})
    # locked at BOTH steps: the right code with a valid challenge no longer works, nor does the password step
    r = client.post("/auth/login/2fa", json={"mfa_token": kept["mfa_token"], "code": code_now(mfa, secret, clock)})
    assert r.status_code == 429
    assert client.post("/auth/login", json={"email": EMAIL, "password": PW}).status_code == 429


def test_changing_the_password_invalidates_a_pending_challenge(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, data = enable(client, signup(client), mfa, clock)
    challenge = login_start(client)
    r = client.post("/auth/change-password", headers=headers(data["access_token"]),
                    json={"current_password": PW, "new_password": "another-long-passphrase-2"})
    assert r.status_code == 200
    assert client.post("/auth/login/2fa", json={"mfa_token": challenge["mfa_token"], "code": code_now(mfa, secret, clock)}).status_code == 401


def test_password_reset_does_not_switch_two_factor_off(client, monkeypatch):
    from app import email_service, mfa
    clock = Clock(mfa, monkeypatch)
    enable(client, signup(client), mfa, clock)
    email_service.OUTBOX.clear()
    client.post("/auth/forgot-password", json={"email": EMAIL})
    import re
    tok = re.search(r"#token=([A-Za-z0-9_-]+)", email_service.OUTBOX[0]["text"]).group(1)
    assert client.post("/auth/reset-password", json={"token": tok, "new_password": "brand-new-passphrase-9"}).status_code == 200
    r = client.post("/auth/login", json={"email": EMAIL, "password": "brand-new-passphrase-9"})
    assert r.json().get("mfa_required") is True


# ------------------------------------------------------------------ recovery codes
def test_recovery_code_works_once(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, data = enable(client, signup(client), mfa, clock)
    code = data["recovery_codes"][0]
    a = login_start(client)
    r = client.post("/auth/login/2fa", json={"mfa_token": a["mfa_token"], "code": code.lower()})   # case/format tolerant
    assert r.status_code == 200
    b = login_start(client)
    assert client.post("/auth/login/2fa", json={"mfa_token": b["mfa_token"], "code": code}).status_code == 401
    assert client.get("/auth/2fa/status", headers=headers(r.json()["access_token"])).json()["recovery_codes_remaining"] == 9


def test_regenerating_codes_needs_password_and_a_totp_code_and_kills_old_codes(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, data = enable(client, signup(client), mfa, clock)
    h = headers(data["access_token"])
    old = data["recovery_codes"][0]
    assert client.post("/auth/2fa/recovery-codes", headers=h, json={"password": "nope-nope-nope-1", "code": code_now(mfa, secret, clock)}).status_code == 400
    assert client.post("/auth/2fa/recovery-codes", headers=h, json={"password": PW, "code": old}).status_code == 400   # recovery code not accepted here
    r = client.post("/auth/2fa/recovery-codes", headers=h, json={"password": PW, "code": code_now(mfa, secret, clock)})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
    chal = login_start(client)
    assert client.post("/auth/login/2fa", json={"mfa_token": chal["mfa_token"], "code": old}).status_code == 401


# ------------------------------------------------------------------ disable
def test_disable_needs_password_and_code_then_login_is_single_step_again(client, monkeypatch):
    from app import mfa
    clock = Clock(mfa, monkeypatch)
    secret, data = enable(client, signup(client), mfa, clock)
    h = headers(data["access_token"])
    assert client.post("/auth/2fa/disable", headers=h, json={"password": PW, "code": "000000"}).status_code == 400
    assert client.post("/auth/2fa/disable", headers=h, json={"password": "nope-nope-nope-1", "code": code_now(mfa, secret, clock)}).status_code == 400
    r = client.post("/auth/2fa/disable", headers=h, json={"password": PW, "code": code_now(mfa, secret, clock)})
    assert r.status_code == 200
    assert client.get("/auth/me", headers=h).status_code == 401                          # old session revoked
    assert "access_token" in login_start(client)                                         # straight in again
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        u = db.query(models.User).first()
        assert u.totp_secret_enc is None and db.query(models.MfaRecoveryCode).count() == 0


# ------------------------------------------------------------------ request size
def test_oversized_request_bodies_are_rejected(client):
    big = '{"email":"a@b.com","password":"' + "x" * (1024 * 1024 + 10) + '"}'
    r = client.post("/auth/login", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_setup_still_works_without_the_qr_library(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "segno", None)               # makes `import segno` fail
    tok = signup(client)
    r = client.post("/auth/2fa/setup", headers=headers(tok), json={"password": PW})
    assert r.status_code == 200
    body = r.json()
    assert body["qr"] is None and len(body["secret"]) == 32 and body["otpauth_uri"].startswith("otpauth://totp/")
