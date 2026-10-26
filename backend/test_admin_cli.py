"""The operator CLI (scripts/admin.py)."""
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db = tmp_path / "admin.db"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    with TestClient(app) as c:
        yield c, {**os.environ, "DATABASE_URL": f"sqlite:///{db}"}


def admin(env_vars, *args):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "admin.py"), *args],
                       capture_output=True, text=True, env=env_vars, cwd=ROOT)
    return r.returncode, r.stdout + r.stderr


def test_reset_2fa_unlock_verify_and_revoke(env):
    c, e = env
    tok = c.post("/auth/signup", json={"email": "u@x.com", "password": PW, "organization_name": "O"}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    secret = c.post("/auth/2fa/setup", headers=h, json={"password": PW}).json()["secret"]
    from app import mfa
    import time
    tok = c.post("/auth/2fa/enable", headers=h, json={"code": mfa._code_at(secret, int(time.time() // 30))}).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert c.get("/auth/me", headers=h).json()["two_factor_enabled"] is True
    for _ in range(5):
        c.post("/auth/login", json={"email": "u@x.com", "password": "wrong-password-xyz"})
    assert c.post("/auth/login", json={"email": "u@x.com", "password": PW}).status_code == 429

    code, out = admin(e, "reset-2fa", "u@x.com")
    assert code != 0 and "--yes" in out                                           # refuses without confirmation
    code, out = admin(e, "reset-2fa", "U@X.com", "--yes")
    assert code == 0 and "OFF" in out
    assert c.get("/auth/me", headers=h).status_code == 401                         # sessions ended
    login = c.post("/auth/login", json={"email": "u@x.com", "password": PW})
    assert login.status_code == 200 and "access_token" in login.json()             # lockout cleared too, single-step login again

    assert "Unlocked" in admin(e, "unlock", "u@x.com")[1]
    assert "verified" in admin(e, "verify-email", "u@x.com")[1]
    out = admin(e, "show", "u@x.com")[1]
    assert "verified: True" in out and "2FA: off" in out and "as owner" in out
    users = admin(e, "users")[1]
    assert "u@x.com" in users and "1 account(s)" in users

    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        actions = {a.action for a in db.query(models.AuditEvent).all()}
    assert {"admin.reset_2fa", "admin.unlock", "admin.verify_email"} <= actions    # everything is on the record


def test_set_plan_and_unknown_account(env):
    c, e = env
    c.post("/auth/signup", json={"email": "u@x.com", "password": PW, "organization_name": "O"})
    org = c.post("/auth/login", json={"email": "u@x.com", "password": PW}).json()["organization_id"]
    assert admin(e, "set-plan", org, "bogus")[0] != 0
    assert "team plan" in admin(e, "set-plan", org, "team")[1]
    assert admin(e, "show", "nobody@x.com")[0] != 0
