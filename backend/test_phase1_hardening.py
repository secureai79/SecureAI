import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

PW = "a-very-long-passphrase-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    with TestClient(app) as c:
        yield c


def _signup(client, email="o@example.com"):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": "Org"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _repo(client, h, name="r1"):
    r = client.post("/repositories", headers=h, json={"repo_url": f"file://{os.path.abspath('../demo_repo')}/{name}", "repo_name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


# ---------- rate limiter ----------
def test_scan_route_is_normalised_so_repo_ids_do_not_multiply_the_limit():
    from app import rate_limit
    assert rate_limit.normalize_path("/repositories/repo_abc/scan") == "/repositories/{id}/scan"
    assert rate_limit.normalize_path("/repositories/repo_xyz/scan") == "/repositories/{id}/scan"
    assert rate_limit.normalize_path("/repositories") == "/repositories"


def test_scan_limit_applies_across_different_repositories(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    import importlib
    from app import rate_limit
    importlib.reload(rate_limit)
    rate_limit.reset_rate_limits()

    class Req:
        method = "POST"
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()
        def __init__(self, path): self.url = type("U", (), {"path": path})()

    results = [rate_limit.check_rate_limit(Req(f"/repositories/repo_{i}/scan")) for i in range(12)]
    assert sum(r is not None for r in results) == 2  # 10 allowed, then blocked even for new repo ids


def test_forwarded_for_only_trusted_behind_configured_proxies(monkeypatch):
    from app import rate_limit

    class Req:
        headers = {"x-forwarded-for": "9.9.9.9, 10.0.0.1"}
        client = type("C", (), {"host": "172.17.0.2"})()

    monkeypatch.delenv("TRUSTED_PROXY_COUNT", raising=False)
    assert rate_limit.client_ip(Req()) == "172.17.0.2"      # header ignored: spoofable
    monkeypatch.setenv("TRUSTED_PROXY_COUNT", "1")
    assert rate_limit.client_ip(Req()) == "10.0.0.1"         # last hop added by our proxy


# ---------- quotas ----------
def test_repository_is_deduplicated_and_capped(client, monkeypatch):
    h = _signup(client)
    a = _repo(client, h, "same")
    assert _repo(client, h, "same") == a
    monkeypatch.setenv("MAX_REPOS_PER_ORG", "1")
    r = client.post("/repositories", headers=h, json={"repo_url": "file:///tmp/other", "repo_name": "other"})
    assert r.status_code == 403


def test_concurrent_scan_quota_blocks_second_scan(client, monkeypatch):
    from app import models
    from app.database import SessionLocal
    h = _signup(client)
    repo_id = _repo(client, h)
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "1")
    with SessionLocal() as db:
        db.add(models.Scan(repository_id=repo_id, status="processing")); db.commit()
    r = client.post(f"/repositories/{repo_id}/scan", headers=h)
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_stale_processing_scans_are_expired_not_counted(client, monkeypatch):
    import datetime as dt
    from app import models
    from app.database import SessionLocal
    h = _signup(client)
    repo_id = _repo(client, h)
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "1")
    with SessionLocal() as db:
        db.add(models.Scan(repository_id=repo_id, status="processing", started_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)))
        db.commit()
    r = client.post(f"/repositories/{repo_id}/scan", headers=h)
    assert r.status_code != 429


def test_daily_scan_cap(client, monkeypatch):
    from app import models
    from app.database import SessionLocal
    h = _signup(client)
    repo_id = _repo(client, h)
    monkeypatch.setenv("DAILY_SCANS_PER_ORG", "1")
    with SessionLocal() as db:
        db.add(models.Scan(repository_id=repo_id, status="completed")); db.commit()
    assert client.post(f"/repositories/{repo_id}/scan", headers=h).status_code == 429


def test_global_slot_returns_503_when_saturated():
    from fastapi import HTTPException
    from app import quota
    held = []
    try:
        for _ in range(64):
            s = quota.ScanSlot(); s.__enter__(); held.append(s)
    except HTTPException as exc:
        assert exc.status_code == 503
    else:
        pytest.fail("global concurrency guard never tripped")
    finally:
        for s in held:
            s.__exit__(None, None, None)


# ---------- authentication ----------
def test_account_locks_after_repeated_failures_even_with_correct_password(client, monkeypatch):
    monkeypatch.setenv("LOGIN_LOCKOUT_THRESHOLD", "3")
    from app import auth
    auth.LOCKOUT_THRESHOLD = 3
    _signup(client, "lock@example.com")
    for _ in range(3):
        assert client.post("/auth/login", json={"email": "lock@example.com", "password": "wrong-password-1"}).status_code == 401
    r = client.post("/auth/login", json={"email": "lock@example.com", "password": PW})
    assert r.status_code == 429 and "Retry-After" in r.headers


def test_legacy_password_hash_is_upgraded_on_login(client):
    import hashlib, secrets
    from app import models
    from app.database import SessionLocal
    _signup(client, "old@example.com")
    salt = secrets.token_hex(16)
    legacy = f"pbkdf2_sha256$260000${salt}${hashlib.pbkdf2_hmac('sha256', PW.encode(), bytes.fromhex(salt), 260000).hex()}"
    with SessionLocal() as db:
        u = db.query(models.User).filter_by(email="old@example.com").first(); u.hashed_password = legacy; db.commit()
    assert client.post("/auth/login", json={"email": "old@example.com", "password": PW}).status_code == 200
    with SessionLocal() as db:
        assert db.query(models.User).filter_by(email="old@example.com").first().hashed_password.startswith("pbkdf2_sha256$600000$")


def test_weak_passwords_rejected(client):
    for pw in ("passwordpassword", "aaaaaaaaaaaaaaaa", "x" * 300):
        r = client.post("/auth/signup", json={"email": f"{len(pw)}@example.com", "password": pw, "organization_name": "O"})
        assert r.status_code == 400


# ---------- audit trail ----------
def test_audit_log_records_events_for_owner_only(client):
    h = _signup(client)
    repo_id = _repo(client, h)
    client.post("/auth/login", json={"email": "o@example.com", "password": "bad-password-123"})
    events = client.get("/auth/audit", headers=h).json()
    actions = {e["action"] for e in events}
    assert {"auth.signup", "repo.created", "auth.login_failed"} <= actions
    other = _signup(client, "other@example.com")
    assert all(e["detail"] is None or "o@example.com" not in str(e) for e in client.get("/auth/audit", headers=other).json())


def test_audit_trail_survives_organisation_deletion(client):
    from app import models
    from app.database import SessionLocal
    h = _signup(client)
    assert client.request("DELETE", "/auth/data", headers=h, json={"confirmation": "DELETE"}).status_code == 200
    with SessionLocal() as db:
        assert db.query(models.AuditEvent).filter_by(action="org.data_deleted").count() == 1


# ---------- misc hardening ----------
def test_readiness_checks_database(client):
    assert client.get("/ready").json() == {"status": "ready"}


def test_authenticated_responses_are_not_cached(client):
    h = _signup(client)
    assert client.get("/repositories", headers=h).headers["Cache-Control"] == "no-store"


def test_scan_debug_log_is_off_by_default(tmp_path, monkeypatch):
    from app.scanner import scan_service
    monkeypatch.delenv("SCAN_DEBUG_LOG", raising=False)
    monkeypatch.setattr("builtins.open", lambda *a, **k: (_ for _ in ()).throw(AssertionError("wrote debug log")))
    scan_service._scan_debug("FILE_START secret/customer/path.py")


# ---------- key handling ----------
def test_production_requires_encryption_key_for_github_app_only(monkeypatch):
    import importlib
    from app import config
    importlib.reload(config)
    base = {
        "ENVIRONMENT": "production", "JWT_SECRET": "x" * 40, "CORS_ALLOWED_ORIGINS": "https://a.example",
        "DATABASE_URL": "postgresql://u:p@h/db", "GITHUB_APP_ID": "1", "GITHUB_APP_SLUG": "s",
        "GITHUB_APP_PRIVATE_KEY": "pem",
        "EMAIL_BACKEND": "smtp", "SMTP_HOST": "smtp.example.com", "EMAIL_FROM": "App <no-reply@example.com>",
    }
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("GITHUB_TOKEN_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GITHUB_TOKEN_ENCRYPTION_KEY"):
        config.validate_startup_config()
    monkeypatch.setenv("GITHUB_TOKEN_ENCRYPTION_KEY", "not-a-key")
    with pytest.raises(RuntimeError, match="invalid Fernet"):
        config.validate_startup_config()
    from cryptography.fernet import Fernet
    monkeypatch.setenv("GITHUB_TOKEN_ENCRYPTION_KEY", Fernet.generate_key().decode())
    config.validate_startup_config()


def test_placeholder_jwt_secret_rejected_in_production(monkeypatch):
    from app import config
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "replace-with-a-long-random-secret")
    with pytest.raises(RuntimeError):
        config.validate_startup_config()


def test_key_rotation_old_ciphertext_still_decrypts(monkeypatch):
    from cryptography.fernet import Fernet
    from app import keyring
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    monkeypatch.setenv("K", old)
    token = keyring.build_fernet("K").encrypt(b"secret")
    monkeypatch.setenv("K", f"{new},{old}")
    rotated = keyring.build_fernet("K")
    assert rotated.decrypt(token) == b"secret"
    assert Fernet(new.encode()).decrypt(rotated.encrypt(b"x")) == b"x"  # new key now encrypts


def test_production_has_no_ephemeral_key_fallback(monkeypatch):
    from app import keyring
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("SOME_KEY", raising=False)
    with pytest.raises(RuntimeError):
        keyring.build_fernet("SOME_KEY")
