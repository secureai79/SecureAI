"""Start-up tolerates old Postgres schemas that carry columns the models no longer map.

Runs only when a PostgreSQL database is available:
    TEST_POSTGRES_URL=postgresql+psycopg://user:pass@127.0.0.1:5432/scratch  pytest test_postgres_legacy_schema.py
(use a scratch database: the test creates and then removes one extra column on `users`).
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
URL = os.environ.get("TEST_POSTGRES_URL", "")
pytestmark = pytest.mark.skipif(not URL.startswith("postgresql"), reason="set TEST_POSTGRES_URL to run against PostgreSQL")

LEGACY = "zz_legacy_required_flag"


def test_not_null_legacy_column_no_longer_breaks_signup(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", URL)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from sqlalchemy import text
    from app import database
    database.init_db()
    with database.engine.begin() as conn:
        conn.execute(text(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {LEGACY} BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text(f"ALTER TABLE users ALTER COLUMN {LEGACY} DROP DEFAULT"))
    try:
        from app import models
        assert database._relax_orphan_columns(models) == [f"users.{LEGACY}"]
        assert database._relax_orphan_columns(models) == []                       # idempotent
        from app.main import app
        email = f"legacy-{os.getpid()}@acme.com"
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.post("/auth/signup", json={"email": email, "password": "correct-horse-battery-1", "organization_name": "Legacy"})
            assert r.status_code == 200, r.text
            assert c.post("/auth/login", json={"email": email, "password": "correct-horse-battery-1"}).status_code == 200
    finally:                                              # separate transactions: one failure must not undo the other
        with database.engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE users DROP COLUMN IF EXISTS {LEGACY}"))
        with database.engine.begin() as conn:
            like = "legacy-%@acme.com"
            conn.execute(text("DELETE FROM email_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE :p)"), {"p": like})
            conn.execute(text("DELETE FROM memberships WHERE user_id IN (SELECT id FROM users WHERE email LIKE :p)"), {"p": like})
            conn.execute(text("DELETE FROM audit_events WHERE organization_id IN (SELECT organization_id FROM users WHERE email LIKE :p)"), {"p": like})
            org_ids = [r[0] for r in conn.execute(text("SELECT organization_id FROM users WHERE email LIKE :p"), {"p": like})]
            conn.execute(text("DELETE FROM users WHERE email LIKE :p"), {"p": like})
            for oid in org_ids:
                conn.execute(text("DELETE FROM organizations WHERE id = :i"), {"i": oid})


def test_mapped_columns_and_defaults_are_left_alone(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", URL)
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from sqlalchemy import inspect
    from app import database, models
    database.init_db()
    assert database._relax_orphan_columns(models) == []
    cols = {c["name"]: c for c in inspect(database.engine).get_columns("users")}
    assert cols["email"]["nullable"] is False and cols["hashed_password"]["nullable"] is False
