"""Accounts never see each other's data; GitHub status / disconnect behave and are audited."""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'iso.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    with TestClient(app) as c:
        yield c


def signup(client, email, org):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": org})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_second_account_sees_none_of_the_first_accounts_data(client):
    a = signup(client, "a@acme.com", "OrgA")
    b = signup(client, "b@acme.com", "OrgB")
    repo = client.post("/repositories", json={"repo_url": "https://github.com/octo/demo"}, headers=a).json()
    assert client.get("/repositories", headers=a).json()[0]["id"] == repo["id"]
    assert client.get("/repositories", headers=b).json() == []
    assert client.get(f"/repositories/{repo['id']}/scans", headers=b).status_code == 404
    assert client.post(f"/repositories/{repo['id']}/scan", headers=b).status_code == 404


def test_me_returns_each_accounts_own_workspace_and_email(client):
    a = signup(client, "a@acme.com", "Alpha Labs")
    b = signup(client, "b@acme.com", "Beta Works")
    assert client.get("/auth/me", headers=a).json()["organization_name"] == "Alpha Labs"
    me_b = client.get("/auth/me", headers=b).json()
    assert me_b["organization_name"] == "Beta Works" and me_b["email"] == "b@acme.com"


def _connect(org_id):
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        db.add(models.Integration(organization_id=org_id, type="github", encrypted_credentials="x", status="active"))
        db.commit()


def test_github_status_and_disconnect_are_per_organisation_and_audited(client):
    a = signup(client, "a@acme.com", "OrgA")
    b = signup(client, "b@acme.com", "OrgB")
    org_a = client.get("/auth/me", headers=a).json()["organization_id"]
    org_b = client.get("/auth/me", headers=b).json()["organization_id"]
    assert client.get("/integrations/github/status", headers=a).json() == {"connected": False, "account": None}
    _connect(org_a)
    _connect(org_b)
    assert client.get("/integrations/github/status", headers=a).json()["connected"] is True
    assert client.delete("/integrations/github/disconnect", headers=a).json() == {"disconnected": True}
    assert client.get("/integrations/github/status", headers=a).json()["connected"] is False
    assert client.get("/integrations/github/status", headers=b).json()["connected"] is True   # untouched
    actions = [e["action"] for e in client.get("/auth/audit", headers=a).json()]
    assert "github.disconnected" in actions
    assert client.get("/integrations/github/status").status_code in (401, 403)
