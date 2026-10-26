"""Team & Access: invitations, roles, removal, permissions and tenant isolation."""
import datetime as dt
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))
PW = "correct-horse-battery-1"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("EMAIL_BACKEND", "memory")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("PREVENT_ACCOUNT_ENUMERATION", "false")
    monkeypatch.setenv("FRONTEND_URL", "http://127.0.0.1:5500")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app import email_service
    email_service.OUTBOX.clear()
    from app.main import app
    with TestClient(app) as c:
        c.outbox = email_service.OUTBOX
        yield c


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def owner(client, email="owner@acme.com", org="Acme"):
    r = client.post("/auth/signup", json={"email": email, "password": PW, "organization_name": org})
    client.outbox.clear()
    return r.json()["access_token"]


def token_from(msg):
    return re.search(r"/accept-invite\.html#token=([A-Za-z0-9_-]+)", msg["text"]).group(1)


def join(client, tok, email, role="member", password=PW):
    r = client.post("/team/invitations", json={"email": email, "role": role}, headers=H(tok))
    assert r.status_code == 200, r.text
    raw = token_from(client.outbox[-1])
    acc = client.post("/team/invitations/accept", json={"token": raw, "password": password})
    assert acc.status_code == 200, acc.text
    return acc.json()["access_token"], r.json()


def test_owner_invites_a_member_who_joins_verified_in_the_same_workspace(client):
    o = owner(client)
    r = client.post("/team/invitations", json={"email": "Bob@Acme.com", "role": "member"}, headers=H(o))
    assert r.status_code == 200 and r.json()["email"] == "bob@acme.com"
    m = client.outbox[-1]
    assert m["to"] == "bob@acme.com" and "owner@acme.com" in m["text"] and "#token=" in m["text"]
    raw = token_from(m)
    pv = client.post("/team/invitations/preview", json={"token": raw}).json()
    assert pv == {"organization_name": "Acme", "email": "bob@acme.com", "role": "member", "account_exists": False}
    acc = client.post("/team/invitations/accept", json={"token": raw, "password": PW})
    b = H(acc.json()["access_token"])
    me = client.get("/auth/me", headers=b).json()
    assert me["role"] == "member" and me["organization_name"] == "Acme" and me["email_verified"] is True
    team = client.get("/team", headers=H(o)).json()
    assert [m_["email"] for m_ in team["members"]] == ["owner@acme.com", "bob@acme.com"]
    assert team["invitations"] == [] and team["seats"] == {"used": 2, "limit": 10}


def test_invitation_links_are_single_use_expire_and_can_be_revoked(client):
    o = owner(client)
    _, inv = join(client, o, "a@acme.com")
    raw_used = token_from(client.outbox[-1])
    assert client.post("/team/invitations/accept", json={"token": raw_used, "password": PW}).status_code == 400   # used
    client.post("/team/invitations", json={"email": "b@acme.com"}, headers=H(o))
    raw = token_from(client.outbox[-1])
    inv_id = client.get("/team", headers=H(o)).json()["invitations"][0]["id"]
    assert client.delete(f"/team/invitations/{inv_id}", headers=H(o)).status_code == 200
    assert client.post("/team/invitations/preview", json={"token": raw}).status_code == 400                       # revoked
    client.post("/team/invitations", json={"email": "c@acme.com"}, headers=H(o))
    raw2 = token_from(client.outbox[-1])
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        row = db.query(models.Invitation).filter(models.Invitation.email == "c@acme.com").first()
        row.expires_at = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1)
        db.commit()
    assert client.post("/team/invitations/accept", json={"token": raw2, "password": PW}).status_code == 400       # expired
    assert client.post("/team/invitations/preview", json={"token": "x" * 43}).status_code == 400


def test_only_a_hash_of_the_invitation_token_is_stored(client):
    o = owner(client)
    client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o))
    raw = token_from(client.outbox[-1])
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        assert raw not in db.query(models.Invitation).first().token_hash


def test_inviting_again_replaces_the_old_link(client):
    o = owner(client)
    client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o))
    first = token_from(client.outbox[-1])
    client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o))
    assert client.post("/team/invitations/preview", json={"token": first}).status_code == 400
    assert len(client.get("/team", headers=H(o)).json()["invitations"]) == 1


def test_weak_password_does_not_burn_the_invitation(client):
    o = owner(client)
    client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o))
    raw = token_from(client.outbox[-1])
    assert client.post("/team/invitations/accept", json={"token": raw, "password": "short"}).status_code == 400
    assert client.post("/team/invitations/accept", json={"token": raw, "password": PW}).status_code == 200


def test_roles_limit_what_each_person_can_do(client):
    o = owner(client)
    m_tok, _ = join(client, o, "member@acme.com", "member")
    a_tok, _ = join(client, o, "admin@acme.com", "admin")
    # members cannot manage the team
    assert client.post("/team/invitations", json={"email": "x@acme.com"}, headers=H(m_tok)).status_code == 403
    assert client.get("/team", headers=H(m_tok)).json()["invitations"] == []
    assert client.get("/team", headers=H(m_tok)).json()["can_manage"] is False
    # admins can invite members but not admins, and cannot change roles
    assert client.post("/team/invitations", json={"email": "x@acme.com"}, headers=H(a_tok)).status_code == 200
    assert client.post("/team/invitations", json={"email": "y@acme.com", "role": "admin"}, headers=H(a_tok)).status_code == 403
    members = {m["email"]: m["id"] for m in client.get("/team", headers=H(o)).json()["members"]}
    assert client.patch(f"/team/members/{members['member@acme.com']}", json={"role": "admin"}, headers=H(a_tok)).status_code == 403
    # members cannot touch org-wide settings, admins and owners can
    assert client.delete("/integrations/github/disconnect", headers=H(m_tok)).status_code == 403
    assert client.delete("/integrations/github/disconnect", headers=H(a_tok)).status_code == 200
    # but members do the normal work
    assert client.post("/repositories", json={"repo_url": "https://github.com/octo/demo"}, headers=H(m_tok)).status_code == 200


def test_owner_can_change_roles_and_the_new_role_applies_immediately(client):
    o = owner(client)
    m_tok, _ = join(client, o, "m@acme.com")
    mid = [m for m in client.get("/team", headers=H(o)).json()["members"] if m["email"] == "m@acme.com"][0]["id"]
    assert client.patch(f"/team/members/{mid}", json={"role": "admin"}, headers=H(o)).json()["role"] == "admin"
    assert client.get("/team", headers=H(m_tok)).json()["can_manage"] is True
    owner_id = [m for m in client.get("/team", headers=H(o)).json()["members"] if m["is_you"]][0]["id"]
    assert client.patch(f"/team/members/{owner_id}", json={"role": "member"}, headers=H(o)).status_code == 400
    assert client.patch(f"/team/members/{mid}", json={"role": "owner"}, headers=H(o)).status_code == 422


def test_removing_a_member_cuts_their_access_at_once_and_frees_the_address(client):
    o = owner(client)
    m_tok, _ = join(client, o, "m@acme.com")
    mid = [m for m in client.get("/team", headers=H(o)).json()["members"] if m["email"] == "m@acme.com"][0]["id"]
    client.outbox.clear()
    assert client.delete(f"/team/members/{mid}", headers=H(o)).status_code == 200
    assert client.get("/auth/me", headers=H(m_tok)).status_code == 401
    assert client.post("/auth/login", json={"email": "m@acme.com", "password": PW}).status_code == 401
    assert any("removed" in m["subject"] for m in client.outbox)
    join(client, o, "m@acme.com")                       # can be invited again


def test_removal_rules(client):
    o = owner(client)
    a_tok, _ = join(client, o, "admin@acme.com", "admin")
    join(client, o, "member@acme.com")
    ids = {m["email"]: m["id"] for m in client.get("/team", headers=H(o)).json()["members"]}
    assert client.delete(f"/team/members/{ids['owner@acme.com']}", headers=H(a_tok)).status_code == 403   # nobody removes the owner
    assert client.delete(f"/team/members/{ids['owner@acme.com']}", headers=H(o)).status_code == 400       # not even themselves
    assert client.delete(f"/team/members/{ids['admin@acme.com']}", headers=H(a_tok)).status_code == 400   # self
    assert client.delete(f"/team/members/{ids['member@acme.com']}", headers=H(a_tok)).status_code == 200  # admin removes member


def test_workspaces_are_isolated_from_each_other(client):
    o1 = owner(client, "o1@one.com", "One")
    o2 = owner(client, "o2@two.com", "Two")
    join(client, o1, "m@one.com")
    t2 = client.get("/team", headers=H(o2)).json()
    assert [m["email"] for m in t2["members"]] == ["o2@two.com"]
    one_member = [m for m in client.get("/team", headers=H(o1)).json()["members"] if m["email"] == "m@one.com"][0]["id"]
    assert client.delete(f"/team/members/{one_member}", headers=H(o2)).status_code == 404
    assert client.patch(f"/team/members/{one_member}", json={"role": "admin"}, headers=H(o2)).status_code == 404
    inv = client.post("/team/invitations", json={"email": "z@one.com"}, headers=H(o1)).json()["id"]
    assert client.delete(f"/team/invitations/{inv}", headers=H(o2)).status_code == 404


def test_address_with_an_account_cannot_create_a_second_account_from_the_link(client):
    o1 = owner(client, "o1@one.com", "One")
    owner(client, "taken@two.com", "Two")
    client.post("/team/invitations", json={"email": "taken@two.com"}, headers=H(o1))
    raw = token_from(client.outbox[-1])
    r = client.post("/team/invitations/accept", json={"token": raw, "password": PW})
    assert r.status_code == 409


def test_cannot_invite_an_existing_member_and_seats_are_capped(client, monkeypatch):
    monkeypatch.setenv("MAX_MEMBERS_PER_ORG", "3")
    o = owner(client)
    assert client.post("/team/invitations", json={"email": "owner@acme.com"}, headers=H(o)).status_code == 400
    assert client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o)).status_code == 200
    assert client.post("/team/invitations", json={"email": "b@acme.com"}, headers=H(o)).status_code == 200
    r = client.post("/team/invitations", json={"email": "c@acme.com"}, headers=H(o))
    assert r.status_code == 403 and "limit of 3" in r.json()["detail"]
    assert client.get("/team", headers=H(o)).json()["seats"] == {"used": 3, "limit": 3}


def test_unverified_owners_cannot_invite_when_verification_is_required(client, monkeypatch):
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "true")
    o = owner(client)
    r = client.post("/team/invitations", json={"email": "a@acme.com"}, headers=H(o))
    assert r.status_code == 403 and "verify your email" in r.json()["detail"].lower()


def test_team_endpoints_require_authentication(client):
    assert client.get("/team").status_code in (401, 403)
    assert client.post("/team/invitations", json={"email": "a@b.com"}).status_code in (401, 403)
    assert client.delete("/team/members/x").status_code in (401, 403)


def test_plan_scales_the_seat_limit(client):
    o = owner(client)
    from app import models
    from app.database import SessionLocal
    with SessionLocal() as db:
        db.query(models.Organization).first().plan = "team"
        db.commit()
    assert client.get("/team", headers=H(o)).json()["seats"]["limit"] == 20
