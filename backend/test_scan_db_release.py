"""A scan must not hold a database transaction open while it clones or analyses a repository.

Postgres kills sessions that sit 'idle in transaction' too long (idle_in_transaction_session_timeout), which made
scans of large repositories (e.g. microsoft/autogen) fail with
`IdleInTransactionSessionTimeout ... terminating connection`.
"""
import os
import subprocess
import sys
import textwrap

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

PW = "a-very-long-passphrase-1"
AGENT = textwrap.dedent('''
    from openai import OpenAI
    client = OpenAI()
    def run(task):
        return client.chat.completions.create(model="m", messages=[{"role": "user", "content": task}])
''')


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/auth/signup", json={"email": "a@example.com", "password": PW, "organization_name": "O"})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        rid = c.post("/repositories", headers=h,
                     json={"repo_url": "https://github.com/octocat/Hello-World", "repo_name": "r"}).json()["id"]
        yield rid


def test_no_open_transaction_during_clone_and_worker(env, monkeypatch):
    from app import models
    from app.database import SessionLocal
    from app.scanner import scan_service

    seen = {}

    def fake_clone(url, dest, token=None):
        seen["clone_in_txn"] = db.in_transaction()
        with open(os.path.join(dest, "agent.py"), "w") as fh:
            fh.write(AGENT)

    real_popen = subprocess.Popen

    def watching_popen(*a, **kw):
        if "app.scanner.sandbox_worker" in " ".join(map(str, a[0] if a else [])):
            seen["worker_in_txn"] = db.in_transaction()
        return real_popen(*a, **kw)

    monkeypatch.setattr(scan_service, "_clone_repo", fake_clone)
    monkeypatch.setattr(subprocess, "Popen", watching_popen)

    with SessionLocal() as db:
        repo = db.get(models.Repository, env)
        scan = scan_service.run_scan_isolated(db, repo)
        assert scan.status in {"completed", "complete", "done", "succeeded"} or scan.status != "failed", scan.error

    assert seen.get("clone_in_txn") is False, "a transaction was open while cloning"
    assert seen.get("worker_in_txn") is False, "a transaction was open while the sandbox worker ran"


def test_no_open_transaction_during_in_process_analysis(env, monkeypatch):
    from app import models
    from app.database import SessionLocal
    from app.scanner import scan_service

    seen = {}

    def fake_clone(url, dest, token=None):
        with open(os.path.join(dest, "agent.py"), "w") as fh:
            fh.write(AGENT)

    real_analyze = scan_service.analyze_directory

    def watching_analyze(root, *a, **kw):
        seen["analyze_in_txn"] = db.in_transaction()
        return real_analyze(root, *a, **kw)

    monkeypatch.setattr(scan_service, "_clone_repo", fake_clone)
    monkeypatch.setattr(scan_service, "analyze_directory", watching_analyze)

    with SessionLocal() as db:
        repo = db.get(models.Repository, env)
        scan_service.run_scan(db, repo)

    assert seen.get("analyze_in_txn") is False, "a transaction was open during in-process analysis"
