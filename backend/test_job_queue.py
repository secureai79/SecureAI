import os
import sys
import textwrap
import threading
import time

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

PW = "a-very-long-passphrase-1"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("ISOLATED_SCAN_PROCESS", "false")
    monkeypatch.setenv("MAX_GLOBAL_CONCURRENT_SCANS", "1")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(textwrap.dedent('''
        import subprocess
        from openai import OpenAI
        client = OpenAI()
        def run(task):
            out = client.chat.completions.create(model="m", messages=[{"role": "user", "content": task}])
            subprocess.run(out.choices[0].message.content, shell=True)
    '''))
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/auth/signup", json={"email": "a@example.com", "password": PW, "organization_name": "O"})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        yield c, h, repo


def add_repo(c, h, repo, name="r"):
    r = c.post("/repositories", headers=h, json={"repo_url": f"file://{repo}", "repo_name": name})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def wait_for(c, h, scan_id, wanted=("completed", "failed"), timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        s = c.get(f"/scans/{scan_id}", headers=h).json()
        if s["status"] in wanted:
            return s
        time.sleep(0.1)
    pytest.fail(f"scan never reached {wanted}; last={s}")


@pytest.fixture()
def blocker(monkeypatch):
    """Make the job body block until released, so queued/full states are observable."""
    gate = threading.Event()
    started = threading.Event()
    from app import jobs
    real = jobs.run_scan_job

    def slow(scan_id):
        started.set()
        gate.wait(20)
        real(scan_id)

    monkeypatch.setattr(jobs, "run_scan_job", slow)
    yield gate, started
    gate.set()


def test_async_scan_returns_202_then_completes(env):
    c, h, repo = env
    rid = add_repo(c, h, repo)
    r = c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    assert r.status_code == 202 and r.json()["status"] == "queued"
    assert r.headers["Location"] == f"/scans/{r.json()['id']}"
    done = wait_for(c, h, r.json()["id"])
    assert done["status"] == "completed" and done["score"] is not None
    assert c.get(f"/scans/{done['id']}/findings", headers=h).status_code == 200


def test_default_is_still_synchronous_for_existing_clients(env):
    c, h, repo = env
    rid = add_repo(c, h, repo)
    r = c.post(f"/repositories/{rid}/scan", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "completed"


def test_second_scan_waits_and_org_concurrency_counts_queued(env, blocker, monkeypatch):
    c, h, repo = env
    gate, started = blocker
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "2")
    rid = add_repo(c, h, repo)
    first = c.post(f"/repositories/{rid}/scan?async=true", headers=h).json()
    assert started.wait(10)
    second = c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    assert second.status_code == 202
    assert c.get(f"/scans/{second.json()['id']}", headers=h).json()["status"] == "queued"
    third = c.post(f"/repositories/{rid}/scan?async=true", headers=h)       # 2 active already
    assert third.status_code == 429 and "Retry-After" in third.headers
    gate.set()
    assert wait_for(c, h, first["id"])["status"] == "completed"
    assert wait_for(c, h, second.json()["id"])["status"] == "completed"


def test_queue_full_returns_503_and_does_not_leave_a_queued_scan(env, blocker, monkeypatch):
    c, h, repo = env
    gate, started = blocker
    monkeypatch.setenv("MAX_QUEUED_SCANS", "1")
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "5")
    rid = add_repo(c, h, repo)
    assert c.post(f"/repositories/{rid}/scan?async=true", headers=h).status_code == 202
    assert started.wait(10)
    r = c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    assert r.status_code == 503 and r.headers["Retry-After"] == "30"
    scans = c.get(f"/repositories/{rid}/scans", headers=h).json()
    # the first (blocked) job is still queued in the DB; the rejected one must be closed, not left queued
    assert sorted(s["status"] for s in scans) == ["failed", "queued"]
    rejected = next(s for s in scans if s["status"] == "failed")
    assert "queue is full" in rejected["error"]


def test_queued_scan_can_be_cancelled_and_is_skipped(env, blocker, monkeypatch):
    c, h, repo = env
    gate, started = blocker
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "5")
    rid = add_repo(c, h, repo)
    c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    assert started.wait(10)
    queued = c.post(f"/repositories/{rid}/scan?async=true", headers=h).json()
    r = c.post(f"/scans/{queued['id']}/cancel", headers=h)
    assert r.status_code == 200 and r.json()["cancelled"] is True
    gate.set()
    time.sleep(1.5)
    final = c.get(f"/scans/{queued['id']}", headers=h).json()
    assert final["status"] == "failed" and final["error"] == "Cancelled by user."
    assert c.post(f"/scans/{queued['id']}/cancel", headers=h).status_code == 409   # no longer queued


def test_cancel_is_tenant_scoped(env):
    c, h, repo = env
    rid = add_repo(c, h, repo)
    scan = c.post(f"/repositories/{rid}/scan", headers=h).json()
    other = c.post("/auth/signup", json={"email": "b@example.com", "password": PW, "organization_name": "P"}).json()
    h2 = {"Authorization": f"Bearer {other['access_token']}"}
    assert c.post(f"/scans/{scan['id']}/cancel", headers=h2).status_code == 404
    assert c.get(f"/scans/{scan['id']}", headers=h2).status_code == 404


def test_crashing_job_marks_scan_failed_instead_of_stuck(env, monkeypatch):
    c, h, repo = env
    from app.scanner import scan_service
    monkeypatch.setattr(scan_service, "run_scan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom secret /etc/x")))
    rid = add_repo(c, h, repo)
    r = c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    done = wait_for(c, h, r.json()["id"])
    assert done["status"] == "failed"
    assert "boom" not in (done["error"] or "") and "/etc" not in (done["error"] or "")   # no internals leaked


def test_recover_orphans_closes_interrupted_scans(env):
    c, h, repo = env
    from app import jobs, models
    from app.database import SessionLocal
    rid = add_repo(c, h, repo)
    with SessionLocal() as db:
        db.add_all([models.Scan(repository_id=rid, status="queued"),
                    models.Scan(repository_id=rid, status="processing"),
                    models.Scan(repository_id=rid, status="completed")])
        db.commit()
        assert jobs.recover_orphans(db) == 2
        statuses = sorted(s.status for s in db.query(models.Scan).all())
        assert statuses == ["completed", "failed", "failed"]
        assert all("restart" in (s.error or "") for s in db.query(models.Scan).filter_by(status="failed"))


def test_stale_queued_scans_stop_blocking_the_org(env, monkeypatch):
    import datetime as dt
    from app import models
    from app.database import SessionLocal
    c, h, repo = env
    rid = add_repo(c, h, repo)
    monkeypatch.setenv("MAX_CONCURRENT_SCANS_PER_ORG", "1")
    with SessionLocal() as db:
        db.add(models.Scan(repository_id=rid, status="queued",
                           started_at=dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)))
        db.commit()
    assert c.post(f"/repositories/{rid}/scan?async=true", headers=h).status_code == 202


def test_worker_that_dies_without_result_is_reported_failed(env, monkeypatch):
    """Isolated mode: a killed/crashed worker must not leave the scan 'processing'."""
    import subprocess
    from app import models
    from app.database import SessionLocal
    from app.scanner import scan_service
    c, h, repo = env
    rid = add_repo(c, h, repo)

    class DeadProc:
        returncode = -9
        def wait(self, timeout=None): return -9
        def kill(self): pass

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: DeadProc())
    with SessionLocal() as db:
        repo_row = db.get(models.Repository, rid)
        scan = scan_service.run_scan_isolated(db, repo_row)
        assert scan.status == "failed" and "stopped unexpectedly" in scan.error