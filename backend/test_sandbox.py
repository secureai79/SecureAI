import glob
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time

sys.path.insert(0, os.path.dirname(__file__))

import pytest
from fastapi.testclient import TestClient

PW = "a-very-long-passphrase-1"
AGENT = textwrap.dedent('''
    import subprocess
    from openai import OpenAI
    client = OpenAI()
    def run(task):
        out = client.chat.completions.create(model="m", messages=[{"role": "user", "content": task}])
        subprocess.run(out.choices[0].message.content, shell=True)
''')
SECRETS = {
    "DATABASE_URL": "postgresql://u:SUPERSECRET@db/x", "JWT_SECRET": "j" * 40,
    "GITHUB_TOKEN_ENCRYPTION_KEY": "k" * 44, "SOURCE_EVIDENCE_ENCRYPTION_KEY": "s" * 44,
    "GITHUB_APP_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----", "ANTHROPIC_API_KEY": "sk-ant-secret",
    "GITHUB_CLIENT_SECRET": "ghsecret", "GITHUB_INSTALLATION_TOKEN": "ghs_secret",
}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 't.db'}")
    monkeypatch.setenv("ALLOW_LOCAL_REPOS", "true")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    for mod in list(sys.modules):
        if mod.startswith("app"):
            del sys.modules[mod]
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text(AGENT)
    from app.main import app
    with TestClient(app) as c:
        r = c.post("/auth/signup", json={"email": "a@example.com", "password": PW, "organization_name": "O"})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        rid = c.post("/repositories", headers=h, json={"repo_url": f"file://{repo}", "repo_name": "r"}).json()["id"]
        yield c, h, rid, repo


def session():
    from app.database import SessionLocal
    return SessionLocal()


def run_isolated(rid):
    from app import models
    from app.scanner import scan_service
    with session() as db:
        repo = db.get(models.Repository, rid)
        scan = scan_service.run_scan_isolated(db, repo)
        db.refresh(scan)
        return scan.status, scan.error, scan.score, scan.id


# ------------------------------------------------------------ what the worker can see
def test_worker_modules_import_no_database_or_secret_handling_code():
    code = ("import sys; import app.scanner.sandbox_worker, app.scanner.pipeline; "
            "bad=[m for m in sys.modules if m in ('app.database','app.models','app.config','app.privacy',"
            "'app.source_crypto','app.keyring','app.auth','app.jobs','app.main','app.security',"
            "'sqlalchemy','cryptography','asyncio','fastapi','httpx') "
            "or m.startswith('app.routers')]; print(bad)")
    out = subprocess.run([sys.executable, "-c", code], cwd=os.path.dirname(__file__),
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": ""})
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]", f"worker pulls in forbidden modules: {out.stdout}"


def test_sandbox_environment_is_an_allow_list_with_no_secrets(monkeypatch, tmp_path):
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("MAX_SCAN_FILES", "123")
    from app.scanner import scan_service
    sandbox_env = scan_service._sandbox_env(str(tmp_path))
    assert not (set(SECRETS) & set(sandbox_env))
    assert "SUPERSECRET" not in json.dumps(sandbox_env)
    assert sandbox_env["MAX_SCAN_FILES"] == "123" and sandbox_env["HOME"] == str(tmp_path)
    allowed = {"PATH", "PYTHONPATH", "HOME", "TMPDIR", "LANG", "PYTHONDONTWRITEBYTECODE", "MAX_SCAN_FILES",
               "MAX_SCAN_BYTES", "SCAN_WORKER_CPU_SECONDS", "SCAN_WORKER_MEMORY_MB", "SCAN_WORKER_FILE_MB",
               "SANDBOX_NO_NETWORK",
               # Windows-only system variables (not secrets); absent on Linux
               "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "USERPROFILE"}
    assert set(sandbox_env) <= allowed


def test_real_worker_process_runs_with_secret_free_env_and_scan_matches_in_process(env, monkeypatch):
    c, h, rid, repo = env
    for k, v in SECRETS.items():
        monkeypatch.setenv(k, v)
    seen = {}
    real_popen = subprocess.Popen

    def spy(args, **kw):
        if "app.scanner.sandbox_worker" in " ".join(map(str, args)):
            seen["env"] = dict(kw["env"])
            seen["args"] = list(args)
        return real_popen(args, **kw)

    monkeypatch.setattr(subprocess, "Popen", spy)
    status, error, score, scan_id = run_isolated(rid)
    assert status == "completed", error
    assert not (set(SECRETS) & set(seen["env"])), "secret leaked into the sandbox environment"
    assert all("SUPERSECRET" not in str(v) for v in seen["env"].values())
    assert not any("SUPERSECRET" in a for a in seen["args"])

    # parity with the in-process pipeline on the same repository
    from app import models
    from app.scanner import scan_service
    with session() as db:
        repo_row = db.get(models.Repository, rid)
        inproc = scan_service.run_scan(db, repo_row)
        db.refresh(inproc)

        def shape(sid):
            rows = db.query(models.Finding).filter_by(scan_id=sid).all()
            return sorted((f.category, f.capability, f.file_path, f.line_number, f.severity, f.scored) for f in rows)

        assert inproc.status == "completed"
        assert shape(scan_id) == shape(inproc.id) and shape(scan_id)
        assert score == inproc.score
        agents = lambda sid: sorted((a.file_path, a.framework, a.model_provider)
                                    for a in db.query(models.Agent).filter_by(scan_id=sid))
        assert agents(scan_id) == agents(inproc.id) and agents(scan_id)


def test_worker_runs_even_when_network_isolation_is_requested(env, monkeypatch, tmp_path):
    c, h, rid, repo = env
    monkeypatch.setenv("SANDBOX_NO_NETWORK", "true")      # best effort: must never break the scan
    out = tmp_path / "out.json"
    proc = subprocess.run(
        [sys.executable, "-m", "app.scanner.sandbox_worker", str(repo), str(out)],
        cwd=os.path.dirname(__file__),
        env={**__import__("app.scanner.scan_service", fromlist=["x"])._sandbox_env(str(tmp_path)),
             "SANDBOX_NO_NETWORK": "true"},
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["version"] == 1 and isinstance(data["sandbox"]["network_isolated"], bool)
    assert data["ai_findings"]


def test_limit_violations_reported_by_the_worker_become_clear_failures(env, monkeypatch):
    c, h, rid, repo = env
    monkeypatch.setenv("MAX_SCAN_FILES", "0")
    status, error, _, _ = run_isolated(rid)
    assert status == "failed" and "too many scannable files" in error


# ------------------------------------------------------ hostile worker output is rejected
class FakeProc:
    returncode = 0
    def wait(self, timeout=None): return 0
    def kill(self): pass


def fake_worker(monkeypatch, payload, exit_code=0, as_bytes=False):
    def popen(args, **kw):
        out = args[-1]
        mode = "wb" if as_bytes else "w"
        with open(out, mode) as fh:
            fh.write(payload if as_bytes else (payload if isinstance(payload, str) else json.dumps(payload)))
        p = FakeProc(); p.returncode = exit_code
        return p
    monkeypatch.setattr(subprocess, "Popen", popen)


GOOD_FINDING = {"title": "t", "severity": "HIGH", "category": "DATA", "file_path": "a.py", "line": 3,
                "capability": "delete", "confidence": 0.9, "evidence": ["e"]}


def good_result(**over):
    base = {"version": 1, "agents": [], "ai_findings": [GOOD_FINDING], "injection_findings": [],
            "security_findings": [], "stats": {"files": 1, "bytes": 1, "repo_has_ai": True}}
    base.update(over)
    return base


def assert_rejected(rid, expect="invalid result"):
    from app import models
    status, error, score, scan_id = run_isolated(rid)
    assert status == "failed" and expect in error, (status, error)
    with session() as db:
        assert db.query(models.Finding).filter_by(scan_id=scan_id).count() == 0
        assert db.query(models.Agent).filter_by(scan_id=scan_id).count() == 0


@pytest.mark.parametrize("bad", [
    {**GOOD_FINDING, "file_path": "../../etc/passwd"},
    {**GOOD_FINDING, "file_path": "/etc/passwd"},
    {**GOOD_FINDING, "file_path": "C:\\\\Windows\\\\x"},
    {**GOOD_FINDING, "severity": "APOCALYPTIC"},
    {**GOOD_FINDING, "line": "3; DROP TABLE findings"},
    {**GOOD_FINDING, "confidence": 7},
    {**GOOD_FINDING, "title": "x" * 600},
    {**GOOD_FINDING, "evidence": [{"nested": "object"}]},
    {**GOOD_FINDING, "potential_points": 1_000_000},
    {**GOOD_FINDING, "extra": {"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}}},
    "not-an-object",
])
def test_invalid_findings_are_rejected_and_nothing_is_stored(env, monkeypatch, bad):
    c, h, rid, repo = env
    fake_worker(monkeypatch, good_result(ai_findings=[bad]))
    assert_rejected(rid)


@pytest.mark.parametrize("payload", [
    "this is not json",
    '{"version": 2}',
    '[1, 2, 3]',
    '{"version": 1, "agents": "nope", "ai_findings": [], "injection_findings": [], "security_findings": []}',
])
def test_malformed_output_is_rejected(env, monkeypatch, payload):
    c, h, rid, repo = env
    fake_worker(monkeypatch, payload)
    assert_rejected(rid)


def test_pickle_bytes_are_never_deserialised(env, monkeypatch):
    import pickle
    c, h, rid, repo = env
    class Evil:
        def __reduce__(self):
            return (os.system, ("touch /tmp/PWNED_BY_WORKER",))
    fake_worker(monkeypatch, pickle.dumps(Evil()), as_bytes=True)
    assert_rejected(rid)
    assert not os.path.exists("/tmp/PWNED_BY_WORKER")


def test_oversized_output_is_rejected_before_parsing(env, monkeypatch):
    c, h, rid, repo = env
    monkeypatch.setenv("MAX_WORKER_OUTPUT_BYTES", "200")
    fake_worker(monkeypatch, good_result())
    assert_rejected(rid, "more output than allowed")


def test_too_many_findings_rejected(env, monkeypatch):
    c, h, rid, repo = env
    fake_worker(monkeypatch, good_result(ai_findings=[GOOD_FINDING] * 5001))
    assert_rejected(rid)


def test_valid_hand_built_result_is_persisted(env, monkeypatch):
    from app import models
    c, h, rid, repo = env
    fake_worker(monkeypatch, good_result(agents=[{"file_path": "a.py", "framework": None, "model_provider": "OpenAI"}]))
    status, error, score, scan_id = run_isolated(rid)
    assert status == "completed", error
    with session() as db:
        f = db.query(models.Finding).filter_by(scan_id=scan_id).one()
        assert f.severity == "HIGH" and f.finding_domain == "AI_SAFETY"
        assert db.query(models.Agent).filter_by(scan_id=scan_id).count() == 1


def test_worker_exit_nonzero_or_missing_output_fails_cleanly(env, monkeypatch):
    c, h, rid, repo = env
    fake_worker(monkeypatch, good_result(), exit_code=-9)
    status, error, _, _ = run_isolated(rid)
    assert status == "failed" and "stopped unexpectedly" in error


def test_timeout_kills_worker_and_fails(env, monkeypatch):
    c, h, rid, repo = env
    killed = {}

    class Slow:
        returncode = None
        def wait(self, timeout=None):
            if not killed:
                raise subprocess.TimeoutExpired("w", timeout)
            return -9
        def kill(self): killed["yes"] = True

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: Slow())
    status, error, _, _ = run_isolated(rid)
    assert killed and status == "failed" and "timed out" in error


def test_temp_directories_are_always_cleaned_up(env, monkeypatch):
    c, h, rid, repo = env
    pattern = os.path.join(tempfile.gettempdir(), "ai_safety_out_*")
    before = set(glob.glob(pattern))
    fake_worker(monkeypatch, "garbage")
    run_isolated(rid)
    run_isolated.__wrapped__ if False else None
    assert set(glob.glob(pattern)) == before


def test_async_queue_uses_the_sandbox_in_isolated_mode(env, monkeypatch):
    c, h, rid, repo = env
    monkeypatch.setenv("ISOLATED_SCAN_PROCESS", "true")
    calls = {"n": 0}
    real_popen = subprocess.Popen

    def spy(args, **kw):
        if "app.scanner.sandbox_worker" in " ".join(map(str, args)):
            calls["n"] += 1
        return real_popen(args, **kw)

    monkeypatch.setattr(subprocess, "Popen", spy)
    r = c.post(f"/repositories/{rid}/scan?async=true", headers=h)
    assert r.status_code == 202
    end = time.time() + 60
    while time.time() < end:
        s = c.get(f"/scans/{r.json()['id']}", headers=h).json()
        if s["status"] in ("completed", "failed"):
            break
        time.sleep(0.2)
    assert s["status"] == "completed" and calls["n"] == 1
    assert c.get(f"/scans/{s['id']}/findings", headers=h).json()