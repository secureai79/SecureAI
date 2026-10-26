import http.server
import os
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from app.scanner import scan_service


def test_classify_clone_error_is_safe_and_specific():
    c = scan_service.classify_clone_error
    assert "not found" in c("remote: Repository not found.\nfatal: repository 'x' not found")
    assert "rejected the credentials" in c("fatal: Authentication failed for 'https://github.com/o/r.git/'")
    assert "could not reach GitHub" in c("fatal: unable to access: Could not resolve host: github.com")
    assert "timed out" in c(None, timed_out=True)
    assert "file permission" in c("error: cannot exec 'x': Permission denied")
    assert c("something odd with ghs_SECRETTOKEN123") == "git clone failed"   # raw stderr is never echoed


def test_token_is_sent_as_scoped_header_not_via_askpass_or_argv(monkeypatch, tmp_path):
    version = scan_service._git_version()
    if not version or version < scan_service.MIN_GIT:
        pytest.skip(f"git >= 2.31 required, found {version or 'none'}")

    # Simulate an IDE/terminal that exports its own credential helper (VS Code does).
    monkeypatch.setenv("GIT_ASKPASS", "/some/ide/askpass.sh")
    monkeypatch.setenv("SSH_ASKPASS", "/some/ide/askpass.sh")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "9")
    seen = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization")
            self.send_response(404); self.end_headers()
        def log_message(self, *a): pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    captured = {}
    result = {}
    real_run = subprocess.run

    def spy(args, **kw):
        if "env" not in kw:                      # e.g. the cached `git --version` probe
            return real_run(args, **kw)
        captured["args"] = args
        captured["env"] = dict(kw.get("env", {}))
        env = dict(kw["env"])
        # Make the observation hermetic: ignore the developer's proxies and personal/system git config.
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(var, None)
        env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["HOME"] = env["USERPROFILE"] = str(tmp_path)
        # point the header scope at our local server so we can observe it
        for k, v in list(env.items()):
            if k.startswith("GIT_CONFIG_KEY_") and "extraheader" in v:
                env[k] = f"http.http://127.0.0.1:{port}/.extraheader"
        kw["env"] = env
        kw["capture_output"] = True
        kw["text"] = True
        kw.pop("stdout", None); kw.pop("stderr", None)
        args = [a.replace("https://github.com/o/r.git", f"http://127.0.0.1:{port}/o/r.git") for a in args]
        try:
            return real_run(args, **kw)
        except subprocess.CalledProcessError as exc:
            result["stderr"] = exc.stderr
            raise

    monkeypatch.setattr(scan_service.subprocess, "run", spy)
    try:
        scan_service._clone_repo("https://github.com/o/r.git", str(tmp_path / "dest"), token="ghs_TESTTOKEN")
    except subprocess.CalledProcessError:
        pass
    srv.shutdown()

    import base64
    assert "auth" in seen, (
        "git never reached the local test server - this is an environment problem, not a token problem. "
        f"git {'.'.join(map(str, version))}; git said: {result.get('stderr')!r}"
    )
    assert seen["auth"] == "basic " + base64.b64encode(b"x-access-token:ghs_TESTTOKEN").decode()
    assert "ghs_TESTTOKEN" not in " ".join(captured["args"])           # not in argv
    assert "GIT_ASKPASS" not in captured["env"]                        # inherited helper stripped
    assert "SSH_ASKPASS" not in captured["env"]
    assert captured["env"]["GIT_CONFIG_COUNT"] == "2"                  # ours, not the inherited 9


def test_no_credentials_attached_to_non_github_hosts(monkeypatch):
    captured = {}
    def spy(args, **kw):
        captured["env"] = kw["env"]
        raise subprocess.CalledProcessError(1, args, stderr="x")
    monkeypatch.setattr(scan_service.subprocess, "run", spy)
    try:
        scan_service._clone_repo("https://evil.example/o/r.git", "/tmp/never", token="ghs_TESTTOKEN")
    except subprocess.CalledProcessError:
        pass
    assert not any("ghs_TESTTOKEN" in v or "Authorization" in v for v in captured["env"].values())