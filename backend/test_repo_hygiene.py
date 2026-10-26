"""scripts/check_repo_clean.py catches what must never be pushed, and passes a clean tree."""
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run(tree, *extra):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "check_repo_clean.py"), "--all", "--root", str(tree), *extra],
                       capture_output=True, text=True)
    return r.returncode, r.stdout


def make(tree, files):
    for name, content in files.items():
        p = tree / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())


def test_a_clean_tree_passes(tmp_path):
    make(tmp_path, {"README.md": "# hi", ".env.example": "JWT_SECRET=\nSMTP_PASSWORD=\nDATABASE_URL=postgresql://user:password@db:5432/x\n",
                    ".env.production.example": "DATABASE_URL=\nPOSTGRES_PASSWORD=changeme\n", "secrets/README.txt": "put keys here",
                    "backend/app.py": "print('ok')"})
    code, out = run(tmp_path)
    assert code == 0 and "Clean" in out


def test_files_that_must_not_be_pushed_are_caught(tmp_path):
    make(tmp_path, {".env": "A=1", "secrets/github.pem": "x", "ai_safety_backup_20261005.sql": "dump", "backups/x.txt": "y",
                    "app.py.bak": "z", "models.backup-before-fix.py": "z", "release.zip": b"PK", ".venv/lib/x.py": "x"})
    code, out = run(tmp_path)
    assert code == 1
    for needle in (".env", "github.pem", "ai_safety_backup_20261005.sql", "backups/x.txt", "app.py.bak", "models.backup-before-fix.py", "release.zip"):
        assert needle in out, needle


def test_secrets_inside_files_are_caught_without_being_printed(tmp_path):
    secret = ("Zk9x" * 11)[:43] + "="  # the shape of a Fernet key
    make(tmp_path, {
        "config/a.txt": "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "config/b.py": "TOKEN = 'ghp_" + "A1b2C3d4" * 5 + "'",
        "config/c.env.example": "JWT_SECRET=superlongrealsecretvalue1234567890",
        "config/d.yml": "DATABASE_URL: postgresql://neonuser:Sup3rS3cretPw@ep-cool-1.eu-central-1.aws.neon.tech/db",
        "config/e.txt": "GITHUB_TOKEN_ENCRYPTION_KEY=" + secret,
        "config/f.txt": "key = xkeysib-" + "a" * 40,
    })
    code, out = run(tmp_path)
    assert code == 1
    for kind in ("private key", "GitHub token", "secret assigned in a file", "database URL with a password", "encryption key", "Brevo API key"):
        assert kind in out, kind
    assert "Sup3rS3cretPw" not in out and secret not in out and "ghp_" not in out        # findings never echo the secret


def test_placeholders_and_local_urls_are_fine(tmp_path):
    make(tmp_path, {"docker.md": "DATABASE_URL=postgresql://user:password@db:5432/app\nDATABASE_URL=postgresql://u:p@localhost/x\n"
                                  "JWT_SECRET=replace-with-a-long-random-secret\nSMTP_PASSWORD=\n"})
    assert run(tmp_path)[0] == 0


def test_demo_and_test_fixtures_may_contain_fake_keys(tmp_path):
    make(tmp_path, {"demo_repo/agents/bad.py": "API_KEY = 'sk-" + "a" * 40 + "'", "backend/test_x.py": "k='ghp_" + "B" * 36 + "'"})
    assert run(tmp_path)[0] == 0


def test_oversized_files_are_flagged(tmp_path):
    make(tmp_path, {"data/big.json": b"0" * (5 * 1024 * 1024 + 10)})
    code, out = run(tmp_path)
    assert code == 1 and "larger than" in out
