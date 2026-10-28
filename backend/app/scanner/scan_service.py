import datetime as dt
import functools
import os
import re
import shutil
import subprocess
import tempfile
import stat
import time

from sqlalchemy.orm import Session

from .. import models
from ..security import allow_local_repos, validate_repository_url
from ..privacy import prepare_finding_for_storage, sanitize_error, redact_json
from . import risk_engine, llm_analyzer
from .pipeline import analyze_directory, _safe_file_path, _scan_debug
from .worker_protocol import WorkerOutputError, max_output_bytes, validate_result

MIN_GIT = (2, 31)   # GIT_CONFIG_COUNT/KEY/VALUE (used to pass credentials without argv/files)


@functools.lru_cache(maxsize=1)
def _git_version() -> tuple[int, ...]:
    """Installed git version, probed once per process (empty tuple if git is unavailable)."""
    try:
        out = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", out)
    return tuple(int(x) for x in m.groups() if x is not None) if m else ()


def _auth_scope(repo_url: str) -> str | None:
    """Return 'https://github.com/' when credentials may be attached, else None."""
    return "https://github.com/" if repo_url.lower().startswith("https://github.com/") else None


def classify_clone_error(stderr: str | None, timed_out: bool = False) -> str:
    """Map git's stderr to a fixed, customer-safe explanation (never echo raw stderr)."""
    if timed_out:
        return "git clone failed: the clone timed out (repository too large or GitHub too slow)."
    e = (stderr or "").lower()
    if "repository not found" in e or "not found" in e or "error: 404" in e:
        return "git clone failed: repository not found, or the GitHub App is not installed on it."
    if any(k in e for k in ("authentication failed", "could not read username", "invalid username or password", "error: 403", "permission to", "access denied")):
        return "git clone failed: GitHub rejected the credentials. Reconnect GitHub and grant access to this repository."
    if any(k in e for k in ("could not resolve host", "failed to connect", "connection timed out", "connection reset", "network is unreachable", "ssl")):
        return "git clone failed: the server could not reach GitHub."
    if "git too old" in e:
        return "git clone failed: the server's git is older than 2.31 and cannot send credentials safely."
    if "cannot exec" in e or "permission denied" in e or "read-only file system" in e:
        return "git clone failed: the server could not run git (file permission problem)."
    if "sparse" in e:
        return "git clone failed: could not prepare the repository checkout."
    return "git clone failed"


def _sparse_patterns() -> list[str]:
    """Allow-list for the checkout: only the file types the analyzers read.

    Everything else (images, videos, datasets, model weights, archives...) is never downloaded, which
    is what makes very large repositories cheap to clone. Later patterns win, so exclusions come last.
    """
    from . import file_selector
    include = [f"*{ext}" for ext in sorted(file_selector.INCLUDE_EXTENSIONS)]
    include += sorted(file_selector.INCLUDE_NAMES)
    # "!**/dir/**" is the form git honours for a directory at any depth ("!dir/" does not cover its contents).
    exclude = [f"!**/{d}/**" for d in sorted(file_selector.IGNORE_DIRS) if d != ".git"]
    exclude += ["!/checkpoints/**", "!/outputs/**"]
    exclude += [f"!{n}" for n in sorted(file_selector.SKIP_NAMES)] + [f"!*{x}" for x in file_selector.SKIP_SUFFIXES]
    return include + exclude


def _dir_megabytes(path: str) -> float:
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        if os.path.basename(dirpath) == ".git":
            dirnames[:] = []
            continue
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total / (1024 * 1024)


def _clone_repo(repo_url: str, dest: str, token: str | None = None) -> None:
    timeout = int(os.environ.get("GIT_CLONE_TIMEOUT_SECONDS", "600"))
    env = os.environ.copy()
    # Never inherit an interactive credential helper from the host/IDE (VS Code, Git
    # Credential Manager, ssh-agent wrappers): clones must be fully non-interactive and
    # use only the explicit header below.
    for inherited in ("GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXEC_PATH"):
        env.pop(inherited, None)
    for key in [k for k in env if k.startswith("GIT_CONFIG_")]:
        env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env.setdefault("HOME", "/tmp")
    config = [("core.hooksPath", os.devnull)]
    scope = _auth_scope(repo_url)
    if token and scope:
        version = _git_version()
        if version and version < MIN_GIT:
            # Older git silently ignores GIT_CONFIG_COUNT, so the clone would fail with a
            # confusing "authentication failed". Fail early with a precise reason instead.
            raise subprocess.CalledProcessError(1, "git", stderr="git too old")
        # Credentials travel as an HTTP header scoped to github.com. Unlike a
        # GIT_ASKPASS helper this needs no executable file (a noexec /tmp
        # breaks helpers) and nothing is written to disk or argv.
        import base64
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        config.append((f"http.{scope}.extraheader", f"AUTHORIZATION: basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(config))
    for i, (k, v) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    try:
        result = subprocess.run(
            [
                "git", "-c", "protocol.version=2",
                "clone",
                "--depth", "1",
                "--no-tags",
                "--no-recurse-submodules",
                "--filter=blob:none",
                "--sparse",
                repo_url,
                dest,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

        if result.returncode != 0:
            _scan_debug(
                f"GIT_CLONE_FAILED returncode={result.returncode} "
                f"stderr={result.stderr[:1000]}"
            )
            raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )

        # Materialize source/configuration while excluding large ML artifacts.
        subprocess.run(
            ["git", "-C", dest, "sparse-checkout", "set", "--no-cone", *_sparse_patterns()],
            check=True, capture_output=True, text=True, timeout=timeout, env=env,
        )
        limit_mb = int(os.environ.get("MAX_CLONE_MB", "1024"))
        if _dir_megabytes(dest) > limit_mb:
            raise ValueError(f"The repository's source files are larger than {limit_mb} MB, which is more than this workspace can scan.")
    finally:
        # Drop the credential from this process's copy of the environment.
        for key in list(env):
            if key.startswith("GIT_CONFIG_VALUE_"):
                env[key] = ""

def _work_root() -> str | None:
    """Directory for clones and worker output. In Docker this is a disk volume, not RAM-backed /tmp."""
    path = os.environ.get("SCAN_WORKDIR", "").strip()
    if path:
        os.makedirs(path, exist_ok=True)
        return path
    return None


def _release_db(db) -> None:
    """End the open database transaction before a long, database-free phase (clone, sandboxed analysis).

    A session that sits "idle in transaction" for minutes is killed by Postgres
    (idle_in_transaction_session_timeout), and the scan then fails on its next query. Large repositories
    (e.g. microsoft/autogen) take long enough to hit that. After commit, ORM attributes are expired and the
    next attribute access opens a NEW transaction, so callers must read the values they need first.
    """
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def _prepare_source(db: Session, repository: models.Repository, local_path: str | None,
                    github_token: str | None = None) -> tuple[str, str | None]:
    """Resolve the directory to analyse. Returns (root, temp_dir_to_delete_or_None).

    This is the only step that needs the network and the GitHub credential, and it always
    runs in the trusted parent - never in the analysis sandbox.
    """
    if local_path:
        return local_path, None
    repo_url = repository.repo_url                  # read now: attributes expire once the transaction ends
    org_id = repository.organization_id
    if repo_url.startswith("file://"):
        if not allow_local_repos():
            raise ValueError("Local repositories are disabled. Set ALLOW_LOCAL_REPOS=true for local development only.")
        return repo_url[len("file://"):], None
    validate_repository_url(repo_url)
    tmp_dir = tempfile.mkdtemp(prefix="ai_safety_scan_", dir=_work_root())
    try:
        if github_token is None:
            try:
                from ..routers.github_oauth import GITHUB_APP_SLUG, GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, get_installation_token
                if GITHUB_APP_SLUG and GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                    github_token = get_installation_token(db, org_id)
            except Exception:
                github_token = None
        _release_db(db)                             # the clone can take minutes: no open transaction meanwhile
        _clone_repo(repo_url, tmp_dir, github_token)
        _scan_debug("STAGE clone_complete")
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    return tmp_dir, tmp_dir


def _coverage_json(stats: dict) -> str | None:
    """JSON describing what a scan did NOT cover, or None when the whole repository was analysed."""
    import json
    total = int(stats.get("files_total") or 0)
    scanned = int(stats.get("files") or 0)
    skipped_large = int(stats.get("skipped_large") or 0)
    over_limit = int(stats.get("skipped_over_limit") or 0)
    time_limited = bool(stats.get("time_limited"))
    if not (skipped_large or over_limit or time_limited):
        return None
    return json.dumps({
        "files_total": total, "files_scanned": scanned, "skipped_large": skipped_large,
        "skipped_over_limit": over_limit, "time_limited": time_limited,
        "examples": list(stats.get("unscanned_examples") or [])[:20],
    })


def _persist_scan_result(db: Session, repository: models.Repository, scan: models.Scan,
                         result: dict, allow_llm: bool = True) -> models.Scan:
    """Store an analysis result (from pipeline.analyze_directory) and score it."""
    # Agents: one per file that imports an AI SDK
    agent_by_file: dict[str, models.Agent] = {}
    for a in result["agents"]:
        agent = models.Agent(
            scan_id=scan.id,
            repository_id=repository.id,
            name=os.path.basename(a["file_path"]),
            framework=a["framework"],
            model_provider=a["model_provider"],
            file_path=a["file_path"],
        )
        db.add(agent)
        agent_by_file[a["file_path"]] = agent
    db.commit()

    raw_findings = result["ai_findings"]
    injection_findings = result["injection_findings"]
    security_findings = result["security_findings"]

    # Stage 5: optional LLM refinement of AI capability snippets only.
    # Security findings stay deterministic so the model cannot invent or
    # suppress a credential/auth/data-flow finding.
    # allow_llm is False for sandbox results: the isolated path never sends code to an external model.
    refined_findings = llm_analyzer.refine_findings(raw_findings) if allow_llm else [dict(f) for f in raw_findings]
    for finding in refined_findings:
        finding["finding_domain"] = "AI_SAFETY"

    for finding in injection_findings:
        finding["finding_domain"] = "AI_SAFETY"
    refined_findings.extend(injection_findings)

    for finding in security_findings:
        finding["finding_domain"] = "PROJECT_SECURITY"

    refined_findings.extend(security_findings)

    for f in refined_findings:
        safe_f = prepare_finding_for_storage(f)
        fingerprint = risk_engine.compute_fingerprint(f)
        finding = models.Finding(
            scan_id=scan.id,
            severity=safe_f["severity"],
            category=safe_f["category"],
            finding_domain=safe_f.get("finding_domain", "PROJECT_SECURITY"),
            title=safe_f["title"],
            description=(
                safe_f.get("description")
                or (
                    "AI-connected code appears able to perform: "
                    f"{safe_f.get('capability', 'an action')}."
                )
            ),
            evidence=safe_f.get("evidence"),
            recommendation=(
                safe_f.get("recommendation")
                or "Review this finding and apply the recommended security controls."
            ),
            file_path=safe_f["file_path"],
            line_number=safe_f["line"],
            confidence=safe_f["confidence"],
            ai_provider=safe_f.get("ai_provider"),
            capability=safe_f["capability"],
            ai_controlled=safe_f.get("ai_controlled"),
            control_confidence=safe_f.get("control_confidence"),
            consequence=safe_f.get("consequence"),
            impact_level=safe_f.get("impact_level"),
            control_status=safe_f.get("control_status"),
            capability_chain=safe_f.get("capability_chain"),
            function_name=safe_f.get("function_name"),
            call_chain=safe_f.get("call_chain"),
            snippet=safe_f.get("snippet"),
            fingerprint=fingerprint,
            scored=safe_f.get("scored", True),
            potential_points=safe_f.get("potential_points", risk_engine.SEVERITY_POINTS[safe_f["severity"]]),
            status="open",
        )
        db.add(finding)

        # Capability graph node — linked to the agent for that file, if any.
        agent = agent_by_file.get(f["file_path"])
        if agent:
            cap = models.Capability(
                agent_id=agent.id,
                category=safe_f["category"],
                provider=safe_f.get("ai_provider"),
                operation=safe_f["capability"],
                ai_controlled=safe_f.get("ai_controlled"),
                control_confidence=safe_f.get("control_confidence"),
                capability_chain=safe_f.get("capability_chain"),
                file_path=safe_f["file_path"],
                line_number=safe_f["line"],
                evidence=safe_f.get("evidence"),
            )
            db.add(cap)
    db.commit()

    score_result = risk_engine.calculate_score(refined_findings)
    _scan_debug(f"STAGE scoring_complete score={score_result['score']} findings={len(refined_findings)}")

    scan.status = "completed"
    scan.score = score_result["score"]
    scan.coverage = _coverage_json(result.get("stats") or {})
    scan.finished_at = dt.datetime.now(dt.UTC)
    repository.last_scanned_at = dt.datetime.now(dt.UTC)
    db.commit()
    db.refresh(scan)
    return scan



def _execute_scan(db: Session, repository: models.Repository, scan: models.Scan, local_path: str | None = None, github_token: str | None = None) -> models.Scan:
    """Run the full pipeline in-process (development, tests, demo repo).

    Production uses ``run_scan_isolated``: same stages, but analysis runs in a secret-free
    sandbox process and only validated JSON comes back.
    """
    tmp_dir = None
    try:
        from ..database import cleanup_expired_scan_data
        try:
            cleanup_expired_scan_data(db)
        except Exception:
            pass
        root, tmp_dir = _prepare_source(db, repository, local_path, github_token)
        _release_db(db)                             # in-process analysis can also take minutes
        result = analyze_directory(root)
        return _persist_scan_result(db, repository, scan, result)

    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        scan.status = "failed"
        scan.error = sanitize_error(classify_clone_error(
            getattr(e, "stderr", None) if isinstance(getattr(e, "stderr", None), str) else None,
            timed_out=isinstance(e, subprocess.TimeoutExpired),
        ))
        scan.finished_at = dt.datetime.now(dt.UTC)
        db.commit()
        return scan
    except Exception as e:
        scan.status = "failed"
        scan.error = sanitize_error(str(e))
        scan.finished_at = dt.datetime.now(dt.UTC)
        db.commit()
        return scan
    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)


def run_scan(db: Session, repository: models.Repository, local_path: str | None = None,
             scan: models.Scan | None = None) -> models.Scan:
    if scan is None:
        scan = models.Scan(repository_id=repository.id, status="processing")
        db.add(scan)
        db.commit()
        db.refresh(scan)
    return _execute_scan(db, repository, scan, local_path)

def isolated_scan_enabled() -> bool:
    return os.environ.get("ENVIRONMENT", "development").lower() == "production" or os.environ.get("ISOLATED_SCAN_PROCESS", "false").lower() in {"1", "true", "yes", "on"}


def _backend_dir() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _sandbox_env(work_dir: str, plan: str | None = None) -> dict[str, str]:
    """Environment for the analysis worker: an allow-list with NO secrets.

    Deliberately absent: DATABASE_URL, JWT_SECRET, GitHub tokens/keys, every *_ENCRYPTION_KEY,
    LLM API keys. The worker only needs to read files and write one JSON file.
    """
    keep = ("MAX_SCAN_FILES", "MAX_SCAN_BYTES", "MAX_SCAN_FILE_BYTES", "SCAN_TIME_BUDGET_SECONDS",
            "SCAN_WORKER_CPU_SECONDS", "SCAN_WORKER_MEMORY_MB", "SCAN_WORKER_FILE_MB", "SANDBOX_NO_NETWORK")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
        "HOME": work_dir,
        "TMPDIR": work_dir,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in keep:
        if key in os.environ:
            env[key] = os.environ[key]
    if plan is not None:                       # per-organisation limits (app/limits.py) override the defaults
        from .. import limits
        env.update(limits.worker_env(plan))
    if os.name == "nt":
        # Windows (development machines): Python cannot even initialise sockets/asyncio
        # without these system variables. None of them is a secret.
        for key in ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT"):
            if key in os.environ:
                env[key] = os.environ[key]
        env["TEMP"] = env["TMP"] = env["USERPROFILE"] = work_dir
    return env


def run_scan_isolated(db: Session, repository: models.Repository, local_path: str | None = None,
                      scan: models.Scan | None = None) -> models.Scan:
    """Scan with a trust boundary.

    1. Trusted parent: resolve/clone the repository (needs network + GitHub credential).
    2. Sandbox worker: analyse the files with NO secrets, write plain JSON.
    3. Trusted parent: validate the JSON strictly, then persist and score it.
    """
    import subprocess as sp
    import sys

    from .. import limits
    org = db.query(models.Organization).filter(models.Organization.id == repository.organization_id).first()
    plan = org.plan if org else None
    timeout = limits.for_plan(plan)["worker_timeout"]
    if scan is None:
        scan = models.Scan(repository_id=repository.id, status="processing")
        db.add(scan)
        db.commit()
        db.refresh(scan)

    def fail(message: str) -> models.Scan:
        scan.status = "failed"
        scan.error = sanitize_error(message)
        scan.finished_at = dt.datetime.now(dt.UTC)
        db.commit()
        return scan

    tmp_dir = work_dir = None
    try:
        try:
            from ..database import cleanup_expired_scan_data
            cleanup_expired_scan_data(db)
        except Exception:
            pass
        try:
            root, tmp_dir = _prepare_source(db, repository, local_path)
        except (sp.CalledProcessError, sp.TimeoutExpired) as exc:
            return fail(classify_clone_error(
                exc.stderr if isinstance(getattr(exc, "stderr", None), str) else None,
                timed_out=isinstance(exc, sp.TimeoutExpired)))
        except ValueError as exc:
            return fail(str(exc))

        _release_db(db)                             # the sandboxed analysis can run for minutes: no open transaction
        work_dir = tempfile.mkdtemp(prefix="ai_safety_out_", dir=_work_root())
        out_path = os.path.join(work_dir, "result.json")
        proc = sp.Popen(
            [sys.executable, "-m", "app.scanner.sandbox_worker", root, out_path],
            cwd=_backend_dir(),
            env=_sandbox_env(work_dir, plan),
            stdin=sp.DEVNULL, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        try:
            proc.wait(timeout=timeout)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            return fail("Scan timed out or exceeded its resource limit.")

        if not os.path.exists(out_path) or getattr(proc, "returncode", 1) != 0:
            return fail("Scan worker stopped unexpectedly or exceeded its resource limit.")
        if os.path.getsize(out_path) > max_output_bytes():
            return fail("Scan produced more output than allowed.")
        try:
            import json
            with open(out_path, "r", encoding="utf-8") as fh:
                result = validate_result(json.load(fh))
        except (ValueError, WorkerOutputError, OSError):
            return fail("Scan worker returned an invalid result.")
        if "error" in result:
            return fail(result["error"])
        return _persist_scan_result(db, repository, scan, result, allow_llm=False)
    except Exception as exc:
        db.rollback()
        return fail(str(exc))
    finally:
        for path in (tmp_dir, work_dir):
            if path and os.path.exists(path):
                shutil.rmtree(path, ignore_errors=True)


def recompute_score(db: Session, scan: models.Scan) -> dict:
    """Recompute score honoring current finding statuses (e.g. after resolving)."""
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()
    as_dicts = [{"severity": f.severity, "status": f.status, "scored": f.scored} for f in findings]
    result = risk_engine.calculate_score(as_dicts)
    scan.score = result["score"]
    db.commit()
    return result


def get_previous_completed_scan(db: Session, repository_id: str, before_scan: models.Scan) -> models.Scan | None:
    return (
        db.query(models.Scan)
        .filter(
            models.Scan.repository_id == repository_id,
            models.Scan.status == "completed",
            models.Scan.id != before_scan.id,
            models.Scan.finished_at < before_scan.finished_at,
        )
        .order_by(models.Scan.finished_at.desc())
        .first()
    )


def compute_regression(db: Session, scan: models.Scan) -> dict:
    """Baseline/regression: compare this scan's findings against the most
    recent prior completed scan for the same repository, matched by stable
    fingerprint (category+operation+file_path) so line-number drift doesn't
    break the diff."""
    current_findings = db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()
    # Only scored findings drive regression alerts -- an unscored "potential
    # capability" appearing/disappearing/shifting severity shouldn't trigger
    # "AI Safety Regression Detected" when the tool itself has low
    # confidence in it.
    current_by_fp = {f.fingerprint: f for f in current_findings if f.fingerprint and f.scored}

    previous_scan = get_previous_completed_scan(db, scan.repository_id, scan)
    if not previous_scan:
        return {
            "has_baseline": False,
            "previous_score": None,
            "current_score": scan.score,
            "score_delta": None,
            "new_findings": [_finding_summary(f) for f in current_findings if f.scored],
            "resolved_findings": [],
        }

    previous_findings = db.query(models.Finding).filter(models.Finding.scan_id == previous_scan.id).all()
    previous_by_fp = {f.fingerprint: f for f in previous_findings if f.fingerprint and f.scored}

    new_fps = set(current_by_fp) - set(previous_by_fp)
    resolved_fps = set(previous_by_fp) - set(current_by_fp)
    # Same fingerprint, but got worse (e.g. a call went from ai_controlled=False
    # to True, or lost its approval guard) — not a brand new fingerprint, but
    # still a regression worth surfacing.
    escalated_fps = {
        fp for fp in (set(current_by_fp) & set(previous_by_fp))
        if risk_engine.SEVERITY_ORDER.index(current_by_fp[fp].severity)
           > risk_engine.SEVERITY_ORDER.index(previous_by_fp[fp].severity)
    }

    new_findings = [_finding_summary(current_by_fp[fp]) for fp in (new_fps | escalated_fps)]
    resolved_findings = [_finding_summary(previous_by_fp[fp]) for fp in resolved_fps]

    score_delta = None
    if previous_scan.score is not None and scan.score is not None:
        score_delta = scan.score - previous_scan.score

    return {
        "has_baseline": True,
        "previous_scan_id": previous_scan.id,
        "previous_score": previous_scan.score,
        "current_score": scan.score,
        "score_delta": score_delta,
        "regression": bool(score_delta is not None and score_delta < 0),
        "new_findings": sorted(new_findings, key=lambda x: -risk_engine.SEVERITY_POINTS[x["severity"]]),
        "resolved_findings": resolved_findings,
    }


def _finding_summary(f: models.Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "file_path": f.file_path,
        "line": f.line_number,
        "capability": f.capability,
        "ai_controlled": f.ai_controlled,
    }