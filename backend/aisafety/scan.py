"""Run the analysis pipeline on a checkout and compare against a base ref or baseline file."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass

from app.scanner import risk_engine
from app.scanner.pipeline import analyze_directory

SEV = risk_engine.SEVERITY_ORDER


class ScanError(RuntimeError):
    pass


@dataclass
class ScanResult:
    root: str
    findings: list
    score: dict
    domain_scores: dict
    stats: dict

    @property
    def fingerprints(self) -> dict:
        return {f["fingerprint"]: f["severity"] for f in self.findings if f.get("scored", True)}


def scan_directory(root: str) -> ScanResult:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise ScanError(f"not a directory: {root}")
    try:
        result = analyze_directory(root)
    except ValueError as exc:                    # expected limits (too many files, too large)
        raise ScanError(str(exc))
    findings: list[dict] = []
    for key, domain in (("ai_findings", "AI_SAFETY"), ("injection_findings", "AI_SAFETY"),
                        ("security_findings", "PROJECT_SECURITY")):
        for f in result[key]:
            f = dict(f)
            f["file_path"] = str(f["file_path"]).replace("\\", "/")
            f["finding_domain"] = domain
            f["fingerprint"] = risk_engine.compute_fingerprint(f)
            findings.append(f)
    findings.sort(key=lambda f: (-risk_engine.SEVERITY_POINTS[f["severity"]], f["file_path"], f.get("line", 0)))
    return ScanResult(
        root=root, findings=findings, score=risk_engine.calculate_score(findings),
        domain_scores=risk_engine.calculate_domain_scores(findings), stats=result["stats"],
    )


# ------------------------------------------------------------------ base ref
def _git(root: str, *args: str, **kw):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, **kw)


def scan_git_ref(root: str, ref: str) -> ScanResult:
    """Scan the tree of ``ref`` (e.g. origin/main) without touching the working copy."""
    if not ref or ref.startswith("-") or any(c in ref for c in "\x00\n\r"):
        raise ScanError(f"invalid git ref: {ref!r}")
    root = os.path.abspath(root)
    probe = _git(root, "rev-parse", "--is-inside-work-tree", text=True)
    if probe.returncode != 0:
        raise ScanError("--base-ref needs a git checkout (fetch full history: actions/checkout fetch-depth: 0)")
    prefix = _git(root, "rev-parse", "--show-prefix", text=True).stdout.strip()
    verify = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", text=True)
    if verify.returncode != 0:
        raise ScanError(f"base ref '{ref}' not found. In CI use actions/checkout with fetch-depth: 0 "
                        f"and pass a ref such as origin/main.")
    tree = f"{ref}:{prefix}" if prefix else ref
    tmp = tempfile.mkdtemp(prefix="aisafety_base_")
    try:
        proc = subprocess.Popen(["git", "-C", root, "archive", "--format=tar", tree],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
            tar.extractall(tmp, filter="data")       # 'data' filter blocks traversal, links, devices
        if proc.wait() != 0:
            raise ScanError(f"could not read {ref}: {proc.stderr.read().decode(errors='ignore')[:200]}")
        return scan_directory(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ baseline
def write_baseline(path: str, result: ScanResult) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "score": result.score["score"], "fingerprints": result.fingerprints}, fh, indent=1)


def read_baseline(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        fps = data["fingerprints"]
        if data.get("version") != 1 or not isinstance(fps, dict) or any(v not in SEV for v in fps.values()):
            raise ValueError
        return {"fingerprints": fps, "score": data.get("score")}
    except (OSError, ValueError, KeyError, TypeError):
        raise ScanError(f"invalid baseline file: {path}")


def existing_fingerprints(head: ScanResult, base_fps: dict) -> set:
    """Findings already present on the base. A finding that got MORE severe counts as new."""
    out = set()
    for f in head.findings:
        base_sev = base_fps.get(f["fingerprint"])
        if base_sev is not None and SEV.index(f["severity"]) <= SEV.index(base_sev):
            out.add(f["fingerprint"])
    return out