import datetime as dt
import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import models, schemas, auth
from ..database import get_db
from ..scanner import risk_engine, scan_service, fix_generator, report_generator

router = APIRouter(tags=["scans"])


def _get_owned_scan(scan_id: str, db: Session, user: models.User) -> models.Scan:
    scan = (
        db.query(models.Scan)
        .join(models.Repository, models.Scan.repository_id == models.Repository.id)
        .filter(models.Scan.id == scan_id, models.Repository.organization_id == user.organization_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    return _get_owned_scan(scan_id, db, user)


@router.post("/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Cancel a scan that has not started yet. Running scans cannot be interrupted safely."""
    scan = _get_owned_scan(scan_id, db, user)
    if scan.status != "queued":
        raise HTTPException(status_code=409, detail=f"Only queued scans can be cancelled (this one is {scan.status}).")
    scan.status = "failed"
    scan.error = "Cancelled by user."
    scan.finished_at = dt.datetime.now(dt.UTC)
    db.commit()
    return {"cancelled": True, "scan_id": scan.id}


@router.get("/scans/{scan_id}/report.pdf")
def download_scan_report(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Generate a customer-facing PDF report for a completed scan."""
    scan = _get_owned_scan(scan_id, db, user)
    if scan.status != "completed":
        raise HTTPException(status_code=409, detail="A PDF report is available only for completed scans")

    repository = db.query(models.Repository).filter(models.Repository.id == scan.repository_id).first()
    findings = (
        db.query(models.Finding)
        .filter(models.Finding.scan_id == scan.id)
        .order_by(models.Finding.severity.desc(), models.Finding.file_path.asc())
        .all()
    )
    score_result = risk_engine.calculate_score([
        {"severity": f.severity, "status": f.status, "scored": f.scored}
        for f in findings
    ])
    regression = scan_service.compute_regression(db, scan)
    pdf = report_generator.build_scan_report_pdf(repository, scan, findings, score_result, regression)
    filename = re.sub(r"[^A-Za-z0-9._-]+", "-", repository.repo_name or scan.id)
    filename = f"ai-safety-report-{filename}.pdf"
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingOut])
def get_scan_findings(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    scan = _get_owned_scan(scan_id, db, user)
    return (
        db.query(models.Finding)
        .filter(models.Finding.scan_id == scan.id)
        .order_by(models.Finding.severity.desc())
        .all()
    )

@router.get(
    "/scans/{scan_id}/domain-scores",
    response_model=schemas.DomainScoresOut,
)
def scan_domain_scores(
    scan_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    scan = _get_owned_scan(scan_id, db, user)

    findings = (
        db.query(models.Finding)
        .filter(models.Finding.scan_id == scan.id)
        .all()
    )

    finding_dicts = [
        {
            "severity": f.severity,
            "status": f.status,
            "scored": f.scored,
            "finding_domain": f.finding_domain,
        }
        for f in findings
    ]

    overall = risk_engine.calculate_score(finding_dicts)
    domains = risk_engine.calculate_domain_scores(finding_dicts)

    return {
        "overall": overall,
        "ai_safety": domains["ai_safety"],
        "project_security": domains["project_security"],
    }


@router.get("/scans/{scan_id}/potential-score")
def potential_score(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """The 'Fix my score' feature: what would the score be if every open
    finding were resolved?

    Per-finding "points" is the exact marginal contribution of resolving
    *that one* finding with everything else held constant -- not a flat
    per-severity value. Under the diminishing-returns/capped scoring model
    (see risk_engine.SEVERITY_SCHEDULE), a flat value would be wrong: e.g.
    if a tier's cap is already being hit, resolving any single finding in
    it might be worth less than its "nominal" severity points, or worth
    zero if the tier cap is still exceeded by the remaining findings.
    """
    scan = _get_owned_scan(scan_id, db, user)
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()
    as_dicts = [{"severity": f.severity, "status": f.status, "scored": f.scored, "id": f.id} for f in findings]

    current = risk_engine.calculate_score(as_dicts)
    hypothetical = risk_engine.calculate_score(
        [{**d, "status": "resolved"} for d in as_dicts]
    )

    fixes = []
    for f in findings:
        if f.status != "open" or not f.scored:
            continue  # unscored findings never had points to give back
        with_this_resolved = [
            {**d, "status": "resolved"} if d["id"] == f.id else d for d in as_dicts
        ]
        marginal_score = risk_engine.calculate_score(with_this_resolved)["score"]
        fixes.append({
            "finding_id": f.id,
            "title": f.title,
            "severity": f.severity,
            "points": marginal_score - current["score"],
        })

    return {
        "current_score": current["score"],
        "potential_score": hypothetical["score"],
        "fixes": sorted(fixes, key=lambda x: -x["points"]),
    }


@router.get("/scans/{scan_id}/regression")
def scan_regression(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Baseline/regression: did this scan introduce new risky capabilities
    compared to the repository's last scan?"""
    scan = _get_owned_scan(scan_id, db, user)
    return scan_service.compute_regression(db, scan)


@router.get("/scans/{scan_id}/graph")
def scan_capability_graph(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Capability graph: Agent -> AI provider -> [AI-generated decision |
    static value] -> dangerous call -> operation, for every finding in this
    scan. Nodes are deduplicated by label (so the graph stays compact when
    the same provider/pattern appears in multiple capabilities), but each
    edge carries a `capability_id` identifying which specific capability it
    belongs to.

    This matters: generic intermediate labels like "AI-generated decision"
    or "static/fixed value" are shared across *unrelated* capabilities on
    purpose (that's what makes the graph compact) — but that means a node
    can have edges from multiple different original chains. Reconstructing
    an end-to-end narrative path by naively following source->target
    adjacency (ignoring which capability an edge came from) can silently
    stitch together fragments of two different capabilities into one false
    combined path -- e.g. wrongly implying a refund function can also send
    email, when in reality that email-sending edge came from a completely
    unrelated support-bot function that merely happens to share the
    generic "AI-generated decision" node. `capability_id` lets a consumer
    group edges back into their real, isolated per-capability chains.
    """
    scan = _get_owned_scan(scan_id, db, user)
    agents = db.query(models.Agent).filter(models.Agent.scan_id == scan.id).all()

    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(label: str, node_type: str):
        if label not in nodes:
            nodes[label] = {"id": label, "label": label, "type": node_type}

    for agent in agents:
        add_node(agent.name, "agent")
        for cap in agent.capabilities:
            chain = cap.capability_chain or [agent.name]
            for i, label in enumerate(chain):
                node_type = (
                    "agent" if i == 0 else
                    "ai_provider" if i == 1 else
                    "control" if i == 2 else
                    "call" if i == 3 else
                    "operation"
                )
                add_node(label, node_type)
                if i > 0:
                    edges.append({
                        "source": chain[i - 1], "target": label,
                        "ai_controlled": cap.ai_controlled,
                        "capability_id": cap.id,
                    })

    return {"nodes": list(nodes.values()), "edges": edges}


@router.get("/repositories/{repo_id}/scans", response_model=list[schemas.ScanOut])
def list_repository_scans(repo_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    repo = db.query(models.Repository).filter(
        models.Repository.id == repo_id, models.Repository.organization_id == user.organization_id,
    ).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return (
        db.query(models.Scan)
        .filter(models.Scan.repository_id == repo_id)
        .order_by(models.Scan.started_at.desc())
        .all()
    )


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    scan = _get_owned_scan(scan_id, db, user)
    db.delete(scan)
    db.commit()
    return {"deleted": True, "scan_id": scan_id}


@router.get("/findings/{finding_id}/fix")
def get_finding_fix(finding_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Priority 6: generate a concrete code patch for a finding (guard-clause
    insertion), not just a text recommendation. Returns a diff for review —
    does not modify anything. See POST /findings/{id}/apply-fix to apply it."""
    finding = _get_owned_finding(finding_id, db, user)
    return fix_generator.generate_fix(finding)


@router.post("/findings/{finding_id}/apply-fix")
def apply_finding_fix(finding_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    """Apply the generated fix and rescan, so the score visibly improves —
    but only for local/file:// repositories. Applying to a live GitHub repo
    would require GitHub OAuth *write* access (opening a branch + PR),
    which isn't implemented in this MVP; the diff from GET .../fix can still
    be applied manually in that case."""
    finding = _get_owned_finding(finding_id, db, user)
    scan = db.query(models.Scan).filter(models.Scan.id == finding.scan_id).first()
    repository = db.query(models.Repository).filter(models.Repository.id == scan.repository_id).first()

    if not repository.repo_url.startswith("file://"):
        raise HTTPException(
            status_code=400,
            detail="Applying fixes directly to a live GitHub repo isn't supported in this MVP "
                   "(requires GitHub OAuth write access + opening a PR). Use GET "
                   f"/findings/{finding_id}/fix to get the diff and apply it manually.",
        )

    root_dir = repository.repo_url[len("file://"):]
    fix = fix_generator.generate_fix(finding)
    if not fix.get("diff"):
        raise HTTPException(
            status_code=400,
            detail="No automatic patch is available for this finding. Follow the recommendation manually.",
        )

    try:
        result = fix_generator.apply_fix_to_local_file(root_dir, fix)
    except FileNotFoundError as e:
        raise HTTPException(status_code=400, detail=str(e))

    score_before = risk_engine.calculate_score(
        [{"severity": f.severity, "status": f.status, "scored": f.scored}
         for f in db.query(models.Finding).filter(models.Finding.scan_id == scan.id).all()]
    )["score"]


    # Rescan first. A returned scan may have status="failed" without raising.
    try:
        new_scan = scan_service.run_scan(db, repository)
    except Exception:
        # The source file may already have been modified. Do not claim
        # verification succeeded; leave the finding unresolved.
        raise HTTPException(
            status_code=500,
            detail=(
                "The fix was written to the local repository, but rescanning "
                "raised an error. Review the file and rescan manually."
            ),
        )

    if new_scan.status != "completed":
        # The file may already have been modified. Keep the finding unresolved.
        raise HTTPException(
            status_code=500,
            detail=(
                "The fix was written to the local repository, but verification "
                "failed. Review the file and retry the scan."
            ),
        )

    # Only update the original finding after a successful rescan.
    finding.status = "resolved"
    db.commit()

    return {
        "applied": result,
        "score_before": score_before,
        "score_after": new_scan.score,
        "rescan_id": new_scan.id,
        "rescan_status": new_scan.status,
    }



def _get_owned_finding(finding_id: str, db: Session, user: models.User) -> models.Finding:
    finding = (
        db.query(models.Finding)
        .join(models.Scan, models.Finding.scan_id == models.Scan.id)
        .join(models.Repository, models.Scan.repository_id == models.Repository.id)
        .filter(models.Finding.id == finding_id, models.Repository.organization_id == user.organization_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}", response_model=schemas.FindingOut)
def update_finding(
    finding_id: str,
    body: schemas.FindingUpdate,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    finding = _get_owned_finding(finding_id, db, user)
    finding.status = body.status
    db.commit()

    scan = db.query(models.Scan).filter(models.Scan.id == finding.scan_id).first()
    scan_service.recompute_score(db, scan)

    db.refresh(finding)
    return finding


@router.get("/organizations/{org_id}/score", response_model=schemas.ScoreOut)
def organization_score(org_id: str, db: Session = Depends(get_db), user: models.User = Depends(auth.get_current_user)):
    if org_id != user.organization_id:
        raise HTTPException(status_code=403, detail="Not authorized for this organization")

    latest_scan = (
        db.query(models.Scan)
        .join(models.Repository, models.Scan.repository_id == models.Repository.id)
        .filter(models.Repository.organization_id == org_id, models.Scan.status == "completed")
        .order_by(models.Scan.finished_at.desc())
        .first()
    )
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scans yet")

    findings = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id).all()
    result = risk_engine.calculate_score([{"severity": f.severity, "status": f.status, "scored": f.scored} for f in findings])
    return schemas.ScoreOut(**result)
