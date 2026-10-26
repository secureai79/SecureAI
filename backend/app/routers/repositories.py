from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from .. import models, schemas, auth, audit, quota, jobs
from ..database import get_db
from ..scanner import scan_service
from ..security import validate_repository_url

router = APIRouter(tags=["repositories"])


@router.post("/repositories", response_model=schemas.RepositoryOut)
def create_repository(
    body: schemas.RepositoryCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_verified_user),
):
    try:
        repo_url = validate_repository_url(body.repo_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Re-adding the same repository returns the existing record instead of duplicating it.
    existing = db.query(models.Repository).filter(
        models.Repository.organization_id == user.organization_id,
        models.Repository.repo_url == repo_url,
    ).first()
    if existing:
        return existing
    quota.check_repo_quota(db, user.organization_id)

    repo_name = body.repo_name or repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    repo = models.Repository(
        organization_id=user.organization_id,
        provider=body.provider,
        repo_name=repo_name,
        repo_url=repo_url,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
    audit.record(db, request, "repo.created", user_id=user.id, organization_id=user.organization_id, repo=repo.repo_name)
    return repo


@router.get("/repositories", response_model=list[schemas.RepositoryOut])
def list_repositories(
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.get_current_user),
):
    return db.query(models.Repository).filter(
        models.Repository.organization_id == user.organization_id
    ).all()


@router.post("/repositories/{repo_id}/scan", response_model=schemas.ScanOut)
def scan_repository(
    repo_id: str,
    request: Request,
    response: Response,
    run_async: bool = Query(False, alias="async"),
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_verified_user),
):
    repo = db.query(models.Repository).filter(
        models.Repository.id == repo_id,
        models.Repository.organization_id == user.organization_id,
    ).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    quota.check_scan_quota(db, user.organization_id)
    audit.record(db, request, "scan.started", user_id=user.id, organization_id=user.organization_id, repo=repo.repo_name)
    if run_async:
        # Return immediately; clients poll GET /scans/{id}. 202 = accepted, not finished.
        scan = models.Scan(repository_id=repo.id, status="queued")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        try:
            jobs.queue.submit(scan.id)
        except jobs.QueueFull:
            scan.status = "failed"
            scan.error = "The scan queue is full. Please try again shortly."
            db.commit()
            raise HTTPException(status_code=503, detail="The scan queue is full. Please try again shortly.",
                                headers={"Retry-After": "30"})
        response.status_code = 202
        response.headers["Location"] = f"/scans/{scan.id}"
        return scan
    with quota.ScanSlot():
        if scan_service.isolated_scan_enabled():
            scan = scan_service.run_scan_isolated(db, repo)
        else:
            scan = scan_service.run_scan(db, repo)
    return scan


@router.delete("/repositories/{repo_id}")
def delete_repository(
    repo_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(auth.require_admin),
):
    repo = db.query(models.Repository).filter(
        models.Repository.id == repo_id,
        models.Repository.organization_id == user.organization_id,
    ).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    name = repo.repo_name
    db.delete(repo)
    db.commit()
    audit.record(db, request, "repo.deleted", user_id=user.id, organization_id=user.organization_id, repo=name)
    return {"deleted": True, "repository_id": repo_id}