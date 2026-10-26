"""Per-organisation quotas and global scan concurrency guard.

Scans are CPU/IO heavy and currently run inside the request, so without a cap a
handful of concurrent scans can exhaust the API's thread pool. These limits keep
the service responsive and make abuse expensive. Tune via environment variables.
"""
import datetime as dt
import os
import threading

from fastapi import HTTPException
from sqlalchemy.orm import Session

from . import models


def _int(name: str, default: int) -> int:
    try:
        return max(0, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


_GLOBAL = threading.BoundedSemaphore(_int("MAX_GLOBAL_CONCURRENT_SCANS", 4) or 1)


def max_repos_per_org() -> int:
    return _int("MAX_REPOS_PER_ORG", 100)


def check_repo_quota(db: Session, org_id: str) -> None:
    count = db.query(models.Repository).filter(models.Repository.organization_id == org_id).count()
    if count >= max_repos_per_org():
        raise HTTPException(status_code=403, detail="Repository limit reached for this organization")


def _org_scans(db: Session, org_id: str):
    return (
        db.query(models.Scan)
        .join(models.Repository, models.Scan.repository_id == models.Repository.id)
        .filter(models.Repository.organization_id == org_id)
    )


def expire_stale_scans(db: Session, org_id: str) -> None:
    """Mark scans stuck in 'processing' (crashed worker) as failed so they stop counting."""
    timeout = _int("SCAN_WORKER_TIMEOUT_SECONDS", 780)
    now = dt.datetime.now(dt.UTC)
    run_cutoff = now - dt.timedelta(seconds=timeout * 2 + 30)
    queue_cutoff = now - dt.timedelta(seconds=_int("MAX_QUEUE_WAIT_SECONDS", 1800))
    changed = False
    for scan in _org_scans(db, org_id).filter(models.Scan.status.in_(("processing", "queued"))).all():
        started = scan.started_at
        if started is not None and started.tzinfo is None:
            started = started.replace(tzinfo=dt.UTC)
        cutoff = queue_cutoff if scan.status == "queued" else run_cutoff
        if started is not None and started < cutoff:
            scan.status = "failed"
            scan.error = "Scan did not finish and was closed automatically."
            scan.finished_at = dt.datetime.now(dt.UTC)
            changed = True
    if changed:
        db.commit()


def check_scan_quota(db: Session, org_id: str) -> None:
    expire_stale_scans(db, org_id)
    concurrent = _org_scans(db, org_id).filter(models.Scan.status.in_(("processing", "queued"))).count()
    if concurrent >= _int("MAX_CONCURRENT_SCANS_PER_ORG", 2):
        raise HTTPException(
            status_code=429,
            detail="A scan is already running for this organization. Wait for it to finish.",
            headers={"Retry-After": "30"},
        )
    since = dt.datetime.now(dt.UTC) - dt.timedelta(hours=24)
    today = _org_scans(db, org_id).filter(models.Scan.started_at >= since).count()
    if today >= _int("DAILY_SCANS_PER_ORG", 50):
        raise HTTPException(
            status_code=429,
            detail="Daily scan limit reached for this organization.",
            headers={"Retry-After": "3600"},
        )


class ScanSlot:
    """Context manager holding one global scan slot; 503 when the service is saturated."""

    def __enter__(self):
        if not _GLOBAL.acquire(blocking=False):
            raise HTTPException(
                status_code=503,
                detail="The scanner is busy. Please retry in a moment.",
                headers={"Retry-After": "15"},
            )
        return self

    def __exit__(self, *exc):
        _GLOBAL.release()
        return False