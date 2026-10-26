"""Bounded background queue for scans.

Scans are slow (clone + static analysis). Running them inside the HTTP request pins a
web thread for minutes, so a handful of concurrent scans can freeze the API. Instead:

* ``POST /repositories/{id}/scan?async=true`` creates a ``queued`` scan and returns at once;
* a fixed pool of worker threads (MAX_GLOBAL_CONCURRENT_SCANS) drains the queue;
* the queue depth is capped (MAX_QUEUED_SCANS) so a flood is rejected with 503, not buffered
  without bound;
* clients poll ``GET /scans/{id}``; queued scans can be cancelled.

The queue lives in process memory. State is durable in the ``scans`` table, so after a
restart ``recover_orphans`` closes anything that was queued/running instead of leaving it
stuck. For several API instances, move this to a shared broker (Redis/SQS) - the job
function and the status model stay the same.
"""
import datetime as dt
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from . import models
from .database import SessionLocal

log = logging.getLogger("aisafety.jobs")

ACTIVE_STATUSES = ("queued", "processing")


class QueueFull(Exception):
    pass


def _int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except ValueError:
        return default


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _fail(db: Session, scan: models.Scan, message: str) -> None:
    scan.status = "failed"
    scan.error = message
    scan.finished_at = _now()
    db.commit()


def run_scan_job(scan_id: str) -> None:
    """Execute one queued scan. Never raises and never leaves the scan 'processing'."""
    from .scanner import scan_service

    db = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        if scan is None or scan.status != "queued":
            return                          # deleted or cancelled while waiting
        repo = db.get(models.Repository, scan.repository_id)
        if repo is None:
            _fail(db, scan, "Repository no longer exists.")
            return
        scan.status = "processing"
        scan.started_at = _now()
        db.commit()
        if scan_service.isolated_scan_enabled():
            scan_service.run_scan_isolated(db, repo, scan=scan)
        else:
            scan_service.run_scan(db, repo, scan=scan)
    except Exception:
        log.exception("scan job %s crashed", scan_id)
        try:
            db.rollback()
            scan = db.get(models.Scan, scan_id)
            if scan is not None and scan.status in ACTIVE_STATUSES:
                _fail(db, scan, "Scan failed unexpectedly. Please try again.")
        except Exception:                   # pragma: no cover - last resort
            log.exception("could not mark scan %s failed", scan_id)
    finally:
        db.close()


class ScanQueue:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None
        self._pending = 0

    @property
    def depth(self) -> int:
        return self._pending

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=_int("MAX_GLOBAL_CONCURRENT_SCANS", 4), thread_name_prefix="scan-worker")

    def submit(self, scan_id: str) -> None:
        self.start()
        with self._lock:
            if self._pending >= _int("MAX_QUEUED_SCANS", 50):
                raise QueueFull()
            self._pending += 1
        try:
            self._executor.submit(self._run, scan_id)
        except RuntimeError:                # executor shut down
            with self._lock:
                self._pending -= 1
            raise QueueFull()

    def _run(self, scan_id: str) -> None:
        try:
            run_scan_job(scan_id)
        finally:
            with self._lock:
                self._pending -= 1

    def shutdown(self) -> None:
        with self._lock:
            executor, self._executor = self._executor, None
            self._pending = 0
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)


queue = ScanQueue()


def recover_orphans(db: Session) -> int:
    """After a restart the in-memory queue is gone: close scans that can never finish."""
    if os.environ.get("SCAN_RECOVERY_ON_START", "true").lower() not in {"1", "true", "yes", "on"}:
        return 0
    stuck = db.query(models.Scan).filter(models.Scan.status.in_(ACTIVE_STATUSES)).all()
    for scan in stuck:
        scan.status = "failed"
        scan.error = "Scan was interrupted by a server restart. Please rescan."
        scan.finished_at = _now()
    if stuck:
        db.commit()
    return len(stuck)