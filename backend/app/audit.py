"""Append-only security audit trail (who did what, when, from where)."""
import json
import logging

from fastapi import Request
from sqlalchemy.orm import Session

from . import models
from .rate_limit import client_ip

log = logging.getLogger("aisafety.audit")


def record(db: Session, request: Request | None, action: str, *, user_id: str | None = None,
           organization_id: str | None = None, **detail) -> None:
    """Best-effort: auditing must never break the request it describes."""
    try:
        event = models.AuditEvent(
            organization_id=organization_id,
            user_id=user_id,
            action=action[:64],
            detail=detail or None,
            ip=client_ip(request) if request is not None else None,
        )
        db.add(event)
        db.commit()
        log.info(json.dumps({"action": action, "org": organization_id, "user": user_id, **detail}, default=str))
    except Exception:  # pragma: no cover - defensive
        db.rollback()
