"""One-time tokens for e-mail verification and password reset.

* 256 bits of randomness, URL-safe (matches the ``[A-Za-z0-9_-]{20,100}`` check in the pages).
* Only a SHA-256 digest is stored; the raw token exists only in the e-mailed link.
* Consuming a token is a single conditional UPDATE, so two concurrent requests can never both win.
* Issuing a new token retires older unused tokens of the same purpose for that user.
"""
import datetime as dt
import hashlib
import secrets

from sqlalchemy import update
from sqlalchemy.orm import Session

from . import models

VERIFY = "verify_email"
RESET = "reset_password"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def issue(db: Session, user: models.User, purpose: str, ttl: dt.timedelta) -> str:
    now = _now()
    db.execute(
        update(models.EmailToken)
        .where(
            models.EmailToken.user_id == user.id,
            models.EmailToken.purpose == purpose,
            models.EmailToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    raw = secrets.token_urlsafe(32)
    db.add(models.EmailToken(
        user_id=user.id, purpose=purpose, token_hash=_digest(raw),
        created_at=now, expires_at=now + ttl,
    ))
    db.commit()
    return raw


def consume(db: Session, raw: str, purpose: str) -> models.User | None:
    """Return the owning user and burn the token, or None if it is unknown/used/expired."""
    if not raw or len(raw) > 200:
        return None
    row = db.query(models.EmailToken).filter(
        models.EmailToken.token_hash == _digest(raw),
        models.EmailToken.purpose == purpose,
    ).first()
    if row is None:
        return None
    now = _now()
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=dt.UTC)
    if row.used_at is not None or expires <= now:
        return None
    won = db.execute(
        update(models.EmailToken)
        .where(models.EmailToken.id == row.id, models.EmailToken.used_at.is_(None))
        .values(used_at=now)
    ).rowcount
    db.commit()
    if won != 1:
        return None
    return db.query(models.User).filter(models.User.id == row.user_id).first()


def retire_all(db: Session, user: models.User, purpose: str) -> None:
    db.execute(
        update(models.EmailToken)
        .where(
            models.EmailToken.user_id == user.id,
            models.EmailToken.purpose == purpose,
            models.EmailToken.used_at.is_(None),
        )
        .values(used_at=_now())
    )


def issued_since(db: Session, user: models.User, purpose: str, since: dt.datetime) -> list[dt.datetime]:
    rows = db.query(models.EmailToken.created_at).filter(
        models.EmailToken.user_id == user.id,
        models.EmailToken.purpose == purpose,
        models.EmailToken.created_at >= since,
    ).order_by(models.EmailToken.created_at.desc()).all()
    out = []
    for (created,) in rows:
        out.append(created if created.tzinfo else created.replace(tzinfo=dt.UTC))
    return out


def purge_old(db: Session | None = None) -> int:
    """Delete tokens that expired more than a week ago."""
    from .database import SessionLocal
    owns = db is None
    session = db or SessionLocal()
    try:
        cutoff = _now() - dt.timedelta(days=7)
        n = session.query(models.EmailToken).filter(models.EmailToken.expires_at < cutoff).delete()
        session.commit()
        return n
    finally:
        if owns:
            session.close()
