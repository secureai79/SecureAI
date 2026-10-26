"""Workspace membership helpers.

A user can belong to several workspaces. ``User.organization_id`` and ``User.role`` hold the ACTIVE one
(every request is scoped to it, and every existing permission check reads ``user.role``); ``Membership``
rows list all of them. Switching copies the chosen membership into the user row.
"""
from sqlalchemy.orm import Session

from . import models


def ensure_membership(db: Session, user: models.User) -> models.Membership:
    """Make sure the user's active workspace has a membership row (covers legacy rows and new users)."""
    mem = db.query(models.Membership).filter(
        models.Membership.user_id == user.id, models.Membership.organization_id == user.organization_id).first()
    if mem is None:
        mem = models.Membership(user_id=user.id, organization_id=user.organization_id, role=user.role or "member")
        db.add(mem)
        db.flush()
    return mem


def memberships_of(db: Session, user: models.User) -> list[models.Membership]:
    ensure_membership(db, user)
    return db.query(models.Membership).filter(models.Membership.user_id == user.id) \
        .order_by(models.Membership.created_at.asc()).all()


def membership_in(db: Session, user_id: str, org_id: str) -> models.Membership | None:
    return db.query(models.Membership).filter(
        models.Membership.user_id == user_id, models.Membership.organization_id == org_id).first()


def activate(user: models.User, mem: models.Membership) -> None:
    """Make ``mem`` the workspace every request is scoped to."""
    user.organization_id = mem.organization_id
    user.role = mem.role


def backfill(db: Session) -> int:
    """Create the missing membership row for every existing user (idempotent)."""
    created = 0
    for user in db.query(models.User).all():
        if membership_in(db, user.id, user.organization_id) is None:
            db.add(models.Membership(user_id=user.id, organization_id=user.organization_id, role=user.role or "member"))
            created += 1
    db.commit()
    return created
