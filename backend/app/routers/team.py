"""Team & Access: invite people by e-mail, manage roles, remove members.

Roles: owner (one per workspace, full control) > admin (manage members, GitHub, repositories) > member
(add repositories, run scans, read results). Invitation tokens are 256-bit, single-use, expire, and are
stored only as SHA-256 digests; the link carries the token in the URL fragment.
"""
import datetime as dt
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from .. import audit, auth, limits, models, schemas, workspaces
from .. import email_service as mail
from ..database import get_db

router = APIRouter(prefix="/team", tags=["team"])

BAD_LINK = "This invitation link is invalid or has expired."


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _aware(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ttl() -> dt.timedelta:
    return dt.timedelta(days=max(1, mail.env_int("INVITE_TTL_DAYS", 7)))


def _org_plan(db: Session, org_id: str) -> str | None:
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    return org.plan if org else None


def _pending(db: Session, org_id: str):
    now = _now()
    rows = db.query(models.Invitation).filter(
        models.Invitation.organization_id == org_id,
        models.Invitation.accepted_at.is_(None),
        models.Invitation.revoked_at.is_(None),
    ).order_by(models.Invitation.created_at.desc()).all()
    return [r for r in rows if _aware(r.expires_at) > now]


def _member_out(u: models.User, mem: models.Membership, me: models.User) -> dict:
    return {
        "id": u.id, "email": u.email, "role": mem.role, "is_you": u.id == me.id,
        "email_verified": u.email_verified, "two_factor_enabled": u.mfa_enabled,
        "joined_at": mem.created_at.isoformat() if mem.created_at else None,
    }


def _invite_out(i: models.Invitation) -> dict:
    return {"id": i.id, "email": i.email, "role": i.role, "expires_at": _aware(i.expires_at).isoformat(),
            "created_at": _aware(i.created_at).isoformat() if i.created_at else None}


def _members(db: Session, org_id: str) -> list[tuple[models.User, models.Membership]]:
    return db.query(models.User, models.Membership).join(
        models.Membership, models.Membership.user_id == models.User.id
    ).filter(models.Membership.organization_id == org_id).order_by(models.Membership.created_at.asc()).all()


@router.get("")
def team_overview(user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    workspaces.ensure_membership(db, user)
    db.commit()
    members = _members(db, user.organization_id)
    is_admin = user.role in auth.ADMIN_ROLES
    pending = _pending(db, user.organization_id) if is_admin else []
    lim = limits.for_plan(_org_plan(db, user.organization_id))
    return {
        "role": user.role,
        "can_manage": is_admin,
        "can_change_roles": user.role == "owner",
        "members": [_member_out(u, m, user) for u, m in members],
        "invitations": [_invite_out(i) for i in pending],
        "seats": {"used": len(members) + len(_pending(db, user.organization_id)), "limit": lim["max_members"]},
    }


@router.post("/invitations")
def invite(body: schemas.InviteRequest, request: Request,
           user: models.User = Depends(auth.require_verified_admin), db: Session = Depends(get_db)):
    if body.role == "admin" and user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the workspace owner can invite admins.")
    email = auth.normalize_email(body.email)
    org_id = user.organization_id
    if db.query(models.Membership).join(models.User, models.User.id == models.Membership.user_id).filter(
            models.Membership.organization_id == org_id, models.User.email == email).first():
        raise HTTPException(status_code=400, detail="That person is already a member of this workspace.")
    if not mail.is_configured():
        raise HTTPException(status_code=503, detail="Email delivery is not configured on this server, so invitations cannot be sent.")
    now = _now()
    # one live invitation per address: inviting again replaces (and so resends) the old one
    existing = [i for i in _pending(db, org_id) if i.email == email]
    for old in existing:
        old.revoked_at = now
    day_ago = now - dt.timedelta(hours=24)
    sent_today = db.query(models.Invitation).filter(
        models.Invitation.organization_id == org_id, models.Invitation.created_at >= day_ago).count()
    if sent_today >= mail.env_int("INVITES_PER_DAY", 20):
        raise HTTPException(status_code=429, detail="Daily invitation limit reached. Try again tomorrow.")
    members = db.query(models.Membership).filter(models.Membership.organization_id == org_id).count()
    seats_used = members + len([i for i in _pending(db, org_id) if i.email != email])
    limit = limits.for_plan(_org_plan(db, org_id))["max_members"]
    if seats_used >= limit:
        db.rollback()
        raise HTTPException(status_code=403, detail=f"Your workspace is at its limit of {limit} members and pending invitations.")
    raw = secrets.token_urlsafe(32)
    inv = models.Invitation(organization_id=org_id, email=email, role=body.role, token_hash=_digest(raw),
                            invited_by=user.id, created_at=now, expires_at=now + _ttl())
    db.add(inv)
    db.commit()
    org_name = user.organization.name if user.organization else "your workspace"
    mail.send_invitation(email, org_name, user.email, body.role, raw)
    audit.record(db, request, "team.invited", user_id=user.id, organization_id=org_id)
    return _invite_out(inv)


@router.delete("/invitations/{invitation_id}")
def revoke_invitation(invitation_id: str, request: Request,
                      user: models.User = Depends(auth.require_admin), db: Session = Depends(get_db)):
    inv = db.query(models.Invitation).filter(
        models.Invitation.id == invitation_id, models.Invitation.organization_id == user.organization_id).first()
    if inv is None or inv.accepted_at is not None:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    if inv.revoked_at is None:
        inv.revoked_at = _now()
        db.commit()
        audit.record(db, request, "team.invite_revoked", user_id=user.id, organization_id=user.organization_id)
    return {"revoked": True}


def _live_invitation(db: Session, raw: str) -> models.Invitation | None:
    inv = db.query(models.Invitation).filter(models.Invitation.token_hash == _digest(raw)).first()
    if inv is None or inv.accepted_at is not None or inv.revoked_at is not None or _aware(inv.expires_at) <= _now():
        return None
    return inv


@router.post("/invitations/preview")
def preview_invitation(body: schemas.InviteTokenRequest, db: Session = Depends(get_db)):
    inv = _live_invitation(db, body.token)
    if inv is None:
        raise HTTPException(status_code=400, detail=BAD_LINK)
    org = db.query(models.Organization).filter(models.Organization.id == inv.organization_id).first()
    exists = db.query(models.User).filter(models.User.email == inv.email).first() is not None
    return {"organization_name": org.name if org else "a workspace", "email": inv.email, "role": inv.role,
            "account_exists": exists}


def _join(db: Session, request: Request, user: models.User, inv: models.Invitation) -> dict:
    """Consume the invitation once and make ``user`` a member of its workspace (and switch to it)."""
    won = db.execute(
        update(models.Invitation)
        .where(models.Invitation.id == inv.id, models.Invitation.accepted_at.is_(None),
               models.Invitation.revoked_at.is_(None))          # expiry was checked by the caller
        .values(accepted_at=_now())
        .execution_options(synchronize_session=False)
    ).rowcount
    if won != 1:
        db.rollback()
        raise HTTPException(status_code=400, detail=BAD_LINK)
    mem = workspaces.membership_in(db, user.id, inv.organization_id)
    if mem is None:
        mem = models.Membership(user_id=user.id, organization_id=inv.organization_id, role=inv.role)
        db.add(mem)
        db.flush()
    workspaces.activate(user, mem)
    db.commit()
    audit.record(db, request, "team.joined", user_id=user.id, organization_id=inv.organization_id)
    org = db.query(models.Organization).filter(models.Organization.id == inv.organization_id).first()
    return {"organization_id": inv.organization_id, "organization_name": org.name if org else "", "role": mem.role}


@router.post("/invitations/accept", response_model=schemas.TokenResponse)
def accept_invitation(body: schemas.InviteAcceptRequest, request: Request, db: Session = Depends(get_db)):
    """Create a NEW account from an invitation. Addresses that already have an account log in instead."""
    try:
        auth.validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    inv = _live_invitation(db, body.token)
    if inv is None:
        raise HTTPException(status_code=400, detail=BAD_LINK)
    if db.query(models.User).filter(models.User.email == inv.email).first():
        raise HTTPException(
            status_code=409,
            detail="This email address already has a SecureAI account. Log in with it to join this workspace.",
        )
    now = _now()
    user = models.User(
        email=inv.email, hashed_password=auth.hash_password(body.password), organization_id=inv.organization_id,
        role=inv.role, email_verified_at=now,      # the invitation reached their inbox, which proves it
    )
    db.add(user)
    try:
        db.flush()
        db.add(models.Membership(user_id=user.id, organization_id=inv.organization_id, role=inv.role))
        won = db.execute(
            update(models.Invitation)
            .where(models.Invitation.id == inv.id, models.Invitation.accepted_at.is_(None),
                   models.Invitation.revoked_at.is_(None))
            .values(accepted_at=now)
            .execution_options(synchronize_session=False)
        ).rowcount
        if won != 1:
            db.rollback()
            raise HTTPException(status_code=400, detail=BAD_LINK)
        db.commit()
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail=BAD_LINK)
    audit.record(db, request, "team.joined", user_id=user.id, organization_id=user.organization_id)
    return schemas.TokenResponse(
        access_token=auth.create_access_token(user.id, user.organization_id, user.token_version),
        organization_id=user.organization_id, user_id=user.id,
    )


@router.post("/invitations/accept-existing")
def accept_invitation_logged_in(body: schemas.InviteTokenRequest, request: Request,
                                user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    """An existing account joins another workspace using the e-mailed link."""
    inv = _live_invitation(db, body.token)
    if inv is None or inv.email != auth.normalize_email(user.email):
        raise HTTPException(status_code=400, detail=BAD_LINK)       # same message: a link for someone else reveals nothing
    return _join(db, request, user, inv)


# ------------------------------------------------------------------ invitations addressed to ME (in-app)
def _my_invitation(db: Session, user: models.User, invitation_id: str) -> models.Invitation:
    inv = db.query(models.Invitation).filter(models.Invitation.id == invitation_id).first()
    if inv is None or inv.email != auth.normalize_email(user.email) or inv.accepted_at is not None \
            or inv.revoked_at is not None or _aware(inv.expires_at) <= _now():
        raise HTTPException(status_code=404, detail="Invitation not found.")
    return inv


@router.get("/my-invitations")
def my_invitations(user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    now = _now()
    rows = db.query(models.Invitation).filter(
        models.Invitation.email == auth.normalize_email(user.email),
        models.Invitation.accepted_at.is_(None), models.Invitation.revoked_at.is_(None),
    ).order_by(models.Invitation.created_at.desc()).all()
    out = []
    for inv in rows:
        if _aware(inv.expires_at) <= now:
            continue
        if workspaces.membership_in(db, user.id, inv.organization_id):
            continue                                   # already a member: nothing to accept
        org = db.query(models.Organization).filter(models.Organization.id == inv.organization_id).first()
        inviter = db.query(models.User).filter(models.User.id == inv.invited_by).first() if inv.invited_by else None
        out.append({"id": inv.id, "organization_name": org.name if org else "a workspace", "role": inv.role,
                    "invited_by": inviter.email if inviter else None,
                    "expires_at": _aware(inv.expires_at).isoformat()})
    return {"invitations": out}


@router.post("/my-invitations/{invitation_id}/accept")
def accept_my_invitation(invitation_id: str, request: Request,
                         user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    return _join(db, request, user, _my_invitation(db, user, invitation_id))


@router.post("/my-invitations/{invitation_id}/decline")
def decline_my_invitation(invitation_id: str, request: Request,
                          user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    inv = _my_invitation(db, user, invitation_id)
    inv.revoked_at = _now()
    db.commit()
    audit.record(db, request, "team.invite_declined", user_id=user.id, organization_id=inv.organization_id)
    return {"declined": True}


# ------------------------------------------------------------------ my workspaces
@router.get("/workspaces")
def my_workspaces(user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    mems = workspaces.memberships_of(db, user)
    db.commit()
    orgs = {o.id: o for o in db.query(models.Organization).filter(
        models.Organization.id.in_([m.organization_id for m in mems])).all()}
    return {"workspaces": [
        {"id": m.organization_id, "name": orgs[m.organization_id].name if m.organization_id in orgs else "",
         "role": m.role, "active": m.organization_id == user.organization_id}
        for m in mems
    ]}


@router.post("/workspaces/switch")
def switch_workspace(body: schemas.SwitchWorkspaceRequest, request: Request,
                     user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    mem = workspaces.membership_in(db, user.id, body.organization_id)
    if mem is None:
        raise HTTPException(status_code=404, detail="You are not a member of that workspace.")
    workspaces.activate(user, mem)
    db.commit()
    audit.record(db, request, "team.switched", user_id=user.id, organization_id=mem.organization_id)
    org = db.query(models.Organization).filter(models.Organization.id == mem.organization_id).first()
    return {"organization_id": mem.organization_id, "organization_name": org.name if org else "", "role": mem.role}


def _drop_membership(db: Session, target: models.User, mem: models.Membership) -> bool:
    """Remove ``target`` from the workspace of ``mem``. Returns True if the whole account was deleted
    (it belonged to no other workspace). Otherwise the account stays and is moved to another workspace."""
    org_id = mem.organization_id
    db.query(models.OAuthState).filter(models.OAuthState.user_id == target.id,
                                       models.OAuthState.organization_id == org_id).delete()
    db.delete(mem)
    db.flush()
    others = db.query(models.Membership).filter(
        models.Membership.user_id == target.id, models.Membership.organization_id != org_id).all()
    if not others:
        db.query(models.OAuthState).filter(models.OAuthState.user_id == target.id).delete()
        db.delete(target)                                # cascades to e-mail tokens, recovery codes, memberships
        return True
    if target.organization_id == org_id:
        keep = sorted(others, key=lambda m: (m.role != "owner", m.created_at or _now()))[0]
        workspaces.activate(target, keep)
    auth.revoke_all_tokens(target)                       # no stale session into the workspace they left
    return False


@router.post("/workspaces/{organization_id}/leave")
def leave_workspace(organization_id: str, request: Request,
                    user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    mem = workspaces.membership_in(db, user.id, organization_id)
    if mem is None:
        raise HTTPException(status_code=404, detail="You are not a member of that workspace.")
    if mem.role == "owner":
        raise HTTPException(status_code=400, detail="The owner cannot leave their own workspace.")
    deleted = _drop_membership(db, user, mem)
    db.commit()
    audit.record(db, request, "team.left", user_id=user.id, organization_id=organization_id)
    if deleted:
        return {"left": True, "account_deleted": True}
    # the old session was ended on purpose; hand back a fresh one that points at the workspace they landed in
    return {"left": True, "account_deleted": False, "organization_id": user.organization_id,
            "access_token": auth.create_access_token(user.id, user.organization_id, user.token_version)}


def _member_or_404(db: Session, actor: models.User, user_id: str) -> tuple[models.User, models.Membership]:
    row = db.query(models.User, models.Membership).join(
        models.Membership, models.Membership.user_id == models.User.id
    ).filter(models.User.id == user_id, models.Membership.organization_id == actor.organization_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Member not found.")
    return row


@router.patch("/members/{user_id}")
def change_role(user_id: str, body: schemas.RoleChangeRequest, request: Request,
                user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the workspace owner can change roles.")
    target, mem = _member_or_404(db, user, user_id)
    if target.id == user.id or mem.role == "owner":
        raise HTTPException(status_code=400, detail="The owner's role cannot be changed.")
    mem.role = body.role
    if target.organization_id == mem.organization_id:
        target.role = body.role                          # keep the active copy in step
    db.commit()
    audit.record(db, request, "team.role_changed", user_id=user.id, organization_id=user.organization_id)
    return _member_out(target, mem, user)


@router.delete("/members/{user_id}")
def remove_member(user_id: str, request: Request,
                  user: models.User = Depends(auth.require_admin), db: Session = Depends(get_db)):
    target, mem = _member_or_404(db, user, user_id)
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot remove yourself.")
    if mem.role == "owner":
        raise HTTPException(status_code=403, detail="The workspace owner cannot be removed.")
    if mem.role == "admin" and user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the workspace owner can remove admins.")
    email, org_name = target.email, user.organization.name if user.organization else "your workspace"
    _drop_membership(db, target, mem)
    db.commit()
    audit.record(db, request, "team.member_removed", user_id=user.id, organization_id=user.organization_id)
    mail.send_removed(email, org_name)
    return {"removed": True}
