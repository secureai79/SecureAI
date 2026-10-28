import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models, schemas, auth, audit
from .. import email_service as mail
from .. import email_tokens as tokens
from .. import mfa
from ..database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


FORGOT_MESSAGE = (
    "If an account exists for that address, we have sent a reset link. "
    "It can take a minute to arrive; check your spam folder too."
)


def _verify_ttl() -> dt.timedelta:
    return dt.timedelta(hours=max(1, mail.env_int("EMAIL_VERIFICATION_TTL_HOURS", 24)))


def _reset_ttl() -> dt.timedelta:
    return dt.timedelta(minutes=max(5, mail.env_int("PASSWORD_RESET_TTL_MINUTES", 30)))


def _send_verification(db: Session, user: models.User) -> bool:
    raw = tokens.issue(db, user, tokens.VERIFY, _verify_ttl())
    return mail.send_verification(user.email, raw)


def _throttled(db: Session, user: models.User, purpose: str, cooldown: int, per_hour: int) -> int:
    """Seconds the caller must wait before another e-mail of this kind, or 0 if allowed."""
    now = dt.datetime.now(dt.UTC)
    recent = tokens.issued_since(db, user, purpose, now - dt.timedelta(hours=1))
    if recent and cooldown > 0:
        wait = cooldown - (now - recent[0]).total_seconds()
        if wait > 0:
            return int(wait) + 1
    if len(recent) >= per_hour:
        return int((recent[-1] + dt.timedelta(hours=1) - now).total_seconds()) + 1
    return 0


SIGNUP_PENDING_MESSAGE = (
    "Almost there. If this address can be used, we have sent a message to it with the next step. "
    "Check your inbox (and spam folder), then log in."
)
_notice_sent: dict[str, float] = {}          # e-mail -> time of the last "you already have an account" notice


def private_signup() -> bool:
    """Answer sign-ups identically whether or not the e-mail is registered. On by default in production."""
    return mail.env_bool("PREVENT_ACCOUNT_ENUMERATION", mail._is_production())


def _notice_due(email: str, every_seconds: int = 600) -> bool:
    import time
    now = time.monotonic()
    if len(_notice_sent) > 5000:
        _notice_sent.clear()
    last = _notice_sent.get(email)
    if last is not None and now - last < every_seconds:
        return False
    _notice_sent[email] = now
    return True


@router.post("/signup", response_model=schemas.SignupResponse | schemas.SignupPending)
def signup(body: schemas.SignupRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.validate_password(body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    email = auth.normalize_email(body.email)
    existing = db.query(models.User).filter(models.User.email == email).first()
    private = private_signup()
    if existing:
        if not private:
            raise HTTPException(status_code=400, detail="Email already registered")
        auth.burn_password_check(body.password)        # same CPU cost as creating an account
        if mail.is_configured() and _notice_due(email):
            mail.send_account_exists(existing.email)   # the real owner learns of it; the requester learns nothing
        return schemas.SignupPending(detail=SIGNUP_PENDING_MESSAGE)

    org = models.Organization(name=body.organization_name.strip()[:200])
    db.add(org)
    db.commit()
    db.refresh(org)

    user = models.User(
        organization_id=org.id,
        email=email,
        hashed_password=auth.hash_password(body.password),
        role="owner",
    )
    db.add(user)
    db.flush()
    db.add(models.Membership(user_id=user.id, organization_id=org.id, role="owner"))
    db.commit()
    db.refresh(user)

    audit.record(db, request, "auth.signup", user_id=user.id, organization_id=org.id)
    sent = False
    if mail.is_configured():
        try:
            sent = _send_verification(db, user)
        except Exception:  # signup must never fail because e-mail is down
            db.rollback()
    if private:
        return schemas.SignupPending(detail=SIGNUP_PENDING_MESSAGE)
    token = auth.create_access_token(user.id, org.id, user.token_version)
    return schemas.SignupResponse(
        access_token=token, organization_id=org.id, user_id=user.id, verification_email_sent=sent,
    )


@router.post("/login", response_model=schemas.TokenResponse | schemas.MfaChallenge)
def login(body: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = auth.normalize_email(body.email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is not None and auth.is_locked(user):
        auth.burn_password_check(body.password)
        audit.record(db, request, "auth.login_blocked", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(auth.LOCKOUT_MINUTES * 60)},
        )
    if user is None:
        auth.burn_password_check(body.password)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not auth.verify_password(body.password, user.hashed_password):
        auth.register_failed_login(user)
        db.commit()
        audit.record(db, request, "auth.login_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if auth.needs_rehash(user.hashed_password):
        user.hashed_password = auth.hash_password(body.password)
    if user.mfa_enabled:
        # Password is right but the sign-in is NOT complete. Failure counters are deliberately not reset
        # here: otherwise someone who knows the password could guess 6-digit codes without ever being locked out.
        db.commit()
        audit.record(db, request, "auth.login_mfa_required", user_id=user.id, organization_id=user.organization_id)
        return schemas.MfaChallenge(mfa_token=mfa.create_challenge(user))
    auth.register_successful_login(user)
    db.commit()
    audit.record(db, request, "auth.login", user_id=user.id, organization_id=user.organization_id)
    token = auth.create_access_token(user.id, user.organization_id, user.token_version)
    return schemas.TokenResponse(access_token=token, organization_id=user.organization_id, user_id=user.id)


@router.post("/logout")
def logout(request: Request, user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    auth.revoke_all_tokens(user)
    db.commit()
    audit.record(db, request, "auth.logout", user_id=user.id, organization_id=user.organization_id)
    return {"logged_out": True}


@router.delete("/data")
def delete_organization_data(
    body: schemas.DataDeletionRequest,
    request: Request,
    user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can delete organization data")
    if body.confirmation != "DELETE":
        raise HTTPException(status_code=400, detail='Type "DELETE" to confirm permanent deletion')
    org = db.query(models.Organization).filter(models.Organization.id == user.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    org_id, user_id = org.id, user.id
    db.delete(org)
    db.commit()
    audit.record(db, request, "org.data_deleted", user_id=user_id, organization_id=org_id)
    return {"deleted": True, "organization_id": user.organization_id}


@router.get("/audit")
def list_audit_events(
    limit: int = 100,
    user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    """Recent security events for the caller's organisation (owner only)."""
    if user.role != "owner":
        raise HTTPException(status_code=403, detail="Only the organization owner can view the audit log")
    limit = max(1, min(int(limit), 500))
    rows = (
        db.query(models.AuditEvent)
        .filter(models.AuditEvent.organization_id == user.organization_id)
        .order_by(models.AuditEvent.created_at.desc())
        .limit(limit)
        .all()
    )
    return [
        {"id": r.id, "action": r.action, "user_id": r.user_id, "ip": r.ip,
         "detail": r.detail, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]



@router.get("/me")
def me(user: models.User = Depends(auth.get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "organization_id": user.organization_id,
        "organization_name": user.organization.name if user.organization else None,
        "email_verified": user.email_verified,
        "verification_required": mail.verification_required(),
        "two_factor_enabled": user.mfa_enabled,
    }


@router.post("/resend-verification")
def resend_verification(
    request: Request,
    user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if user.email_verified:
        return {"detail": "Your email is already confirmed.", "email_verified": True}
    if not mail.is_configured():
        raise HTTPException(status_code=503, detail="Email delivery is not configured on this server.")
    wait = _throttled(
        db, user, tokens.VERIFY,
        cooldown=mail.env_int("VERIFICATION_RESEND_COOLDOWN_SECONDS", 60),
        per_hour=mail.env_int("VERIFICATION_RESEND_MAX_PER_HOUR", 5),
    )
    if wait:
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {wait} seconds before requesting another email.",
            headers={"Retry-After": str(wait)},
        )
    if not _send_verification(db, user):
        raise HTTPException(status_code=503, detail="Could not send the email right now. Try again shortly.")
    audit.record(db, request, "auth.verification_resent", user_id=user.id, organization_id=user.organization_id)
    return {"detail": f"We sent a new confirmation link to {user.email}. Check your inbox and spam folder."}


@router.post("/verify-email")
def verify_email(body: schemas.VerifyEmailRequest, request: Request, db: Session = Depends(get_db)):
    user = tokens.consume(db, body.token, tokens.VERIFY)
    if user is None:
        raise HTTPException(status_code=400, detail="This link is invalid or has expired.")
    if user.email_verified_at is None:
        user.email_verified_at = dt.datetime.now(dt.UTC)
        db.commit()
    audit.record(db, request, "auth.email_verified", user_id=user.id, organization_id=user.organization_id)
    return {"verified": True, "detail": "Your email is confirmed."}


@router.post("/forgot-password")
def forgot_password(body: schemas.ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Always answers the same way, so it cannot be used to discover which e-mails are registered."""
    email = auth.normalize_email(body.email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is not None and mail.is_configured():
        wait = _throttled(
            db, user, tokens.RESET,
            cooldown=mail.env_int("PASSWORD_RESET_COOLDOWN_SECONDS", 60),
            per_hour=mail.env_int("PASSWORD_RESET_MAX_PER_HOUR", 3),
        )
        if not wait:
            raw = tokens.issue(db, user, tokens.RESET, _reset_ttl())
            mail.send_password_reset(user.email, raw)
            audit.record(db, request, "auth.password_reset_requested", user_id=user.id, organization_id=user.organization_id)
        else:
            audit.record(db, request, "auth.password_reset_throttled", user_id=user.id, organization_id=user.organization_id)
    return {"detail": FORGOT_MESSAGE}


@router.post("/reset-password")
def reset_password(body: schemas.ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    try:
        auth.validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    user = tokens.consume(db, body.token, tokens.RESET)
    if user is None:
        raise HTTPException(status_code=400, detail="This reset link is invalid or has expired.")
    user.hashed_password = auth.hash_password(body.new_password)
    auth.revoke_all_tokens(user)            # every signed-in device is logged out
    auth.register_successful_login(user)   # clears any lockout
    if user.email_verified_at is None:     # they just proved they control the inbox
        user.email_verified_at = dt.datetime.now(dt.UTC)
    tokens.retire_all(db, user, tokens.RESET)
    db.commit()
    audit.record(db, request, "auth.password_reset", user_id=user.id, organization_id=user.organization_id)
    mail.send_password_changed(user.email)
    return {"detail": "Password updated. Log in with your new password."}


@router.post("/change-password")
def change_password(
    body: schemas.ChangePasswordRequest,
    request: Request,
    user: models.User = Depends(auth.get_current_user),
    db: Session = Depends(get_db),
):
    if auth.is_locked(user):
        auth.burn_password_check(body.current_password)
        raise HTTPException(
            status_code=429, detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(auth.LOCKOUT_MINUTES * 60)},
        )
    if not auth.verify_password(body.current_password, user.hashed_password):
        auth.register_failed_login(user)   # a stolen session must not be able to brute-force the password
        db.commit()
        audit.record(db, request, "auth.change_password_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=400, detail="Your current password is incorrect.")
    try:
        auth.validate_password(body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="Choose a password different from your current one.")
    user.hashed_password = auth.hash_password(body.new_password)
    auth.revoke_all_tokens(user)
    auth.register_successful_login(user)
    tokens.retire_all(db, user, tokens.RESET)
    db.commit()
    audit.record(db, request, "auth.password_changed", user_id=user.id, organization_id=user.organization_id)
    mail.send_password_changed(user.email)
    token = auth.create_access_token(user.id, user.organization_id, user.token_version)
    return {
        "access_token": token, "token_type": "bearer",
        "organization_id": user.organization_id, "user_id": user.id,
    }
