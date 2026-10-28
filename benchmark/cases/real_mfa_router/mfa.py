"""Two-factor authentication (TOTP + recovery codes)."""
import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_, update
from sqlalchemy.orm import Session

from .. import audit, auth, crypto, models, schemas
from .. import email_service as mail
from .. import mfa
from ..database import get_db

router = APIRouter(prefix="/auth", tags=["two-factor"])

BAD_CODE = "That code is not valid. Check your authenticator app and try again."


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _locked_response(user: models.User) -> HTTPException:
    return HTTPException(
        status_code=429, detail="Too many failed attempts. Try again later.",
        headers={"Retry-After": str(auth.LOCKOUT_MINUTES * 60)},
    )


def _check_password(db: Session, user: models.User, request: Request, password: str) -> None:
    """Re-authenticate before a security-sensitive change. Failures count toward the lockout."""
    if auth.is_locked(user):
        auth.burn_password_check(password)
        raise _locked_response(user)
    if not auth.verify_password(password, user.hashed_password):
        auth.register_failed_login(user)
        db.commit()
        audit.record(db, request, "auth.2fa_reauth_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=400, detail="Your password is incorrect.")


def _use_totp(db: Session, user: models.User, code: str) -> bool:
    """Validate a TOTP code and burn its time-step (replay protection). Atomic."""
    secret = crypto.decrypt_secret(user.totp_secret_enc or "")
    if not secret:
        return False
    step = mfa.match_step(secret, code)
    if step is None:
        return False
    won = db.execute(
        update(models.User)
        .where(models.User.id == user.id,
               or_(models.User.totp_last_step.is_(None), models.User.totp_last_step < step))
        .values(totp_last_step=step)
    ).rowcount
    db.commit()
    db.refresh(user)
    return won == 1


def _use_recovery(db: Session, user: models.User, code: str) -> bool:
    if not mfa.looks_like_recovery(code):
        return False
    won = db.execute(
        update(models.MfaRecoveryCode)
        .where(models.MfaRecoveryCode.user_id == user.id,
               models.MfaRecoveryCode.code_hash == mfa.recovery_hash(code),
               models.MfaRecoveryCode.used_at.is_(None))
        .values(used_at=_now())
    ).rowcount
    db.commit()
    return won == 1


def _issue_recovery_codes(db: Session, user: models.User) -> list[str]:
    db.query(models.MfaRecoveryCode).filter(models.MfaRecoveryCode.user_id == user.id).delete()
    codes = mfa.new_recovery_codes()
    for c in codes:
        db.add(models.MfaRecoveryCode(user_id=user.id, code_hash=mfa.recovery_hash(c)))
    db.commit()
    return codes


def _fresh_token(user: models.User) -> dict:
    return {
        "access_token": auth.create_access_token(user.id, user.organization_id, user.token_version),
        "token_type": "bearer", "organization_id": user.organization_id, "user_id": user.id,
    }


# ------------------------------------------------------------------ sign-in, step 2
@router.post("/login/2fa", response_model=schemas.TokenResponse)
def login_second_factor(body: schemas.Login2FARequest, request: Request, db: Session = Depends(get_db)):
    claims = mfa.read_challenge(body.mfa_token)
    user = db.query(models.User).filter(models.User.id == claims["sub"]).first() if claims else None
    if user is None or not user.mfa_enabled or claims.get("tv") != user.token_version:
        raise HTTPException(status_code=401, detail="This sign-in has expired. Please log in again.")
    if auth.is_locked(user):
        audit.record(db, request, "auth.login_blocked", user_id=user.id, organization_id=user.organization_id)
        raise _locked_response(user)
    used_recovery = False
    ok = _use_totp(db, user, body.code)
    if not ok:
        ok = used_recovery = _use_recovery(db, user, body.code)
    if not ok:
        auth.register_failed_login(user)
        db.commit()
        audit.record(db, request, "auth.2fa_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=401, detail=BAD_CODE)
    auth.register_successful_login(user)
    db.commit()
    audit.record(db, request, "auth.2fa_recovery_used" if used_recovery else "auth.login",
                 user_id=user.id, organization_id=user.organization_id)
    return schemas.TokenResponse(
        access_token=auth.create_access_token(user.id, user.organization_id, user.token_version),
        organization_id=user.organization_id, user_id=user.id,
    )


# ------------------------------------------------------------------ manage
@router.get("/2fa/status")
def two_factor_status(user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    remaining = db.query(models.MfaRecoveryCode).filter(
        models.MfaRecoveryCode.user_id == user.id, models.MfaRecoveryCode.used_at.is_(None)).count()
    return {
        "enabled": user.mfa_enabled,
        "pending_setup": bool(user.totp_secret_enc) and not user.mfa_enabled,
        "recovery_codes_remaining": remaining if user.mfa_enabled else 0,
    }


@router.post("/2fa/setup")
def two_factor_setup(body: schemas.TwoFactorPasswordRequest, request: Request,
                     user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    _check_password(db, user, request, body.password)
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is already turned on.")
    secret = mfa.generate_secret()
    user.totp_secret_enc = crypto.encrypt_secret(secret)       # pending until the first code is confirmed
    user.totp_enabled_at = None
    user.totp_last_step = 0
    db.commit()
    audit.record(db, request, "auth.2fa_setup_started", user_id=user.id, organization_id=user.organization_id)
    uri = mfa.otpauth_uri(user.email, secret, mail.app_name())
    return {"secret": secret, "otpauth_uri": uri, "qr": mfa.qr_data_uri(uri)}


@router.post("/2fa/enable")
def two_factor_enable(body: schemas.TwoFactorEnableRequest, request: Request,
                      user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is already turned on.")
    if not user.totp_secret_enc:
        raise HTTPException(status_code=400, detail="Start the setup first.")
    if auth.is_locked(user):
        raise _locked_response(user)
    if not _use_totp(db, user, body.code):
        auth.register_failed_login(user)
        db.commit()
        audit.record(db, request, "auth.2fa_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=400, detail=BAD_CODE)
    user.totp_enabled_at = _now()
    codes = _issue_recovery_codes(db, user)
    auth.revoke_all_tokens(user)                  # sign out every other device
    db.commit()
    audit.record(db, request, "auth.2fa_enabled", user_id=user.id, organization_id=user.organization_id)
    mail.send_two_factor_changed(user.email, True)
    return {**_fresh_token(user), "recovery_codes": codes}


def _reauth_with_code(db: Session, user: models.User, request: Request, body: schemas.TwoFactorConfirmRequest,
                      allow_recovery: bool) -> None:
    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is not turned on.")
    _check_password(db, user, request, body.password)
    ok = _use_totp(db, user, body.code) or (allow_recovery and _use_recovery(db, user, body.code))
    if not ok:
        auth.register_failed_login(user)
        db.commit()
        audit.record(db, request, "auth.2fa_failed", user_id=user.id, organization_id=user.organization_id)
        raise HTTPException(status_code=400, detail=BAD_CODE)


@router.post("/2fa/disable")
def two_factor_disable(body: schemas.TwoFactorConfirmRequest, request: Request,
                       user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    _reauth_with_code(db, user, request, body, allow_recovery=True)
    user.totp_secret_enc = None
    user.totp_enabled_at = None
    user.totp_last_step = 0
    db.query(models.MfaRecoveryCode).filter(models.MfaRecoveryCode.user_id == user.id).delete()
    auth.revoke_all_tokens(user)
    db.commit()
    audit.record(db, request, "auth.2fa_disabled", user_id=user.id, organization_id=user.organization_id)
    mail.send_two_factor_changed(user.email, False)
    return _fresh_token(user)


@router.post("/2fa/recovery-codes")
def two_factor_new_recovery_codes(body: schemas.TwoFactorConfirmRequest, request: Request,
                                  user: models.User = Depends(auth.get_current_user), db: Session = Depends(get_db)):
    _reauth_with_code(db, user, request, body, allow_recovery=False)
    codes = _issue_recovery_codes(db, user)
    audit.record(db, request, "auth.2fa_codes_regenerated", user_id=user.id, organization_id=user.organization_id)
    return {"recovery_codes": codes}
