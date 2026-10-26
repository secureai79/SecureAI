import datetime as dt
import hashlib
import hmac
import os
import secrets

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from . import models
from .database import get_db

_env_secret = os.environ.get("JWT_SECRET")
if _env_secret:
    SECRET_KEY = _env_secret
else:
    # Development-only fallback. Production startup validation rejects this
    # situation so an instance restart cannot silently invalidate customers.
    SECRET_KEY = secrets.token_hex(32)

ALGORITHM = "HS256"
EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "60"))
PBKDF2_ITERATIONS = 600_000  # OWASP guidance for PBKDF2-HMAC-SHA256
LOCKOUT_THRESHOLD = int(os.environ.get("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOCKOUT_MINUTES = int(os.environ.get("LOGIN_LOCKOUT_MINUTES", "15"))
_COMMON_PASSWORDS = {
    "password1234", "123456789012", "qwertyuiop12", "iloveyou1234", "administrator",
    "passwordpassword", "letmein123456", "welcome12345", "changeme1234",
}
bearer_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        scheme, iterations, salt, hash_hex = hashed.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return int(hashed.split("$")[1]) < PBKDF2_ITERATIONS
    except (IndexError, ValueError):
        return True


# Verified against when the account does not exist, so response time does not
# reveal whether an email is registered.
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def burn_password_check(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def is_locked(user: models.User) -> bool:
    until = user.locked_until
    if until is None:
        return False
    if until.tzinfo is None:
        until = until.replace(tzinfo=dt.UTC)
    return until > dt.datetime.now(dt.UTC)


def register_failed_login(user: models.User) -> None:
    user.failed_login_count = int(user.failed_login_count or 0) + 1
    if user.failed_login_count >= LOCKOUT_THRESHOLD:
        user.locked_until = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_count = 0


def register_successful_login(user: models.User) -> None:
    user.failed_login_count = 0
    user.locked_until = None


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_password(password: str) -> None:
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    if len(password) > 256:
        raise ValueError("Password must be at most 256 characters long")
    if password.lower() in _COMMON_PASSWORDS or len(set(password)) < 5:
        raise ValueError("Password is too easy to guess; choose a longer, less common one")


def create_access_token(user_id: str, organization_id: str, token_version: int = 0) -> str:
    now = dt.datetime.now(dt.UTC)
    payload = {
        "sub": user_id,
        "org": organization_id,
        "ver": token_version,
        "iat": now,
        "exp": now + dt.timedelta(minutes=EXPIRE_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM], options={"require": ["sub", "exp", "iat"]})
        user_id = payload.get("sub")
        token_version = int(payload.get("ver", 0))
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None or user.token_version != token_version:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return user


def revoke_all_tokens(user: models.User) -> None:
    user.token_version = int(user.token_version or 0) + 1


VERIFY_MESSAGE = "Please verify your email address to continue."


def require_verified_user(user: models.User = Depends(get_current_user)) -> models.User:
    """Like get_current_user, but refuses unverified accounts when verification is required."""
    from .email_service import verification_required
    if verification_required() and not user.email_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=VERIFY_MESSAGE)
    return user


ADMIN_ROLES = {"owner", "admin"}
ADMIN_MESSAGE = "Only workspace owners and admins can do this."


def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=ADMIN_MESSAGE)
    return user


def require_verified_admin(user: models.User = Depends(require_verified_user)) -> models.User:
    if user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=ADMIN_MESSAGE)
    return user
