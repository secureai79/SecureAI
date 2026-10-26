"""Encryption of small secrets at rest (currently: two-factor TOTP seeds).

Key selection (first match wins; comma-separated lists are accepted, the FIRST key encrypts and every
key can decrypt, which allows rotation):
  1. MFA_ENCRYPTION_KEY
  2. GITHUB_TOKEN_ENCRYPTION_KEY
  3. a key derived from JWT_SECRET (so development works with no extra configuration)
"""
import base64
import hashlib
import hmac
import os

from cryptography.fernet import Fernet, InvalidToken, MultiFernet


def _derived_key() -> bytes:
    secret = os.environ.get("JWT_SECRET") or os.environ.get("SECRET_KEY") or "dev-only-insecure-secret"
    digest = hmac.new(secret.encode("utf-8"), b"secureai/at-rest/v1", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest)


def _fernet() -> MultiFernet:
    raw = os.environ.get("MFA_ENCRYPTION_KEY", "").strip() or os.environ.get("GITHUB_TOKEN_ENCRYPTION_KEY", "").strip()
    keys = [k.strip().encode() for k in raw.split(",") if k.strip()] or [_derived_key()]
    return MultiFernet([Fernet(k) for k in keys])


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str) -> str | None:
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
