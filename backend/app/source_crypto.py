"""Application-level encryption for optional stored source evidence."""
import os
from cryptography.fernet import Fernet, InvalidToken

from .keyring import build_fernet

_fernet = build_fernet("SOURCE_EVIDENCE_ENCRYPTION_KEY")


def encrypt(value: str | None) -> str | None:
    if value is None:
        return None
    return _fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return _fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        # Existing plaintext rows from pre-hardening versions are treated as
        # unavailable rather than returned accidentally.
        return None
