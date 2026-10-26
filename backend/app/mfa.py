"""Time-based one-time passwords (RFC 6238) and recovery codes, with no extra dependencies.

Security properties
* 160-bit random seed, stored encrypted (app/crypto.py).
* +/-1 time-step tolerance (30 s) for clock drift; a code can be used only once (last accepted step is
  recorded and must strictly increase), which stops replay of a shoulder-surfed or phished code.
* Constant-time comparison everywhere.
* The sign-in "challenge" token is signed with a key derived from (but different to) the access-token
  key and carries purpose="mfa", so it can never be presented as an access token.
* Recovery codes: 80 bits, shown once, stored only as SHA-256 digests, single use.
"""
import base64
import datetime as dt
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

import jwt

from . import auth

DIGITS = 6
PERIOD = 30
WINDOW = 1                      # accept one step either side of "now"
CHALLENGE_MINUTES = 5
RECOVERY_CODE_COUNT = 10


# ------------------------------------------------------------------ TOTP
def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _code_at(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(value).zfill(DIGITS)


def clean_code(code: str) -> str:
    return "".join(ch for ch in (code or "") if not ch.isspace() and ch != "-")


def match_step(secret_b32: str, code: str, now: float | None = None) -> int | None:
    """Return the time-step the code belongs to, or None. Does not check replay."""
    code = clean_code(code)
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int((time.time() if now is None else now) // PERIOD)
    found = None
    for step in range(current - WINDOW, current + WINDOW + 1):     # no early exit: constant work
        if hmac.compare_digest(_code_at(secret_b32, step), code):
            found = step
    return found


def otpauth_uri(email: str, secret_b32: str, issuer: str) -> str:
    label = quote(f"{issuer}:{email}", safe="")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def qr_data_uri(uri: str) -> str | None:
    """QR code as an SVG data URI, or None if the QR library is unavailable.

    Setup still works without it: the page falls back to showing the secret key for manual entry.
    """
    try:
        import segno
    except ImportError:
        import logging
        logging.getLogger("aisafety").warning("segno is not installed: 2FA setup shows the key without a QR code. "
                                              "Run: pip install -r requirements.txt")
        return None
    return segno.make(uri, error="m").svg_data_uri(scale=6, border=2, dark="#111111", light="#ffffff")


# ------------------------------------------------------------------ recovery codes
def _norm_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "") if ch.isalnum()).upper()


def recovery_hash(code: str) -> str:
    return hashlib.sha256(_norm_recovery(code).encode("utf-8")).hexdigest()


def looks_like_recovery(code: str) -> bool:
    n = _norm_recovery(code)
    return len(n) == 16 and not n.isdigit()


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    out = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(10)).decode("ascii")     # 16 chars, 80 bits
        out.append("-".join(raw[i:i + 4] for i in range(0, 16, 4)))
    return out


# ------------------------------------------------------------------ sign-in challenge
def _challenge_key() -> str:
    return hmac.new(auth.SECRET_KEY.encode("utf-8"), b"secureai/mfa-challenge/v1", hashlib.sha256).hexdigest()


def create_challenge(user) -> str:
    now = dt.datetime.now(dt.UTC)
    return jwt.encode(
        {"sub": user.id, "tv": user.token_version, "pur": "mfa", "iat": now,
         "exp": now + dt.timedelta(minutes=CHALLENGE_MINUTES)},
        _challenge_key(), algorithm=auth.ALGORITHM,
    )


def read_challenge(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, _challenge_key(), algorithms=[auth.ALGORITHM])
    except Exception:
        return None
    return payload if payload.get("pur") == "mfa" and payload.get("sub") else None
