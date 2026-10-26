"""Dependency-free rate limiter for a single API process.

Hardening over the first version:
* the scan limit is keyed on the *normalised* route (``/repositories/{id}/scan``)
  so creating many repositories no longer multiplies the allowance;
* when the caller presents a valid access token the bucket is per user, not per IP;
* the client IP honours ``X-Forwarded-For`` only when ``TRUSTED_PROXY_COUNT`` is set,
  so users behind a reverse proxy are not all lumped into one bucket;
* idle buckets are pruned so memory cannot grow without bound.

For multi-instance deployments also enforce an equivalent limit at the WAF/API
gateway or back this with Redis.
"""
import collections
import os
import re
import threading
import time

from fastapi import Request
from fastapi.responses import JSONResponse

_LOCK = threading.Lock()
_BUCKETS: dict[str, collections.deque[float]] = {}
_MAX_BUCKETS = 20_000
_SCAN_PATH = re.compile(r"^/repositories/[^/]+/scan$")

RULES = {
    "/auth/login": (10, 60),
    "/auth/signup": (5, 300),
    "/auth/forgot-password": (5, 900),
    "/auth/reset-password": (10, 900),
    "/auth/verify-email": (20, 900),
    "/auth/resend-verification": (6, 900),
    "/auth/change-password": (10, 900),
    "/auth/login/2fa": (10, 300),
    "/support/requests": (5, 900),
    "/team/invitations": (20, 900),
    "/team/invitations/preview": (20, 900),
    "/team/invitations/accept": (10, 900),
    "/team/invitations/accept-existing": (10, 900),
    "/team/workspaces/switch": (30, 900),
    "/auth/2fa/setup": (10, 900),
    "/auth/2fa/enable": (10, 900),
    "/auth/2fa/disable": (10, 900),
    "/auth/2fa/recovery-codes": (10, 900),
    "/repositories": (30, 60),
    "/repositories/{id}/scan": (10, 60),
}


def _enabled() -> bool:
    return os.environ.get("RATE_LIMIT_ENABLED", "true").lower() in {"1", "true", "yes", "on"}


def normalize_path(path: str) -> str:
    if _SCAN_PATH.match(path):
        return "/repositories/{id}/scan"
    return path


def client_ip(request: Request) -> str:
    """Best-effort client address. Trust X-Forwarded-For only behind N known proxies."""
    try:
        proxies = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
    except ValueError:
        proxies = 0
    if proxies > 0:
        hops = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        if len(hops) >= proxies:
            return hops[-proxies]
    return request.client.host if request.client else "unknown"


def _identity(request: Request) -> str:
    """Per-user bucket when a valid bearer token is present, otherwise per-IP."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        try:
            import jwt
            from . import auth
            payload = jwt.decode(header[7:], auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
            if payload.get("sub"):
                return f"user:{payload['sub']}"
        except Exception:
            pass
    return f"ip:{client_ip(request)}"


def _prune(now: float) -> None:
    for key in [k for k, q in _BUCKETS.items() if not q or q[-1] < now - 3600]:
        _BUCKETS.pop(key, None)


def reset_rate_limits() -> None:
    with _LOCK:
        _BUCKETS.clear()


def check_rate_limit(request: Request):
    if not _enabled() or request.method not in {"POST", "PATCH", "DELETE"}:
        return None
    route = normalize_path(request.url.path)
    rule = RULES.get(route)
    if not rule:
        return None
    limit, window = rule
    # Auth endpoints are limited per IP (the caller has no token yet).
    who = f"ip:{client_ip(request)}" if route.startswith("/auth/") else _identity(request)
    key = f"{who}:{route}"
    now = time.monotonic()
    with _LOCK:
        if len(_BUCKETS) > _MAX_BUCKETS:
            _prune(now)
        q = _BUCKETS.setdefault(key, collections.deque())
        cutoff = now - window
        while q and q[0] <= cutoff:
            q.popleft()
        if len(q) >= limit:
            retry = max(1, int(window - (now - q[0])))
            return JSONResponse(
                {"detail": "Too many requests. Please try again later."},
                status_code=429,
                headers={"Retry-After": str(retry)},
            )
        q.append(now)
    return None
