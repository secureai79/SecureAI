"""Optional error monitoring (Sentry). Does nothing unless SENTRY_DSN is set.

Privacy: no personal data is sent (send_default_pii=False) and request headers/cookies/bodies are removed
before an event leaves the server, so tokens, passwords and source code never reach the monitoring service.
"""
import logging
import os

log = logging.getLogger("aisafety")

_SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "x-api-key", "password", "new_password", "current_password",
                   "token", "access_token", "mfa_token", "code", "secret"}


def scrub_event(event: dict, hint=None) -> dict:
    """Remove anything that could carry credentials or customer code from an outgoing Sentry event."""
    req = event.get("request")
    if isinstance(req, dict):
        req.pop("data", None)
        req.pop("cookies", None)
        req.pop("query_string", None)
        headers = req.get("headers")
        if isinstance(headers, dict):
            req["headers"] = {k: ("[removed]" if k.lower() in _SENSITIVE_KEYS else v) for k, v in headers.items()}
    event.pop("user", None)
    for crumb in (event.get("breadcrumbs") or {}).get("values", []) if isinstance(event.get("breadcrumbs"), dict) else []:
        if isinstance(crumb, dict):
            crumb.pop("data", None)
    return event


def init_observability() -> bool:
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        import sentry_sdk
    except ImportError:
        log.warning("SENTRY_DSN is set but sentry-sdk is not installed (pip install -r requirements.txt)")
        return False
    sentry_sdk.init(
        dsn=dsn,
        environment=os.environ.get("ENVIRONMENT", "development"),
        release=os.environ.get("RELEASE", None),
        traces_sample_rate=float(os.environ.get("SENTRY_TRACES_SAMPLE_RATE", "0") or 0),
        send_default_pii=False,
        before_send=scrub_event,
    )
    log.info("Sentry error monitoring enabled")
    return True
