"""Transactional e-mail (verification, password reset, security notices).

Backends (``EMAIL_BACKEND``):
  smtp      deliver through ``SMTP_HOST`` (Brevo, Resend, SES, Postmark, ...). Production.
  console   write the message, links included, to the server log. Local development only.
  memory    keep messages in ``OUTBOX``. Used by the test-suite.
  disabled  send nothing. Default in production when nothing is configured.

Design notes
* Sending never blocks a request: messages are handed to a small worker pool, so a slow or
  broken mail provider cannot stall the API or leak (through response time) whether an
  address is registered.
* All settings are read at call time, so tests and operators can change them without a re-import.
* Header-injection safe: addresses and subjects containing CR/LF are rejected.
* Links and tokens are never logged by the ``smtp`` backend.
"""
from __future__ import annotations

import html
import logging
import os
import smtplib
import ssl
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

log = logging.getLogger("aisafety.email")

OUTBOX: list[dict] = []          # populated only by the "memory" backend
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mailer")
_TRUE = {"1", "true", "yes", "on"}


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in _TRUE


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default


def _is_production() -> bool:
    return os.environ.get("ENVIRONMENT", "development").lower() == "production"


def app_name() -> str:
    return (os.environ.get("APP_NAME", "").strip() or "SecureAI")[:60]


def backend() -> str:
    raw = os.environ.get("EMAIL_BACKEND", "").strip().lower()
    if raw:
        return raw
    return "disabled" if _is_production() else "console"


def is_configured() -> bool:
    """True when a message could actually reach a person's inbox."""
    b = backend()
    if b == "smtp":
        return bool(os.environ.get("SMTP_HOST", "").strip() and os.environ.get("EMAIL_FROM", "").strip())
    return b in {"console", "memory"}


def verification_required() -> bool:
    """Gate scanning behind a confirmed e-mail. On by default in production."""
    return env_bool("REQUIRE_EMAIL_VERIFICATION", _is_production())


def frontend_url() -> str:
    return (os.environ.get("FRONTEND_URL", "").strip() or "http://127.0.0.1:5500").rstrip("/")


def link(page: str, token: str) -> str:
    # The token travels in the URL fragment: browsers never send it to servers, proxies or logs.
    return f"{frontend_url()}/{page}#token={token}"


def _clean_header(value: str, what: str) -> str:
    if any(c in value for c in "\r\n\x00"):
        raise ValueError(f"Invalid {what}")
    return value.strip()


def _build(to: str, subject: str, text: str, html_body: str, reply_to: str | None = None) -> EmailMessage:
    to = _clean_header(to, "recipient")
    subject = _clean_header(subject, "subject")
    from_raw = _clean_header(os.environ.get("EMAIL_FROM", ""), "sender")
    name, addr = parseaddr(from_raw)
    if not addr or "@" not in addr:
        raise ValueError("EMAIL_FROM must look like 'Name <address@domain>'")
    if "@" not in parseaddr(to)[1]:
        raise ValueError("Invalid recipient")
    msg = EmailMessage()
    msg["From"] = formataddr((name, addr)) if name else addr
    msg["To"] = to
    msg["Subject"] = subject
    reply_to = (reply_to or os.environ.get("EMAIL_REPLY_TO", "")).strip()
    if reply_to:
        msg["Reply-To"] = _clean_header(reply_to, "reply-to")
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg


def _deliver_smtp(msg: EmailMessage) -> None:
    host = os.environ["SMTP_HOST"].strip()
    port = env_int("SMTP_PORT", 587)
    security = (os.environ.get("SMTP_SECURITY", "starttls").strip().lower() or "starttls")
    user = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "")
    timeout = env_int("SMTP_TIMEOUT_SECONDS", 15)
    ctx = ssl.create_default_context()
    if security == "ssl":
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
    try:
        server.ehlo()
        if security == "starttls":
            server.starttls(context=ctx)
            server.ehlo()
        elif security == "none" and _is_production() and host not in {"localhost", "127.0.0.1"}:
            raise RuntimeError("SMTP_SECURITY=none is not allowed for remote hosts in production")
        if user:
            server.login(user, password)
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except Exception:
            pass


def _send_now(to: str, subject: str, text: str, html_body: str, reply_to: str | None = None) -> bool:
    b = backend()
    try:
        if b == "memory":
            OUTBOX.append({"to": to, "subject": subject, "text": text, "html": html_body, "reply_to": reply_to})
            return True
        if b == "console":
            log.warning("[dev e-mail] to=%s subject=%s\n%s", to, subject, text)
            return True
        if b == "smtp":
            if not is_configured():
                log.error("EMAIL_BACKEND=smtp but SMTP_HOST / EMAIL_FROM are not set")
                return False
            _deliver_smtp(_build(to, subject, text, html_body, reply_to))
            log.info("e-mail sent: subject=%r", subject)
            return True
        log.warning("e-mail not sent: EMAIL_BACKEND=%s", b)
        return False
    except Exception as exc:  # never let mail problems break a request
        log.error("e-mail delivery failed (%s): %s", type(exc).__name__, exc)
        return False


def send(to: str, subject: str, text: str, html_body: str, reply_to: str | None = None) -> bool:
    """Queue a message. Returns True if it was accepted for delivery (not that it arrived)."""
    if not is_configured():
        log.warning("e-mail skipped: EMAIL_BACKEND=%s is not usable", backend())
        return False
    if backend() == "memory":                    # deterministic for tests
        return _send_now(to, subject, text, html_body, reply_to)
    _POOL.submit(_send_now, to, subject, text, html_body, reply_to)
    return True


# ------------------------------------------------------------------ templates
def _wrap(title: str, intro: str, button: str | None, url: str | None, footer: str) -> tuple[str, str]:
    name = html.escape(app_name())
    btn = ""
    if button and url:
        btn = (
            f'<p style="margin:26px 0"><a href="{html.escape(url, quote=True)}" '
            'style="background:#6c60e9;color:#ffffff;padding:13px 22px;border-radius:10px;'
            f'text-decoration:none;font-weight:700;display:inline-block">{html.escape(button)}</a></p>'
            f'<p style="color:#687083;font-size:12px;word-break:break-all">Or paste this link into your browser:<br>{html.escape(url)}</p>'
        )
    html_body = (
        '<div style="font-family:Inter,Segoe UI,Arial,sans-serif;max-width:520px;margin:0 auto;'
        'padding:28px;color:#171923;line-height:1.6">'
        f'<div style="font-weight:800;font-size:18px;margin-bottom:18px">{name}</div>'
        f'<h2 style="margin:0 0 12px;font-size:21px">{html.escape(title)}</h2>'
        f'<p style="margin:0">{html.escape(intro)}</p>{btn}'
        f'<p style="color:#687083;font-size:12px;margin-top:28px">{html.escape(footer)}</p></div>'
    )
    text = f"{title}\n\n{intro}\n" + (f"\n{url}\n" if url else "") + f"\n{footer}\n"
    return text, html_body


def send_verification(to: str, token: str) -> bool:
    hours = env_int("EMAIL_VERIFICATION_TTL_HOURS", 24)
    text, body = _wrap(
        "Confirm your email address",
        f"Welcome to {app_name()}. Confirm this address to connect repositories and run scans.",
        "Confirm email", link("verify-email.html", token),
        f"The link works once and expires in {hours} hours. If you did not create an account, ignore this message.",
    )
    return send(to, f"Confirm your email for {app_name()}", text, body)


def send_password_reset(to: str, token: str) -> bool:
    minutes = env_int("PASSWORD_RESET_TTL_MINUTES", 30)
    text, body = _wrap(
        "Reset your password",
        f"We received a request to reset the password for your {app_name()} account.",
        "Choose a new password", link("reset-password.html", token),
        f"The link works once and expires in {minutes} minutes. If you did not ask for this, ignore this "
        "message; your password will not change.",
    )
    return send(to, f"Reset your {app_name()} password", text, body)


def send_password_changed(to: str) -> bool:
    text, body = _wrap(
        "Your password was changed",
        f"The password for your {app_name()} account was just changed and all devices were signed out.",
        None, None,
        "If this was not you, reset your password immediately from the log-in page and contact support.",
    )
    return send(to, f"Your {app_name()} password was changed", text, body)


def send_two_factor_changed(to: str, enabled: bool) -> bool:
    state = "turned on" if enabled else "turned off"
    text, body = _wrap(
        f"Two-factor authentication {state}",
        f"Two-factor authentication was just {state} for your {app_name()} account and other devices were signed out.",
        None, None,
        "If this was not you, reset your password immediately and contact support.",
    )
    return send(to, f"Two-factor authentication {state} on {app_name()}", text, body)


def support_address() -> str:
    """Where help requests go: SUPPORT_EMAIL, else EMAIL_REPLY_TO, else the sender address itself."""
    for name in ("SUPPORT_EMAIL", "EMAIL_REPLY_TO"):
        value = os.environ.get(name, "").strip()
        if "@" in parseaddr(value)[1]:
            return parseaddr(value)[1]
    return parseaddr(os.environ.get("EMAIL_FROM", ""))[1]


def send_account_exists(to: str) -> bool:
    login = f"{frontend_url()}/login.html"
    reset = f"{frontend_url()}/forgot-password.html"
    text, body = _wrap(
        "You already have an account",
        f"Someone (hopefully you) tried to create a {app_name()} account with this email address, but one already exists. "
        f"Log in at {login}. If you forgot your password, reset it at {reset}.",
        "Log in", login,
        "If this was not you, you can ignore this message: nothing about your account has changed.",
    )
    return send(to, f"You already have a {app_name()} account", text, body)


def send_invitation(to: str, org_name: str, inviter: str, role: str, token: str) -> bool:
    days = env_int("INVITE_TTL_DAYS", 7)
    text, body = _wrap(
        f"Join {org_name} on {app_name()}",
        f"{inviter} invited you to the {org_name} workspace on {app_name()} as {'an admin' if role == 'admin' else 'a member'}. "
        "Accept the invitation to choose a password and get started.",
        "Accept invitation", link("accept-invite.html", token),
        f"The link works once and expires in {days} days. If you were not expecting this, ignore this message.",
    )
    return send(to, f"{inviter} invited you to {org_name} on {app_name()}", text, body)


def send_removed(to: str, org_name: str) -> bool:
    text, body = _wrap(
        "Your access was removed",
        f"You no longer have access to the {org_name} workspace on {app_name()}.",
        None, None, "If you think this is a mistake, contact the workspace owner.",
    )
    return send(to, f"Your access to {org_name} was removed", text, body)
