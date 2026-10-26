import os


def is_production() -> bool:
    return os.environ.get("ENVIRONMENT", "development").lower() == "production"


def validate_startup_config() -> None:
    if not is_production():
        return

    jwt_secret = os.environ.get("JWT_SECRET", "")
    if len(jwt_secret.encode()) < 32:
        raise RuntimeError("Production requires JWT_SECRET of at least 32 bytes")

    enc = os.environ.get("GITHUB_TOKEN_ENCRYPTION_KEY", "")
    source_key = os.environ.get("SOURCE_EVIDENCE_ENCRYPTION_KEY", "")
    store_snippets = os.environ.get("STORE_SOURCE_SNIPPETS", "false").lower() in {
        "1", "true", "yes", "on"
    }

    if store_snippets and not source_key:
        raise RuntimeError(
            "STORE_SOURCE_SNIPPETS=true requires SOURCE_EVIDENCE_ENCRYPTION_KEY"
        )

    # Any GitHub setting (App or legacy OAuth) means credentials get stored,
    # so a stable encryption key is mandatory. Without one the server would
    # silently use a random per-process key and lose every integration on restart.
    github_configured = any(
        os.environ.get(name, "").strip()
        for name in (
            "GITHUB_CLIENT_ID", "GITHUB_APP_ID", "GITHUB_APP_SLUG",
            "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_PRIVATE_KEY_FILE",
        )
    )
    if github_configured and not enc:
        raise RuntimeError(
            "Production GitHub integration requires GITHUB_TOKEN_ENCRYPTION_KEY"
        )

    from cryptography.fernet import Fernet
    from .keyring import parse_keys

    for env_name in ("GITHUB_TOKEN_ENCRYPTION_KEY", "SOURCE_EVIDENCE_ENCRYPTION_KEY", "MFA_ENCRYPTION_KEY"):
        for key in parse_keys(os.environ.get(env_name)):
            try:
                Fernet(key.encode())
            except Exception:
                raise RuntimeError(f"{env_name} contains an invalid Fernet key")

    if os.environ.get("JWT_SECRET", "") in {
        "replace-with-a-long-random-secret", "changeme", "secret",
    }:
        raise RuntimeError("JWT_SECRET is still a placeholder value")

    # GitHub App configuration is optional. If it is configured, validate it.
    app_id = os.environ.get("GITHUB_APP_ID", "").strip()
    app_slug = os.environ.get("GITHUB_APP_SLUG", "").strip()
    app_private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()

    if not app_private_key:
        private_key_file = os.environ.get(
            "GITHUB_APP_PRIVATE_KEY_FILE", ""
        ).strip()

        if private_key_file:
            try:
                with open(private_key_file, encoding="utf-8") as fh:
                    app_private_key = fh.read().strip()
            except FileNotFoundError:
                # A missing key file is acceptable when GitHub App
                # integration has not been configured.
                app_private_key = ""

    app_configured = bool(app_id and app_slug and app_private_key)

    # If any GitHub App setting is supplied, require all of them.
    any_app_setting = bool(
        app_id
        or app_slug
        or os.environ.get("GITHUB_APP_PRIVATE_KEY", "").strip()
        or os.environ.get("GITHUB_APP_PRIVATE_KEY_FILE", "").strip()
    )

    if any_app_setting and not app_configured:
        raise RuntimeError(
            "GitHub App configuration is incomplete; provide "
            "GITHUB_APP_ID, GITHUB_APP_SLUG, and a valid private key"
        )

    # If the legacy GitHub OAuth client is configured, production must
    # also have a complete GitHub App configuration.
    if os.environ.get("GITHUB_CLIENT_ID") and not app_configured:
        raise RuntimeError(
            "Production GitHub integration requires a GitHub App "
            "(not the broad OAuth App flow)"
        )

    origins = [
        x.strip()
        for x in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
        if x.strip()
    ]

    if not origins or "*" in origins:
        raise RuntimeError(
            "Production requires explicit CORS_ALLOWED_ORIGINS; "
            "wildcard is not allowed"
        )

    if os.environ.get("DATABASE_URL", "").startswith("sqlite"):
        raise RuntimeError(
            "Production requires PostgreSQL or another managed server database"
        )

    if os.environ.get("ALLOW_LOCAL_REPOS", "false").lower() in {
        "1", "true", "yes", "on"
    }:
        raise RuntimeError("ALLOW_LOCAL_REPOS must be false in production")

    if (
        os.environ.get("ENABLE_EXTERNAL_LLM_REFINEMENT", "false").lower()
        in {"1", "true", "yes", "on"}
        and not os.environ.get("EXTERNAL_LLM_PRIVACY_ACK")
    ):
        raise RuntimeError(
            "External LLM refinement requires explicit "
            "EXTERNAL_LLM_PRIVACY_ACK=true"
        )

    _validate_email_config()
    _validate_frontend_url()


def _validate_email_config() -> None:
    from . import email_service as mail

    backend = mail.backend()
    if backend not in {"smtp", "disabled"}:
        raise RuntimeError(
            f"EMAIL_BACKEND={backend} is for development/tests only; "
            "production must use EMAIL_BACKEND=smtp (the console backend would write reset links to logs)"
        )
    if backend == "smtp":
        host = os.environ.get("SMTP_HOST", "").strip()
        sender = os.environ.get("EMAIL_FROM", "").strip()
        if not host or "@" not in sender:
            raise RuntimeError("EMAIL_BACKEND=smtp requires SMTP_HOST and EMAIL_FROM (e.g. 'SecureAI <no-reply@yourdomain>')")
        if os.environ.get("SMTP_SECURITY", "starttls").strip().lower() not in {"starttls", "ssl", "none"}:
            raise RuntimeError("SMTP_SECURITY must be one of: starttls, ssl, none")
        if os.environ.get("SMTP_USERNAME", "").strip() and not os.environ.get("SMTP_PASSWORD", ""):
            raise RuntimeError("SMTP_USERNAME is set but SMTP_PASSWORD is empty")
    if mail.verification_required() and backend != "smtp":
        raise RuntimeError(
            "REQUIRE_EMAIL_VERIFICATION is on but no e-mail delivery is configured; "
            "set EMAIL_BACKEND=smtp with SMTP_* values, or set REQUIRE_EMAIL_VERIFICATION=false"
        )


def _validate_frontend_url() -> None:
    from urllib.parse import urlparse

    url = os.environ.get("FRONTEND_URL", "").strip()
    if not url:
        return
    parsed = urlparse(url)
    local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("FRONTEND_URL must be an absolute http(s) URL")
    if parsed.scheme != "https" and not local:
        raise RuntimeError("FRONTEND_URL must use https in production (e-mailed links carry one-time tokens)")
