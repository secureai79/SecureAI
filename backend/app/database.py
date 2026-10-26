import datetime as dt
import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

def normalize_database_url(raw: str) -> tuple[str, dict]:
    """Turn whatever the host gives us into (SQLAlchemy URL, extra psycopg connect args).

    * ``postgres://`` and ``postgresql://`` (what Neon, Render, Heroku... hand out) become ``postgresql+psycopg://``.
    * Neon hosts always get ``sslmode=require`` (Neon refuses unencrypted connections anyway).
    * Connection poolers (Neon ``-pooler`` hosts, or DB_POOLER=transaction) run in transaction mode and
      do not support server-side prepared statements, so those are switched off.
    * A cold database (Neon scales to zero) can take a few seconds to wake: allow a longer connect timeout.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    url = (raw or "").strip()
    if not url:
        return "sqlite:///./ai_safety_checkup.db", {"check_same_thread": False}
    if url.startswith("sqlite"):
        return url, {"check_same_thread": False}
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            url = "postgresql+psycopg://" + url[len(prefix):]
            break
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    extra: dict = {"connect_timeout": int(os.environ.get("DB_CONNECT_TIMEOUT_SECONDS", "15") or 15)}
    if host.endswith(".neon.tech") and "sslmode" not in query:
        query["sslmode"] = "require"
    pooled = "-pooler" in host or os.environ.get("DB_POOLER", "").strip().lower() in {"transaction", "pgbouncer", "1", "true"}
    if pooled:
        extra["prepare_threshold"] = None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)), extra


DATABASE_URL, connect_args = normalize_database_url(os.environ.get("DATABASE_URL", ""))

_engine_kwargs: dict = {"connect_args": connect_args, "pool_pre_ping": True}
if not DATABASE_URL.startswith("sqlite"):
    # Managed Postgres closes idle connections (Neon after ~5 minutes): recycle before that, and test on checkout.
    _engine_kwargs.update(
        pool_recycle=int(os.environ.get("DB_POOL_RECYCLE_SECONDS", "240") or 240),
        pool_size=int(os.environ.get("DB_POOL_SIZE", "5") or 5),
        max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "5") or 5),
    )

engine = create_engine(DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _ensure_legacy_columns():
    """Apply safe, additive migrations to existing databases.

    New installations use create_all(). Existing databases receive missing
    columns without deleting tables, rows, scans, or findings.
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    # Existing authentication migration.
    if "users" in tables:
        cols = {
            column["name"]
            for column in inspector.get_columns("users")
        }

        if "token_version" not in cols:
            with engine.begin() as conn:
                if DATABASE_URL.startswith("sqlite"):
                    conn.execute(
                        text(
                            "ALTER TABLE users "
                            "ADD COLUMN token_version "
                            "INTEGER NOT NULL DEFAULT 0"
                        )
                    )
                else:
                    conn.execute(
                        text(
                            "ALTER TABLE users "
                            "ADD COLUMN IF NOT EXISTS token_version "
                            "INTEGER NOT NULL DEFAULT 0"
                        )
                    )

    # Account-lockout migration.
    if "users" in tables:
        ucols = {c["name"] for c in inspector.get_columns("users")}
        with engine.begin() as conn:
            if "failed_login_count" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0"))
            if "locked_until" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"))
            # E-mail verification migration (existing users stay unverified until they confirm).
            if "email_verified_at" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP"))
            # Two-factor authentication migration.
            if "totp_secret_enc" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret_enc TEXT"))
            if "totp_enabled_at" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_enabled_at TIMESTAMP"))
            if "totp_last_step" not in ucols:
                conn.execute(text("ALTER TABLE users ADD COLUMN totp_last_step INTEGER DEFAULT 0"))

    # Plans (future subscriptions) and scan-coverage migration.
    if "organizations" in tables:
        ocols = {c["name"] for c in inspector.get_columns("organizations")}
        if "plan" not in ocols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE organizations ADD COLUMN plan VARCHAR DEFAULT 'pilot'"))
    if "scans" in tables:
        scols = {c["name"] for c in inspector.get_columns("scans")}
        if "coverage" not in scols:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE scans ADD COLUMN coverage TEXT"))

    # Consequence-analysis metadata migration.
    if "findings" in tables:
        cols = {
            column["name"]
            for column in inspector.get_columns("findings")
        }

        missing = {
            "consequence",
            "impact_level",
            "control_status",
        } - cols

        if missing:
            with engine.begin() as conn:
                for column_name in sorted(missing):
                    if DATABASE_URL.startswith("sqlite"):
                        conn.execute(
                            text(
                                f"ALTER TABLE findings "
                                f"ADD COLUMN {column_name} VARCHAR"
                            )
                        )
                    else:
                        conn.execute(
                            text(
                                f"ALTER TABLE findings "
                                f"ADD COLUMN IF NOT EXISTS "
                                f"{column_name} VARCHAR"
                            )
                        )
            # GitHub App installation ownership validation.
    if "oauth_states" in tables:
        cols = {
            column["name"]
            for column in inspector.get_columns("oauth_states")
        }

        if "github_account_login" not in cols:
            with engine.begin() as conn:
                if DATABASE_URL.startswith("sqlite"):
                    conn.execute(
                        text(
                            "ALTER TABLE oauth_states "
                            "ADD COLUMN github_account_login VARCHAR"
                        )
                    )
                else:
                    conn.execute(
                        text(
                            "ALTER TABLE oauth_states "
                            "ADD COLUMN IF NOT EXISTS "
                            "github_account_login VARCHAR"
                        )
                    )

def cleanup_expired_scan_data(db=None) -> int:
    """Delete scan results older than SCAN_RETENTION_DAYS."""
    from . import models
    from .privacy import retention_days

    owns = db is None
    session = db or SessionLocal()

    try:
        cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(
            days=retention_days()
        )

        old = (
            session.query(models.Scan)
            .filter(
                models.Scan.finished_at.isnot(None),
                models.Scan.finished_at < cutoff,
            )
            .all()
        )

        count = len(old)

        for scan in old:
            session.delete(scan)

        session.commit()
        return count

    finally:
        if owns:
            session.close()


def _scrub_legacy_plaintext_snippets():
    """Encrypt legacy snippets only when enabled; otherwise erase them."""
    from . import models
    from .privacy import store_source_snippets
    from .source_crypto import encrypt

    session = SessionLocal()

    try:
        rows = session.query(models.Finding).all()
        changed = False

        for finding in rows:
            raw = finding._snippet_ciphertext

            if raw and not raw.startswith("gAAAA"):
                finding._snippet_ciphertext = (
                    encrypt(raw)
                    if store_source_snippets()
                    else None
                )
                changed = True

        if changed:
            session.commit()

    finally:
        session.close()


def _relax_orphan_columns(models_module) -> list[str]:
    """Let INSERTs succeed on databases that carry columns this version of the models does not map.

    Older schemas (or manual experiments) can leave a NOT NULL column with no default, for example
    ``users.mfa_enabled``. The application never writes it, so every new row is rejected by the database.
    Making such a column nullable is non-destructive: no data is dropped or changed. PostgreSQL only
    (SQLite cannot alter a column and is used for tests and local development with fresh files).
    Returns the "table.column" names that were relaxed.
    """
    if engine.dialect.name != "postgresql":
        return []
    relaxed: list[str] = []
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    for table in models_module.Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        mapped = {c.name for c in table.columns}
        for col in inspector.get_columns(table.name):
            if col["name"] in mapped or col.get("nullable", True):
                continue
            if col.get("default") is not None or col.get("autoincrement") or col.get("identity"):
                continue
            with engine.begin() as conn:
                conn.execute(text(f'ALTER TABLE "{table.name}" ALTER COLUMN "{col["name"]}" DROP NOT NULL'))
            relaxed.append(f"{table.name}.{col['name']}")
    if relaxed:
        import logging
        logging.getLogger("aisafety").warning(
            "Relaxed NOT NULL on legacy column(s) the application does not use: %s", ", ".join(relaxed))
    return relaxed


def init_db():
    from . import models

    models.Base.metadata.create_all(bind=engine)
    _ensure_legacy_columns()
    try:
        from . import workspaces
        with SessionLocal() as _db:
            workspaces.backfill(_db)
    except Exception:
        import logging
        logging.getLogger("aisafety").exception("Could not backfill workspace memberships")
    try:
        _relax_orphan_columns(models)
    except Exception:  # never block start-up; an unrelaxed column only affects inserts into that table
        import logging
        logging.getLogger("aisafety").exception("Could not relax legacy NOT NULL columns")

    try:
        _scrub_legacy_plaintext_snippets()
    except Exception:
        pass

    # Retention is best-effort. A scan should not fail because cleanup
    # encounters a transient database problem.
    try:
        cleanup_expired_scan_data()
    except Exception:
        pass