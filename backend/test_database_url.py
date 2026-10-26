"""DATABASE_URL handling for managed Postgres (Neon) and poolers."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from app.database import normalize_database_url as norm  # noqa: E402


def test_neon_url_is_converted_and_keeps_ssl():
    url, extra = norm("postgresql://user:p%40ss@ep-cool-123.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require")
    assert url.startswith("postgresql+psycopg://user:p%40ss@ep-cool-123.eu-central-1.aws.neon.tech/neondb?")
    assert "sslmode=require" in url and "channel_binding=require" in url
    assert extra["connect_timeout"] == 15 and "prepare_threshold" not in extra


def test_neon_without_sslmode_gets_it():
    url, _ = norm("postgres://u:p@ep-x.us-east-2.aws.neon.tech/db")
    assert url.startswith("postgresql+psycopg://") and "sslmode=require" in url


def test_pooled_neon_host_disables_prepared_statements():
    _, extra = norm("postgresql://u:p@ep-x-pooler.us-east-2.aws.neon.tech/db?sslmode=require")
    assert extra["prepare_threshold"] is None


def test_pooler_can_be_forced_for_other_providers(monkeypatch):
    monkeypatch.setenv("DB_POOLER", "transaction")
    assert norm("postgresql://u:p@db.example.com:6543/postgres")[1]["prepare_threshold"] is None


def test_local_and_compose_hosts_are_left_alone():
    url, extra = norm("postgresql+psycopg://aisafety:pw@db:5432/ai_safety_checkup")
    assert url == "postgresql+psycopg://aisafety:pw@db:5432/ai_safety_checkup" and "prepare_threshold" not in extra
    assert "sslmode" not in norm("postgresql://u:p@localhost/db")[0]


def test_sqlite_and_empty_defaults():
    assert norm("") == ("sqlite:///./ai_safety_checkup.db", {"check_same_thread": False})
    assert norm("sqlite:///x.db")[0] == "sqlite:///x.db"
