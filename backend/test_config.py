import pytest


def test_production_rejects_missing_security_secrets(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    from app.config import validate_startup_config
    with pytest.raises(RuntimeError):
        validate_startup_config()


def test_production_rejects_wildcard_cors(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "x" * 64)
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db/x")
    from app.config import validate_startup_config
    with pytest.raises(RuntimeError):
        validate_startup_config()


def test_production_rejects_external_llm_without_ack(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "x" * 64)
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@db/x")
    monkeypatch.setenv("ENABLE_EXTERNAL_LLM_REFINEMENT", "true")
    monkeypatch.delenv("EXTERNAL_LLM_PRIVACY_ACK", raising=False)
    from app.config import validate_startup_config
    with pytest.raises(RuntimeError):
        validate_startup_config()
