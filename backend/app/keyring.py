"""Fernet key handling with rotation support.

Set the env var to one key, or a comma-separated list: the FIRST key encrypts,
every key can decrypt. Rotate by prepending a new key, then (after re-encrypting
or letting old data expire) removing the old one.
"""
import os

from cryptography.fernet import Fernet, MultiFernet


def parse_keys(raw: str | None) -> list[str]:
    return [k.strip() for k in (raw or "").split(",") if k.strip()]


def build_fernet(env_name: str) -> MultiFernet:
    keys = parse_keys(os.environ.get(env_name))
    if not keys:
        if os.environ.get("ENVIRONMENT", "development").lower() == "production":
            raise RuntimeError(f"{env_name} is required in production")
        # Development only: ephemeral key, data does not survive a restart.
        keys = [Fernet.generate_key().decode()]
    try:
        return MultiFernet([Fernet(k.encode()) for k in keys])
    except Exception as exc:
        raise RuntimeError(f"{env_name} contains an invalid Fernet key") from exc
