"""Optional Sentry integration: off by default, and nothing sensitive can leave the server."""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from app import observability  # noqa: E402


def test_does_nothing_without_a_dsn(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    assert observability.init_observability() is False


def test_events_are_scrubbed_of_credentials_and_bodies():
    event = {
        "request": {"url": "https://api/x", "data": {"password": "hunter2"}, "cookies": {"a": "b"}, "query_string": "token=abc",
                    "headers": {"Authorization": "Bearer secret", "Cookie": "s=1", "User-Agent": "UA", "X-Api-Key": "k"}},
        "user": {"email": "a@b.com", "ip_address": "1.2.3.4"},
        "breadcrumbs": {"values": [{"message": "m", "data": {"sql": "select ..."}}]},
        "exception": {"values": [{"type": "ValueError"}]},
    }
    out = observability.scrub_event(event)
    assert "data" not in out["request"] and "cookies" not in out["request"] and "query_string" not in out["request"]
    assert out["request"]["headers"]["Authorization"] == "[removed]" and out["request"]["headers"]["Cookie"] == "[removed]"
    assert out["request"]["headers"]["X-Api-Key"] == "[removed]" and out["request"]["headers"]["User-Agent"] == "UA"
    assert "user" not in out and "data" not in out["breadcrumbs"]["values"][0]
    assert out["exception"]["values"][0]["type"] == "ValueError"           # the useful part survives


def test_missing_sdk_is_reported_not_fatal(monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://key@example.ingest.sentry.io/1")
    monkeypatch.setitem(sys.modules, "sentry_sdk", None)                   # makes `import sentry_sdk` fail
    assert observability.init_observability() is False
