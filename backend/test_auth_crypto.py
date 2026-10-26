import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from app import auth


def test_hash_password_roundtrip():
    hashed = auth.hash_password("correct horse battery staple")
    assert hashed.startswith("pbkdf2_sha256$")
    assert auth.verify_password("correct horse battery staple", hashed) is True


def test_verify_password_rejects_wrong_password():
    hashed = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("wrong password", hashed) is False


def test_verify_password_handles_garbage_hash_gracefully():
    # Must not raise on malformed stored hashes (e.g. corrupted DB row).
    assert auth.verify_password("anything", "not-a-valid-hash") is False
    assert auth.verify_password("anything", "") is False


def test_two_hashes_of_same_password_differ():
    # Random salt per call -> no two hashes of the same password should match.
    h1 = auth.hash_password("same-password")
    h2 = auth.hash_password("same-password")
    assert h1 != h2
    assert auth.verify_password("same-password", h1)
    assert auth.verify_password("same-password", h2)


def test_github_token_encrypt_decrypt_roundtrip(monkeypatch):
    import app.routers.github_oauth as gh

    token = "gho_abcdef1234567890"
    encrypted = gh.encrypt_token(token)
    assert encrypted != token
    assert gh.decrypt_token(encrypted) == token


def test_github_token_encryption_uses_random_nonce():
    """Two encryptions of the same token must differ (random nonce), so
    identical tokens don't produce identical ciphertext in storage."""
    import app.routers.github_oauth as gh

    token = "gho_same_token_both_times"
    enc1 = gh.encrypt_token(token)
    enc2 = gh.encrypt_token(token)
    assert enc1 != enc2
    assert gh.decrypt_token(enc1) == token
    assert gh.decrypt_token(enc2) == token
