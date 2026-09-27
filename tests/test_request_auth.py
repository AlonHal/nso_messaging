"""Tests for canonical HMAC request signing and verification."""

import base64
import secrets

from nso_messaging.request_auth import sign_request, verify_request_signature


def test_request_signature_verifies_only_for_the_signed_request():
    """Bind the signature to the HTTP method, path, and exact body bytes."""
    auth_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    body = b'{"message":"payload"}'
    signature = sign_request(auth_key, "POST", "/messages", body)

    assert verify_request_signature(auth_key, "POST", "/messages", body, signature)
    assert not verify_request_signature(auth_key, "GET", "/messages", body, signature)
    assert not verify_request_signature(auth_key, "POST", "/messages/other", body, signature)
    assert not verify_request_signature(auth_key, "POST", "/messages", body + b" ", signature)


def test_invalid_auth_key_fails_signature_verification():
    """Treat malformed locally stored credentials as invalid, not exceptional."""
    assert not verify_request_signature("not-base64!", "GET", "/health", b"", "bad")
