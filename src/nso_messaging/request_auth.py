"""HMAC signing helpers for authenticated HTTP requests."""

import base64
import hashlib
import hmac


def _request_bytes(method: str, path: str, body: bytes) -> bytes:
    """Build the canonical bytes covered by a request signature."""
    return method.encode() + b"\n" + path.encode() + b"\n" + body


def sign_request(auth_key: str, method: str, path: str, body: bytes) -> str:
    """Sign the exact request method, path, and body with an encoded auth key."""
    secret = base64.urlsafe_b64decode(auth_key.encode())
    return hmac.new(
        secret,
        _request_bytes(method, path, body),
        hashlib.sha256,
    ).hexdigest()


def verify_request_signature(
    auth_key: str,
    method: str,
    path: str,
    body: bytes,
    signature: str,
) -> bool:
    """Verify a request signature, failing closed on malformed credentials."""
    try:
        expected_signature = sign_request(auth_key, method, path, body)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected_signature, signature)
