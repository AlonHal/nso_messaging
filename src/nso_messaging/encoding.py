"""Shared encodings used by local state and JSON protocol payloads."""

import base64


def encode_bytes(value: bytes) -> str:
    """Encode bytes as ASCII base64 for JSON-safe storage and transport."""
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value: str) -> bytes:
    """Decode an ASCII base64 value produced by :func:`encode_bytes`."""
    return base64.b64decode(value)
