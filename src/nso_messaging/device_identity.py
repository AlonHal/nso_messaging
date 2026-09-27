"""Device fingerprint derivation tying a device identity to its host.

The fingerprint mimics a locally administered MAC-style address: the first
12 bytes encode the account phone number's digits (one hex digit per byte,
truncated or zero-padded to 12 digits), followed by a ``0x0a`` separator and
3 random bytes for per-device uniqueness. Two devices registered under the
same phone number (a primary and a companion) share the phone-derived
prefix but each persist their own random suffix, so their fingerprints never
collide in normal use.
"""

import json
import secrets
from pathlib import Path

from .json_store import write_json_atomic

FINGERPRINT_SIZE = 16
_PHONE_DIGIT_BYTES = 12
_SEPARATOR_BYTE = 0x0A
_RANDOM_SUFFIX_SIZE = 3


def phone_digits_to_bytes(phone_number: str) -> bytes:
    """Encode the first 12 digits of a phone number as one byte per digit.

    Non-digit characters (such as a leading ``+``) are dropped first. Numbers
    with fewer than 12 digits are zero-padded on the right so the prefix
    always has a fixed, comparable length.
    """
    digits = "".join(character for character in phone_number if character.isdigit())
    digits = digits.ljust(_PHONE_DIGIT_BYTES, "0")[:_PHONE_DIGIT_BYTES]
    return bytes(int(digit) for digit in digits)


def generate_device_fingerprint(phone_number: str) -> bytes:
    """Derive a fresh 16-byte device fingerprint for this phone number.

    The random suffix is generated per call, so calling this twice for the
    same phone number yields two distinct device fingerprints.
    """
    prefix = phone_digits_to_bytes(phone_number)
    return prefix + bytes([_SEPARATOR_BYTE]) + secrets.token_bytes(_RANDOM_SUFFIX_SIZE)


def format_fingerprint(fingerprint: bytes) -> str:
    """Render a fingerprint as a dash-joined hex string, MAC-address style."""
    return "-".join(f"{byte:02x}" for byte in fingerprint)


def parse_fingerprint(formatted: str) -> bytes:
    """Parse a dash-joined hex string produced by :func:`format_fingerprint`."""
    return bytes.fromhex(formatted.replace("-", ""))


def validate_device_id(device_id: str, phone_number: str) -> bytes:
    """Parse a canonical device ID and ensure its account-derived prefix matches."""
    try:
        fingerprint = parse_fingerprint(device_id)
    except ValueError:
        raise ValueError("device_id must be a canonical device fingerprint") from None
    if (
        len(fingerprint) != FINGERPRINT_SIZE
        or format_fingerprint(fingerprint) != device_id
        or fingerprint[:_PHONE_DIGIT_BYTES] != phone_digits_to_bytes(phone_number)
        or fingerprint[_PHONE_DIGIT_BYTES] != _SEPARATOR_BYTE
    ):
        raise ValueError("device_id does not match the account")
    return fingerprint


def load_or_create_device_fingerprint(path: str | Path, phone_number: str) -> bytes:
    """Reuse a persisted device fingerprint, or generate and store a new one.

    Each device keeps its own fingerprint file, so restarting a client on the
    same host reuses its identity, while a companion device using a
    different state directory always gets a fingerprint of its own.
    """
    destination = Path(path)
    if destination.exists():
        stored = json.loads(destination.read_text())
        return validate_device_id(stored["device_fingerprint"], phone_number)
    fingerprint = generate_device_fingerprint(phone_number)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(destination, {"device_fingerprint": format_fingerprint(fingerprint)})
    destination.chmod(0o600)
    return fingerprint
