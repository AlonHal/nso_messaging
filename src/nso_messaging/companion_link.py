"""File-based companion device linking.

The assignment's companion pairing bonus describes exchanging linking data by
QR code. This project replaces the QR image with a shared JSON file under
``/tmp``: the companion writes its offered identity key, the primary reads it
and writes back its half of the signed certificate, and the companion reads
that response to complete the link. The underlying signatures are identical
to the QR-code flow; only the transport differs.
"""

import json
from pathlib import Path

from .encoding import decode_bytes, encode_bytes
from .json_store import write_json_atomic

DEFAULT_LINK_DIR = Path("/tmp")


def _offer_path(link_id: str, directory: Path) -> Path:
    """Return the path a companion writes its offered identity key to."""
    return directory / f"nso-companion-link-{link_id}-offer.json"


def _response_path(link_id: str, directory: Path) -> Path:
    """Return the path a primary writes its signed link response to."""
    return directory / f"nso-companion-link-{link_id}-response.json"


def write_companion_offer(
    link_id: str,
    companion_identity_ed25519_public_key: bytes,
    *,
    directory: Path = DEFAULT_LINK_DIR,
) -> Path:
    """Publish a companion's identity key for the primary to read and sign."""
    path = _offer_path(link_id, directory)
    write_json_atomic(
        path,
        {
            "companion_identity_ed25519_public_key": encode_bytes(
                companion_identity_ed25519_public_key
            )
        },
    )
    return path


def read_companion_offer(link_id: str, *, directory: Path = DEFAULT_LINK_DIR) -> bytes:
    """Read the companion identity key written by :func:`write_companion_offer`."""
    data = json.loads(_offer_path(link_id, directory).read_text())
    return decode_bytes(data["companion_identity_ed25519_public_key"])


def write_primary_link_response(
    link_id: str,
    primary_identity_ed25519_public_key: bytes,
    metadata: bytes,
    primary_signature: bytes,
    *,
    directory: Path = DEFAULT_LINK_DIR,
) -> Path:
    """Publish the primary's identity, metadata, and A_signature for the companion."""
    path = _response_path(link_id, directory)
    write_json_atomic(
        path,
        {
            "primary_identity_ed25519_public_key": encode_bytes(
                primary_identity_ed25519_public_key
            ),
            "metadata": encode_bytes(metadata),
            "primary_signature": encode_bytes(primary_signature),
        },
    )
    return path


def read_primary_link_response(
    link_id: str, *, directory: Path = DEFAULT_LINK_DIR
) -> tuple[bytes, bytes, bytes]:
    """Read the primary's response written by :func:`write_primary_link_response`."""
    data = json.loads(_response_path(link_id, directory).read_text())
    return (
        decode_bytes(data["primary_identity_ed25519_public_key"]),
        decode_bytes(data["metadata"]),
        decode_bytes(data["primary_signature"]),
    )
