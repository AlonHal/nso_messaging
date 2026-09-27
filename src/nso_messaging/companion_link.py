"""File-based companion device linking.

The assignment's companion pairing bonus describes exchanging linking data by
QR code. This project replaces the QR image with a shared JSON offer file: the
companion writes its identity, device ID, and linking secret, then the primary
uses the server to deliver the signed linking response. The secret remains
client-side and authenticates the server-forwarded data with PHMAC.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from .encoding import decode_bytes, encode_bytes
from .json_store import write_json_atomic
from .session import LINKING_SECRET_SIZE

DEFAULT_LINK_DIR = Path("/tmp")


@dataclass(frozen=True)
class CompanionLinkOffer:
    """Local stand-in for QR data shared from companion to primary."""

    device_id: str
    companion_identity_ed25519_public_key: bytes
    linking_secret: bytes


def _offer_path(link_id: str, directory: Path) -> Path:
    """Return the path a companion writes its offered identity key to."""
    if not link_id or Path(link_id).name != link_id or link_id in {".", ".."}:
        raise ValueError("link_id must be a single non-empty path component")
    return directory / f"nso-companion-link-{link_id}-offer.json"


def write_companion_offer(
    link_id: str,
    device_id: str,
    companion_identity_ed25519_public_key: bytes,
    linking_secret: bytes,
    *,
    directory: Path = DEFAULT_LINK_DIR,
) -> Path:
    """Write device identity and L_companion for the primary to read from disk."""
    if not device_id:
        raise ValueError("device_id is required")
    if len(companion_identity_ed25519_public_key) != 32:
        raise ValueError("companion Ed25519 identity public key must be 32 bytes")
    if len(linking_secret) != LINKING_SECRET_SIZE:
        raise ValueError(f"linking_secret must be {LINKING_SECRET_SIZE} bytes")
    path = _offer_path(link_id, directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_atomic(
        path,
        {
            "device_id": device_id,
            "companion_identity_ed25519_public_key": encode_bytes(
                companion_identity_ed25519_public_key
            )
            ,"linking_secret": encode_bytes(linking_secret)
        },
    )
    return path


def read_companion_offer(
    link_id: str, *, directory: Path = DEFAULT_LINK_DIR
) -> CompanionLinkOffer:
    """Read the offer written by :func:`write_companion_offer`."""
    data = json.loads(_offer_path(link_id, directory).read_text())
    offer = CompanionLinkOffer(
        device_id=data["device_id"],
        companion_identity_ed25519_public_key=decode_bytes(
            data["companion_identity_ed25519_public_key"]
        ),
        linking_secret=decode_bytes(data["linking_secret"]),
    )
    if len(offer.companion_identity_ed25519_public_key) != 32:
        raise ValueError("companion Ed25519 identity public key must be 32 bytes")
    if len(offer.linking_secret) != LINKING_SECRET_SIZE:
        raise ValueError(f"linking_secret must be {LINKING_SECRET_SIZE} bytes")
    return offer
