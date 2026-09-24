"""Identity, pre-key bundle, and initial session setup primitives."""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import derive_initial_keys


@dataclass
class IdentityKeyPair:
    """Matched X25519 and Ed25519 identity keys for one device."""

    x25519_private_key: x25519.X25519PrivateKey
    ed25519_private_key: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> IdentityKeyPair:
        """Generate a fresh identity pair."""
        return cls(x25519.X25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate())

    @property
    def x25519_public_bytes(self) -> bytes:
        """Return the raw X25519 identity public key."""
        return _raw_public_bytes(self.x25519_private_key.public_key())

    @property
    def ed25519_public_bytes(self) -> bytes:
        """Return the raw Ed25519 identity public key."""
        return _raw_public_bytes(self.ed25519_private_key.public_key())


@dataclass
class PublicPreKeyBundle:
    """Public registration material needed to initiate a session."""

    identity_x25519_public_key: bytes
    identity_ed25519_public_key: bytes
    signed_pre_key: bytes
    signed_pre_key_signature: bytes
    one_time_pre_keys: list[dict[str, bytes]]


@dataclass
class PreKeyBundle:
    """Private device key material retained by the recipient."""

    identity: IdentityKeyPair
    signed_pre_key: x25519.X25519PrivateKey
    signed_pre_key_signature: bytes
    one_time_pre_keys: dict[str, x25519.X25519PrivateKey]

    @classmethod
    def generate(cls, one_time_pre_key_count: int = 10) -> PreKeyBundle:
        """Generate identity, signed pre-key, and one-time pre-keys."""
        identity = IdentityKeyPair.generate()
        signed_pre_key = x25519.X25519PrivateKey.generate()
        signed_public = _raw_public_bytes(signed_pre_key.public_key())
        signature = identity.ed25519_private_key.sign(signed_public)
        one_time_pre_keys = {
            str(uuid.uuid4()): x25519.X25519PrivateKey.generate()
            for _ in range(one_time_pre_key_count)
        }
        return cls(identity, signed_pre_key, signature, one_time_pre_keys)

    def public_bundle(self) -> PublicPreKeyBundle:
        """Return the public subset safe to publish to the server."""
        return PublicPreKeyBundle(
            identity_x25519_public_key=self.identity.x25519_public_bytes,
            identity_ed25519_public_key=self.identity.ed25519_public_bytes,
            signed_pre_key=_raw_public_bytes(self.signed_pre_key.public_key()),
            signed_pre_key_signature=self.signed_pre_key_signature,
            one_time_pre_keys=[
                {"key_id": key_id, "public_key": _raw_public_bytes(key.public_key())}
                for key_id, key in self.one_time_pre_keys.items()
            ],
        )

    def consume_one_time_pre_key(self, key_id: str) -> x25519.X25519PrivateKey | None:
        """Remove and return one one-time pre-key, if it is still available."""
        return self.one_time_pre_keys.pop(key_id, None)


def serialize_public_bundle(bundle: PublicPreKeyBundle) -> dict:
    """Encode a public bundle as JSON-safe base64 strings for HTTP transport."""
    return {
        "identity_x25519_public_key": _b64(bundle.identity_x25519_public_key),
        "identity_ed25519_public_key": _b64(bundle.identity_ed25519_public_key),
        "signed_pre_key": _b64(bundle.signed_pre_key),
        "signed_pre_key_signature": _b64(bundle.signed_pre_key_signature),
        "one_time_pre_keys": [
            {"key_id": entry["key_id"], "public_key": _b64(entry["public_key"])}
            for entry in bundle.one_time_pre_keys
        ],
    }


def deserialize_public_bundle(data: dict) -> PublicPreKeyBundle:
    """Decode a JSON-safe bundle produced by :func:`serialize_public_bundle`."""
    return PublicPreKeyBundle(
        identity_x25519_public_key=_unb64(data["identity_x25519_public_key"]),
        identity_ed25519_public_key=_unb64(data["identity_ed25519_public_key"]),
        signed_pre_key=_unb64(data["signed_pre_key"]),
        signed_pre_key_signature=_unb64(data["signed_pre_key_signature"]),
        one_time_pre_keys=[
            {"key_id": entry["key_id"], "public_key": _unb64(entry["public_key"])}
            for entry in data["one_time_pre_keys"]
        ],
    )


def _b64(raw: bytes) -> str:
    """Base64-encode raw key bytes for JSON transport."""
    return base64.b64encode(raw).decode("ascii")


def _unb64(encoded: str) -> bytes:
    """Decode a base64 string produced by :func:`_b64`."""
    return base64.b64decode(encoded)


@dataclass
class SessionHeader:
    """Handshake fields carried by the initiator's first message."""

    identity_public_key: bytes
    ephemeral_public_key: bytes
    one_time_pre_key_id: str | None


@dataclass
class SessionState:
    """Root and directional chain state for an established session."""

    root_key: bytes
    send_chain_key: bytes
    receive_chain_key: bytes
    identity_public_key: bytes


def verify_signed_pre_key(bundle: PublicPreKeyBundle) -> bool:
    """Verify the signed X25519 pre-key using the Ed25519 identity key."""
    try:
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(bundle.identity_ed25519_public_key)
        verifier.verify(bundle.signed_pre_key_signature, bundle.signed_pre_key)
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("signed pre-key signature is invalid") from None
    return True


def establish_initiator_session(
    identity: IdentityKeyPair,
    recipient_bundle: PublicPreKeyBundle,
) -> tuple[SessionState, SessionHeader]:
    """Derive initiator state and the header needed by the recipient."""
    verify_signed_pre_key(recipient_bundle)
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    recipient_identity = x25519.X25519PublicKey.from_public_bytes(
        recipient_bundle.identity_x25519_public_key
    )
    recipient_signed_pre_key = x25519.X25519PublicKey.from_public_bytes(
        recipient_bundle.signed_pre_key
    )
    one_time_entry = recipient_bundle.one_time_pre_keys[0] if recipient_bundle.one_time_pre_keys else None
    one_time_public_key = (
        x25519.X25519PublicKey.from_public_bytes(one_time_entry["public_key"])
        if one_time_entry
        else None
    )
    # X3DH: DH1 (our identity x their signed pre-key), DH2 (ephemeral x their
    # identity), DH3 (ephemeral x their signed pre-key), DH4 (ephemeral x their
    # one-time pre-key, if offered). The responder must combine the same four
    # DH outputs in this exact order for the derived master_secret to match.
    master_secret = b"".join(
        [
            identity.x25519_private_key.exchange(recipient_signed_pre_key),
            ephemeral_private_key.exchange(recipient_identity),
            ephemeral_private_key.exchange(recipient_signed_pre_key),
            b"" if one_time_public_key is None else ephemeral_private_key.exchange(one_time_public_key),
        ]
    )
    root_key, chain_key = derive_initial_keys(master_secret)
    # initiator=True yields (first, second) here; the responder below swaps the
    # unpacking order instead of passing initiator=False, so both sides agree
    # on which physical chain is "send" vs. "receive".
    send_chain, receive_chain = _directional_chains(root_key, chain_key, initiator=True)
    return (
        SessionState(root_key, send_chain, receive_chain, identity.x25519_public_bytes),
        SessionHeader(
            identity.x25519_public_bytes,
            _raw_public_bytes(ephemeral_private_key.public_key()),
            None if one_time_entry is None else one_time_entry["key_id"],
        ),
    )


def establish_responder_session(
    recipient_bundle: PreKeyBundle,
    initiator_identity_public_key: bytes,
    header: SessionHeader,
) -> SessionState:
    """Derive responder state from the initiator header and private bundle."""
    initiator_identity = x25519.X25519PublicKey.from_public_bytes(initiator_identity_public_key)
    initiator_ephemeral = x25519.X25519PublicKey.from_public_bytes(header.ephemeral_public_key)
    one_time_private = (
        recipient_bundle.consume_one_time_pre_key(header.one_time_pre_key_id)
        if header.one_time_pre_key_id is not None
        else None
    )
    # Mirrors the initiator's DH1-DH4, each computed from the responder's side
    # of the same key pair so the resulting master_secret is identical.
    master_secret = b"".join(
        [
            recipient_bundle.signed_pre_key.exchange(initiator_identity),
            recipient_bundle.identity.x25519_private_key.exchange(initiator_ephemeral),
            recipient_bundle.signed_pre_key.exchange(initiator_ephemeral),
            b"" if one_time_private is None else one_time_private.exchange(initiator_ephemeral),
        ]
    )
    root_key, chain_key = derive_initial_keys(master_secret)
    # Same derivation as the initiator, but chains are unpacked in the opposite
    # order so the responder's send chain matches the initiator's receive chain.
    receive_chain, send_chain = _directional_chains(root_key, chain_key, initiator=True)
    return SessionState(
        root_key,
        send_chain,
        receive_chain,
        recipient_bundle.identity.x25519_public_bytes,
    )


def _directional_chains(root_key: bytes, chain_key: bytes, *, initiator: bool) -> tuple[bytes, bytes]:
    """Derive independent send/receive chains with role-specific ordering."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"nso directional chains",
    ).derive(chain_key)
    first, second = derived[:32], derived[32:]
    return (first, second) if initiator else (second, first)


def _raw_public_bytes(key) -> bytes:
    """Serialize an X25519 or Ed25519 public key in raw form."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
