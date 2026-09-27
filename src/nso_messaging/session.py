"""Identity, pre-key bundle, and initial session setup primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import derive_initial_keys
from .encoding import decode_bytes, encode_bytes


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
        "identity_x25519_public_key": encode_bytes(bundle.identity_x25519_public_key),
        "identity_ed25519_public_key": encode_bytes(bundle.identity_ed25519_public_key),
        "signed_pre_key": encode_bytes(bundle.signed_pre_key),
        "signed_pre_key_signature": encode_bytes(bundle.signed_pre_key_signature),
        "one_time_pre_keys": [
            {"key_id": entry["key_id"], "public_key": encode_bytes(entry["public_key"])}
            for entry in bundle.one_time_pre_keys
        ],
    }


def deserialize_public_bundle(data: dict) -> PublicPreKeyBundle:
    """Decode a JSON-safe bundle produced by :func:`serialize_public_bundle`."""
    return PublicPreKeyBundle(
        identity_x25519_public_key=decode_bytes(data["identity_x25519_public_key"]),
        identity_ed25519_public_key=decode_bytes(data["identity_ed25519_public_key"]),
        signed_pre_key=decode_bytes(data["signed_pre_key"]),
        signed_pre_key_signature=decode_bytes(data["signed_pre_key_signature"]),
        one_time_pre_keys=[
            {"key_id": entry["key_id"], "public_key": decode_bytes(entry["public_key"])}
            for entry in data["one_time_pre_keys"]
        ],
    )


def serialize_private_bundle(bundle: PreKeyBundle) -> dict:
    """Encode client-owned identity and pre-key material for local storage."""
    return {
        "identity_x25519_private_key": encode_bytes(_raw_private_bytes(bundle.identity.x25519_private_key)),
        "identity_ed25519_private_key": encode_bytes(_raw_private_bytes(bundle.identity.ed25519_private_key)),
        "signed_pre_key": encode_bytes(_raw_private_bytes(bundle.signed_pre_key)),
        "signed_pre_key_signature": encode_bytes(bundle.signed_pre_key_signature),
        "one_time_pre_keys": {
            key_id: encode_bytes(_raw_private_bytes(key))
            for key_id, key in bundle.one_time_pre_keys.items()
        },
    }


def deserialize_private_bundle(data: dict) -> PreKeyBundle:
    """Restore client-owned identity and pre-key material from local storage."""
    return PreKeyBundle(
        identity=IdentityKeyPair(
            x25519.X25519PrivateKey.from_private_bytes(
                decode_bytes(data["identity_x25519_private_key"])
            ),
            ed25519.Ed25519PrivateKey.from_private_bytes(
                decode_bytes(data["identity_ed25519_private_key"])
            ),
        ),
        signed_pre_key=x25519.X25519PrivateKey.from_private_bytes(
            decode_bytes(data["signed_pre_key"])
        ),
        signed_pre_key_signature=decode_bytes(data["signed_pre_key_signature"]),
        one_time_pre_keys={
            key_id: x25519.X25519PrivateKey.from_private_bytes(decode_bytes(encoded))
            for key_id, encoded in data["one_time_pre_keys"].items()
        },
    )


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


@dataclass
class Session:
    """One established session's chain state paired with its handshake header.

    Replaces tracking state and header in two separate, index-aligned dicts.
    """

    state: SessionState
    header: SessionHeader


def serialize_session_header(header: SessionHeader) -> dict[str, str | None]:
    """Encode handshake public-key fields for envelope or local-state JSON."""
    return {
        "identity_public_key": encode_bytes(header.identity_public_key),
        "ephemeral_public_key": encode_bytes(header.ephemeral_public_key),
        "one_time_pre_key_id": header.one_time_pre_key_id,
    }


def deserialize_session_header(data: dict) -> SessionHeader:
    """Restore a session header from its JSON representation."""
    return SessionHeader(
        identity_public_key=decode_bytes(data["identity_public_key"]),
        ephemeral_public_key=decode_bytes(data["ephemeral_public_key"]),
        one_time_pre_key_id=data.get("one_time_pre_key_id"),
    )


def session_id_for_header(header: SessionHeader) -> str:
    """Use the initiator's ephemeral public key as the session identifier."""
    return encode_bytes(header.ephemeral_public_key)


def serialize_session_state(state: SessionState) -> dict[str, str]:
    """Encode root and directional chain keys for local persistence."""
    return {
        "root_key": encode_bytes(state.root_key),
        "send_chain_key": encode_bytes(state.send_chain_key),
        "receive_chain_key": encode_bytes(state.receive_chain_key),
        "identity_public_key": encode_bytes(state.identity_public_key),
    }


def deserialize_session_state(data: dict) -> SessionState:
    """Restore root and directional chain keys from local-state JSON."""
    return SessionState(
        root_key=decode_bytes(data["root_key"]),
        send_chain_key=decode_bytes(data["send_chain_key"]),
        receive_chain_key=decode_bytes(data["receive_chain_key"]),
        identity_public_key=decode_bytes(data["identity_public_key"]),
    )


def serialize_session(session: Session) -> dict:
    """Encode a paired session state and header for local persistence."""
    return {
        "state": serialize_session_state(session.state),
        "header": serialize_session_header(session.header),
    }


def deserialize_session(data: dict) -> Session:
    """Restore a paired session state and header from local-state JSON."""
    return Session(
        state=deserialize_session_state(data["state"]),
        header=deserialize_session_header(data["header"]),
    )


def verify_signed_pre_key(bundle: PublicPreKeyBundle) -> bool:
    """Verify the signed X25519 pre-key using the Ed25519 identity key."""
    try:
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(bundle.identity_ed25519_public_key)
        verifier.verify(bundle.signed_pre_key_signature, bundle.signed_pre_key)
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("signed pre-key signature is invalid") from None
    return True


# Domain-separation prefixes for the two companion-linking signatures, per the
# assignment's companion pairing bonus section.
_COMPANION_LINK_PREFIX = b"\x06\x00"
_COMPANION_ACK_PREFIX = b"\x06\x01"


@dataclass
class CompanionLinkCertificate:
    """Proof that a companion device's identity is linked to a primary device.

    ``primary_signature`` (A_signature) is the primary vouching for the
    companion's identity key; ``companion_signature`` (D_signature) is the
    companion countersigning that same link. A sender must verify both
    before establishing a session with a companion device.
    """

    primary_identity_ed25519_public_key: bytes
    companion_identity_ed25519_public_key: bytes
    metadata: bytes
    primary_signature: bytes
    companion_signature: bytes


def sign_companion_link(
    primary_identity: IdentityKeyPair,
    companion_identity_ed25519_public_key: bytes,
    metadata: bytes,
) -> bytes:
    """Compute A_signature: the primary vouching for a companion's identity key."""
    return primary_identity.ed25519_private_key.sign(
        _COMPANION_LINK_PREFIX + metadata + companion_identity_ed25519_public_key
    )


def sign_companion_acknowledgement(
    companion_identity: IdentityKeyPair,
    primary_identity_ed25519_public_key: bytes,
    metadata: bytes,
) -> bytes:
    """Compute D_signature: the companion countersigning acceptance of the link."""
    return companion_identity.ed25519_private_key.sign(
        _COMPANION_ACK_PREFIX
        + metadata
        + companion_identity.ed25519_public_bytes
        + primary_identity_ed25519_public_key
    )


def verify_companion_link_certificate(certificate: CompanionLinkCertificate) -> bool:
    """Verify both the primary's and companion's signatures over a link certificate."""
    try:
        primary_verifier = ed25519.Ed25519PublicKey.from_public_bytes(
            certificate.primary_identity_ed25519_public_key
        )
        primary_verifier.verify(
            certificate.primary_signature,
            _COMPANION_LINK_PREFIX
            + certificate.metadata
            + certificate.companion_identity_ed25519_public_key,
        )
        companion_verifier = ed25519.Ed25519PublicKey.from_public_bytes(
            certificate.companion_identity_ed25519_public_key
        )
        companion_verifier.verify(
            certificate.companion_signature,
            _COMPANION_ACK_PREFIX
            + certificate.metadata
            + certificate.companion_identity_ed25519_public_key
            + certificate.primary_identity_ed25519_public_key,
        )
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("companion link certificate is invalid") from None
    return True


def serialize_companion_link_certificate(certificate: CompanionLinkCertificate) -> dict:
    """Encode a companion link certificate as JSON-safe base64 strings."""
    return {
        "primary_identity_ed25519_public_key": encode_bytes(
            certificate.primary_identity_ed25519_public_key
        ),
        "companion_identity_ed25519_public_key": encode_bytes(
            certificate.companion_identity_ed25519_public_key
        ),
        "metadata": encode_bytes(certificate.metadata),
        "primary_signature": encode_bytes(certificate.primary_signature),
        "companion_signature": encode_bytes(certificate.companion_signature),
    }


def deserialize_companion_link_certificate(data: dict) -> CompanionLinkCertificate:
    """Decode a JSON-safe certificate produced by :func:`serialize_companion_link_certificate`."""
    return CompanionLinkCertificate(
        primary_identity_ed25519_public_key=decode_bytes(
            data["primary_identity_ed25519_public_key"]
        ),
        companion_identity_ed25519_public_key=decode_bytes(
            data["companion_identity_ed25519_public_key"]
        ),
        metadata=decode_bytes(data["metadata"]),
        primary_signature=decode_bytes(data["primary_signature"]),
        companion_signature=decode_bytes(data["companion_signature"]),
    )


# Sizes and domain-separation prefix for the QR-code linking handshake
# (WhatsApp whitepaper "Client Registration: Option 1, Link Using a QR-Code").
LINKING_SECRET_SIZE = 32  # L_companion: HMAC key, kept off the server.
LINK_METADATA_SIZE = 16  # L_metadata: opaque per-link nonce.
_ED25519_PUBLIC_KEY_SIZE = 32
_ED25519_SIGNATURE_SIZE = 64
_DEVICE_LIST_SIGNATURE_PREFIX = b"\x06\x02"


def generate_linking_secret() -> bytes:
    """Generate L_companion, the ephemeral HMAC key shared only via the QR code."""
    return secrets.token_bytes(LINKING_SECRET_SIZE)


def generate_linking_metadata() -> bytes:
    """Generate L_metadata, an opaque per-link nonce identifying this linking attempt."""
    return secrets.token_bytes(LINK_METADATA_SIZE)


def serialize_linking_data(
    metadata: bytes,
    primary_identity_ed25519_public_key: bytes,
    account_signature: bytes,
) -> bytes:
    """Serialize L_data: metadata, I_primary, and A_signature at fixed offsets.

    Every field has a fixed byte length, so the concatenation is unambiguous
    to parse back with :func:`deserialize_linking_data` without a length
    prefix or delimiter.
    """
    return metadata + primary_identity_ed25519_public_key + account_signature


def deserialize_linking_data(linking_data: bytes) -> tuple[bytes, bytes, bytes]:
    """Split L_data back into ``(metadata, I_primary, A_signature)``."""
    primary_key_start = LINK_METADATA_SIZE
    signature_start = primary_key_start + _ED25519_PUBLIC_KEY_SIZE
    return (
        linking_data[:primary_key_start],
        linking_data[primary_key_start:signature_start],
        linking_data[signature_start : signature_start + _ED25519_SIGNATURE_SIZE],
    )


def compute_linking_hmac(linking_secret: bytes, linking_data: bytes) -> bytes:
    """Compute PHMAC = HMAC-SHA256(L_companion, L_data)."""
    return hmac.new(linking_secret, linking_data, hashlib.sha256).digest()


def verify_linking_hmac(linking_secret: bytes, linking_data: bytes, expected_hmac: bytes) -> bool:
    """Verify PHMAC before a companion trusts the primary's forwarded L_data."""
    if not hmac.compare_digest(compute_linking_hmac(linking_secret, linking_data), expected_hmac):
        raise ValueError("linking HMAC does not match L_data")
    return True


def serialize_device_list(companion_identity_ed25519_public_keys: list[bytes]) -> bytes:
    """Encode ListData: the account's currently linked companion identity keys."""
    encoded_keys = sorted(encode_bytes(key) for key in companion_identity_ed25519_public_keys)
    return json.dumps(encoded_keys, separators=(",", ":")).encode()


def sign_device_list(primary_identity: IdentityKeyPair, device_list_data: bytes) -> bytes:
    """Compute ListSignature over ListData with the primary's identity key."""
    return primary_identity.ed25519_private_key.sign(
        _DEVICE_LIST_SIGNATURE_PREFIX + device_list_data
    )


def verify_device_list_signature(
    primary_identity_ed25519_public_key: bytes,
    device_list_data: bytes,
    list_signature: bytes,
) -> bool:
    """Verify ListSignature was produced by the account's primary identity key."""
    try:
        verifier = ed25519.Ed25519PublicKey.from_public_bytes(primary_identity_ed25519_public_key)
        verifier.verify(list_signature, _DEVICE_LIST_SIGNATURE_PREFIX + device_list_data)
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("device list signature is invalid") from None
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


def _raw_private_bytes(key) -> bytes:
    """Serialize an X25519 or Ed25519 private key without encryption."""
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
