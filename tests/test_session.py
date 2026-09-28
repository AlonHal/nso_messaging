import json

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from nso_messaging.session import (
    LINK_METADATA_SIZE,
    LINKING_SECRET_SIZE,
    CompanionLinkCertificate,
    IdentityKeyPair,
    PreKeyBundle,
    compute_linking_hmac,
    derive_ratchet_keys,
    deserialize_companion_link_certificate,
    deserialize_linking_data,
    deserialize_public_bundle,
    establish_initiator_session,
    establish_responder_session,
    generate_linking_metadata,
    generate_linking_secret,
    serialize_companion_link_certificate,
    serialize_device_list,
    serialize_linking_data,
    serialize_public_bundle,
    sign_companion_acknowledgement,
    sign_companion_link,
    sign_device_list,
    verify_companion_link_certificate,
    verify_device_list_signature,
    verify_linking_hmac,
    verify_signed_pre_key,
)


def test_signed_pre_key_bundle_verifies_and_one_time_key_is_consumed():
    """Verify signed bundle authenticity and single-use private pre-key removal."""
    recipient = PreKeyBundle.generate(one_time_pre_key_count=1)
    bundle = recipient.public_bundle()

    assert verify_signed_pre_key(bundle)
    one_time_id = bundle.one_time_pre_keys[0]["key_id"]
    assert recipient.consume_one_time_pre_key(one_time_id) is not None
    assert recipient.consume_one_time_pre_key(one_time_id) is None


def test_session_setup_derives_matching_directional_chains():
    """Verify initiator and responder derive matching directional chains."""
    initiator = IdentityKeyPair.generate()
    recipient = PreKeyBundle.generate(one_time_pre_key_count=1)
    public_bundle = recipient.public_bundle()

    initiator_state, header = establish_initiator_session(initiator, public_bundle)
    responder_state = establish_responder_session(recipient, initiator_state.identity_public_key, header)

    assert initiator_state.send_chain_key == responder_state.receive_chain_key
    assert initiator_state.receive_chain_key == responder_state.send_chain_key
    assert initiator_state.root_key == responder_state.root_key


def test_dh_ratchet_derives_matching_root_and_chain_keys():
    """Derive the same next root and chain keys from both sides of the ECDH ratchet."""
    sender_ephemeral = x25519.X25519PrivateKey.generate()
    recipient_ephemeral = x25519.X25519PrivateKey.generate()
    root_key = bytes(range(32))
    sender_secret = sender_ephemeral.exchange(recipient_ephemeral.public_key())
    recipient_secret = recipient_ephemeral.exchange(sender_ephemeral.public_key())

    sender_chain, sender_root = derive_ratchet_keys(root_key, sender_secret)
    recipient_chain, recipient_root = derive_ratchet_keys(root_key, recipient_secret)

    assert sender_chain == recipient_chain
    assert sender_root == recipient_root
    assert sender_root != root_key


def test_invalid_signed_pre_key_is_rejected():
    """Reject a bundle whose signed pre-key signature does not verify."""
    recipient = PreKeyBundle.generate(one_time_pre_key_count=1)
    bundle = recipient.public_bundle()
    bundle.signed_pre_key_signature = bytes(len(bundle.signed_pre_key_signature))

    with pytest.raises(ValueError, match="signed pre-key signature"):
        verify_signed_pre_key(bundle)


def test_public_bundle_round_trips_through_json_safe_serialization():
    """Verify public bundle serialization preserves all published key fields."""
    recipient = PreKeyBundle.generate(one_time_pre_key_count=2)
    bundle = recipient.public_bundle()

    wire_payload = json.loads(json.dumps(serialize_public_bundle(bundle)))
    restored = deserialize_public_bundle(wire_payload)

    assert restored == bundle
    assert verify_signed_pre_key(restored)


def _linked_companion_certificate(metadata: bytes = b"nso-link-metadata") -> CompanionLinkCertificate:
    """Build a fully signed companion link certificate for the tests below."""
    primary = IdentityKeyPair.generate()
    companion = IdentityKeyPair.generate()
    primary_signature = sign_companion_link(primary, companion.ed25519_public_bytes, metadata)
    companion_signature = sign_companion_acknowledgement(
        companion, primary.ed25519_public_bytes, metadata
    )
    return CompanionLinkCertificate(
        primary_identity_ed25519_public_key=primary.ed25519_public_bytes,
        companion_identity_ed25519_public_key=companion.ed25519_public_bytes,
        metadata=metadata,
        primary_signature=primary_signature,
        companion_signature=companion_signature,
    )


def test_companion_link_certificate_with_both_signatures_verifies():
    """Verify a companion certificate signed by both the primary and companion."""
    certificate = _linked_companion_certificate()

    assert verify_companion_link_certificate(certificate)


def test_companion_link_certificate_rejects_tampered_primary_signature():
    """Reject a companion certificate whose primary (A_signature) half is tampered."""
    certificate = _linked_companion_certificate()
    certificate.primary_signature = bytes(len(certificate.primary_signature))

    with pytest.raises(ValueError, match="companion link certificate"):
        verify_companion_link_certificate(certificate)


def test_companion_link_certificate_rejects_tampered_companion_signature():
    """Reject a companion certificate whose companion (D_signature) half is tampered."""
    certificate = _linked_companion_certificate()
    certificate.companion_signature = bytes(len(certificate.companion_signature))

    with pytest.raises(ValueError, match="companion link certificate"):
        verify_companion_link_certificate(certificate)


def test_companion_link_certificate_round_trips_through_json_safe_serialization():
    """Verify companion certificate serialization preserves every signed field."""
    certificate = _linked_companion_certificate()

    wire_payload = json.loads(json.dumps(serialize_companion_link_certificate(certificate)))
    restored = deserialize_companion_link_certificate(wire_payload)

    assert restored == certificate
    assert verify_companion_link_certificate(restored)


def test_generated_linking_secret_and_metadata_have_documented_sizes():
    """Verify L_companion and L_metadata match the whitepaper's byte sizes."""
    assert len(generate_linking_secret()) == LINKING_SECRET_SIZE
    assert len(generate_linking_metadata()) == LINK_METADATA_SIZE


def test_linking_data_round_trips_through_serialization():
    """Verify L_data serialization preserves metadata, I_primary, and A_signature."""
    primary = IdentityKeyPair.generate()
    companion = IdentityKeyPair.generate()
    metadata = generate_linking_metadata()
    account_signature = sign_companion_link(primary, companion.ed25519_public_bytes, metadata)

    linking_data = serialize_linking_data(metadata, primary.ed25519_public_bytes, account_signature)
    restored_metadata, restored_primary_key, restored_signature = deserialize_linking_data(
        linking_data
    )

    assert restored_metadata == metadata
    assert restored_primary_key == primary.ed25519_public_bytes
    assert restored_signature == account_signature


def test_linking_hmac_verifies_with_the_matching_linking_secret():
    """Verify PHMAC computed over L_data with L_companion authenticates correctly."""
    linking_secret = generate_linking_secret()
    linking_data = b"opaque-linking-data-bytes"

    linking_hmac = compute_linking_hmac(linking_secret, linking_data)

    assert verify_linking_hmac(linking_secret, linking_data, linking_hmac)


def test_linking_hmac_rejects_a_tampered_linking_secret():
    """Reject PHMAC verification when the companion's linking secret does not match."""
    linking_data = b"opaque-linking-data-bytes"
    linking_hmac = compute_linking_hmac(generate_linking_secret(), linking_data)

    with pytest.raises(ValueError, match="linking HMAC"):
        verify_linking_hmac(generate_linking_secret(), linking_data, linking_hmac)


def test_device_list_signature_verifies_with_the_primary_identity():
    """Verify ListSignature over ListData authenticates with the primary's identity."""
    primary = IdentityKeyPair.generate()
    companion = IdentityKeyPair.generate()
    device_list = serialize_device_list([companion.ed25519_public_bytes])

    list_signature = sign_device_list(primary, device_list)

    assert verify_device_list_signature(primary.ed25519_public_bytes, device_list, list_signature)


def test_device_list_signature_rejects_a_tampered_device_list():
    """Reject ListSignature verification when ListData was altered after signing."""
    primary = IdentityKeyPair.generate()
    companion = IdentityKeyPair.generate()
    device_list = serialize_device_list([companion.ed25519_public_bytes])
    list_signature = sign_device_list(primary, device_list)
    tampered_list = serialize_device_list([companion.ed25519_public_bytes, b"\x00" * 32])

    with pytest.raises(ValueError, match="device list signature"):
        verify_device_list_signature(primary.ed25519_public_bytes, tampered_list, list_signature)

