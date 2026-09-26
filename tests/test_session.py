import json

import pytest

from nso_messaging.session import (
    CompanionLinkCertificate,
    IdentityKeyPair,
    PreKeyBundle,
    deserialize_companion_link_certificate,
    deserialize_public_bundle,
    establish_initiator_session,
    establish_responder_session,
    serialize_companion_link_certificate,
    serialize_public_bundle,
    sign_companion_acknowledgement,
    sign_companion_link,
    verify_companion_link_certificate,
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

