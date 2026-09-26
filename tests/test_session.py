import json

import pytest

from nso_messaging.session import (
    IdentityKeyPair,
    PreKeyBundle,
    deserialize_public_bundle,
    establish_initiator_session,
    establish_responder_session,
    serialize_public_bundle,
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

