import pytest

from nso_messaging.crypto import (
    AuthenticationError,
    advance_chain,
    decrypt_message,
    derive_initial_keys,
    derive_message_key,
    encrypt_message,
)


def test_initial_hkdf_keys_are_split_into_root_and_chain_keys():
    """Verify initial HKDF output contains distinct 32-byte root and chain keys."""
    master_secret = bytes(range(32))

    root_key, chain_key = derive_initial_keys(master_secret)

    assert len(root_key) == 32
    assert len(chain_key) == 32
    assert root_key != chain_key


def test_chain_advancement_returns_message_key_and_next_chain():
    """Verify deterministic message-key derivation advances the chain."""
    chain_key = bytes(range(32))

    message_key, next_chain_key = derive_message_key(chain_key)
    repeated_message_key, repeated_next_chain_key = derive_message_key(chain_key)

    assert len(message_key) == 80
    assert next_chain_key == repeated_next_chain_key
    assert message_key == repeated_message_key
    assert next_chain_key != chain_key
    assert advance_chain(chain_key) == next_chain_key


def test_encrypt_and_decrypt_round_trip_uses_derived_iv():
    """Verify ciphertext round-trips using the IV derived in message material."""
    message_key = derive_message_key(bytes(range(32)))[0]
    plaintext = b"hello from the protocol slice"

    ciphertext, mac = encrypt_message(message_key, plaintext)

    assert ciphertext != plaintext
    assert len(mac) == 32
    assert decrypt_message(message_key, ciphertext, mac) == plaintext


def test_tampered_ciphertext_is_rejected_before_decryption():
    """Reject modified ciphertext before releasing plaintext."""
    message_key = derive_message_key(bytes(range(32)))[0]
    ciphertext, mac = encrypt_message(message_key, b"authenticated message")
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(AuthenticationError):
        decrypt_message(message_key, tampered, mac)
