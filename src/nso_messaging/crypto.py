"""Assignment-compatible key derivation and authenticated message protection."""

from __future__ import annotations

import hmac
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7

KEY_SIZE = 32
MESSAGE_KEY_SIZE = 80
IV_SIZE = 16


class AuthenticationError(ValueError):
    """Raised when a message MAC cannot be verified."""


def derive_initial_keys(master_secret: bytes) -> tuple[bytes, bytes]:
    """Derive the 32-byte root and chain keys from a handshake secret."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"nso initial session",
    ).derive(master_secret)
    return derived[:KEY_SIZE], derived[KEY_SIZE:]


def advance_chain(chain_key: bytes) -> bytes:
    """Advance a chain with the assignment's ``HMAC(chain_key, 0x02)`` rule."""
    return hmac.new(chain_key, b"\x02", sha256).digest()


def derive_message_key(chain_key: bytes) -> tuple[bytes, bytes]:
    """Return an 80-byte message key and the next chain key.

    The assignment defines the message-key seed as ``HMAC(chain_key, 0x01)``
    and requires 80 bytes for AES key, MAC key, and IV. HKDF expands that
    32-byte seed to the required 80-byte message material.
    """
    message_seed = hmac.new(chain_key, b"\x01", sha256).digest()
    message_key = HKDF(
        algorithm=hashes.SHA256(),
        length=MESSAGE_KEY_SIZE,
        salt=None,
        info=b"nso message key",
    ).derive(message_seed)
    return message_key, advance_chain(chain_key)


def encrypt_message(message_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-CBC and return ciphertext plus HMAC."""
    aes_key, mac_key, iv = _split_message_key(message_key)
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, _mac(mac_key, ciphertext)


def decrypt_message(message_key: bytes, ciphertext: bytes, mac: bytes) -> bytes:
    """Verify the ciphertext MAC, then decrypt and remove PKCS7 padding."""
    aes_key, mac_key, iv = _split_message_key(message_key)
    expected_mac = _mac(mac_key, ciphertext)
    if not hmac.compare_digest(expected_mac, mac):
        raise AuthenticationError("message authentication failed")
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as error:
        raise AuthenticationError("invalid message padding") from error


def _split_message_key(message_key: bytes) -> tuple[bytes, bytes, bytes]:
    """Split message material into AES key, HMAC key, and derived IV."""
    if len(message_key) != MESSAGE_KEY_SIZE:
        raise ValueError(f"message key must be {MESSAGE_KEY_SIZE} bytes")
    return message_key[:32], message_key[32:64], message_key[64:]


def _mac(mac_key: bytes, ciphertext: bytes) -> bytes:
    """Calculate the assignment's HMAC-SHA256 over ciphertext."""
    signer = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(ciphertext)
    return signer.finalize()
