import pytest

from nso_messaging.client import MessagingClient


def test_companion_client_requires_encryption_and_can_be_initialized(tmp_path):
    """Require a companion to have a device identity and pre-key bundle."""
    with pytest.raises(ValueError, match="encryption to be enabled"):
        MessagingClient("http://127.0.0.1:8000", "+15550030", tmp_path, client_role="companion")

    client = MessagingClient(
        "http://127.0.0.1:8000",
        "+15550030",
        tmp_path,
        client_role="companion",
        encryption_enabled=True,
    )

    assert client.device_id
    assert client.pre_key_bundle is not None


def test_encryption_flag_initializes_an_encrypted_client(tmp_path):
    """Initialize one stable client identity with its encrypted pre-key bundle."""
    client = MessagingClient(
        "http://127.0.0.1:8000",
        "+15550031",
        tmp_path,
        encryption_enabled=True,
    )

    assert client.encryption_enabled is True
    assert client.identity is not None
    assert client.pre_key_bundle is not None
    assert client.identity is client.pre_key_bundle.identity
