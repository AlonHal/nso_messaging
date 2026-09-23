import pytest

from nso_messaging.client import MessagingClient


def test_collaborator_client_is_explicitly_reserved_for_future_support(tmp_path):
    with pytest.raises(NotImplementedError, match="primary client role"):
        MessagingClient("http://127.0.0.1:8000", "+15550030", tmp_path, client_role="companion")


def test_encryption_flag_is_explicitly_reserved_for_future_support(tmp_path):
    with pytest.raises(NotImplementedError, match="Encrypted messaging"):
        MessagingClient("http://127.0.0.1:8000", "+15550031", tmp_path, encryption_enabled=True)
