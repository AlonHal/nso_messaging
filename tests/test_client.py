import urllib.error

import pytest

from nso_messaging.client import MessagingClient
from nso_messaging.crypto import AuthenticationError
from nso_messaging.session import PreKeyBundle


def test_clients_register_exchange_and_store_local_history(running_server, tmp_path):
    """Verify plaintext clients exchange messages and retain local history."""
    alice = MessagingClient(running_server.base_url, "+15550010", tmp_path / "alice")
    bob = MessagingClient(running_server.base_url, "+15550011", tmp_path / "bob")

    assert alice.register(name="Alice")["name"] == "Alice"
    assert bob.register(name="Bob")["name"] == "Bob"

    sent = alice.send("+15550011", "hello Bob")
    received = bob.receive()

    assert received[0]["message_id"] == sent["message_id"]
    assert received[0]["content"] == "hello Bob"
    assert alice.history() == [sent | {"direction": "sent"}]
    assert bob.history() == [received[0] | {"direction": "received"}]


def test_client_publishes_and_fetches_public_pre_key_bundle(running_server, tmp_path):
    """Verify client publication exposes only public bundle material."""
    client = MessagingClient(running_server.base_url, "+15550015", tmp_path / "client")
    client.register()
    private_bundle = PreKeyBundle.generate(one_time_pre_key_count=1)

    response = client.publish_pre_key_bundle(private_bundle)
    fetched = client.fetch_pre_key_bundle()

    assert response["one_time_pre_key_count"] == 1
    assert fetched.identity_x25519_public_key == private_bundle.identity.x25519_public_bytes
    assert len(fetched.one_time_pre_keys) == 1
    assert private_bundle.one_time_pre_keys


def test_encrypted_clients_exchange_plaintext_only_in_local_history(running_server, tmp_path):
    """Verify encrypted transport decrypts only for client-local history."""
    alice = MessagingClient(
        running_server.base_url,
        "+15550018",
        tmp_path / "alice-encrypted",
        encryption_enabled=True,
    )
    bob = MessagingClient(
        running_server.base_url,
        "+15550019",
        tmp_path / "bob-encrypted",
        encryption_enabled=True,
    )
    alice.register(name="Alice")
    bob.register(name="Bob")

    sent = alice.send("+15550019", "secret hello")
    received = bob.receive()

    assert sent["content"] == "secret hello"
    assert received[0]["content"] == "secret hello"
    assert alice.history()[0]["content"] == "secret hello"
    assert bob.history()[0]["content"] == "secret hello"


def test_tampered_encrypted_envelope_fails_before_history_write(running_server, tmp_path):
    """Ensure authentication failure prevents plaintext history insertion."""
    alice = MessagingClient(
        running_server.base_url, "+15550023", tmp_path / "alice", encryption_enabled=True
    )
    bob = MessagingClient(
        running_server.base_url, "+15550024", tmp_path / "bob", encryption_enabled=True
    )
    alice.register()
    bob.register()
    alice.send("+15550024", "tamper me")

    envelope = running_server._messages["+15550024"][0]["content"]
    tampered = envelope.replace("ciphertext", "ciphertext-tampered", 1)
    running_server._messages["+15550024"][0]["content"] = tampered

    with pytest.raises((AuthenticationError, KeyError)):
        bob.receive()

    assert bob.history() == []


def test_encrypted_receive_retries_ack_without_redecrypting(running_server, tmp_path, monkeypatch):
    """Ensure a lost ACK response is retried without reusing the receive key."""
    alice = MessagingClient(
        running_server.base_url, "+15550046", tmp_path / "alice-ack-retry", encryption_enabled=True
    )
    bob_dir = tmp_path / "bob-ack-retry"
    bob = MessagingClient(
        running_server.base_url, "+15550047", bob_dir, encryption_enabled=True
    )
    alice.register()
    bob.register()
    alice.send("+15550047", "ack retry")

    original_request = bob._request
    failed_ack = False

    def lose_ack_response(path, method="GET", payload=None, *, retries=0):
        """Commit the ACK server-side, then simulate losing its response."""
        nonlocal failed_ack
        if path.endswith("/ack") and not failed_ack:
            failed_ack = True
            original_request(path, method, payload, retries=retries)
            raise urllib.error.URLError("temporary ACK failure")
        return original_request(path, method, payload, retries=retries)

    monkeypatch.setattr(bob, "_request", lose_ack_response)
    with pytest.raises(urllib.error.URLError, match="temporary ACK failure"):
        bob.receive()
    assert running_server._messages.get("+15550047", []) == []

    restarted_bob = MessagingClient(
        running_server.base_url, "+15550047", bob_dir, encryption_enabled=True
    )
    retried = restarted_bob.receive()

    assert failed_ack
    assert retried == []
    assert [message["content"] for message in restarted_bob.history()] == ["ack retry"]
    assert restarted_bob.receive() == []


def test_valid_message_before_malformed_batch_item_is_acknowledged(running_server, tmp_path):
    """Keep processed messages recoverable when a later batch envelope is invalid."""
    alice = MessagingClient(
        running_server.base_url, "+15550048", tmp_path / "alice-batch", encryption_enabled=True
    )
    bob = MessagingClient(
        running_server.base_url, "+15550049", tmp_path / "bob-batch", encryption_enabled=True
    )
    alice.register()
    bob.register()
    alice.send("+15550049", "valid first")
    alice.send("+15550049", "malformed second")

    queued = running_server._messages["+15550049"]
    malformed_id = queued[1]["message_id"]
    queued[1]["content"] = queued[1]["content"].replace('"mac":"', '"mac":"AAAA', 1)

    with pytest.raises((AuthenticationError, ValueError)):
        bob.receive()
    assert [message["content"] for message in bob.history()] == ["valid first"]

    with pytest.raises((AuthenticationError, ValueError)):
        bob.receive()

    assert [message["message_id"] for message in running_server._messages["+15550049"]] == [
        malformed_id
    ]
    assert [message["content"] for message in bob.history()] == ["valid first"]


def test_encrypted_state_survives_new_client_instances(running_server, tmp_path):
    """Verify identity, pre-keys, and session chains survive client restarts."""
    alice_dir = tmp_path / "alice-persistent"
    bob_dir = tmp_path / "bob-persistent"
    alice = MessagingClient(running_server.base_url, "+15550026", alice_dir, encryption_enabled=True)
    bob = MessagingClient(running_server.base_url, "+15550027", bob_dir, encryption_enabled=True)
    alice.register()
    bob.register()
    alice.send("+15550027", "before restart")
    assert bob.receive()[0]["content"] == "before restart"

    restarted_alice = MessagingClient(
        running_server.base_url, "+15550026", alice_dir, encryption_enabled=True
    )
    restarted_bob = MessagingClient(
        running_server.base_url, "+15550027", bob_dir, encryption_enabled=True
    )

    sent = restarted_alice.send("+15550027", "survives restart")
    received = restarted_bob.receive()

    assert received[0]["content"] == sent["content"] == "survives restart"


def test_encrypted_clients_can_cross_initiate_before_polling(running_server, tmp_path):
    """Verify independent incoming and outgoing sessions support crossed initiation."""
    alice = MessagingClient(
        running_server.base_url, "+15550029", tmp_path / "alice-crossed", encryption_enabled=True
    )
    bob = MessagingClient(
        running_server.base_url, "+15550030", tmp_path / "bob-crossed", encryption_enabled=True
    )
    alice.register()
    bob.register()

    alice.send("+15550030", "hello from Alice")
    bob.send("+15550029", "hello from Bob")

    assert bob.receive()[0]["content"] == "hello from Alice"
    assert alice.receive()[0]["content"] == "hello from Bob"


def test_encrypted_send_retries_transient_transport_failure(
    running_server, tmp_path, monkeypatch
):
    """Verify transient send failure retries the same idempotent envelope."""
    alice = MessagingClient(
        running_server.base_url, "+15550035", tmp_path / "alice-retry", encryption_enabled=True
    )
    bob = MessagingClient(
        running_server.base_url, "+15550036", tmp_path / "bob-retry", encryption_enabled=True
    )
    alice.register()
    bob.register()
    original_urlopen = urllib.request.urlopen
    failed_once = False

    def flaky_urlopen(request, timeout):
        """Fail the first message submission before it reaches the server."""
        nonlocal failed_once
        if request.full_url.endswith("/messages") and not failed_once:
            failed_once = True
            raise urllib.error.URLError("temporary transport failure")
        return original_urlopen(request, timeout=timeout)

    monkeypatch.setattr(urllib.request, "urlopen", flaky_urlopen)

    sent = alice.send("+15550036", "retry me")
    received = bob.receive()

    assert failed_once
    assert received[0]["content"] == sent["content"] == "retry me"
    assert len(bob.receive()) == 0


def test_shared_client_state_serializes_session_updates(running_server, tmp_path):
    """Verify clients sharing local state serialize session-chain updates."""
    alice_dir = tmp_path / "alice-shared"
    bob_dir = tmp_path / "bob-shared"
    alice = MessagingClient(running_server.base_url, "+15550039", alice_dir, encryption_enabled=True)
    bob = MessagingClient(running_server.base_url, "+15550040", bob_dir, encryption_enabled=True)
    alice.register()
    bob.register()
    alice.send("+15550040", "establish session")
    assert bob.receive()[0]["content"] == "establish session"

    first_process = MessagingClient(
        running_server.base_url, "+15550039", alice_dir, encryption_enabled=True
    )
    second_process = MessagingClient(
        running_server.base_url, "+15550039", alice_dir, encryption_enabled=True
    )
    first_process.send("+15550040", "first process")
    second_process.send("+15550040", "second process")

    received = bob.receive()

    assert [message["content"] for message in received] == [
        "first process",
        "second process",
    ]
