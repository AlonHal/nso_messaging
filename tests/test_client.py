import threading

import pytest

from nso_messaging.client import MessagingClient
from nso_messaging.server import MessagingServer
from nso_messaging.session import PreKeyBundle


@pytest.fixture
def running_server(tmp_path):
    server = MessagingServer("127.0.0.1", 0, tmp_path / "server")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_clients_register_exchange_and_store_local_history(running_server, tmp_path):
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
    client = MessagingClient(running_server.base_url, "+15550015", tmp_path / "client")
    client.register()
    private_bundle = PreKeyBundle.generate(one_time_pre_key_count=1)

    response = client.publish_pre_key_bundle(private_bundle)
    fetched = client.fetch_pre_key_bundle()

    assert response["one_time_pre_key_count"] == 1
    assert fetched.identity_x25519_public_key == private_bundle.identity.x25519_public_bytes
    assert len(fetched.one_time_pre_keys) == 0
    assert private_bundle.one_time_pre_keys


def test_encrypted_clients_exchange_plaintext_only_in_local_history(running_server, tmp_path):
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
