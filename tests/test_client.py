import threading

import pytest

from nso_messaging.client import MessagingClient
from nso_messaging.server import MessagingServer


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
