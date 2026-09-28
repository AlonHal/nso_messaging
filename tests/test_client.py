import json
import threading
import urllib.error

import pytest

from nso_messaging.client import MessagingClient
from nso_messaging.crypto import AuthenticationError
from nso_messaging.encoding import decode_bytes, encode_bytes
from nso_messaging.session import (
    CompanionLinkCertificate,
    IdentityKeyPair,
    PreKeyBundle,
    serialize_device_list,
    serialize_public_bundle,
    sign_companion_acknowledgement,
    verify_device_list_signature,
)


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


def _link_companion(primary, companion, link_id, directory):
    """Run the completed POC offer/approve/register flow for one companion."""
    companion.write_link_offer(link_id, directory=directory)
    primary.link_companion(link_id, directory=directory)
    companion.complete_companion_link(link_id, directory=directory)


def test_encrypted_send_fans_out_to_each_other_participant_device(running_server, tmp_path):
    """Encrypt one copy per participant device, excluding only the sending device."""
    alice = MessagingClient(
        running_server.base_url, "+15550060", tmp_path / "alice", encryption_enabled=True
    )
    alice_companion = MessagingClient(
        running_server.base_url,
        alice.phone_number,
        tmp_path / "alice-companion",
        client_role="companion",
        encryption_enabled=True,
    )
    bob = MessagingClient(
        running_server.base_url, "+15550061", tmp_path / "bob", encryption_enabled=True
    )
    bob_companion = MessagingClient(
        running_server.base_url,
        bob.phone_number,
        tmp_path / "bob-companion",
        client_role="companion",
        encryption_enabled=True,
    )
    alice.register()
    bob.register()
    _link_companion(alice, alice_companion, "alice-device", tmp_path)
    _link_companion(bob, bob_companion, "bob-device", tmp_path)

    sent = alice.send(bob.phone_number, "fan out to every other device")
    bob_messages = bob.receive()
    bob_companion_messages = bob_companion.receive()
    alice_companion_messages = alice_companion.receive()

    assert [message["content"] for message in bob_messages] == [sent["content"]]
    assert [message["content"] for message in bob_companion_messages] == [sent["content"]]
    assert [message["content"] for message in alice_companion_messages] == [sent["content"]]
    assert alice.receive() == []

    reply = bob_companion.send(alice.phone_number, "reply from companion")
    companion_copy = running_server._messages[(alice.phone_number, alice.device_id)][0]
    companion_header = json.loads(companion_copy["content"])["header"]
    assert companion_header["companion_link_certificate"] == running_server._registrations[
        bob.phone_number
    ]["devices"][bob_companion.device_id]["link_certificate"]

    alice_messages = alice.receive()
    alice_companion_messages = alice_companion.receive()
    bob_messages = bob.receive()

    assert [message["content"] for message in alice_messages] == [reply["content"]]
    assert [message["content"] for message in alice_companion_messages] == [reply["content"]]
    assert [message["content"] for message in bob_messages] == [reply["content"]]
    assert bob_companion.receive() == []


def test_client_lists_account_devices_and_validates_companion_proof(running_server, tmp_path):
    """Return a roster whose companion identity and signatures match the primary."""
    primary = MessagingClient(
        running_server.base_url, "+15550062", tmp_path / "primary", encryption_enabled=True
    )
    companion = MessagingClient(
        running_server.base_url,
        primary.phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    primary.register()
    _link_companion(primary, companion, "roster-link", tmp_path)

    roster = primary.fetch_devices(primary.phone_number)

    assert {device["device_id"] for device in roster["devices"]} == {
        primary.device_id,
        companion.device_id,
    }
    companion_record = next(
        device for device in roster["devices"] if device["device_id"] == companion.device_id
    )
    assert companion_record["client_role"] == "companion"


def test_encrypted_send_rejects_bundle_identity_not_in_verified_roster(running_server, tmp_path):
    """Do not establish a session with a bundle identity that contradicts its device roster."""
    sender = MessagingClient(
        running_server.base_url, "+15550063", tmp_path / "sender", encryption_enabled=True
    )
    recipient = MessagingClient(
        running_server.base_url, "+15550064", tmp_path / "recipient", encryption_enabled=True
    )
    sender.register()
    recipient.register()
    substituted_bundle = PreKeyBundle.generate().public_bundle()
    running_server._bundles[recipient.phone_number][recipient.device_id] = serialize_public_bundle(
        substituted_bundle
    )

    with pytest.raises(ValueError, match="bundle identity does not match registered device"):
        sender.send(recipient.phone_number, "must not go to a substituted identity")

    assert running_server._messages == {}


def test_receiver_rejects_tampered_companion_session_certificate(running_server, tmp_path):
    """Reject companion session setup if its carried link proof is tampered."""
    sender_primary = MessagingClient(
        running_server.base_url, "+15550065", tmp_path / "sender-primary", encryption_enabled=True
    )
    sender_companion = MessagingClient(
        running_server.base_url,
        sender_primary.phone_number,
        tmp_path / "sender-companion",
        client_role="companion",
        encryption_enabled=True,
    )
    recipient = MessagingClient(
        running_server.base_url, "+15550066", tmp_path / "recipient", encryption_enabled=True
    )
    sender_primary.register()
    recipient.register()
    _link_companion(sender_primary, sender_companion, "sender-proof-test", tmp_path)
    sender_companion.send(recipient.phone_number, "tamper companion proof")

    recipient_queue = (recipient.phone_number, recipient.device_id)
    queued_message = running_server._messages[recipient_queue][0]
    envelope = json.loads(queued_message["content"])
    certificate = envelope["header"]["companion_link_certificate"]
    certificate["companion_signature"] = encode_bytes(bytes(64))
    queued_message["content"] = json.dumps(envelope)

    with pytest.raises(ValueError, match="invalid link certificate"):
        recipient.receive()

    assert recipient.history() == []


def test_dh_ratchet_rotates_ephemeral_on_conversation_turn(running_server, tmp_path):
    """Reuse the pairwise session and advertise a fresh ephemeral on reply."""
    alice = MessagingClient(
        running_server.base_url, "+15550067", tmp_path / "alice", encryption_enabled=True
    )
    bob = MessagingClient(
        running_server.base_url, "+15550068", tmp_path / "bob", encryption_enabled=True
    )
    alice.register()
    bob.register()

    alice.send(bob.phone_number, "first turn")
    bob_queue = (bob.phone_number, bob.device_id)
    first_header = json.loads(running_server._messages[bob_queue][0]["content"])["header"]
    alice.send(bob.phone_number, "same sending turn")
    same_turn_header = json.loads(running_server._messages[bob_queue][1]["content"])["header"]
    assert same_turn_header["ratchet_public_key"] != first_header["ratchet_public_key"]
    assert [message["content"] for message in bob.receive()] == [
        "first turn",
        "same sending turn",
    ]
    bob.send(alice.phone_number, "reply turn")

    alice_queue = (alice.phone_number, alice.device_id)
    reply_header = json.loads(running_server._messages[alice_queue][0]["content"])["header"]

    assert reply_header["ephemeral_public_key"] == first_header["ephemeral_public_key"]
    assert reply_header["ratchet_public_key"] != same_turn_header["ratchet_public_key"]
    assert alice.receive()[0]["content"] == "reply turn"

    alice_session = alice._crypto.sessions[f"{bob.phone_number}/{bob.device_id}"]
    bob_session = bob._crypto.incoming_sessions[
        (f"{alice.phone_number}/{alice.device_id}", first_header["ephemeral_public_key"])
    ]
    assert alice_session.state.root_key == bob_session.state.root_key
    assert alice_session.state.send_chain_key == bob_session.state.receive_chain_key
    assert alice_session.state.receive_chain_key == bob_session.state.send_chain_key

    alice.send(bob.phone_number, "second turn")
    second_copy = running_server._messages[bob_queue][0]
    second_header = json.loads(second_copy["content"])["header"]
    assert second_header["ratchet_public_key"] != reply_header["ratchet_public_key"]
    assert bob.receive()[0]["content"] == "second turn"


def test_client_registers_a_stable_device_identity(running_server, tmp_path):
    """Verify registration binds a persistent local device ID to its server record."""
    state_dir = tmp_path / "stable-device"
    client = MessagingClient(
        running_server.base_url, "+15550014", state_dir, encryption_enabled=True
    )

    registration = client.register()
    device_id = client.device_id

    assert registration["device_id"] == device_id
    assert running_server._registrations[client.phone_number]["devices"][device_id][
        "client_role"
    ] == "primary"
    restarted = MessagingClient(
        running_server.base_url, client.phone_number, state_dir, encryption_enabled=True
    )
    assert restarted.device_id == device_id


def test_direct_client_uses_global_configured_request_timeout(tmp_path, monkeypatch):
    """Apply process config to clients constructed directly by debugger tests."""
    config_path = tmp_path / "debug-timeouts.json"
    config_path.write_text(json.dumps({"request_timeout": None}))
    monkeypatch.setenv("NSO_MESSAGING_CONFIG", str(config_path))

    client = MessagingClient("http://localhost", "+15550014", tmp_path / "client")
    explicit_timeout_client = MessagingClient(
        "http://localhost",
        "+15550015",
        tmp_path / "explicit-client",
        request_timeout=12,
    )

    assert client.request_timeout is None
    assert explicit_timeout_client.request_timeout == 12


def test_client_listen_yields_messages_until_stopped(tmp_path, monkeypatch):
    """Poll through receive and yield messages until a stop event is set."""
    client = MessagingClient("http://localhost", "+15550025", tmp_path / "listener")
    stop_event = threading.Event()
    message = {"message_id": "message-1", "content": "hello"}
    calls = 0

    def receive():
        nonlocal calls
        calls += 1
        if calls == 1:
            return [message]
        stop_event.set()
        return []

    monkeypatch.setattr(client, "receive", receive)

    assert list(client.listen(poll_interval=0.001, stop_event=stop_event)) == [message]
    assert calls == 2


@pytest.mark.parametrize("poll_interval", [0, -1, float("inf"), float("nan")])
def test_client_listen_rejects_invalid_poll_intervals(tmp_path, poll_interval):
    """Avoid a busy loop or invalid wait duration in the long-running listener."""
    client = MessagingClient("http://localhost", "+15550025", tmp_path / "listener")

    with pytest.raises(ValueError, match="poll_interval"):
        list(client.listen(poll_interval=poll_interval))


def test_primary_and_verified_companion_have_separate_server_device_records(
    running_server, tmp_path
):
    """Verify a companion joins the account only with a valid two-party certificate."""
    primary = MessagingClient(
        running_server.base_url, "+15550017", tmp_path / "primary", encryption_enabled=True
    )
    primary.register()
    companion = MessagingClient(
        running_server.base_url,
        primary.phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    link_id = "verified-device-record-link"
    companion.write_link_offer(link_id, directory=tmp_path)
    primary.link_companion(link_id, directory=tmp_path)
    registration = companion.complete_companion_link(link_id, directory=tmp_path)
    account_devices = running_server._registrations[primary.phone_number]["devices"]

    assert registration["device_id"] == companion.device_id
    assert set(account_devices) == {primary.device_id, companion.device_id}
    assert account_devices[companion.device_id]["client_role"] == "companion"
    assert companion.fetch_pre_key_bundle().identity_ed25519_public_key == (
        companion.identity.ed25519_public_bytes
    )


def test_primary_server_companion_linking_exchange(running_server, tmp_path):
    """Complete QR-file linking through server forwarding and verified registration."""
    phone_number = "+15550018"
    primary = MessagingClient(
        running_server.base_url, phone_number, tmp_path / "primary", encryption_enabled=True
    )
    companion = MessagingClient(
        running_server.base_url,
        phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    primary.register()
    link_id = "pairing-test-18"

    companion.write_link_offer(link_id, directory=tmp_path)
    primary.link_companion(link_id, directory=tmp_path)
    registration = companion.complete_companion_link(link_id, directory=tmp_path)

    account = running_server._registrations[phone_number]
    device_list_data = decode_bytes(account["device_list_data"])
    list_signature = decode_bytes(account["device_list_signature"])
    assert verify_device_list_signature(
        primary.identity.ed25519_public_bytes, device_list_data, list_signature
    )
    assert registration["device_id"] == companion.device_id
    assert account["devices"][companion.device_id]["client_role"] == "companion"
    assert companion._crypto.primary_identity_ed25519_public_key == (
        primary.identity.ed25519_public_bytes
    )
    assert companion._crypto.link_metadata
    assert companion.fetch_pre_key_bundle().identity_ed25519_public_key == (
        companion.identity.ed25519_public_bytes
    )
    restarted_companion = MessagingClient(
        running_server.base_url,
        phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    assert restarted_companion._crypto.primary_identity_ed25519_public_key == (
        primary.identity.ed25519_public_bytes
    )
    assert restarted_companion._crypto.link_metadata == companion._crypto.link_metadata


def test_companion_rejects_server_forwarded_link_with_tampered_hmac(running_server, tmp_path):
    """Reject a server response that fails PHMAC before companion registration."""
    phone_number = "+15550022"
    primary = MessagingClient(
        running_server.base_url, phone_number, tmp_path / "primary", encryption_enabled=True
    )
    companion = MessagingClient(
        running_server.base_url,
        phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    primary.register()
    link_id = "bad-phmac-22"
    companion.write_link_offer(link_id, directory=tmp_path)
    primary.link_companion(link_id, directory=tmp_path)
    running_server._registrations[phone_number]["pending_links"][companion.device_id][
        "linking_hmac"
    ] = encode_bytes(bytes(32))

    with pytest.raises(ValueError, match="linking HMAC"):
        companion.complete_companion_link(link_id, directory=tmp_path)

    assert companion.device_id not in running_server._registrations[phone_number]["devices"]


def test_primary_does_not_persist_device_list_when_link_upload_fails(
    running_server, tmp_path, monkeypatch
):
    """Keep local signed device state unchanged when the server rejects a link upload."""
    phone_number = "+15550023"
    primary = MessagingClient(
        running_server.base_url, phone_number, tmp_path / "primary", encryption_enabled=True
    )
    companion = MessagingClient(
        running_server.base_url,
        phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    primary.register()
    link_id = "failed-link-23"
    companion.write_link_offer(link_id, directory=tmp_path)

    def reject_link(path, method="GET", payload=None, *, retries=0):
        raise RuntimeError("simulated link upload rejection")

    monkeypatch.setattr(primary, "_request", reject_link)
    with pytest.raises(RuntimeError, match="simulated link upload rejection"):
        primary.link_companion(link_id, directory=tmp_path)

    assert primary._crypto.companion_identity_ed25519_public_keys == []


def test_server_rejects_companion_with_a_tampered_link_signature(running_server, tmp_path):
    """Reject invalid companion proofs without adding a server device record."""
    primary = MessagingClient(
        running_server.base_url, "+15550020", tmp_path / "primary", encryption_enabled=True
    )
    primary.register()
    companion = MessagingClient(
        running_server.base_url,
        primary.phone_number,
        tmp_path / "companion",
        client_role="companion",
        encryption_enabled=True,
    )
    metadata = b"tampered-link-metadata"
    certificate = CompanionLinkCertificate(
        primary_identity_ed25519_public_key=primary.identity.ed25519_public_bytes,
        companion_identity_ed25519_public_key=companion.identity.ed25519_public_bytes,
        metadata=metadata,
        primary_signature=bytes(64),
        companion_signature=sign_companion_acknowledgement(
            companion.identity, primary.identity.ed25519_public_bytes, metadata
        ),
    )

    with pytest.raises(urllib.error.HTTPError) as error:
        companion.register(link_certificate=certificate)

    assert error.value.code == 400
    assert set(running_server._registrations[primary.phone_number]["devices"]) == {
        primary.device_id
    }


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


def test_primary_updates_and_persists_signed_companion_device_list(tmp_path):
    """Verify a linked companion is added to the durable, primary-signed device list."""
    state_dir = tmp_path / "primary"
    client = MessagingClient("http://localhost", "+15550016", state_dir, encryption_enabled=True)
    companion = IdentityKeyPair.generate()

    payload = client.update_device_list(companion.ed25519_public_bytes)
    device_list_data = decode_bytes(payload["device_list_data"])
    list_signature = decode_bytes(payload["list_signature"])

    assert device_list_data == serialize_device_list([companion.ed25519_public_bytes])
    assert verify_device_list_signature(
        client.identity.ed25519_public_bytes, device_list_data, list_signature
    )

    restarted = MessagingClient(
        "http://localhost", "+15550016", state_dir, encryption_enabled=True
    )
    assert restarted.update_device_list(companion.ed25519_public_bytes) == payload


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

    recipient_queue = (bob.phone_number, bob.device_id)
    envelope = running_server._messages[recipient_queue][0]["content"]
    tampered = envelope.replace("ciphertext", "ciphertext-tampered", 1)
    running_server._messages[recipient_queue][0]["content"] = tampered

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
    assert running_server._messages.get((bob.phone_number, bob.device_id), []) == []

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

    recipient_queue = (bob.phone_number, bob.device_id)
    queued = running_server._messages[recipient_queue]
    malformed_id = queued[1]["message_id"]
    queued[1]["content"] = queued[1]["content"].replace('"mac":"', '"mac":"AAAA', 1)

    with pytest.raises((AuthenticationError, ValueError)):
        bob.receive()
    assert [message["content"] for message in bob.history()] == ["valid first"]

    with pytest.raises((AuthenticationError, ValueError)):
        bob.receive()

    assert [message["message_id"] for message in running_server._messages[recipient_queue]] == [
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
    bob.send("+15550026", "ratchet state before restart")
    assert alice.receive()[0]["content"] == "ratchet state before restart"

    restarted_alice = MessagingClient(
        running_server.base_url, "+15550026", alice_dir, encryption_enabled=True
    )
    restarted_bob = MessagingClient(
        running_server.base_url, "+15550027", bob_dir, encryption_enabled=True
    )

    sent = restarted_alice.send("+15550027", "survives ratchet restart")
    received = restarted_bob.receive()

    assert received[0]["content"] == sent["content"] == "survives ratchet restart"


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

    reply = alice.send("+15550030", "reply on Bob's initiated session")
    received_reply = bob.receive()

    assert received_reply[0]["content"] == reply["content"]


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
