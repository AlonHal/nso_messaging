import json
import threading
import urllib.error

import pytest
from http_helpers import (
    authenticated_request_json,
    authenticated_request_raw,
    register,
    request_json,
)

from nso_messaging.server import MessagingServer
from nso_messaging.session import PreKeyBundle, serialize_public_bundle


def test_message_is_delivered_once_without_server_chat_history(running_server):
    """Verify queued delivery and explicit ACK do not create server chat history."""
    sender = register(running_server, "+15550003")
    recipient = register(running_server, "+15550004")
    envelope = {
        "sender_id": "+15550003",
        "recipient_id": "+15550004",
        "content": "hello",
        "sent_at": "2026-09-23T12:00:00Z",
    }

    status, response = authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        envelope,
    )

    assert status == 202
    assert response["message_id"]
    assert response["recipient_id"] == "+15550004"

    status, delivered = authenticated_request_json(
        running_server.base_url + "/messages/+15550004",
        recipient["phone_number"],
        recipient["auth_key"],
        "GET",
    )
    assert status == 200
    assert len(delivered) == 1
    assert delivered[0]["content"] == "hello"
    assert delivered[0]["message_id"] == response["message_id"]

    authenticated_request_json(
        running_server.base_url + "/messages/+15550004/ack",
        recipient["phone_number"],
        recipient["auth_key"],
        "POST",
        {"message_ids": [response["message_id"]]},
    )
    _, empty = authenticated_request_json(
        running_server.base_url + "/messages/+15550004",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    assert empty == []
    assert not (running_server.data_dir / "messages").exists()


def test_polling_is_non_destructive_until_acknowledged(running_server):
    """Keep a message available across polls until the recipient acknowledges it."""
    sender = register(running_server, "+15550037")
    recipient = register(running_server, "+15550038")
    envelope = {
        "sender_id": sender["phone_number"],
        "recipient_id": recipient["phone_number"],
        "content": "ack me",
        "sent_at": "2026-09-25T12:00:00Z",
    }
    authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        envelope,
    )

    _, first_poll = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550038",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    _, repeated_poll = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550038",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    _, acknowledged = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550038/ack",
        recipient["phone_number"],
        recipient["auth_key"],
        "POST",
        {"message_ids": [first_poll[0]["message_id"]]},
    )
    _, after_ack = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550038",
        recipient["phone_number"],
        recipient["auth_key"],
    )

    assert repeated_poll == first_poll
    assert acknowledged == {"acknowledged": 1}
    assert after_ack == []


def test_repeated_message_id_is_idempotent(running_server):
    """Return the original receipt and queue only one submission on retry."""
    sender = register(running_server, "+15550033")
    recipient = register(running_server, "+15550034")
    envelope = {
        "message_id": "client-message-1",
        "sender_id": sender["phone_number"],
        "recipient_id": recipient["phone_number"],
        "content": "retry safely",
        "sent_at": "2026-09-25T12:00:00Z",
    }

    first_status, first_response = authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        envelope,
    )
    second_status, second_response = authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        envelope,
    )

    assert first_status == second_status == 202
    assert second_response == first_response
    assert first_response["message_id"] != "client-message-1"
    _, delivered = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550034",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    assert len(delivered) == 1
    assert delivered[0]["message_id"] == first_response["message_id"]
    assert delivered[0]["client_message_id"] == "client-message-1"


def test_sender_scoped_client_ids_get_distinct_delivery_ids(running_server):
    """Keep sender-local idempotency IDs separate from unique delivery IDs."""
    first_sender = register(running_server, "+15550043")
    second_sender = register(running_server, "+15550044")
    recipient = register(running_server, "+15550045")
    shared_client_id = "sender-local-id"
    responses = []

    for sender, content in (
        (first_sender, "from first sender"),
        (second_sender, "from second sender"),
    ):
        _, response = authenticated_request_json(
            running_server.base_url + "/messages",
            sender["phone_number"],
            sender["auth_key"],
            "POST",
            {
                "client_message_id": shared_client_id,
                "sender_id": sender["phone_number"],
                "recipient_id": recipient["phone_number"],
                "content": content,
                "sent_at": "2026-09-25T12:00:00Z",
            },
        )
        responses.append(response)

    _, delivered = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550045",
        recipient["phone_number"],
        recipient["auth_key"],
    )

    assert responses[0]["message_id"] != responses[1]["message_id"]
    assert len({message["message_id"] for message in delivered}) == 2
    assert {message["client_message_id"] for message in delivered} == {shared_client_id}
    assert {message["content"] for message in delivered} == {
        "from first sender",
        "from second sender",
    }


def test_incomplete_message_envelope_is_rejected(running_server):
    """Reject incomplete submissions without discarding already queued messages."""
    sender = register(running_server, "+15550008")
    recipient = register(running_server, "+15550009")
    authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        {
            "sender_id": "+15550008",
            "recipient_id": "+15550009",
            "content": "valid message",
            "sent_at": "2026-09-23T12:00:00Z",
        },
    )

    with pytest.raises(urllib.error.HTTPError) as error:
        authenticated_request_json(
            running_server.base_url + "/messages",
            sender["phone_number"],
            sender["auth_key"],
            "POST",
            {
                "sender_id": "+15550008",
                "recipient_id": "+15550009",
                "content": "missing timestamp",
            },
        )

    assert error.value.code == 400
    _, delivered = authenticated_request_json(
        running_server.base_url + "/messages/+15550009",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    assert [message["content"] for message in delivered] == ["valid message"]


def test_non_object_message_body_is_rejected(running_server):
    """Reject authenticated message bodies that decode to non-object JSON."""
    sender = register(running_server, "+15550012")
    register(running_server, "+15550013")

    with pytest.raises(urllib.error.HTTPError) as error:
        authenticated_request_raw(
            running_server.base_url + "/messages",
            sender["phone_number"],
            sender["auth_key"],
            b"null",
        )

    assert error.value.code == 400


def test_message_requests_require_hmac_and_bind_sender_to_authenticated_account(running_server):
    """Reject unsigned submissions and authenticated sender impersonation."""
    _, alice = request_json(
        running_server.base_url + "/register",
        "POST",
        {"phone_number": "+15550016"},
    )
    request_json(
        running_server.base_url + "/register",
        "POST",
        {"phone_number": "+15550017"},
    )
    envelope = {
        "sender_id": "+15550017",
        "recipient_id": "+15550016",
        "content": "forged",
        "sent_at": "2026-09-23T12:00:00Z",
    }

    with pytest.raises(urllib.error.HTTPError) as missing_auth:
        request_json(running_server.base_url + "/messages", "POST", envelope)
    assert missing_auth.value.code == 401

    with pytest.raises(urllib.error.HTTPError) as forged_sender:
        authenticated_request_json(
            running_server.base_url + "/messages",
            alice["phone_number"],
            alice["auth_key"],
            "POST",
            envelope,
        )
    assert forged_sender.value.code == 403


def test_polling_requires_authenticated_recipient_and_preserves_queue(running_server):
    """Prevent one account from reading or consuming another account's queue."""
    sender = register(running_server, "+15550031")
    recipient = register(running_server, "+15550032")
    authenticated_request_json(
        running_server.base_url + "/messages",
        sender["phone_number"],
        sender["auth_key"],
        "POST",
        {
            "sender_id": sender["phone_number"],
            "recipient_id": recipient["phone_number"],
            "content": "private message",
            "sent_at": "2026-09-25T12:00:00Z",
        },
    )

    with pytest.raises(urllib.error.HTTPError) as unauthorized_poll:
        authenticated_request_json(
            running_server.base_url + "/messages/%2B15550032",
            sender["phone_number"],
            sender["auth_key"],
        )

    assert unauthorized_poll.value.code == 403
    _, delivered = authenticated_request_json(
        running_server.base_url + "/messages/%2B15550032",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    assert [message["content"] for message in delivered] == ["private message"]


def test_public_bundle_is_published_and_one_time_key_is_consumed_on_fetch(running_server):
    """Serve exactly one public pre-key per fetch and consume it from storage."""
    account = register(running_server, "+15550014")
    bundle = serialize_public_bundle(PreKeyBundle.generate(one_time_pre_key_count=2).public_bundle())

    status, response = authenticated_request_json(
        running_server.base_url + "/bundles/%2B15550014",
        account["phone_number"],
        account["auth_key"],
        "POST",
        bundle,
    )

    assert status == 201
    assert response == {"phone_number": "+15550014", "one_time_pre_key_count": 2}

    status, fetched = authenticated_request_json(
        running_server.base_url + "/bundles/%2B15550014",
        account["phone_number"],
        account["auth_key"],
    )
    assert status == 200
    assert fetched["identity_x25519_public_key"] == bundle["identity_x25519_public_key"]
    assert len(fetched["one_time_pre_keys"]) == 1
    assert fetched["one_time_pre_keys"][0] == bundle["one_time_pre_keys"][0]
    assert "private_key" not in json.dumps(fetched)

    _, fetched_again = authenticated_request_json(
        running_server.base_url + "/bundles/%2B15550014",
        account["phone_number"],
        account["auth_key"],
    )
    assert fetched_again["one_time_pre_keys"] == [bundle["one_time_pre_keys"][1]]


def test_invalid_signed_bundle_is_rejected(running_server):
    """Reject public bundles with an invalid signed-pre-key signature."""
    account = register(running_server, "+15550025")
    bundle = serialize_public_bundle(PreKeyBundle.generate(one_time_pre_key_count=1).public_bundle())
    bundle["signed_pre_key_signature"] = "AA=="

    with pytest.raises(urllib.error.HTTPError) as error:
        authenticated_request_json(
            running_server.base_url + "/bundles/%2B15550025",
            account["phone_number"],
            account["auth_key"],
            "POST",
            bundle,
        )

    assert error.value.code == 400


def test_republishing_a_consumed_one_time_pre_key_is_rejected(running_server):
    """Reject replayed bundle publication after key consumption and restart."""
    account = register(running_server, "+15550041")
    original_bundle = serialize_public_bundle(
        PreKeyBundle.generate(one_time_pre_key_count=2).public_bundle()
    )
    bundle_url = running_server.base_url + "/bundles/%2B15550041"
    authenticated_request_json(
        bundle_url,
        account["phone_number"],
        account["auth_key"],
        "POST",
        original_bundle,
    )
    _, first_fetched = authenticated_request_json(
        bundle_url,
        account["phone_number"],
        account["auth_key"],
    )

    legacy_store = {account["phone_number"]: running_server._bundles[account["phone_number"]]}
    (running_server.data_dir / "pre_key_bundles.json").write_text(
        json.dumps(legacy_store)
    )

    restarted_server = MessagingServer("127.0.0.1", 0, running_server.data_dir)
    thread = threading.Thread(target=restarted_server.serve_forever, daemon=True)
    thread.start()
    restarted_bundle_url = restarted_server.base_url + "/bundles/%2B15550041"
    try:
        with pytest.raises(urllib.error.HTTPError) as replay:
            authenticated_request_json(
                restarted_bundle_url,
                account["phone_number"],
                account["auth_key"],
                "POST",
                original_bundle,
            )
        assert replay.value.code == 409
        _, next_fetched = authenticated_request_json(
            restarted_bundle_url,
            account["phone_number"],
            account["auth_key"],
        )
    finally:
        restarted_server.shutdown()
        thread.join(timeout=2)

    assert first_fetched["one_time_pre_keys"] == [original_bundle["one_time_pre_keys"][0]]
    assert next_fetched["one_time_pre_keys"] == [original_bundle["one_time_pre_keys"][1]]


def test_duplicate_one_time_pre_key_ids_are_rejected(running_server):
    """Reject a published pre-key batch containing duplicate IDs."""
    account = register(running_server, "+15550042")
    bundle = serialize_public_bundle(
        PreKeyBundle.generate(one_time_pre_key_count=2).public_bundle()
    )
    bundle["one_time_pre_keys"][1]["key_id"] = bundle["one_time_pre_keys"][0]["key_id"]

    with pytest.raises(urllib.error.HTTPError) as error:
        authenticated_request_json(
            running_server.base_url + "/bundles/%2B15550042",
            account["phone_number"],
            account["auth_key"],
            "POST",
            bundle,
        )

    assert error.value.code == 400


def test_public_bundles_survive_server_restart(running_server, tmp_path):
    """Restore published public bundles and remaining one-time keys after restart."""
    account = register(running_server, "+15550028")
    bundle = serialize_public_bundle(PreKeyBundle.generate(one_time_pre_key_count=2).public_bundle())
    authenticated_request_json(
        running_server.base_url + "/bundles/%2B15550028",
        account["phone_number"],
        account["auth_key"],
        "POST",
        bundle,
    )

    restarted_server = MessagingServer("127.0.0.1", 0, running_server.data_dir)
    thread = threading.Thread(target=restarted_server.serve_forever, daemon=True)
    thread.start()
    try:
        status, restored = authenticated_request_json(
            restarted_server.base_url + "/bundles/%2B15550028",
            account["phone_number"],
            account["auth_key"],
        )
    finally:
        restarted_server.shutdown()
        thread.join(timeout=2)

    assert status == 200
    assert restored["identity_x25519_public_key"] == bundle["identity_x25519_public_key"]
    assert len(restored["one_time_pre_keys"]) == 1
