import base64
import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request

import pytest

from nso_messaging.server import MessagingServer
from nso_messaging.session import PreKeyBundle, serialize_public_bundle


@pytest.fixture
def running_server(tmp_path):
    server = MessagingServer("127.0.0.1", 0, tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=2)


def request_json(url, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def authenticated_request_json(url, account_id, auth_key, method="GET", payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    path = url[url.index("/", len("http://")) :]
    signing_input = method.encode() + b"\n" + path.encode() + b"\n" + (data or b"")
    secret = base64.urlsafe_b64decode(auth_key.encode())
    signature = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Auth-Account": account_id,
            "X-Auth-Signature": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def authenticated_request_raw(url, account_id, auth_key, body, method="POST"):
    path = url[url.index("/", len("http://")) :]
    signing_input = method.encode() + b"\n" + path.encode() + b"\n" + body
    secret = base64.urlsafe_b64decode(auth_key.encode())
    signature = hmac.new(secret, signing_input, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Auth-Account": account_id,
            "X-Auth-Signature": signature,
        },
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def register(server, phone_number):
    _, account = request_json(
        server.base_url + "/register",
        "POST",
        {"phone_number": phone_number},
    )
    return account


def test_message_is_delivered_once_without_server_chat_history(running_server):
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

    _, empty = authenticated_request_json(
        running_server.base_url + "/messages/+15550004",
        recipient["phone_number"],
        recipient["auth_key"],
    )
    assert empty == []
    assert not (running_server.data_dir / "messages").exists()


def test_incomplete_message_envelope_is_rejected(running_server):
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


def test_public_bundle_is_published_and_one_time_key_is_consumed_on_fetch(running_server):
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
    assert "private_key" not in json.dumps(fetched)

    _, fetched_again = authenticated_request_json(
        running_server.base_url + "/bundles/%2B15550014",
        account["phone_number"],
        account["auth_key"],
    )
    assert fetched_again["one_time_pre_keys"] == []
