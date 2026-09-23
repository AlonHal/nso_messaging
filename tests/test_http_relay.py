import json
import threading
import urllib.error
import urllib.request

import pytest

from nso_messaging.server import MessagingServer


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


def register(server, phone_number):
    request_json(
        server.base_url + "/register",
        "POST",
        {"phone_number": phone_number},
    )


def test_message_is_delivered_once_without_server_chat_history(running_server):
    register(running_server, "+15550003")
    register(running_server, "+15550004")
    envelope = {
        "sender_id": "+15550003",
        "recipient_id": "+15550004",
        "content": "hello",
        "sent_at": "2026-09-23T12:00:00Z",
    }

    status, response = request_json(
        running_server.base_url + "/messages",
        "POST",
        envelope,
    )

    assert status == 202
    assert response["message_id"]
    assert response["recipient_id"] == "+15550004"

    status, delivered = request_json(
        running_server.base_url + "/messages/+15550004",
        "GET",
    )
    assert status == 200
    assert len(delivered) == 1
    assert delivered[0]["content"] == "hello"
    assert delivered[0]["message_id"] == response["message_id"]

    _, empty = request_json(running_server.base_url + "/messages/+15550004")
    assert empty == []
    assert not (running_server.data_dir / "messages").exists()


def test_incomplete_message_envelope_is_rejected(running_server):
    register(running_server, "+15550008")
    register(running_server, "+15550009")
    request_json(
        running_server.base_url + "/messages",
        "POST",
        {
            "sender_id": "+15550008",
            "recipient_id": "+15550009",
            "content": "valid message",
            "sent_at": "2026-09-23T12:00:00Z",
        },
    )

    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(
            running_server.base_url + "/messages",
            "POST",
            {
                "sender_id": "+15550008",
                "recipient_id": "+15550009",
                "content": "missing timestamp",
            },
        )

    assert error.value.code == 400
    _, delivered = request_json(running_server.base_url + "/messages/+15550009")
    assert [message["content"] for message in delivered] == ["valid message"]


def test_non_object_message_body_is_rejected(running_server):
    register(running_server, "+15550012")
    register(running_server, "+15550013")
    request = urllib.request.Request(
        running_server.base_url + "/messages",
        data=b"null",
        method="POST",
        headers={"Content-Type": "application/json"},
    )

    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, timeout=2)

    assert error.value.code == 400
