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


def request_raw(url, body):
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status, json.load(response)


def test_registration_persists_account_configuration(running_server):
    status, response = request_json(
        running_server.base_url + "/register",
        "POST",
        {
            "phone_number": "+15550001",
            "name": "Alice",
            "client_role": "primary",
            "encryption_enabled": False,
        },
    )

    assert status == 201
    assert response | {"auth_key": None} == {
        "phone_number": "+15550001",
        "name": "Alice",
        "client_role": "primary",
        "encryption_enabled": False,
        "auth_key": None,
    }
    assert isinstance(response["auth_key"], str)
    assert json.loads((running_server.data_dir / "registrations.json").read_text()) == {
        "+15550001": response
    }


def test_duplicate_registration_is_rejected(running_server):
    payload = {"phone_number": "+15550002", "name": "Bob"}
    request_json(running_server.base_url + "/register", "POST", payload)

    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(running_server.base_url + "/register", "POST", payload)

    assert error.value.code == 409


@pytest.mark.parametrize("body", [b"null", b"[]", b'"text"', b"42"])
def test_non_object_registration_body_is_rejected(running_server, body):
    with pytest.raises(urllib.error.HTTPError) as error:
        request_raw(running_server.base_url + "/register", body)

    assert error.value.code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {"phone_number": "+15550005", "client_role": "companion"},
        {"phone_number": "+15550007", "encryption_enabled": "false"},
    ],
)
def test_unsupported_registration_modes_are_rejected(running_server, payload):
    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(running_server.base_url + "/register", "POST", payload)

    assert error.value.code == 400
