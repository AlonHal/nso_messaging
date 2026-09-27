import json
import urllib.error

import pytest
from http_helpers import request_json, request_raw


def test_registration_persists_account_configuration(running_server):
    """Return and persist account configuration with a fresh auth credential."""
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
        "device_id": response["device_id"],
        "auth_key": None,
    }
    assert isinstance(response["auth_key"], str)
    stored_account = json.loads(
        (running_server.data_dir / "registrations.json").read_text()
    )["+15550001"]
    assert stored_account["phone_number"] == response["phone_number"]
    assert stored_account["name"] == response["name"]
    assert stored_account["primary_device_id"] == response["device_id"]
    assert stored_account["devices"][response["device_id"]] == {
        "device_id": response["device_id"],
        "client_role": "primary",
        "encryption_enabled": False,
        "auth_key": response["auth_key"],
    }


def test_duplicate_registration_is_rejected(running_server):
    """Reject registering an account identifier more than once."""
    payload = {"phone_number": "+15550002", "name": "Bob"}
    request_json(running_server.base_url + "/register", "POST", payload)

    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(running_server.base_url + "/register", "POST", payload)

    assert error.value.code == 409


@pytest.mark.parametrize("body", [b"null", b"[]", b'"text"', b"42"])
def test_non_object_registration_body_is_rejected(running_server, body):
    """Reject registration bodies that are valid JSON but not objects."""
    with pytest.raises(urllib.error.HTTPError) as error:
        request_raw(running_server.base_url + "/register", body)

    assert error.value.code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {"phone_number": "+15550005", "client_role": "companion"},
        {"phone_number": "+15550006", "client_role": "tablet"},
        {"phone_number": "+15550007", "encryption_enabled": "false"},
    ],
)
def test_unsupported_registration_modes_are_rejected(running_server, payload):
    """Reject unsupported device roles and non-boolean encryption settings."""
    with pytest.raises(urllib.error.HTTPError) as error:
        request_json(running_server.base_url + "/register", "POST", payload)

    assert error.value.code == 400
