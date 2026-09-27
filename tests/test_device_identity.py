import json

from nso_messaging.device_identity import (
    FINGERPRINT_SIZE,
    format_fingerprint,
    generate_device_fingerprint,
    load_or_create_device_fingerprint,
    parse_fingerprint,
    phone_digits_to_bytes,
)


def test_phone_digits_to_bytes_encodes_first_twelve_digits_one_byte_each():
    assert phone_digits_to_bytes("9725023332222") == bytes(
        [0x09, 0x07, 0x02, 0x05, 0x00, 0x02, 0x03, 0x03, 0x03, 0x02, 0x02, 0x02]
    )


def test_phone_digits_to_bytes_strips_non_digits_and_pads_short_numbers():
    assert phone_digits_to_bytes("+123") == bytes([0x01, 0x02, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0])


def test_generate_device_fingerprint_matches_documented_example_shape():
    """Verify the fingerprint's phone-derived prefix and separator byte."""
    fingerprint = generate_device_fingerprint("9725023332222")

    assert len(fingerprint) == FINGERPRINT_SIZE
    assert fingerprint[:12] == bytes(
        [0x09, 0x07, 0x02, 0x05, 0x00, 0x02, 0x03, 0x03, 0x03, 0x02, 0x02, 0x02]
    )
    assert fingerprint[12] == 0x0A


def test_generate_device_fingerprint_is_unique_per_call():
    """Verify two fingerprints for the same phone number never collide."""
    first = generate_device_fingerprint("9725023332222")
    second = generate_device_fingerprint("9725023332222")

    assert first != second
    assert first[:13] == second[:13]


def test_format_and_parse_fingerprint_round_trip():
    """Verify formatting and parsing a fingerprint is lossless."""
    fingerprint = generate_device_fingerprint("9725023332222")

    formatted = format_fingerprint(fingerprint)

    assert formatted.count("-") == FINGERPRINT_SIZE - 1
    assert parse_fingerprint(formatted) == fingerprint


def test_load_or_create_device_fingerprint_persists_and_reuses(tmp_path):
    """Verify a persisted fingerprint is reused rather than regenerated."""
    path = tmp_path / "device.json"

    first = load_or_create_device_fingerprint(path, "9725023332222")
    second = load_or_create_device_fingerprint(path, "9725023332222")

    assert first == second
    assert path.exists()
    assert json.loads(path.read_text())["device_fingerprint"] == format_fingerprint(first)


def test_load_or_create_device_fingerprint_differs_across_separate_files(tmp_path):
    """Verify separate fingerprint files never derive the same fingerprint."""
    primary_fingerprint = load_or_create_device_fingerprint(
        tmp_path / "primary.json", "9725023332222"
    )
    companion_fingerprint = load_or_create_device_fingerprint(
        tmp_path / "companion.json", "9725023332222"
    )

    assert primary_fingerprint != companion_fingerprint
    assert primary_fingerprint[:13] == companion_fingerprint[:13]
