from nso_messaging.companion_link import (
    read_companion_offer,
    write_companion_offer,
)
from nso_messaging.session import IdentityKeyPair, generate_linking_secret


def test_companion_file_offer_round_trips_linking_material(tmp_path):
    """Verify the shared-file offer carries the device ID, identity, and L_companion."""
    companion = IdentityKeyPair.generate()
    link_id = "test-link-1"

    linking_secret = generate_linking_secret()
    device_id = "companion-device-1"
    write_companion_offer(
        link_id,
        device_id,
        companion.ed25519_public_bytes,
        linking_secret,
        directory=tmp_path,
    )
    offer = read_companion_offer(link_id, directory=tmp_path)
    assert offer.device_id == device_id
    assert offer.companion_identity_ed25519_public_key == companion.ed25519_public_bytes
    assert offer.linking_secret == linking_secret


def test_default_link_directory_is_tmp():
    """Verify the default exchange directory is /tmp, per the assignment's QR-code stand-in."""
    from nso_messaging.companion_link import DEFAULT_LINK_DIR

    assert str(DEFAULT_LINK_DIR) == "/tmp"
