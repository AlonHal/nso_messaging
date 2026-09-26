from nso_messaging.companion_link import (
    read_companion_offer,
    read_primary_link_response,
    write_companion_offer,
    write_primary_link_response,
)
from nso_messaging.session import (
    CompanionLinkCertificate,
    IdentityKeyPair,
    sign_companion_acknowledgement,
    sign_companion_link,
    verify_companion_link_certificate,
)


def test_full_file_based_link_exchange_produces_a_verified_certificate(tmp_path):
    """Verify the /tmp-file exchange (QR-code stand-in) yields a valid certificate."""
    primary = IdentityKeyPair.generate()
    companion = IdentityKeyPair.generate()
    link_id = "test-link-1"
    metadata = b"nso-companion-link"

    write_companion_offer(link_id, companion.ed25519_public_bytes, directory=tmp_path)
    offered_companion_key = read_companion_offer(link_id, directory=tmp_path)

    primary_signature = sign_companion_link(primary, offered_companion_key, metadata)
    write_primary_link_response(
        link_id,
        primary.ed25519_public_bytes,
        metadata,
        primary_signature,
        directory=tmp_path,
    )
    primary_key, read_metadata, read_primary_signature = read_primary_link_response(
        link_id, directory=tmp_path
    )
    companion_signature = sign_companion_acknowledgement(companion, primary_key, read_metadata)

    certificate = CompanionLinkCertificate(
        primary_identity_ed25519_public_key=primary_key,
        companion_identity_ed25519_public_key=offered_companion_key,
        metadata=read_metadata,
        primary_signature=read_primary_signature,
        companion_signature=companion_signature,
    )

    assert verify_companion_link_certificate(certificate)


def test_default_link_directory_is_tmp():
    """Verify the default exchange directory is /tmp, per the assignment's QR-code stand-in."""
    from nso_messaging.companion_link import DEFAULT_LINK_DIR

    assert str(DEFAULT_LINK_DIR) == "/tmp"
