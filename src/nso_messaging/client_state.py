"""Encapsulated persistent encrypted state for one client device.

Groups the directory/file/lock paths, in-memory sessions, and processed-
message journal that were previously scattered across ``MessagingClient``
attributes into one component, composed rather than inlined.
"""

import fcntl
import json
from contextlib import contextmanager
from pathlib import Path

from .encoding import decode_bytes, encode_bytes
from .json_store import write_json_atomic
from .session import (
    PreKeyBundle,
    Session,
    deserialize_private_bundle,
    deserialize_session,
    serialize_private_bundle,
    serialize_session,
)


class ClientCryptoState:
    """Own one device's identity, pre-keys, sessions, and their on-disk state.

    ``sessions`` holds outgoing sessions keyed by recipient id; ``incoming_sessions``
    holds sessions keyed by ``(sender_id, session_id)`` so crossed initiation
    (both peers starting a session before either replies) cannot collide.
    """

    def __init__(self, state_dir: Path, fingerprint: str):
        """Bind this state to a device fingerprint's directory under ``state_dir``."""
        self.directory = state_dir / "crypto" / fingerprint
        self.path = self.directory / "state.json"
        self.lock_path = self.directory / "state.lock"
        self.pre_key_bundle: PreKeyBundle | None = None
        self.sessions: dict[str, Session] = {}
        self.incoming_sessions: dict[tuple[str, str], Session] = {}
        self.active_sessions: dict[str, str] = {}
        self.processed_incoming: dict[str, dict] = {}
        self.companion_identity_ed25519_public_keys: list[bytes] = []
        self.primary_identity_ed25519_public_key: bytes | None = None
        self.link_metadata: bytes | None = None

    @property
    def identity(self):
        """Return the device identity owned by the current pre-key bundle."""
        return None if self.pre_key_bundle is None else self.pre_key_bundle.identity

    def load_or_create(self) -> None:
        """Restore persisted state, or generate and persist a fresh identity."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.lock():
            if self.path.exists():
                self.restore()
                return
            self.pre_key_bundle = PreKeyBundle.generate()
            self.save()

    def restore(self) -> None:
        """Load identity, pre-keys, sessions, and pending deliveries from disk."""
        data = json.loads(self.path.read_text())
        self.pre_key_bundle = deserialize_private_bundle(data["pre_key_bundle"])
        self.sessions = {
            recipient_id: deserialize_session(entry)
            for recipient_id, entry in data.get("sessions", {}).items()
        }
        self.incoming_sessions = {
            (entry["peer_id"], entry["session_id"]): deserialize_session(entry)
            for entry in data.get("incoming_sessions", [])
        }
        self.active_sessions = data.get("active_sessions", {})
        self.processed_incoming = data.get("processed_incoming", {})
        self.companion_identity_ed25519_public_keys = [
            decode_bytes(encoded_key)
            for encoded_key in data.get("companion_identity_ed25519_public_keys", [])
        ]
        encoded_primary_key = data.get("primary_identity_ed25519_public_key")
        self.primary_identity_ed25519_public_key = (
            None if encoded_primary_key is None else decode_bytes(encoded_primary_key)
        )
        encoded_metadata = data.get("link_metadata")
        self.link_metadata = None if encoded_metadata is None else decode_bytes(encoded_metadata)

    def save(self) -> None:
        """Persist the current state atomically and restrict its permissions."""
        self.directory.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "pre_key_bundle": serialize_private_bundle(self.pre_key_bundle),
            "sessions": {
                recipient_id: serialize_session(session)
                for recipient_id, session in self.sessions.items()
            },
            "incoming_sessions": [
                {"peer_id": peer_id, "session_id": session_id, **serialize_session(session)}
                for (peer_id, session_id), session in self.incoming_sessions.items()
            ],
            "active_sessions": self.active_sessions,
            "processed_incoming": self.processed_incoming,
            "companion_identity_ed25519_public_keys": [
                encode_bytes(key)
                for key in self.companion_identity_ed25519_public_keys
            ],
            "primary_identity_ed25519_public_key": (
                None
                if self.primary_identity_ed25519_public_key is None
                else encode_bytes(self.primary_identity_ed25519_public_key)
            ),
            "link_metadata": None if self.link_metadata is None else encode_bytes(self.link_metadata),
        }
        write_json_atomic(self.path, data)
        self.path.chmod(0o600)

    @contextmanager
    def lock(self):
        """Serialize state updates across processes sharing this directory."""
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
