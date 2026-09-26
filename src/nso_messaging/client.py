"""Primary client with HTTP transport and local SQLite message history."""

import base64
import fcntl
import hashlib
import hmac
import json
import logging
import sqlite3
import urllib.error
import urllib.request
import uuid
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .config import DEFAULT_REQUEST_TIMEOUT
from .crypto import decrypt_message, derive_message_key, encrypt_message
from .session import (
    PreKeyBundle,
    PublicPreKeyBundle,
    SessionHeader,
    SessionState,
    deserialize_private_bundle,
    deserialize_public_bundle,
    establish_initiator_session,
    establish_responder_session,
    serialize_private_bundle,
    serialize_public_bundle,
)

logger = logging.getLogger(__name__)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(encoded: str) -> bytes:
    return base64.b64decode(encoded)


def _serialize_session_header(header: SessionHeader) -> dict:
    return {
        "identity_public_key": _b64(header.identity_public_key),
        "ephemeral_public_key": _b64(header.ephemeral_public_key),
        "one_time_pre_key_id": header.one_time_pre_key_id,
    }


def _deserialize_session_header(data: dict) -> SessionHeader:
    return SessionHeader(
        identity_public_key=_unb64(data["identity_public_key"]),
        ephemeral_public_key=_unb64(data["ephemeral_public_key"]),
        one_time_pre_key_id=data.get("one_time_pre_key_id"),
    )


def _session_id(header: SessionHeader) -> str:
    """Identify an initiated session by its unique ephemeral public key."""
    return _b64(header.ephemeral_public_key)


def _serialize_session_state(state: SessionState) -> dict:
    return {
        "root_key": _b64(state.root_key),
        "send_chain_key": _b64(state.send_chain_key),
        "receive_chain_key": _b64(state.receive_chain_key),
        "identity_public_key": _b64(state.identity_public_key),
    }


def _deserialize_session_state(data: dict) -> SessionState:
    return SessionState(
        root_key=_unb64(data["root_key"]),
        send_chain_key=_unb64(data["send_chain_key"]),
        receive_chain_key=_unb64(data["receive_chain_key"]),
        identity_public_key=_unb64(data["identity_public_key"]),
    )


class MessagingClient:
    """Register, send, receive, and locally store plaintext messages.

    The client supports primary-only plaintext or session-encrypted messaging.
    """

    def __init__(
        self,
        server_url: str,
        phone_number: str,
        state_dir: str | Path,
        *,
        client_role: str = "primary",
        encryption_enabled: bool = False,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ):
        """Create a client and initialize its local SQLite history database.

        ``request_timeout`` bounds how long ``urlopen`` waits for the server to
        respond; raise it (or load a config file) when stepping through server
        code under a debugger so requests don't time out mid-breakpoint.
        """
        if client_role != "primary":
            raise NotImplementedError("Only the primary client role is currently supported")
        self.server_url = server_url.rstrip("/")
        self.phone_number = phone_number
        self.client_role = client_role
        self.encryption_enabled = encryption_enabled
        self.request_timeout = request_timeout
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = self.state_dir / "messages.sqlite3"
        self.credentials_path = self.state_dir / "credentials.json"
        fingerprint = hashlib.sha256(phone_number.encode()).hexdigest()
        self.crypto_state_dir = self.state_dir / "crypto" / fingerprint
        self.crypto_state_path = self.crypto_state_dir / "state.json"
        self.crypto_lock_path = self.crypto_state_dir / "state.lock"
        self.auth_key = self._load_auth_key()
        self.identity = None
        self.pre_key_bundle = None
        self._sessions: dict[str, SessionState] = {}
        self._session_headers: dict[str, SessionHeader] = {}
        self._incoming_sessions: dict[tuple[str, str], SessionState] = {}
        self._incoming_headers: dict[tuple[str, str], SessionHeader] = {}
        if encryption_enabled:
            self._load_or_create_crypto_state()
        self._initialize_database()
        logger.info("client initialized for local account")

    def register(self, name: str | None = None):
        """Register this client and return the server's account record.

        Registration is intentionally separate from local history creation so a
        client can be initialized offline before connecting to a server.
        """
        payload = {
            "phone_number": self.phone_number,
            "name": name,
            "client_role": self.client_role,
            "encryption_enabled": self.encryption_enabled,
        }
        result = self._request("/register", "POST", payload)
        self.auth_key = result["auth_key"]
        self._save_auth_key()
        if self.encryption_enabled:
            self.publish_pre_key_bundle(self.pre_key_bundle)
        logger.info("client registration completed")
        return {key: value for key, value in result.items() if key != "auth_key"}

    def publish_pre_key_bundle(self, bundle: PreKeyBundle):
        """Publish this client's public pre-key material without private keys."""
        payload = serialize_public_bundle(bundle.public_bundle())
        return self._request(f"/bundles/{quote(self.phone_number, safe='')}", "POST", payload)

    def fetch_pre_key_bundle(self, recipient_id: str | None = None) -> PublicPreKeyBundle:
        """Fetch and deserialize one recipient's currently available public bundle."""
        account_id = self.phone_number if recipient_id is None else recipient_id
        payload = self._request(f"/bundles/{quote(account_id, safe='')}")
        return deserialize_public_bundle(payload)

    def send(self, recipient_id: str, content: str):
        """Send one message and store the sent copy locally.

        The server assigns the authoritative message id. The client replaces
        its provisional id with that value before writing local history.
        """
        if self.encryption_enabled:
            return self._send_encrypted(recipient_id, content)
        message = {
            "message_id": str(uuid.uuid4()),
            "sender_id": self.phone_number,
            "recipient_id": recipient_id,
            "content": content,
            "sent_at": datetime.now(UTC).isoformat(),
        }
        response = self._request("/messages", "POST", message)
        message["message_id"] = response["message_id"]
        self._store_message(message, "sent")
        logger.info("message sent; local history updated")
        return message

    def receive(self):
        """Poll the server, store delivered messages, and return them.

        The local primary key makes repeated processing of the same envelope
        harmless if a caller retries its history operation.
        """
        messages = self._request(f"/messages/{self.phone_number}")
        acknowledged_ids = []
        for index, message in enumerate(messages):
            if self.encryption_enabled:
                message = self._decrypt_envelope(message)
                messages[index] = message
            self._store_message(message, "received")
            acknowledged_ids.append(message["message_id"])
        if acknowledged_ids:
            self._request(
                f"/messages/{quote(self.phone_number, safe='')}/ack",
                "POST",
                {"message_ids": acknowledged_ids},
            )
        logger.info("messages received; count=%d", len(messages))
        return messages

    def _load_or_create_crypto_state(self):
        """Restore or initialize encrypted identity, pre-keys, and sessions."""
        self.crypto_state_dir.mkdir(parents=True, exist_ok=True)
        with self._crypto_state_lock():
            if self.crypto_state_path.exists():
                self._restore_crypto_state()
                return
            self.pre_key_bundle = PreKeyBundle.generate()
            self.identity = self.pre_key_bundle.identity
            self._save_crypto_state()

    def _restore_crypto_state(self):
        """Load encrypted state after the caller has acquired the state lock."""
        state = json.loads(self.crypto_state_path.read_text())
        self.pre_key_bundle = deserialize_private_bundle(state["pre_key_bundle"])
        self.identity = self.pre_key_bundle.identity
        self._sessions = {}
        self._session_headers = {}
        self._incoming_sessions = {}
        self._incoming_headers = {}
        for recipient_id, session in state.get("sessions", {}).items():
            self._sessions[recipient_id] = _deserialize_session_state(session["state"])
            self._session_headers[recipient_id] = _deserialize_session_header(session["header"])
        for session in state.get("incoming_sessions", []):
            key = (session["peer_id"], session["session_id"])
            self._incoming_sessions[key] = _deserialize_session_state(session["state"])
            self._incoming_headers[key] = _deserialize_session_header(session["header"])

    @contextmanager
    def _crypto_state_lock(self):
        """Serialize encrypted state updates across client processes."""
        self.crypto_state_dir.mkdir(parents=True, exist_ok=True)
        with self.crypto_lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _save_crypto_state(self):
        """Persist private encrypted state under the phone fingerprint directory."""
        self.crypto_state_dir.mkdir(parents=True, exist_ok=True)
        state = {
            "version": 1,
            "pre_key_bundle": serialize_private_bundle(self.pre_key_bundle),
            "sessions": {
                recipient_id: {
                    "state": _serialize_session_state(session),
                    "header": _serialize_session_header(self._session_headers[recipient_id]),
                }
                for recipient_id, session in self._sessions.items()
            },
            "incoming_sessions": [
                {
                    "peer_id": peer_id,
                    "session_id": session_id,
                    "state": _serialize_session_state(session),
                    "header": _serialize_session_header(self._incoming_headers[(peer_id, session_id)]),
                }
                for (peer_id, session_id), session in self._incoming_sessions.items()
            ],
        }
        temporary_path = self.crypto_state_path.with_suffix(".tmp")
        temporary_path.write_text(json.dumps(state, sort_keys=True))
        temporary_path.replace(self.crypto_state_path)
        self.crypto_state_path.chmod(0o600)

    def _send_encrypted(self, recipient_id: str, content: str):
        """Serialize an encrypted send against the latest persisted state."""
        with self._crypto_state_lock():
            self._restore_crypto_state()
            return self._send_encrypted_locked(recipient_id, content)

    def _send_encrypted_locked(self, recipient_id: str, content: str):
        """Encrypt a message using the recipient session's next send key."""
        state = self._sessions.get(recipient_id)
        if state is None:
            recipient_bundle = self.fetch_pre_key_bundle(recipient_id)
            state, header = establish_initiator_session(self.identity, recipient_bundle)
            self._sessions[recipient_id] = state
            self._session_headers[recipient_id] = header
        message_key, next_chain_key = derive_message_key(state.send_chain_key)
        ciphertext, mac = encrypt_message(message_key, content.encode())
        envelope = {
            "version": 1,
            "header": _serialize_session_header(self._session_headers[recipient_id]),
            "ciphertext": _b64(ciphertext),
            "mac": _b64(mac),
        }
        message = {
            "message_id": str(uuid.uuid4()),
            "sender_id": self.phone_number,
            "recipient_id": recipient_id,
            "content": json.dumps(envelope, separators=(",", ":")),
            "sent_at": datetime.now(UTC).isoformat(),
        }
        response = self._request("/messages", "POST", message, retries=1)
        state.send_chain_key = next_chain_key
        message["message_id"] = response["message_id"]
        message["content"] = content
        self._store_message(message, "sent")
        self._save_crypto_state()
        return message

    def _decrypt_envelope(self, message):
        """Serialize encrypted receive state against other client processes."""
        with self._crypto_state_lock():
            self._restore_crypto_state()
            return self._decrypt_envelope_locked(message)

    def _decrypt_envelope_locked(self, message):
        """Decrypt one envelope and advance its receive chain after verification."""
        envelope = json.loads(message["content"])
        sender_id = message["sender_id"]
        header = _deserialize_session_header(envelope["header"])
        session_id = _session_id(header)
        session_key = (sender_id, session_id)
        state = self._incoming_sessions.get(session_key)
        available_pre_keys = None
        try:
            new_session = state is None
            if new_session:
                available_pre_keys = dict(self.pre_key_bundle.one_time_pre_keys)
                state = establish_responder_session(
                    self.pre_key_bundle,
                    header.identity_public_key,
                    header,
                )
            message_key, next_chain_key = derive_message_key(state.receive_chain_key)
            plaintext = decrypt_message(
                message_key,
                _unb64(envelope["ciphertext"]),
                _unb64(envelope["mac"]),
            )
        except (ValueError, KeyError, TypeError):
            if available_pre_keys is not None:
                self.pre_key_bundle.one_time_pre_keys = available_pre_keys
            raise
        state.receive_chain_key = next_chain_key
        if new_session:
            self._incoming_sessions[session_key] = state
            self._incoming_headers[session_key] = header
        self._save_crypto_state()
        decrypted = dict(message)
        decrypted["content"] = plaintext.decode()
        return decrypted

    def history(self):
        """Return locally stored messages in insertion order.

        History is read from the client's SQLite file and is never requested
        from the relay server.
        """
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.row_factory = sqlite3.Row
            with connection:
                rows = connection.execute(
                    """
                    SELECT message_id, sender_id, recipient_id, content, sent_at, direction
                    FROM messages
                    ORDER BY rowid
                    """
                ).fetchall()
        return [dict(row) for row in rows]

    def _initialize_database(self):
        """Create the local history schema when it does not yet exist."""
        # SQLite keeps client history local; the relay never receives this database.
        with closing(sqlite3.connect(self.database_path)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    direction TEXT NOT NULL CHECK (direction IN ('sent', 'received'))
                )
                """
            )

    def _load_auth_key(self):
        """Load the local transport credential, if this client was registered."""
        if not self.credentials_path.exists():
            return None
        credentials = json.loads(self.credentials_path.read_text())
        return credentials.get("auth_key")

    def _save_auth_key(self):
        """Persist the transport credential without including it in logs or history."""
        self.credentials_path.write_text(json.dumps({"auth_key": self.auth_key}))
        self.credentials_path.chmod(0o600)

    def _store_message(self, message, direction: str):
        """Persist one message and ignore duplicate deliveries by message id.

        ``INSERT OR IGNORE`` makes the receive path idempotent without needing
        a second in-memory deduplication cache.
        """
        with closing(sqlite3.connect(self.database_path)) as connection, connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO messages
                    (message_id, sender_id, recipient_id, content, sent_at, direction)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    message["message_id"],
                    message["sender_id"],
                    message["recipient_id"],
                    message["content"],
                    message["sent_at"],
                    direction,
                ),
            )

    def _request(self, path: str, method: str = "GET", payload=None, *, retries: int = 0):
        """Send one JSON HTTP request without logging request bodies.

        Keeping transport in one helper gives future encryption and retry logic
        a single boundary without mixing it into history management.
        """
        data = None if payload is None else json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.auth_key is not None:
            secret = base64.urlsafe_b64decode(self.auth_key.encode())
            signed_data = method.encode() + b"\n" + path.encode() + b"\n" + (data or b"")
            signature = hmac.new(secret, signed_data, hashlib.sha256).hexdigest()
            headers.update({
                "X-Auth-Account": self.phone_number,
                "X-Auth-Signature": signature,
            })
        request = urllib.request.Request(
            self.server_url + path,
            data=data,
            method=method,
            headers=headers,
        )
        for attempt in range(retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                    return json.load(response)
            except (urllib.error.URLError, TimeoutError):
                if attempt == retries:
                    raise
