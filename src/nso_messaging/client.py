"""Primary client with HTTP transport and local SQLite message history."""

import base64
import hashlib
import hmac
import json
import logging
import sqlite3
import urllib.request
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .config import DEFAULT_REQUEST_TIMEOUT
from .crypto import decrypt_message, derive_message_key, encrypt_message
from .session import (
    IdentityKeyPair,
    PreKeyBundle,
    PublicPreKeyBundle,
    SessionHeader,
    SessionState,
    deserialize_public_bundle,
    establish_initiator_session,
    establish_responder_session,
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
        self.auth_key = self._load_auth_key()
        self.identity = IdentityKeyPair.generate() if encryption_enabled else None
        self.pre_key_bundle = PreKeyBundle.generate() if encryption_enabled else None
        self._sessions: dict[str, SessionState] = {}
        self._session_headers: dict[str, SessionHeader] = {}
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
        for index, message in enumerate(messages):
            if self.encryption_enabled:
                message = self._decrypt_envelope(message)
                messages[index] = message
            self._store_message(message, "received")
        logger.info("messages received; count=%d", len(messages))
        return messages

    def _send_encrypted(self, recipient_id: str, content: str):
        """Encrypt a message using the recipient session's next send key."""
        state = self._sessions.get(recipient_id)
        if state is None:
            recipient_bundle = self.fetch_pre_key_bundle(recipient_id)
            state, header = establish_initiator_session(self.identity, recipient_bundle)
            self._sessions[recipient_id] = state
            self._session_headers[recipient_id] = header
        message_key, next_chain_key = derive_message_key(state.send_chain_key)
        ciphertext, mac = encrypt_message(message_key, content.encode())
        state.send_chain_key = next_chain_key
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
        response = self._request("/messages", "POST", message)
        message["message_id"] = response["message_id"]
        message["content"] = content
        self._store_message(message, "sent")
        return message

    def _decrypt_envelope(self, message):
        """Decrypt one envelope and advance its receive chain after verification."""
        envelope = json.loads(message["content"])
        sender_id = message["sender_id"]
        state = self._sessions.get(sender_id)
        if state is None:
            header = _deserialize_session_header(envelope["header"])
            state = establish_responder_session(
                self.pre_key_bundle,
                header.identity_public_key,
                header,
            )
            self._sessions[sender_id] = state
        message_key, next_chain_key = derive_message_key(state.receive_chain_key)
        plaintext = decrypt_message(
            message_key,
            _unb64(envelope["ciphertext"]),
            _unb64(envelope["mac"]),
        )
        state.receive_chain_key = next_chain_key
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

    def _request(self, path: str, method: str = "GET", payload=None):
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
        with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
            return json.load(response)
