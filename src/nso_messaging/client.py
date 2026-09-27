"""Primary client with HTTP transport and local SQLite message history."""

import hashlib
import json
import logging
import sqlite3
import urllib.error
import urllib.request
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .client_state import ClientCryptoState
from .config import DEFAULT_REQUEST_TIMEOUT
from .crypto import decrypt_message, derive_message_key, encrypt_message
from .encoding import decode_bytes, encode_bytes
from .json_store import write_json_atomic
from .request_auth import sign_request
from .session import (
    PreKeyBundle,
    PublicPreKeyBundle,
    Session,
    deserialize_public_bundle,
    deserialize_session_header,
    establish_initiator_session,
    establish_responder_session,
    serialize_public_bundle,
    serialize_session_header,
    session_id_for_header,
)

logger = logging.getLogger(__name__)


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
        fingerprint = hashlib.sha256(phone_number.encode()).hexdigest()
        self._crypto = ClientCryptoState(self.state_dir, fingerprint) if encryption_enabled else None
        if self._crypto is not None:
            self._crypto.load_or_create()
        self._initialize_database()
        logger.info("client initialized for local account")

    @property
    def identity(self):
        """Return this client's device identity, if encryption is enabled."""
        return None if self._crypto is None else self._crypto.identity

    @property
    def pre_key_bundle(self):
        """Return this client's private pre-key bundle, if encryption is enabled."""
        return None if self._crypto is None else self._crypto.pre_key_bundle

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
            "client_message_id": str(uuid.uuid4()),
            "sender_id": self.phone_number,
            "recipient_id": recipient_id,
            "content": content,
            "sent_at": datetime.now(UTC).isoformat(),
        }
        response = self._request("/messages", "POST", message)
        message.pop("client_message_id")
        message["message_id"] = response["message_id"]
        self._store_message(message, "sent")
        logger.info("message sent; local history updated")
        return message

    def receive(self):
        """Poll the server, store delivered messages, and return them.

        For encrypted messages, processing progress is persisted before ACK so
        redelivery can retry acknowledgment without consuming another chain key.
        """
        if self.encryption_enabled:
            with self._crypto.lock():
                self._crypto.restore()
                return self._receive_locked()
        return self._receive_locked()

    def _receive_locked(self):
        """Process queued messages while encrypted state is locked when enabled."""
        if self.encryption_enabled:
            self._flush_processed_incoming()
        messages = self._request(f"/messages/{self.phone_number}")
        acknowledged_ids = []
        for index, message in enumerate(messages):
            if self.encryption_enabled:
                message = self._decrypt_envelope_locked(message)
                messages[index] = message
            message.pop("client_message_id", None)
            self._store_message(message, "received")
            acknowledged_ids.append(message["message_id"])
        if acknowledged_ids:
            self._request(
                f"/messages/{quote(self.phone_number, safe='')}/ack",
                "POST",
                {"message_ids": acknowledged_ids},
            )
            if self.encryption_enabled:
                for message_id in acknowledged_ids:
                    self._crypto.processed_incoming.pop(message_id, None)
                self._crypto.save()
        logger.info("messages received; count=%d", len(messages))
        return messages

    def _flush_processed_incoming(self):
        """Persist cached plaintext and retry ACKs before polling for more data."""
        if not self._crypto.processed_incoming:
            return
        message_ids = list(self._crypto.processed_incoming)
        for message in self._crypto.processed_incoming.values():
            self._store_message(message, "received")
        self._request(
            f"/messages/{quote(self.phone_number, safe='')}/ack",
            "POST",
            {"message_ids": message_ids},
        )
        for message_id in message_ids:
            self._crypto.processed_incoming.pop(message_id, None)
        self._crypto.save()

    def _send_encrypted(self, recipient_id: str, content: str):
        """Serialize an encrypted send against the latest persisted state."""
        with self._crypto.lock():
            self._crypto.restore()
            return self._send_encrypted_locked(recipient_id, content)

    def _send_encrypted_locked(self, recipient_id: str, content: str):
        """Encrypt a message using the recipient session's next send key."""
        session = self._crypto.sessions.get(recipient_id)
        if session is None:
            recipient_bundle = self.fetch_pre_key_bundle(recipient_id)
            state, header = establish_initiator_session(self.identity, recipient_bundle)
            session = Session(state=state, header=header)
            self._crypto.sessions[recipient_id] = session
        message_key, next_chain_key = derive_message_key(session.state.send_chain_key)
        ciphertext, mac = encrypt_message(message_key, content.encode())
        envelope = {
            "version": 1,
            "header": serialize_session_header(session.header),
            "ciphertext": encode_bytes(ciphertext),
            "mac": encode_bytes(mac),
        }
        message = {
            "client_message_id": str(uuid.uuid4()),
            "sender_id": self.phone_number,
            "recipient_id": recipient_id,
            "content": json.dumps(envelope, separators=(",", ":")),
            "sent_at": datetime.now(UTC).isoformat(),
        }
        response = self._request("/messages", "POST", message, retries=1)
        # Advance the chain only after the server accepts the message, so a
        # failed submission can retry with the same still-unused key.
        session.state.send_chain_key = next_chain_key
        message.pop("client_message_id")
        message["message_id"] = response["message_id"]
        message["content"] = content
        self._store_message(message, "sent")
        self._crypto.save()
        return message

    def _decrypt_envelope_locked(self, message):
        """Decrypt one envelope and advance its receive chain after verification."""
        delivery_id = message["message_id"]
        # A redelivered message (e.g. after a lost ACK) returns the cached
        # plaintext instead of decrypting again with an already-advanced key.
        previously_processed = self._crypto.processed_incoming.get(delivery_id)
        if previously_processed is not None:
            return dict(previously_processed)
        envelope = json.loads(message["content"])
        sender_id = message["sender_id"]
        header = deserialize_session_header(envelope["header"])
        session_key = (sender_id, session_id_for_header(header))
        session = self._crypto.incoming_sessions.get(session_key)
        available_pre_keys = None
        try:
            new_session = session is None
            if new_session:
                available_pre_keys = dict(self.pre_key_bundle.one_time_pre_keys)
                state = establish_responder_session(
                    self.pre_key_bundle,
                    header.identity_public_key,
                    header,
                )
                session = Session(state=state, header=header)
            message_key, next_chain_key = derive_message_key(session.state.receive_chain_key)
            plaintext = decrypt_message(
                message_key,
                decode_bytes(envelope["ciphertext"]),
                decode_bytes(envelope["mac"]),
            )
        except (ValueError, KeyError, TypeError):
            # Restore any one-time pre-key consumed for a new session that
            # ultimately failed authentication, so it remains available.
            if available_pre_keys is not None:
                self.pre_key_bundle.one_time_pre_keys = available_pre_keys
            raise
        # Advance the chain only after decryption succeeds, so a rejected
        # envelope leaves the receive chain untouched for a future retry.
        session.state.receive_chain_key = next_chain_key
        if new_session:
            self._crypto.incoming_sessions[session_key] = session
        decrypted = dict(message)
        decrypted["content"] = plaintext.decode()
        decrypted.pop("client_message_id", None)
        self._crypto.processed_incoming[delivery_id] = decrypted
        # Persist before returning so a lost ACK can be retried without
        # re-deriving the message key from an already-advanced chain.
        self._crypto.save()
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
        write_json_atomic(self.credentials_path, {"auth_key": self.auth_key})
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
            signature = sign_request(self.auth_key, method, path, data or b"")
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
