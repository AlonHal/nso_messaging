"""Primary client with HTTP transport and local SQLite message history."""

import json
import logging
import sqlite3
import urllib.request
import uuid
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class MessagingClient:
    """Register, send, receive, and locally store plaintext messages.

    The current client is intentionally primary-only and plaintext. The role and
    encryption options remain explicit so future implementations can add them
    without changing the local history interface.
    """

    def __init__(
        self,
        server_url: str,
        phone_number: str,
        state_dir: str | Path,
        *,
        client_role: str = "primary",
        encryption_enabled: bool = False,
    ):
        """Create a client and initialize its local SQLite history database."""
        if client_role != "primary":
            raise NotImplementedError("Only the primary client role is currently supported")
        if encryption_enabled:
            raise NotImplementedError("Encrypted messaging is not implemented yet")
        self.server_url = server_url.rstrip("/")
        self.phone_number = phone_number
        self.client_role = client_role
        self.encryption_enabled = encryption_enabled
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = self.state_dir / "messages.sqlite3"
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
        logger.info("client registration completed")
        return result

    def send(self, recipient_id: str, content: str):
        """Send one plaintext message and store the sent copy locally.

        The server assigns the authoritative message id. The client replaces
        its provisional id with that value before writing local history.
        """
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
        for message in messages:
            self._store_message(message, "received")
        logger.info("messages received; count=%d", len(messages))
        return messages

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
        request = urllib.request.Request(
            self.server_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
