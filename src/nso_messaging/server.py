"""HTTP registration and message relay for the primary-client foundation."""

import json
import logging
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .config import DEFAULT_SOCKET_TIMEOUT

logger = logging.getLogger(__name__)


class MessagingServer:
    """Serve account registration and transient message delivery over HTTP.

    Registration records are persisted locally. Message envelopes stay in memory
    until the recipient polls, so this server does not become a chat-history store.
    """

    def __init__(
        self,
        host: str,
        port: int,
        data_dir: str | Path,
        *,
        socket_timeout: float | None = DEFAULT_SOCKET_TIMEOUT,
    ):
        """Create a server bound to ``host`` and ``port``.

        Passing port ``0`` asks the operating system to select a free port,
        which is useful for tests and embedded usage. ``socket_timeout`` bounds
        how long a connection's socket waits for further request bytes; leave
        it ``None`` (no timeout) when debugging a handler under a breakpoint.
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._registrations_path = self.data_dir / "registrations.json"
        self._lock = threading.RLock()
        self._registrations = self._load_registrations()
        self._messages: dict[str, list[dict]] = {}
        self.http_server = ThreadingHTTPServer((host, port), self._handler(socket_timeout))
        self.http_server.messaging_server = self
        bound_host, bound_port = self.http_server.server_address
        self.base_url = f"http://{bound_host}:{bound_port}"
        logger.info("server initialized at %s", self.base_url)

    def serve_forever(self):
        """Run the HTTP request loop until :meth:`shutdown` is called."""
        logger.info("server listening at %s", self.base_url)
        self.http_server.serve_forever()

    def shutdown(self):
        """Stop accepting requests and release the listening socket."""
        logger.info("server shutting down")
        self.http_server.shutdown()
        self.http_server.server_close()

    def _load_registrations(self) -> dict[str, dict]:
        """Load persisted account configuration, or return an empty directory."""
        if not self._registrations_path.exists():
            return {}
        return json.loads(self._registrations_path.read_text())

    def _save_registrations(self):
        """Persist registrations atomically so interrupted writes do not corrupt them."""
        temporary_path = self._registrations_path.with_suffix(".tmp")
        temporary_path.write_text(json.dumps(self._registrations, indent=2, sort_keys=True))
        temporary_path.replace(self._registrations_path)

    def _handler(self, socket_timeout: float | None = None):
        """Build a request handler bound to this server's state.

        ``BaseHTTPRequestHandler`` creates one handler instance per request, so
        the closure gives each instance access to the shared registration
        directory, delivery queues, and lock without using module globals.
        """
        outer = self

        class RequestHandler(BaseHTTPRequestHandler):
            timeout = socket_timeout

            def do_GET(self):
                """Handle health checks and one-time recipient polling."""
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(200, {"status": "ok"})
                    return
                if parsed.path.startswith("/messages/"):
                    recipient_id = unquote(parsed.path.removeprefix("/messages/"))
                    self._deliver_messages(recipient_id)
                    return
                self._send_error(404, "Not found")

            def do_POST(self):
                """Handle registration and message-envelope submission."""
                parsed = urlparse(self.path)
                if parsed.path == "/register":
                    self._register()
                    return
                if parsed.path == "/messages":
                    self._queue_message()
                    return
                self._send_error(404, "Not found")

            def log_message(self, format, *args):
                logger.info("http request: " + format, *args)

            def _read_json(self):
                """Decode a request body without logging its potentially sensitive content."""
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(self.rfile.read(length))
                except (ValueError, json.JSONDecodeError):
                    self._send_error(400, "Request body must be valid JSON")
                    return None
                if not isinstance(payload, dict):
                    self._send_error(400, "Request body must be a JSON object")
                    return None
                return payload

            def _register(self):
                """Validate and persist one account registration.

                The server stores account configuration only. Cryptographic key
                bundles will be added at the protocol stage without changing
                the registration endpoint's ownership boundary.
                """
                payload = self._read_json()
                if payload is None:
                    return
                phone_number = payload.get("phone_number")
                if not isinstance(phone_number, str) or not phone_number.strip():
                    self._send_error(400, "phone_number is required")
                    return
                client_role = payload.get("client_role", "primary")
                if client_role != "primary":
                    self._send_error(400, "only the primary client role is supported")
                    return
                encryption_enabled = payload.get("encryption_enabled", False)
                if type(encryption_enabled) is not bool:
                    self._send_error(400, "encryption_enabled must be a boolean")
                    return
                if encryption_enabled:
                    self._send_error(400, "encrypted messaging is not implemented yet")
                    return
                name = payload.get("name")
                if name is not None and not isinstance(name, str):
                    self._send_error(400, "name must be a string or null")
                    return
                account = {
                    "phone_number": phone_number,
                    "name": name,
                    "client_role": client_role,
                    "encryption_enabled": encryption_enabled,
                }
                with outer._lock:
                    if phone_number in outer._registrations:
                        logger.warning("registration rejected: duplicate account")
                        self._send_error(409, "phone_number is already registered")
                        return
                    outer._registrations[phone_number] = account
                    outer._save_registrations()
                logger.info("account registered; total accounts=%d", len(outer._registrations))
                self._send_json(201, account)

            def _queue_message(self):
                """Queue an envelope for a registered recipient.

                The relay validates routing identities but treats the remaining
                fields as opaque. That keeps the current plaintext foundation
                compatible with the future encrypted-envelope contract.
                """
                payload = self._read_json()
                if payload is None:
                    return
                sender_id = payload.get("sender_id")
                recipient_id = payload.get("recipient_id")
                if not isinstance(sender_id, str) or not isinstance(recipient_id, str):
                    self._send_error(400, "sender_id and recipient_id are required")
                    return
                content = payload.get("content")
                sent_at = payload.get("sent_at")
                if not isinstance(content, str) or not content:
                    self._send_error(400, "content is required and must be a non-empty string")
                    return
                if not isinstance(sent_at, str) or not sent_at:
                    self._send_error(400, "sent_at is required and must be a non-empty string")
                    return
                with outer._lock:
                    if sender_id not in outer._registrations:
                        logger.warning("message rejected: sender is not registered")
                        self._send_error(404, "sender is not registered")
                        return
                    if recipient_id not in outer._registrations:
                        logger.warning("message rejected: recipient is not registered")
                        self._send_error(404, "recipient is not registered")
                        return
                    message = dict(payload)
                    message["message_id"] = str(uuid.uuid4())
                    # The queue is deliberately transient; polling removes messages.
                    outer._messages.setdefault(recipient_id, []).append(message)
                logger.info("message queued; pending recipient queues=%d", len(outer._messages))
                self._send_json(202, {
                    "message_id": message["message_id"],
                    "recipient_id": recipient_id,
                })

            def _deliver_messages(self, recipient_id):
                """Deliver and remove all currently queued envelopes for a recipient.

                Removing the queue while holding the lock makes polling
                destructive and prevents two concurrent polls from receiving the
                same envelope.
                """
                with outer._lock:
                    messages = outer._messages.pop(recipient_id, [])
                logger.info("messages delivered; count=%d", len(messages))
                self._send_json(200, messages)

            def _send_json(self, status, payload):
                """Write a JSON response with consistent HTTP metadata."""
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_error(self, status, message):
                """Return a structured error without exposing internal exception details."""
                self._send_json(status, {"error": message})

        return RequestHandler
