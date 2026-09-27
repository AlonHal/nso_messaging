"""HTTP registration and message relay for the primary-client foundation."""

import base64
import json
import logging
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

from .config import DEFAULT_SOCKET_TIMEOUT
from .device_identity import (
    format_fingerprint,
    generate_device_fingerprint,
    validate_device_id,
)
from .encoding import decode_bytes, encode_bytes
from .json_store import write_json_atomic
from .request_auth import verify_request_signature
from .session import (
    deserialize_companion_link_certificate,
    deserialize_public_bundle,
    serialize_companion_link_certificate,
    serialize_public_bundle,
    verify_companion_link_certificate,
    verify_signed_pre_key,
)

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
        self._bundles_path = self.data_dir / "pre_key_bundles.json"
        self._lock = threading.RLock()
        self._registrations = self._load_registrations()
        self._bundles, self._consumed_pre_key_ids = self._load_bundle_store()
        self._messages: dict[str, list[dict]] = {}
        self._message_receipts: dict[tuple[str, str], dict] = {}
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
        write_json_atomic(self._registrations_path, self._registrations, indent=2)

    def _load_bundle_store(self) -> tuple[dict[str, dict[str, dict]], dict[str, dict[str, set[str]]]]:
        """Load device-scoped bundles and their served-key ledger."""
        if not self._bundles_path.exists():
            return {}, {}
        stored_data = json.loads(self._bundles_path.read_text())
        if stored_data.get("version") != 2 or not isinstance(stored_data.get("bundles"), dict):
            raise ValueError("pre-key bundle store must use device-scoped version 2 format")
        bundles = stored_data["bundles"]
        consumed_ids = stored_data.get("consumed_pre_key_ids", {})
        return bundles, {
            account_id: {
                device_id: set(key_ids)
                for device_id, key_ids in device_records.items()
            }
            for account_id, device_records in consumed_ids.items()
        }

    def _save_bundles(self):
        """Persist bundles and served-key history together with atomic replacement."""
        stored_data = {
            "version": 2,
            "bundles": self._bundles,
            "consumed_pre_key_ids": {
                account_id: {
                    device_id: sorted(key_ids)
                    for device_id, key_ids in device_records.items()
                }
                for account_id, device_records in self._consumed_pre_key_ids.items()
            },
        }
        write_json_atomic(self._bundles_path, stored_data, indent=2)

    def _handler(self, socket_timeout: float | None = None):
        """Build a request handler bound to this server's state.

        ``BaseHTTPRequestHandler`` creates one handler instance per request, so
        the closure gives each instance access to the shared registration
        directory, delivery queues, and lock without using module globals.
        """
        outer = self

        class RequestHandler(BaseHTTPRequestHandler):
            """Route one HTTP request against the enclosing server's shared state."""

            timeout = socket_timeout

            def do_GET(self):
                """Handle health checks and one-time recipient polling."""
                parsed = urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(200, {"status": "ok"})
                    return
                if parsed.path.startswith("/bundles/"):
                    parts = parsed.path.removeprefix("/bundles/").split("/")
                    phone_number = unquote(parts[0])
                    device_id = unquote(parts[1]) if len(parts) == 2 else None
                    if len(parts) > 2:
                        self._send_error(404, "Not found")
                        return
                    if not self._require_auth():
                        return
                    self._fetch_bundle(phone_number, device_id)
                    return
                if parsed.path.startswith("/messages/"):
                    recipient_id = unquote(parsed.path.removeprefix("/messages/"))
                    if not self._require_auth():
                        return
                    self._deliver_messages(recipient_id)
                    return
                self._send_error(404, "Not found")

            def do_POST(self):
                """Handle registration and message-envelope submission."""
                parsed = urlparse(self.path)
                if parsed.path == "/register":
                    self._register()
                    return
                if parsed.path.startswith("/bundles/"):
                    parts = parsed.path.removeprefix("/bundles/").split("/")
                    phone_number = unquote(parts[0])
                    device_id = unquote(parts[1]) if len(parts) == 2 else None
                    if len(parts) > 2:
                        self._send_error(404, "Not found")
                        return
                    self._publish_bundle(phone_number, device_id)
                    return
                if parsed.path.startswith("/messages/") and parsed.path.endswith("/ack"):
                    recipient_id = unquote(parsed.path.removeprefix("/messages/").removesuffix("/ack"))
                    self._acknowledge_messages(recipient_id)
                    return
                if parsed.path == "/messages":
                    self._queue_message()
                    return
                self._send_error(404, "Not found")

            def log_message(self, format, *args):
                """Route HTTP access logs through the application's logger."""
                logger.info("http request: " + format, *args)

            def _read_json(self, *, require_auth=False):
                """Decode a request body without logging its potentially sensitive content."""
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    raw_body = self.rfile.read(length)
                    if require_auth and not self._is_authenticated(raw_body):
                        self._send_error(401, "valid HMAC credentials are required")
                        return None
                    payload = json.loads(raw_body)
                except (ValueError, json.JSONDecodeError):
                    self._send_error(400, "Request body must be valid JSON")
                    return None
                if not isinstance(payload, dict):
                    self._send_error(400, "Request body must be a JSON object")
                    return None
                return payload

            def _is_authenticated(self, body):
                """Verify the request signature and return its authenticated account."""
                account_id = self.headers.get("X-Auth-Account")
                signature = self.headers.get("X-Auth-Signature")
                if not account_id or not signature:
                    return False
                with outer._lock:
                    account = outer._registrations.get(account_id)
                if account is None:
                    return False
                requested_device_id = self.headers.get("X-Auth-Device")
                devices = account.get("devices", {})
                candidates = []
                if requested_device_id is not None:
                    device = devices.get(requested_device_id)
                    if device is None:
                        return False
                    candidates.append((requested_device_id, device.get("auth_key")))
                else:
                    candidates.extend(
                        (device_id, device.get("auth_key"))
                        for device_id, device in devices.items()
                    )
                    if account.get("auth_key"):
                        candidates.append((account.get("primary_device_id"), account["auth_key"]))
                for device_id, auth_key in candidates:
                    if auth_key and verify_request_signature(
                        auth_key, self.command, self.path, body, signature
                    ):
                        self._authenticated_device_id = device_id
                        return True
                return False

            def _require_auth(self):
                """Verify an empty-body request and return whether it is authorized."""
                if self._is_authenticated(b""):
                    return True
                self._send_error(401, "valid HMAC credentials are required")
                return False

            def _authenticated_account(self):
                """Return the account named by the request's authentication header."""
                return self.headers.get("X-Auth-Account")

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
                if client_role not in {"primary", "companion"}:
                    self._send_error(400, "client_role must be 'primary' or 'companion'")
                    return
                encryption_enabled = payload.get("encryption_enabled", False)
                if type(encryption_enabled) is not bool:
                    self._send_error(400, "encryption_enabled must be a boolean")
                    return
                name = payload.get("name")
                if name is not None and not isinstance(name, str):
                    self._send_error(400, "name must be a string or null")
                    return
                if client_role == "companion" and not encryption_enabled:
                    self._send_error(400, "companion clients require encryption")
                    return
                encoded_identity_key = payload.get("identity_ed25519_public_key")
                identity_key = None
                if encryption_enabled:
                    try:
                        identity_key = decode_bytes(encoded_identity_key)
                    except (TypeError, ValueError):
                        self._send_error(400, "an Ed25519 identity public key is required")
                        return
                    if len(identity_key) != 32:
                        self._send_error(400, "Ed25519 identity public key must be 32 bytes")
                        return
                device_id = payload.get("device_id")
                if device_id is None:
                    device_id = format_fingerprint(generate_device_fingerprint(phone_number))
                if not isinstance(device_id, str):
                    self._send_error(400, "device_id must be a valid device fingerprint")
                    return
                try:
                    validate_device_id(device_id, phone_number)
                except ValueError as error:
                    self._send_error(400, str(error))
                    return
                certificate = None
                if client_role == "companion":
                    try:
                        certificate = deserialize_companion_link_certificate(
                            payload["link_certificate"]
                        )
                        verify_companion_link_certificate(certificate)
                    except (KeyError, TypeError, ValueError):
                        self._send_error(400, "companion link certificate is invalid")
                        return
                with outer._lock:
                    account = outer._registrations.get(phone_number)
                    if client_role == "primary":
                        if account is not None:
                            logger.warning("registration rejected: duplicate account")
                            self._send_error(409, "phone_number is already registered")
                            return
                        account = {
                            "phone_number": phone_number,
                            "name": name,
                            "primary_device_id": device_id,
                            "devices": {},
                        }
                    elif account is None:
                        self._send_error(404, "primary account is not registered")
                        return
                    devices = account.setdefault("devices", {})
                    if device_id in devices:
                        self._send_error(409, "device_id is already registered")
                        return
                    if client_role == "companion":
                        primary_device_id = account.get("primary_device_id")
                        primary_device = devices.get(primary_device_id, {})
                        primary_identity_key = primary_device.get("identity_ed25519_public_key")
                        if (
                            primary_identity_key is None
                            or certificate.primary_identity_ed25519_public_key
                            != decode_bytes(primary_identity_key)
                            or certificate.companion_identity_ed25519_public_key != identity_key
                        ):
                            self._send_error(400, "companion certificate identities do not match")
                            return
                        if any(
                            device.get("identity_ed25519_public_key")
                            == encode_bytes(identity_key)
                            for device in devices.values()
                        ):
                            self._send_error(409, "companion identity is already registered")
                            return
                    auth_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
                    device = {
                        "device_id": device_id,
                        "client_role": client_role,
                        "encryption_enabled": encryption_enabled,
                        "auth_key": auth_key,
                    }
                    if identity_key is not None:
                        device["identity_ed25519_public_key"] = encode_bytes(identity_key)
                    if certificate is not None:
                        device["link_certificate"] = serialize_companion_link_certificate(
                            certificate
                        )
                    devices[device_id] = device
                    if client_role == "primary":
                        account["auth_key"] = auth_key
                        outer._registrations[phone_number] = account
                    outer._save_registrations()
                logger.info("account registered; total accounts=%d", len(outer._registrations))
                self._send_json(201, {
                    "phone_number": phone_number,
                    "name": account.get("name"),
                    "client_role": client_role,
                    "encryption_enabled": encryption_enabled,
                    "device_id": device_id,
                    "auth_key": auth_key,
                })

            def _publish_bundle(self, phone_number, device_id=None):
                """Store only a validated public pre-key bundle for an account."""
                payload = self._read_json(require_auth=True)
                if payload is None:
                    return
                if self._authenticated_account() != phone_number:
                    self._send_error(403, "authenticated account does not match bundle owner")
                    return
                with outer._lock:
                    account = outer._registrations.get(phone_number)
                    if account is None:
                        self._send_error(404, "phone_number is not registered")
                        return
                    device_id = device_id or self._authenticated_device_id or account.get(
                        "primary_device_id"
                    )
                    if (
                        self._authenticated_device_id is not None
                        and self._authenticated_device_id != device_id
                    ):
                        self._send_error(403, "authenticated device does not match bundle owner")
                        return
                    if device_id not in account.get("devices", {}):
                        self._send_error(404, "device_id is not registered")
                        return
                try:
                    bundle = deserialize_public_bundle(payload)
                    verify_signed_pre_key(bundle)
                    public_payload = serialize_public_bundle(bundle)
                except (KeyError, TypeError, ValueError, IndexError):
                    self._send_error(400, "public pre-key bundle is invalid")
                    return
                key_ids = [entry["key_id"] for entry in public_payload["one_time_pre_keys"]]
                if any(not isinstance(key_id, str) or not key_id for key_id in key_ids):
                    self._send_error(400, "one-time pre-key IDs must be non-empty strings")
                    return
                if len(key_ids) != len(set(key_ids)):
                    self._send_error(400, "one-time pre-key IDs must be unique")
                    return
                with outer._lock:
                    # This exercise has no bundle-rotation operation; immutability also protects legacy stores without served-key history.
                    account_bundles = outer._bundles.setdefault(phone_number, {})
                    if device_id in account_bundles:
                        self._send_error(409, "a pre-key bundle is already published for this device")
                        return
                    consumed_ids = outer._consumed_pre_key_ids.get(phone_number, {}).get(
                        device_id, set()
                    )
                    if consumed_ids.intersection(key_ids):
                        self._send_error(409, "bundle reintroduces a consumed one-time pre-key")
                        return
                    account_bundles[device_id] = public_payload
                    outer._save_bundles()
                logger.info("public pre-key bundle published")
                self._send_json(201, {
                    "phone_number": phone_number,
                    "device_id": device_id,
                    "one_time_pre_key_count": len(public_payload["one_time_pre_keys"]),
                })

            def _fetch_bundle(self, phone_number, device_id=None):
                """Return a bundle and consume at most one one-time pre-key."""
                with outer._lock:
                    account = outer._registrations.get(phone_number)
                    if account is None:
                        self._send_error(404, "phone_number is not registered")
                        return
                    device_id = device_id or account.get("primary_device_id")
                    if device_id not in account.get("devices", {}):
                        self._send_error(404, "device_id is not registered")
                        return
                    payload = outer._bundles.get(phone_number, {}).get(device_id)
                    if payload is None:
                        self._send_error(404, "public pre-key bundle is not published for this device")
                        return
                    payload = dict(payload)
                    available_pre_keys = outer._bundles[phone_number][device_id]["one_time_pre_keys"]
                    if available_pre_keys:
                        selected_pre_key = available_pre_keys.pop(0)
                        payload["one_time_pre_keys"] = [selected_pre_key]
                        outer._consumed_pre_key_ids.setdefault(phone_number, {}).setdefault(
                            device_id, set()
                        ).add(
                            selected_pre_key["key_id"]
                        )
                        outer._save_bundles()
                    else:
                        payload["one_time_pre_keys"] = []
                logger.info("public pre-key bundle fetched")
                self._send_json(200, payload)

            def _queue_message(self):
                """Queue an envelope for a registered recipient.

                The relay validates routing identities but treats the remaining
                fields as opaque. That keeps the current plaintext foundation
                compatible with the future encrypted-envelope contract.
                """
                payload = self._read_json(require_auth=True)
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
                if self._authenticated_account() != sender_id:
                    self._send_error(403, "authenticated account does not match sender_id")
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
                    client_message_id = payload.get("client_message_id", payload.get("message_id"))
                    if client_message_id is not None and (
                        not isinstance(client_message_id, str) or not client_message_id
                    ):
                        self._send_error(400, "client_message_id must be a non-empty string")
                        return
                    if client_message_id is not None:
                        receipt_key = (sender_id, client_message_id)
                        existing_receipt = outer._message_receipts.get(receipt_key)
                        if existing_receipt is not None:
                            self._send_json(202, existing_receipt)
                            return
                    message = dict(payload)
                    message.pop("message_id", None)
                    if client_message_id is not None:
                        message["client_message_id"] = client_message_id
                    message["message_id"] = str(uuid.uuid4())
                    # The queue is deliberately transient; polling removes messages.
                    outer._messages.setdefault(recipient_id, []).append(message)
                    receipt = {
                        "message_id": message["message_id"],
                        "recipient_id": recipient_id,
                    }
                    if client_message_id is not None:
                        outer._message_receipts[receipt_key] = receipt
                logger.info("message queued; pending recipient queues=%d", len(outer._messages))
                self._send_json(202, receipt)

            def _deliver_messages(self, recipient_id):
                """Return a snapshot of queued envelopes without removing them.

                Clients acknowledge messages only after authentication, decryption,
                and local persistence succeed.
                """
                if self._authenticated_account() != recipient_id:
                    self._send_error(403, "authenticated account does not match recipient")
                    return
                with outer._lock:
                    messages = list(outer._messages.get(recipient_id, []))
                logger.info("messages delivered; count=%d", len(messages))
                self._send_json(200, messages)

            def _acknowledge_messages(self, recipient_id):
                """Remove only messages successfully processed by the recipient."""
                payload = self._read_json(require_auth=True)
                if payload is None:
                    return
                if self._authenticated_account() != recipient_id:
                    self._send_error(403, "authenticated account does not match recipient")
                    return
                message_ids = payload.get("message_ids")
                if (
                    not isinstance(message_ids, list)
                    or not message_ids
                    or any(not isinstance(message_id, str) or not message_id for message_id in message_ids)
                ):
                    self._send_error(400, "message_ids must be a non-empty list of strings")
                    return
                requested_ids = set(message_ids)
                with outer._lock:
                    queued_messages = outer._messages.get(recipient_id, [])
                    remaining_messages = [
                        message for message in queued_messages
                        if message["message_id"] not in requested_ids
                    ]
                    acknowledged_count = len(queued_messages) - len(remaining_messages)
                    if remaining_messages:
                        outer._messages[recipient_id] = remaining_messages
                    else:
                        outer._messages.pop(recipient_id, None)
                self._send_json(200, {"acknowledged": acknowledged_count})

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
