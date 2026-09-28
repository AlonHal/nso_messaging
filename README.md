# nso_messaging

A small Python server-client foundation for the take-home encrypted messaging assignment. The current implementation provides device identities, primary and certificate-linked companion registration, an HTTP relay server, local client chat history, and a CLI.

The client supports authenticated HTTP requests and encrypted message envelopes. Device-scoped identities, companion registration, encrypted multi-device fan-out, and a per-session DH ratchet are implemented.

## Requirements

- Python 3.11 or newer
- The project virtual environment at `.venv/`

## Setup

From the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[test,dev]"
```

If the environment already exists, update the installed project with:

```bash
.venv/bin/python -m pip install -e ".[test,dev]"
```

## Run the Server

Start the server with its default settings:

```bash
.venv/bin/python -m nso_messaging serve
```

The server listens on `127.0.0.1:8000` and stores registration records in `server-data/registrations.json`.

Choose a different address, port, or data directory with:

```bash
.venv/bin/python -m nso_messaging serve \
  --host 127.0.0.1 \
  --port 8000 \
  --data-dir server-data
```

Keep the server terminal running while using client commands from another terminal.

## Use the Client

Each client needs its own local state directory. The phone number is the account identifier.

### Register Two Primary Clients

```bash
.venv/bin/python -m nso_messaging register \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --name Alice \
  --state-dir client-data/alice

.venv/bin/python -m nso_messaging register \
  --server http://127.0.0.1:8000 \
  --phone +15550002 \
  --name Bob \
  --state-dir client-data/bob
```

Registration stores the account configuration on the server. The client creates a local SQLite history database in its state directory.

### Link a Companion Device

The POC replaces the QR code with an offer JSON file shared between the companion and primary processes. Use the same `--link-dir` and `--link-id` for each command:

```bash
.venv/bin/python -m nso_messaging link-offer \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --state-dir client-data/alice-companion \
  --link-id alice-companion

.venv/bin/python -m nso_messaging link \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --state-dir client-data/alice \
  --link-id alice-companion

.venv/bin/python -m nso_messaging register \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --state-dir client-data/alice-companion \
  --client-role companion \
  --encryption-enabled \
  --link-id alice-companion
```

The offer contains the companion device ID, identity public key, and `L_companion` as readable JSON/Base64. The primary uploads the signed device list, `L_data`, and `PHMAC`; the companion verifies the forwarded proof before uploading its signed pre-key bundle.

### Send a Message

```bash
.venv/bin/python -m nso_messaging send \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --state-dir client-data/alice \
  --recipient +15550002 \
  --message "Hello Bob"
```

The server assigns a message ID and queues the envelope for the recipient.

### Receive Messages

```bash
.venv/bin/python -m nso_messaging receive \
  --server http://127.0.0.1:8000 \
  --phone +15550002 \
  --state-dir client-data/bob
```

Receiving polls the server and removes the delivered envelopes from the server's transient queue. The received messages are stored in Bob's local SQLite history.

### Listen for Messages

Keep a registered client online and polling for incoming messages with:

```bash
.venv/bin/python -m nso_messaging listen \
  --server http://127.0.0.1:8000 \
  --phone +15550001 \
  --state-dir client-data/alice \
  --encryption-enabled \
  --poll-interval 1
```

For a companion, use its state directory and add `--client-role companion`. The command prints each received message as a JSON line, stores it locally, and continues until interrupted with Ctrl-C. Run one listener process for each device that should receive messages.

### View Local History

History does not require a running server:

```bash
.venv/bin/python -m nso_messaging history \
  --state-dir client-data/bob
```

The output is JSON containing message IDs, sender and recipient account IDs, content, timestamps, and direction.

### View CLI Help

```bash
.venv/bin/python -m nso_messaging --help
.venv/bin/python -m nso_messaging send --help
```

## Run the Tests

Run the complete test suite:

```bash
.venv/bin/python -m pytest -q
```

Run tests with coverage:

```bash
.venv/bin/python -m pytest -q \
  --cov=nso_messaging \
  --cov-report=term-missing
```

Run a focused test file:

```bash
.venv/bin/python -m pytest -q tests/test_http_registration.py
```

Run linting:

```bash
.venv/bin/ruff check src tests
```

## Debugging in VS Code

`.vscode/launch.json` provides debug configurations for the server, each client command, and pytest:

- `Serve: nso-messaging server`
- `Client: register (Alice)` / `register (Bob)` / `send` / `receive` / `history`
- `Pytest: Current File` / `Pytest: All tests`

To debug the server, set a breakpoint inside `src/nso_messaging/server.py` (for example in `_register` for registration or `_queue_message` for sending), start `Serve: nso-messaging server` from the Run and Debug panel, then trigger the matching CLI command from a separate terminal or debug session. `ThreadingHTTPServer` handles each request on its own thread, but `debugpy` instruments every thread, so the breakpoint still stops execution.

You can also run both a client and the server under the debugger at the same time: start two debug sessions (e.g. `Serve: nso-messaging server` and `Client: send`) to step through a request end-to-end.

`.vscode/settings.json` points `python.defaultInterpreterPath` at `.venv/bin/python` and enables pytest discovery, so debug sessions and the Testing panel resolve against the project's virtual environment.

### Extending Timeouts While Debugging

Pausing at a breakpoint inside the server can take longer than a client's default 5-second HTTP request timeout. CLI commands and clients constructed directly in tests or Python code use the same JSON configuration. For a long timeout, set `request_timeout` to a number; use `null` to wait without a client request timeout:

```json
{
  "request_timeout": null,
  "socket_timeout": null
}
```

Place the file at `nso-messaging.config.json` in the current directory or set `NSO_MESSAGING_CONFIG` to its path. The default `running_server` test fixture already has no socket read timeout. To set a per-client timeout in a test, pass `request_timeout=600` to `MessagingClient`; explicit constructor values take precedence over the global configuration. CLI flags likewise take precedence over the config file.

A `nso-messaging` console script is also installed into `.venv/bin` (via `[project.scripts]` in `pyproject.toml`), so commands can be run directly without `python -m`:

```bash
.venv/bin/nso-messaging serve
.venv/bin/nso-messaging register --server http://127.0.0.1:8000 --phone +15550001 --name Alice --state-dir client-data/alice
```

## Cryptography and Encrypted Messaging

`src/nso_messaging/crypto.py` and `src/nso_messaging/session.py` implement the assignment's key derivation, session setup, and authenticated-message building blocks. Encrypted `MessagingClient` instances publish public pre-key bundles, establish sessions on first send/receive, and keep decrypted plaintext only in local history.

- `session.py`: `PreKeyBundle.generate()` creates a device's identity and pre-keys; `establish_initiator_session`/`establish_responder_session` perform an X3DH-style handshake and derive matching send/receive chain keys for both sides.
- `crypto.py`: `derive_message_key` advances a chain key into fresh AES/HMAC/IV material, and `encrypt_message`/`decrypt_message` apply AES-256-CBC with an HMAC-SHA256 tag, rejecting tampered ciphertext or padding as `AuthenticationError`.

Example round trip:

```python
from nso_messaging.crypto import decrypt_message, derive_message_key, encrypt_message
from nso_messaging.session import IdentityKeyPair, PreKeyBundle, establish_initiator_session, establish_responder_session

alice = IdentityKeyPair.generate()
bob = PreKeyBundle.generate()

alice_state, header = establish_initiator_session(alice, bob.public_bundle())
bob_state = establish_responder_session(bob, alice_state.identity_public_key, header)

message_key, alice_state.send_chain_key = derive_message_key(alice_state.send_chain_key)
ciphertext, mac = encrypt_message(message_key, b"hello bob")

message_key, bob_state.receive_chain_key = derive_message_key(bob_state.receive_chain_key)
plaintext = decrypt_message(message_key, ciphertext, mac)
```

## Current Scope and Limitations

- The server stores account configuration but does not persist chat history.
- Public pre-key bundles and one-time-key consumption are persisted in `pre_key_bundles.json` under the server data directory.
- Message delivery uses transient in-memory queues keyed by account and device, with polling and per-device acknowledgments.
- Registration issues per-device HMAC credentials. The server stores devices under their account, and each device has a stable 16-byte fingerprint-derived ID persisted in `device_identity.json`.
- Encrypted identity, pre-key, and session state are persisted as readable JSON/Base64 files in the client's state directory; this is a proof of concept, not encrypted-at-rest key storage.
- Companion registration requires a primary-signed and companion-signed link certificate. The server checks both signatures and verifies that the certificate keys match the registered primary and companion identities.
- Bundle records are keyed by account and device ID, with one-time pre-keys consumed independently per device.
- Encrypted sends validate sender/recipient device rosters and create one pairwise encrypted envelope for each encrypted device on both accounts, excluding only the sending device. Each device has an independent session and delivery queue.
- Companion-originated session headers carry the companion link certificate, and receivers verify it against the authenticated device roster. Each encrypted message advertises a fresh DH ratchet ephemeral; new peer ephemerals advance the root and directional chain keys.
- The CLI supports offer creation, primary link approval, companion registration, and long-running per-device polling with `listen`.
- Plaintext remains the default; pass `--encryption-enabled` to register and use an encrypted client.
- Phone-number verification, group messaging, media attachments, durable server message storage, and non-CLI interfaces are out of scope for this stage.

See [docs/plans/server-client-foundation.md](docs/plans/server-client-foundation.md) for the staged implementation plan for this feature.
See [docs/plans/protocol-security.md](docs/plans/protocol-security.md) for the protocol-security implementation plan.
