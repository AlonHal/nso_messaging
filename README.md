# nso_messaging

A small Python server-client foundation for the take-home encrypted messaging assignment. The current implementation provides a primary client, an HTTP relay server, local client chat history, and a CLI.

The current transport and message flow are plaintext. Encryption, cryptographic key bundles, companion clients, session setup, and ratcheting are planned next and are not enabled yet.

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

## Current Scope and Limitations

- The server stores account configuration but does not persist chat history.
- Message delivery uses a transient in-memory queue and polling.
- The current HTTP relay has no authentication or authorization and is intended only for local or trusted development; authenticated HMAC/encrypted transport is a future protocol slice.
- The current client role is `primary`.
- Encryption is disabled and not implemented yet.
- The `--client-role` and `--encryption-enabled` options reserve configuration space for future work, but unsupported values currently fail explicitly.
- Phone-number verification, group messaging, media attachments, durable server message storage, and non-CLI interfaces are out of scope for this stage.

See [docs/plans/server-client-foundation.md](docs/plans/server-client-foundation.md) for the staged implementation plan for this feature.
