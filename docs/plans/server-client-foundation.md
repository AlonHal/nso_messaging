# Server-Client Foundation Plan

Scope: a CLI-driven primary client and local server foundation, with plaintext transport behind a configuration boundary. Encryption and companion-client support remain explicit future options.

## Work Items

- [x] 1. Define server configuration and persistent registration records.
  - Acceptance: registration stores phone number, optional name, client role, and encryption option locally on the server.
- [x] 2. Implement HTTP registration and health endpoints.
  - Acceptance: a client can register and retrieve a stable registration response; duplicate phone numbers are rejected.
- [x] 3. Implement the message relay and polling endpoint.
  - Acceptance: the server accepts an envelope for a recipient and delivers it once; the server does not persist chat history.
- [x] 4. Implement local client state and chat history.
  - Acceptance: each client stores sent and received messages locally with message id, account ids, content, and timestamps.
- [x] 5. Implement the CLI.
  - Acceptance: commands support registration, sending, receiving, and server configuration.
- [x] 6. Add configuration boundaries for encryption and collaborator clients.
  - Acceptance: primary/plaintext is the current default; unsupported future modes fail clearly without changing stored data contracts.
- [x] 7. Complete testing and quality review.
  - Acceptance: unit, integration, CLI, negative, and regression tests pass; Ruff passes; no secrets or generated environments are committed.

## Current Slice

Slice 3: CLI commands and explicit configuration defaults. Follow Red-Green-Refactor for each acceptance criterion.

## Explicit Exclusions

- Cryptographic session setup and encrypted message exchange are not part of this foundation slice.
- Durable server-side message history, phone-number verification, group messaging, media, and UI are out of scope for this slice.