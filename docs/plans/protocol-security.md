# Protocol Security Plan

Scope: add the assignment's cryptographic identity, session, authenticated-message, and transport-security layers to the merged primary-client foundation.

## Work Items

- [x] 1. Implement assignment-compatible cryptographic primitives.
  - Acceptance: HKDF-SHA256 derives root and chain keys; HMAC chain advancement uses `0x01` and `0x02`; message material contains AES key, HMAC key, and derived IV; tampering fails before decryption.
- [x] 2. Implement identity and initial session setup.
  - Acceptance: matched X25519/Ed25519 identity material, signed pre-key verification, one-time pre-key consumption, and matching initiator/responder directional chains.
- [x] 3. Publish and fetch public pre-key bundles through the server.
  - Acceptance: public bundles are serialized safely; one-time pre-keys are removed when served; private key material never leaves the client.
- [x] 4. Add HMAC authentication for client-server requests.
  - Acceptance: registration issues credentials; polling and sending require valid credentials; forged sender identities are rejected.
- [x] 5. Integrate encrypted message envelopes into client send/receive.
  - Acceptance: clients establish sessions, encrypt/decrypt messages, advance chains once, and store plaintext only in local history.
- [x] 6. Add protocol integration and CLI tests.
  - Acceptance: two clients complete an encrypted round trip; tampered envelopes, invalid signatures, exhausted pre-keys, and unauthorized requests fail safely.
- [x] 7. Implement companion-device pairing.
  - Acceptance: the file-based QR stand-in carries the companion identity and linking secret; the primary signs the link and device list; the companion verifies PHMAC and A_signature, returns D_signature, registers a device-scoped pre-key bundle, and sends session-setup proofs.
- [x] 8. Implement client-side multi-device fan-out and device-addressed relay queues.
  - Acceptance: a separate pairwise encrypted envelope reaches every other encrypted device, including sender companions, and only the addressed device can poll or ACK its queue.
- [x] 9. Add the DH ratchet bonus.
  - Acceptance: every encrypted message advertises a fresh X25519 ephemeral; when a peer ephemeral changes, both sides derive matching ratchet root/chain keys and ratchet state survives restart.

## Current Boundary

The core crypto, session, public pre-key transport, HMAC request-authentication, and encrypted client-envelope layers are complete. Companion pairing, multi-device fan-out, and the DH ratchet bonus are implemented. The HTTP relay sees only opaque encrypted content for encrypted clients.

## Assignment Decisions

- Use separate Ed25519 signing keys paired with X25519 identity keys, as explicitly permitted by the assignment Notes section.
- Expand the 32-byte `HMAC(chain_key, 0x01)` message seed with HKDF-SHA256 to produce the required 80-byte message material; keep this convention isolated for review.
- Use AES-256-CBC with the final 16 message-key bytes as the IV and HMAC-SHA256 over ciphertext, as required by the assignment.
