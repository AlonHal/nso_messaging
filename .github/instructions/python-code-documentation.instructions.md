---
applyTo: "**/*.py"
---

# Python Code Structure and Documentation

- Organize non-trivial functions and methods into clearly separated logical blocks: input validation, state lookup, transformation or cryptographic work, persistence, and response construction.
- Add one short comment before a non-obvious block explaining its purpose and invariant. Prefer comments that explain why the block exists or what must remain true after it runs.
- Do not add comments to obvious single-line assignments, loops, or direct API calls. Comments should clarify structure, control flow, protocol state, failure behavior, or security boundaries.
- Keep comments short and factual. Do not narrate every line or duplicate the code in prose.
- Give public classes, functions, and methods concise docstrings that state their responsibility, inputs or important preconditions, outputs, and security-sensitive side effects where relevant.
- For cryptographic code, comment key roles, derivation direction, authenticated data, and state-advancement timing. Never include private keys, plaintext secrets, credentials, or fixture values in comments, logs, or documentation.
- For persistence and transport code, comment atomicity, retry/idempotency behavior, authorization checks, and whether a mutation occurs before or after authentication or acknowledgment.
- Preserve existing behavior and local naming/style when adding documentation. Keep refactoring separate from comment-only changes unless the structure is too tangled to explain accurately.