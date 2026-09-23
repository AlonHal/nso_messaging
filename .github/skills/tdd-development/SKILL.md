---
name: tdd-development
description: "Run task- and feature-level development using a coordinated TDD workflow. Use when starting, implementing, testing, reviewing, or completing work in this encrypted messaging project, especially protocol, cryptography, CLI, or client/server changes."
compatibility: "Python 3.11+; use the repository .venv, pytest, pytest-cov, Ruff, and the local PDF reader when protocol questions require the assignment documents."
metadata:
  sources: "VS Code Agent Skills documentation; github/awesome-copilot ai-team-orchestration; Martin Fowler TDD and Practical Test Pyramid"
  version: "1.0"
---

# TDD Development Workflow

Use this skill to move one task or feature from a clear requirement to verified code. Keep the workflow proportional: a small task may use a short checklist, while a cross-cutting protocol feature needs explicit handoffs and integration tests.

## Team Roles

- **Planner**: turns the request into observable acceptance criteria, identifies protocol dependencies and security risks, and answers questions from the assignment PDFs. The planner does not implement code.
- **Coder**: writes the smallest production change that satisfies the current failing test and owns implementation details. The coder does not silently change protocol semantics.
- **Tester**: independently checks behavior, negative cases, regressions, and security boundaries. The tester reports reproducible findings and does not weaken assertions.
- **Coordinator**: keeps the current scope visible, routes ambiguity to the planner, and decides when the task is ready to close.

## Starting a Task or Feature

1. Read repository instructions, the relevant source, existing tests, and the applicable assignment/white-paper sections.
2. Classify the work:
   - **Task**: one bounded change with a local observable result.
   - **Feature**: a user-visible capability or protocol slice that crosses modules, state, or a process boundary.
3. Write a compact work brief before editing:
   - Outcome and explicit exclusions.
   - Acceptance criteria stated as observable behavior.
   - Security and compatibility constraints.
   - Files or boundaries likely to change.
   - Test layers required: unit, integration, CLI, or end-to-end.
4. Identify the smallest first scenario. For crypto work, prefer a deterministic contract around key shape, state transition, authentication, or message behavior rather than testing private implementation details.
5. If a requirement is ambiguous, stop implementation and ask the planner. Resolve ambiguity before encoding assumptions in tests.

A useful handoff is:

```text
Work item: <task or feature>
Outcome: <one sentence>
Acceptance criteria:
- <observable behavior>
- <observable failure or security behavior>
Exclusions: <what is deliberately out of scope>
First scenario: <the smallest behavior to drive with TDD>
Risks: <protocol, state, compatibility, or secret-handling risks>
Validation: <commands and test layers>
```

## Red-Green-Refactor Loop

For each acceptance criterion, repeat this loop:

1. **Red**: the tester or coder writes one focused test that expresses the next behavior. Run it and confirm it fails for the intended reason. Do not accept a test that fails because of a broken environment or import error.
2. **Green**: the coder implements the smallest correct change. Avoid speculative abstractions, unrelated cleanup, and protocol extensions not demanded by the current criterion.
3. **Focused validation**: rerun the same test, then the nearest relevant test slice. Use the project environment:
   - `.venv/bin/python -m pytest -q <test-or-directory>`
   - `.venv/bin/python -m pytest --cov=<package> --cov-report=term-missing`
   - `.venv/bin/ruff check .`
4. **Refactor**: improve names, boundaries, duplication, and test readability while keeping the suite green. Preserve observable behavior and cryptographic invariants.
5. **Handoff**: record what changed, the checks run, and the next smallest scenario before moving to another slice.

One test should establish one meaningful behavior. Prefer Arrange-Act-Assert or Given-When-Then. Test public behavior and state transitions, not private call order or incidental implementation structure.

## Test Layers for This Project

Build a test pyramid with many fast tests, fewer boundary tests, and a small number of full workflows:

- **Unit tests**: key serialization, public-key validation, HKDF/HMAC derivation, chain-key advancement, message-key layout, padding, AES-CBC/MAC verification, and signature checks.
- **Integration tests**: registration with a local server/store, pre-key publication and consumption, session initiation/receipt, and transport serialization.
- **CLI acceptance tests**: registration, send, receive, and pairing commands through the supported interface.
- **Security regression tests**: tampered ciphertext or headers, wrong keys, replayed state, reused one-time pre-keys, invalid signatures, and accidental secret disclosure.

Push edge cases down to the lowest useful layer. Keep high-level tests focused on proving that components connect and that a user workflow works; do not duplicate every unit edge case at the CLI layer.

## Crypto-Specific Gates

Do not mark a protocol slice complete until the relevant gates pass:

- Identity roles and public-key formats are explicit; X25519 is used for ECDH and Ed25519 for signatures when using the permitted substitution.
- Key derivation labels, input ordering, output lengths, and chain direction are tested.
- Authentication is checked before plaintext is released; malformed inputs fail closed.
- AES-256-CBC uses the derived message IV required by the assignment, and the ciphertext MAC covers the specified authenticated data.
- One-time pre-keys cannot be consumed twice.
- Sending and receiving state advances exactly once per accepted message.
- Private keys, plaintext secrets, and test fixtures are not logged or committed.
- Optional pairing and DH-ratchet work stays behind the required core and has its own acceptance criteria.

When the assignment conflicts with a generic best practice, follow the assignment for this take-home implementation, document the deviation, and keep the boundary easy to replace.

## Completion Gate

A task or feature is complete only when:

- Every acceptance criterion has a passing test.
- The negative and security cases relevant to the change pass.
- Focused tests, the broader regression suite, and Ruff have been run as applicable.
- The tester has reviewed the diff and found no unresolved high-severity issue.
- The handoff records limitations, skipped optional scope, and the exact validation commands.
- No generated environments, secrets, PDFs, or unrelated files are included in the change.

If a higher-level test finds a defect without a lower-level reproducer, add the lower-level regression test before fixing or closing the issue.

## Sources

This skill is an adaptation, not a copy, of the following public guidance:

- [VS Code Agent Skills](https://code.visualstudio.com/docs/copilot/customization/agent-skills)
- [GitHub awesome-copilot: AI team orchestration](https://github.com/github/awesome-copilot/tree/main/skills/ai-team-orchestration)
- [Martin Fowler: Test Driven Development](https://martinfowler.com/bliki/TestDrivenDevelopment.html)
- [Martin Fowler: The Practical Test Pyramid](https://martinfowler.com/articles/practical-test-pyramid.html)
