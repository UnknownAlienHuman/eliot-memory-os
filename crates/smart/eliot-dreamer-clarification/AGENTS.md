# `eliot-dreamer-clarification` implementation contract

Owning issue: [#630 — A-07 single discriminative clarification candidate](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/630).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal capability-cell placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`A9.2 — Dreamer, Researcher and Memory Curator`](../../../docs/architecture/A09-02-dreamer-researcher-and-memory-curator.md#a92-dreamer-researcher-and-memory-curator)
- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.11 — Clarification routing`](../../../docs/architecture/I09-11-clarification-routing.md#i911-clarification-routing)
- [`I13.7 — Critical Attention`](../../../docs/architecture/I13-07-critical-attention.md#i137-critical-attention)
- [`I15.2 — Principal and Session binding`](../../../docs/architecture/I15-02-principal-and-session-binding.md#i152-principal-and-session-binding)
- [`I15.4 — Secrets`](../../../docs/architecture/I15-04-secrets.md#i154-secrets)
- [`I15.6 — Instruction/data separation`](../../../docs/architecture/I15-06-instructiondata-separation.md#i156-instructiondata-separation)
- [`I5.16 — Common durable fields`](../../../docs/architecture/I05-16-common-durable-fields.md#i516-common-durable-fields)
- [`I7.20 — Agent-facing error contract`](../../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)

## What to implement

Replace the placeholder with the deterministic pure owner of zero or one atomic, material and discriminative clarification candidate. One candidate represents exactly one decision variable and one bounded answer schema.

## How

- Consume exact validated A-03 clarification input and the owner-neutral active-agent/Human boundary; do not implement transport, mailbox, authentication or response validation.
- Validate job/profile/task/attempt/scope/fence, draft, boundary, policy, source denominator and all independent bounds before selection.
- Select a question only when different valid answers materially change safe downstream branches or a governing contract requires the value.
- Reject compound variables, hidden follow-ups, arbitrary object/list schemas and prose that merely contains one question mark.
- Use only closed answer families: choice/reference, Boolean/ternary, bounded scalar with unit/range/precision, date/time/version/entity reference, or bounded text with an external interpretation owner.
- Map every valid answer to exactly one branch; keep unknown, refusal, unanswered, expired and invalid-value dispositions distinct.
- Route to an agent only for task-local authorized decisions; Human-owned objective, consent, privacy, material cost or irreversible effect stays at the Human boundary.
- Define safe unanswered/expired fallback without inventing an answer, widening authority or issuing effects.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` status are removed only with cohesive implementation and substantive tests.
- Every emitted candidate contains one decision-variable identity, one bounded answer schema, complete branch mapping, materiality evidence, responder boundary, expiry and fallback.
- Multiple independent unknowns yield decomposition/no-selection, not a disguised questionnaire.
- No secret, credential, protected evidence, executable command, implicit preferred answer or default framing is emitted.
- No actual answer, delivery, acknowledgement, Dreamer rerun, task mutation, authority, effect or Finish path exists.
- Exact replay is deterministic; changed same-ID objective, branch map, boundary or policy conflicts/invalidates identity.
- All 39 `WORK_UNIT_CASE: 630/1..39` cases from the Issue execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains independently buildable until #968 performs serialized workspace admission.
