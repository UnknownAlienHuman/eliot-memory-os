# W1 result-envelope ContractChallenge

Status: `RESOLVED_PROGRAM_REVISION_v1.3`

## Conflict

The recovery program requires files under `swarm/results/` to serialize in
ELIOT types and describes a rich `TerminalWorkUpdate` with:

- `work_item_id`;
- `disposition: completed | challenged | blocked | failed`;
- `artifacts`, `evidence`, both discriminators, uncertainty, unresolved
  questions, proposed effects, and evidence lineage.

Current source truth at `crates/agent/eliot-swarm/src/lib.rs` defines a
`#[serde(deny_unknown_fields)] TerminalWorkUpdate` with exactly four fields:

- `work_item_id`;
- `attempt_id`;
- `disposition: COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME`;
- `evidence_digest`.

Adding the program's rich fields to that JSON is type-invalid. Omitting them
violates the program profile. Renaming a custom evidence object
`TerminalWorkUpdate` would launder authority and is rejected by the program's
own section 2.2 rule: a missing type field requires a ContractChallenge to
`eliot-swarm`, not an ad-hoc field.

## Safe evidence that remains usable

The current W1 inventories and their structured evidence envelopes can remain
`EVIDENCE_ONLY` BootstrapDraft artifacts when independently content-bound and
verified. They cannot be represented as canonical `TerminalWorkUpdate` until
this challenge is resolved.

## Accepted decision — program revision v1.3

The user resumed the blocked recovery goal on 2026-08-24 and directed Root to
complete it after Package A had been presented. This authorizes Option A with
one necessary honesty constraint:

- `BootstrapWorkResult` is an evidence-only BootstrapDraft wrapper;
- `structured_result` carries the rich §4.2 profile;
- `terminal_update`, when present, is the exact four-field Rust
  `TerminalWorkUpdate` with no added fields;
- `terminal_update` is omitted entirely when no genuine admitted attempt and
  provider-bound `attempt_id` exist; it is never null or fabricated;
- current W1 results therefore contain structured evidence only and remain
  `EVIDENCE_ONLY`;
- no product-contract change, activation, cutover, commit, push, or real
  ProgramData mutation is authorized by this decision.

The authoritative program amendment is
`swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md`.

## Decision options

### A. Program revision with an explicit wrapper

Define a versioned `BootstrapWorkResult` wrapper containing:

1. an exact source-compatible `terminal_update` object using the current Rust
   type and disposition vocabulary; and
2. a separately named `structured_result` object carrying the rich evidence
   profile.

The wrapper remains BootstrapDraft/evidence until `eliot-swarm` admits a
first-party equivalent. This resolves W1 without mutating product code during
the read-only wave. The required human program revision is now recorded as
v1.3 above.

### B. Product-contract change

Change `eliot-swarm::TerminalWorkUpdate` and all callers/tests to carry the
rich profile, then serialize the exact Rust type. This is a material product
contract change and is not legal inside read-only W1; W1 remains blocked until
that separately admitted work lands.

### C. Evidence only, no W1 acceptance

Keep all W1 results as custom `EVIDENCE_ONLY` envelopes, record no terminal
updates, and leave W1/cutover blocked.

No W1 result file is accepted as an ELIOT `TerminalWorkUpdate`; W1 has no
genuine admitted attempt. The resolved wrapper authorizes independently
verified `EVIDENCE_ONLY` structured results, not terminal authority.
