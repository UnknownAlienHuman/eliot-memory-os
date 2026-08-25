# W1 result-envelope program revision v1.3

Status: `ACCEPTED_EVIDENCE_ONLY`

Authority: user-directed recovery-program revision recorded by Root on
2026-08-24. This is program authority only; it is not Architecture,
Implementation, Product Proof, activation, cutover, commit, or push authority.

## Conflict resolved

`docs/tasks/RECOVERY_PROGRAM_v1.md` §2.2 requires target swarm types, §2.3
describes `TerminalWorkUpdate + structured result`, and the former §4.2 rich
shape was not serializable as the current product type. Current source
`crates/agent/eliot-swarm/src/lib.rs:917-935` defines an exact four-field,
`deny_unknown_fields` `TerminalWorkUpdate` bound to one real attempt.

## Decision

The program uses `eliot.bootstrap-work-result.v1` with:

1. `schema_version`;
2. `authority_status = EVIDENCE_ONLY`;
3. `work_item_id`;
4. optional `terminal_update`;
5. required `structured_result` carrying the rich evidence profile.

`terminal_update` is permitted only when a genuine admitted attempt supplies
the exact `work_item_id`, provider-bound `attempt_id`, product disposition, and
content-bound `evidence_digest`. If that precondition is absent, the property
is omitted. Null, partial, caller-invented, and extra-field terminal objects are
invalid.

W1 has no admitted attempt. W1-01 through W1-07 therefore omit
`terminal_update` and remain independently verified BootstrapDraft evidence.
No result may claim terminal completion, release WIP, or authorize a wave.

## One-shot retry authorization

Exactly one next mechanism-changed attempt is authorized for each challenged
item:

- W1-01 attempt 3;
- W1-02 attempt 4;
- W1-05 attempt 4;
- W1-06 next bounded correction after V4 review.

The order is: apply this contract first; flip each local challenge status;
change the mechanism rather than its output bytes; run generator self-test and
check, independent verifier self-test and normal mode, per-field mutation
fixtures, and an independent Luna gate. Any new failure requires a new
Mechanism Review and decision.

## Exclusions

- no `eliot-swarm` product-contract mutation;
- no fabricated `TerminalWorkUpdate` or `attempt_id`;
- no activation or cutover;
- no acceptance beyond the declared evidence ceiling;
- no commit or push;
- no mutation of real `C:\ProgramData\Eliot` by unit tests.
