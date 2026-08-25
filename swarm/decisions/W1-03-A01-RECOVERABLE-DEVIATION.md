# W1-03 decision — A-01 Recoverable Deviation

Status: `ACCEPTED_RECOVERABLE_DEVIATION`

Authority: Root / Sol decision under `A0.6`, accepted on 2026-08-24. The
underlying W1 evidence remains `EVIDENCE_ONLY`; this decision is not a
canonical `TerminalWorkUpdate`, Product Proof, launch authority, or acceptance
of A-01 itself.

Owner: Root / Sol for the deviation decision; Luna-A / Integration Owner for
any later bounded execution.
Reason: Break only the internal acceptance SCC at the A-01 launch consumer
while provider evidence is unavailable; accepting the deviation does not
satisfy A-01 acceptance.
Scope: A-01 pre-execution typed `PLAN_GAP`/`UNAVAILABLE` candidate only; A-03 and A-05 remain blocked.
Review condition: Independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate.
Rollback: Revoke this proposal, restore normal A-01 admission, retain negative evidence, and rerun graph/trio checks.

## Scope

The seven-cell graph has one concrete mixed product/proof SCC: `C0-13 → G-03 → A-01 → C0-13`. Its minimum vertex cut is size one, with equal cuts `{A-01}`, `{C0-13}`, and `{G-03}`. A-01 is the selected proposal cut because the ledger permits a typed-unavailable pre-execution boundary.

Only A-01 may return a typed `PLAN_GAP`/`UNAVAILABLE` candidate with missing provider identities and content-bound source digests. The deviation does not satisfy A-01 acceptance and does not apply to A-03 or A-05.

It may not start a process, issue `DispatchPermit`, widen Session/WorkScope/Task/route/fence/effect authority, fabricate readiness or verifier evidence, emit `VERIFIED_COMPLETE`, or authorize a later wave.

## Review and rollback

Review requires independently executed provider-issued P-03 and C0-06 evidence and the unchanged A-01/A-03/A-05 trio gate. Revoke the proposal, restore the normal A-01 admission predicate, retain typed-unavailable receipts as negative evidence, and rerun graph/trio checks. No canonical product state is created.

## Boundaries

No canonical Architecture/Implementation text, Rust source, Cargo graph,
external provider, or authority contract is changed by this decision. Proof
ceiling remains static content-bound graph evidence.
