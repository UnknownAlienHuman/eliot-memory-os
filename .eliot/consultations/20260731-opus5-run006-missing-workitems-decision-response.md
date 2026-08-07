# Opus 5 decision: run006 missing WorkItems/OperationJobs

- Session: `9dc4bbc2-cc87-4152-af94-504638666540`
- Model: `claude-opus-5`
- Effort: `max`
- Tools: disabled
- Result: completed

## Decision

The recovery block is a false negative caused by conflating request-referenced IDs with records
actually present in the authority stores. The verified state supports the conclusion that run006
aborted before WorkItem and OperationJob projections were committed.

`recover-seal --apply` may proceed only after adding an explicit non-projection proof. A zero
count must not be accepted by count alone.

## Accepted safeguards

1. Inventory request-referenced, present, missing, and transitioned IDs separately.
2. Require successful, nonempty owner-store loads and exact set equality for the four scoped
   legacy sessions and leases.
3. For absent WorkItems, record that WorkState predates the first run006 request and that an
   exhaustive reports/control scan completed without errors or foreign matches.
4. For absent OperationJobs, record successful owner-state load, exhaustive scan, and the
   source-backed fact that the legacy request builder minted a WorkItem ID but never created a
   WorkItem or OperationJob.
5. Require the complete pre-provider gate: no provider plan, reservation, result, raw output, or
   provider artifact.
6. Write an in-progress typed recovery record before mutation. Persist per-step outcomes and
   explicitly state that the guarantee is ordered, idempotent, resumable recovery rather than a
   cross-file atomic transaction.
7. Revoke authority before quarantine; hash before move and re-verify after move.
8. Prove postconditions from fresh state loads. Absence of a matching WorkItem/OperationJob is an
   acceptable terminal postcondition.

## Required focused cases

- zero projections with a complete proof is safe;
- failed/degraded store load, incomplete scan, partial (1..3) projection, substituted ID,
  binding mismatch, stale/non-legacy authority, or any provider evidence blocks;
- exact four present projections transition all four;
- crash/resume and second APPLY converge idempotently;
- dry-run performs zero writes;
- quarantine hashes are reverified;
- record validation enforces `transitioned subset present subset referenced`.

## Local correction to the consultation

The global HostBroker legitimately contains unrelated sessions and leases. “No fifth” is applied
to the run006 attribution scope (client-instance/call bindings and the four session references),
not to unrelated global broker rows.
