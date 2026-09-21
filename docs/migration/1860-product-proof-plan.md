# 1860 first Product Proof plan

Owner: `bins/eliotd` migration coordination, executed under issue #11
(installed Product Pulse). This plan is the I19.2 "first Product Proof plan"
output; it authorizes exactly one bounded pulse and proves nothing until run.

## Installed route under proof

```text
Operator surface (bins/eliot CLI)
  → eliotd (bins/eliotd, semantic Governor, owner #18)
  → Kernel (bins/eliot-kernel, owner #15)
  → Store bridge (bins/eliot-store-surreal → named Store operation, owner #19)
  → direct receipt readback + governed L2/read-model observation
```

Named owner binaries: `eliot` (operator front door), `eliotd`, `eliot-kernel`,
`eliot-store-surreal`, with independent Watchdog observation
(`bins/eliot-watchdog`, #16) and Host lifecycle containment
(`bins/eliot-host`, #14).

## Exact entrypoint

One admitted capture (or equivalent user input) submitted through the real user
surface — `eliot` CLI against the installed generation — producing one exact
canonical write through `eliotd` → Kernel → one named Store operation, then one
direct receipt readback and one governed read-model observation. Library
shortcuts, fixtures, in-memory calls, and simulated evidence are forbidden as
proof; the pulse runs the applicable user surface end to end.

## Required identities (single-identity rule)

One pulse binds exactly one of each; mixed-identity evidence cannot be combined:

source head + normative pair + Cargo lock/toolchain + built artifact digests +
installation/lineage/generation + machine/environment class + principal/session
+ AuthorityEpoch + StateFence + Store namespace/schema/heads + capability
registry (#13) + scenario set + verifier set + deadlines + cleanup obligations.
Stale, expired, blind, or incomplete prerequisites reject the pulse before
Product promotion (a diagnostic run with an explicit incomplete ceiling is
allowed but proves nothing).

Pre-start, independently read back installed Host, Kernel, Watchdog, `eliotd`,
and Store bridge/server process generations; re-read after the scenario and
reject stale-generation adoption.

## Expected receipt

The pulse emits one immutable **`ProductPulseReceipt`** (the installed-route
receipt): per-stage start/end identities, raw evidence handles, omissions,
conflicts, unknowns, cleanup state, verifier receipts, proof ceilings, and a
complete invalidation set. Aggregate status is the weakest required stage —
`NOT_EXECUTED`, `NOT_RUNNING`, `UNAVAILABLE`, `PARTIAL`, `UNKNOWN`, `STALE`,
`CONFLICTED`, `FAILED`, `PASSED` stay distinct; no majority or scalar score.
Secrets and protected payloads are redacted, retaining digests/owners/
timestamps sufficient for independent replay. `VERIFIED_COMPLETE` requires the
exact current applicable independent verifier receipts with all external
effects and cleanup reconciled.

## Failure preservation rule

Restart or replace `eliotd` and the Store bridge/server at predeclared safe
points and prove exact rehydration with unchanged canonical readback; exercise
one controlled unknown-commit (or lost-acknowledgement) path and reconcile the
same `OperationId` before retry — no duplicate write. Watchdog independently
observes the failure/recovery interval and preserves every coverage gap. Failing
fixtures and revisions are preserved, never overwritten; every unavailable,
partial, unknown, stale, conflicted, failed, or cleanup-incomplete stage stays
visible and lowers the aggregate result.

## Rollback / recovery boundary

Per I19.11: rollback is a generation switch while formats remain compatible.
If the new write format or migration is irreversible, restore the isolated
backup or forward-repair; never fake a binary rollback. After the no-return
boundary (I19.16 cutover receipt selects the new owner), rollback is a forward
repair/migration, not resurrection of the old truth. Required preconditions
from I19.10 apply: one canonical write path, no active agent holding DB
credentials, restart/resume proof, backup/restore proof, explicit
rejection/redirect from the old entrypoint, migration gaps visible on
ControlBoard, and a tested rollback plan.

## Invalidation

Changing any load-bearing source, artifact, install, runtime, Store, policy,
verifier, or environment identity invalidates the dependent Product claim. A
later run under a new identity is a new pulse, not a continuation.
