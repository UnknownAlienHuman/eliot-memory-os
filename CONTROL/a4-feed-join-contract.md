# A4 → A1 feed join contract — settled-plan feed output shape

Counterpart: A1 transport contract
(`1941-1942-join-c1-transport.md`, §"A4 source feed contract", as built at
`c2fe33ad`). A1 owns the transport; A4 owns this production feed. This file
is the A4 half of that join, implemented in
`crates/smart/eliot-reactive-context-plan/src/settled_plan_feed.rs`.

## What the feed emits

`produce_settled_plan_feed(SettledPlanFeedInputs) ->
Result<SettledPlanFeedOutcome, SettledPlanFeedError>` where inputs are the
six borrowed owner projections (view, cue activation, session snapshot,
attention projection, coverage profile, policy) and:

- `Ok(Ready(SettledPlanFeed { plan, batch }))` — `plan` is the
  `PendingContextInjectionPlan` settled by the real planner;
  `batch` is the `BridgeAdmissionBatch` derived from that same plan in the
  same call (same `result_digest`; emitted + skipped == `plan.items.len`
  by producer construction). A1 admits either half:
  - `plan` → `SettledPlanAdmission::admit_settled_plan(runner, &plan,
    assess)` (transport re-runs the producer, aborts on defect), or
  - `batch` → `SettledPlanAdmission::admit_batch(runner, &batch, assess)`.
- `Ok(NoSettledPlan(disposition))` — planner settled no injection. Carries
  the full `NoInjectionDisposition` (reason, item ledger, accounting).
  **Emits zero instructions: there is no batch.** A1 must not synthesize
  one; buffer bounded owner-side or drop WITH a receipt per the transport
  contract.
- `Err(Planning(error))` — projections invalid/stale/conflicted/forged.
  No batch exists. Buffer bounded owner-side or drop WITH a receipt; never
  retry as a new item without new owner evidence.
- `Err(Producer(error))` — settled plan defective (sourceless/over-bound
  item). Surfaces as A1 `PlanAdmissionError::Producer`; never downgraded.

## Exact A1 call shape (in-process, same layer as the stdio loop — never a new stdio op)

```rust
let outcome = produce_settled_plan_feed(SettledPlanFeedInputs {
    view, cue_activation, session_snapshot,
    critical_attention, integration_coverage, policy,
})?;
let report = match outcome {
    SettledPlanFeedOutcome::Ready(feed) => admission.admit_batch(
        runner,
        &feed.batch,
        |item| governor_assess(&live_derivation, item, item.severity == BridgeAdmissionSeverity::Critical),
    )?,
    SettledPlanFeedOutcome::NoSettledPlan(_) => { /* receipt, no calls */ return Ok(()); }
};
```

Rules A1 already enforces (restated for the join, no change requested):
session gate (`batch.session_id` == live attach, else zero calls);
`assess` is the Governor risk owner per item over the SAME critical bit the
transport derives from stickiness (`severity == Critical` ⇔ `critical =
true` — the feed's severity already encodes that bit 1:1 from owner
stickiness, never inference); withholds (`Err`) are skipped with reason,
never admitted; invalidations apply first; replay window retained across
batches in the driver; report via `PlanAdmissionReport` (no silent drops).

## What the feed guarantees / refuses

- Plans derive ONLY from the six owner projections; cue digests come from
  owner source refs, the firing rule from the plan activation digest, the
  governance rev verbatim from the policy digest, the fence natively from
  the request. No caller text is accepted (signature-unrepresentable).
- No sessions minted, no receipts/tokens/snapshots fabricated, no risk
  tier carried (risk is Governor-owned; the batch deliberately lacks it).
- No state held across calls: replay/dedup live in the A1 window + bridge
  ledger (defense in depth, single owners).

## Pending integrator input (B2 daemon central export)

Live projection supplier + live `GovernorCoverageDerivation` threading +
`SettledPlanAdmission` driver retention across batches. Requested via B2;
out of A4 scope to write.
