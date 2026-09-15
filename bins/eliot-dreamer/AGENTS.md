# `eliot-dreamer` governed runtime contract

Owning issue: [#702 — governed Dreamer daemon and semantic runtime composition](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/702).

Current source base: `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`.

The package contains provisional job/input/result DTOs and a `KernelSupervisedComposition`, but production is not connected. `AuthenticatedKernelJobPort::connect()` performs a generic string operation `dreamer.claim` and then always returns `KernelAdmissionRequired`; every `KernelJobPort` method also always refuses. `src/main.rs` converts even hypothetical successful connection into exit 78. No semantic pipeline, admitted model route, handler registry, durable result submission or reconciliation is reachable.

## Mandatory documentation

Run `scripts/docs_read.py` for every actual mutable path, then directly read:

- [`I9.1 — Process model`](../../docs/architecture/I09-01-process-model.md#i91-process-model)
- [`I9.2 — Dreamer service responsibilities`](../../docs/architecture/I09-02-dreamer-service-responsibilities.md#i92-dreamer-service-responsibilities)
- [`I9.3 — Job classes`](../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.4 — Dreamer input bundle`](../../docs/architecture/I09-04-dreamer-input-bundle.md#i94-dreamer-input-bundle)
- [`I9.5 — Dream Packet`](../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.6 — Curation candidate`](../../docs/architecture/I09-06-curation-candidate.md#i96-curation-candidate)
- [`I9.7 — Memory transformation validation`](../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I9.8 — Background policy`](../../docs/architecture/I09-08-background-policy.md#i98-background-policy)
- [`I9.15 — Dreamer failure`](../../docs/architecture/I09-15-dreamer-failure.md#i915-dreamer-failure)
- [`I1.5 — Demand start, observable use, supervision and idle shutdown`](../../docs/architecture/I01-05-demand-start-observable-use-supervision-and-idle-shutdown.md#i15-demand-start-observable-use-supervision-and-idle-shutdown)
- [`I1.13 — Kernel unavailability`](../../docs/architecture/I01-13-kernel-unavailability.md#i113-kernel-unavailability)
- [`I7.20 — Agent-facing error contract`](../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)
- [`I14.22 — Maintenance jobs`](../../docs/architecture/I14-22-maintenance-jobs.md#i1422-maintenance-jobs)
- [`I14.29 — Stage-local recovery, progress clocks and parkable resources`](../../docs/architecture/I14-29-stage-local-recovery-progress-clocks-and-parkable-resources.md#i1429-stage-local-recovery-progress-clocks-and-parkable-resources)

## Required owner chain

Do not implement a local substitute for the existing owners. The runtime chain is:

```text
Kernel-admitted A-03 job
→ pure controller transition (#806)
→ frozen bundle (#593)
→ Curation screen when applicable (#588)
→ externally admitted model/provider route
→ structured A-03 draft
→ grounding (#602)
→ pre-handler A-05 validation exactly once (#595)
→ exact native semantic owner
→ intrinsic A-03 result-envelope validation
→ typed durable result submission/reconciliation
→ bounded output and acknowledgement
```

Required control/storage edges are #769, #773, #775, #777, #779 and #781. Required native semantic owners are listed in #702; do not invent a tenth job class or a generic handler fallback.

## What to implement

- Replace generic `dreamer.claim` and unconditional refusal with the exact role-separated typed Kernel Dreamer control contract.
- Remove, migrate or explicitly isolate provisional duplicate DTOs in this package once canonical public types exist.
- Compose the pure controller, frozen-bundle stage, Curation pre-screen, admitted model stage, grounding, one pre-handler validation, exact semantic dispatch and result submission.
- Build one immutable registry for the nine job classes and eleven Curation wire kinds/ten handler families.
- Preserve durable operation identity, replay, cancellation, unknown submission, restart, drain and idle shutdown without local authoritative job state.
- Keep stdout as bounded protocol output and logs/diagnostics on stderr.

## How

- Obtain installation/principal/session/requester/task/attempt/scope/fence/epoch/generation, route/model/privacy/effect ceilings, budgets, cancellation and idempotency from authenticated Kernel admission.
- Reject missing or stale authority before source/model/handler work; health or process liveness is not capability.
- Resolve only admitted immutable source handles. Invoke the bundle compiler once and retain incomplete/partial/exhausted frontiers.
- For Curation, invoke the exact screen once before model work. Existing mutable targets must be terminal eligible; protected records may remain immutable evidence/counterevidence.
- Invoke the exact admitted model/provider operation once. After possible work or submission, reconcile the same operation rather than rerunning or changing route.
- Ground once, validate once before dispatch, and invoke exactly one native semantic owner. A-31 remains the sole Curation fan-in.
- Preserve every phase identity, receipt, omission, contradiction, unknown and proof ceiling in the result packet.
- Keep result construction, durable submission, committed readback, output delivery, acknowledgement and user-task Finish distinct.
- Rehydrate only from exact durable records and the pure controller. Do not infer ownership from liveness, latest timestamp or process name.

## Acceptance criteria

- A valid typed Kernel claim enters the real pipeline; missing/invalid/stale admission still fails before any semantic/provider effect.
- No production generic string `dreamer.claim` or always-refusing `KernelJobPort` remains.
- The governed profile cannot fall back to test/fixture mode; fixture mode cannot access real credentials, provider or Store.
- The canonical nine job classes map to exactly one native owner/profile; Curation maps eleven kinds to ten families through A-31.
- Bundle, screen, model, grounding and A-05 validation execute at most once per admitted operation and in the mandated order.
- Unknown provider or result submission never triggers semantic recomputation or alternate-route retry.
- Every job/result phase retains one predecessor, durable identity and terminal/reconciliation disposition.
- Cancellation before possible work remains distinct from possible provider/result work; stale late output cannot revive ownership.
- Output failure after committed result replays the stored result without rerunning the pipeline.
- Drain/idle shutdown requires a complete denominator of accepted, pending, unknown and reconciling operations.
- No candidate application, canonical semantic write, authority issuance, task Finish or duplicate scheduler exists in this package.
- All 75 `WORK_UNIT_CASE: 702/1..75` tests execute and pass against the production composition path.
- Package fmt/test/Clippy and `git diff --check` pass; actual live Kernel/provider/Store and Product evidence remains separate.
