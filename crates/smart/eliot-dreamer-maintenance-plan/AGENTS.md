# `eliot-dreamer-maintenance-plan` implementation contract

Owning issue: [#677 — A-41 finite owner-bound maintenance candidate](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/677).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.4 — Dreamer input bundle`](../../../docs/architecture/I09-04-dreamer-input-bundle.md#i94-dreamer-input-bundle)
- [`I9.5 — Dream Packet`](../../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I9.8 — Background policy`](../../../docs/architecture/I09-08-background-policy.md#i98-background-policy)
- [`I14.20 — Canonical runtime lifecycle vocabulary`](../../../docs/architecture/I14-20-canonical-runtime-lifecycle-vocabulary.md#i1420-canonical-runtime-lifecycle-vocabulary)
- [`I14.22 — Maintenance jobs`](../../../docs/architecture/I14-22-maintenance-jobs.md#i1422-maintenance-jobs)
- [`I12.24 — Meta-learning and improvement delivery`](../../../docs/architecture/I12-24-meta-learning-and-improvement-delivery.md#i1224-meta-learning-and-improvement-delivery)
- [`I0.10 — User outcome and anti-proxy development`](../../../docs/architecture/I00-10-user-outcome-recovery-invariants-and-anti-proxy-development-contract.md#i010-user-outcome-recovery-invariants-and-anti-proxy-development-contract)
- [`I10.15 — Agent execution fabric and durable swarm`](../../../docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md#i1015-agent-execution-fabric-and-durable-swarm)
- [`I18.2 — Discriminator-first repair`](../../../docs/architecture/I18-02-discriminator-first-repair.md#i182-discriminator-first-repair)
- [`I18.22 — Flake, hang and recurrence handling`](../../../docs/architecture/I18-22-flake-hang-and-recurrence-handling.md#i1822-flake-hang-and-recurrence-handling)

## What to implement

Replace the placeholder with the pure candidate-only planner of one finite owner-bound Maintenance objective: exact trigger, condition, operations, dependencies, independent budgets, expected deltas, semantic verifier, stop/reopen, rollback/disable and Human boundary.

## How

- Validate exact job/task/scope/fence/bundle/grounding/input receipt, objective/owner/current state, trigger evidence/coverage, prior history, policy and all independent resource/context/cost/Human/time/work bounds.
- Require one concrete observed condition and current owner. Generic optimize/monitor/keep-thinking, unknown measurement or unmapped proxy is not a plan.
- Separate observation/diagnosis owner from every mutation/execution owner and from Human/policy/automation decisions. Unknown ownership blocks completeness.
- Account every prior plan/attempt across planned/admitted/scheduled/attempted/executed/observed/verified/rollback/partial/unknown stages. Equivalent failed/no-progress work requires new conditions or Mechanism Review.
- Use only finite typed operations from the public vocabulary. Every operation has one external owner, immutable inputs/preconditions, observable output, verifier, effect/privacy ceiling, budget, cancellation/deadline, retry/reconciliation, cleanup/rollback and stop/reopen.
- Build a finite acyclic dependency graph or only an explicitly bounded progress-measured loop. Planned budgets are not reservations and independent dimensions cannot compensate.
- Preserve independent correctness, recovery, memory/Context quality, latency/resources/cost, evidence/conformance, capability, security/privacy, maintenance/Human burden and user-outcome deltas.
- Emit a candidate only; create no DurableJob, recurrence, schedule, ReadyQueue/WakeIntent, lease, route, Doctor/tool/process call or configuration effect.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every complete plan has one owner-bound objective, grounded trigger, finite operation graph and one owner/verifier/budget/rollback boundary per operation.
- Generic/proxy/unknown triggers and incomplete denominators cannot produce a complete plan.
- Equivalent prior failure cannot be retried without a changed discriminator/condition or justified controlled repetition.
- Unknown possible effects block unsafe repetition; process exit or metric movement alone is not semantic success.
- Privacy/cost/remote/model/configuration/objective widening requires exact external decision and can be rejected rather than warned.
- No scheduling, execution, live resource acquisition, canonical mutation, authority, effect or Finish API exists.
- All 50 `WORK_UNIT_CASE: 677/1..50` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #969 performs serialized workspace admission.
