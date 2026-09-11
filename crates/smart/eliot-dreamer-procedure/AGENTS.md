# `eliot-dreamer-procedure` implementation contract

Owning issue: [#661 — A-25 grounded inert procedure/Skill candidate](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/661).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal capability-cell placeholder. `module.toml` is planning metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I9.3 — Job classes`](../../../docs/architecture/I09-03-job-classes.md#i93-job-classes)
- [`I9.5 — Dream Packet`](../../../docs/architecture/I09-05-dream-packet.md#i95-dream-packet)
- [`I9.6 — Candidate kinds`](../../../docs/architecture/I09-06-candidate-kinds.md#i96-candidate-kinds)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I7.12 — Short Skills`](../../../docs/architecture/I07-12-short-skills.md#i712-short-skills)
- [`I7.25 — Skill lifecycle and execution evidence`](../../../docs/architecture/I07-25-skill-lifecycle-interaction-and-execution-evidence.md#i725-skill-lifecycle-interaction-and-execution-evidence)
- [`I12.4 — Core record families`](../../../docs/architecture/I12-04-core-record-families.md#i124-core-record-families)
- [`I12.18 — Prediction and calibration`](../../../docs/architecture/I12-18-prediction-and-calibration.md#i1218-prediction-and-calibration)
- [`I12.19 — Negative memory`](../../../docs/architecture/I12-19-negative-memory.md#i1219-negative-memory)
- [`I12.21 — Memory ecology, residual experience and transfer`](../../../docs/architecture/I12-21-memory-ecology-residual-experience-and-transfer.md#i1221-memory-ecology-residual-experience-and-transfer)
- [`I12.26 — Memory admission and retrieval trace`](../../../docs/architecture/I12-26-memory-admission-and-retrieval-trace.md#i1226-memory-admission-and-retrieval-trace)
- [`I10.8.2 — One Windows ProcessExecutor`](../../../docs/architecture/I10-08-02-ip0-one-windows-processexecutor.md#i1082-ip0--one-windows-processexecutor)
- [`I21.6 — Source portfolio and coverage denominator`](../../../docs/architecture/I21-06-source-portfolio-coverage-denominator-and-coveragereceipt.md#i216-source-portfolio-coverage-denominator-and-coveragereceipt)
- [`I5.27 — Canonical operation and effect identity`](../../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity)

## What to implement

Replace the placeholder with the deterministic stateless owner of one bounded, reversible, inert Procedure/Skill candidate grounded in validated structured evidence.

## How

- Consume exact A-03/A-05 validated inputs and canonical Procedure/Skill, capability, operation, verifier and execution-evidence contracts; invoke none of their algorithms.
- Require one objective and a finite typed step graph. Every step names one operation owner/contract, inputs, preconditions, dependencies, observable postcondition, verifier, effect boundary, cancel/timeout/retry/reconcile/cleanup/rollback semantics.
- Reject raw shell/command/SDK payloads, acquired credentials/leases/permits/process handles and unbounded loops/fan-out/retries.
- Separate requested, admitted, attempted, executed, acknowledged, observed and semantically verified evidence. Exit zero, confidence or one successful episode does not prove mechanism or portability.
- Preserve failures, partial/cancel/timeout/unknown-effect runs, counterexamples, environment differences and negative transfer.
- Unknown possible effect blocks retry until the external owner reconciles the exact operation.
- Derive trigger and applicability only within supported environment/scope/version evidence. Similarity is not an exact failure fingerprint or execution permission.
- Emit duplicate/refinement/conflict/empirical/missing-verifier/unsafe/partial dispositions without installing, publishing or executing the candidate.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and substantive tests.
- Every complete candidate has finite typed steps; each step has exactly one owner, precondition, postcondition, verifier, budget, failure, cancellation, reconciliation and rollback/compensation boundary.
- Unknown effects have no blind-retry path; cleanup and rollback are independently owned and verified.
- Trigger/applicability/transfer cannot exceed exact evidence; negative episodes and contradictory lineages remain visible.
- Capability availability never becomes authority or a live reservation.
- No executor/tool/provider/model/environment discovery, secret, Skill installation/publication, configuration/canonical mutation, authority, effect or Finish API exists.
- All 50 `WORK_UNIT_CASE: 661/1..50` cases from the Issue execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains independently buildable until #965 performs serialized workspace admission.
