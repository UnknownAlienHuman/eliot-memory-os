# `eliot-dreamer-orchestration-plan` implementation contract

Owning issue: [#681 — A-43 bounded agent work-unit planning](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/681).

Current state on `main@8ebf8b41847391c340393d56aeb14dd4f2b5e37b`: `Cargo.toml` declares `source_status = "NOT_IMPLEMENTED"`; `src/lib.rs` is a literal placeholder. `module.toml` is target metadata only.

## Mandatory documentation

Read through `scripts/docs_read.py`, then directly:

- [`I10.15 — Agent execution fabric and durable swarm`](../../../docs/architecture/I10-15-agent-execution-fabric-and-durable-swarm.md#i1015-agent-execution-fabric-and-durable-swarm)
- [`I2.16 — Crate size and agent context envelope`](../../../docs/architecture/I02-16-crate-size-and-agent-context-envelope.md#i216-crate-size-and-agent-context-envelope)
- [`I2.17 — Parallel agent development contract`](../../../docs/architecture/I02-17-parallel-agent-development-contract.md#i217-parallel-agent-development-contract)
- [`I17.14 — Agent work unit over a FunctionalCapabilityCell`](../../../docs/architecture/I17-14-agent-work-unit-over-a-functionalcapabilitycell.md#i1714-agent-work-unit-over-a-functionalcapabilitycell)
- [`I2.18 — Build, test and artifact graph`](../../../docs/architecture/I02-18-build-test-and-artifact-graph.md#i218-build-test-and-artifact-graph)
- [`I2.22 — Parallel build, cache, artifact and environment lanes`](../../../docs/architecture/I02-22-parallel-build-cache-artifact-and-environment-lanes.md#i222-parallel-build-cache-artifact-and-environment-lanes)
- [`I9.7 — Memory transformation validation`](../../../docs/architecture/I09-07-memory-transformation-validation.md#i97-memory-transformation-validation)
- [`I18.7 — Independently testable capability-cell contract`](../../../docs/architecture/I18-07-independently-testable-capability-cell-contract.md#i187-independently-testable-capability-cell-contract)
- [`I18.27 — Oracle ownership and test-change governance`](../../../docs/architecture/I18-27-oracle-ownership-and-test-change-governance.md#i1827-oracle-ownership-and-test-change-governance)
- [`I7.20 — Agent-facing error contract`](../../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract)

## What to implement

Replace the placeholder with the pure candidate-only decomposition owner: one exact admitted objective and immutable owner/source/Architecture evidence produce finite `AgentWorkUnitBrief` candidates, typed dependencies, write serialization, qualified context/cost/proof budgets, artifact handoffs and one synthesis owner.

## How

- Reuse canonical FunctionalCapabilityCell, AgentWorkUnitBrief, path, WorkScope, StateFence, capability, proof and ContextEnvelopeSelectionReceipt contracts; define no competing plan schema.
- Validate exact objective/acceptance, task/scope/fence, source/Architecture/owner/currentness evidence, requirement/surface denominator and all independent bounds.
- Partition by causal owner/cell and exact result/discriminator/proof, not raw LOC or arbitrary file chunks. One unit has one primary cell and one coherent causal property.
- Distinguish write claims, required reads, scan universes, forbidden paths and future artifacts. Shared reads do not serialize work; shared files/manifests/locks/reexports require one explicit writer/integrator.
- Detect lexical/case/path aliases, directory/file overlap and duplicate semantic ownership without filesystem traversal.
- Keep compile/contract prerequisites, runtime producer/consumer edges, write serialization, proof-before-admission and artifact dependencies as distinct relation types; runtime cycles are not automatically compile cycles.
- Derive deterministic readiness order and candidate parallel groups from applicable prerequisites only.
- Measure the complete causal workset plus instructions, tools, evidence, diagnostics, review and safety reserve; select the smallest qualified context profile. Unknown estimates cannot certify fit or force an arbitrary split.
- Require exact parent-requirement→unit→artifact/oracle coverage, one implementation owner per retained requirement, explicit integration consumers and no orphaned safety/recovery obligations.
- Emit candidates only; do not create issues, branches, worktrees, jobs, agents, schedules, routes, leases, processes, patches, merges or Finish.

## Acceptance

- Placeholder and `NOT_IMPLEMENTED` state are removed only with cohesive implementation and tests.
- Every complete plan covers the entire frozen requirement/surface denominator or justified exclusions; file/count success cannot hide an omitted requirement.
- Every unit has exact cell/property/inputs/paths/non-goals/result/discriminator/oracle/proof/budgets/stop/rollback/handoff fields.
- Hidden write or semantic-owner overlaps fail; shared writes have one serialized integrator.
- Readiness cycles, missing prerequisites, orphaned artifacts and duplicate writers fail closed; runtime producer cycles remain distinct.
- Context qualification includes the full workset and reserves; scan roots are not counted as loaded context, and nominal window size is not usable-context proof.
- Package-local proof, workspace admission, Edge and Product/release stages remain distinct and cannot deadlock circularly.
- No launch, resource reservation, issue/agent creation, execution, synthesis, task mutation, authority, effect or Finish API exists.
- All 22 `WORK_UNIT_CASE: 681/1..22` cases execute and pass.
- Package `fmt`, `test`, `clippy -D warnings`, `doc --no-deps` and `git diff --check` pass.
- Package remains standalone until #969 performs serialized workspace admission.
