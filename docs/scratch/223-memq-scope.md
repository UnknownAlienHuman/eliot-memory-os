# W9 consumer scoping: `eliot-memory-quality` (order 76, `smart.memory.ecology`) — #223 follow-up

Status: SCOPING ONLY. No crate created, no `Cargo.toml`, no `src/`, no tests.
The cell exists on base only as prototype `crates/smart/eliot-memory-quality/module.toml`
(status `PROTOTYPE`, no `Cargo.toml` — verified absent). No implementation until Sagan
admits the B-freeze crates.

## 1. Bounded consumer contract

`eliot-memory-quality` is a **pure, stateless, Smart-plane (R5/D3b/C1) consumer** that assesses
one bounded memory scope from **immutable, owner-produced projections only** and emits a
`MemoryEcologyAssessment` with gravity, economics, maintenance, and counter-metric sections
(per `module.toml`: `primary_responsibility`, `outputs`, `state_class = "stateless"`,
`owned_mutable_state = []`, `allowed_effects = []`).

Frozen intake surface (freeze cell_binding order 76, `consumer_of_freeze = true`):

- `MemoryProjectionRecord` read set **by handle** (CC-008);
- admitted task / continuity / safety projections **by handle** (CC-004);
- `HarnessActivationReceiptCandidate` **by handle** (advisory only).

By-handle consumption only: no store queries, no read-set expansion, no second graph,
no retrieval, no popularity signal. Deterministic evaluation in input order; per-item gaps
become explicit unknown exclusions, never silent drops (module.toml `failure_behavior`).

## 2. Exact frozen types reused (all verified in source at base 12eae28a)

From `eliot-memory-projection-contracts` 0.1.0
(`crates/foundation/eliot-memory-projection-contracts/src/`):

- `eliot_memory_projection_contracts::MemoryProjectionBatch` (`batch.rs`) —
  `{contract_version, binding, records, coverage}`; record binding must equal batch
  binding; every record fence `is_compatible_with` the batch fence; handles unique.
- `eliot_memory_projection_contracts::ApplicableMemorySet` (`set.rs`) —
  `{contract_version, binding, applicable, excluded, denominator, truncated,
  revalidation_required, cue_hits_considered}`; denominator/truncation/revalidation echo
  the evaluated batch; `cue_hit` advisory only, never promotes.
- `eliot_memory_projection_contracts::DenominatorState` (`batch.rs`) —
  `Known{total}` / `Unknown{reason}`; Unknown stays representable but evaluation fails
  closed (applicability without a denominator is unprovable).
- `eliot_memory_projection_contracts::MemoryProjectionRecord` (`record.rs`) —
  19 frozen fields incl. `binding`, `state_fence`, `epistemic`, `assertability`,
  `lifecycle`, `freshness`, `roles`, `influence_eligible`, `preconditions`,
  `applicability_limits`, `cue_triggers`, `negative_trigger`; no score/rank/similarity
  field by design.
- `eliot_memory_projection_contracts::MemoryScopeBinding` (`record.rs`) —
  `{task_id, scope_id, session_id, state_fence}`.
- `eliot_memory_projection_contracts::ProjectionCoverage` (`batch.rs`) —
  `{denominator, truncated, frontier, omissions, revalidation_required}`;
  `Known{total}` must cover projected + omitted volume; truncation needs a nonempty
  resume frontier; truncation/omission requires revalidation.
- `eliot_memory_projection_contracts::ExclusionReason` (`set.rs`) — closed set
  (`STALE`, `CONFLICTED`, `REJECTED`, `EPISTEMICALLY_UNKNOWN`, `PROTECTED`,
  `NEGATIVE_MEMORY`, `PRECONDITION_FAILED{id}`, `PRECONDITION_UNASSESSED{id}`,
  `LIFECYCLE_INACTIVE`, `FENCE_MISMATCH`, `SCOPE_MISMATCH`); no cue-hit variant.
- Enums (`record.rs`): `MemoryKind{Episode, Observation, Procedure, Concept,
  NegativeMemory, Counterexample}`, `MemoryRole{Protected, Minority, Counterexample,
  Audit, FailureFingerprint}`, `FreshnessState{Current, Stale, Unknown}`.
- Bounds: `MAX_RECORD_ROLES` 8, `MAX_PRECONDITIONS` 32, `MAX_APPLICABILITY_LIMITS` 32,
  `MAX_CUE_TRIGGERS` 32, `MAX_SCOPE_CHARS` 256, `MEMORY_PROJECTION_MAX_RECORDS` 256,
  `MAX_BATCH_OMISSIONS` 256, `MAX_BATCH_FRONTIER` 256.

From `eliot-context-contracts` 1.0.0 (`crates/smart/eliot-context-contracts/src/`):

- `eliot_context_contracts::TaskProjection`, `ContinuityProjection`, `SafetyProjection`
  (`canonical_projections.rs`, each with `schema_version` + own `ContextBinding`).
- `SafetyProjection::negative_memory_triggers: Vec<String>` — exact trigger identities
  copied verbatim from the Governor owner (verified at `canonical_projections.rs:128`).
- `eliot_context_contracts::ContextBinding` (`{task_id, attempt_id, scope_id,
  state_fence, decision_id, operation_id}`); every member binding must equal the set
  binding under a two-way `is_compatible_with` fence gate.
- `ActiveUnderstandingView` is recorded for boundary completeness; memq does NOT
  consume or produce it (order-85 crate owns that edge).

From `eliot-learning-contracts` (`crates/smart/eliot-learning-contracts/src/`):

- `eliot_learning_contracts::HarnessActivationReceiptCandidate` (`activation.rs`) —
  **advisory input only** (module.toml: "advisory HarnessActivationReceipt candidates
  by handle"); owns no aggregate, derivation, invocation, activation, admission,
  or promotion.
- `eliot_learning_contracts::SourceDenominator` (`state_view.rs`, `{declared,
  observed}`; declared nonzero, observed never above declared) — pattern reference for
  the memq denominator recheck rule; memq's own `MemoryEcologyAssessment` field contract
  is W9-consumer-owned and defined at implementation time, not in the freeze.

NOT consumed: `eliot-epistemic-contracts` (frozen but not in the order-76
`frozen_inputs`); reactive path-D types (`ContextCandidateSet`, `AdmittedContextSet`,
`ContextPlanningView`, `SessionDeliverySnapshot`, reactive coverage/attention — freeze
records them for boundary completeness only); all `[[not_frozen]]` names
(`MemoryQueryIntent`, `MemorySelectionPolicy`, `MemorySelectionTrace`,
`MemoryContextProjectionRequest`, owner-neutral `FailureObservation` /
`ProviderContribution`, rev12 closed seven-class provider enum, `MemoryRevisionEvidence`).

Code/document agreement note: freeze `cell_number_note` reports historical #223 cell
numbers 69/70/72/73/75 have no referent in the current topology (orders 1–43 + 76–86)
as `REPORTED_NOT_INVENTED`. This scope binds current order 76 only and invents no
mapping for the stale numbers. No code/document disagreement found in the frozen
type shapes themselves — freeze field lists match the verified source structs.

## 3. Version / scope / fence / denominator compatibility obligations

- VR-EXACT-CONTRACT-VERSION: batch/set/view written against a different
  `ContractVersion` triple is rejected with `VersionMismatch`. Equality only.
- VR-EXACT-SCHEMA-VERSION: canonical projections require
  `CANONICAL_PROJECTIONS_SCHEMA_VERSION` exactly (1); mismatch fails closed.
- VR-DENY-UNKNOWN-FIELDS: every frozen wire shape carries `deny_unknown_fields`
  (or a checked wire `TryFrom`); unknown fields fail at the boundary. memq's own
  future types must set `require_deny_unknown_fields = true`, `forbid_unsafe = true`.
- VR-NO-AGGREGATE-SCORE: no aggregate intelligence/confidence/utility/learning score
  anywhere; installed/delivered/executed/useful stay distinct. memq gravity/economics
  sections must be per-record/per-section evidence with denominators, never one scalar.
- VR-FENCE-GATE: cross-record/cross-projection acceptance requires
  `StateFence::is_compatible_with` against the governing fence; incompatible material
  becomes a named omission/exclusion, never silent loss or filler.
- DEN-MEMORY-BATCH: every `Complete` state requires the exact independently
  recheckable denominator — `DenominatorState::Known{total}` over the read-side
  observed volume at the named batch fence, with explicit truncation frontier, named
  omissions, and revalidation flag.
- Scope/fence bindings travel intact: `MemoryScopeBinding` equality for batch
  membership; `ContextBinding` equality + two-way fence compatibility for projection
  intake; minority/protected/counterexample/audit `MemoryRole`s travel intact.
- Normative memory invariants (A14.4, bundle-verified): low use never reduces factual
  support; frequent retrieval never strengthens a record; popularity never deletes
  minority evidence. Gravity marks narrowing/suppression *candidates*, never automatic
  deletion (A14.4 "Memory gravity … creates a narrowing or suppression candidate, not
  automatic deletion of minority evidence"). Health measures to cover at proof time:
  stale reuse, false promotion, wrong-scope reuse, negative transfer, poisoned
  influence, cue overload, false activation/block, missing-context regret, compaction
  loss, capture/curation/restore cost, failures prevented / decisions improved.
- Fences: F-NO-MODEL-STORAGE-NETWORK (no model route, storage, network, canonical
  write, admission, lease, or effect); F-NO-REACTIVE-PATH-D (no `ContextPlanningView`
  production, cue activation wiring, session delivery, reactive feed — #1942-owned);
  F-NO-AUTO-TRIGGER (workflows stay `workflow_dispatch` only);
  F-PACKAGE-PROOF-BEFORE-EDGE (independent package build against the freeze, declared
  contract only; `PACKAGE_PROOF_ONLY` before any edge promotion; package proof alone
  never reports product support). Product Pulse at promotion: `W9_MEMORY_QUALITY_PULSE_01`.
  F-NO-W9-CONSUMER-INVENTION constrains *projection* packages, not this crate:
  `MemoryEcologyAssessment` output belongs here (order 76), and its field contract is
  defined at implementation time — out of scope for this note.

## 4. Non-goals (explicit)

- No scoring invention: no aggregate score, rank, similarity, retrieval-count, or
  model-judgment field; no universal fixed thresholds (module.toml `non_goals`).
- No reactive path D: nothing from the frozen reactive/view type list is implemented.
- No support promotion: retrieval/repetition/agreement never reinforce support; low
  use never reduces support; gravity output is a candidate, not a deletion or a
  lifecycle transition (transitions stay on the named Governor path).
- No store queries, no read-set expansion, no second graph, no canonical writes.
- No provider/model SDKs, vendor, or storage types in the public contract.
- No `MemoryQueryIntent` / `MemorySelectionPolicy` / `MemorySelectionTrace` /
  `MemoryContextProjectionRequest` invention (all `NOT_FROZEN` — stop and return
  `ContractChallenge` to `cognitive-wave-integrator` if needed).

## 5. Workspace-admission dependency lines (for Sagan at implementation time — DO NOT APPLY NOW)

Root `Cargo.toml` `[workspace] members` (Sagan-owned): add exactly

```toml
"crates/smart/eliot-memory-quality",
```

Future `crates/smart/eliot-memory-quality/Cargo.toml` `[dependencies]` (conventions
verified: foundation paths from `eliot-memory-applicability/Cargo.toml:24-26`;
sibling path+version form from `eliot-dreamer-bundle/Cargo.toml:24`):

```toml
eliot-contracts = { path = "../../foundation/eliot-contracts", version = "0.1.0" }
eliot-evidence = { path = "../../foundation/eliot-evidence", version = "0.1.0" }
eliot-memory-projection-contracts = { path = "../../foundation/eliot-memory-projection-contracts", version = "0.1.0" }
eliot-context-contracts = { path = "../eliot-context-contracts", version = "0.1.0" }
eliot-learning-contracts = { path = "../eliot-learning-contracts", version = "0.1.0" }
```

Plus the standard prototype `[workspace]` standalone-root + mirrored `[workspace.lints]`
tables (copy verbatim from `eliot-memory-applicability/Cargo.toml:39-62`), dropped at
promotion; `[package.metadata.eliot]` with `functional_cell = "smart.memory.ecology"`,
`agent_order = 76`, `workspace_admission = "pending_agent_implementation_and_proof"`.
`Cargo.lock` / member index updates are Sagan-owned. No new third-party dependency:
`schemars`, `serde` (derive), `thiserror` only, matching the applicability prototype.

## 6. Reading attestation

- `docs_read` route receipt `sha256:8de2cb55f6af9888d9df9e71c2d7dcfad16fb139691abf0ca0c35d6b6a986570`,
  read receipt `sha256:8718c884bab62e7e5f0c104e1a1f853cf91b4d8dd055ede56a2ee4211d2434d1`,
  matched routes `generic-source, memory-context`, bundle
  `f807d3f41d0a6aca9203218e2f1903c1f1d06cd79104deae51ec5df447df5065` (35 required
  items, all opened and read, incl. A14.3/A14.4, A2.3, I2.17/I2.20, DEPENDENCY_POLICY).
- Freeze `cognitive-rev12-contract-schema-freeze-2026-09-22` read read-only via
  `git show be1f4b73:...` (24,480 bytes); base 12eae28a verified ancestor of this branch.
- GH issue #223: one owner comment (tracker dedup of #253, stays OPEN, no
  implementation claims) read via `gh issue view 223`.
- Module/proof sources read: `eliot-memory-quality/module.toml`,
  `eliot-memory-applicability/{module,Cargo}.toml`,
  `eliot-memory-curation-contracts/module.toml`, `eliot-context-contracts/src/quality.rs`
  + `canonical_projections.rs` (struct + `negative_memory_triggers` verification),
  `eliot-memory-projection-contracts` `record.rs`/`batch.rs`/`set.rs` type inventory,
  `eliot-learning-contracts` `activation.rs`/`state_view.rs` type inventory.
