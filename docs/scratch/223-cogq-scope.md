# W9 consumer scoping: `eliot-cognitive-quality` (orders 80–84) — #223 follow-up

Status: SCOPING ONLY. No crate created, no `Cargo.toml`, no `src/`, no tests.
The cell exists on base only as prototype `crates/smart/eliot-cognitive-quality/module.toml`
(status `PROTOTYPE`, no `Cargo.toml`/`src/`/`tests/` — verified absent). No implementation
until Sagan admits the B-freeze crates (`eliot-memory-projection`,
`eliot-experience-projection`, `eliot-dreamer-self-query`,
`eliot-epistemic-context-provider` — all absent at base 12eae28a, present only on
`work/223-rev12-freeze` tip be1f4b73, inspected read-only via `git show`).

## 1. Bounded consumer contract

`eliot-cognitive-quality` is a **pure, stateless, Smart-plane consumer** that projects one
bounded quality scope from **immutable, owner-produced projections and refs by handle
only** and emits `CognitiveQualityAssessment` sections as **reversible candidates with
exact per-sub-assessment denominators and no aggregate score** (per `module.toml`:
`primary_responsibility`, `outputs = ["CognitiveQualityAssessment"]`,
`state_class = "stateless"`, `owned_mutable_state = []`, `allowed_effects = []`,
`module_id = "smart.cognitive.quality"`, orders 80–84 in `cognitive-wave-09.toml`).

Sub-scopes (one crate, five functional cells, `W9_COGNITIVE_QUALITY_PULSE_01`):

- order 80 `smart.skill.lifecycle` → `SkillLifecycleView` candidate (one derived view per
  Skill revision from execution evidence; lifecycle changes stay reversible candidates);
- order 81 `smart.tool.surface` → `ToolSurfaceAssessment` candidate (exact tool-definition
  versions, eligibility/activation/adherence checkpoints, false-activation history; mark
  stale before material use on definition change);
- order 82 `smart.dreamer.job_economics` → `DreamerJobEconomics` candidate (durable job,
  route-usage, curation, outcome receipts; promotion needs declared downstream utility
  exceeding full cost plus measured harms);
- order 83 `smart.self.quality_view` → `EliotSelfQualityView` + `LearningBottleneckDiagnosis`
  candidates (problem-oriented, counter-metrics, failing contours; never a global score);
- order 84 `smart.self.intervention_candidate` → `SelfQualityInterventionReceipt` candidate
  (causal hypothesis, rivals, discriminator, authority refs, rollback, terminal
  disposition; recurring same-hypothesis failure yields Mechanism Review).

Frozen intake surface (freeze `cell_binding` order 80, `consumer_of_freeze = true`):

- `HarnessActivationReceiptCandidate` **by handle** (frozen; §2);
- `MemoryProjectionRecord` read set **by handle** (CC-008, frozen; memory evidence for
  skill/tool sections cites records, never re-projects);
- `ExperienceProjectionView` refs **by handle** (B-freeze package; typed journal / bank /
  feedback projections stay `NOT_FROZEN` → handle-only, §2);
- `CurrentEpistemicPosition` / `EpistemicContextContribution` **by handle**
  (frozen contracts + B-freeze envelope; digest and claim echoed exactly, §2);
- `Problem` / `ImprovementCandidate` refs **by handle** (owner-held; never re-authored
  here); applicable verifier / Product Pulse refs **by handle**.

By-handle consumption only: no store queries, no read-set expansion, no second graph, no
retrieval/popularity signal, no second compilation, no second admission, no model route.
Deterministic evaluation in input order; per-item gaps become explicit unknown
exclusions, never silent drops (module.toml `failure_behavior`: fail closed with exact
missing evidence, never fabricate quality/benefit/promotion).

## 2. Exact frozen types reused (all verified in source)

From `eliot-learning-contracts` (frozen upstream; verified at base
`crates/smart/eliot-learning-contracts/src/`):

- `eliot_learning_contracts::HarnessActivationReceiptCandidate` (`activation.rs:244`) —
  `{binding, activation_id, target, view_digest, delta_id, overlay_id,
  admission_receipt, activation_request_receipt, stages, member_denominator, metrics,
  attrition, confounders, independent_evaluator_receipt, canonical_digest}`; matches the
  freeze `frozen_type` field list exactly (15/15). Per-attempt refs decide
  eligibility/activation/adherence; `member_denominator: SourceDenominator{declared,
  observed}` is retained separately from observed counts (declared nonzero, observed never
  above declared — `state_view.rs:85`).
- `eliot_learning_contracts::ContractBinding` (`identity.rs:89`) —
  `{schema_version, policy_revision, request_id, operation_id, product_id, task_id,
  scope, state_fence, source, proof_ceiling}`; scope/fence gate for every receipt cited.
- Candidate types (`UseAttributionCandidate`, `ImprovementExperimentCandidate`,
  `PromotionBoundaryCandidate`, `AttemptLearningDeltaCandidate`,
  `CampaignLearningStateView`, `CampaignHarnessOverlayCandidate`) recorded for boundary
  completeness; cogq cites receipts, never derives promotions.

From `eliot-epistemic-contracts` 1.2.0 (frozen upstream; verified at base
`crates/smart/eliot-epistemic-contracts/src/admitted.rs:256`):

- `eliot_epistemic_contracts::CurrentEpistemicPosition` —
  `{view_kind, admission, currentness, supersession, claim, digest}`; matches the freeze
  field list exactly (6/6), `deny_unknown_fields` + checked wire `TryFrom`. Consumer uses
  the canonical name only: the `CurrentEpistemicPositionView` alias (`admitted.rs:277`)
  is a migration shim for existing readers, not a second type to import.
- `Currentness{Current, Superseded}`; superseded positions contribute nothing
  (DEN-EPISTEMIC-CLOSURE: coverage completeness only by explicit closed validation;
  unknown/assumed/conflicted/stale stay distinct).

From the B-freeze packages (tip be1f4b73, read-only via `git show`; `FREEZE_ID =
"cognitive-rev12-contract-schema-freeze-2026-09-22"` in all four):

- `eliot-memory-projection`: `MemoryCandidateSnapshot{binding, candidates[],
  denominator_total, truncated, revalidation_required}` over `MemoryCandidateRef{handle,
  kind}` selected by `MemoryCandidateQuery{binding, limit, kinds[]}` from one validated
  `MemoryProjectionBatch`. cogq may cite snapshot handles plus the echoed
  `binding`/`denominator_total`; the snapshot emits no applicability verdict, so
  selection is never support/utility evidence (VR-NO-AGGREGATE-SCORE).
- `eliot-experience-projection`: `ExperienceProjectionView{scope_id, state_fence, refs[],
  declared_total, omissions[]}` with `ExperienceEvidenceRef{handle, kind}` where `kind ∈
  {SystemObservation, ExperienceBankRecord, AgentFeedback}`. Refs only — the typed
  `SystemObservationJournal` / `EliotSystemExperienceBank` / `AgentFeedbackReceipt`
  projections stay `NOT_FROZEN` (freeze `[[not_frozen]]`, CC-W9-COGNITIVE-QUALITY), so
  cogq consumes experience evidence **by handle only** and recomputes the
  declared == observed + omitted denominator at the named fence; contradiction fails
  closed. No second self-memory owner (retired `eliot-system-experience` stays retired).
- `eliot-epistemic-context-provider`: `EpistemicContextContribution{contract_version,
  provider, position_digest, claim, scope_id, state_fence}` (`PROVIDER_LABEL =
  "smart.epistemic.context-provider"`); digest + claim echoed exactly, one scope, one
  carried fence, superseded rejected, fence compatibility gated at the consumer edge.
  cogq cites the contribution envelope for observation-coverage comparison; it never
  resolves/acquires/ranks/stores/applies. The owner-neutral `ProviderContribution` stays
  `NOT_FROZEN` — this envelope is not duplicated under a new name.
- `eliot-dreamer-self-query`: `SelfQueryRequest{subject{question, task_family},
  scope_id, state_fence, view_ref, source_refs[]}` + `SelfQueryCandidate{request,
  request_digest}` (sha256 over canonical JSON). Boundary only: cogq does NOT pose
  queries, compile views, admit, author briefs, or call model routes; the digest pattern
  is the reference for how cogq's own intervention refs stay handle-bound and
  re-verifiable. (Order-85 `ActiveUnderstandingView` edge belongs to
  `eliot-understanding-assessment`, not this crate.)

NOT consumed: reactive path-D types (`ContextPlanningView`, cue activation wiring,
session delivery — freeze records them for boundary completeness only, #1942-owned);
owner-neutral `FailureObservation` / `MemoryRevisionEvidence` (`NOT_FROZEN` — order-79
territory); `MemoryQueryIntent` / `MemorySelectionPolicy` / `MemorySelectionTrace` /
`MemoryContextProjectionRequest` (`NOT_FROZEN`); rev12 closed seven-class provider enum
(`NOT_FROZEN` — current `ProviderRole` is a slot struct); accepted-source projection
(CC-006, `NOT_FROZEN`); retired `eliot-system-experience` ownership; MCP surface DTOs.

Code/document agreement note: freeze `cell_number_note` already reports historical #223
cell numbers 69/70/72/73/75 as `REPORTED_NOT_INVENTED` (no referent in orders 1–43 +
76–86). This scope binds current orders 80–84 only and invents no mapping. No new
code/document disagreement found in the frozen shapes checked here — freeze field lists
for `HarnessActivationReceiptCandidate` (15/15) and `CurrentEpistemicPosition` (6/6)
match the verified source structs. Disjointness: sibling scope
`docs/scratch/223-memq-scope.md` (branch `work/223-memq-scope`) owns order 76
(`MemoryEcologyAssessment`); this note emits nothing outside `CognitiveQualityAssessment`
sections and cites sibling outputs by handle only.

## 3. Version / scope / fence / denominator compatibility obligations

- VR-EXACT-CONTRACT-VERSION: record/batch/contribution written against a different
  `ContractVersion` triple is rejected with `VersionMismatch`. Equality only.
- VR-EXACT-SCHEMA-VERSION: canonical projections require
  `CANONICAL_PROJECTIONS_SCHEMA_VERSION` exactly (1); learning bindings require
  `LEARNING_SCHEMA_VERSION` exactly; mismatch fails closed.
- VR-DENY-UNKNOWN-FIELDS: every frozen wire shape carries `deny_unknown_fields` (or a
  checked wire `TryFrom`); cogq's own future types must set
  `require_deny_unknown_fields = true`, `forbid_unsafe = true` (module.toml
  `[acceptance]`).
- VR-NO-AGGREGATE-SCORE: no aggregate intelligence/confidence/utility/learning score,
  no global self-quality score, no single understanding-style scalar anywhere;
  installed != delivered != executed != useful; acknowledgement is not use, use is not
  adherence, adherence is not benefit. Skill/tool/economics/self sections stay
  per-attempt/per-section evidence with denominators.
- VR-FENCE-GATE: cross-record/cross-projection acceptance requires
  `StateFence::is_compatible_with` against the governing fence; tool-definition versions
  pin staleness; incompatible material becomes a named omission/exclusion, never silent
  loss or filler. Silence about adherence is unknown, not compliance.
- Per-sub-assessment denominators (each `Complete` needs its own independently
  recheckable denominator; aggregate counts never substitute for per-attempt receipts):
  skill/tool-surface recompute delivered/expanded/executed + eligibility/activation/
  adherence from per-attempt `HarnessActivationReceiptCandidate` refs at the named
  task/host/route/governance scope; Dreamer economics re-resolves the declared
  job/job-family window + full compute/storage/context/human cost ledger + held-out/live
  outcome refs; self-quality compares observations against the
  `ObservationObligationProfile` (admission need, §5); intervention re-enumerates the
  affected capability closure.
- DEN-LEARNING-STATE / DEN-EPISTEMIC-CLOSURE / DEN-MEMORY-BATCH apply to cited inputs
  as stated in the freeze; cogq echoes, never rewrites, denominators.
- Fences: F-NO-MODEL-STORAGE-NETWORK (no model route, storage, network, canonical
  write, admission, lease, effect); F-NO-REACTIVE-PATH-D (#1942-owned);
  F-NO-W9-CONSUMER-INVENTION constrains *projection* packages, not this crate:
  `CognitiveQualityAssessment` output belongs here (orders 80–84), field contract per
  `cognitive-wave-09.toml`, defined at implementation time; F-NO-AUTO-TRIGGER
  (workflows stay `workflow_dispatch` only); F-PACKAGE-PROOF-BEFORE-EDGE (independent
  package build against the freeze, `PACKAGE_PROOF_ONLY` before edge promotion; package
  proof alone never reports product support). Proof ceiling at freeze stage:
  `STATIC_FIELD_CONTRACT_ONLY`, `NOT_EXECUTED`. Promotion pulse:
  `W9_COGNITIVE_QUALITY_PULSE_01` (one Skill revision + one Dreamer job family, exact
  denominators, no aggregate score).

## 4. Non-goals (explicit)

- No aggregate-score invention: no single intelligence/confidence/utility/learning
  score, no global `EliotSelfQualityView` scalar, no elegant-but-unused synthesis counted
  as utility, no universal fixed thresholds (module.toml `non_goals`, `invariants`).
- No W9 assessment-type emission beyond refs: cogq emits only `CognitiveQualityAssessment`
  sections (`SkillLifecycleView`, `ToolSurfaceAssessment`, `DreamerJobEconomics`,
  `EliotSelfQualityView`, `LearningBottleneckDiagnosis`, `SelfQualityInterventionReceipt`
  candidates). It never emits `MemoryEcologyAssessment`, `NegativeMemoryExtinctionCandidate`,
  `CommonGroundAssessment`, or `ScopedUnderstandingAssessment`; those are cited by handle
  only when a rival/discriminator input names them.
- No reactive D: nothing from the frozen reactive/view type list is implemented; no
  `ContextPlanningView` production, cue wiring, session delivery, or reactive feed.
- No promotion: Dreamer/Curator proposals stay reversible candidates until governed
  promotion; no autonomous schedule promotion; no self-certification or self-promotion;
  one model's delete recommendation is never its own oracle; equivalent retry without a
  changed hypothesis/discriminator is rejected — recurring failure opens Mechanism
  Review; proof depth follows effect per I12-34 lifecycle rules.
- No Skill/tool/config/route mutation, no scheduler/effect/authority ownership, no task
  finish, no store queries, no read-set expansion, no canonical writes.
- No provider/model SDKs, vendor, or storage types in the public contract; no
  `serde_json::Value`, `unimplemented!`, `todo!` (module.toml `[acceptance]`).
- No invention of `NOT_FROZEN` shapes (typed skill-execution evidence, typed
  journal/bank/feedback projections, owner-neutral `FailureObservation` /
  `ProviderContribution`, rev12 provider enum, accepted-source projection) — stop and
  return `ContractChallenge` to `cognitive-wave-integrator` if required.

## 5. Admission needs (for Sagan — DO NOT APPLY NOW)

1. B-freeze crate admission: `eliot-memory-projection`, `eliot-experience-projection`,
   `eliot-dreamer-self-query`, `eliot-epistemic-context-provider` do not exist at base;
   workspace membership, `Cargo.lock`, and package proof order are Sagan-owned. Root
   manifests/indexes untouched by this note.
2. Typed-projection freeze gaps (freeze `[[not_frozen]]`, CC-W9-COGNITIVE-QUALITY):
   Skill execution evidence and `SystemObservationJournal` / `EliotSystemExperienceBank`
   / `AgentFeedbackReceipt` typed projections are consumed **by handle only** until a
   versioned owner-neutral contract exists. Confirm handle-only intake is sufficient for
   orders 80/83 denominators at implementation time.
3. `ObservationObligationProfile` (`crates/foundation/eliot-observation-contracts/src/lib.rs:297`,
   verified at base with `{profile_id, profile_revision,
   producer_capability_and_generation, applicable_classes, expected_event_classes,
   trigger_boundaries, required_capture_route, minimum_durability, denominator,
   sampling, maximum_blind_interval_ms, freshness_window_ms,
   failure_gap_and_governance_disposition, invalidation_set}`) is required by the
   wave-09 denominator rule ("compare observations against the
   ObservationObligationProfile") but is NOT in the freeze upstream list — Sagan to
   confirm whether it is admitted as frozen input or likewise consumed by handle only.
4. `Problem` / `ImprovementCandidate` ref owners for order-84 inputs (by handle;
   authority/rollback scope must be present or the intervention stays INCONCLUSIVE).
5. Declared Cargo dependency closure at implementation time follows
   `module.toml depends_on = ["eliot-dreamer-contracts", "eliot-learning-contracts"]`
   plus frozen memory/epistemic/experience inputs as admitted; no new third-party
   dependency beyond the freeze packages' existing set (`serde`/`schemars`/`thiserror`
   pattern). No directive issued here — Sagan decides.

## 6. Reading attestation

- `docs_read` route receipt `sha256:b6851b8cd2d610b8448a02e624fffadb56b595cd4365d389cdd762c553be5d12`,
  read receipt `sha256:5ea1ff0d57b9cfe728b2101bcaeab646d453b89f9c93b8220126c2b9b5fdc5f3`,
  matched route `documentation-authority`, bundle
  `e7f2a051acf533f52736d869332d691e3a3e98d7cc5e77d4913757c6b56f59f2` (24 required
  items, all opened and read: baseline files + A0.1–A0.6, A16.3, I0.3–I0.5, I0.13,
  I0.14, I2.17, I18; normative pair
  `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`).
- Freeze `cognitive-rev12-contract-schema-freeze-2026-09-22` read read-only via
  `git show be1f4b73:crates/smart/cognitive-rev12-contract-schema-freeze.toml`
  (24,480 bytes); B-package `src/lib.rs` read read-only via `git show be1f4b73:...`
  for all four packages. Base 12eae28a verified ancestor of this branch; no
  rebase/reset/merge performed.
- GH issue #223 (OPEN): body + one owner comment (tracker dedup of #253, stays OPEN;
  package proof, Edge Proof, Product Pulse remain distinct; no implementation claims)
  read via `gh issue view 223`.
- Sources verified at base: `eliot-cognitive-quality/module.toml` (whole file),
  `cognitive-wave-09.toml` orders 80–84 + `CognitiveQualityAssessment` field contract +
  ownership rows, `eliot-learning-contracts/src/activation.rs:244`
  (`HarnessActivationReceiptCandidate`), `identity.rs:89` (`ContractBinding`),
  `state_view.rs:85` (`SourceDenominator`),
  `eliot-epistemic-contracts/src/admitted.rs:256` (`CurrentEpistemicPosition`),
  `eliot-observation-contracts/src/lib.rs:297` (`ObservationObligationProfile`);
  sibling scope `docs/scratch/223-memq-scope.md` (branch `work/223-memq-scope`,
  read-only) for disjointness.
- I attest I read every required bundle item above, inspected the freeze and B-package
  sources read-only as cited, verified each named type/field in code via grep/read, and
  wrote only `docs/scratch/223-cogq-scope.md` (this file). No code, tests, manifests,
  or indexes touched; nothing pushed.
