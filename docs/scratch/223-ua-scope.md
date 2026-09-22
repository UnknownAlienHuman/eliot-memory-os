# W9 consumer scoping: `eliot-understanding-assessment` (orders 85-86) — #223 follow-up

Status: SCOPING ONLY. No crate created, no `Cargo.toml`, no `src/`, no tests.
The cell exists on base only as prototype
`crates/smart/eliot-understanding-assessment/module.toml` (status `PROTOTYPE`,
`proof_ceiling = "STATIC_FIELD_CONTRACT_ONLY"`; no `Cargo.toml`/`src/`/`tests/` —
verified absent). Exact candidate path confirmed by inspection:
`crates/smart/eliot-understanding-assessment/module.toml`; nothing created.
No implementation until Sagan admits the B-freeze crates
(`eliot-memory-projection`, `eliot-experience-projection`,
`eliot-dreamer-self-query`, `eliot-epistemic-context-provider` — all absent at
base 12eae28a, present only on `work/223-rev12-freeze` tip be1f4b73, inspected
read-only via `git show`).

## 1. Bounded consumer contract

`eliot-understanding-assessment` is a **pure, stateless, Smart-plane consumer**
(`module_id = "smart.understanding.assessment"`, `plane = "Smart"`,
`state_class = "stateless"`, `owned_mutable_state = []`, `allowed_effects = []`)
that assesses one question/task family at one State Fence from **immutable,
owner-produced projections and refs by handle only** and emits a
`CommonGroundAssessment` + `ScopedUnderstandingAssessment` pair as **reversible
candidates with the exact independently recheckable denominator and no score**
(per `module.toml`: `primary_responsibility`, `outputs =
["CommonGroundAssessment candidate", "ScopedUnderstandingAssessment"]`,
`product_pulse = "W9_UNDERSTANDING_PULSE_01"`, orders 85-86 in
`cognitive-wave-09.toml`).

Two functional cells, one crate, one manifest
(`crates_manifest` lists both cells under one `module.toml`; observed, not
resolved here):

- order 85 `smart.understanding.common_ground` — check Common Ground as public
  causal-inheritance survival across model/harness change; tacit competence
  requires requalification. Inputs: immutable `ActiveUnderstandingView` by
  handle (`contract_only`, via `eliot-context-assembly`) + accepted-source
  projection by handle (CC-006). Output: `CommonGroundAssessment` candidate to
  the model/harness-change review path (candidate only).
- order 86 `smart.understanding.scoped_assessment` — emit one
  `ScopedUnderstandingAssessment` per question/task family at one State Fence
  with rival-aware prediction-before-observation and applicable held-out
  discipline. Inputs: immutable `ActiveUnderstandingView` by handle
  (`contract_only`) + outcome/verifier evidence by handle. Output:
  `ScopedUnderstandingAssessment` to the product acceptance path (candidate
  only, held-out where applicable).

Frozen intake surface (freeze `cell_binding` order 85, `consumer_of_freeze =
true`; order 86 reuses the same frozen view type, see §2):

- `ActiveUnderstandingView` **by handle** (frozen; §2). The single compiled-view
  entry point: no second `ContextCompiler` invocation, no second admission
  pass, no `mutable UnderstandingState` (freeze `F-NO-W9-CONSUMER-INVENTION`
  fence, wave-09 `forbidden_edge`, `module.toml` non-goals).
- `CurrentEpistemicPosition` **by handle, already compiled into the view**
  (frozen contracts 1.2.0; §2). The assessment never resolves, acquires, ranks,
  stores, or applies a position itself; where an epistemic contribution envelope
  is cited, it is the B-freeze `EpistemicContextContribution` (digest and claim
  echoed exactly, one scope, one carried fence; superseded positions rejected).
- Outcome/verifier evidence **by handle** (owner-held; never re-authored here).
  Where that evidence is experience-family, it travels as B-freeze
  `ExperienceProjectionView` refs (handle-bound, declared/observed/omitted
  denominator); the typed `SystemObservationJournal` / `EliotSystemExperienceBank`
  / `AgentFeedbackReceipt` projections stay `NOT_FROZEN` — refs only, never
  bodies, never bank/journal ownership, never lifecycle transitions.
- Accepted-source projection **by handle — BLOCKED** (`blocked_inputs =
  ["accepted-source projection (NOT_FROZEN, CC-006)"]`). No assessment may
  invent accepted-source fields, edition identity, section handles, or conflict
  precedence. Until the Architecture/Implementation accepted-source owner
  versions that projection, Common Ground closure fails closed
  (`NOT_ONBOARDED` / `INCONCLUSIVE` / `STALE` per `failure_behavior`; never
  `LOCALLY_ADEQUATE`).

By-handle consumption only: no store queries, no read-set expansion, no model
route, no retrieval/popularity/completion/delivery/agreement signal as
understanding. Deterministic evaluation in input order; per-item gaps become
explicit unknown exclusions with exact missing inputs, never silent drops
(`failure_behavior`: typed `INCONCLUSIVE`/`REFUTED`/`STALE`/`NOT_ONBOARDED`,
never `LOCALLY_ADEQUATE` without the full closure).

## 2. Exact frozen types reused (all verified in source at base)

From `eliot-context-contracts` 1.0.0 (frozen upstream; verified at base
`crates/smart/eliot-context-contracts/src/view.rs:114`):

- `eliot_context_contracts::ActiveUnderstandingView` —
  `{binding: ContextBinding, admitted_ids: Vec<ArtifactId>, rendered:
  Vec<RenderedAtom>, selection: SelectionIntegrityProof, quality:
  QualityScorecard, measurement: SerializedContextMeasurement, output_digest,
  recipe_digest, fence_digest}`; matches the freeze `frozen_type` field list
  exactly (9/9). Immutable assembled view consumed read-only; `binding` is the
  scope/fence gate; digests bind recipe and fence.
- `eliot_context_contracts::ContextBinding` —
  `{task_id, attempt_id, scope_id, state_fence, decision_id, operation_id}`;
  the per-assessment product/State-Fence binding carrier.
- Boundary-recorded, not consumed: `CanonicalProjectionSet`,
  `OmissionRecord`, reactive/view types (`ContextCandidateSet`,
  `AdmittedContextSet`, `ContextPlanningView`, …) — recorded in the freeze for
  boundary completeness; #223 packages must not implement reactive path D
  (`F-NO-REACTIVE-PATH-D`).

From `eliot-epistemic-contracts` 1.2.0 (frozen upstream; verified at base
`crates/smart/eliot-epistemic-contracts/src/admitted.rs:256`):

- `eliot_epistemic_contracts::CurrentEpistemicPosition` —
  `{view_kind: AdmittedKind, admission: AdmittedReceipt, currentness:
  Currentness, supersession: BTreeSet<ArtifactId>, claim: ClaimId, digest}`;
  matches the freeze `frozen_type` field list exactly (6/6). Read view over an
  externally admitted position; coverage completeness only by explicit closed
  validation (`DEN-EPISTEMIC-CLOSURE`).
- Enums: `AdmittedKind{CURRENT_EPISTEMIC_POSITION}`, `Currentness{Current,
  Superseded}`.

From the B-freeze packages (inspected read-only at be1f4b73, `FREEZE_ID =
"cognitive-rev12-contract-schema-freeze-2026-09-22"` in both):

- `EpistemicContextContribution`
  (`eliot-epistemic-context-provider/src/lib.rs`) — read-only envelope over
  frozen shared types (`ProviderId`, position digest + `ClaimId` echoed
  exactly, one `WorkScopeId`, one carried `StateFence`); rejects superseded
  positions. Cited by handle where an epistemic contribution is evidence; the
  owner-neutral `ProviderContribution` stays `NOT_FROZEN` and is never
  duplicated here.
- `ExperienceProjectionView` + `ExperienceEvidenceKind{SystemObservation,
  ExperienceBankRecord, AgentFeedback}` + declared/observed/omitted denominator
  (`eliot-experience-projection/src/lib.rs`) — handle-bound refs under one
  scope and fence; `MAX_EXPERIENCE_REFS/OMISSIONS = 256`. Cited by handle where
  outcome/verifier evidence is experience-family.

Assessment-side field contracts are **already frozen, not invented here**:
`UnderstandingAssessment` (`cognitive-wave-09.toml:365-380`,
`FROZEN_STATIC_FIELD_CONTRACT`, 24 fields — 7 `common_ground_*` + 17
`scoped_*` exactly as listed there), owned public types
`CommonGroundAssessment` (cell `smart.understanding.common_ground`) and
`ScopedUnderstandingAssessment` (cell `smart.understanding.scoped_assessment`)
with `contract_index = "UnderstandingAssessment"`. Implementation reuses these
verbatim; no new public assessment type is scoped.

## 3. Version / scope / fence / denominator obligations

- `VR-EXACT-CONTRACT-VERSION`: records/views cited against a different
  `ContractVersion` triple are rejected (`VersionMismatch`; equality only).
  Frozen: `eliot-context-contracts 1.0.0`, `eliot-epistemic-contracts 1.2.0`.
- `VR-EXACT-SCHEMA-VERSION`: canonical projections require
  `CANONICAL_PROJECTIONS_SCHEMA_VERSION == 1` exactly.
- `VR-DENY-UNKNOWN-FIELDS`: every frozen wire shape denies unknown fields;
  similarity scores, ranks, and model judgments have no field to hide in. Any
  future assessment candidate wire shape carries the same rule.
- `VR-NO-AGGREGATE-SCORE`: no frozen type carries an aggregate intelligence,
  confidence, utility, or learning score — and neither does any assessment the
  crate emits (no global `understands` flag, no single understanding score).
- `VR-FENCE-GATE`: acceptance requires `StateFence::is_compatible_with`
  against the governing fence at the consumer edge. Scope per assessment: one
  declared question/task family × one product/State Fence × one onboarding
  slice with missing inputs; transfer requires an explicit boundary and
  requalification (`fence = "Product and State Fence binding per assessment;
  transfer requires explicit boundary and requalification."`).
- Denominator
  `declared_question_task_family_times_state_fence_with_onboarding_slice_plus_discriminator_plus_outcome_verifier_closure`
  with `RECHECK` rule: re-resolve the declared question/task family,
  product/State Fence, onboarding slice, and missing inputs; verify a public
  rival-aware model, a prediction fixed before observation, a discriminative
  probe/action, applicable outcome/verifier evidence, and revision on failure;
  for product claims verify held-out or leakage-controlled evidence. Any
  `LOCALLY_ADEQUATE` without this exact closure is invalid. Every `Complete`
  state and every `LOCALLY_ADEQUATE` requires the exact independently
  recheckable denominator; `NOT_ONBOARDED` forbids `LOCALLY_ADEQUATE` until
  missing inputs resolve. Omission semantics: graphs, prose quality,
  self-report, delivery receipts, correlated-agent agreement, and fixed
  graph/edge/context thresholds can never set `LOCALLY_ADEQUATE`.
- Proof ladder (I12-34): assessment candidates explain why a proof step was or
  was not reached; they never elevate a step by themselves. Product-level
  claims additionally require the ecological A/B field-test shape (fresh agent,
  real unseen task, no markers/handles/prescribed queries, matched memory-free
  control, real verifier, retention re-check) and the named Product Pulse
  `W9_UNDERSTANDING_PULSE_01`. Package proof records `PACKAGE_PROOF_ONLY`
  before any edge promotion (`F-PACKAGE-PROOF-BEFORE-EDGE`); package proof
  alone never reports product support.

## 4. Non-goals (binding)

- No assessment-type invention beyond frozen refs: `CommonGroundAssessment`
  and `ScopedUnderstandingAssessment` reuse the frozen `UnderstandingAssessment`
  field contract verbatim; no third assessment type, no parallel contribution
  schema, no provider-specific duplicate request/contribution type.
- No model/judgment scores: no global `understands` flag, no single
  understanding score, no model agreement / summary similarity / delivery /
  graph-threshold proxy as `LOCALLY_ADEQUATE` or understanding.
- No reactive D: no `ContextPlanningView` production, no cue-activation wiring,
  no session delivery, no reactive feed (belongs to #1942).
- No promotion: candidates only, to the model/harness-change review path and
  the product acceptance path respectively. No truth/support/authority/policy/
  finish/effect promotion; no canonical writes; no admission, delivery/use
  receipt, lease, or effect ownership (`F-NO-MODEL-STORAGE-NETWORK`).
- No second compilation or admission pass; no mutable `UnderstandingState`; no
  semantic Understanding ownership; no revival of the retired
  `eliot-understanding` facade (`RETIRED_DUPLICATE_UNDERSTANDING_FACADE`, #251);
  no 233 memory-curation/dreamer-cycle or 246 cue-file touches; orders 1-43
  never reused; no automatic workflow trigger (`F-NO-AUTO-TRIGGER`).

## 5. Admission needs (Sagan-owned; no implementation until admitted)

1. B-freeze crate admission: `eliot-memory-projection`,
   `eliot-experience-projection`, `eliot-dreamer-self-query`,
   `eliot-epistemic-context-provider` (producer of the contribution envelope
   and experience refs cited above).
2. Accepted-source projection versioning by the Architecture/Implementation
   owner (CC-006: edition identity, section handles, conflict precedence) —
   unblocks the order-85 `blocked_inputs`.
3. UA crate implementation behind the frozen field contracts, package proof at
   the declared ceiling, real provider/consumer edge proofs
   (`eliot-context-assembly → eliot-understanding-assessment` on
   `ActiveUnderstandingView`; assessment → review/acceptance paths), then the
   named Product Pulse `W9_UNDERSTANDING_PULSE_01` with held-out discipline
   where product claims apply.
4. Workspace admission stays forbidden until implementation, package proof,
   affected edge proof, current-main rebase, and integration-owner
   (`cognitive-wave-integrator`) review.

## 6. Blockers

- `accepted-source projection (CC-006)` is `NOT_FROZEN`: exact versioned
  projection with edition identity does not exist in source; Common Ground
  closure cannot complete until the accepted-source owner versions it. This is
  a producer-side prerequisite, not a license to invent fields here.
- `CC-W9-UNDERSTANDING` is `OPEN_PROVIDER_CONFORMANCE` (required owner:
  Architecture/Implementation accepted-source projection owner); `CC-W9-REV12-HANDOFF`
  resolves for projections via the B-freeze, but UA-side implementation, edge
  proof, and `W9_UNDERSTANDING_PULSE_01` stay `NOT_EXECUTED` until §5 admits.
- Code/document note (reported, not resolved by invention): the freeze binds
  only order 85 explicitly; order 86 reuses the same frozen
  `ActiveUnderstandingView` type entry. Historical #223 cell numbers
  69/70/72/73/75 have no referent in the current topology (orders 1-43 plus
  76-86); disposition `REPORTED_NOT_INVENTED` per the freeze.

## 7. Receipts and reading attestation

- Base: `12eae28aa4154fd4f8deed21cde8b3c9c0e5094a` (verified ancestor of this
  branch; `main` untouched, manager branch `codex/finish-bc-20260922`
  untouched).
- B-freeze tip (read-only): `be1f4b73` =
  `be1f4b732a6b4abac310d9ca14d61b12c4b582e5` (`work/223-rev12-freeze`);
  freeze file `crates/smart/cognitive-rev12-contract-schema-freeze.toml`
  sha256 `8aad397375a1c71da433a55d8a3881c5c009524e51fa7ec70f3ed77376727f13`
  (24480 bytes), `freeze_id =
  "cognitive-rev12-contract-schema-freeze-2026-09-22"`, `proof_ceiling =
  "STATIC_FIELD_CONTRACT_ONLY"`, `implementation_support = "TARGET"`,
  `evidence_execution_status = "NOT_EXECUTED"`.
- Docs routing (unique files, kept out of Git per `AGENTS.md`):
  route receipt `sha256:122dbef634f4c3cd113b6be95bea8d4f815f787995d54eb18909d2ddee519a4d`,
  read receipt `sha256:eeb0d4dfb76fd067d37517837cf84316d5b43c9b413735d62bf0305461cdb146`,
  matched routes `generic-source, memory-context`, 35 required items,
  bundle sha256 `50c836c55c3175babf2077566ab766f6cc5bd50ec92032efad69dbe28e897800`,
  normative pair key `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`.
  Attestation: I opened the verified bundle and read all 35 required items
  (AGENTS.md, WORKFLOW.md, crates/AGENTS.md, ARCHITECTURE_CONTRACT.md,
  DEPENDENCY_POLICY.md, READING_PROTOCOL.md, ACTIVE.toml, fragments
  A0.1/A0.2/A0.3/A0.4/A0.6/A2.3/A4/A5/A6/A7/A10.4/A14.1-A14.4/A14.8/
  I0.3/I0.4/I0.5/I0.13/I0.14/I2.17/I2.20/I12.9/I12.10/I13/I16/I18) before
  writing; no optional fragment was loaded from the bundle. Adjacent owning
  contracts read directly from base: `I06-16-scoped-understanding-assessment`
  (authoritative ScopedUnderstandingAssessment fields, `LOCALLY_ADEQUATE`
  minimum, `NOT_ONBOARDED` rule),
  `I12-34-cognitive-proof-ladder-and-ecological-field-proof` (proof ladder,
  ecological A/B field-test shape), UA `module.toml`, `cognitive-wave-09.toml`
  orders 85-86/field-contract/ownership/edge/donor entries,
  `cognitive-contract-challenges.toml` `CC-W9-UNDERSTANDING`, and the frozen
  source structs (`view.rs:114`, `admitted.rs:256`).
- Doc conformance: `docs/architecture/` is authority; where code and document
  disagree it is reported (§6), no third design invented. #223 owning
  fragments satisfied as scoping inputs: I02-20 (cell/manifest/capsule
  triad — UA has one manifest covering two cells, observed), I18-07/I18-10
  (package proof before edge/product — recorded as ceilings, nothing
  executed). No code, tests, manifests, indexes, or workflows touched; no
  push; no test/eval run.
