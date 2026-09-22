# W9 consumer scoping: `eliot-dreamer-memory-revision` (order 79, `smart.dreamer.memory_revision`) — #223 follow-up

Status: SCOPING ONLY. No crate created, no `Cargo.toml`, no `src/`, no tests.
The cell exists on base only as prototype `crates/smart/eliot-dreamer-memory-revision/module.toml`
(status `PROTOTYPE`, no `Cargo.toml` — verified absent). No implementation until Sagan
admits the B-freeze crates (`eliot-dreamer-self-query` lives only on `work/223-rev12-freeze`,
absent at base).

## 1. Bounded consumer contract

`eliot-dreamer-memory-revision` is a **pure, stateless, Smart-plane (R6/D3a/C1) consumer**
that proposes one advisory `NegativeMemoryExtinctionCandidate` over an exact failure
fingerprint with a full dependency-closure denominator, while the original failure
history is preserved verbatim (per `module.toml`: `primary_responsibility`,
`product_objective`, `state_class = "stateless"`, `owned_mutable_state = []`,
`allowed_effects = []`).

Frozen intake surface (freeze `cell_binding` order 79, `consumer_of_freeze = true`):

- admitted task / safety projections **by handle** (CC-004);
- posed dreamer self-query candidates **by digest/handle** (advisory traceability only);
- already-compiled `ActiveUnderstandingView` **by handle** (read-only, no second compilation).

By-handle consumption only: no store queries, no read-set expansion, no compilation,
no admission pass, no brief authorship, no model route. Deterministic evaluation in
input order; missing evidence becomes an explicit unsupported/inconclusive candidate
with the exact missing evidence named — original records remain unchanged
(module.toml `failure_behavior`).

Discriminator (module.toml): the extinction candidate narrows only the advisory
activation/influence fields and preserves every history field; without adequate
adjudication only reversible suppress/quarantine/archive is allowed. Recurring failure
with the same causal hypothesis yields Mechanism Review rather than another equivalent
retry (module.toml `invariants`).

## 2. Exact frozen types reused (all verified in source)

At base `12eae28a`, from `eliot-context-contracts` (`crates/smart/eliot-context-contracts/src/`):

- `eliot_context_contracts::TaskProjection`, `SafetyProjection`
  (`canonical_projections.rs`, each with `schema_version` + own `ContextBinding`;
  `CANONICAL_PROJECTIONS_SCHEMA_VERSION` exactly 1) — the order-79 `frozen_inputs`.
- `eliot_context_contracts::ContextBinding`
  (`{task_id, attempt_id, scope_id, state_fence, decision_id}`); every member binding
  must equal the set binding under a two-way `is_compatible_with` fence gate.
- `eliot_context_contracts::ActiveUnderstandingView`
  (`{binding, admitted_ids, rendered, selection, quality, measurement, output_digest,
  recipe_digest, fence_digest}`, `scope_fence_fields = ["binding"]`) — immutable
  assembled view consumed read-only; no second compilation, no second admission pass,
  no mutable `UnderstandingState`.

From the B-freeze self-query package (read-only via
`git show work/223-rev12-freeze`, commit `da0ae893`; NOT on base, Sagan-owned admission):

- `SelfQuerySubject { question, task_family }` (non-blank, no control chars, ≤1024 bytes);
- `SelfQueryRequest { subject, scope_id: WorkScopeId, state_fence: StateFence,
  view_ref: ArtifactId, source_refs: Vec<ArtifactId> }` — refs by handle only, deduped,
  `MAX_SELF_QUERY_REFS` 32, `MAX_SCOPE_CHARS` 256;
- `SelfQueryCandidate { request, request_digest }` — digest is sha256 over the canonical
  JSON bytes of the request, frozen at `pose()` time; `validate()` recomputes it;
- `pose()`, `FREEZE_ID = "cognitive-rev12-contract-schema-freeze-2026-09-22"`,
  `SelfQueryError { InvalidField, Bounds, NotDigestible }` — every case fails closed.
- Package fences honored downstream: never compiles context, never admits, never authors
  `ArchitectureBrief`/`ImplementationBrief`, never calls a model route; accepted-source
  projection stays `NOT_FROZEN` (CC-006), source refs travel as handles only.

Foundation identities (base source):

- `eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex}`;
  `StateFence::is_compatible_with` + `validate()`; `eliot_receipts::WorkScopeId`.
- `eliot_memory_projection_contracts::MemoryRole::FailureFingerprint`
  (`record.rs:88` — "compact failure identity for recurrence detection"): the ONLY
  `FailureFingerprint` referent in source at base (repo-wide `rg` for a
  `FailureFingerprint` struct/type: no hits). It is a role label on projected records,
  not an owner-neutral observation contract — DMR must not promote it into one.

From `eliot-dreamer-contracts` (ADMITTED hub, order 3 — depended on, not duplicated):

- `depends_on = ["eliot-dreamer-contracts"]` (module.toml); the `self_query::` namespace
  (`input.rs`/`result.rs`/`source.rs`: `SelfQueryInput`, `ArchitectureBriefCandidate`,
  `ArchitectureSourceSnapshot`, `ArchitectureDependencyDenominator`, …) is the A-03 →
  brief-owner handoff — DMR does NOT consume brief outputs (brief authorship is a
  non-goal) and does NOT redeclare any of these shapes (no shims, no aliases, no
  `From`/`Into` bridges).
- The `failure::` namespace (`input.rs`/`records.rs`/`result.rs`) carries no
  owner-neutral `FailureObservation`, `MemoryRevisionEvidence`, or
  `NegativeMemoryExtinctionCandidate` type (verified: no such `pub struct`/`pub enum`
  in `failure/*.rs`). Those outputs belong to this crate at implementation time
  (F-NO-W9-CONSUMER-INVENTION binds *projection* packages, not this consumer).

NOT consumed / blocked (freeze `[[not_frozen]]` + order-79 `blocked_inputs`):

- `FailureObservation` (NOT_FROZEN, CC-FAILURE-OBSERVATION-SCHEMA),
  `MemoryRevisionEvidence` (NOT_FROZEN, CC-W9-MEMORY-REVISION) — stop and return
  `ContractChallenge` to `cognitive-wave-integrator` if needed; never prose-invent.
- accepted-source projection (NOT_FROZEN, CC-006); rev12 closed seven-class provider
  enum (NOT_FROZEN); reactive path-D types (`ContextCandidateSet`, `AdmittedContextSet`,
  `ContextPlanningView`, session delivery — boundary completeness only, #1942-owned).

Code/document agreement note: freeze `cell_number_note` reports historical #223 cell
numbers 69/70/72/73/75 have no referent in the current topology (orders 1–43 + 76–86)
as `REPORTED_NOT_INVENTED`. This scope binds current order 79 only and invents no
mapping for the stale numbers. No code/document disagreement found in the frozen type
shapes themselves — freeze field lists match the verified source structs.

## 3. Version / scope / fence / denominator obligations

- VR-EXACT-CONTRACT-VERSION: batch/set/view written against a different
  `ContractVersion` triple is rejected with `VersionMismatch`. Equality only.
- VR-EXACT-SCHEMA-VERSION: canonical projections require
  `CANONICAL_PROJECTIONS_SCHEMA_VERSION` exactly (1); mismatch fails closed.
- VR-DENY-UNKNOWN-FIELDS: every frozen wire shape carries `deny_unknown_fields`
  (or a checked wire `TryFrom`); unknown fields fail at the boundary. DMR's own
  future types must set `require_deny_unknown_fields = true`, `forbid_unsafe = true`.
- VR-NO-AGGREGATE-SCORE: no aggregate intelligence/confidence/utility/learning score
  anywhere; the candidate carries per-item evidence with denominators, never one scalar.
- VR-FENCE-GATE: cross-record/cross-projection acceptance requires
  `StateFence::is_compatible_with` against the governing fence; incompatible material
  becomes a named omission/exclusion, never silent loss or filler.
- Closure denominator (`cognitive-wave-09.toml` `field_contract_index`
  `NegativeMemoryExtinctionCandidate`): `denominator_ref =
  "enumerated_affected_procedures_views_and_dependency_closure over
  independently_re-enumerated_closure_at_named_fence_with_exclusions"`;
  module.toml invariant: every `Complete` state requires the exact independently
  recheckable closure denominator (source handles I12-19, I12-21).
- Scope/fence bindings travel intact: `ContextBinding` equality + two-way fence
  compatibility for projection intake; self-query `scope_id`/`state_fence` echoed
  exactly; candidate `request_digest` recomputed (never trusted blindly).
- Normative memory invariants (A14.4, bundle-verified): popularity, retrieval
  repetition, or majority narrative must not delete minority, counterexample, audit,
  or failure-fingerprint material; extinction narrows influence after new evidence
  and history remains.
- Fences: F-NO-MODEL-STORAGE-NETWORK (no model route, storage, network, canonical
  write, admission, lease, or effect); F-NO-REACTIVE-PATH-D (no `ContextPlanningView`
  production, cue activation wiring, session delivery, reactive feed); F-NO-AUTO-TRIGGER
  (workflows stay `workflow_dispatch` only); F-PACKAGE-PROOF-BEFORE-EDGE (independent
  package build against the freeze, declared contract only; `PACKAGE_PROOF_ONLY`
  before any edge promotion; package proof alone never reports product support).
  Proof ceiling: `STATIC_FIELD_CONTRACT_ONLY`. Product Pulse at promotion:
  `W9_MEMORY_QUALITY_PULSE_01`.

## 4. Non-goals (explicit)

- No compile/admit/brief/model work: no second `ContextCompiler` invocation, no second
  admission pass, no mutable `UnderstandingState`, no `ArchitectureBrief` /
  `ImplementationBrief` authorship, no model route calls, no support/truth promotion.
- No reactive path D: nothing from the frozen reactive/view type list is implemented.
- No promotion: candidate-only, advisory to the Governor transition path; no
  truth/support/authority/policy/finish/effect promotion.
- No physical purge without full closure; no narrative rewrite; no support revision;
  no automatic deletion; no suppression from rare action-change alone
  (module.toml `non_goals` + wave-09 `forbidden`).
- No `FailureObservation` / `MemoryRevisionEvidence` invention (both `NOT_FROZEN`).
- No provider/model SDKs, vendor, or storage types in the public contract; no unbounded
  synchronous work; no silent truncation; no implicit scope widening.

## 5. Workspace-admission dependency lines (for Sagan at implementation time — DO NOT APPLY NOW)

Root `Cargo.toml` `[workspace] members` (Sagan-owned): add exactly

```toml
"crates/smart/eliot-dreamer-memory-revision",
```

Future `crates/smart/eliot-dreamer-memory-revision/Cargo.toml` `[dependencies]`
(conventions verified: foundation paths from sibling B-freeze `Cargo.toml` files on
`work/223-rev12-freeze`; smart-sibling path+version form):

```toml
eliot-contracts = { path = "../../foundation/eliot-contracts", version = "0.1.0" }
eliot-receipts = { path = "../../foundation/eliot-receipts", version = "0.1.0" }
eliot-context-contracts = { path = "../eliot-context-contracts", version = "0.1.0" }
eliot-dreamer-contracts = { path = "../eliot-dreamer-contracts", version = "0.1.0" }
eliot-dreamer-self-query = { path = "../eliot-dreamer-self-query", version = "0.1.0" }
```

Plus the standard prototype `[workspace]` standalone-root + mirrored
`[workspace.lints]` tables at implementation time, dropped at promotion;
`[package.metadata.eliot]` with `functional_cell = "smart.dreamer.memory_revision"`,
`agent_order = 79`, `workspace_admission = "pending_agent_implementation_and_proof"`.
`Cargo.lock` / member index updates are Sagan-owned. No new third-party dependency:
`serde` (derive) + `deny_unknown_fields`, `schemars`, `thiserror` only, matching the
B-freeze self-query package. No `Cargo.toml`/`src/`/tests created by this scope.

## 6. Reading attestation

- `docs_read` route receipt `sha256:7cf3ffc9429d722d1a6493e7df1c42feedb0d527f11c7ee3bb0aa4387ab3c21a`,
  read receipt `sha256:599166f5530b482268ebc4c118563897ea760b5e195b031ddcd6dc6930e4757a`,
  matched routes `generic-source, memory-context`, bundle
  `5c852af675694bb68f5d3a25504bd879fdc57c54dde9f199e836aab5c1b4ea77` (35 required
  items opened and read).
- Freeze `cognitive-rev12-contract-schema-freeze-2026-09-22` read read-only via
  `git show work/223-rev12-freeze:...` (branch tip `be1f4b73`); B self-query package
  (`src/lib.rs`, `module.toml`, `Cargo.toml`) read read-only via `git show da0ae893:...`.
  Base `12eae28a` verified ancestor of this branch (`git merge-base --is-ancestor` OK).
- GH issue #223: body + one owner comment (tracker dedup of #253, stays OPEN, no
  implementation claims) read via `gh issue view 223`.
- Module/proof sources read at base: `eliot-dreamer-memory-revision/module.toml`,
  `eliot-dreamer-contracts/{module.toml, src/self_query/mod.rs, src/failure/mod.rs}`,
  `cognitive-wave-09.toml` (order-79 brief, `NegativeMemoryExtinctionCandidate`
  ownership + denominator_ref), `cognitive-contract-challenges.toml`
  (CC-W9-MEMORY-REVISION, CC-FAILURE-OBSERVATION-SCHEMA, CC-W9-REV12-HANDOFF),
  `eliot-memory-projection-contracts/src/record.rs` (`MemoryRole::FailureFingerprint`).

## 7. Implementation addendum (real-code era, branch `work/223-dreamer-memory-revision-scope`)

Scoping-only era over. Converged `164e9c8c` by local merge (`b0a9559c`, no
conflicts), reconciled candidate B r4 (`0f3cb2cd`) by read-only checkout
(26 files, committed `4a199f6a`, never edited afterwards).

Blocked inputs implemented FIRST, owner-placed: `FailureObservation`
(CC-FAILURE-OBSERVATION-SCHEMA) and `MemoryRevisionEvidence`
(CC-W9-MEMORY-REVISION) live in
`crates/foundation/eliot-observation-contracts/src/failure_observation.rs`
(new module, wired `mod` + `pub use` in `lib.rs`). Placement: wave briefs
name the Governor canonical observation owner as producer and no separate
failure-observation crate, so this module is the projection-schema owner
beside `experience_projection.rs`, reusing `ObservationScope`,
`SourceRevisionHandle`, `CoverageEvidence`, handle, and fence vocabulary;
live admission/enumeration stays with `eliot-observation`. A14.3 field
shape (trigger, failed action, outcome, violated invariant, scope, reopen
and extinction conditions), closed `FailureOmissionClass`, owner
`Complete`-with-empty-blinds doctrine, frozen digests, `deny_unknown_fields`.

Revision consumer: `crates/smart/eliot-dreamer-memory-revision/` now
`Cargo.toml` + `src/lib.rs`. `propose()` over `FailureObservation` +
`MemoryRevisionEvidence` refs + admitted task/safety projections +
`SelfQueryInput`/`AcceptedSourceProjection` refs with pose-digest recheck
and citation revalidation via owner `check_cited`; scope equality and
`is_compatible_with` fence gates; safety-floor veto (trigger in
`safety.negative_memory_triggers` yields `Unsupported`); same-hypothesis
recurrence yields Mechanism Review (`Inconclusive`); `Complete` requires
exact independently recheckable `ClosureDenominator` (sorted closure,
verbatim exclusions, recheck digest). Output narrows only reversible
advisory fields (no purge field exists); candidate-only, no
compile/admit/brief/model work, no reactive D, no promotion. No parallel
types: reuses `AcceptedSourceProjection`, `SelfQueryInput`,
`TaskProjection`, `SafetyProjection`, foundation observation shapes.

Registration: root `members` + `"crates/smart/eliot-dreamer-memory-revision",
# agent_order 79`; `Cargo.lock` minimal delta (one `[[package]]` entry with
exact edges, hand-applied after `cargo generate-lockfile --offline`
re-resolved unrelated patch versions — reverted); `module.toml`
`workspace_admission = "pending_agent_implementation_and_proof"`.
No new third-party dependency; no `config/dependency-policy.toml` change
(schemars/serde/serde_json/thiserror already inventoried). Sagan
A1/engine files untouched.

Gates: `cargo check --locked --offline` green for
`eliot-observation-contracts`, `eliot-dreamer-memory-revision`,
`eliot-epistemic-contracts` (plus `eliot-dreamer-contracts`,
`eliot-context-contracts` as deps). Note: shared lane target dir
(`rust-env-target`) served a stale-fresh judgment once; forced rebuild
confirmed. `eliot-memory-projection-contracts` is a nonmember prototype —
not checked, not in scope. No tests executed (brief). Edge proofs,
`W9_MEMORY_QUALITY_PULSE_01`, and acceptance remain future; no product
support claimed (`CURRENT_UNVERIFIED` at best, `NOT_EXECUTED` evidence).
