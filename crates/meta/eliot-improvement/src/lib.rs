//! Governed, advisory self-improvement candidates.
//!
//! This crate deliberately stops at the promotion boundary.  It records a
//! replayable proposal and produces an outcome-linked input for an external
//! governor decision; no API in this crate can make a candidate active.
//!
//! # Inventory (#1145 W1)
//!
//! This is the measured reverse-consumer, state, effect, experiment-path and
//! test inventory of the whole package. Every count and every consumer below
//! was read off the source at `main@7eb86a841`; where a claim is "no consumer",
//! the exact `git grep` that established it is named. Nothing here is a
//! projection of intent: a name listed as consumed carries its call site, and a
//! name listed as unconsumed was searched for by `use eliot_improvement` path
//! form, by bare path form and by method-call form.
//!
//! ## Public surface
//!
//! 192 top-level `pub` items and 80 `pub` methods across twelve source files.
//! The crate root declares 11 `pub mod`s, 10 `pub use` groups that flatten to
//! 91 crate-root names, and 8 crate-root types (`ImprovementSurface`,
//! `CandidateState`, `ImprovementLifecycle`, `ReplayPlan`,
//! `ImprovementCandidate`, `OutcomeEvidence`, `PromotionInput`,
//! `ImprovementError`). Seven `learning_closure` names are deliberately not
//! re-exported at the root; the block comment further down records which.
//!
//! ## Reverse consumers
//!
//! Only ONE consumer leg in this repository reaches a production entry point.
//! It is `bins/eliotd`, and every crate-level item on that leg is listed below
//! with its call site. One further crate, `crates/meta/eliot-self-quality`,
//! reaches this crate from inside that same leg. Every other in-workspace
//! consumer is a second dead end.
//!
//! The live leg, verified by following each hop:
//!
//! ```text
//! bins/eliotd/src/main.rs:30                       daemon_runtime::run()
//! -> daemon_runtime.rs:895                         runtime.block_on(run_loop(..))
//! -> daemon_runtime.rs:1573                        run_loop
//! -> daemon_runtime.rs:1795                        maybe_start_improvement_intake
//! -> daemon_runtime.rs:5487                        run_improvement_intake(..).await
//! -> daemon_runtime.rs:5150/5157                   improvement_intake_artifact
//! -> daemon_runtime.rs:5025/5047                   assemble_improvement_artifact
//! -> improvement_intake_dispatch.rs:379            pub fn assemble_improvement_artifact
//! ```
//!
//! From that entry point the crate is entered through exactly these items:
//!
//! | Crate item | Call site on the live leg |
//! |---|---|
//! | `evidence_sources::sourced_evidence` | `improvement_intake_dispatch.rs:416` |
//! | `evidence_sources::candidate_from_evidence` | `improvement_intake_dispatch.rs:430` |
//! | `ImprovementCandidate::new` | `evidence_sources.rs:89` |
//! | `ImprovementCandidate::transition_lifecycle` | `improvement_intake_dispatch.rs:447` |
//! | `ImprovementCandidate::validate` | `improvement_dedup_read.rs:555` (and internally at `evidence_sources.rs:114`, `brief.rs:279`) |
//! | `brief::SafeBoundary::from_observed_closure` | `improvement_intake_dispatch.rs:491` |
//! | `brief::brief_at_safe_boundary` | `improvement_intake_dispatch.rs:538` |
//! | `brief::record_owner_decision` | `improvement_intake.rs:34` (from `improvement_intake_dispatch.rs:585`) |
//! | `application_class::classify` | `improvement_intake_dispatch.rs:804` |
//! | `application_class::check_class_gate` | `improvement_intake_dispatch.rs:805` |
//! | `application_class::ChangeDescriptor::from_recorded_surface` | `improvement_intake_dispatch.rs:803` |
//! | `candidate_bounds::BoundedBacklog::restored` | `improvement_dedup_read.rs:483` |
//! | `candidate_bounds::BoundedBacklog::admit_reporting_pressure` | `improvement_intake_dispatch.rs:1239` |
//! | `candidate_bounds::BoundedBacklog::entry_for` | `improvement_intake_dispatch.rs:1286` |
//! | `candidate_bounds::canonical_evidence_lineage` | `improvement_dedup_read.rs:540`, `candidate_dispatch.rs:591` |
//! | `candidate_bounds::evidence_lineage_digest` | `improvement_dedup_read.rs:546`, `candidate_dispatch.rs:591` |
//! | `candidate_bounds::CandidateBoundPolicy` | `improvement_intake_dispatch.rs:1060,1085` |
//! | `ImprovementSurface::closed_name` | `improvement_candidate_dispatch.rs:497` |
//! | `ImprovementLifecycle::is_terminal` | `improvement_dedup_read.rs:626` |
//! | `ImprovementCandidate`, `ImprovementSurface`, `ImprovementLifecycle`, `ReplayPlan`, `SourcedEvidence`, `EvidenceSource`, `OwnerDecision`, `OwnerDecisionKind`, `ImprovementBrief`, `SafeBoundary`, `ImprovementError`, `AdmitOutcome`, `AdmitReport`, `TrackedCandidate`, `ArchivedCandidate`, `DurableCandidateRecord`, `BoundsError` | type positions in `improvement_intake.rs`, `improvement_intake_dispatch.rs`, `improvement_dedup_read.rs`, `improvement_candidate_dispatch.rs`, `daemon_runtime.rs:58,5106` |
//!
//! The consumer half of the same pass — the leg that reads a candidate back —
//! rides the same observation at `daemon_runtime.rs:5263`
//! (`dispatch_improvement_candidate_route` ->
//! `improvement_candidate_dispatch.rs:260 route_improvement_candidate` ->
//! `improvement_candidate_route.rs:100`). The path that consumes a candidate
//! is the path that constructs it.
//!
//! One crate reaches in from inside that leg. `crates/meta/eliot-self-quality`
//! calls `evidence_sources::sourced_evidence` at `improvement_handoff.rs:69`
//! and returns `SourcedEvidence` at `conformance_evidence.rs:98`;
//! `git grep -n "sourced_evidence_from_conformance_diagnosis"` shows its
//! production call at `improvement_intake_dispatch.rs:1003`, so the
//! conformance-diagnosis arm of the live leg reaches this crate through
//! `eliot_self_quality::conformance_evidence.rs:111`. `eliotd` depends on
//! `eliot-self-quality` (`bins/eliotd/Cargo.toml:94`), so this is one consumer
//! leg, not two.
//!
//! ### Named elsewhere, but not on a live path
//!
//! These have an in-workspace caller in non-test source, and that caller is
//! itself unreachable from any production entry point. Each was traced:
//!
//! - `producer::produce_learning_candidate` and `producer::LearningProduction`.
//!   `git grep -n "produce_learning_candidate(" -- '*.rs'` returns two
//!   non-definition hits: `bins/eliot-wasm-host/src/governed_admission.rs:197`
//!   inside `admit_governed_host`, and
//!   `crates/smart/eliot-context-compiler-wasm/src/governed_compose.rs:149`.
//!   `git grep -n "admit_governed_host" -- '*.rs'` returns only its definition,
//!   the `pub use` in `bins/eliot-wasm-host/src/lib.rs:78`, and one prose
//!   mention in `eliot-context-admission/src/lib.rs:271` — zero callers.
//!   `compose_governed_compilation` is likewise only its definition and the
//!   `lib.rs:55` re-export of a crate that is not in the root `Cargo.toml`
//!   members list at all. **Open disposition: live contract, bounded reference
//!   fixture, or delete.**
//! - `governed_screen::{check_governed_carriage, CarriageMark,
//!   PresentedLearning, bounds_to_context_error, datetime_from_unix}` and
//!   `candidate_bounds::{retrieve_governed, GovernedRetrieval,
//!   RetrievalDecision, ReusableCandidateRef, CrossTaskCarryover,
//!   bound_compilation_task}`. Their only workspace callers are
//!   `crates/smart/eliot-context-admission/src/learning_gate.rs:209` (inside
//!   `admit_context_with_learning`) and
//!   `crates/smart/eliot-context-assembly/src/learning_gate.rs:81` (inside
//!   `assemble_active_view_with_learning`). `git grep` for those two functions
//!   returns, outside their own definitions and tests, only
//!   `bins/eliot-wasm-host/src/governed_admission.rs` (inside the callerless
//!   `admit_governed_host`) and the non-member wasm crate. `eliotd` itself
//!   reaches those crates only through the NON-learning `admit_context_traced`
//!   (`daemon_runtime`-side `kernel_context_read_client.rs:74`) and
//!   `assemble_active_view` (`:76`), neither of which touches this crate. That
//!   crate's own
//!   `crates/smart/eliot-context-admission/src/lib.rs:258-274` already records
//!   this as a measured absence.
//!
//! ### No consumer outside this crate, at all
//!
//! Searched by `git grep -n "<name>(" -- '*.rs'` and by `git grep -n
//! "eliot_improvement::<name>" -- '*.rs'`, both excluding
//! `crates/meta/eliot-improvement/**`:
//!
//! - `intake_from_evidence` — zero call sites. The three `eliotd` hits at
//!   `improvement_intake_dispatch.rs:95,100,452` are prose explaining why the
//!   daemon deliberately does NOT call it.
//! - `require_matched_budget_for_promotion` — zero external call sites. The two
//!   `eliotd` hits (`improvement_intake_dispatch.rs:88,96`) are prose. Its only
//!   callers are internal: `intake.rs:284` and `lib.rs:933`.
//! - `intake_from_evidence_governed`, `IntakeRequest`, `IntakeOutcome`,
//!   `GovernedIntakeOutcome`, `GovernedIntakeError`,
//!   `RetainedCampaignLearning`, `RetainedReusableClosure` — no `.rs` hit
//!   outside the crate except the generated
//!   `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
//!   projection.
//! - `stamp_outcome_budget` — exactly one external caller,
//!   `bins/eliotd/src/improvement_intake.rs:46`, inside
//!   `stamp_promotion_budget`. `git grep -n "stamp_promotion_budget"` returns
//!   only that definition. So the one budget-stamping bridge is itself
//!   uncalled, and `BudgetProof` and `OutcomeEvidence` are named in
//!   `improvement_intake.rs` but never reached from the daemon.
//! - `ImprovementCandidate::promotion_input` and `PromotionInput` — no `.rs`
//!   consumer outside the crate. `PromotionInput::validate` is unreached;
//!   `ImprovementCandidate::promotion_input` has no caller at all.
//! - `promote_lifecycle` — zero external call sites. The only gate that can
//!   reach a promoting disposition has no production caller; the live leg uses
//!   `transition_lifecycle(Triaged)`.
//! - `ImprovementCandidate::transition` (the advisory `CandidateState` machine)
//!   — zero external call sites; grepped `candidate.transition(`.
//! - `ImprovementLifecycle::is_promoting_disposition`,
//!   `CandidateState::is_experimental` — zero external call sites.
//! - `route_rejected_surface`, `ImprovementCandidateDraft`,
//!   `route_overlay_task_policy_change` — the whole
//!   `overlay_policy_routing` module has no production consumer.
//! - `sourced_evidence_from_repeated_verifier_failure` — zero external hits.
//! - `brief::is_non_mutating`, `budget_proof::{ComplexityEconomicsDelta,
//!   is_conclusive, supports_promotion}` — zero external hits.
//! - The entire `promotion_input` module (45 top-level items, including
//!   `prepare_promotion_input`, `promotion_evidence_digest`,
//!   `PriorPromotionHistory`, `PromotionRequest`, `PromotionCandidate`,
//!   `ClosureBinding`, `PromotionGateEvidence`, `PromotionInputError`,
//!   `PromotionInputPolicy`, `PromotionPreparation`, `AGENT_ORDER`,
//!   `PROOF_CEILING`, `PRIVACY_CEILING`, `REQUESTED_EFFECT`,
//!   `SUPPORTED_SCHEMA_VERSIONS`, `SCOPED_UPDATE_PROMOTED`) — every `.rs`
//!   hit outside the crate is a hit in this crate's own `tests/`.
//!   `MODULE_ID`, `RUNTIME_LAYER`, `SOURCE_LAYER` and `CAUSAL_PROPERTY` are
//!   re-exported at the crate root; `PRODUCT_PULSE`,
//!   `SUPPORTED_SCHEMA_VERSIONS`, `PROOF_CEILING`, `PRIVACY_CEILING` and
//!   `REQUESTED_EFFECT` are reachable only as
//!   `eliot_improvement::promotion_input::<NAME>`, which is where this crate's
//!   own `tests/candidate_admission_edge.rs:271,334-336,365-369` read them.
//! - The entire `learning_closure` module (50 top-level items, including
//!   `assemble_campaign_learning_closure`,
//!   `assemble_campaign_learning_closure_with_evidence`, `ClosurePolicy`,
//!   `CampaignLearningClosure`, `LearningDebt`, `trigger_closure_due`,
//!   `allowed_disposition`, `supported_episode_disposition`) — every `.rs`
//!   hit outside the crate is a hit in this crate's own `tests/`. That is
//!   consistent with I12.24:289, which puts closure assembly on "existing Meta,
//!   Memory OS and Governor paths" and says its disposition "records, but
//!   never performs, a promotion" — this crate holds the record shape and no
//!   assembly owner.
//! - `candidate_bounds::{BoundedBacklog::new, BoundedBacklog::admit,
//!   BoundedBacklog::admit_governed, BoundedBacklog::archive,
//!   BoundedBacklog::active_for, BoundedBacklog::active_reusable,
//!   BoundedBacklog::policy_for, bind_local_overlay, live_local_overlay,
//!   bind_reusable_candidate, retrieve_for_attempt, reverify_live,
//!   governed_assemble_campaign_learning_closure,
//!   governed_assemble_at_lifecycle_event,
//!   governed_closure_assembly_admission, closure_candidate_usable_by_task,
//!   GovernedOverlay::is_live_local_admitted(_at_unix)}` — no production
//!   consumer; the hits are in this crate's `tests/`, in other crates'
//!   `tests/`, or doc prose. The live daemon reaches the backlog only through
//!   `restored`, `admit_reporting_pressure` and `entry_for`.
//! - `CrossTaskCarryover::verify` is reached from
//!   `improvement_intake_dispatch.rs:1486` inside
//!   `verify_cross_task_carryover`, and `git grep -n
//!   "verify_cross_task_carryover"` returns only that definition plus its own
//!   doc comments — so the cross-task revalidation seam is present and typed
//!   but uncalled.
//!
//! ### Names that are NOT this crate's
//!
//! `crates/governor/eliot-maintenance/src/improvement_pipeline.rs` declares its
//! OWN `ExperimentPlan` (`:429`), `MechanismDeclaration` (`:366`),
//! `ActivationEvidence` (`:491`), `RollbackContract` (`:524`) and
//! `ImprovementProposal` (`:544`). Those five names have ZERO occurrences
//! anywhere in `crates/meta/eliot-improvement`, verified by `Select-String`
//! over `src/*.rs` and `tests/*.rs`. Reading a #1145 claim about "the six exact
//! identities" as a claim about this crate substitutes one crate for another;
//! this crate's own contribution is the advisory `ImprovementCandidate`, the
//! `ReplayPlan`, the `ImprovementBrief` and the lifecycle/budget gates.
//!
//! ## Mutable state and effects
//!
//! The crate is stateless in the sense ARCH-MOD-03 requires it to declare.
//! Measured:
//!
//! - **No global or static state.** `Select-String` for `static `,
//!   `OnceLock`, `LazyLock` and `lazy_static` over `src/*.rs` returns no
//!   declaration; every `'static` hit is a `&'static str` type in an error
//!   enum or a returned name.
//! - **No interior mutability.** No `Mutex`, `RwLock`, `RefCell`, `Cell`,
//!   `UnsafeCell` or `Atomic*` anywhere in `src/`. The only `&mut self`
//!   receivers are `ImprovementCandidate::{set_details, transition,
//!   transition_lifecycle, promote_lifecycle}` and
//!   `BoundedBacklog::{admit, admit_governed, admit_reporting_pressure,
//!   archive, bind_local_overlay, bind_reusable_candidate}`. `BoundedBacklog`
//!   is the crate's one stateful aggregate and it is a plain value the CALLER
//!   owns; `eliotd` constructs one per pass at `daemon_runtime.rs:5106` and
//!   drops it at the end of that pass.
//! - **No filesystem, process, network, thread, env or async effect.**
//!   `grep` for `std::fs`, `std::net`, `std::process`, `std::thread`,
//!   `std::env`, `Command::new`, `tokio`, `async `, `await` and `unsafe`
//!   over `src/*.rs` returns ZERO source hits. The textual matches for those
//!   strings live in `tests/promotion_input.rs:1199-1221` and
//!   `tests/learning_closure.rs:1928-1941`, where they are the FORBIDDEN list
//!   of a source-bound test that asserts the module's own source contains none
//!   of them. `unsafe_code = "forbid"` is inherited from the workspace
//!   `[workspace.lints.rust]`, and `overlay_policy_routing.rs:19` repeats it
//!   at module scope.
//! - **Clock.** Ten clock reads in total, all in construction or bookkeeping
//!   paths, none in a gate: `OffsetDateTime::now_utc()` at `lib.rs:646` (`new`),
//!   `lib.rs:724,863,946` (`set_details`, `transition`,
//!   `apply_lifecycle_edge`), `lib.rs:969` (`promotion_input`),
//!   `brief.rs:299,322` (`brief_at_safe_boundary`, `record_owner_decision`) and
//!   `candidate_bounds.rs:1122` (a lineage merge), plus `Uuid::now_v7()` at
//!   `lib.rs:961` and `brief.rs:288`. `datetime_from_unix` converts a
//!   caller-supplied timestamp and reads no clock. No expiry, admission or
//!   promotion decision in this crate consults the clock on its own behalf;
//!   `now` is always a parameter (`candidate_bounds.rs:1370,1877,1897,2237,2355`
//!   and `governed_screen.rs:83,152,190`). The two modules that own the inner
//!   learning loop are clock-free outright: `Select-String` for
//!   `OffsetDateTime` over `learning_closure.rs` and `promotion_input.rs`
//!   returns nothing, so neither module can read a clock even by accident.
//! - **One owner-held read.** `brief.rs:200` calls
//!   `CanonicalLearningDeltaStore::load()`, a read of already-committed
//!   IN-PROCESS state the caller passes in. It opens no transport, no store
//!   client and no durability path; `brief.rs:176-181` states the caller's
//!   mutex obligation.
//!
//! Per acceptance item A9 — "cannot edit source/config/policy, install
//! artifacts, activate generations, issue authority, promote support/truth or
//! produce `VERIFIED_COMPLETE`" — the per-item evidence is:
//! source/config/policy edit: no filesystem or process effect at all, above;
//! artifact installation: no process spawn; generation activation: the crate
//! has no generation API and reads no generation store; authority issuance:
//! every boundary is a refusal (`SelfPromotionForbidden`,
//! `ApplicationClassViolation`, `UnsafeBoundary`, `BudgetGateViolation`,
//! `MissingBudgetProof`), and `validate_base` at `lib.rs:805` refuses
//!   `advisory_only: false` at `lib.rs:820` outright; support/truth promotion
//!   and `VERIFIED_COMPLETE`: no name in this crate's source spells either, and
//!   the only transition into a promoting disposition, `promote_lifecycle`
//! (`lib.rs:916`), is unreachable from production because it has no caller
//! and `require_matched_budget_for_promotion` is itself uncalled externally.
//!
//! ## Experiment path
//!
//! Nothing in this crate RUNS an experiment. What it holds is record and
//! validation only:
//!
//! - `ReplayPlan` (`lib.rs:570`) names the fixed-replay, holdout, transfer and
//!   counter-metric references. `ReplayPlan::validate` (`lib.rs:579`) refuses
//!   empty reference groups and an empty `transfer_refs`. It matches
//!   I12.24:67, "fixed replay as diagnostic evidence only".
//! - `canary_plan`, `rollback` and `stop_condition` are `String` REFERENCES on
//!   the candidate (`lib.rs:617-621`); `validate` (`lib.rs:744-746`) requires
//!   them to be non-empty and never resolves them.
//! - `BudgetProof` / `ComplexityEconomicsDelta` /
//!   `require_matched_budget_for_promotion` are the I12.24:76 matched-budget
//!   gate. `OutcomeEvidence::validate_for` (`lib.rs:1008`) refuses a
//!   promotion-bound outcome that lacks a budget ledger, a conclusive
//!   economics delta, affected checks, live shadow/canary evidence or
//!   delayed-harm visibility. That is I12.24:76's "An unmatched ledger or
//!   inconclusive complexity delta cannot promote the candidate merely because
//!   replay or a local metric improved."
//! - The promotion record carries the BOUND proof, so those seven
//!   obligations are re-checked against records and not against names:
//!   `ImprovementCandidate::promotion_input` takes `&BudgetProof` and writes
//!   the outcome's seven legs through `stamp_outcome_budget`, the single
//!   owner of that projection, and the returned `PromotionInput` holds the
//!   same `BudgetProof`. `PromotionInput::validate` re-runs
//!   `stamp_outcome_budget` on the bound proof, so the canonical
//!   `BudgetEquivalenceLedger::validate`, the recorded delta slots and the
//!   live shadow/canary and delayed-harm legs are checked against the
//!   original `BudgetEquivalenceLedger` value, and a record whose names
//!   disagree with that proof is refused. No ledger, delta or evidence leg is
//!   recomputed, re-derived or substituted on either path.
//! - The lifecycle enums carry the experiment states and enforce the edge
//!   table: `AcceptedForExperiment` and `Running` exist only as transitions
//!   `lifecycle_edge_allowed` (`lib.rs:517`) permits, and the promoting step
//!   "promote, narrow, rollback or archive" (I12.24:70) is gated so that
//!   `transition_lifecycle` refuses `Supported`/`Narrowed` outright
//!   (`lib.rs:892`) and only `promote_lifecycle` admits them, and only with a
//!   budget proof.
//! - `promotion_input::prepare_promotion_input` (`promotion_input.rs:551`) is a
//!   pure gate over already-supplied evidence, and it has no production caller.
//!
//! ## Tests
//!
//! 106 `#[test]` functions, all in `crates/meta/eliot-improvement/tests/`, one
//! file per cell, none inline in `src/` (measured: zero `#[test]`, zero
//! `mod tests`, zero `cfg(test)` under `src/`):
//!
//! | File | `#[test]` |
//! |---|---|
//! | `tests/learning_closure.rs` | 58 |
//! | `tests/promotion_input.rs` | 28 |
//! | `tests/candidate_bounds_1869.rs` | 10 |
//! | `tests/candidate_admission_edge.rs` | 5 |
//! | `tests/producer_1869.rs` | 5 |
//!
//! Counted by matching the `#[test]` attribute in each file's source, not by a
//! test run. Two of them are source-bound negatives rather than behavioural
//! proofs and are the direct evidence for the effect claims above:
//! `tests/promotion_input.rs:1197` and `tests/learning_closure.rs:1926` read
//! their own module's source with `include_str!` and assert the forbidden
//! effect vocabulary is absent.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::candidate_bounds::canonical_evidence_lineage;

pub mod application_class;
pub mod brief;
pub mod budget_proof;
pub mod candidate_bounds;
pub mod evidence_sources;
pub mod governed_screen;
pub mod intake;
pub mod learning_closure;
pub mod overlay_policy_routing;
pub mod producer;

pub use governed_screen::{
    CarriageMark, PresentedLearning, bounds_to_context_error, check_governed_carriage,
    datetime_from_unix,
};
pub use overlay_policy_routing::{ImprovementCandidateDraft, route_rejected_surface};
pub use producer::{
    LearningProduction, produce_learning_candidate, route_overlay_task_policy_change,
};

pub mod promotion_input;

pub use application_class::{
    ApplicationClass, ChangeDescriptor, check_class_gate, classify, is_prohibited_tuning_surface,
};
pub use brief::{
    ImprovementBrief, OwnerDecision, OwnerDecisionKind, SafeBoundary, brief_at_safe_boundary,
    record_owner_decision,
};
pub use budget_proof::{
    BudgetProof, ComplexityEconomicsDelta, require_matched_budget_for_promotion,
    stamp_outcome_budget,
};
pub use evidence_sources::{
    EvidenceSource, SourcedEvidence, candidate_from_evidence, sourced_evidence,
    sourced_evidence_from_repeated_verifier_failure,
};
pub use intake::{IntakeOutcome, IntakeRequest, intake_from_evidence};

// Shared export integration for the learning-closure cell (#973).  Seven of the
// cell's public names are deliberately NOT re-exported here:
//
// - `MODULE_ID`, `SOURCE_LAYER`, `RUNTIME_LAYER`, `CAUSAL_PROPERTY`,
//   `PRODUCT_PULSE` and `SUPPORTED_SCHEMA_VERSIONS` are declared by both
//   `learning_closure` and `promotion_input`, and one package-root name cannot
//   carry two values.  The four the existing promotion-input block already binds
//   (`MODULE_ID`, `SOURCE_LAYER`, `RUNTIME_LAYER`, `CAUSAL_PROPERTY`) stay bound
//   to it, so this list mirrors that block's convention exactly.
// - `EvidenceSource` is a *different* enum that this crate root already exports
//   from `evidence_sources` (the evidence-sourcing enum), so re-exporting the
//   closure cell's own `EvidenceSource` would collide with it.
//
// Every excluded name stays reachable at
// `eliot_improvement::learning_closure::<NAME>`, so the closure cell keeps its
// own identity.  The closure cell's assembly functions and record types are
// re-exported so the package public API is importable normally, which is the
// integration the two module routers reserved for this owner.  Closure stays
// candidate material: nothing here can activate, promote or finish anything.
pub use learning_closure::{
    AdmissionState, AttemptDelta, AttemptOutcomesAndDeltas, AttemptRecord, AttemptStatus,
    CampaignAndTarget, CampaignLearningClosure, CampaignLearningClosureCandidate,
    CausalAttribution, ClosureAssembly, ClosureCompletion, ClosureDisposition, ClosureDue,
    ClosureEvidenceRefs, ClosureLifecycleEvent, ClosurePolicy, ClosureRecordAssembly,
    ClosureStatus, DeltaKind, DenominatorAccounting, EconomicsRecord, ExternalHandoff, HarmRecord,
    LearningClosureDisposition, LearningClosureError, LearningDebt, LearningDebtProjection,
    LifecycleStage, OutcomeHarmAndEconomicsEvidence, OutcomeKind, OutcomeRecord,
    OverlayAndActivationAssessments, OverlayRecord, PriorClosure, PriorClosureHistory,
    StageAssessment, allowed_disposition, assemble_campaign_learning_closure,
    assemble_campaign_learning_closure_with_evidence, closure_evidence_digest,
    evidence_refs_complete, supported_episode_disposition, trigger_closure_due,
};
pub use promotion_input::{
    AGENT_ORDER, CAUSAL_PROPERTY, ClosureBinding, MODULE_ID, PriorPromotionHistory,
    PromotionCandidate, PromotionGateEvidence, PromotionInputError, PromotionInputPolicy,
    PromotionPreparation, PromotionRequest, RUNTIME_LAYER, SOURCE_LAYER, prepare_promotion_input,
    promotion_evidence_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementSurface {
    Memory,
    Skill,
    ToolProfile,
    Rule,
    PacketCompiler,
    Verifier,
    Scheduler,
}

impl ImprovementSurface {
    /// The closed `snake_case` name, identical to the `Serialize` spelling.
    ///
    /// Total and allocation-free, so a value that participates in a content
    /// digest (see [`ImprovementCandidate::derive_candidate_id`]) names the
    /// surface without restating a literal that a variant rename could
    /// desynchronize from the wire spelling.
    #[must_use]
    pub const fn closed_name(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Skill => "skill",
            Self::ToolProfile => "tool_profile",
            Self::Rule => "rule",
            Self::PacketCompiler => "packet_compiler",
            Self::Verifier => "verifier",
            Self::Scheduler => "scheduler",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateState {
    Candidate,
    ReplayPending,
    Evaluating,
    Rejected,
    Retired,
}

impl CandidateState {
    pub fn is_experimental(self) -> bool {
        matches!(
            self,
            Self::Candidate | Self::ReplayPending | Self::Evaluating
        )
    }
}

/// Owner-decision lifecycle of an improvement candidate (I12.24:36-37).
///
/// `CandidateState` above tracks the advisory pipeline position (candidate,
/// replay, evaluation); this enum tracks the named owner decision lifecycle
/// from proposal to terminal disposition. Both are stored on the candidate so
/// deduplication, briefs, and promotion gates observe the full lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementLifecycle {
    Proposed,
    Triaged,
    AcceptedForExperiment,
    Running,
    Supported,
    Narrowed,
    Rejected,
    RolledBack,
    Stale,
    Archived,
}

impl ImprovementLifecycle {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Supported
                | Self::Narrowed
                | Self::Rejected
                | Self::RolledBack
                | Self::Stale
                | Self::Archived
        )
    }

    /// The promoting dispositions of the I12.24:70 pipeline step
    /// "→ promote, narrow, rollback or archive →".
    ///
    /// `Supported` is "promote" and `Narrowed` is "narrow"; `RolledBack` and
    /// `Archived` are the other two dispositions in that same step and are not
    /// promotions. I12.24:76 makes these two the only dispositions a
    /// replay-only record can never reach, so every transition INTO one of them
    /// is gated by
    /// [`require_matched_budget_for_promotion`](crate::budget_proof::require_matched_budget_for_promotion).
    pub fn is_promoting_disposition(self) -> bool {
        matches!(self, Self::Supported | Self::Narrowed)
    }
}

/// The complete owner-decision lifecycle edge table (I12.24:36-37).
///
/// Held as one free function so both transition entry points — the
/// ungated [`ImprovementCandidate::transition_lifecycle`] and the
/// budget-gated [`ImprovementCandidate::promote_lifecycle`] — validate the
/// exact same edges, and so no entry point can hold a divergent copy of the
/// table that decides legality.
fn lifecycle_edge_allowed(from: ImprovementLifecycle, to: ImprovementLifecycle) -> bool {
    matches!(
        (from, to),
        (
            ImprovementLifecycle::Proposed,
            ImprovementLifecycle::Triaged
        ) | (
            ImprovementLifecycle::Triaged,
            ImprovementLifecycle::AcceptedForExperiment
        ) | (
            ImprovementLifecycle::AcceptedForExperiment,
            ImprovementLifecycle::Running
        ) | (
            ImprovementLifecycle::Running,
            ImprovementLifecycle::Supported
        ) | (
            ImprovementLifecycle::Running,
            ImprovementLifecycle::Narrowed
        ) | (
            ImprovementLifecycle::Running,
            ImprovementLifecycle::Rejected
        ) | (
            ImprovementLifecycle::Running,
            ImprovementLifecycle::RolledBack
        ) | (
            ImprovementLifecycle::Triaged,
            ImprovementLifecycle::Rejected
        ) | (
            ImprovementLifecycle::Proposed,
            ImprovementLifecycle::Rejected
        ) | (ImprovementLifecycle::Proposed, ImprovementLifecycle::Stale)
            | (ImprovementLifecycle::Triaged, ImprovementLifecycle::Stale)
            | (
                ImprovementLifecycle::Narrowed,
                ImprovementLifecycle::Archived
            )
            | (
                ImprovementLifecycle::Supported,
                ImprovementLifecycle::Archived
            )
            | (
                ImprovementLifecycle::Rejected,
                ImprovementLifecycle::Archived
            )
            | (
                ImprovementLifecycle::RolledBack,
                ImprovementLifecycle::Archived
            )
            | (ImprovementLifecycle::Stale, ImprovementLifecycle::Archived)
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReplayPlan {
    pub fixed_replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub counter_metric_names: Vec<String>,
    pub verifier_refs: Vec<String>,
}

impl ReplayPlan {
    fn validate(&self) -> Result<(), ImprovementError> {
        require_refs(&self.fixed_replay_refs, "fixed_replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.verifier_refs, "verifier_refs")?;
        require_names(&self.counter_metric_names, "counter_metric_names")?;
        if self.transfer_refs.is_empty() {
            return Err(ImprovementError::MissingField("transfer_refs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImprovementCandidate {
    pub candidate_id: String,
    pub project_id: String,
    pub target_surface: ImprovementSurface,
    pub proposed_change: String,
    pub applies_when: Vec<String>,
    pub does_not_apply_when: Vec<String>,
    pub source_trace_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub replay_plan: ReplayPlan,
    pub baseline_metrics: BTreeMap<String, f64>,
    pub state: CandidateState,
    /// I12.24 trigger: problem statement or metric that raised the candidate.
    pub trigger_problem_or_metric: String,
    /// I12.24 root-cause hypotheses carried with the candidate.
    pub root_cause_hypotheses: Vec<String>,
    /// I12.24 counter-metrics that must not regress.
    pub counter_metrics: BTreeMap<String, f64>,
    /// I12.24 validity scope of the proposed change.
    pub validity_scope: String,
    /// I12.24 owner and decision authority for this candidate.
    pub owner_and_decision_authority: String,
    /// I12.24 delivery target (work item / module / config path).
    pub delivery_target: String,
    /// I12.24 canary plan reference.
    pub canary_plan: String,
    /// I12.24 rollback reference.
    pub rollback: String,
    /// I12.24 stop condition for the experiment.
    pub stop_condition: String,
    /// I12.24 owner-decision lifecycle (proposed .. archived).
    pub lifecycle: ImprovementLifecycle,
    pub revision: u64,
    pub advisory_only: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl ImprovementCandidate {
    #[allow(
        clippy::too_many_arguments,
        reason = "this public constructor is the established candidate protocol façade"
    )]
    pub fn new(
        project_id: impl Into<String>,
        target_surface: ImprovementSurface,
        proposed_change: impl Into<String>,
        applies_when: Vec<String>,
        does_not_apply_when: Vec<String>,
        source_trace_refs: Vec<String>,
        evidence_refs: Vec<String>,
        replay_plan: ReplayPlan,
        baseline_metrics: BTreeMap<String, f64>,
    ) -> Result<Self, ImprovementError> {
        let now = OffsetDateTime::now_utc();
        let project_id = project_id.into();
        let proposed_change = proposed_change.into();
        // Content-derived identity (I12.24:20-38, W3). The id is a digest over
        // the project, the target surface, the proposed change, both scope-rule
        // sets and the CANONICAL evidence lineage, so the same lineage always
        // yields the same candidate identity. A fresh random id per pass made
        // lineage deduplication unreachable and minted a new durable record key
        // on every repeat — the opposite of "deduplicated by target surface and
        // evidence lineage". Two different lineages still differ, so this never
        // collapses two different problems onto one candidate.
        let candidate_id = Self::derive_candidate_id(
            &project_id,
            target_surface,
            &proposed_change,
            &applies_when,
            &does_not_apply_when,
            &source_trace_refs,
            &evidence_refs,
        );
        let candidate = Self {
            candidate_id,
            project_id,
            target_surface,
            proposed_change,
            applies_when,
            does_not_apply_when,
            source_trace_refs,
            evidence_refs,
            replay_plan,
            baseline_metrics,
            state: CandidateState::Candidate,
            trigger_problem_or_metric: String::new(),
            root_cause_hypotheses: Vec::new(),
            counter_metrics: BTreeMap::new(),
            validity_scope: String::new(),
            owner_and_decision_authority: String::new(),
            delivery_target: String::new(),
            canary_plan: String::new(),
            rollback: String::new(),
            stop_condition: String::new(),
            lifecycle: ImprovementLifecycle::Proposed,
            revision: 0,
            advisory_only: true,
            created_at: now,
            updated_at: now,
        };
        candidate.validate_base()?;
        Ok(candidate)
    }

    /// Attach the I12.24 decision fields after construction.
    ///
    /// All fields are public, so evidence adapters (see
    /// [`crate::evidence_sources::candidate_from_evidence`]) may also assign
    /// them directly; this helper keeps the assignment in one place.
    #[allow(clippy::too_many_arguments)]
    pub fn set_details(
        &mut self,
        trigger_problem_or_metric: impl Into<String>,
        root_cause_hypotheses: Vec<String>,
        counter_metrics: BTreeMap<String, f64>,
        validity_scope: impl Into<String>,
        owner_and_decision_authority: impl Into<String>,
        delivery_target: impl Into<String>,
        canary_plan: impl Into<String>,
        rollback: impl Into<String>,
        stop_condition: impl Into<String>,
    ) {
        self.trigger_problem_or_metric = trigger_problem_or_metric.into();
        self.root_cause_hypotheses = root_cause_hypotheses;
        self.counter_metrics = counter_metrics;
        self.validity_scope = validity_scope.into();
        self.owner_and_decision_authority = owner_and_decision_authority.into();
        self.delivery_target = delivery_target.into();
        self.canary_plan = canary_plan.into();
        self.rollback = rollback.into();
        self.stop_condition = stop_condition.into();
        self.updated_at = OffsetDateTime::now_utc();
    }

    pub fn validate(&self) -> Result<(), ImprovementError> {
        self.validate_base()?;
        non_empty(&self.trigger_problem_or_metric, "trigger_problem_or_metric")?;
        require_names(&self.root_cause_hypotheses, "root_cause_hypotheses")?;
        if self
            .counter_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        non_empty(&self.validity_scope, "validity_scope")?;
        non_empty(
            &self.owner_and_decision_authority,
            "owner_and_decision_authority",
        )?;
        non_empty(&self.delivery_target, "delivery_target")?;
        non_empty(&self.canary_plan, "canary_plan")?;
        non_empty(&self.rollback, "rollback")?;
        non_empty(&self.stop_condition, "stop_condition")?;
        Ok(())
    }

    /// Derives the stable candidate identity from candidate CONTENT.
    ///
    /// The digest covers the fields that decide WHICH improvement this is —
    /// project, target surface, proposed change, the applies/does-not-apply
    /// scope rules, the source trace and the canonical evidence lineage — and
    /// nothing that varies per pass or per owner action. `created_at`,
    /// `updated_at`, `revision` and `lifecycle` are deliberately excluded, so
    /// re-observing the same evidence under the same change yields the same
    /// id and the lineage merge in `BoundedBacklog::admit_reporting_pressure`
    /// becomes reachable in production.
    ///
    /// Component boundaries are length-prefixed rather than concatenated, so no
    /// two different field splittings can produce the same digest input.
    #[allow(
        clippy::too_many_arguments,
        reason = "one hashed component per identity field; the point is the digest input, not the arity"
    )]
    fn derive_candidate_id(
        project_id: &str,
        target_surface: ImprovementSurface,
        proposed_change: &str,
        applies_when: &[String],
        does_not_apply_when: &[String],
        source_trace_refs: &[String],
        evidence_refs: &[String],
    ) -> String {
        let mut hasher = Hasher::new();
        let mut component = |value: &str| {
            hasher.update(&(value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        };
        component(project_id.trim());
        component(target_surface.closed_name());
        component(proposed_change.trim());
        for rule in applies_when {
            component(rule.trim());
        }
        for rule in does_not_apply_when {
            component(rule.trim());
        }
        for reference in source_trace_refs {
            component(reference.trim());
        }
        // The lineage is canonicalised (sorted, deduplicated, blank-free) so two
        // orderings of the same refs are ONE identity, matching the comparison
        // `BoundedBacklog` already performs on admission.
        for reference in canonical_evidence_lineage(evidence_refs) {
            component(&reference);
        }
        format!("cand-{}", hasher.finalize().to_hex())
    }

    /// Base structural checks that hold for every candidate, including
    /// freshly constructed ones whose I12.24 decision details are attached
    /// later via [`Self::set_details`].
    fn validate_base(&self) -> Result<(), ImprovementError> {
        non_empty(&self.project_id, "project_id")?;
        non_empty(&self.proposed_change, "proposed_change")?;
        require_refs(&self.source_trace_refs, "source_trace_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        require_names(&self.applies_when, "applies_when")?;
        require_names(&self.does_not_apply_when, "does_not_apply_when")?;
        if self
            .applies_when
            .iter()
            .any(|rule| self.does_not_apply_when.contains(rule))
        {
            return Err(ImprovementError::ConflictingScopeRule);
        }
        self.replay_plan.validate()?;
        if !self.advisory_only {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        if self
            .baseline_metrics
            .values()
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        Ok(())
    }

    pub fn transition(
        &mut self,
        expected_revision: u64,
        next: CandidateState,
    ) -> Result<(), ImprovementError> {
        self.validate()?;
        if self.revision != expected_revision {
            return Err(ImprovementError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        let allowed = matches!(
            (self.state, next),
            (CandidateState::Candidate, CandidateState::ReplayPending)
                | (CandidateState::ReplayPending, CandidateState::Evaluating)
                | (CandidateState::Evaluating, CandidateState::Rejected)
                | (CandidateState::Evaluating, CandidateState::Retired)
                | (CandidateState::ReplayPending, CandidateState::Rejected)
                | (CandidateState::Candidate, CandidateState::Rejected)
                | (CandidateState::Rejected, CandidateState::Retired)
        );
        if !allowed || next == CandidateState::Candidate {
            return Err(ImprovementError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        self.revision += 1;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    /// Move the owner-decision lifecycle forward (I12.24:36-37).
    ///
    /// Terminal lifecycles admit no outgoing transition. The advisory
    /// `CandidateState` machine is untouched; lifecycle transitions only
    /// refresh `updated_at` and never touch `revision`, so pipeline guards
    /// keep their exact semantics.
    ///
    /// This entry point carries every NON-promoting disposition of the I12.24:70
    /// step "→ promote, narrow, rollback or archive →": triage, experiment
    /// acceptance, experiment start, rejection, rollback, staleness, and every
    /// archival closure. It cannot promote. `Supported` and `Narrowed` are the
    /// promoting dispositions, and I12.24:76 states the guarantee on the move
    /// INTO them — "Replay-only evidence cannot promote… An unmatched ledger or
    /// inconclusive complexity delta cannot promote the candidate merely because
    /// replay or a local metric improved" — so a caller reaching one of them
    /// here is refused with a typed
    /// [`ImprovementError::BudgetGateViolation`] and must use
    /// [`ImprovementCandidate::promote_lifecycle`], which is the only seam that
    /// admits a budget record. The gate therefore lives on the transition to
    /// promotion itself, not only on the intake path.
    pub fn transition_lifecycle(
        &mut self,
        next: ImprovementLifecycle,
    ) -> Result<(), ImprovementError> {
        if next.is_promoting_disposition() && lifecycle_edge_allowed(self.lifecycle, next) {
            return Err(ImprovementError::BudgetGateViolation(
                "promote or narrow requires a matched budget-equivalence ledger and \
                 conclusive complexity-economics delta; use promote_lifecycle",
            ));
        }
        self.apply_lifecycle_edge(next)
    }

    /// Move the candidate to a promoting disposition under the I12.24:76 gate.
    ///
    /// `next` must be `Supported` ("promote") or `Narrowed` ("narrow"); every
    /// other disposition is the ungated [`Self::transition_lifecycle`], which
    /// refuses the two promoting values outright. `proof` is required by
    /// signature — there is no form of this call that omits the budget record —
    /// and it is judged solely by
    /// [`require_matched_budget_for_promotion`](crate::budget_proof::require_matched_budget_for_promotion),
    /// the single owner of the matched-budget decision: this method adds no
    /// check, revalidation, or digest of its own. A replay-only candidate
    /// therefore cannot be promoted or narrowed, and cannot reach either
    /// disposition by any other route, because no other seam accepts them.
    ///
    /// Fails closed and validate-then-commit: the lifecycle is left at its
    /// previous value when the edge is illegal or the gate refuses, so a
    /// refused promotion is never half-applied.
    pub fn promote_lifecycle(
        &mut self,
        next: ImprovementLifecycle,
        proof: &BudgetProof,
    ) -> Result<(), ImprovementError> {
        if !next.is_promoting_disposition() {
            return Err(ImprovementError::BudgetGateViolation(
                "the budget gate admits only the promote and narrow dispositions",
            ));
        }
        if !lifecycle_edge_allowed(self.lifecycle, next) {
            return Err(ImprovementError::InvalidLifecycleTransition {
                from: self.lifecycle,
                to: next,
            });
        }
        require_matched_budget_for_promotion(Some(proof))?;
        self.apply_lifecycle_edge(next)
    }

    /// Commit one validated lifecycle edge. Both entry points reach this only
    /// after the edge is legal under [`lifecycle_edge_allowed`].
    fn apply_lifecycle_edge(&mut self, next: ImprovementLifecycle) -> Result<(), ImprovementError> {
        if !lifecycle_edge_allowed(self.lifecycle, next) {
            return Err(ImprovementError::InvalidLifecycleTransition {
                from: self.lifecycle,
                to: next,
            });
        }
        self.lifecycle = next;
        self.updated_at = OffsetDateTime::now_utc();
        Ok(())
    }

    /// Build the I12.24:76 promotion record over a BOUND budget proof.
    ///
    /// `proof` is required by signature and is the ORIGINAL [`BudgetProof`]
    /// value — the `BudgetEquivalenceLedger` itself plus the recorded
    /// `ComplexityEconomicsDelta` — not a name for one. The seven obligations
    /// on `outcome` are written by [`stamp_outcome_budget`], the single owner
    /// of that projection, straight out of the records
    /// [`BudgetProof::supports_promotion`] validated; a hand-written outcome
    /// therefore cannot supply a budget leg, and one already bound to a
    /// different ledger, delta or evidence leg is refused rather than
    /// overwritten. [`OutcomeEvidence::validate_for`] then runs on the stamped
    /// record, and the same bound proof travels on the returned
    /// [`PromotionInput`] so [`PromotionInput::validate`] can re-check the
    /// seven obligations against the original record instead of against the
    /// names. Nothing about a promotion is decided by a caller-set string, and
    /// the lifecycle promotion itself remains
    /// [`ImprovementCandidate::promote_lifecycle`].
    pub fn promotion_input(
        &self,
        mut outcome: OutcomeEvidence,
        proof: &BudgetProof,
    ) -> Result<PromotionInput, ImprovementError> {
        self.validate()?;
        if !matches!(self.state, CandidateState::Evaluating) {
            return Err(ImprovementError::OutcomeRequiresEvaluation);
        }
        stamp_outcome_budget(&mut outcome, proof)?;
        outcome.validate_for(self)?;
        let digest = promotion_digest(self, &outcome);
        Ok(PromotionInput {
            input_id: Uuid::now_v7().to_string(),
            candidate_id: self.candidate_id.clone(),
            project_id: self.project_id.clone(),
            candidate_revision: self.revision,
            target_surface: self.target_surface,
            outcome,
            budget_proof: proof.clone(),
            evidence_digest: digest,
            direct_promotion: false,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

/// The I12.24 evaluation record for one candidate revision.
///
/// ## The budget legs are a PROJECTION of a bound record
///
/// The seven I12.24:76 obligations — a canonical budget-equivalence ledger, a
/// conclusive complexity-economics delta, affected checks, matched-budget live
/// shadow/canary evidence and delayed-harm visibility — are not discharged by
/// the names below. [`ImprovementCandidate::promotion_input`] takes the
/// ORIGINAL [`BudgetProof`] and writes these fields from the records
/// [`BudgetProof::supports_promotion`] validated
/// ([`stamp_outcome_budget`]), and the resulting [`PromotionInput`] carries
/// that same bound proof, so [`PromotionInput::validate`] re-checks the seven
/// obligations against the original `BudgetEquivalenceLedger` value and the
/// recorded delta slots — never against a string, and never by recomputing,
/// re-deriving or substituting a ledger or digest. A name that some other
/// route wrote therefore carries no gate, and a record whose names disagree
/// with the proof it travels with is refused.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutcomeEvidence {
    pub outcome_ref: String,
    pub downstream_outcome_ref: String,
    pub verifier_ref: String,
    pub verifier_passed: bool,
    pub replay_refs: Vec<String>,
    pub holdout_refs: Vec<String>,
    pub transfer_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub observed_metrics: BTreeMap<String, f64>,
    pub counter_metrics: BTreeMap<String, f64>,
    /// Canonical budget-equivalence ledger binding (I12.24:76, I18.47).
    ///
    /// Names the single `BudgetEquivalenceLedger` record this outcome is
    /// compared under, written from the bound proof's own
    /// `BudgetEquivalenceLedger::ledger_id`. Replay-only outcomes leave it
    /// empty and are refused promotion by [`OutcomeEvidence::validate_for`].
    pub budget_ledger_ref: String,
    /// Complexity-economics delta record (I12.24:76, I18.47), written from the
    /// bound proof's recorded `delta_ref`.
    pub complexity_delta_ref: String,
    /// Whether the bound complexity-economics delta is conclusive, written from
    /// the bound delta's six recorded slots through the contract's own
    /// `ComplexityEconomicsDelta::is_conclusive`.
    /// An inconclusive delta never promotes, however good replay looks.
    pub economics_conclusive: bool,
    /// Affected checks evaluated under the matched budget.
    pub affected_check_refs: Vec<String>,
    /// Matched-budget live shadow evidence refs.
    pub live_shadow_refs: Vec<String>,
    /// Matched-budget live canary evidence refs.
    pub live_canary_refs: Vec<String>,
    /// Delayed-harm visibility window reference.
    pub delayed_harm_window_ref: String,
}

impl OutcomeEvidence {
    fn validate_for(&self, candidate: &ImprovementCandidate) -> Result<(), ImprovementError> {
        non_empty(&self.outcome_ref, "outcome_ref")?;
        non_empty(&self.downstream_outcome_ref, "downstream_outcome_ref")?;
        non_empty(&self.verifier_ref, "verifier_ref")?;
        if !self.verifier_passed {
            return Err(ImprovementError::VerifierNotPassed);
        }
        require_refs(&self.replay_refs, "replay_refs")?;
        require_refs(&self.holdout_refs, "holdout_refs")?;
        require_refs(&self.transfer_refs, "transfer_refs")?;
        require_refs(&self.evidence_refs, "evidence_refs")?;
        if !self
            .replay_refs
            .iter()
            .all(|item| candidate.replay_plan.fixed_replay_refs.contains(item))
            || !self
                .holdout_refs
                .iter()
                .all(|item| candidate.replay_plan.holdout_refs.contains(item))
            || !self
                .transfer_refs
                .iter()
                .all(|item| candidate.replay_plan.transfer_refs.contains(item))
            || !candidate
                .replay_plan
                .verifier_refs
                .contains(&self.verifier_ref)
        {
            return Err(ImprovementError::OutcomeOutsidePlan);
        }
        if self
            .counter_metrics
            .keys()
            .any(|name| !candidate.replay_plan.counter_metric_names.contains(name))
        {
            return Err(ImprovementError::UnknownCounterMetric);
        }
        if self
            .observed_metrics
            .values()
            .chain(self.counter_metrics.values())
            .any(|value| !value.is_finite())
        {
            return Err(ImprovementError::NonFiniteMetric);
        }
        // I12.24:76 promotion gate: replay-only evidence never promotes.
        // A promotion-bound outcome must bind the single canonical
        // budget-equivalence ledger and a conclusive complexity-economics
        // delta, name the affected checks, carry matched-budget live
        // shadow/canary evidence, and expose delayed-harm visibility.
        if self.budget_ledger_ref.trim().is_empty() {
            return Err(ImprovementError::MissingBudgetProof);
        }
        if self.complexity_delta_ref.trim().is_empty() {
            return Err(ImprovementError::MissingBudgetProof);
        }
        if !self.economics_conclusive {
            return Err(ImprovementError::BudgetGateViolation(
                "inconclusive complexity-economics delta cannot promote",
            ));
        }
        if self.affected_check_refs.is_empty()
            || self
                .affected_check_refs
                .iter()
                .any(|value| value.trim().is_empty())
        {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires affected checks under the matched budget",
            ));
        }
        if self.live_shadow_refs.is_empty() && self.live_canary_refs.is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires matched-budget live shadow or canary evidence",
            ));
        }
        if self.delayed_harm_window_ref.trim().is_empty() {
            return Err(ImprovementError::BudgetGateViolation(
                "promotion requires delayed-harm visibility",
            ));
        }
        Ok(())
    }
}

/// The I12.24:76 promotion record, and the bound budget record it is judged by.
///
/// [`budget_proof`](Self::budget_proof) is the ORIGINAL `BudgetProof`: the
/// `BudgetEquivalenceLedger` value and the recorded `ComplexityEconomicsDelta`
/// that produced the seven projections in `outcome`. It is here so the
/// obligations are re-checkable against a canonical record rather than against
/// the names `outcome` carries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PromotionInput {
    pub input_id: String,
    pub candidate_id: String,
    pub project_id: String,
    pub candidate_revision: u64,
    pub target_surface: ImprovementSurface,
    pub outcome: OutcomeEvidence,
    /// The bound I18.47 budget/economics record this promotion is judged under
    /// (I12.24:76). Matchedness and conclusiveness are read from it by
    /// [`BudgetProof::supports_promotion`], never asserted here.
    pub budget_proof: BudgetProof,
    pub evidence_digest: String,
    pub direct_promotion: bool,
    pub created_at: OffsetDateTime,
}

impl PromotionInput {
    /// Re-check the I12.24:76 promotion obligations against the bound ORIGINAL
    /// proof.
    ///
    /// I12.24:76 — "Replay-only evidence cannot promote a policy/module/Skill/
    /// retrieval change. The evaluation record binds the single canonical
    /// `BudgetEquivalenceLedger` and `ComplexityEconomicsDelta` contracts of
    /// I18.47… An unmatched ledger or inconclusive complexity delta cannot
    /// promote the candidate merely because replay or a local metric improved."
    ///
    /// The seven obligations are therefore re-checked on records, not on the
    /// outcome's names:
    ///
    /// - the record must NAME the binding, exactly as
    ///   [`OutcomeEvidence::validate_for`] requires on the path that builds it,
    ///   so carrying a valid proof cannot stand in for a stamped outcome.
    /// - [`stamp_outcome_budget`] is then the one owner of the outcome/proof
    ///   comparison. It runs [`BudgetProof::supports_promotion`] on the bound
    ///   proof — which calls the existing [`BudgetProof::validate`], and with
    ///   it the canonical `BudgetEquivalenceLedger::validate` on the ledger
    ///   value itself — and refuses a record bound to a DIFFERENT ledger, delta
    ///   or evidence leg. Nothing here recomputes, re-derives or substitutes a
    ///   ledger or digest, and the copy it runs that comparison on is local, so
    ///   no field of `self` is written.
    pub fn validate(&self) -> Result<(), ImprovementError> {
        if self.direct_promotion {
            return Err(ImprovementError::SelfPromotionForbidden);
        }
        non_empty(&self.evidence_digest, "evidence_digest")?;
        non_empty(&self.candidate_id, "candidate_id")?;
        non_empty(&self.project_id, "project_id")?;
        if self.outcome.budget_ledger_ref.trim().is_empty()
            || self.outcome.complexity_delta_ref.trim().is_empty()
        {
            return Err(ImprovementError::MissingBudgetProof);
        }
        let mut bound = self.outcome.clone();
        stamp_outcome_budget(&mut bound, &self.budget_proof)
    }
}

fn promotion_digest(candidate: &ImprovementCandidate, outcome: &OutcomeEvidence) -> String {
    let mut hasher = Hasher::new();
    hasher.update(candidate.candidate_id.as_bytes());
    hasher.update(candidate.revision.to_string().as_bytes());
    hasher.update(outcome.outcome_ref.as_bytes());
    hasher.update(outcome.downstream_outcome_ref.as_bytes());
    hasher.update(outcome.verifier_ref.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn non_empty(value: &str, field: &'static str) -> Result<(), ImprovementError> {
    if value.trim().is_empty() {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_refs(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        Err(ImprovementError::MissingField(field))
    } else {
        Ok(())
    }
}

fn require_names(values: &[String], field: &'static str) -> Result<(), ImprovementError> {
    require_refs(values, field)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ImprovementError {
    #[error("required field is missing: {0}")]
    MissingField(&'static str),
    #[error("candidate scope contains both apply and exclusion rule")]
    ConflictingScopeRule,
    #[error("non-finite metric is not admissible")]
    NonFiniteMetric,
    #[error("candidate lifecycle revision conflict: expected {expected}, actual {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("invalid candidate lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: CandidateState,
        to: CandidateState,
    },
    #[error("improvement candidates cannot self-promote")]
    SelfPromotionForbidden,
    #[error("outcome input requires an evaluating candidate")]
    OutcomeRequiresEvaluation,
    #[error("verifier outcome did not pass")]
    VerifierNotPassed,
    #[error("outcome references data outside the candidate replay plan")]
    OutcomeOutsidePlan,
    #[error("outcome contains an undeclared counter metric")]
    UnknownCounterMetric,
    #[error("invalid owner lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycleTransition {
        from: ImprovementLifecycle,
        to: ImprovementLifecycle,
    },
    #[error("brief requires an active Main Agent or Human at a safe boundary")]
    UnsafeBoundary,
    #[error("application-class boundary refused the change")]
    ApplicationClassViolation,
    #[error("promotion requires a bound budget-equivalence and economics record")]
    MissingBudgetProof,
    #[error("budget gate refused promotion: {0}")]
    BudgetGateViolation(&'static str),
    #[error("backlog refused intake: {0}")]
    BacklogRefused(String),
}
