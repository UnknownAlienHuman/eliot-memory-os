//! Bounded, candidate-only Dreamer generation.
//!
//! This crate is deliberately a pure boundary.  It does not call a model,
//! launch an agent, read storage, or promote semantic state.  A route adapter
//! supplies a bounded model draft and this crate turns it into an inspectable
//! candidate while enforcing scope, fence, lineage, preservation, and budget
//! invariants.
//!
//! ## Issue #1143 ledger — `SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE`
//!
//! Authority: issue #1143 (owns only `eliot-cues` + `eliot-dreamer-core`) and
//! `crates/smart/cognitive-donor-map.toml` (`SPLIT_AND_RETAIN_AS_TEMPORARY_FACADE`
//! with 25 targets: `eliot-dreamer-contracts`, `eliot-dreamer-bundle`,
//! `eliot-dreamer-claim-grounding`, `eliot-dreamer-candidate-validation`,
//! `eliot-dreamer-rival-model`, `eliot-dreamer-probe-plan`,
//! `eliot-dreamer-orientation`, `eliot-dreamer-clarification`,
//! `eliot-dreamer-architecture-brief`, `eliot-dreamer-implementation-brief`,
//! `eliot-dreamer-classification`, `eliot-dreamer-relation`,
//! `eliot-dreamer-episode`, `eliot-dreamer-concept`, `eliot-dreamer-procedure`,
//! `eliot-dreamer-failure`, `eliot-dreamer-structure-repair`,
//! `eliot-dreamer-reconsolidation`, `eliot-dreamer-accessibility`,
//! `eliot-dreamer-memory-repair`, `eliot-dreamer-curation`,
//! `eliot-dreamer-conflict-analysis`, `eliot-dreamer-development-diagnosis`,
//! `eliot-dreamer-maintenance-plan`, `eliot-dreamer-configuration-plan`,
//! `eliot-dreamer-orchestration-plan`).
//!
//! CONTRACT-UNIFICATION this turn: the facade `JobClass`, `DreamJobInput`,
//! `DraftItem`, and `ModelDraft` duplicates are deleted; the three canonical
//! shapes are re-exported from `eliot-dreamer-contracts` (new
//! `eliot-dreamer-core -> eliot-dreamer-contracts` edge) and generation is
//! rebuilt on the canonical single-hypothesis draft. No root turn (root
//! `Cargo.toml` members, `Cargo.lock`, generated indexes remain a serialized
//! residual owned by the LEGACY-DELETE-last root turn).
//! Zero live Cargo reverse-deps and zero `use eliot_dreamer_core::` outside
//! self were re-verified; this ledger is the sufficiency record. The owner
//! cells prove their own live behavior in their suites; the re-exported side
//! runs live here with meaningful assertions in each `differential_1143`
//! fixture body.
//!
//! Dispositions — exactly one per row:
//! - `MIGRATED-1143`: edge facet migrated this turn; differential fixture
//!   cited; facade item retained byte-identical until LEGACY-DELETE.
//! - `FIXTURE`: bounded compatibility fixture with expiry/removal condition.
//! - `DELETE-PROPOSED`: removal deferred to the LEGACY-DELETE-last root turn
//!   once the stated precondition closes. Never executed here.
//!
//! | # | Facade item | Current #94 owner | Bounded fixture + expiry | Disposition |
//! |---|-------------|-------------------|--------------------------|-------------|
//! | 1 | `CONTRACT_NAME` | contracts `CONTRACT_NAME` ("eliot.smart.dreamer.contracts") | replay/diagnostic string; expires at LEGACY-DELETE | FIXTURE |
//! | 2 | `CONTRACT_VERSION` | contracts `CONTRACT_VERSION` ("1.0.0" str) + `DREAM_JOB_SCHEMA_VERSION` (1u32) | version-string fixture (see D-DRM-6); expires at LEGACY-DELETE | FIXTURE |
//! | 3 | `MAX_TEXT` | contracts per-field `check_text` bounds + bundle ceilings | bound differential; expires at LEGACY-DELETE | DELETE-PROPOSED after bundle/validation own every bound |
//! | 4 | `MAX_ITEMS` | contracts per-collection bounds (64: draft items/unknowns) | bound differential; expires at LEGACY-DELETE | DELETE-PROPOSED after validation owns every bound |
//! | 5 | `MAX_SOURCES` | contracts lineage bounds (128) | bound differential; expires at LEGACY-DELETE | DELETE-PROPOSED after validation owns every bound |
//! | 6 | `DreamerError` | contracts `ContractViolation` + candidate-validation `DreamDraftValidationError` | error-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after pipeline uses owner errors |
//! | 7 | `JobClass` (facade deleted; canonical re-export) | contracts `job::JobClass` (9 closed classes) | canonical `snake_case` wire vocabulary asserted live (see D-DRM-1..3) | RE-EXPORTED (contract-unification turn) |
//! | 8 | `Requester` (4 variants) | contracts `job::{Requester, RequesterOrigin}` (origin + principal/session binding) | requester-mapping fixture (see D-DRM-4); expires after intake migration | DELETE-PROPOSED after bundle owns requester binding |
//! | 9 | `CandidateKind` (17 variants) | contracts `curation::CurationKind` + kind families + 13 typed handler cells (classification/relation/episode/concept/procedure/failure/structure-repair/reconsolidation/accessibility/memory-repair + rival-model/probe-plan + clarification) | kind-mapping fixture; expires after curation + handlers admit every kind | DELETE-PROPOSED after handler migration |
//! | 10 | `PrivacyClass` | `eliot-security-contracts::PrivacyClass` via contracts re-export | privacy-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after intake uses owner class |
//! | 11 | `DreamBudget` | contracts `budget::BudgetLimits` (11 independent dimensions) | EDGE-DRM-1143 budget-shape differential (see D-DRM-5); retained until jobs carry owner budgets | MIGRATED-1143 (`differential_1143` in this file) |
//! | 12 | `DreamBudget::validate` | contracts `BudgetLimits::validate`/`require_exact` | EDGE-DRM-1143 zero-rejection differential; retained until jobs carry owner budgets | MIGRATED-1143 (`differential_1143` in this file) |
//! | 13 | `DreamJobInput` (facade deleted; canonical re-export) | contracts `job::DreamJobInput` (closed intake) via bundle `DreamInputBundle` assembly | canonical intake validation asserted live (see D-DRM-8) | RE-EXPORTED (contract-unification turn) |
//! | 14 | `DreamJobInput::validate` (facade deleted with row 13) | contracts intake `validate` | owner validation asserted live with row 13 | DELETED with row 13 |
//! | 15 | `DreamJobInput::all_handles` (facade deleted with row 13) | bundle `AssemblyMaterialSet` / material closure | handle closure belongs to bundle assembly, never to intake | DELETED with row 13 |
//! | 16 | `DraftItem` (facade deleted, no re-export) | contracts `draft::ModelDraft` single-hypothesis shape + claim-grounding `GroundedDreamDraft` items | single-hypothesis generation asserted live with row 17 | DELETED (contract-unification turn) |
//! | 17 | `ModelDraft` (facade deleted; canonical re-export) | contracts `draft::{ModelDraft, RawProviderOutput}` + grounding | candidate-only rejection asserted live | RE-EXPORTED (contract-unification turn) |
//! | 18 | `ModelDraft::validate` (facade deleted with row 17) | candidate-validation `validate_grounded_dream_draft_at` + structured validation | owner validation asserted live with row 17 | DELETED with row 17 |
//! | 19 | `PreservationReport` (6 bools) | contracts `candidate::PreservationReport` (7 verdicts, no averaging) | ceiling-shape fixture (see D-DRM-7; `authority_unchanged` is the candidate-only bit); expires after candidate migration | DELETE-PROPOSED after candidate cell owns preservation |
//! | 20 | `CandidateArtifact` | contracts `candidate::{CandidateProposal, CandidateResult}` | candidate-shape fixture; expires after candidate migration | DELETE-PROPOSED after candidate cell owns results |
//! | 21 | `DreamPacket` | bundle `DreamInputBundle` + candidate results + assembly result | packet-shape fixture; expires after bundle migration | DELETE-PROPOSED after bundle owns packets |
//! | 22 | `CandidateGenerator` | pipeline bundle -> claim-grounding -> candidate-validation -> handlers (no single owner by donor rejected-overgeneralization) | pipeline-skeleton fixture; expires after pipeline migration | DELETE-PROPOSED after pipeline migration |
//! | 23 | `CandidateGenerator::generate` | pipeline bundle -> claim-grounding -> candidate-validation -> handlers | EDGE-DRM-1143 candidate-only differential (budget gates + ceiling); retained byte-identical until LEGACY-DELETE | MIGRATED-1143 (`differential_1143` in this file) |
//!
//! ## EDGE-DRM-1143 (migrated this turn, candidate-only ceiling)
//!
//! Facade [`CandidateGenerator::generate`] with its intake vocabulary
//! ([`JobClass`]) and budget gate ([`DreamBudget::validate`]) projects onto the
//! owner pipeline (`eliot-dreamer-contracts` schemas, functional capabilities
//! `smart.dreamer.contracts` / `smart.dreamer.bundle` /
//! `smart.dreamer.candidate_validation` per
//! `crates/smart/cognitive-crate-decisions.toml`). Differential fixtures in
//! `differential_1143` prove: (a) the 9 canonical job classes serialize to the
//! frozen owner spellings, including `architecture_self_query` and the
//! first-class `configuration_assistance` (D-DRM-1..3); (b) degenerate budgets are
//! rejected at validation and enforced at generation; (c) generation stays
//! candidate-only — fence carried verbatim, `authority_unchanged` held,
//! promotion/empty inputs rejected, digests deterministic, and no
//! `VERIFIED_COMPLETE` marker exists on the wire. Aggregate output still cannot
//! acquire Research acquisition, Governor admission, canonical write,
//! authority, durable scheduling, provider execution, or Finish ownership.
//! #13 capability resolution for this edge maps to `smart.dreamer.contracts`
//! (schemas), `smart.dreamer.bundle` (assembly), and
//! `smart.dreamer.candidate_validation` (validation); full runtime/Product
//! proof stays with #1100/#11. Proof ceiling:
//! `COGNITIVE_AGGREGATE_RETIREMENT_CANDIDATE`.
//!
//! ## Closed divergences (contract-unification turn; the facade side is gone)
//!
//! - D-DRM-1 (closed): the `SCREAMING_SNAKE_CASE` facade wire enums are
//!   deleted. `JobClass` is the canonical closed `snake_case` enum
//!   re-exported from contracts; the fixture asserts the canonical spellings
//!   live, never equated through case folding.
//! - D-DRM-2 (closed): canonical `architecture_self_query` is the single
//!   architecture surface spelling. The owner keeps architecture/implementation
//!   brief surfaces distinct (`ARCHITECTURE_BRIEF_KIND` vs
//!   `IMPLEMENTATION_BRIEF_KIND`); generation must never synthesize the
//!   distinction.
//! - D-DRM-3 (closed): `configuration_assistance` is first-class canonical
//!   with live wire assertions. There is no facade counterpart left to diverge.
//! - D-DRM-4: facade flat `Requester` (4 variants, no binding) vs owner
//!   `RequesterOrigin` (3 origins) + principal/session binding that model text
//!   can never rewrite. Only `Human`/`human` is an exact correspondence; the
//!   remaining mapping is proposed for intake migration, never asserted here.
//! - D-DRM-5: facade 4 coarse `u32` budget fields vs owner 11 independent
//!   dimensions with no cross-subsidy. Facade zero-rejection is retained;
//!   `route_cost_units` is a passthrough, never an authorization.
//! - D-DRM-6: facade `CONTRACT_VERSION: ContractVersion(1,0,0)` vs owner
//!   `CONTRACT_VERSION: &str "1.0.0"` + `DREAM_JOB_SCHEMA_VERSION: u32 = 1`.
//!   Wire schema versions are never equated.
//! - D-DRM-7: facade 6-bool `PreservationReport` vs owner 7-dimension verdicts
//!   with no averaging. Facade `authority_unchanged` is retained as the
//!   candidate-only ceiling bit, never as a promotion claim.
//! - D-DRM-8 (closed): the facade free-text `ArtifactId` handles, `ArtifactId`
//!   job id, and `all_handles` dedup are deleted with row 13. Intake is the
//!   canonical closed shape (`job_id`/`exact_question`/`scope_id` strings,
//!   `BudgetLimits`-era `budget_units`, `allowed_model_routes`); handle closure
//!   belongs to bundle assembly, never to intake.
//!
//! ## Sequencing (read-only; not duplicated here)
//!
//! SHIM-SWEEP-SMART / CUEKIND-OWNER touch adjacent state; the read-only check
//! found no exact-titled issues, only adjacent owners: #833 (facade shaping),
//! #835 + #706 (`eliot-types` `CueKind` alias/denominator), #804 (A-10 dreamer
//! vocabulary owner), orientation/clarification/curation handler issues. This
//! turn pre-deletes nothing and invents no handler semantics. Residual for the
//! LEGACY-DELETE-last root turn: root `Cargo.toml` member line, `Cargo.lock`
//! own-entry, generated doc indexes, `module.toml` donor anchors.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use blake3::Hasher;
use eliot_contracts::{ArtifactId, ContractError, ContractVersion, StateFence};
use eliot_dreamer_contracts::ContractViolation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Canonical intake/draft vocabulary, owned by `eliot-dreamer-contracts`.
/// The facade duplicates are deleted (contract-unification turn); this crate
/// re-exports the canonical shapes so surviving items (`CandidateGenerator`,
/// `CandidateArtifact`, `DreamPacket`) bind to owner vocabulary directly.
pub use eliot_dreamer_contracts::{DreamJobInput, JobClass, ModelDraft};

pub const CONTRACT_NAME: &str = "eliot.smart.dreamer";
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
pub const MAX_TEXT: usize = 16_384;
pub const MAX_ITEMS: usize = 64;
pub const MAX_SOURCES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DreamerError {
    #[error("{field} must be non-blank, control-free, and at most {maximum} bytes")]
    InvalidText { field: &'static str, maximum: usize },
    #[error("{field} exceeds the bounded item limit of {maximum}")]
    TooMany { field: &'static str, maximum: usize },
    #[error("{field} must contain at least one source handle")]
    MissingLineage { field: &'static str },
    #[error("dream job state fence is invalid")]
    InvalidFence,
    #[error("draft evidence is outside the job state fence")]
    FenceMismatch,
    #[error("model output cannot assert canonical epistemic state")]
    UnsupportedPromotion,
    #[error("candidate budget is exhausted")]
    BudgetExhausted,
    #[error("candidate has no material content")]
    EmptyCandidate,
    #[error("generated artifact id is invalid: {0}")]
    InvalidArtifactId(#[from] ContractError),
    #[error(transparent)]
    OwnerContract(#[from] ContractViolation),
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Requester {
    Human,
    MainAgent,
    Watchdog,
    MaintenancePolicy,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CandidateKind {
    Interpretation,
    RivalModel,
    Relation,
    Classification,
    Episode,
    Concept,
    Procedure,
    Failure,
    Merge,
    Split,
    Reconsolidation,
    Accessibility,
    Repair,
    Clarification,
    Probe,
    Maintenance,
    WorkPlan,
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClass {
    LocalOnly,
    GovernedExternal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamBudget {
    pub maximum_candidates: u32,
    pub maximum_source_handles: u32,
    pub maximum_output_bytes: u32,
    pub route_cost_units: u32,
}

impl DreamBudget {
    pub fn validate(&self) -> Result<(), DreamerError> {
        if self.maximum_candidates == 0
            || self.maximum_source_handles == 0
            || self.maximum_output_bytes == 0
        {
            return Err(DreamerError::BudgetExhausted);
        }
        Ok(())
    }
}

/// Maps canonical intake validation onto the candidate-only error vocabulary.
/// A non-positive canonical budget (`budget_units`/`deadline_ms`) is a
/// degenerate budget, mirroring the retained facade `DreamBudget`
/// zero-rejection; every other owner violation passes through verbatim.
fn map_input_violation(violation: ContractViolation) -> DreamerError {
    match violation {
        ContractViolation::BindingMismatch {
            field: "budget", ..
        } => DreamerError::BudgetExhausted,
        other => DreamerError::OwnerContract(other),
    }
}

/// Maps canonical draft validation onto the candidate-only error vocabulary.
/// Model text that declares confirmed evidence is a promotion attempt, exactly
/// as the deleted facade `ModelDraft::validate` classified it; every other
/// owner violation passes through verbatim.
fn map_draft_violation(violation: ContractViolation) -> DreamerError {
    match violation {
        ContractViolation::ForbiddenCarry(_) => DreamerError::UnsupportedPromotion,
        other => DreamerError::OwnerContract(other),
    }
}

fn artifact_id(value: &str) -> Result<ArtifactId, DreamerError> {
    ArtifactId::new(value).map_err(DreamerError::InvalidArtifactId)
}

fn artifact_ids(values: &[String]) -> Result<Vec<ArtifactId>, DreamerError> {
    values.iter().map(|value| artifact_id(value)).collect()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the boolean preservation dimensions are an established serialized report shape"
)]
pub struct PreservationReport {
    pub source_count: u32,
    pub counterevidence_count: u32,
    pub alternatives_preserved: bool,
    pub uncertainty_visible: bool,
    pub reversible: bool,
    pub authority_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateArtifact {
    pub candidate_id: ArtifactId,
    pub kind: CandidateKind,
    pub job_id: ArtifactId,
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub statement: String,
    pub source_handles: Vec<ArtifactId>,
    pub counterevidence: Vec<ArtifactId>,
    pub uncertainty: String,
    pub expected_benefit: String,
    pub rollback: String,
    pub preservation: PreservationReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamPacket {
    pub packet_id: ArtifactId,
    pub job_id: ArtifactId,
    pub question: String,
    pub scope: String,
    pub state_fence: StateFence,
    pub synthesis: String,
    pub candidates: Vec<CandidateArtifact>,
    pub unknowns: Vec<String>,
    pub recommended_probes: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub source_coverage: u32,
    pub route_cost_units: u32,
}

pub struct CandidateGenerator;

impl CandidateGenerator {
    /// Turns one canonical [`ModelDraft`] single hypothesis into an inspectable
    /// candidate-only [`DreamPacket`].
    ///
    /// The draft must belong to the input job (`draft.job_id == input.job_id`)
    /// and every draft handle must close over the input handle union
    /// (evidence + memory + architecture + implementation + conformance);
    /// anything else is a [`DreamerError::FenceMismatch`]. The packet byte
    /// length must fit inside the canonical `budget_units`, otherwise
    /// [`DreamerError::BudgetExhausted`]. The candidate records the model's
    /// invalidation conditions as its rollback, so reversibility is exactly
    /// what the model declared — never synthesized.
    pub fn generate(
        input: &DreamJobInput,
        draft: &ModelDraft,
    ) -> Result<DreamPacket, DreamerError> {
        input.validate().map_err(map_input_violation)?;
        draft.validate().map_err(map_draft_violation)?;
        if draft.job_id != input.job_id {
            return Err(DreamerError::FenceMismatch);
        }
        let allowed: BTreeSet<&str> = input
            .evidence_handles
            .iter()
            .chain(&input.memory_handles)
            .chain(&input.architecture_handles)
            .chain(&input.implementation_handles)
            .chain(&input.conformance_handles)
            .map(String::as_str)
            .collect();
        if draft
            .source_handles
            .iter()
            .chain(&draft.counterevidence)
            .any(|handle| !allowed.contains(handle.as_str()))
        {
            return Err(DreamerError::FenceMismatch);
        }
        let source_handles = artifact_ids(&draft.source_handles)?;
        let counterevidence = artifact_ids(&draft.counterevidence)?;
        let item_source_count = u32::try_from(draft.source_handles.len()).unwrap_or(u32::MAX);
        let item_counterevidence_count =
            u32::try_from(draft.counterevidence.len()).unwrap_or(u32::MAX);
        // Single-hypothesis draft: no rival displacement is possible, so the
        // alternatives-preserved bit holds exactly as the old multi-item rule
        // concluded for a rival-free item set.
        let preservation = PreservationReport {
            source_count: item_source_count,
            counterevidence_count: item_counterevidence_count,
            alternatives_preserved: true,
            uncertainty_visible: true,
            reversible: !draft
                .invalidation_conditions
                .iter()
                .all(|c| c.trim().is_empty()),
            authority_unchanged: true,
        };
        let rollback = draft.invalidation_conditions.join("; ");
        let candidate_id = digest_id(
            "candidate",
            &[&input.job_id, &input.scope_id, &draft.statement],
        )?;
        let candidates = vec![CandidateArtifact {
            candidate_id,
            kind: CandidateKind::Interpretation,
            job_id: artifact_id(&input.job_id)?,
            question: input.exact_question.clone(),
            scope: input.scope_id.clone(),
            state_fence: input.state_fence.clone(),
            statement: draft.statement.clone(),
            source_handles,
            counterevidence,
            uncertainty: draft.uncertainty.clone(),
            expected_benefit: draft.expected_benefit.clone(),
            rollback,
            preservation,
        }];
        let packet_id = digest_id("packet", &[&input.job_id, &input.exact_question])?;
        let packet = DreamPacket {
            packet_id,
            job_id: artifact_id(&input.job_id)?,
            question: input.exact_question.clone(),
            scope: input.scope_id.clone(),
            state_fence: input.state_fence.clone(),
            synthesis: draft.statement.clone(),
            candidates,
            unknowns: dedup_text(&input.conflicts_and_unknowns),
            recommended_probes: dedup_text(&draft.recommended_probes),
            invalidation_conditions: dedup_text(&draft.invalidation_conditions),
            source_coverage: item_source_count,
            // Canonical intake carries no route-cost passthrough (the old
            // facade `DreamBudget::route_cost_units` passthrough is retained
            // only on the facade budget shape); candidate-only packets record
            // zero until a cost owner exists.
            route_cost_units: 0,
        };
        let bytes = serde_json::to_vec(&packet).map_err(|_| DreamerError::EmptyCandidate)?;
        if (bytes.len() as u64) > input.budget_units {
            return Err(DreamerError::BudgetExhausted);
        }
        Ok(packet)
    }
}

fn dedup_text(values: &[String]) -> Vec<String> {
    let mut result = values.to_vec();
    result.sort();
    result.dedup();
    result
}

fn digest_id(prefix: &str, parts: &[&str]) -> Result<ArtifactId, DreamerError> {
    let mut hasher = Hasher::new();
    hasher.update(prefix.as_bytes());
    for part in parts {
        hasher.update(&[0]);
        hasher.update(part.as_bytes());
    }
    ArtifactId::new(format!(
        "{prefix}:{}",
        &hasher.finalize().to_hex().to_string()[..32]
    ))
    .map_err(DreamerError::InvalidArtifactId)
}

#[cfg(test)]
mod differential_1143 {
    //! Issue #1143, EDGE-DRM-1143 differential fixtures (candidate-only ceiling).
    //!
    //! Each fixture runs the canonical intake/draft vocabulary live through
    //! this crate's re-exports (`super::{JobClass, DreamJobInput, ModelDraft}`)
    //! plus the direct `eliot_dreamer_contracts` edge (parse fns, owner error).
    //! The owner cells prove their own behavior in their suites
    //! (`eliot-dreamer-contracts` budget/job/draft tests, e.g.
    //! `WORK_UNIT_CASE: 578/10-12`); these fixtures prove generation on the
    //! canonical shapes stays candidate-only.

    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_dreamer_contracts::{ContractViolation, parse_job_class};

    use super::{
        CONTRACT_NAME, CandidateGenerator, CandidateKind, DreamBudget, DreamJobInput, DreamerError,
        JobClass, MAX_ITEMS, MAX_SOURCES, MAX_TEXT, ModelDraft, PrivacyClass, Requester,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> Result<StateFence, Box<dyn std::error::Error>> {
        let lineage = EpochLineageId::new(TEST_LINEAGE_A)?;
        let epoch = EpochId::new(lineage, NonZeroU64::MIN)?;
        Ok(StateFence::new(epoch, ResourceGeneration::genesis()))
    }

    fn generous_budget() -> DreamBudget {
        DreamBudget {
            maximum_candidates: 8,
            maximum_source_handles: 8,
            maximum_output_bytes: 16_384,
            route_cost_units: 3,
        }
    }

    fn test_input_with_budget(
        budget_units: u64,
    ) -> Result<DreamJobInput, Box<dyn std::error::Error>> {
        Ok(DreamJobInput {
            job_id: "dream-job:ledger-1143".to_owned(),
            job_class: JobClass::Orientation,
            exact_question: "ledger probe question".to_owned(),
            requester: "alice".to_owned(),
            scope_id: "ledger-1143".to_owned(),
            task_id: Some("task-ledger-1".to_owned()),
            state_fence: test_fence()?,
            evidence_handles: vec!["evidence:ledger-1".to_owned()],
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: vec!["unknown-1".to_owned()],
            privacy_profile: "local_only".to_owned(),
            allowed_tools: vec!["read".to_owned()],
            allowed_model_routes: vec!["route-a".to_owned()],
            budget_units,
            deadline_ms: 60_000,
            output_schema: "candidate-packet-v1".to_owned(),
            forbidden_effects: Vec::new(),
        })
    }

    fn test_input() -> Result<DreamJobInput, Box<dyn std::error::Error>> {
        test_input_with_budget(16_384)
    }

    fn test_draft(statement: &str) -> Result<ModelDraft, Box<dyn std::error::Error>> {
        Ok(ModelDraft {
            schema_version: 1,
            job_id: "dream-job:ledger-1143".to_owned(),
            statement: statement.to_owned(),
            source_handles: vec!["evidence:ledger-1".to_owned()],
            counterevidence: Vec::new(),
            uncertainty: "ledger uncertainty".to_owned(),
            expected_benefit: "ledger benefit".to_owned(),
            recommended_probes: vec!["probe-1".to_owned()],
            invalidation_conditions: vec!["condition-1".to_owned()],
            declared_confirmed_handles: Vec::new(),
        })
    }

    // EDGE-DRM-1143 wire vocabulary: the re-exported canonical `JobClass`
    // (`eliot-dreamer-contracts/src/job.rs`: closed snake_case enum +
    // `parse_job_class`) serializes to the frozen owner spellings live through
    // this crate (D-DRM-1). `architecture_self_query` is the single
    // architecture spelling (D-DRM-2) and `configuration_assistance` is
    // first-class with live assertions (D-DRM-3). SCREAMING_SNAKE spellings
    // are rejected, never equated.
    #[test]
    fn ledger_1143_job_class_wire_matches_owner_spellings() -> TestResult {
        assert_eq!(CONTRACT_NAME, "eliot.smart.dreamer");
        let canonical: [(JobClass, &str); 9] = [
            (JobClass::Orientation, "orientation"),
            (JobClass::Curation, "curation"),
            (JobClass::Clarification, "clarification"),
            (JobClass::ResearchSynthesis, "research_synthesis"),
            (JobClass::ArchitectureSelfQuery, "architecture_self_query"),
            (JobClass::DevelopmentDiagnosis, "development_diagnosis"),
            (JobClass::Maintenance, "maintenance"),
            (JobClass::OrchestrationPlanning, "orchestration_planning"),
            (
                JobClass::ConfigurationAssistance,
                "configuration_assistance",
            ),
        ];
        for (class, owner_spelling) in canonical {
            assert_eq!(class.as_str(), owner_spelling);
            assert_eq!(
                parse_job_class(owner_spelling).expect("known spelling"),
                class
            );
            let wire = serde_json::to_string(&class)?;
            assert_eq!(wire, ["\"", owner_spelling, "\""].concat());
        }
        for rejected in [
            "ORIENTATION",
            "ARCHITECTURE",
            "CONFIGURATION_ASSISTANCE",
            "other",
        ] {
            assert!(parse_job_class(rejected).is_err());
        }
        let requesters: [(Requester, &str); 4] = [
            (Requester::Human, "\"HUMAN\""),
            (Requester::MainAgent, "\"MAIN_AGENT\""),
            (Requester::Watchdog, "\"WATCHDOG\""),
            (Requester::MaintenancePolicy, "\"MAINTENANCE_POLICY\""),
        ];
        for (requester, wire_spelling) in requesters {
            let wire = serde_json::to_string(&requester)?;
            assert_eq!(wire, wire_spelling);
        }
        // D-DRM-4: only Human/human is an exact correspondence; the owner binds
        // origin + principal/session (`job.rs`), which the facade cannot carry.
        assert_eq!(
            serde_json::to_string(&PrivacyClass::LocalOnly)?,
            "\"LOCAL_ONLY\""
        );
        assert_eq!(
            serde_json::to_string(&PrivacyClass::GovernedExternal)?,
            "\"GOVERNED_EXTERNAL\""
        );
        let kinds: [(CandidateKind, &str); 4] = [
            (CandidateKind::RivalModel, "\"RIVAL_MODEL\""),
            (CandidateKind::Clarification, "\"CLARIFICATION\""),
            (CandidateKind::Probe, "\"PROBE\""),
            (CandidateKind::WorkPlan, "\"WORK_PLAN\""),
        ];
        for (kind, wire_spelling) in kinds {
            let wire = serde_json::to_string(&kind)?;
            assert_eq!(wire, wire_spelling);
        }
        Ok(())
    }

    // EDGE-DRM-1143 budget gate: degenerate facade budgets are rejected at
    // validation (mirroring the owner `BudgetLimits` zero-rejection in
    // `eliot-dreamer-contracts/src/budget.rs`), and degenerate canonical
    // budgets are rejected at generation: `budget_units == 0` fails intake
    // validation and maps to `BudgetExhausted`, and a packet that does not fit
    // inside `budget_units` is refused. Frozen facade bounds pinned.
    #[test]
    fn ledger_1143_budget_edge_rejects_degenerate_budgets() -> TestResult {
        assert_eq!(MAX_TEXT, 16_384);
        assert_eq!(MAX_ITEMS, 64);
        assert_eq!(MAX_SOURCES, 128);
        let base = generous_budget();
        assert!(base.validate().is_ok());
        for degenerate in [
            DreamBudget {
                maximum_candidates: 0,
                ..base.clone()
            },
            DreamBudget {
                maximum_source_handles: 0,
                ..base.clone()
            },
            DreamBudget {
                maximum_output_bytes: 0,
                ..base.clone()
            },
        ] {
            assert_eq!(degenerate.validate(), Err(DreamerError::BudgetExhausted));
        }
        let draft = test_draft("tiny")?;
        let zero_budget = test_input_with_budget(0)?;
        assert_eq!(
            CandidateGenerator::generate(&zero_budget, &draft),
            Err(DreamerError::BudgetExhausted)
        );
        let input = test_input_with_budget(1)?;
        assert_eq!(
            CandidateGenerator::generate(&input, &draft),
            Err(DreamerError::BudgetExhausted)
        );
        let healthy = test_input()?;
        assert!(CandidateGenerator::generate(&healthy, &draft).is_ok());
        Ok(())
    }

    // EDGE-DRM-1143 candidate-only ceiling: generation carries the fence
    // verbatim, holds `authority_unchanged`, rejects promotion and empty
    // drafts, binds the draft to its job, issues deterministic digests, and
    // emits no VERIFIED_COMPLETE marker. No Research acquisition, Governor
    // admission, canonical write, authority, durable scheduling, provider
    // execution, or Finish ownership.
    #[test]
    fn ledger_1143_generate_stays_candidate_only() -> TestResult {
        let input = test_input()?;
        let draft = test_draft("ledger candidate statement")?;
        let first = CandidateGenerator::generate(&input, &draft)?;
        let again = CandidateGenerator::generate(&input, &draft)?;
        assert_eq!(first, again);
        assert_eq!(first.job_id.as_str(), input.job_id);
        assert_eq!(first.state_fence, input.state_fence);
        assert_eq!(first.candidates.len(), 1);
        let candidate = &first.candidates[0];
        assert_eq!(candidate.kind, CandidateKind::Interpretation);
        assert_eq!(candidate.statement, "ledger candidate statement");
        assert_eq!(candidate.uncertainty, "ledger uncertainty");
        assert_eq!(candidate.expected_benefit, "ledger benefit");
        assert_eq!(candidate.rollback, "condition-1");
        assert!(candidate.preservation.authority_unchanged);
        assert!(candidate.preservation.reversible);
        assert!(candidate.preservation.alternatives_preserved);
        assert!(candidate.preservation.uncertainty_visible);
        assert_eq!(candidate.job_id.as_str(), input.job_id);
        assert_eq!(candidate.question, input.exact_question);
        assert_eq!(candidate.scope, input.scope_id);
        assert_eq!(first.source_coverage, 1);
        assert_eq!(first.route_cost_units, 0);
        assert_eq!(first.synthesis, "ledger candidate statement");
        assert_eq!(first.unknowns, vec!["unknown-1".to_owned()]);
        assert_eq!(first.recommended_probes, vec!["probe-1".to_owned()]);
        assert_eq!(
            first.invalidation_conditions,
            vec!["condition-1".to_owned()]
        );
        let mut promoted = test_draft("promoted")?;
        promoted.declared_confirmed_handles = vec!["evidence:ledger-1".to_owned()];
        assert_eq!(
            CandidateGenerator::generate(&input, &promoted),
            Err(DreamerError::UnsupportedPromotion)
        );
        let mut fenced = test_draft("fenced")?;
        fenced.source_handles = vec!["evidence:unknown".to_owned()];
        assert_eq!(
            CandidateGenerator::generate(&input, &fenced),
            Err(DreamerError::FenceMismatch)
        );
        let mut rebound = test_draft("rebound")?;
        rebound.job_id = "dream-job:other".to_owned();
        assert_eq!(
            CandidateGenerator::generate(&input, &rebound),
            Err(DreamerError::FenceMismatch)
        );
        let blank = test_draft("")?;
        assert!(matches!(
            CandidateGenerator::generate(&input, &blank),
            Err(DreamerError::OwnerContract(
                ContractViolation::MissingField("statement")
            ))
        ));
        let wire = serde_json::to_string(&first)?;
        assert!(!wire.contains("VERIFIED_COMPLETE"));
        assert!(!wire.contains("verified_complete"));
        Ok(())
    }
}
