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
//! LEDGER + EDGE MIGRATION ONLY this turn: no root turn (root `Cargo.toml`
//! members, `Cargo.lock`, generated indexes are a serialized residual owned by
//! the LEGACY-DELETE-last root turn), no deletions (`LEGACY-DELETE-last`).
//! Zero live Cargo reverse-deps and zero `use eliot_dreamer_core::` outside
//! self were re-verified; this ledger (23 pub items, one row each) is the
//! sufficiency record. No new dependency edge is added this turn, so the
//! current-cell side of the migrated edge is pinned to frozen owner schemas
//! (cited by file) and proven live by the owner cells' own suites; the facade
//! side runs live here with aggregate fallback unavailable inside each
//! `differential_1143` fixture body.
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
//! | 7 | `JobClass` (8 variants) | contracts `job::JobClass` (9 closed classes) | EDGE-DRM-1143 wire-vocabulary differential (see D-DRM-1..3); retained until handlers migrate | MIGRATED-1143 (`differential_1143` in this file) |
//! | 8 | `Requester` (4 variants) | contracts `job::{Requester, RequesterOrigin}` (origin + principal/session binding) | requester-mapping fixture (see D-DRM-4); expires after intake migration | DELETE-PROPOSED after bundle owns requester binding |
//! | 9 | `CandidateKind` (17 variants) | contracts `curation::CurationKind` + kind families + 13 typed handler cells (classification/relation/episode/concept/procedure/failure/structure-repair/reconsolidation/accessibility/memory-repair + rival-model/probe-plan + clarification) | kind-mapping fixture; expires after curation + handlers admit every kind | DELETE-PROPOSED after handler migration |
//! | 10 | `PrivacyClass` | `eliot-security-contracts::PrivacyClass` via contracts re-export | privacy-mapping fixture; expires at LEGACY-DELETE | DELETE-PROPOSED after intake uses owner class |
//! | 11 | `DreamBudget` | contracts `budget::BudgetLimits` (11 independent dimensions) | EDGE-DRM-1143 budget-shape differential (see D-DRM-5); retained until jobs carry owner budgets | MIGRATED-1143 (`differential_1143` in this file) |
//! | 12 | `DreamBudget::validate` | contracts `BudgetLimits::validate`/`require_exact` | EDGE-DRM-1143 zero-rejection differential; retained until jobs carry owner budgets | MIGRATED-1143 (`differential_1143` in this file) |
//! | 13 | `DreamJobInput` | contracts `job::DreamJobInput` (closed intake) via bundle `DreamInputBundle` assembly | intake-shape fixture (see D-DRM-8); expires after bundle owns assembly | DELETE-PROPOSED after bundle migration |
//! | 14 | `DreamJobInput::validate` | contracts intake `validate` + bundle assembly checks | intake-validation fixture; expires with row 13 | DELETE-PROPOSED after bundle migration |
//! | 15 | `DreamJobInput::all_handles` | bundle `AssemblyMaterialSet` / material closure | handle-closure fixture (assembly-input convenience only, never authority); expires with row 13 | DELETE-PROPOSED after bundle migration |
//! | 16 | `DraftItem` | contracts `draft::ModelDraft` items + claim-grounding `GroundedDreamDraft` items | draft-item fixture; expires after grounding migration | DELETE-PROPOSED after claim-grounding owns items |
//! | 17 | `ModelDraft` | contracts `draft::{ModelDraft, RawProviderOutput}` + grounding | draft-shape fixture (candidate-only rejection retained); expires after grounding migration | DELETE-PROPOSED after claim-grounding owns drafts |
//! | 18 | `ModelDraft::validate` | candidate-validation `validate_grounded_dream_draft_at` + structured validation | draft-validation fixture; expires with row 17 | DELETE-PROPOSED after candidate-validation owns validation |
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
//! `differential_1143` prove: (a) the 7 shared job classes map to the frozen
//! owner spellings with the `Architecture` rename and the missing
//! `ConfigurationAssistance` logged (D-DRM-2/3); (b) degenerate budgets are
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
//! ## Corrected divergences (explicit; never restored for output-match)
//!
//! - D-DRM-1: facade wire enums are `SCREAMING_SNAKE_CASE`; owner enums are
//!   closed `snake_case`. Case convention is never equated — the fixture maps
//!   through `to_uppercase` on frozen owner spellings.
//! - D-DRM-2: facade `Architecture` vs owner `architecture_self_query`. The
//!   owner keeps architecture/implementation brief surfaces distinct
//!   (`ARCHITECTURE_BRIEF_KIND` vs `IMPLEMENTATION_BRIEF_KIND`); the facade
//!   must never synthesize the distinction.
//! - D-DRM-3: owner `configuration_assistance` is first-class with no facade
//!   counterpart. The facade must never emit or accept it.
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
//! - D-DRM-8: facade free-text handles + `ArtifactId` job id vs owner closed
//!   intake (`schema_version`, `operation_id`, `idempotency_key`,
//!   `frozen_manifest_digest`, `BudgetLimits`). Facade `all_handles` dedup is
//!   an assembly-input convenience, never lineage authority.
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
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
}

fn text(value: &str, field: &'static str, maximum: usize) -> Result<(), DreamerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > maximum {
        Err(DreamerError::InvalidText { field, maximum })
    } else {
        Ok(())
    }
}

fn bounded<T>(items: &[T], field: &'static str, maximum: usize) -> Result<(), DreamerError> {
    if items.len() > maximum {
        Err(DreamerError::TooMany { field, maximum })
    } else {
        Ok(())
    }
}

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobClass {
    Orientation,
    Curation,
    Clarification,
    ResearchSynthesis,
    Architecture,
    DevelopmentDiagnosis,
    Maintenance,
    OrchestrationPlanning,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamJobInput {
    pub job_id: ArtifactId,
    pub job_class: JobClass,
    pub question: String,
    pub requester: Requester,
    pub scope: String,
    pub state_fence: StateFence,
    pub evidence_handles: Vec<ArtifactId>,
    pub memory_handles: Vec<ArtifactId>,
    pub architecture_handles: Vec<ArtifactId>,
    pub implementation_handles: Vec<ArtifactId>,
    pub conflicts_and_unknowns: Vec<String>,
    pub privacy: PrivacyClass,
    pub budget: DreamBudget,
}

impl DreamJobInput {
    pub fn validate(&self) -> Result<(), DreamerError> {
        text(self.job_id.as_str(), "job_id", MAX_TEXT)?;
        text(&self.question, "question", MAX_TEXT)?;
        text(&self.scope, "scope", MAX_TEXT)?;
        self.state_fence
            .validate()
            .map_err(|_| DreamerError::InvalidFence)?;
        self.budget.validate()?;
        for (field, values) in [
            ("evidence_handles", &self.evidence_handles),
            ("memory_handles", &self.memory_handles),
            ("architecture_handles", &self.architecture_handles),
            ("implementation_handles", &self.implementation_handles),
        ] {
            bounded(values, field, MAX_SOURCES)?;
            if values.iter().any(|id| id.as_str().trim().is_empty()) {
                return Err(DreamerError::MissingLineage { field });
            }
        }
        bounded(
            &self.conflicts_and_unknowns,
            "conflicts_and_unknowns",
            MAX_ITEMS,
        )?;
        for item in &self.conflicts_and_unknowns {
            text(item, "conflicts_and_unknowns", MAX_TEXT)?;
        }
        Ok(())
    }

    pub fn all_handles(&self) -> Vec<ArtifactId> {
        let mut seen = BTreeSet::new();
        for id in self
            .evidence_handles
            .iter()
            .chain(&self.memory_handles)
            .chain(&self.architecture_handles)
            .chain(&self.implementation_handles)
        {
            seen.insert(id.clone());
        }
        seen.into_iter().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DraftItem {
    pub kind: CandidateKind,
    pub statement: String,
    pub source_handles: Vec<ArtifactId>,
    pub counterevidence: Vec<ArtifactId>,
    pub uncertainty: String,
    pub expected_benefit: String,
    pub rollback: String,
}

impl DraftItem {
    fn validate(&self, input: &DreamJobInput) -> Result<(), DreamerError> {
        text(&self.statement, "draft.statement", MAX_TEXT)?;
        text(&self.uncertainty, "draft.uncertainty", MAX_TEXT)?;
        text(&self.expected_benefit, "draft.expected_benefit", MAX_TEXT)?;
        text(&self.rollback, "draft.rollback", MAX_TEXT)?;
        bounded(&self.source_handles, "draft.source_handles", MAX_SOURCES)?;
        bounded(&self.counterevidence, "draft.counterevidence", MAX_SOURCES)?;
        if self.source_handles.is_empty() {
            return Err(DreamerError::MissingLineage {
                field: "draft.source_handles",
            });
        }
        let allowed = input.all_handles().into_iter().collect::<BTreeSet<_>>();
        if self
            .source_handles
            .iter()
            .chain(&self.counterevidence)
            .any(|id| !allowed.contains(id))
        {
            return Err(DreamerError::FenceMismatch);
        }
        if matches!(
            self.kind,
            CandidateKind::Merge | CandidateKind::Split | CandidateKind::Repair
        ) && self.rollback.trim().is_empty()
        {
            return Err(DreamerError::UnsupportedPromotion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelDraft {
    pub synthesis: String,
    pub items: Vec<DraftItem>,
    pub unknowns: Vec<String>,
    pub recommended_probes: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub declared_confirmed_handles: Vec<ArtifactId>,
}

impl ModelDraft {
    pub fn validate(&self) -> Result<(), DreamerError> {
        text(&self.synthesis, "draft.synthesis", MAX_TEXT)?;
        bounded(&self.items, "draft.items", MAX_ITEMS)?;
        bounded(&self.unknowns, "draft.unknowns", MAX_ITEMS)?;
        bounded(
            &self.recommended_probes,
            "draft.recommended_probes",
            MAX_ITEMS,
        )?;
        bounded(
            &self.invalidation_conditions,
            "draft.invalidation_conditions",
            MAX_ITEMS,
        )?;
        for (field, values) in [
            ("draft.unknowns", &self.unknowns),
            ("draft.recommended_probes", &self.recommended_probes),
            (
                "draft.invalidation_conditions",
                &self.invalidation_conditions,
            ),
        ] {
            for item in values {
                text(item, field, MAX_TEXT)?;
            }
        }
        if !self.declared_confirmed_handles.is_empty() {
            return Err(DreamerError::UnsupportedPromotion);
        }
        Ok(())
    }
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
    pub fn generate(
        input: &DreamJobInput,
        draft: &ModelDraft,
    ) -> Result<DreamPacket, DreamerError> {
        input.validate()?;
        draft.validate()?;
        bounded(
            &draft.items,
            "draft.items",
            input.budget.maximum_candidates as usize,
        )?;
        let mut candidates = Vec::with_capacity(draft.items.len());
        let mut source_count = 0_u32;
        for item in &draft.items {
            item.validate(input)?;
            let item_source_count = u32::try_from(item.source_handles.len()).unwrap_or(u32::MAX);
            let item_counterevidence_count =
                u32::try_from(item.counterevidence.len()).unwrap_or(u32::MAX);
            source_count = source_count.saturating_add(item_source_count);
            let preservation = PreservationReport {
                source_count: item_source_count,
                counterevidence_count: item_counterevidence_count,
                alternatives_preserved: !item.counterevidence.is_empty()
                    || !draft
                        .items
                        .iter()
                        .any(|other| other.kind == CandidateKind::RivalModel),
                uncertainty_visible: true,
                reversible: !item.rollback.trim().is_empty(),
                authority_unchanged: true,
            };
            let candidate_id = digest_id(
                "candidate",
                &[input.job_id.as_str(), &input.scope, &item.statement],
            )?;
            candidates.push(CandidateArtifact {
                candidate_id,
                kind: item.kind,
                job_id: input.job_id.clone(),
                question: input.question.clone(),
                scope: input.scope.clone(),
                state_fence: input.state_fence.clone(),
                statement: item.statement.clone(),
                source_handles: item.source_handles.clone(),
                counterevidence: item.counterevidence.clone(),
                uncertainty: item.uncertainty.clone(),
                expected_benefit: item.expected_benefit.clone(),
                rollback: item.rollback.clone(),
                preservation,
            });
        }
        if candidates.is_empty() && draft.synthesis.trim().is_empty() {
            return Err(DreamerError::EmptyCandidate);
        }
        let packet_id = digest_id("packet", &[input.job_id.as_str(), &input.question])?;
        let packet = DreamPacket {
            packet_id,
            job_id: input.job_id.clone(),
            question: input.question.clone(),
            scope: input.scope.clone(),
            state_fence: input.state_fence.clone(),
            synthesis: draft.synthesis.clone(),
            candidates,
            unknowns: dedup_text(&draft.unknowns),
            recommended_probes: dedup_text(&draft.recommended_probes),
            invalidation_conditions: dedup_text(&draft.invalidation_conditions),
            source_coverage: source_count,
            route_cost_units: input.budget.route_cost_units,
        };
        let bytes = serde_json::to_vec(&packet).map_err(|_| DreamerError::EmptyCandidate)?;
        if bytes.len() > input.budget.maximum_output_bytes as usize {
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
    //! Each fixture runs the facade edge live with aggregate fallback
    //! unavailable inside its own body: no `eliot_dreamer_contracts::`,
    //! `eliot_dreamer_bundle::`, or handler item is imported anywhere in this
    //! module (no such dependency edge exists this turn, by design), and the
    //! current-cell side is pinned to frozen owner schemas cited by file. The
    //! owner cells prove their own live behavior in their suites
    //! (`eliot-dreamer-contracts` budget/job/candidate tests, e.g.
    //! `WORK_UNIT_CASE: 578/10-12`); these fixtures prove the facade side
    //! matches that frozen contract and stays candidate-only.

    use std::num::NonZeroU64;

    use eliot_contracts::{ArtifactId, EpochId, EpochLineageId, ResourceGeneration, StateFence};

    use super::{
        CONTRACT_NAME, CandidateGenerator, CandidateKind, DraftItem, DreamBudget, DreamJobInput,
        DreamerError, JobClass, MAX_ITEMS, MAX_SOURCES, MAX_TEXT, ModelDraft, PrivacyClass,
        Requester,
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

    fn test_input(budget: DreamBudget) -> Result<DreamJobInput, Box<dyn std::error::Error>> {
        Ok(DreamJobInput {
            job_id: ArtifactId::new("dream-job:ledger-1143")?,
            job_class: JobClass::Orientation,
            question: "ledger probe question".to_owned(),
            requester: Requester::Human,
            scope: "ledger-1143".to_owned(),
            state_fence: test_fence()?,
            evidence_handles: vec![ArtifactId::new("evidence:ledger-1")?],
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conflicts_and_unknowns: vec!["unknown-1".to_owned()],
            privacy: PrivacyClass::LocalOnly,
            budget,
        })
    }

    fn test_draft(statement: &str) -> Result<ModelDraft, Box<dyn std::error::Error>> {
        Ok(ModelDraft {
            synthesis: "ledger synthesis".to_owned(),
            items: vec![DraftItem {
                kind: CandidateKind::Clarification,
                statement: statement.to_owned(),
                source_handles: vec![ArtifactId::new("evidence:ledger-1")?],
                counterevidence: Vec::new(),
                uncertainty: "ledger uncertainty".to_owned(),
                expected_benefit: "ledger benefit".to_owned(),
                rollback: "ledger rollback".to_owned(),
            }],
            unknowns: vec!["unknown-1".to_owned()],
            recommended_probes: vec!["probe-1".to_owned()],
            invalidation_conditions: vec!["condition-1".to_owned()],
            declared_confirmed_handles: Vec::new(),
        })
    }

    // EDGE-DRM-1143 wire vocabulary: the 7 shared job classes map to the frozen
    // owner spellings (`eliot-dreamer-contracts/src/job.rs`: snake_case closed
    // `JobClass` + `parse_job_class`) through the documented SCREAMING_SNAKE
    // convention (D-DRM-1). Facade `Architecture` keeps its wire spelling; the
    // owner `architecture_self_query` rename (D-DRM-2) and the first-class
    // `configuration_assistance` with no facade counterpart (D-DRM-3) are pinned
    // as divergences, never papered over.
    #[test]
    fn ledger_1143_job_class_wire_matches_owner_spellings() -> TestResult {
        assert_eq!(CONTRACT_NAME, "eliot.smart.dreamer");
        let shared: [(JobClass, &str); 7] = [
            (JobClass::Orientation, "orientation"),
            (JobClass::Curation, "curation"),
            (JobClass::Clarification, "clarification"),
            (JobClass::ResearchSynthesis, "research_synthesis"),
            (JobClass::DevelopmentDiagnosis, "development_diagnosis"),
            (JobClass::Maintenance, "maintenance"),
            (JobClass::OrchestrationPlanning, "orchestration_planning"),
        ];
        for (class, owner_spelling) in shared {
            let upper = owner_spelling.to_uppercase();
            let wire = serde_json::to_string(&class)?;
            assert_eq!(wire, ["\"", upper.as_str(), "\""].concat());
        }
        let wire = serde_json::to_string(&JobClass::Architecture)?;
        assert_eq!(wire, "\"ARCHITECTURE\"");
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

    // EDGE-DRM-1143 budget gate: degenerate budgets are rejected at validation
    // (mirroring the owner `BudgetLimits` zero-rejection in
    // `eliot-dreamer-contracts/src/budget.rs`) and enforced at generation
    // (candidate-count and output-byte ceilings). Frozen facade bounds pinned.
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
        let input = test_input(DreamBudget {
            maximum_output_bytes: 1,
            ..generous_budget()
        })?;
        let draft = test_draft("tiny")?;
        assert_eq!(
            CandidateGenerator::generate(&input, &draft),
            Err(DreamerError::BudgetExhausted)
        );
        let mut crowded = test_draft("crowded")?;
        crowded.items.push(crowded.items[0].clone());
        let capped = test_input(DreamBudget {
            maximum_candidates: 1,
            ..generous_budget()
        })?;
        assert!(matches!(
            CandidateGenerator::generate(&capped, &crowded),
            Err(DreamerError::TooMany { .. })
        ));
        Ok(())
    }

    // EDGE-DRM-1143 candidate-only ceiling: generation carries the fence
    // verbatim, holds `authority_unchanged`, rejects promotion and empty
    // drafts, issues deterministic digests, and emits no VERIFIED_COMPLETE
    // marker. No Research acquisition, Governor admission, canonical write,
    // authority, durable scheduling, provider execution, or Finish ownership.
    #[test]
    fn ledger_1143_generate_stays_candidate_only() -> TestResult {
        let input = test_input(generous_budget())?;
        let draft = test_draft("ledger candidate statement")?;
        let first = CandidateGenerator::generate(&input, &draft)?;
        let again = CandidateGenerator::generate(&input, &draft)?;
        assert_eq!(first, again);
        assert_eq!(first.job_id, input.job_id);
        assert_eq!(first.state_fence, input.state_fence);
        assert_eq!(first.candidates.len(), 1);
        let candidate = &first.candidates[0];
        assert!(candidate.preservation.authority_unchanged);
        assert!(candidate.preservation.reversible);
        assert!(candidate.preservation.alternatives_preserved);
        assert!(candidate.preservation.uncertainty_visible);
        assert_eq!(candidate.job_id, input.job_id);
        assert_eq!(candidate.question, input.question);
        assert_eq!(candidate.scope, input.scope);
        assert_eq!(first.source_coverage, 1);
        assert_eq!(first.route_cost_units, input.budget.route_cost_units);
        let mut promoted = test_draft("promoted")?;
        promoted.declared_confirmed_handles = vec![ArtifactId::new("evidence:ledger-1")?];
        assert_eq!(
            CandidateGenerator::generate(&input, &promoted),
            Err(DreamerError::UnsupportedPromotion)
        );
        let mut fenced = test_draft("fenced")?;
        fenced.items[0].source_handles = vec![ArtifactId::new("evidence:unknown")?];
        assert_eq!(
            CandidateGenerator::generate(&input, &fenced),
            Err(DreamerError::FenceMismatch)
        );
        let mut synthesized = test_draft("empty")?;
        synthesized.items.clear();
        let synthesis_only = CandidateGenerator::generate(&input, &synthesized)?;
        assert!(synthesis_only.candidates.is_empty());
        assert_eq!(synthesis_only.synthesis, "ledger synthesis");
        let mut blank = test_draft("blank")?;
        blank.items.clear();
        blank.synthesis.clear();
        assert_eq!(
            CandidateGenerator::generate(&input, &blank),
            Err(DreamerError::InvalidText {
                field: "draft.synthesis",
                maximum: MAX_TEXT,
            })
        );
        let wire = serde_json::to_string(&first)?;
        assert!(!wire.contains("VERIFIED_COMPLETE"));
        assert!(!wire.contains("verified_complete"));
        Ok(())
    }
}
