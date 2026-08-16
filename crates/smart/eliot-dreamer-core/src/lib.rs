//! Bounded, candidate-only Dreamer generation.
//!
//! This crate is deliberately a pure boundary.  It does not call a model,
//! launch an agent, read storage, or promote semantic state.  A route adapter
//! supplies a bounded model draft and this crate turns it into an inspectable
//! candidate while enforcing scope, fence, lineage, preservation, and budget
//! invariants.

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
