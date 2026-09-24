//! Versioned R6 Researcher inquiry-profile resolution and governance state.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use eliot_contracts::{StateFence, TaskId, canonical_json_bytes, sha256_hex};
use eliot_epistemic_contracts::ClaimAuditOutcome;
use eliot_research_exchange_api::{DisclosureClass, SourceClass};
use eliot_task::{TaskError, TaskGraphCompilationReceipt, TaskLifecycleOwner};

use super::inquiry_obligations::{
    InquiryObligation, InquiryObligationInput, compile_obligation_inputs, task_graph_request,
};
use super::source_admissibility::{SourceAdmissibilityRecord, SourceProposal};

pub const INQUIRY_GOVERNANCE_CONTRACT: &str = "eliot.research.inquiry-governance";
pub const INQUIRY_GOVERNANCE_VERSION: &str = "1.0.0";

/// Fail-closed validation errors for the R6 domain boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InquiryGovernanceError {
    Blank {
        field: &'static str,
    },
    ControlCharacter {
        field: &'static str,
    },
    InvalidDigest {
        field: &'static str,
    },
    InvalidField {
        field: &'static str,
    },
    DuplicateIdentity {
        field: &'static str,
    },
    UnknownProfile {
        profile_id: String,
        revision: u64,
    },
    RevisionConflict {
        profile_id: String,
        revision: u64,
    },
    EmptyRevision {
        profile_id: String,
    },
    InvalidObligation {
        obligation_id: String,
        reason: &'static str,
    },
    CircularDependency {
        obligation_id: String,
    },
    /// The existing Task Controller owner rejected the exact compilation
    /// request. The owner error is retained instead of replacing it with a
    /// caller-supplied success/issuer string.
    TaskOwnerRejected {
        error: TaskError,
    },
    SourceIdentityConflict {
        source_handle: String,
    },
}

impl std::fmt::Display for InquiryGovernanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blank { field } => write!(f, "{field} must be non-blank"),
            Self::ControlCharacter { field } => write!(f, "{field} contains a control character"),
            Self::InvalidDigest { field } => {
                write!(f, "{field} must be a lowercase SHA-256 digest")
            }
            Self::InvalidField { field } => write!(f, "{field} is invalid"),
            Self::DuplicateIdentity { field } => write!(f, "{field} contains a duplicate identity"),
            Self::UnknownProfile {
                profile_id,
                revision,
            } => {
                write!(f, "profile {profile_id}@{revision} is unknown")
            }
            Self::RevisionConflict {
                profile_id,
                revision,
            } => {
                write!(
                    f,
                    "profile {profile_id}@{revision} conflicts with an existing revision"
                )
            }
            Self::EmptyRevision { profile_id } => {
                write!(
                    f,
                    "profile {profile_id} revision does not change its governed shape"
                )
            }
            Self::InvalidObligation {
                obligation_id,
                reason,
            } => {
                write!(f, "obligation {obligation_id} is invalid: {reason}")
            }
            Self::CircularDependency { obligation_id } => {
                write!(f, "obligation dependency cycle at {obligation_id}")
            }
            Self::TaskOwnerRejected { error } => {
                write!(f, "Task Controller rejected inquiry compilation: {error}")
            }
            Self::SourceIdentityConflict { source_handle } => {
                write!(
                    f,
                    "source {source_handle} conflicts within its evidence set"
                )
            }
        }
    }
}

impl std::error::Error for InquiryGovernanceError {}

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), InquiryGovernanceError> {
    if value.trim().is_empty() {
        return Err(InquiryGovernanceError::Blank { field });
    }
    if value.chars().any(char::is_control) {
        return Err(InquiryGovernanceError::ControlCharacter { field });
    }
    Ok(())
}

pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), InquiryGovernanceError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(InquiryGovernanceError::InvalidDigest { field });
    }
    Ok(())
}

pub(crate) fn unique_texts(
    values: &[String],
    field: &'static str,
) -> Result<(), InquiryGovernanceError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        text(value, field)?;
        if !seen.insert(value) {
            return Err(InquiryGovernanceError::DuplicateIdentity { field });
        }
    }
    Ok(())
}

pub(crate) fn push_field(preimage: &mut String, tag: &str, value: &str) {
    preimage.push_str(tag);
    preimage.push('=');
    preimage.push_str(&value.len().to_string());
    preimage.push(':');
    preimage.push_str(value);
    preimage.push(';');
}

pub(crate) fn push_count(preimage: &mut String, tag: &str, count: usize) {
    let _ = writeln!(preimage, "{tag}={count};");
}

pub(crate) fn freeze(preimage: &str) -> String {
    sha256_hex(preimage.as_bytes())
}

/// Protocol vocabulary from I21.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InquiryProtocol {
    Lookup,
    EvidenceReview,
    CausalDiagnosis,
    FormalProof,
    ProgramSynthesis,
    ArchitectureDecision,
    AlgorithmSearch,
    EmpiricalDiscovery,
    TheoryDevelopment,
    DecisionSupport,
}

impl InquiryProtocol {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::EvidenceReview => "evidence_review",
            Self::CausalDiagnosis => "causal_diagnosis",
            Self::FormalProof => "formal_proof",
            Self::ProgramSynthesis => "program_synthesis",
            Self::ArchitectureDecision => "architecture_decision",
            Self::AlgorithmSearch => "algorithm_search",
            Self::EmpiricalDiscovery => "empirical_discovery",
            Self::TheoryDevelopment => "theory_development",
            Self::DecisionSupport => "decision_support",
        }
    }
}

/// The canonical I21.2 grade projection, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvidenceGrade {
    Orienting,
    Grounded,
    Corroborated,
    ScienceGrade,
}

impl EvidenceGrade {
    pub const E0: Self = Self::Orienting;
    pub const E1: Self = Self::Grounded;
    pub const E2: Self = Self::Corroborated;
    pub const E3: Self = Self::ScienceGrade;

    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Orienting => 0,
            Self::Grounded => 1,
            Self::Corroborated => 2,
            Self::ScienceGrade => 3,
        }
    }

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Orienting => "ORIENTING",
            Self::Grounded => "GROUNDED",
            Self::Corroborated => "CORROBORATED",
            Self::ScienceGrade => "SCIENCE_GRADE",
        }
    }

    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "ORIENTING" | "E0" => Some(Self::Orienting),
            "GROUNDED" | "E1" => Some(Self::Grounded),
            "CORROBORATED" | "E2" => Some(Self::Corroborated),
            "SCIENCE_GRADE" | "SCIENCE GRADE" | "E3" => Some(Self::ScienceGrade),
            _ => None,
        }
    }

    /// Checks this typed projection against the existing evidence-portfolio
    /// grade owner instead of creating a second grade vocabulary.
    pub fn validate_canonical(self) -> Result<(), InquiryGovernanceError> {
        let expected = crate::evidence_portfolio::grade_name(self.rank()).map_err(|_| {
            InquiryGovernanceError::InvalidField {
                field: "profile.evidence_grade",
            }
        })?;
        if expected != self.wire_name() {
            return Err(InquiryGovernanceError::InvalidField {
                field: "profile.evidence_grade",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InquiryLane {
    Confirmatory,
    Exploratory,
    MixedWithDeclaredSplit,
}

impl InquiryLane {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Confirmatory => "confirmatory",
            Self::Exploratory => "exploratory",
            Self::MixedWithDeclaredSplit => "mixed_with_declared_split",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageGoal {
    Exploratory,
    Representative,
    HighRecall,
    Exhaustive,
}

impl CoverageGoal {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exploratory => "exploratory",
            Self::Representative => "representative",
            Self::HighRecall => "high_recall",
            Self::Exhaustive => "exhaustive",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HypothesisPolicy {
    AlternativesRequired,
    CounterSearchRequired,
    FalsificationRequired,
}

impl HypothesisPolicy {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AlternativesRequired => "alternatives_required",
            Self::CounterSearchRequired => "counter_search_required",
            Self::FalsificationRequired => "falsification_required",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum VerifierStrength {
    None,
    Limited,
    Strong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SpecialistDiscoverability {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InquiryHorizon {
    Immediate,
    Extended,
    Strategic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InquiryUncertainty {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InquiryRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// Feature inputs used by protocol selection. These are deliberately not
/// task vocabulary, matching I21.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InquirySelectionFeatures {
    pub sequential_dependency: bool,
    pub branch_independence: bool,
    pub shared_mutable_state: bool,
    pub verifier_cost: VerifierStrength,
    pub verifier_strength: VerifierStrength,
    pub specialist_discoverability: SpecialistDiscoverability,
    pub horizon: InquiryHorizon,
    pub uncertainty: InquiryUncertainty,
    pub risk: InquiryRisk,
}

impl Default for InquirySelectionFeatures {
    fn default() -> Self {
        Self {
            sequential_dependency: false,
            branch_independence: true,
            shared_mutable_state: false,
            verifier_cost: VerifierStrength::Limited,
            verifier_strength: VerifierStrength::Limited,
            specialist_discoverability: SpecialistDiscoverability::Medium,
            horizon: InquiryHorizon::Immediate,
            uncertainty: InquiryUncertainty::Medium,
            risk: InquiryRisk::Medium,
        }
    }
}

impl InquirySelectionFeatures {
    #[must_use]
    pub fn digest(self) -> String {
        let mut p = String::from("inquiry-selection-features/v1;");
        push_field(
            &mut p,
            "sequential_dependency",
            if self.sequential_dependency {
                "true"
            } else {
                "false"
            },
        );
        push_field(
            &mut p,
            "branch_independence",
            if self.branch_independence {
                "true"
            } else {
                "false"
            },
        );
        push_field(
            &mut p,
            "shared_mutable_state",
            if self.shared_mutable_state {
                "true"
            } else {
                "false"
            },
        );
        push_field(
            &mut p,
            "verifier_cost",
            &format!("{:?}", self.verifier_cost),
        );
        push_field(
            &mut p,
            "verifier_strength",
            &format!("{:?}", self.verifier_strength),
        );
        push_field(
            &mut p,
            "specialist_discoverability",
            &format!("{:?}", self.specialist_discoverability),
        );
        push_field(&mut p, "horizon", &format!("{:?}", self.horizon));
        push_field(&mut p, "uncertainty", &format!("{:?}", self.uncertainty));
        push_field(&mut p, "risk", &format!("{:?}", self.risk));
        freeze(&p)
    }
}

#[must_use]
pub fn select_protocol(features: InquirySelectionFeatures) -> InquiryProtocol {
    if features.shared_mutable_state || features.risk >= InquiryRisk::High {
        InquiryProtocol::CausalDiagnosis
    } else if features.horizon == InquiryHorizon::Strategic
        || (features.sequential_dependency && features.branch_independence)
    {
        InquiryProtocol::ArchitectureDecision
    } else if features.specialist_discoverability == SpecialistDiscoverability::High
        && features.branch_independence
    {
        InquiryProtocol::AlgorithmSearch
    } else if features.verifier_strength == VerifierStrength::Strong
        && features.uncertainty == InquiryUncertainty::High
    {
        InquiryProtocol::FormalProof
    } else if features.uncertainty == InquiryUncertainty::High {
        InquiryProtocol::EvidenceReview
    } else {
        InquiryProtocol::Lookup
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndependenceBlindingPolicy {
    pub independence_dimensions: Vec<String>,
    pub minimum_independent_families: u64,
    pub blinded_fields: Vec<String>,
    pub shared_assumptions: Vec<String>,
    pub allowed_deviations: Vec<String>,
}

impl Default for IndependenceBlindingPolicy {
    fn default() -> Self {
        Self {
            independence_dimensions: vec!["source_family".to_owned()],
            minimum_independent_families: 1,
            blinded_fields: Vec::new(),
            shared_assumptions: Vec::new(),
            allowed_deviations: Vec::new(),
        }
    }
}

impl IndependenceBlindingPolicy {
    fn validate(&self) -> Result<(), InquiryGovernanceError> {
        unique_texts(
            &self.independence_dimensions,
            "profile.independence_dimensions",
        )?;
        if self.minimum_independent_families == 0 {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.minimum_independent_families",
            });
        }
        unique_texts(&self.blinded_fields, "profile.blinded_fields")?;
        unique_texts(&self.shared_assumptions, "profile.shared_assumptions")?;
        unique_texts(&self.allowed_deviations, "profile.allowed_deviations")
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let mut p = String::from("independence-blinding-policy/v1;");
        push_count(&mut p, "dimensions", self.independence_dimensions.len());
        for value in &self.independence_dimensions {
            push_field(&mut p, "dimension", value);
        }
        push_field(
            &mut p,
            "minimum_independent_families",
            &self.minimum_independent_families.to_string(),
        );
        for value in &self.blinded_fields {
            push_field(&mut p, "blinded_field", value);
        }
        for value in &self.shared_assumptions {
            push_field(&mut p, "shared_assumption", value);
        }
        for value in &self.allowed_deviations {
            push_field(&mut p, "allowed_deviation", value);
        }
        freeze(&p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetDeadlineStopRule {
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub stop_rule: String,
    pub cancellation_identity: String,
}

impl BudgetDeadlineStopRule {
    fn validate(&self) -> Result<(), InquiryGovernanceError> {
        if self.budget_units == 0 {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.budget_units",
            });
        }
        if self.deadline_ms <= 0 {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.deadline_ms",
            });
        }
        text(&self.stop_rule, "profile.stop_rule")?;
        text(&self.cancellation_identity, "profile.cancellation_identity")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputContractAndReopenConditions {
    pub output_contract: String,
    pub reopen_conditions: Vec<String>,
}

impl OutputContractAndReopenConditions {
    fn validate(&self) -> Result<(), InquiryGovernanceError> {
        text(&self.output_contract, "profile.output_contract")?;
        if self.reopen_conditions.is_empty() {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.reopen_conditions",
            });
        }
        unique_texts(&self.reopen_conditions, "profile.reopen_conditions")
    }
}

/// Full constructor input for a profile resolution/revision.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InquiryProtocolProfileParams {
    pub profile_id: String,
    pub task_id: TaskId,
    pub question: String,
    pub intended_decision_or_artifact: String,
    pub scope: String,
    pub protocol: Option<InquiryProtocol>,
    pub features: InquirySelectionFeatures,
    pub evidence_grade: EvidenceGrade,
    pub lane: InquiryLane,
    pub truth_surfaces_and_admissible_providers: Vec<String>,
    pub admissible_source_classes: Vec<SourceClass>,
    pub allowed_uses: Vec<String>,
    pub reference_manifest_digest: String,
    pub coverage_goal: CoverageGoal,
    pub hypothesis_policy: HypothesisPolicy,
    pub independence_and_blinding_policy: IndependenceBlindingPolicy,
    pub fidelity_ceiling: String,
    pub budget_and_deadline_and_stop_rule: BudgetDeadlineStopRule,
    pub output_contract_and_reopen_conditions: OutputContractAndReopenConditions,
    pub task_definition_digest: String,
    pub state_fence: StateFence,
    pub disclosure_ceiling: DisclosureClass,
    pub change_reason: String,
}

/// Immutable profile revision selected by Researcher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InquiryProtocolProfile {
    pub profile_id: String,
    pub task_id: TaskId,
    pub revision: u64,
    pub question: String,
    pub intended_decision_or_artifact: String,
    pub scope: String,
    pub protocol: InquiryProtocol,
    pub selection_features_digest: String,
    pub evidence_grade: EvidenceGrade,
    pub lane: InquiryLane,
    pub truth_surfaces_and_admissible_providers: Vec<String>,
    pub admissible_source_classes: Vec<SourceClass>,
    pub allowed_uses: Vec<String>,
    pub reference_manifest_digest: String,
    pub coverage_goal: CoverageGoal,
    pub hypothesis_policy: HypothesisPolicy,
    pub independence_and_blinding_policy: IndependenceBlindingPolicy,
    pub independence_and_blinding_policy_digest: String,
    pub fidelity_ceiling: String,
    pub budget_and_deadline_and_stop_rule: BudgetDeadlineStopRule,
    pub output_contract_and_reopen_conditions: OutputContractAndReopenConditions,
    pub task_definition_digest: String,
    pub state_fence: StateFence,
    pub disclosure_ceiling: DisclosureClass,
    pub change_reason: String,
    pub supersedes_digest: Option<String>,
    /// Digest over the complete profile shape, including the fence and task
    /// identity. This catches public-field mutation before a receipt is used.
    pub integrity_digest: String,
    pub digest: String,
}

impl InquiryProtocolProfile {
    pub fn resolve(params: InquiryProtocolProfileParams) -> Result<Self, InquiryGovernanceError> {
        Self::build(params, 1, None)
    }

    pub fn revise(
        previous: &Self,
        params: InquiryProtocolProfileParams,
    ) -> Result<Self, InquiryGovernanceError> {
        if params.profile_id != previous.profile_id || params.task_id != previous.task_id {
            return Err(InquiryGovernanceError::RevisionConflict {
                profile_id: params.profile_id,
                revision: previous.revision.saturating_add(1),
            });
        }
        text(&params.change_reason, "profile.change_reason")?;
        let revision =
            previous
                .revision
                .checked_add(1)
                .ok_or(InquiryGovernanceError::InvalidField {
                    field: "profile.revision",
                })?;
        let next = Self::build(params, revision, Some(previous.digest.clone()))?;
        if next.same_governed_shape(previous) {
            return Err(InquiryGovernanceError::EmptyRevision {
                profile_id: previous.profile_id.clone(),
            });
        }
        Ok(next)
    }

    #[must_use]
    pub fn profile_id_and_revision(&self) -> String {
        format!("{}@{}", self.profile_id, self.revision)
    }

    #[must_use]
    pub fn matches_binding(&self, task_definition_digest: &str, fence: &StateFence) -> bool {
        self.task_definition_digest == task_definition_digest
            && self.state_fence == *fence
            && self.state_fence.validate().is_ok()
            && self.validate_integrity().is_ok()
    }

    fn compute_integrity_digest(&self) -> Result<String, InquiryGovernanceError> {
        let shape = (
            (
                &self.profile_id,
                &self.task_id,
                &self.revision,
                &self.question,
                &self.intended_decision_or_artifact,
                &self.scope,
                &self.protocol,
                &self.selection_features_digest,
            ),
            (
                &self.evidence_grade,
                &self.lane,
                &self.truth_surfaces_and_admissible_providers,
                &self.admissible_source_classes,
                &self.allowed_uses,
                &self.reference_manifest_digest,
                &self.coverage_goal,
                &self.hypothesis_policy,
                &self.independence_and_blinding_policy,
            ),
            (
                &self.independence_and_blinding_policy_digest,
                &self.fidelity_ceiling,
                &self.budget_and_deadline_and_stop_rule,
                &self.output_contract_and_reopen_conditions,
                &self.task_definition_digest,
                &self.state_fence,
                &self.disclosure_ceiling,
                &self.change_reason,
            ),
            &self.supersedes_digest,
        );
        let bytes =
            canonical_json_bytes(&shape).map_err(|_| InquiryGovernanceError::InvalidField {
                field: "profile.integrity_digest",
            })?;
        Ok(sha256_hex(&bytes))
    }

    /// Revalidates the complete profile shape before a binding is consumed.
    pub fn validate_integrity(&self) -> Result<(), InquiryGovernanceError> {
        if self.integrity_digest != self.compute_integrity_digest()?
            || self.digest != self.integrity_digest
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "profile.integrity_digest",
            });
        }
        Ok(())
    }

    /// Checks the complete task identity binding used by the Task Controller
    /// compilation seam. The digest-only helper remains for compatibility with
    /// the existing profile projection, but all production paths use this
    /// method before compiling or assessing material.
    #[must_use]
    pub fn matches_task_binding(
        &self,
        task_id: &TaskId,
        task_definition_digest: &str,
        fence: &StateFence,
    ) -> bool {
        self.task_id == *task_id && self.matches_binding(task_definition_digest, fence)
    }

    #[must_use]
    pub fn governor_admission_request(&self) -> GovernorProfileAdmissionRequest {
        GovernorProfileAdmissionRequest {
            profile_id: self.profile_id.clone(),
            task_id: self.task_id.clone(),
            profile_revision: self.revision,
            profile_digest: self.digest.clone(),
            profile_integrity_digest: self.integrity_digest.clone(),
            reference_manifest_digest: self.reference_manifest_digest.clone(),
            task_definition_digest: self.task_definition_digest.clone(),
            state_fence: self.state_fence.clone(),
            budget_units: self.budget_and_deadline_and_stop_rule.budget_units,
            deadline_ms: self.budget_and_deadline_and_stop_rule.deadline_ms,
            request_type: "admit_resolved_inquiry_profile".to_owned(),
            canonical_write_authorized: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn build(
        mut params: InquiryProtocolProfileParams,
        revision: u64,
        supersedes_digest: Option<String>,
    ) -> Result<Self, InquiryGovernanceError> {
        if revision == 0 {
            return Err(InquiryGovernanceError::InvalidField {
                field: "profile.revision",
            });
        }
        text(&params.profile_id, "profile.profile_id")?;
        text(params.task_id.as_str(), "profile.task_id")?;
        text(&params.question, "profile.question")?;
        text(
            &params.intended_decision_or_artifact,
            "profile.intended_decision_or_artifact",
        )?;
        text(&params.scope, "profile.scope")?;
        text(&params.fidelity_ceiling, "profile.fidelity_ceiling")?;
        params.evidence_grade.validate_canonical()?;
        digest(
            &params.task_definition_digest,
            "profile.task_definition_digest",
        )?;
        if params.change_reason.trim().is_empty() {
            params.change_reason = String::from("initial");
        }
        text(&params.change_reason, "profile.change_reason")?;
        params
            .state_fence
            .validate()
            .map_err(|_| InquiryGovernanceError::InvalidField {
                field: "profile.state_fence",
            })?;
        if params.truth_surfaces_and_admissible_providers.is_empty() {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.truth_surfaces_and_admissible_providers",
            });
        }
        if params.admissible_source_classes.is_empty() {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.admissible_source_classes",
            });
        }
        if params.allowed_uses.is_empty() {
            return Err(InquiryGovernanceError::Blank {
                field: "profile.allowed_uses",
            });
        }
        digest(
            &params.reference_manifest_digest,
            "profile.reference_manifest_digest",
        )?;
        params.truth_surfaces_and_admissible_providers.sort();
        params
            .admissible_source_classes
            .sort_by_key(|class| format!("{class:?}"));
        params.allowed_uses.sort();
        unique_texts(
            &params.truth_surfaces_and_admissible_providers,
            "profile.truth_surfaces_and_admissible_providers",
        )?;
        params.independence_and_blinding_policy.validate()?;
        params.budget_and_deadline_and_stop_rule.validate()?;
        params.output_contract_and_reopen_conditions.validate()?;
        if let Some(previous) = &supersedes_digest {
            digest(previous, "profile.supersedes_digest")?;
        }
        let protocol = params
            .protocol
            .unwrap_or_else(|| select_protocol(params.features));
        let selection_features_digest = params.features.digest();
        let independence_and_blinding_policy_digest =
            params.independence_and_blinding_policy.digest();
        let fence_digest =
            sha256_hex(&canonical_json_bytes(&params.state_fence).map_err(|_| {
                InquiryGovernanceError::InvalidField {
                    field: "profile.state_fence",
                }
            })?);
        let mut p = String::from("inquiry-protocol-profile/v1;");
        push_field(&mut p, "contract", INQUIRY_GOVERNANCE_CONTRACT);
        push_field(&mut p, "version", INQUIRY_GOVERNANCE_VERSION);
        push_field(&mut p, "profile_id", &params.profile_id);
        push_field(&mut p, "task_id", params.task_id.as_str());
        push_field(&mut p, "revision", &revision.to_string());
        push_field(&mut p, "question", &params.question);
        push_field(
            &mut p,
            "intended_decision_or_artifact",
            &params.intended_decision_or_artifact,
        );
        push_field(&mut p, "scope", &params.scope);
        push_field(&mut p, "protocol", protocol.wire_name());
        push_field(
            &mut p,
            "selection_features_digest",
            &selection_features_digest,
        );
        push_field(&mut p, "evidence_grade", params.evidence_grade.wire_name());
        push_field(&mut p, "lane", params.lane.wire_name());
        push_count(
            &mut p,
            "providers",
            params.truth_surfaces_and_admissible_providers.len(),
        );
        for provider in &params.truth_surfaces_and_admissible_providers {
            push_field(&mut p, "provider", provider);
        }
        push_count(
            &mut p,
            "source_classes",
            params.admissible_source_classes.len(),
        );
        for class in &params.admissible_source_classes {
            push_field(&mut p, "source_class", &format!("{class:?}"));
        }
        push_count(&mut p, "allowed_uses", params.allowed_uses.len());
        for allowed_use in &params.allowed_uses {
            push_field(&mut p, "allowed_use", allowed_use);
        }
        push_field(
            &mut p,
            "reference_manifest_digest",
            &params.reference_manifest_digest,
        );
        push_field(&mut p, "coverage_goal", params.coverage_goal.wire_name());
        push_field(
            &mut p,
            "hypothesis_policy",
            params.hypothesis_policy.wire_name(),
        );
        push_field(
            &mut p,
            "independence_policy_digest",
            &independence_and_blinding_policy_digest,
        );
        push_field(&mut p, "fidelity_ceiling", &params.fidelity_ceiling);
        push_field(
            &mut p,
            "budget_units",
            &params
                .budget_and_deadline_and_stop_rule
                .budget_units
                .to_string(),
        );
        push_field(
            &mut p,
            "deadline_ms",
            &params
                .budget_and_deadline_and_stop_rule
                .deadline_ms
                .to_string(),
        );
        push_field(
            &mut p,
            "stop_rule",
            &params.budget_and_deadline_and_stop_rule.stop_rule,
        );
        push_field(
            &mut p,
            "cancellation_identity",
            &params
                .budget_and_deadline_and_stop_rule
                .cancellation_identity,
        );
        push_field(
            &mut p,
            "output_contract",
            &params.output_contract_and_reopen_conditions.output_contract,
        );
        push_count(
            &mut p,
            "reopen_conditions",
            params
                .output_contract_and_reopen_conditions
                .reopen_conditions
                .len(),
        );
        for condition in &params
            .output_contract_and_reopen_conditions
            .reopen_conditions
        {
            push_field(&mut p, "reopen_condition", condition);
        }
        push_field(
            &mut p,
            "task_definition_digest",
            &params.task_definition_digest,
        );
        push_field(&mut p, "state_fence_digest", &fence_digest);
        push_field(
            &mut p,
            "disclosure_ceiling",
            &format!("{:?}", params.disclosure_ceiling),
        );
        push_field(&mut p, "change_reason", &params.change_reason);
        if let Some(previous) = &supersedes_digest {
            push_field(&mut p, "supersedes_digest", previous);
        }
        let _legacy_preimage_digest = freeze(&p);
        let mut profile = Self {
            profile_id: params.profile_id,
            task_id: params.task_id,
            revision,
            question: params.question,
            intended_decision_or_artifact: params.intended_decision_or_artifact,
            scope: params.scope,
            protocol,
            selection_features_digest,
            evidence_grade: params.evidence_grade,
            lane: params.lane,
            truth_surfaces_and_admissible_providers: params.truth_surfaces_and_admissible_providers,
            admissible_source_classes: params.admissible_source_classes,
            allowed_uses: params.allowed_uses,
            reference_manifest_digest: params.reference_manifest_digest,
            coverage_goal: params.coverage_goal,
            hypothesis_policy: params.hypothesis_policy,
            independence_and_blinding_policy: params.independence_and_blinding_policy,
            independence_and_blinding_policy_digest,
            fidelity_ceiling: params.fidelity_ceiling,
            budget_and_deadline_and_stop_rule: params.budget_and_deadline_and_stop_rule,
            output_contract_and_reopen_conditions: params.output_contract_and_reopen_conditions,
            task_definition_digest: params.task_definition_digest,
            state_fence: params.state_fence,
            disclosure_ceiling: params.disclosure_ceiling,
            change_reason: params.change_reason,
            supersedes_digest,
            integrity_digest: String::new(),
            digest: String::new(),
        };
        profile.integrity_digest = profile.compute_integrity_digest()?;
        profile.digest = profile.integrity_digest.clone();
        Ok(profile)
    }

    fn same_governed_shape(&self, other: &Self) -> bool {
        self.profile_id == other.profile_id
            && self.task_id == other.task_id
            && self.question == other.question
            && self.intended_decision_or_artifact == other.intended_decision_or_artifact
            && self.scope == other.scope
            && self.protocol == other.protocol
            && self.selection_features_digest == other.selection_features_digest
            && self.evidence_grade == other.evidence_grade
            && self.lane == other.lane
            && self.truth_surfaces_and_admissible_providers
                == other.truth_surfaces_and_admissible_providers
            && self.admissible_source_classes == other.admissible_source_classes
            && self.allowed_uses == other.allowed_uses
            && self.reference_manifest_digest == other.reference_manifest_digest
            && self.coverage_goal == other.coverage_goal
            && self.hypothesis_policy == other.hypothesis_policy
            && self.independence_and_blinding_policy_digest
                == other.independence_and_blinding_policy_digest
            && self.fidelity_ceiling == other.fidelity_ceiling
            && self.budget_and_deadline_and_stop_rule == other.budget_and_deadline_and_stop_rule
            && self.output_contract_and_reopen_conditions
                == other.output_contract_and_reopen_conditions
            && self.task_definition_digest == other.task_definition_digest
            && self.state_fence == other.state_fence
            && self.disclosure_ceiling == other.disclosure_ceiling
    }
}

/// Governor-addressed request; it is not an admission or canonical receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernorProfileAdmissionRequest {
    pub profile_id: String,
    pub task_id: TaskId,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub profile_integrity_digest: String,
    pub reference_manifest_digest: String,
    pub task_definition_digest: String,
    pub state_fence: StateFence,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub request_type: String,
    pub canonical_write_authorized: bool,
}

/// Runtime-local profile/obligation/source registry. It owns no canonical
/// storage and creates no second work graph.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InquiryGovernance {
    profiles: BTreeMap<(String, u64), InquiryProtocolProfile>,
    latest_revision: BTreeMap<String, u64>,
    obligations: BTreeMap<(String, u64), Vec<InquiryObligation>>,
    sources: BTreeMap<(String, String, u64, String), SourceAdmissibilityRecord>,
}

impl InquiryGovernance {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve_profile(
        &mut self,
        params: InquiryProtocolProfileParams,
    ) -> Result<InquiryProtocolProfile, InquiryGovernanceError> {
        if self.latest_revision.contains_key(&params.profile_id) {
            return Err(InquiryGovernanceError::RevisionConflict {
                profile_id: params.profile_id,
                revision: 1,
            });
        }
        let profile = InquiryProtocolProfile::resolve(params)?;
        self.profiles.insert(
            (profile.profile_id.clone(), profile.revision),
            profile.clone(),
        );
        self.latest_revision
            .insert(profile.profile_id.clone(), profile.revision);
        Ok(profile)
    }

    pub fn revise_profile(
        &mut self,
        profile_id: &str,
        params: InquiryProtocolProfileParams,
    ) -> Result<InquiryProtocolProfile, InquiryGovernanceError> {
        let revision = self
            .latest_revision
            .get(profile_id)
            .copied()
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: 0,
            })?;
        let previous = self.profile(profile_id, revision).cloned().ok_or_else(|| {
            InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision,
            }
        })?;
        let next = InquiryProtocolProfile::revise(&previous, params)?;
        self.profiles
            .insert((next.profile_id.clone(), next.revision), next.clone());
        self.latest_revision
            .insert(next.profile_id.clone(), next.revision);
        Ok(next)
    }

    #[must_use]
    pub fn profile(&self, profile_id: &str, revision: u64) -> Option<&InquiryProtocolProfile> {
        self.profiles.get(&(profile_id.to_owned(), revision))
    }

    #[must_use]
    pub fn latest_profile(&self, profile_id: &str) -> Option<&InquiryProtocolProfile> {
        self.latest_revision
            .get(profile_id)
            .and_then(|revision| self.profile(profile_id, *revision))
    }

    #[must_use]
    pub fn profile_history(&self, profile_id: &str) -> Vec<&InquiryProtocolProfile> {
        self.profiles
            .iter()
            .filter(|((id, _), _)| id == profile_id)
            .map(|(_, profile)| profile)
            .collect()
    }

    pub fn compile_obligations(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        task_owner: &TaskLifecycleOwner,
    ) -> Result<TaskGraphCompilationReceipt, InquiryGovernanceError> {
        let profile = self
            .profile(profile_id, profile_revision)
            .cloned()
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?;
        profile.validate_integrity()?;
        let obligations = compile_obligation_inputs(&profile, inputs)?;
        let request = task_graph_request(&profile, &obligations, &profile.task_id)?;
        let receipt = task_owner
            .compile_inquiry_obligations(request.clone())
            .map_err(|error| InquiryGovernanceError::TaskOwnerRejected { error })?;
        receipt
            .validate_against(&request)
            .map_err(|error| InquiryGovernanceError::TaskOwnerRejected { error })?;
        self.obligations
            .insert((profile_id.to_owned(), profile_revision), obligations);
        Ok(receipt)
    }

    #[must_use]
    pub fn obligations(
        &self,
        profile_id: &str,
        profile_revision: u64,
    ) -> Option<&[InquiryObligation]> {
        self.obligations
            .get(&(profile_id.to_owned(), profile_revision))
            .map(Vec::as_slice)
    }

    pub fn assess_source(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        evidence_set_id: &str,
        proposal: &SourceProposal,
    ) -> Result<SourceAdmissibilityRecord, InquiryGovernanceError> {
        let profile = self
            .profile(profile_id, profile_revision)
            .cloned()
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?;
        profile.validate_integrity()?;
        let record = SourceAdmissibilityRecord::evaluate(&profile, evidence_set_id, proposal)?;
        let key = (
            evidence_set_id.to_owned(),
            profile_id.to_owned(),
            profile_revision,
            proposal.provenance.source_handle.clone(),
        );
        if let Some(previous) = self.sources.get(&key)
            && previous != &record
        {
            return Err(InquiryGovernanceError::SourceIdentityConflict {
                source_handle: proposal.provenance.source_handle.clone(),
            });
        }
        self.sources.insert(key, record.clone());
        Ok(record)
    }

    #[must_use]
    pub fn source_record(
        &self,
        profile_id: &str,
        profile_revision: u64,
        evidence_set_id: &str,
        source_handle: &str,
    ) -> Option<&SourceAdmissibilityRecord> {
        self.sources.get(&(
            evidence_set_id.to_owned(),
            profile_id.to_owned(),
            profile_revision,
            source_handle.to_owned(),
        ))
    }
}

/// Terminal inquiry outcomes from I21.9. Only the first two may close an
/// inquiry; every other value carries an explicit continuation field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InquiryDisposition {
    AnsweredWithSupportedResult,
    NoMatchInCompleteScope,
    NoNewUsefulEvidence,
    SourceUnavailable,
    StaleSourceOrIndex,
    PolicyOrDisclosureDenied,
    IncompleteCoverage,
    Inconclusive,
    Cancelled,
}

impl InquiryDisposition {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AnsweredWithSupportedResult => "ANSWERED_WITH_SUPPORTED_RESULT",
            Self::NoMatchInCompleteScope => "NO_MATCH_IN_COMPLETE_SCOPE",
            Self::NoNewUsefulEvidence => "NO_NEW_USEFUL_EVIDENCE",
            Self::SourceUnavailable => "SOURCE_UNAVAILABLE",
            Self::StaleSourceOrIndex => "STALE_SOURCE_OR_INDEX",
            Self::PolicyOrDisclosureDenied => "POLICY_OR_DISCLOSURE_DENIED",
            Self::IncompleteCoverage => "INCOMPLETE_COVERAGE",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::Cancelled => "CANCELLED",
        }
    }

    #[must_use]
    pub const fn may_close(self) -> bool {
        matches!(
            self,
            Self::AnsweredWithSupportedResult | Self::NoMatchInCompleteScope
        )
    }
}

/// A typed, candidate-only inquiry disposition bound to every prerequisite
/// that would otherwise be lost in a free-form result string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InquiryDispositionRecord {
    pub inquiry_id: String,
    pub task_id: TaskId,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub evidence_set_id: String,
    pub portfolio_digest: Option<String>,
    pub manifest_digest: Option<String>,
    pub coverage_receipt_digest: Option<String>,
    pub state_fence: StateFence,
    pub disposition: InquiryDisposition,
    pub next_probe: Option<String>,
    pub narrower_claim: Option<String>,
    pub explicit_unknown: Option<String>,
    pub digest: String,
}

impl InquiryDispositionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        inquiry_id: impl Into<String>,
        profile: &InquiryProtocolProfile,
        evidence_set_id: impl Into<String>,
        portfolio_digest: Option<String>,
        manifest_digest: Option<String>,
        coverage_receipt_digest: Option<String>,
        disposition: InquiryDisposition,
        next_probe: Option<String>,
        narrower_claim: Option<String>,
        explicit_unknown: Option<String>,
    ) -> Result<Self, InquiryGovernanceError> {
        let inquiry_id = inquiry_id.into();
        let evidence_set_id = evidence_set_id.into();
        text(&inquiry_id, "disposition.inquiry_id")?;
        text(&evidence_set_id, "disposition.evidence_set_id")?;
        if let Some(portfolio_digest) = &portfolio_digest {
            digest(portfolio_digest, "disposition.portfolio_digest")?;
        }
        if let Some(manifest_digest) = &manifest_digest {
            digest(manifest_digest, "disposition.manifest_digest")?;
        }
        if let Some(receipt) = &coverage_receipt_digest {
            digest(receipt, "disposition.coverage_receipt_digest")?;
        }
        if disposition.may_close()
            && (portfolio_digest.is_none()
                || manifest_digest.is_none()
                || coverage_receipt_digest.is_none())
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "disposition.coverage_receipt_digest",
            });
        }
        if !disposition.may_close()
            && next_probe.is_none()
            && narrower_claim.is_none()
            && explicit_unknown.is_none()
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "disposition.reopen_condition",
            });
        }
        for value in [&next_probe, &narrower_claim, &explicit_unknown]
            .into_iter()
            .flatten()
        {
            text(value, "disposition.reopen_condition")?;
        }
        if !profile.matches_binding(&profile.task_definition_digest, &profile.state_fence) {
            return Err(InquiryGovernanceError::InvalidField {
                field: "disposition.profile_binding",
            });
        }
        let mut p = String::from("inquiry-disposition/v1;");
        push_field(&mut p, "inquiry_id", &inquiry_id);
        push_field(&mut p, "task_id", profile.task_id.as_str());
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_field(&mut p, "evidence_set_id", &evidence_set_id);
        if let Some(portfolio_digest) = &portfolio_digest {
            push_field(&mut p, "portfolio_digest", portfolio_digest);
        }
        if let Some(manifest_digest) = &manifest_digest {
            push_field(&mut p, "manifest_digest", manifest_digest);
        }
        if let Some(receipt) = &coverage_receipt_digest {
            push_field(&mut p, "coverage_receipt_digest", receipt);
        }
        push_field(
            &mut p,
            "state_fence_digest",
            &fence_digest(&profile.state_fence)?,
        );
        push_field(&mut p, "disposition", disposition.wire_name());
        for (tag, value) in [
            ("next_probe", next_probe.as_deref()),
            ("narrower_claim", narrower_claim.as_deref()),
            ("explicit_unknown", explicit_unknown.as_deref()),
        ] {
            if let Some(value) = value {
                push_field(&mut p, tag, value);
            }
        }
        let digest = freeze(&p);
        Ok(Self {
            inquiry_id,
            task_id: profile.task_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            evidence_set_id,
            portfolio_digest,
            manifest_digest,
            coverage_receipt_digest,
            state_fence: profile.state_fence.clone(),
            disposition,
            next_probe,
            narrower_claim,
            explicit_unknown,
            digest,
        })
    }
}

fn fence_digest(fence: &StateFence) -> Result<String, InquiryGovernanceError> {
    let bytes = canonical_json_bytes(fence).map_err(|_| InquiryGovernanceError::InvalidField {
        field: "state_fence",
    })?;
    Ok(sha256_hex(&bytes))
}

/// Evidence freeze projection. It records the exact accepted evidence shape
/// before any synthesis candidate is created; it does not freeze mutable state
/// or grant synthesis authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFreeze {
    pub freeze_id: String,
    pub task_id: TaskId,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub portfolio_digest: String,
    pub manifest_digest: String,
    pub coverage_receipt_digest: String,
    pub state_fence: StateFence,
    pub included_evidence_refs: Vec<String>,
    pub excluded_evidence: Vec<String>,
    pub unresolved_contradictions: Vec<String>,
    pub open_research_debts: Vec<String>,
    pub frozen_at_ms: i64,
    pub digest: String,
}

impl EvidenceFreeze {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        freeze_id: impl Into<String>,
        profile: &InquiryProtocolProfile,
        portfolio_digest: impl Into<String>,
        manifest_digest: impl Into<String>,
        coverage_receipt_digest: impl Into<String>,
        included_evidence_refs: Vec<String>,
        excluded_evidence: Vec<String>,
        unresolved_contradictions: Vec<String>,
        open_research_debts: Vec<String>,
        frozen_at_ms: i64,
    ) -> Result<Self, InquiryGovernanceError> {
        let freeze_id = freeze_id.into();
        let portfolio_digest = portfolio_digest.into();
        let manifest_digest = manifest_digest.into();
        let coverage_receipt_digest = coverage_receipt_digest.into();
        text(&freeze_id, "freeze.freeze_id")?;
        digest(&portfolio_digest, "freeze.portfolio_digest")?;
        digest(&manifest_digest, "freeze.manifest_digest")?;
        digest(&coverage_receipt_digest, "freeze.coverage_receipt_digest")?;
        if included_evidence_refs.is_empty() || frozen_at_ms <= 0 {
            return Err(InquiryGovernanceError::InvalidField {
                field: "freeze.evidence",
            });
        }
        unique_texts(&included_evidence_refs, "freeze.included_evidence_refs")?;
        unique_texts(&excluded_evidence, "freeze.excluded_evidence")?;
        unique_texts(
            &unresolved_contradictions,
            "freeze.unresolved_contradictions",
        )?;
        unique_texts(&open_research_debts, "freeze.open_research_debts")?;
        let mut p = String::from("evidence-freeze/v1;");
        push_field(&mut p, "freeze_id", &freeze_id);
        push_field(&mut p, "task_id", profile.task_id.as_str());
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_field(&mut p, "portfolio_digest", &portfolio_digest);
        push_field(&mut p, "manifest_digest", &manifest_digest);
        push_field(&mut p, "coverage_receipt_digest", &coverage_receipt_digest);
        push_field(
            &mut p,
            "state_fence_digest",
            &fence_digest(&profile.state_fence)?,
        );
        push_count(&mut p, "included", included_evidence_refs.len());
        for value in &included_evidence_refs {
            push_field(&mut p, "included", value);
        }
        for (tag, values) in [
            ("excluded", &excluded_evidence),
            ("contradiction", &unresolved_contradictions),
            ("debt", &open_research_debts),
        ] {
            push_count(&mut p, tag, values.len());
            for value in values {
                push_field(&mut p, tag, value);
            }
        }
        push_field(&mut p, "frozen_at_ms", &frozen_at_ms.to_string());
        let digest = freeze(&p);
        Ok(Self {
            freeze_id,
            task_id: profile.task_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            portfolio_digest,
            manifest_digest,
            coverage_receipt_digest,
            state_fence: profile.state_fence.clone(),
            included_evidence_refs,
            excluded_evidence,
            unresolved_contradictions,
            open_research_debts,
            frozen_at_ms,
            digest,
        })
    }
}

/// Typed research debt categories from I21.12.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResearchDebtKind {
    Epistemic,
    Verification,
    Replication,
    Coverage,
    Contradiction,
    Fidelity,
    Provenance,
    Authority,
}

impl ResearchDebtKind {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Epistemic => "epistemic",
            Self::Verification => "verification",
            Self::Replication => "replication",
            Self::Coverage => "coverage",
            Self::Contradiction => "contradiction",
            Self::Fidelity => "fidelity",
            Self::Provenance => "provenance",
            Self::Authority => "authority",
        }
    }
}

/// A governed debt record; a debt is never collapsed into a caveat string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResearchDebt {
    pub debt_id: String,
    pub kind: ResearchDebtKind,
    pub summary: String,
    pub owner: String,
    pub review_condition: String,
    pub expires_at_ms: Option<i64>,
    pub blocks_closure: bool,
    pub digest: String,
}

impl ResearchDebt {
    pub fn new(
        debt_id: impl Into<String>,
        kind: ResearchDebtKind,
        summary: impl Into<String>,
        owner: impl Into<String>,
        review_condition: impl Into<String>,
        expires_at_ms: Option<i64>,
    ) -> Result<Self, InquiryGovernanceError> {
        let debt_id = debt_id.into();
        let summary = summary.into();
        let owner = owner.into();
        let review_condition = review_condition.into();
        text(&debt_id, "debt.debt_id")?;
        text(&summary, "debt.summary")?;
        text(&owner, "debt.owner")?;
        text(&review_condition, "debt.review_condition")?;
        if expires_at_ms.is_some_and(|value| value <= 0) {
            return Err(InquiryGovernanceError::InvalidField {
                field: "debt.expires_at_ms",
            });
        }
        let mut p = String::from("research-debt/v1;");
        push_field(&mut p, "debt_id", &debt_id);
        push_field(&mut p, "kind", kind.wire_name());
        push_field(&mut p, "summary", &summary);
        push_field(&mut p, "owner", &owner);
        push_field(&mut p, "review_condition", &review_condition);
        if let Some(value) = expires_at_ms {
            push_field(&mut p, "expires_at_ms", &value.to_string());
        }
        let digest = freeze(&p);
        Ok(Self {
            debt_id,
            kind,
            summary,
            owner,
            review_condition,
            expires_at_ms,
            blocks_closure: true,
            digest,
        })
    }
}

/// Claim-audit adapter that preserves the Researcher verdict and the canonical
/// epistemic audit outcome without defining a second claim vocabulary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAudit {
    pub claim_id: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub manifest_digest: String,
    pub portfolio_verdict: crate::evidence_portfolio::ClaimVerdict,
    pub canonical_outcome: ClaimAuditOutcome,
    pub state_fence: StateFence,
    pub digest: String,
}

impl ClaimAudit {
    pub fn from_portfolio_verdict(
        profile: &InquiryProtocolProfile,
        manifest_digest: impl Into<String>,
        verdict: crate::evidence_portfolio::ClaimVerdict,
    ) -> Result<Self, InquiryGovernanceError> {
        let manifest_digest = manifest_digest.into();
        digest(&manifest_digest, "claim_audit.manifest_digest")?;
        let canonical_outcome = match verdict.outcome {
            crate::evidence_portfolio::ClaimOutcome::Supported => ClaimAuditOutcome::Supported,
            crate::evidence_portfolio::ClaimOutcome::PartiallySupported => {
                ClaimAuditOutcome::PartiallySupported
            }
            crate::evidence_portfolio::ClaimOutcome::Unsupported => ClaimAuditOutcome::Unsupported,
            crate::evidence_portfolio::ClaimOutcome::Contradicted => {
                ClaimAuditOutcome::Contradicted
            }
            crate::evidence_portfolio::ClaimOutcome::OutsideManifest
            | crate::evidence_portfolio::ClaimOutcome::StaleLimited
            | crate::evidence_portfolio::ClaimOutcome::IncompleteAccounting => {
                ClaimAuditOutcome::NotVerifiableInScope
            }
        };
        let mut p = String::from("claim-audit/v1;");
        push_field(&mut p, "claim_id", &verdict.claim_id);
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_field(&mut p, "manifest_digest", &manifest_digest);
        push_field(
            &mut p,
            "canonical_outcome",
            &format!("{canonical_outcome:?}"),
        );
        push_field(
            &mut p,
            "state_fence_digest",
            &fence_digest(&profile.state_fence)?,
        );
        let digest = freeze(&p);
        Ok(Self {
            claim_id: verdict.claim_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            manifest_digest,
            portfolio_verdict: verdict,
            canonical_outcome,
            state_fence: profile.state_fence.clone(),
            digest,
        })
    }
}
