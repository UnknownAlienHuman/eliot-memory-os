//! Versioned R6 Researcher inquiry-profile resolution and governance state.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

use eliot_contracts::{StateFence, sha256_hex};
use eliot_research_exchange_api::{DisclosureClass, SourceClass};

use super::inquiry_obligations::{
    InquiryObligation, InquiryObligationInput, TaskGraphCompilationReceipt, TaskGraphCompiler,
    compile_obligation_inputs,
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
    CompilerRejected {
        compiler_id: String,
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
            Self::CompilerRejected { compiler_id } => {
                write!(
                    f,
                    "TaskGraphCompiler {compiler_id} rejected inquiry obligations"
                )
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifierStrength {
    None,
    Limited,
    Strong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpecialistDiscoverability {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InquiryHorizon {
    Immediate,
    Extended,
    Strategic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InquiryUncertainty {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InquiryRisk {
    Low,
    Medium,
    High,
    Critical,
}

/// Feature inputs used by protocol selection. These are deliberately not
/// task vocabulary, matching I21.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, PartialEq, Eq)]
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
#[derive(Clone, Debug)]
pub struct InquiryProtocolProfileParams {
    pub profile_id: String,
    pub question: String,
    pub intended_decision_or_artifact: String,
    pub scope: String,
    pub protocol: Option<InquiryProtocol>,
    pub features: InquirySelectionFeatures,
    pub evidence_grade: EvidenceGrade,
    pub lane: InquiryLane,
    pub truth_surfaces_and_admissible_providers: Vec<String>,
    pub admissible_source_classes: Vec<SourceClass>,
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryProtocolProfile {
    pub profile_id: String,
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
        if params.profile_id != previous.profile_id {
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
        self.task_definition_digest == task_definition_digest && self.state_fence == *fence
    }

    #[must_use]
    pub fn governor_admission_request(&self) -> GovernorProfileAdmissionRequest {
        GovernorProfileAdmissionRequest {
            profile_id: self.profile_id.clone(),
            profile_revision: self.revision,
            profile_digest: self.digest.clone(),
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
        params.truth_surfaces_and_admissible_providers.sort();
        params
            .admissible_source_classes
            .sort_by_key(|class| format!("{class:?}"));
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
        let mut p = String::from("inquiry-protocol-profile/v1;");
        push_field(&mut p, "contract", INQUIRY_GOVERNANCE_CONTRACT);
        push_field(&mut p, "version", INQUIRY_GOVERNANCE_VERSION);
        push_field(&mut p, "profile_id", &params.profile_id);
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
        push_field(
            &mut p,
            "disclosure_ceiling",
            &format!("{:?}", params.disclosure_ceiling),
        );
        push_field(&mut p, "change_reason", &params.change_reason);
        if let Some(previous) = &supersedes_digest {
            push_field(&mut p, "supersedes_digest", previous);
        }
        let digest = freeze(&p);
        Ok(Self {
            profile_id: params.profile_id,
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
            digest,
        })
    }

    fn same_governed_shape(&self, other: &Self) -> bool {
        self.profile_id == other.profile_id
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorProfileAdmissionRequest {
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub task_definition_digest: String,
    pub state_fence: StateFence,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub request_type: String,
    pub canonical_write_authorized: bool,
}

/// Runtime-local profile/obligation/source registry. It owns no canonical
/// storage and creates no second work graph.
#[derive(Clone, Debug, Default)]
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

    pub fn compile_obligations<C: TaskGraphCompiler>(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        compiler_id: impl Into<String>,
        compiler: &mut C,
    ) -> Result<TaskGraphCompilationReceipt, InquiryGovernanceError> {
        let profile = self
            .profile(profile_id, profile_revision)
            .cloned()
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?;
        let obligations = compile_obligation_inputs(&profile, inputs)?;
        let compiler_id = compiler_id.into();
        text(&compiler_id, "compiler.compiler_id")?;
        compiler
            .compile(&obligations)
            .map_err(|_| InquiryGovernanceError::CompilerRejected {
                compiler_id: compiler_id.clone(),
            })?;
        let receipt = TaskGraphCompilationReceipt::new(compiler_id, &profile, &obligations)?;
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
