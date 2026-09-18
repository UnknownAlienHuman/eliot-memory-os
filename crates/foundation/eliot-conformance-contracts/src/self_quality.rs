//! Bounded Self-Quality evidence and diagnosis contract (issue #971).
//!
//! This module is the contract-only prerequisite for A-38 (#820). It defines
//! versioned input, observation, diagnosis, and inert-handoff types plus pure
//! validation, canonicalization, and digest functions. It contains no
//! diagnosis algorithm, scoring, live query, mutable state, persistence,
//! effect, or authority issuance.
//!
//! # Field to owner map (frozen)
//!
//! | Field family | Owner | Notes |
//! |---|---|---|
//! | `product` objective / acceptance / recovery refs | Product contract owner (external) | opaque refs, never metric targets |
//! | `source` source / artifact / configuration / generation / task / scope / fence | originating source owner | all seven load-bearing |
//! | observation `owner` / `schema` / `revision` / `content_digest` | emitting evidence owner | exact closed wire, hex digest |
//! | observation `window` / environment / platform / toolchain | emitting evidence owner | bounds `created_at_ms` |
//! | metric value / unit / normalization / population | emitting evidence owner | unit triple exact, no cross-unit math |
//! | Learning delivery / use / outcome / closure observations | A-32 (#590) vocabulary; LearningClosure evidence via A-37 (#819) | narrow projection, no copied models |
//! | Context floor / selection / quality / economy observations | A-15 (#584) vocabulary | narrow projection |
//! | Dreamer grounding / candidate / controller observations | A-03 (#578) vocabulary | narrow projection |
//! | diagnosis dimensions / severity / priority / recurrence | this contract (#971) | independent axes, no pass scalar |
//! | handoffs to #673 / #675 / #677 / #679 / incident / Human | downstream remediation owners | inert refs only, no job/plan/executable |
//! | maturity / support / execution / observation dimensions | existing `validation` module (I0.5) | unchanged by this module |
//!
//! # #820-requirement to type map (frozen)
//!
//! | #820 need | Contract type |
//! |---|---|
//! | exact Product acceptance + recovery identity | [`ProductContractRef`] |
//! | frozen observation snapshot | [`SelfQualityInput`] + [`SelfQualityObservation`] |
//! | prior diagnosis / intervention history | [`PriorDiagnosisRecord`] |
//! | explicit policy + finite bounds | [`SelfQualityPolicy`] + [`QualityLimits`] |
//! | privacy / authority / proof ceilings | [`EvidenceCeilings`] |
//! | dimension / source / member denominator | [`QualityDenominator`] + [`DenominatorCompleteness`] |
//! | zero vs missing measurement | [`MetricPresence`] + [`MetricMeasurement`] |
//! | diagnosis candidate | [`SelfQualityDiagnosisCandidate`] + [`DimensionOutcome`] |
//! | no-problem / no-action / incomplete / unknown / blocked / conflicted | disposition types |
//! | inert owner handoffs | [`SelfQualityHandoff`] + [`SelfQualityHandoffOwner`] |
//!
//! Compatibility is explicit: [`validate_compatibility_version`] accepts only
//! [`SELF_QUALITY_CONTRACT_VERSION`]. There is no trial decoding and no
//! fabricated evidence.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Current serialized Self-Quality contract revision.
pub const SELF_QUALITY_CONTRACT_VERSION: u16 = 1;
/// Stable schema identity for [`SelfQualityInput`].
pub const SELF_QUALITY_SCHEMA: &str = "eliot.self-quality.input.v1";
/// Stable schema identity for [`SelfQualityDiagnosisCandidate`].
pub const SELF_QUALITY_CANDIDATE_SCHEMA: &str = "eliot.self-quality.candidate.v1";
/// Stable schema identity for [`SelfQualityHandoff`].
pub const SELF_QUALITY_HANDOFF_SCHEMA: &str = "eliot.self-quality.handoff.v1";
/// Maximum observations in one frozen snapshot.
pub const MAX_SELF_QUALITY_OBSERVATIONS: usize = 256;
/// Maximum prior-history records in one input.
pub const MAX_SELF_QUALITY_HISTORY: usize = 128;
/// Maximum handoffs on one candidate.
pub const MAX_SELF_QUALITY_HANDOFFS: usize = 16;
/// Maximum dimension outcomes on one candidate.
pub const MAX_SELF_QUALITY_DIMENSIONS: usize = 64;
/// Maximum entries in one ref collection.
pub const MAX_SELF_QUALITY_REFS: usize = 64;
/// Maximum UTF-8 bytes in one identifier, handle, or ref.
pub const MAX_SELF_QUALITY_TEXT_BYTES: usize = 1_024;
/// Minimum bytes of a hex content/rules digest.
pub const MIN_SELF_QUALITY_DIGEST_BYTES: usize = 16;
/// Maximum bytes of a hex content/rules digest.
pub const MAX_SELF_QUALITY_DIGEST_BYTES: usize = 128;
/// A-36 learning-activation evidence supplier (immutable evidence only).
pub const ISSUE_A36_LEARNING_ACTIVATION: u32 = 620;
/// A-37 learning-closure evidence supplier (immutable evidence only).
///
/// The old reference to #809 is incorrect; the correct A-37 issue is #819.
pub const ISSUE_A37_LEARNING_CLOSURE: u32 = 819;
/// A-39 downstream conflict-analysis handoff owner.
pub const ISSUE_A39_CONFLICT_ANALYSIS: u32 = 673;
/// A-40 downstream development-diagnosis handoff owner.
pub const ISSUE_A40_DEVELOPMENT_DIAGNOSIS: u32 = 675;
/// A-41 downstream maintenance-plan handoff owner.
pub const ISSUE_A41_MAINTENANCE_PLAN: u32 = 677;
/// A-42 downstream configuration-assistance handoff owner.
pub const ISSUE_A42_CONFIGURATION_ASSISTANCE: u32 = 679;

/// Whether the dimension/source/member denominator is fully supplied.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenominatorCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Whether a metric slot carries an observed zero, a measured value, or no
/// measurement at all. Observed zero is never interchangeable with missing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetricPresence {
    NoEventZero,
    Value,
    Unavailable,
    Unmeasured,
}

/// Closed diagnosis dimensions. Each is evaluated independently against its
/// own owner-issued baseline; no single pass scalar exists.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfQualityDimension {
    Correctness,
    ProductOutcome,
    AcceptanceRecovery,
    IntegrityReversibility,
    ReliabilityAvailability,
    ReconciliationUnknownEffects,
    RealEdgeEvidence,
    ContextQuality,
    DreamerQuality,
    LearningQuality,
    MemoryQuality,
    SecurityPrivacy,
    PerformanceResources,
    CostQuota,
    HumanBurden,
    Compatibility,
}

impl SelfQualityDimension {
    /// Canonical order for deterministic serialization and hashing.
    pub const ALL: [Self; 16] = [
        Self::Correctness,
        Self::ProductOutcome,
        Self::AcceptanceRecovery,
        Self::IntegrityReversibility,
        Self::ReliabilityAvailability,
        Self::ReconciliationUnknownEffects,
        Self::RealEdgeEvidence,
        Self::ContextQuality,
        Self::DreamerQuality,
        Self::LearningQuality,
        Self::MemoryQuality,
        Self::SecurityPrivacy,
        Self::PerformanceResources,
        Self::CostQuota,
        Self::HumanBurden,
        Self::Compatibility,
    ];
}

/// Per-dimension evaluation state. Missing evidence is never a pass.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DimensionStatus {
    Pass,
    Fail,
    Partial,
    Inconclusive,
    NotApplicable,
    Missing,
}

/// Independent severity axis. Never a substitute for the status axis.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

/// Independent priority axis. Never a substitute for status or severity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Priority {
    None,
    Low,
    Medium,
    High,
    Urgent,
}

/// Causal standing of one finding. A symptom is not a hypothesis, and neither
/// is a proven cause without falsifiable discriminator evidence on record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CauseHypothesisStatus {
    Symptom,
    Hypothesis,
    ProvenCause,
}

/// Recurrence standing of one finding, kept distinct from intervention lineage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Recurrence {
    OneShot,
    Persistent,
    Recurrent,
    Flaky,
    Unknown,
}

/// Lineage state of one prior intervention, kept distinct from recurrence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InterventionState {
    Observed,
    Censored,
    NotAttempted,
    Applied,
    RolledBack,
    Partial,
    Failed,
    Unknown,
}

/// Closed inert handoff owners. Every variant names an external decision
/// owner; none carries a job, issue, plan, executable, effect, promotion, or
/// Finish token.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfQualityHandoffOwner {
    Instrumentation,
    #[serde(rename = "CONFLICT_ANALYSIS_673")]
    ConflictAnalysis673,
    #[serde(rename = "DEVELOPMENT_DIAGNOSIS_675")]
    DevelopmentDiagnosis675,
    #[serde(rename = "MAINTENANCE_PLAN_677")]
    MaintenancePlan677,
    #[serde(rename = "CONFIGURATION_ASSISTANCE_679")]
    ConfigurationAssistance679,
    IncidentRecovery,
    HumanObjective,
    HumanPolicy,
    HumanPrivacy,
    HumanCostRisk,
    UnsupportedOwner,
}

impl SelfQualityHandoffOwner {
    /// Canonical order for deterministic serialization and hashing.
    pub const ALL: [Self; 11] = [
        Self::Instrumentation,
        Self::ConflictAnalysis673,
        Self::DevelopmentDiagnosis675,
        Self::MaintenancePlan677,
        Self::ConfigurationAssistance679,
        Self::IncidentRecovery,
        Self::HumanObjective,
        Self::HumanPolicy,
        Self::HumanPrivacy,
        Self::HumanCostRisk,
        Self::UnsupportedOwner,
    ];

    /// Issue number for issue-bound downstream owners, if any.
    #[must_use]
    pub const fn issue_number(self) -> Option<u32> {
        match self {
            Self::ConflictAnalysis673 => Some(ISSUE_A39_CONFLICT_ANALYSIS),
            Self::DevelopmentDiagnosis675 => Some(ISSUE_A40_DEVELOPMENT_DIAGNOSIS),
            Self::MaintenancePlan677 => Some(ISSUE_A41_MAINTENANCE_PLAN),
            Self::ConfigurationAssistance679 => Some(ISSUE_A42_CONFIGURATION_ASSISTANCE),
            Self::Instrumentation
            | Self::IncidentRecovery
            | Self::HumanObjective
            | Self::HumanPolicy
            | Self::HumanPrivacy
            | Self::HumanCostRisk
            | Self::UnsupportedOwner => None,
        }
    }

    /// Whether this handoff waits on a Human decision owner.
    #[must_use]
    pub const fn is_human(self) -> bool {
        matches!(
            self,
            Self::HumanObjective | Self::HumanPolicy | Self::HumanPrivacy | Self::HumanCostRisk
        )
    }
}

/// Exact Product Objective / acceptance / recovery contract identity. Metric
/// targets cannot substitute for any of the three refs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductContractRef {
    pub contract_version: u16,
    pub objective_ref: String,
    pub acceptance_ref: String,
    pub recovery_ref: String,
}

/// Load-bearing source identity. Every field is required.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub contract_version: u16,
    pub source_ref: String,
    pub artifact_ref: String,
    pub configuration_ref: String,
    pub generation_ref: String,
    pub task_ref: String,
    pub scope_ref: String,
    pub fence_ref: String,
}

/// Observation window plus execution environment. Windows must close at or
/// before the input `created_at_ms`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationWindow {
    pub observed_from_ms: u64,
    pub observed_to_ms: u64,
    pub environment_ref: String,
    pub platform_ref: String,
    pub toolchain_ref: String,
}

/// Exact emitting-owner binding for one observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerBinding {
    pub owner_ref: String,
    pub schema_ref: String,
    pub revision_ref: String,
    pub content_digest: String,
}

/// One primitive measurement. Unit, normalization, and population are exact
/// identity; this contract performs no cross-unit comparison.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricMeasurement {
    pub metric_ref: String,
    pub value: f64,
    pub unit_ref: String,
    pub normalization_ref: String,
    pub population_ref: String,
    pub presence: MetricPresence,
}

/// Expected versus supplied dimension / source / member counts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityDenominator {
    pub expected_dimensions: u32,
    pub supplied_dimensions: u32,
    pub expected_sources: u32,
    pub supplied_sources: u32,
    pub expected_members: u32,
    pub supplied_members: u32,
    pub completeness: DenominatorCompleteness,
}

/// Shared inner payload of every observation family variant.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCore {
    pub observation_ref: String,
    pub dimension: SelfQualityDimension,
    pub owner: OwnerBinding,
    pub window: ObservationWindow,
    pub metric: MetricMeasurement,
    pub completeness: DenominatorCompleteness,
    pub status: DimensionStatus,
    pub counterevidence_refs: Vec<String>,
    pub confounder_refs: Vec<String>,
    pub intervention_refs: Vec<String>,
}

/// Closed observation union covering every #820 input family. Each variant
/// wraps [`ObservationCore`]; structural distinctions (liveness versus
/// service versus semantic versus recovery versus Product; Learning delivery
/// versus use versus outcome versus closure) are type-level, never a shared
/// generic value or duplicated owner schema.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfQualityObservation {
    Conformance(ObservationCore),
    SourceBuild(ObservationCore),
    RealEdge(ObservationCore),
    Runtime(ObservationCore),
    Liveness(ObservationCore),
    Service(ObservationCore),
    Semantic(ObservationCore),
    Recovery(ObservationCore),
    Product(ObservationCore),
    ContextFloor(ObservationCore),
    ContextSelection(ObservationCore),
    ContextQuality(ObservationCore),
    ContextEconomy(ObservationCore),
    DreamerGrounding(ObservationCore),
    DreamerCandidate(ObservationCore),
    DreamerController(ObservationCore),
    LearningDelivery(ObservationCore),
    LearningUse(ObservationCore),
    LearningOutcome(ObservationCore),
    /// Learning-closure evidence supplied via A-37 (#819), never #809.
    LearningClosure(ObservationCore),
    MemoryProvenance(ObservationCore),
    MemoryConflict(ObservationCore),
    SecurityPrivacy(ObservationCore),
    ErasureInfluence(ObservationCore),
    PerformanceResources(ObservationCore),
    CostQuota(ObservationCore),
    HumanAttention(ObservationCore),
    RecoveryCompatibility(ObservationCore),
}

impl SelfQualityObservation {
    /// Borrow the shared inner payload of any family variant.
    #[must_use]
    pub const fn core(&self) -> &ObservationCore {
        match self {
            Self::Conformance(inner)
            | Self::SourceBuild(inner)
            | Self::RealEdge(inner)
            | Self::Runtime(inner)
            | Self::Liveness(inner)
            | Self::Service(inner)
            | Self::Semantic(inner)
            | Self::Recovery(inner)
            | Self::Product(inner)
            | Self::ContextFloor(inner)
            | Self::ContextSelection(inner)
            | Self::ContextQuality(inner)
            | Self::ContextEconomy(inner)
            | Self::DreamerGrounding(inner)
            | Self::DreamerCandidate(inner)
            | Self::DreamerController(inner)
            | Self::LearningDelivery(inner)
            | Self::LearningUse(inner)
            | Self::LearningOutcome(inner)
            | Self::LearningClosure(inner)
            | Self::MemoryProvenance(inner)
            | Self::MemoryConflict(inner)
            | Self::SecurityPrivacy(inner)
            | Self::ErasureInfluence(inner)
            | Self::PerformanceResources(inner)
            | Self::CostQuota(inner)
            | Self::HumanAttention(inner)
            | Self::RecoveryCompatibility(inner) => inner,
        }
    }

    /// Stable family name for ordering and digest encoding.
    #[must_use]
    pub const fn family_name(&self) -> &'static str {
        match self {
            Self::Conformance(_) => "CONFORMANCE",
            Self::SourceBuild(_) => "SOURCE_BUILD",
            Self::RealEdge(_) => "REAL_EDGE",
            Self::Runtime(_) => "RUNTIME",
            Self::Liveness(_) => "LIVENESS",
            Self::Service(_) => "SERVICE",
            Self::Semantic(_) => "SEMANTIC",
            Self::Recovery(_) => "RECOVERY",
            Self::Product(_) => "PRODUCT",
            Self::ContextFloor(_) => "CONTEXT_FLOOR",
            Self::ContextSelection(_) => "CONTEXT_SELECTION",
            Self::ContextQuality(_) => "CONTEXT_QUALITY",
            Self::ContextEconomy(_) => "CONTEXT_ECONOMY",
            Self::DreamerGrounding(_) => "DREAMER_GROUNDING",
            Self::DreamerCandidate(_) => "DREAMER_CANDIDATE",
            Self::DreamerController(_) => "DREAMER_CONTROLLER",
            Self::LearningDelivery(_) => "LEARNING_DELIVERY",
            Self::LearningUse(_) => "LEARNING_USE",
            Self::LearningOutcome(_) => "LEARNING_OUTCOME",
            Self::LearningClosure(_) => "LEARNING_CLOSURE",
            Self::MemoryProvenance(_) => "MEMORY_PROVENANCE",
            Self::MemoryConflict(_) => "MEMORY_CONFLICT",
            Self::SecurityPrivacy(_) => "SECURITY_PRIVACY",
            Self::ErasureInfluence(_) => "ERASURE_INFLUENCE",
            Self::PerformanceResources(_) => "PERFORMANCE_RESOURCES",
            Self::CostQuota(_) => "COST_QUOTA",
            Self::HumanAttention(_) => "HUMAN_ATTENTION",
            Self::RecoveryCompatibility(_) => "RECOVERY_COMPATIBILITY",
        }
    }
}

/// One prior diagnosis / intervention record with exact source, configuration,
/// and environment lineage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorDiagnosisRecord {
    pub diagnosis_ref: String,
    pub intervention_ref: String,
    pub intervention_state: InterventionState,
    pub recurrence: Recurrence,
    pub hypothesis_status: CauseHypothesisStatus,
    pub source_ref: String,
    pub configuration_ref: String,
    pub environment_ref: String,
    pub observed_at_ms: u64,
}

/// Finite policy bounds. All limits are strictly positive and capped.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityLimits {
    pub max_observations: u32,
    pub max_history: u32,
    pub max_handoffs: u32,
    pub max_bytes: u64,
    pub max_depth: u32,
    pub max_work_units: u64,
    pub max_output_refs: u32,
    pub max_time_ms: u64,
}

/// Explicit self-quality policy. Diagnosis urgency derives from these exact
/// rules; there is no weighted score.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQualityPolicy {
    pub contract_version: u16,
    pub policy_ref: String,
    pub schema_ref: String,
    pub revision_ref: String,
    pub rules_digest: String,
    pub limits: QualityLimits,
}

/// Independent privacy / authority / proof ceilings bounding all evidence use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCeilings {
    pub privacy_ceiling_ref: String,
    pub authority_ceiling_ref: String,
    pub proof_ceiling_ref: String,
}

/// One closed versioned Self-Quality input: exact Product contract, frozen
/// observation snapshot, prior diagnosis/intervention history, and policy.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQualityInput {
    pub contract_version: u16,
    pub input_ref: String,
    pub product: ProductContractRef,
    pub source: SourceIdentity,
    pub observations: Vec<SelfQualityObservation>,
    pub prior_history: Vec<PriorDiagnosisRecord>,
    pub policy: SelfQualityPolicy,
    pub ceilings: EvidenceCeilings,
    pub denominator: QualityDenominator,
    pub created_at_ms: u64,
}

/// Per-dimension diagnosis outcome on independent status, severity, priority,
/// hypothesis, and recurrence axes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionOutcome {
    pub dimension: SelfQualityDimension,
    pub status: DimensionStatus,
    pub severity: Severity,
    pub priority: Priority,
    pub hypothesis: CauseHypothesisStatus,
    pub recurrence: Recurrence,
}

/// Immutable diagnosis candidate. The overall severity and priority are the
/// maxima of the per-dimension outcomes: the aggregate never hides the
/// weakest load-bearing ceiling.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQualityDiagnosisCandidate {
    pub contract_version: u16,
    pub candidate_ref: String,
    pub input_digest: String,
    pub policy_digest: String,
    pub outcomes: Vec<DimensionOutcome>,
    pub overall_severity: Severity,
    pub overall_priority: Priority,
    pub symptom_refs: Vec<String>,
    pub mechanism_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub handoffs: Vec<SelfQualityHandoff>,
    pub expires_at_ms: u64,
}

/// Evidence-backed no-problem disposition: complete current compatible
/// coverage with every required dimension passing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoProblemDisposition {
    pub input_digest: String,
    pub completed_dimensions: Vec<SelfQualityDimension>,
    pub window: ObservationWindow,
}

/// Evidence-backed no-action disposition: complete coverage with no failure
/// and explicit justification for tolerated partial findings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoActionDisposition {
    pub input_digest: String,
    pub justification_refs: Vec<String>,
    pub tolerated_dimensions: Vec<SelfQualityDimension>,
}

/// Incomplete diagnosis naming the exact missing evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IncompleteDiagnosis {
    pub input_digest: String,
    pub missing_evidence_refs: Vec<String>,
}

/// Unknown diagnosis naming the exact unknown scopes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownDiagnosis {
    pub input_digest: String,
    pub unknown_refs: Vec<String>,
}

/// Blocked diagnosis naming the exact blockers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockedDiagnosis {
    pub input_digest: String,
    pub blocker_refs: Vec<String>,
}

/// Conflicted diagnosis naming the exact conflicting evidence refs (at least
/// two: a conflict has more than one side).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictedDiagnosis {
    pub input_digest: String,
    pub conflict_refs: Vec<String>,
}

/// One closed inert handoff to an external owner. It carries symptom,
/// problem, evidence, missing-evidence, applicability, and priority refs plus
/// constraints and an invalidation set. It cannot encode a job, issue, plan,
/// executable, effect, promotion, or Finish token: no such field exists.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfQualityHandoff {
    pub contract_version: u16,
    pub handoff_ref: String,
    pub owner: SelfQualityHandoffOwner,
    pub symptom_refs: Vec<String>,
    pub problem_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub missing_evidence_refs: Vec<String>,
    pub applicability_refs: Vec<String>,
    pub priority: Priority,
    pub constraint_refs: Vec<String>,
    pub invalidation_set: Vec<String>,
}

/// Closed structural and semantic failures. Messages carry field names,
/// reasons, and identity refs only; measured values are never rendered, so
/// validation errors redact load-bearing content by construction.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SelfQualityContractError {
    #[error("unsupported self-quality contract version {actual}; expected {expected}")]
    UnsupportedContractVersion { expected: u16, actual: u16 },
    #[error("invalid {field}: {reason}")]
    InvalidText {
        field: &'static str,
        reason: &'static str,
    },
    #[error("protected default rejected in {field}")]
    ProtectedDefault { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("{field} contains {actual} entries; maximum is {maximum}")]
    CollectionTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("duplicate value in {field}: {value}")]
    DuplicateValue { field: &'static str, value: String },
    #[error("{field} is not in canonical order")]
    NonCanonicalCollection { field: &'static str },
    #[error("duplicate observation {observation_ref}")]
    DuplicateObservation { observation_ref: String },
    #[error("duplicate dimension {dimension:?}")]
    DuplicateDimension { dimension: SelfQualityDimension },
    #[error("duplicate diagnosis {diagnosis_ref}")]
    DuplicateDiagnosis { diagnosis_ref: String },
    #[error("duplicate handoff {handoff_ref}")]
    DuplicateHandoff { handoff_ref: String },
    #[error("invalid denominator: {reason}")]
    InvalidDenominator { reason: &'static str },
    #[error("invalid metric: {reason}")]
    InvalidMetric { reason: &'static str },
    #[error("invalid time field {field}")]
    InvalidTime { field: &'static str },
    #[error("invalid window field {field}")]
    InvalidWindow { field: &'static str },
    #[error("evidence from the future in {field}")]
    FutureEvidence { field: &'static str },
    #[error("history is not in chronological order in {field}")]
    ChronologyViolation { field: &'static str },
    #[error("invalid hypothesis combination: {reason}")]
    InvalidHypothesis { reason: &'static str },
    #[error("invalid severity combination: {reason}")]
    InvalidSeverityCombination { reason: &'static str },
    #[error("required evidence is missing: {field}")]
    MissingEvidence { field: &'static str },
    #[error("empty observation coverage is not clean evidence")]
    EmptyCoverage,
    #[error("digest mismatch in {field}")]
    DigestMismatch { field: &'static str },
}

/// Accepts exactly [`SELF_QUALITY_CONTRACT_VERSION`]. Compatibility is
/// explicit; there is no trial decoding of other revisions.
pub fn validate_compatibility_version(actual: u16) -> Result<(), SelfQualityContractError> {
    if actual == SELF_QUALITY_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(SelfQualityContractError::UnsupportedContractVersion {
            expected: SELF_QUALITY_CONTRACT_VERSION,
            actual,
        })
    }
}

/// Validates the exact Product Objective / acceptance / recovery identity.
pub fn validate_product_contract_ref(
    product: &ProductContractRef,
) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(product.contract_version)?;
    validate_text("product.objective_ref", &product.objective_ref)?;
    validate_text("product.acceptance_ref", &product.acceptance_ref)?;
    validate_text("product.recovery_ref", &product.recovery_ref)?;
    if product.objective_ref == product.acceptance_ref
        || product.objective_ref == product.recovery_ref
        || product.acceptance_ref == product.recovery_ref
    {
        return Err(SelfQualityContractError::DuplicateValue {
            field: "product",
            value: product.objective_ref.clone(),
        });
    }
    Ok(())
}

/// Validates all seven load-bearing source identity bindings.
pub fn validate_source_identity(source: &SourceIdentity) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(source.contract_version)?;
    let fields: [(&'static str, &String); 7] = [
        ("source.source_ref", &source.source_ref),
        ("source.artifact_ref", &source.artifact_ref),
        ("source.configuration_ref", &source.configuration_ref),
        ("source.generation_ref", &source.generation_ref),
        ("source.task_ref", &source.task_ref),
        ("source.scope_ref", &source.scope_ref),
        ("source.fence_ref", &source.fence_ref),
    ];
    let mut seen = BTreeSet::new();
    for (field, value) in &fields {
        validate_text(field, value)?;
        if !seen.insert((*value).clone()) {
            return Err(SelfQualityContractError::DuplicateValue {
                field: "source",
                value: (*value).clone(),
            });
        }
    }
    Ok(())
}

/// Validates one observation window and its environment bindings.
pub fn validate_observation_window(
    window: &ObservationWindow,
) -> Result<(), SelfQualityContractError> {
    if window.observed_to_ms == 0 || window.observed_from_ms >= window.observed_to_ms {
        return Err(SelfQualityContractError::InvalidWindow {
            field: "window.observed_to_ms",
        });
    }
    validate_text("window.environment_ref", &window.environment_ref)?;
    validate_text("window.platform_ref", &window.platform_ref)?;
    validate_text("window.toolchain_ref", &window.toolchain_ref)?;
    Ok(())
}

/// Validates one exact owner / schema / revision / digest binding.
pub fn validate_owner_binding(owner: &OwnerBinding) -> Result<(), SelfQualityContractError> {
    validate_text("owner.owner_ref", &owner.owner_ref)?;
    validate_text("owner.schema_ref", &owner.schema_ref)?;
    validate_text("owner.revision_ref", &owner.revision_ref)?;
    validate_hex_digest("owner.content_digest", &owner.content_digest)?;
    Ok(())
}

/// Validates one primitive measurement, keeping observed zero distinct from
/// missing and rejecting non-finite values.
pub fn validate_metric_measurement(
    metric: &MetricMeasurement,
) -> Result<(), SelfQualityContractError> {
    validate_text("metric.metric_ref", &metric.metric_ref)?;
    validate_text("metric.unit_ref", &metric.unit_ref)?;
    validate_text("metric.normalization_ref", &metric.normalization_ref)?;
    validate_text("metric.population_ref", &metric.population_ref)?;
    if !metric.value.is_finite() {
        return Err(SelfQualityContractError::InvalidMetric {
            reason: "metric value must be finite",
        });
    }
    match metric.presence {
        MetricPresence::NoEventZero | MetricPresence::Unavailable | MetricPresence::Unmeasured => {
            if metric.value != 0.0 {
                return Err(SelfQualityContractError::InvalidMetric {
                    reason: "zero-event, unavailable, and unmeasured slots must carry value 0.0",
                });
            }
        }
        MetricPresence::Value => {}
    }
    Ok(())
}

/// Validates the intrinsic shape of one denominator (counts consistent with
/// the declared completeness).
pub fn validate_denominator(
    denominator: &QualityDenominator,
) -> Result<(), SelfQualityContractError> {
    for (_field, expected, supplied) in [
        (
            "denominator.dimensions",
            denominator.expected_dimensions,
            denominator.supplied_dimensions,
        ),
        (
            "denominator.sources",
            denominator.expected_sources,
            denominator.supplied_sources,
        ),
        (
            "denominator.members",
            denominator.expected_members,
            denominator.supplied_members,
        ),
    ] {
        if supplied > expected {
            return Err(SelfQualityContractError::InvalidDenominator {
                reason: "supplied counts cannot exceed expected counts",
            });
        }
    }
    let complete = denominator.supplied_dimensions == denominator.expected_dimensions
        && denominator.supplied_sources == denominator.expected_sources
        && denominator.supplied_members == denominator.expected_members
        && denominator.expected_dimensions > 0
        && denominator.expected_sources > 0
        && denominator.expected_members > 0;
    let empty = denominator.supplied_dimensions == 0
        && denominator.supplied_sources == 0
        && denominator.supplied_members == 0;
    match denominator.completeness {
        DenominatorCompleteness::Complete => {
            if !complete {
                return Err(SelfQualityContractError::InvalidDenominator {
                    reason: "COMPLETE requires every supplied count to equal a positive expected count",
                });
            }
        }
        DenominatorCompleteness::Partial => {
            if complete || empty {
                return Err(SelfQualityContractError::InvalidDenominator {
                    reason: "PARTIAL requires some but not all expected evidence",
                });
            }
        }
        DenominatorCompleteness::Unknown => {
            if !empty {
                return Err(SelfQualityContractError::InvalidDenominator {
                    reason: "UNKNOWN requires zero supplied dimensions, sources, and members",
                });
            }
        }
    }
    Ok(())
}

/// Validates one shared observation payload.
pub fn validate_observation_core(core: &ObservationCore) -> Result<(), SelfQualityContractError> {
    validate_text("observation.observation_ref", &core.observation_ref)?;
    validate_owner_binding(&core.owner)?;
    validate_observation_window(&core.window)?;
    validate_metric_measurement(&core.metric)?;
    match core.status {
        DimensionStatus::Missing => match core.metric.presence {
            MetricPresence::Unavailable | MetricPresence::Unmeasured => {}
            MetricPresence::NoEventZero | MetricPresence::Value => {
                return Err(SelfQualityContractError::InvalidMetric {
                    reason: "MISSING status cannot carry an observed measurement",
                });
            }
        },
        DimensionStatus::NotApplicable => match core.metric.presence {
            MetricPresence::Value => {
                return Err(SelfQualityContractError::InvalidMetric {
                    reason: "NOT_APPLICABLE status cannot carry a measured value",
                });
            }
            MetricPresence::NoEventZero
            | MetricPresence::Unavailable
            | MetricPresence::Unmeasured => {}
        },
        DimensionStatus::Pass
        | DimensionStatus::Fail
        | DimensionStatus::Partial
        | DimensionStatus::Inconclusive => match core.metric.presence {
            MetricPresence::Value | MetricPresence::NoEventZero => {}
            MetricPresence::Unavailable | MetricPresence::Unmeasured => {
                return Err(SelfQualityContractError::MissingEvidence {
                    field: "observation.metric",
                });
            }
        },
    }
    validate_ref_set(
        "observation.counterevidence_refs",
        &core.counterevidence_refs,
    )?;
    validate_ref_set("observation.confounder_refs", &core.confounder_refs)?;
    validate_ref_set("observation.intervention_refs", &core.intervention_refs)?;
    Ok(())
}

/// Validates one closed observation family member.
pub fn validate_observation(
    observation: &SelfQualityObservation,
) -> Result<(), SelfQualityContractError> {
    validate_observation_core(observation.core())
}

/// Validates one prior diagnosis / intervention record.
pub fn validate_prior_record(
    record: &PriorDiagnosisRecord,
) -> Result<(), SelfQualityContractError> {
    validate_text("history.diagnosis_ref", &record.diagnosis_ref)?;
    validate_text("history.intervention_ref", &record.intervention_ref)?;
    validate_text("history.source_ref", &record.source_ref)?;
    validate_text("history.configuration_ref", &record.configuration_ref)?;
    validate_text("history.environment_ref", &record.environment_ref)?;
    if record.observed_at_ms == 0 {
        return Err(SelfQualityContractError::InvalidTime {
            field: "history.observed_at_ms",
        });
    }
    Ok(())
}

/// Validates finite policy bounds.
pub fn validate_limits(limits: &QualityLimits) -> Result<(), SelfQualityContractError> {
    if limits.max_observations == 0
        || usize::try_from(limits.max_observations).unwrap_or(usize::MAX)
            > MAX_SELF_QUALITY_OBSERVATIONS
    {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "policy.limits.max_observations",
            maximum: MAX_SELF_QUALITY_OBSERVATIONS,
            actual: limits.max_observations as usize,
        });
    }
    if limits.max_history == 0
        || usize::try_from(limits.max_history).unwrap_or(usize::MAX) > MAX_SELF_QUALITY_HISTORY
    {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "policy.limits.max_history",
            maximum: MAX_SELF_QUALITY_HISTORY,
            actual: limits.max_history as usize,
        });
    }
    if limits.max_handoffs == 0
        || usize::try_from(limits.max_handoffs).unwrap_or(usize::MAX) > MAX_SELF_QUALITY_HANDOFFS
    {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "policy.limits.max_handoffs",
            maximum: MAX_SELF_QUALITY_HANDOFFS,
            actual: limits.max_handoffs as usize,
        });
    }
    for (field, value, maximum) in [
        ("policy.limits.max_bytes", limits.max_bytes, 1_u64 << 40),
        (
            "policy.limits.max_work_units",
            limits.max_work_units,
            1_u64 << 40,
        ),
        (
            "policy.limits.max_time_ms",
            limits.max_time_ms,
            31_536_000_000,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(SelfQualityContractError::CollectionTooLarge {
                field,
                maximum: maximum as usize,
                actual: value as usize,
            });
        }
    }
    for (field, value, maximum) in [
        ("policy.limits.max_depth", limits.max_depth, 128_u32),
        (
            "policy.limits.max_output_refs",
            limits.max_output_refs,
            1_024_u32,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(SelfQualityContractError::CollectionTooLarge {
                field,
                maximum: maximum as usize,
                actual: value as usize,
            });
        }
    }
    Ok(())
}

/// Validates one explicit policy with its finite bounds.
pub fn validate_policy(policy: &SelfQualityPolicy) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(policy.contract_version)?;
    validate_text("policy.policy_ref", &policy.policy_ref)?;
    validate_text("policy.schema_ref", &policy.schema_ref)?;
    validate_text("policy.revision_ref", &policy.revision_ref)?;
    validate_hex_digest("policy.rules_digest", &policy.rules_digest)?;
    validate_limits(&policy.limits)?;
    Ok(())
}

/// Validates the independent privacy / authority / proof ceilings.
pub fn validate_ceilings(ceilings: &EvidenceCeilings) -> Result<(), SelfQualityContractError> {
    validate_text(
        "ceilings.privacy_ceiling_ref",
        &ceilings.privacy_ceiling_ref,
    )?;
    validate_text(
        "ceilings.authority_ceiling_ref",
        &ceilings.authority_ceiling_ref,
    )?;
    validate_text("ceilings.proof_ceiling_ref", &ceilings.proof_ceiling_ref)?;
    if ceilings.privacy_ceiling_ref == ceilings.authority_ceiling_ref
        || ceilings.privacy_ceiling_ref == ceilings.proof_ceiling_ref
        || ceilings.authority_ceiling_ref == ceilings.proof_ceiling_ref
    {
        return Err(SelfQualityContractError::DuplicateValue {
            field: "ceilings",
            value: ceilings.privacy_ceiling_ref.clone(),
        });
    }
    Ok(())
}

/// Validates one complete closed input: identities, every observation,
/// chronological history, policy, ceilings, denominator counts against the
/// actual snapshot, and the creation boundary. Pure: the input is never
/// mutated and nothing is fetched or repaired.
pub fn validate_self_quality_input(
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(input.contract_version)?;
    validate_text("input.input_ref", &input.input_ref)?;
    if input.created_at_ms == 0 {
        return Err(SelfQualityContractError::InvalidTime {
            field: "input.created_at_ms",
        });
    }
    validate_product_contract_ref(&input.product)?;
    validate_source_identity(&input.source)?;
    validate_policy(&input.policy)?;
    validate_ceilings(&input.ceilings)?;
    validate_denominator(&input.denominator)?;

    if input.observations.is_empty() {
        return Err(SelfQualityContractError::EmptyCoverage);
    }
    if input.observations.len() > MAX_SELF_QUALITY_OBSERVATIONS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "input.observations",
            maximum: MAX_SELF_QUALITY_OBSERVATIONS,
            actual: input.observations.len(),
        });
    }
    let policy_cap = usize::try_from(input.policy.limits.max_observations).unwrap_or(0);
    if input.observations.len() > policy_cap {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "input.observations",
            maximum: policy_cap,
            actual: input.observations.len(),
        });
    }
    let mut observation_refs = BTreeSet::new();
    let mut previous_ref: Option<&str> = None;
    for observation in &input.observations {
        let core = observation.core();
        validate_observation(observation)?;
        if !observation_refs.insert(core.observation_ref.clone()) {
            return Err(SelfQualityContractError::DuplicateObservation {
                observation_ref: core.observation_ref.clone(),
            });
        }
        if let Some(previous) = previous_ref
            && core.observation_ref.as_str() <= previous
        {
            return Err(SelfQualityContractError::NonCanonicalCollection {
                field: "input.observations",
            });
        }
        previous_ref = Some(core.observation_ref.as_str());
        if core.window.observed_to_ms > input.created_at_ms {
            return Err(SelfQualityContractError::FutureEvidence {
                field: "observation.window",
            });
        }
    }

    if input.prior_history.len() > MAX_SELF_QUALITY_HISTORY {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "input.prior_history",
            maximum: MAX_SELF_QUALITY_HISTORY,
            actual: input.prior_history.len(),
        });
    }
    let history_cap = usize::try_from(input.policy.limits.max_history).unwrap_or(0);
    if input.prior_history.len() > history_cap {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "input.prior_history",
            maximum: history_cap,
            actual: input.prior_history.len(),
        });
    }
    let mut diagnosis_refs = BTreeSet::new();
    let mut previous_at_ms: Option<u64> = None;
    for record in &input.prior_history {
        validate_prior_record(record)?;
        if !diagnosis_refs.insert(record.diagnosis_ref.clone()) {
            return Err(SelfQualityContractError::DuplicateDiagnosis {
                diagnosis_ref: record.diagnosis_ref.clone(),
            });
        }
        // Semantic time order is preserved: history stays chronological and is
        // never re-sorted by canonicalization.
        if let Some(previous) = previous_at_ms
            && record.observed_at_ms < previous
        {
            return Err(SelfQualityContractError::ChronologyViolation {
                field: "input.prior_history",
            });
        }
        previous_at_ms = Some(record.observed_at_ms);
        if record.observed_at_ms > input.created_at_ms {
            return Err(SelfQualityContractError::FutureEvidence {
                field: "history.observed_at_ms",
            });
        }
    }

    validate_denominator_counts(input)?;
    Ok(())
}

/// Validates one per-dimension outcome on its independent axes.
pub fn validate_dimension_outcome(
    outcome: &DimensionOutcome,
) -> Result<(), SelfQualityContractError> {
    match outcome.status {
        DimensionStatus::Pass | DimensionStatus::NotApplicable | DimensionStatus::Missing => {
            if outcome.severity != Severity::Negligible {
                return Err(SelfQualityContractError::InvalidSeverityCombination {
                    reason: "pass, not-applicable, and missing outcomes carry NEGLIGIBLE severity",
                });
            }
            if outcome.priority != Priority::None {
                return Err(SelfQualityContractError::InvalidSeverityCombination {
                    reason: "pass, not-applicable, and missing outcomes carry no priority",
                });
            }
        }
        DimensionStatus::Fail => {
            if outcome.severity == Severity::Negligible {
                return Err(SelfQualityContractError::InvalidSeverityCombination {
                    reason: "FAIL requires a non-negligible severity",
                });
            }
            if outcome.priority == Priority::None {
                return Err(SelfQualityContractError::InvalidSeverityCombination {
                    reason: "FAIL requires an explicit priority",
                });
            }
        }
        DimensionStatus::Partial | DimensionStatus::Inconclusive => {}
    }
    if outcome.hypothesis == CauseHypothesisStatus::ProvenCause
        && !matches!(
            outcome.status,
            DimensionStatus::Fail | DimensionStatus::Partial
        )
    {
        return Err(SelfQualityContractError::InvalidHypothesis {
            reason: "PROVEN_CAUSE requires a FAIL or PARTIAL dimension status",
        });
    }
    Ok(())
}

/// Validates one inert handoff. The type cannot encode jobs, issues, plans,
/// executables, effects, promotions, or Finish tokens: no such field exists
/// and unknown wire fields are rejected before normalization.
pub fn validate_handoff(handoff: &SelfQualityHandoff) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(handoff.contract_version)?;
    validate_text("handoff.handoff_ref", &handoff.handoff_ref)?;
    validate_ref_set("handoff.symptom_refs", &handoff.symptom_refs)?;
    validate_ref_set("handoff.problem_refs", &handoff.problem_refs)?;
    validate_ref_set("handoff.evidence_refs", &handoff.evidence_refs)?;
    validate_ref_set(
        "handoff.missing_evidence_refs",
        &handoff.missing_evidence_refs,
    )?;
    validate_ref_set("handoff.applicability_refs", &handoff.applicability_refs)?;
    validate_ref_set("handoff.constraint_refs", &handoff.constraint_refs)?;
    validate_ref_set("handoff.invalidation_set", &handoff.invalidation_set)?;
    if handoff.symptom_refs.is_empty()
        || handoff.problem_refs.is_empty()
        || handoff.evidence_refs.is_empty()
        || handoff.applicability_refs.is_empty()
    {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "handoff.symptom/problem/evidence/applicability",
        });
    }
    if handoff.invalidation_set.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "handoff.invalidation_set",
        });
    }
    Ok(())
}

/// Validates an already canonical handoff set with unique sorted refs.
pub fn validate_handoff_set(
    handoffs: &[SelfQualityHandoff],
) -> Result<(), SelfQualityContractError> {
    if handoffs.len() > MAX_SELF_QUALITY_HANDOFFS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "handoffs",
            maximum: MAX_SELF_QUALITY_HANDOFFS,
            actual: handoffs.len(),
        });
    }
    let mut refs = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for handoff in handoffs {
        validate_handoff(handoff)?;
        if !refs.insert(handoff.handoff_ref.clone()) {
            return Err(SelfQualityContractError::DuplicateHandoff {
                handoff_ref: handoff.handoff_ref.clone(),
            });
        }
        if let Some(prev) = previous
            && handoff.handoff_ref.as_str() <= prev
        {
            return Err(SelfQualityContractError::NonCanonicalCollection { field: "handoffs" });
        }
        previous = Some(handoff.handoff_ref.as_str());
    }
    Ok(())
}

/// Validates one candidate against its exact input snapshot: digests bind the
/// input and policy, every observed dimension is accounted for, overall
/// severity/priority are the per-dimension maxima, and mechanism refs exist
/// exactly when a cause is proven.
pub fn validate_candidate_against_input(
    candidate: &SelfQualityDiagnosisCandidate,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_compatibility_version(candidate.contract_version)?;
    validate_text("candidate.candidate_ref", &candidate.candidate_ref)?;
    validate_self_quality_input(input)?;
    if candidate.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "candidate.input_digest",
        });
    }
    if candidate.policy_digest != digest_policy(&input.policy) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "candidate.policy_digest",
        });
    }
    if candidate.outcomes.is_empty() || candidate.outcomes.len() > MAX_SELF_QUALITY_DIMENSIONS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "candidate.outcomes",
            maximum: MAX_SELF_QUALITY_DIMENSIONS,
            actual: candidate.outcomes.len(),
        });
    }
    let mut dimensions = BTreeSet::new();
    let mut previous: Option<SelfQualityDimension> = None;
    let mut top_severity = Severity::Negligible;
    let mut top_priority = Priority::None;
    let mut proven = false;
    for outcome in &candidate.outcomes {
        validate_dimension_outcome(outcome)?;
        if !dimensions.insert(outcome.dimension) {
            return Err(SelfQualityContractError::DuplicateDimension {
                dimension: outcome.dimension,
            });
        }
        if let Some(prev) = previous
            && outcome.dimension <= prev
        {
            return Err(SelfQualityContractError::NonCanonicalCollection {
                field: "candidate.outcomes",
            });
        }
        previous = Some(outcome.dimension);
        if severity_rank(outcome.severity) > severity_rank(top_severity) {
            top_severity = outcome.severity;
        }
        if priority_rank(outcome.priority) > priority_rank(top_priority) {
            top_priority = outcome.priority;
        }
        if outcome.hypothesis == CauseHypothesisStatus::ProvenCause {
            proven = true;
        }
    }
    // Every observed dimension must survive aggregation: failed, harmful,
    // minority, and unknown observations cannot disappear.
    for observation in &input.observations {
        if !dimensions.contains(&observation.core().dimension) {
            return Err(SelfQualityContractError::MissingEvidence {
                field: "candidate.outcomes",
            });
        }
    }
    if candidate.overall_severity != top_severity || candidate.overall_priority != top_priority {
        return Err(SelfQualityContractError::InvalidSeverityCombination {
            reason: "overall severity and priority are the per-dimension maxima",
        });
    }
    validate_ref_set("candidate.symptom_refs", &candidate.symptom_refs)?;
    validate_ref_set("candidate.mechanism_refs", &candidate.mechanism_refs)?;
    validate_ref_set(
        "candidate.counterevidence_refs",
        &candidate.counterevidence_refs,
    )?;
    if candidate.symptom_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "candidate.symptom_refs",
        });
    }
    // A correlation, sequence, or failed component is not a mechanism: proven
    // causes require mechanism refs, and unproven findings forbid them.
    if proven && candidate.mechanism_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "candidate.mechanism_refs",
        });
    }
    if !proven && !candidate.mechanism_refs.is_empty() {
        return Err(SelfQualityContractError::InvalidHypothesis {
            reason: "mechanism refs require at least one PROVEN_CAUSE outcome",
        });
    }
    let handoff_cap = usize::try_from(input.policy.limits.max_handoffs).unwrap_or(0);
    if candidate.handoffs.len() > handoff_cap {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "candidate.handoffs",
            maximum: handoff_cap,
            actual: candidate.handoffs.len(),
        });
    }
    validate_handoff_set(&candidate.handoffs)?;
    if candidate.expires_at_ms < input.created_at_ms || candidate.expires_at_ms == 0 {
        return Err(SelfQualityContractError::InvalidTime {
            field: "candidate.expires_at_ms",
        });
    }
    Ok(())
}

/// Validates an evidence-backed no-problem disposition: complete denominator,
/// every observation passing, and exact digest binding.
pub fn validate_no_problem_against_input(
    disposition: &NoProblemDisposition,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if disposition.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "no_problem.input_digest",
        });
    }
    if input.denominator.completeness != DenominatorCompleteness::Complete {
        return Err(SelfQualityContractError::InvalidDenominator {
            reason: "no-problem requires a COMPLETE denominator",
        });
    }
    for observation in &input.observations {
        if observation.core().status != DimensionStatus::Pass {
            return Err(SelfQualityContractError::InvalidSeverityCombination {
                reason: "no-problem requires every observation to PASS",
            });
        }
    }
    let mut expected: Vec<SelfQualityDimension> = input
        .observations
        .iter()
        .map(|observation| observation.core().dimension)
        .collect();
    expected.sort();
    expected.dedup();
    let mut completed = disposition.completed_dimensions.clone();
    completed.sort();
    completed.dedup();
    if completed != expected {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "no_problem.completed_dimensions",
        });
    }
    validate_observation_window(&disposition.window)?;
    Ok(())
}

/// Validates an evidence-backed no-action disposition: complete denominator,
/// no failure or missing evidence, explicit justification, and digest binding.
pub fn validate_no_action_against_input(
    disposition: &NoActionDisposition,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if disposition.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "no_action.input_digest",
        });
    }
    if input.denominator.completeness != DenominatorCompleteness::Complete {
        return Err(SelfQualityContractError::InvalidDenominator {
            reason: "no-action requires a COMPLETE denominator",
        });
    }
    for observation in &input.observations {
        match observation.core().status {
            DimensionStatus::Fail | DimensionStatus::Missing => {
                return Err(SelfQualityContractError::InvalidSeverityCombination {
                    reason: "no-action forbids FAIL and MISSING observations",
                });
            }
            DimensionStatus::Pass
            | DimensionStatus::Partial
            | DimensionStatus::Inconclusive
            | DimensionStatus::NotApplicable => {}
        }
    }
    validate_ref_set(
        "no_action.justification_refs",
        &disposition.justification_refs,
    )?;
    if disposition.justification_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "no_action.justification_refs",
        });
    }
    let mut tolerated = disposition.tolerated_dimensions.clone();
    tolerated.sort();
    tolerated.dedup();
    for dimension in &tolerated {
        if !input
            .observations
            .iter()
            .any(|observation| &observation.core().dimension == dimension)
        {
            return Err(SelfQualityContractError::MissingEvidence {
                field: "no_action.tolerated_dimensions",
            });
        }
    }
    Ok(())
}

/// Validates an incomplete diagnosis: it must name its missing evidence and
/// bind the exact input digest.
pub fn validate_incomplete_against_input(
    diagnosis: &IncompleteDiagnosis,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if diagnosis.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "incomplete.input_digest",
        });
    }
    validate_ref_set(
        "incomplete.missing_evidence_refs",
        &diagnosis.missing_evidence_refs,
    )?;
    if diagnosis.missing_evidence_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "incomplete.missing_evidence_refs",
        });
    }
    Ok(())
}

/// Validates an unknown diagnosis against its exact input digest.
pub fn validate_unknown_against_input(
    diagnosis: &UnknownDiagnosis,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if diagnosis.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "unknown.input_digest",
        });
    }
    validate_ref_set("unknown.unknown_refs", &diagnosis.unknown_refs)?;
    if diagnosis.unknown_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "unknown.unknown_refs",
        });
    }
    Ok(())
}

/// Validates a blocked diagnosis against its exact input digest.
pub fn validate_blocked_against_input(
    diagnosis: &BlockedDiagnosis,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if diagnosis.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "blocked.input_digest",
        });
    }
    validate_ref_set("blocked.blocker_refs", &diagnosis.blocker_refs)?;
    if diagnosis.blocker_refs.is_empty() {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "blocked.blocker_refs",
        });
    }
    Ok(())
}

/// Validates a conflicted diagnosis: at least two conflicting sides plus the
/// exact input digest binding.
pub fn validate_conflicted_against_input(
    diagnosis: &ConflictedDiagnosis,
    input: &SelfQualityInput,
) -> Result<(), SelfQualityContractError> {
    validate_self_quality_input(input)?;
    if diagnosis.input_digest != digest_self_quality_input(input) {
        return Err(SelfQualityContractError::DigestMismatch {
            field: "conflicted.input_digest",
        });
    }
    validate_ref_set("conflicted.conflict_refs", &diagnosis.conflict_refs)?;
    if diagnosis.conflict_refs.len() < 2 {
        return Err(SelfQualityContractError::MissingEvidence {
            field: "conflicted.conflict_refs",
        });
    }
    Ok(())
}

/// Canonicalizes an observation set: sorts by `(family, observation_ref)` and
/// rejects duplicate refs. Accepts arbitrary source ordering.
pub fn canonicalize_observations(
    mut observations: Vec<SelfQualityObservation>,
) -> Result<Vec<SelfQualityObservation>, SelfQualityContractError> {
    if observations.len() > MAX_SELF_QUALITY_OBSERVATIONS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "input.observations",
            maximum: MAX_SELF_QUALITY_OBSERVATIONS,
            actual: observations.len(),
        });
    }
    for observation in &observations {
        validate_observation(observation)?;
    }
    observations.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    let mut seen = BTreeSet::new();
    for observation in &observations {
        let observation_ref = observation.core().observation_ref.clone();
        if !seen.insert(observation_ref.clone()) {
            return Err(SelfQualityContractError::DuplicateObservation { observation_ref });
        }
    }
    Ok(observations)
}

/// Canonicalizes dimension outcomes into dimension order.
pub fn canonicalize_dimension_outcomes(
    mut outcomes: Vec<DimensionOutcome>,
) -> Result<Vec<DimensionOutcome>, SelfQualityContractError> {
    if outcomes.len() > MAX_SELF_QUALITY_DIMENSIONS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "candidate.outcomes",
            maximum: MAX_SELF_QUALITY_DIMENSIONS,
            actual: outcomes.len(),
        });
    }
    for outcome in &outcomes {
        validate_dimension_outcome(outcome)?;
    }
    outcomes.sort_by_key(|outcome| outcome.dimension);
    let mut seen = BTreeSet::new();
    for outcome in &outcomes {
        if !seen.insert(outcome.dimension) {
            return Err(SelfQualityContractError::DuplicateDimension {
                dimension: outcome.dimension,
            });
        }
    }
    Ok(outcomes)
}

/// Canonicalizes a handoff set into handoff-ref order.
pub fn canonicalize_handoffs(
    mut handoffs: Vec<SelfQualityHandoff>,
) -> Result<Vec<SelfQualityHandoff>, SelfQualityContractError> {
    if handoffs.len() > MAX_SELF_QUALITY_HANDOFFS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field: "handoffs",
            maximum: MAX_SELF_QUALITY_HANDOFFS,
            actual: handoffs.len(),
        });
    }
    for handoff in &handoffs {
        validate_handoff(handoff)?;
    }
    handoffs.sort_by(|left, right| left.handoff_ref.cmp(&right.handoff_ref));
    let mut seen = BTreeSet::new();
    for handoff in &handoffs {
        if !seen.insert(handoff.handoff_ref.clone()) {
            return Err(SelfQualityContractError::DuplicateHandoff {
                handoff_ref: handoff.handoff_ref.clone(),
            });
        }
    }
    Ok(handoffs)
}

/// Canonicalizes one input's set-like members. Prior history keeps its
/// semantic chronological order and is never re-sorted.
pub fn canonicalize_self_quality_input(
    mut input: SelfQualityInput,
) -> Result<SelfQualityInput, SelfQualityContractError> {
    input.observations = canonicalize_observations(input.observations)?;
    validate_self_quality_input(&input)?;
    Ok(input)
}

/// Deterministic digest of one input snapshot (lowercase hex, FNV-1a 64).
/// Set-like members are encoded in canonical order, so permutations of the
/// same snapshot share one digest, while removing any load-bearing field
/// changes it.
#[must_use]
pub fn digest_self_quality_input(input: &SelfQualityInput) -> String {
    let mut encoded = String::from("sq1");
    push_field(
        &mut encoded,
        SELF_QUALITY_CONTRACT_VERSION.to_string().as_str(),
    );
    push_field(&mut encoded, &input.input_ref);
    push_field(&mut encoded, &input.product.objective_ref);
    push_field(&mut encoded, &input.product.acceptance_ref);
    push_field(&mut encoded, &input.product.recovery_ref);
    for value in [
        &input.source.source_ref,
        &input.source.artifact_ref,
        &input.source.configuration_ref,
        &input.source.generation_ref,
        &input.source.task_ref,
        &input.source.scope_ref,
        &input.source.fence_ref,
    ] {
        push_field(&mut encoded, value);
    }
    let mut observations: Vec<&SelfQualityObservation> = input.observations.iter().collect();
    observations.sort_by(|left, right| {
        (left.family_name(), left.core().observation_ref.as_str())
            .cmp(&(right.family_name(), right.core().observation_ref.as_str()))
    });
    for observation in observations {
        let core = observation.core();
        push_field(&mut encoded, observation.family_name());
        push_field(&mut encoded, &core.observation_ref);
        push_field(&mut encoded, format!("{:?}", core.dimension).as_str());
        push_field(&mut encoded, &core.owner.owner_ref);
        push_field(&mut encoded, &core.owner.schema_ref);
        push_field(&mut encoded, &core.owner.revision_ref);
        push_field(&mut encoded, &core.owner.content_digest);
        push_field(
            &mut encoded,
            core.window.observed_from_ms.to_string().as_str(),
        );
        push_field(
            &mut encoded,
            core.window.observed_to_ms.to_string().as_str(),
        );
        push_field(&mut encoded, &core.window.environment_ref);
        push_field(&mut encoded, &core.window.platform_ref);
        push_field(&mut encoded, &core.window.toolchain_ref);
        push_field(&mut encoded, &core.metric.metric_ref);
        push_field(
            &mut encoded,
            format!("{:016x}", core.metric.value.to_bits()).as_str(),
        );
        push_field(&mut encoded, &core.metric.unit_ref);
        push_field(&mut encoded, &core.metric.normalization_ref);
        push_field(&mut encoded, &core.metric.population_ref);
        push_field(&mut encoded, format!("{:?}", core.metric.presence).as_str());
        push_field(&mut encoded, format!("{:?}", core.completeness).as_str());
        push_field(&mut encoded, format!("{:?}", core.status).as_str());
        push_sorted_refs(&mut encoded, &core.counterevidence_refs);
        push_sorted_refs(&mut encoded, &core.confounder_refs);
        push_sorted_refs(&mut encoded, &core.intervention_refs);
    }
    for record in &input.prior_history {
        push_field(&mut encoded, &record.diagnosis_ref);
        push_field(&mut encoded, &record.intervention_ref);
        push_field(
            &mut encoded,
            format!("{:?}", record.intervention_state).as_str(),
        );
        push_field(&mut encoded, format!("{:?}", record.recurrence).as_str());
        push_field(
            &mut encoded,
            format!("{:?}", record.hypothesis_status).as_str(),
        );
        push_field(&mut encoded, &record.source_ref);
        push_field(&mut encoded, &record.configuration_ref);
        push_field(&mut encoded, &record.environment_ref);
        push_field(&mut encoded, record.observed_at_ms.to_string().as_str());
    }
    push_field(&mut encoded, &input.policy.policy_ref);
    push_field(&mut encoded, &input.policy.schema_ref);
    push_field(&mut encoded, &input.policy.revision_ref);
    push_field(&mut encoded, &input.policy.rules_digest);
    push_field(&mut encoded, &input.ceilings.privacy_ceiling_ref);
    push_field(&mut encoded, &input.ceilings.authority_ceiling_ref);
    push_field(&mut encoded, &input.ceilings.proof_ceiling_ref);
    for value in [
        input.denominator.expected_dimensions,
        input.denominator.supplied_dimensions,
        input.denominator.expected_sources,
        input.denominator.supplied_sources,
        input.denominator.expected_members,
        input.denominator.supplied_members,
    ] {
        push_field(&mut encoded, value.to_string().as_str());
    }
    push_field(
        &mut encoded,
        format!("{:?}", input.denominator.completeness).as_str(),
    );
    push_field(&mut encoded, input.created_at_ms.to_string().as_str());
    fnv1a64_hex(encoded.as_bytes())
}

/// Deterministic digest of one policy (lowercase hex, FNV-1a 64).
#[must_use]
pub fn digest_policy(policy: &SelfQualityPolicy) -> String {
    let mut encoded = String::from("sqp1");
    push_field(
        &mut encoded,
        SELF_QUALITY_CONTRACT_VERSION.to_string().as_str(),
    );
    push_field(&mut encoded, &policy.policy_ref);
    push_field(&mut encoded, &policy.schema_ref);
    push_field(&mut encoded, &policy.revision_ref);
    push_field(&mut encoded, &policy.rules_digest);
    for value in [
        u64::from(policy.limits.max_observations),
        u64::from(policy.limits.max_history),
        u64::from(policy.limits.max_handoffs),
        policy.limits.max_bytes,
        u64::from(policy.limits.max_depth),
        policy.limits.max_work_units,
        u64::from(policy.limits.max_output_refs),
        policy.limits.max_time_ms,
    ] {
        push_field(&mut encoded, value.to_string().as_str());
    }
    fnv1a64_hex(encoded.as_bytes())
}

/// Deterministic digest of one candidate's content (lowercase hex, FNV-1a 64).
#[must_use]
pub fn digest_candidate(candidate: &SelfQualityDiagnosisCandidate) -> String {
    let mut encoded = String::from("sqc1");
    push_field(&mut encoded, &candidate.candidate_ref);
    push_field(&mut encoded, &candidate.input_digest);
    push_field(&mut encoded, &candidate.policy_digest);
    let mut outcomes = candidate.outcomes.clone();
    outcomes.sort_by_key(|outcome| outcome.dimension);
    for outcome in &outcomes {
        push_field(&mut encoded, format!("{:?}", outcome.dimension).as_str());
        push_field(&mut encoded, format!("{:?}", outcome.status).as_str());
        push_field(&mut encoded, format!("{:?}", outcome.severity).as_str());
        push_field(&mut encoded, format!("{:?}", outcome.priority).as_str());
        push_field(&mut encoded, format!("{:?}", outcome.hypothesis).as_str());
        push_field(&mut encoded, format!("{:?}", outcome.recurrence).as_str());
    }
    push_field(
        &mut encoded,
        format!("{:?}", candidate.overall_severity).as_str(),
    );
    push_field(
        &mut encoded,
        format!("{:?}", candidate.overall_priority).as_str(),
    );
    push_sorted_refs(&mut encoded, &candidate.symptom_refs);
    push_sorted_refs(&mut encoded, &candidate.mechanism_refs);
    push_sorted_refs(&mut encoded, &candidate.counterevidence_refs);
    let mut handoffs: Vec<&SelfQualityHandoff> = candidate.handoffs.iter().collect();
    handoffs.sort_by(|left, right| left.handoff_ref.cmp(&right.handoff_ref));
    for handoff in handoffs {
        push_field(&mut encoded, &handoff.handoff_ref);
        push_field(&mut encoded, format!("{:?}", handoff.owner).as_str());
    }
    push_field(&mut encoded, candidate.expires_at_ms.to_string().as_str());
    fnv1a64_hex(encoded.as_bytes())
}

const fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Negligible => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

const fn priority_rank(priority: Priority) -> u8 {
    match priority {
        Priority::None => 0,
        Priority::Low => 1,
        Priority::Medium => 2,
        Priority::High => 3,
        Priority::Urgent => 4,
    }
}

fn validate_denominator_counts(input: &SelfQualityInput) -> Result<(), SelfQualityContractError> {
    let mut dimensions = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for observation in &input.observations {
        dimensions.insert(observation.core().dimension);
        sources.insert(observation.core().owner.owner_ref.clone());
    }
    let actual = (
        u32::try_from(dimensions.len()).unwrap_or(u32::MAX),
        u32::try_from(sources.len()).unwrap_or(u32::MAX),
        u32::try_from(input.observations.len()).unwrap_or(u32::MAX),
    );
    if input.denominator.supplied_dimensions != actual.0
        || input.denominator.supplied_sources != actual.1
        || input.denominator.supplied_members != actual.2
    {
        return Err(SelfQualityContractError::InvalidDenominator {
            reason: "supplied counts must equal the actual snapshot counts",
        });
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), SelfQualityContractError> {
    if value.is_empty() {
        return Err(SelfQualityContractError::InvalidText {
            field,
            reason: "must not be empty",
        });
    }
    if value.trim() != value {
        return Err(SelfQualityContractError::InvalidText {
            field,
            reason: "must not contain leading or trailing whitespace",
        });
    }
    if value.len() > MAX_SELF_QUALITY_TEXT_BYTES {
        return Err(SelfQualityContractError::InvalidText {
            field,
            reason: "exceeds the maximum UTF-8 byte length",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(SelfQualityContractError::InvalidText {
            field,
            reason: "must not contain control characters",
        });
    }
    if is_protected_default(value) {
        return Err(SelfQualityContractError::ProtectedDefault { field });
    }
    Ok(())
}

fn is_protected_default(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "default" | "changeme" | "todo" | "tbd" | "xxx" | "unknown_default" | "protected_default"
    )
}

fn validate_hex_digest(field: &'static str, value: &str) -> Result<(), SelfQualityContractError> {
    if value.len() < MIN_SELF_QUALITY_DIGEST_BYTES || value.len() > MAX_SELF_QUALITY_DIGEST_BYTES {
        return Err(SelfQualityContractError::InvalidDigest { field });
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SelfQualityContractError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_ref_set(
    field: &'static str,
    values: &[String],
) -> Result<(), SelfQualityContractError> {
    if values.len() > MAX_SELF_QUALITY_REFS {
        return Err(SelfQualityContractError::CollectionTooLarge {
            field,
            maximum: MAX_SELF_QUALITY_REFS,
            actual: values.len(),
        });
    }
    for value in values {
        validate_text(field, value)?;
    }
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(SelfQualityContractError::DuplicateValue {
                field,
                value: pair[0].clone(),
            });
        }
        if pair[0] > pair[1] {
            return Err(SelfQualityContractError::NonCanonicalCollection { field });
        }
    }
    Ok(())
}

fn push_field(encoded: &mut String, value: &str) {
    encoded.push('\x1f');
    encoded.push_str(value);
}

fn push_sorted_refs(encoded: &mut String, values: &[String]) {
    let mut sorted: Vec<&str> = values.iter().map(String::as_str).collect();
    sorted.sort();
    for value in sorted {
        push_field(encoded, value);
    }
}

fn fnv1a64_hex(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}
