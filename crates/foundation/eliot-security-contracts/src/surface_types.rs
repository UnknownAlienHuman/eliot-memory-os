//! Wire shapes for source assurance, disclosure, influence, purge and selection.

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Origin and use assurance for one immutable source observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAssurance {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement for the source snapshot.
    pub integrity: IntegrityStatus,
    /// Freshness relative to the current scope.
    pub freshness: FreshnessStatus,
    /// Domain competence classification.
    pub competence: CompetenceLevel,
    /// Independence from the decision route.
    pub independence: IndependenceLevel,
    /// Privacy sensitivity of the source.
    pub privacy_class: PrivacyClass,
    /// Instruction taint carried by source content.
    pub instruction_taint: InstructionTaint,
    /// Allowed epistemic uses, never an authority grant.
    pub allowed_epistemic_use: Vec<EpistemicUse>,
    /// Bounded effect ceilings for derived consumers.
    pub allowed_effects: Vec<EffectCeiling>,
    /// Required verifier or explicit empty marker.
    pub required_verifier: Option<String>,
    /// Quarantine/review state.
    pub quarantine: QuarantineState,
    /// Current source fence.
    pub state_fence: StateFence,
}

/// Integrity of the source snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityStatus {
    Verified,
    Unverified,
    Modified,
    Conflicted,
}

/// Freshness of a source relative to a state fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FreshnessStatus {
    Current,
    Stale,
    Unknown,
}

/// Bounded competence classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompetenceLevel {
    DomainVerified,
    Attributed,
    Unknown,
}

/// Whether the source is independent of the evaluated route.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependenceLevel {
    Independent,
    Related,
    CommonMode,
    Unknown,
}

/// Privacy class attached to a source domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrivacyClass {
    Public,
    Internal,
    Private,
    Secret,
    Licensed,
}

/// Instruction/data taint is independent from epistemic truth.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InstructionTaint {
    Cleared,
    DataOnly,
    Untrusted,
    CommandLike,
}

/// Permitted epistemic interpretation of a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicUse {
    Observation,
    AttributedInput,
    CandidateEvidence,
    VerificationInput,
}

/// Maximum effect class a consumer may propose from a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectCeiling {
    ReadOnly,
    CandidateOnly,
    NoExternalEffect,
}

/// Reversible source quarantine state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QuarantineState {
    None,
    ReviewRequired,
    Quarantined,
    Released,
}

/// Policy-sized observation domain; IDs are opaque and non-revealing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationDomainRef {
    pub domain_id: String,
    pub kind: ObservationDomainKind,
    pub authority_root: String,
    pub resource_scope: String,
    pub privacy_class: PrivacyClass,
    pub visibility_and_export_rule: String,
    pub model_route_rule: String,
    pub state_fence: StateFence,
}

/// Domain category used by disclosure policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObservationDomainKind {
    LocalRoot,
    ConnectedResource,
    UserPrivate,
    Tenant,
    SecretClass,
    ProviderRetention,
    LicensedSource,
    Custom,
}

/// Coverage status of a disclosure closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClosureCompleteness {
    Complete,
    Partial,
    Unknown,
}

/// Explicit domain lineage for one subject or derived representation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureDependencyClosure {
    pub closure_id: String,
    pub subject_ref: String,
    pub direct_domain_refs: Vec<ObservationDomainRef>,
    pub inherited_closure_refs: Vec<String>,
    pub derivation_or_transformation_refs: Vec<String>,
    pub completeness: ClosureCompleteness,
    pub declassification_receipt_refs: Vec<String>,
    pub policy_snapshot_id: String,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Decision made against a closure and recipient capability set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureDecision {
    pub subject_and_closure_ref: String,
    pub recipient_principal_or_route: String,
    pub recipient_capability_set: Vec<String>,
    pub covered_domains: Vec<String>,
    pub uncovered_domains: Vec<String>,
    pub decision: DisclosureDecisionKind,
    pub policy_snapshot_and_state_fence: PolicyFence,
    pub receipt_ref: String,
    pub closure_completeness: ClosureCompleteness,
}

/// Outcome of disclosure admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisclosureDecisionKind {
    Allow,
    AllowRedacted,
    RecomputeNarrower,
    ForkPrivate,
    RequireAuthority,
    Deny,
}

/// Policy revision and state fence used by a disclosure decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyFence {
    pub policy_snapshot_id: String,
    pub state_fence: StateFence,
}

/// Verified deterministic transformation that may remove a domain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeclassificationReceipt {
    pub input_closure_ref: String,
    pub transformation_id_and_version: String,
    pub exact_input_hash: String,
    pub exact_output_hash: String,
    pub removed_or_generalized_domains: Vec<String>,
    pub preserved_domains: Vec<String>,
    pub verifier_and_property: String,
    pub residual_limitations: Vec<String>,
    pub authority_and_policy_ref: String,
    pub state_fence: StateFence,
}

/// Transformation lineage retaining input taint unless explicitly cleared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransformationLineage {
    pub transformation_id: String,
    pub input_refs: Vec<String>,
    pub output_ref: String,
    pub operation: TransformationKind,
    pub input_taint: InstructionTaint,
    pub output_taint: InstructionTaint,
    pub declassification_receipt_ref: Option<String>,
    pub state_fence: StateFence,
}

/// Structural transform categories relevant to taint laundering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransformationKind {
    Copy,
    Normalize,
    ModelSummary,
    Redact,
    Declassify,
    Aggregate,
}

/// Explicit influence dependency closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfluenceDependencyClosure {
    pub closure_id: String,
    pub root_ref: String,
    pub dependent_refs: Vec<String>,
    pub invalidation_reason: Option<RevocationReason>,
    pub current_influence: InfluenceState,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Current support/influence state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceState {
    Active,
    Quarantined,
    Revoked,
    Unknown,
}

/// Why an origin or dependency was invalidated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    SourceRevoked,
    WrongScope,
    Poisoned,
    VerifierInvalid,
    PolicyChanged,
    Erasure,
}

/// Explicit purge ledger entry; it carries no deleted content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PurgeLedgerEntry {
    pub purge_id: String,
    pub subject_ref: String,
    pub scope: String,
    pub purged_locations: Vec<PurgeLocation>,
    pub tombstone_digest: String,
    pub state: PurgeState,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Location to which an erasure obligation applies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PurgeLocation {
    CanonicalPayload,
    Projection,
    Index,
    Blob,
    OperationalRecovery,
    ProviderCopy,
    BackupRestorePath,
    RouteContinuation,
}

/// Purge lifecycle; terminal purged state cannot be restored as current data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PurgeState {
    Requested,
    InProgress,
    Purged,
    Blocked,
}

/// Receipt of candidate-set membership through all selection transformations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionIntegrityReceipt {
    pub selection_id: String,
    pub initial_candidate_refs: Vec<String>,
    pub admitted_candidate_refs: Vec<String>,
    pub rejected_candidate_refs: Vec<String>,
    pub transformation_stages: Vec<SelectionStage>,
    pub final_output_refs: Vec<String>,
    pub untrusted_structure_changed_membership: bool,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// One selection-transforming stage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionStage {
    pub stage: SelectionStageKind,
    pub input_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub disclosure_closure_ref: String,
    pub state_fence: StateFence,
}

/// Stage categories for selection-integrity lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionStageKind {
    GraphPivot,
    ClusterExpansion,
    Rerank,
    Prune,
    Summary,
    ContextCompile,
    ToolExport,
}
