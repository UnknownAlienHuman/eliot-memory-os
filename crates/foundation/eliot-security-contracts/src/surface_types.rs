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

/// Stable schema identity of the versioned selection-integrity receipt family.
pub const SELECTION_INTEGRITY_SCHEMA: &str =
    "eliot.foundation.security-contracts.selection-integrity.v2";
/// Maximum stages one selection-integrity chain may declare.
pub const MAX_SELECTION_STAGES: usize = 64;
/// Maximum members one selection-integrity membership collection may declare.
pub const MAX_SELECTION_MEMBERS: usize = 4_096;
/// One-way disposition for a legacy unversioned selection receipt.
pub const SELECTION_INTEGRITY_LEGACY_V1_DISPOSITION: &str = concat!(
    "imported-as-unknown: a legacy receipt-level untrusted_structure_changed_membership=false ",
    "is absence of the old flag only, never proven absence of stage influence; a legacy stage ",
    "output that was not a legacy stage input is not attributable to any input member and is ",
    "rejected"
);

/// Closed untrusted-influence state of one stage or of the whole chain.
///
/// Declaration order is the claim-ceiling order: `Absent` is the strongest and
/// `Unknown` the weakest statement. I12.13 `Selection integrity` makes `unknown`
/// an admissible finding that lowers the claim ceiling of the dependent packet;
/// it never becomes `Absent` by assumption, and a later deterministic stage
/// cannot erase an earlier `Present` or `Unknown`.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionInfluenceState {
    /// Untrusted input provably did not change this membership.
    Absent,
    /// Untrusted input changed this membership and the change is recorded.
    Present,
    /// The producer cannot state whether untrusted input changed this membership.
    Unknown,
}

/// One hashed selection member: identity, revision and representation.
///
/// A membership digest binds these three fields in declared order, so it also
/// preserves the order a ranking or presentation boundary produced. Display
/// labels and counts are never hashed in their place.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionMember {
    /// Opaque member identity.
    pub member_ref: String,
    /// Exact member revision observed at this stage boundary.
    pub member_revision: String,
    /// Exact representation handed to or produced by the transformer.
    pub representation_ref: String,
}

/// What one stage did to one member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelectionMemberDispositionKind {
    /// Carried forward unchanged into this stage's output membership.
    Retained,
    /// Left the membership; a reason is required.
    Removed,
    /// Folded into a derived output that took its place in the membership.
    Derived,
    /// Introduced during expansion from named admitted source evidence.
    Admitted,
}

/// One per-member disposition row.
///
/// `Removed` requires `reason`; `Derived` requires `derived_output_ref`; and
/// `Admitted` requires `source_evidence_ref`. A field that does not belong to
/// the disposition is absent, never an empty string.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionMemberDisposition {
    /// The input member, or the newly admitted output member, this row accounts for.
    pub member_ref: String,
    /// What the stage did to that member.
    pub disposition: SelectionMemberDispositionKind,
    /// Why the member left the membership.
    pub reason: Option<String>,
    /// Derived output that took the member's place in the membership.
    pub derived_output_ref: Option<String>,
    /// Admitted source evidence that introduced the member.
    pub source_evidence_ref: Option<String>,
}

/// How one stage's input membership was derived from earlier stages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "link", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SelectionStageLink {
    /// The input is the complete output membership of the named stage.
    FromPredecessor {
        /// Stable identity of the immediately preceding stage.
        predecessor_stage_id: String,
    },
    /// The input is the complete union of the named parents' output memberships.
    FromJoin {
        /// Stable identities of every parent stage of the join.
        parent_stage_ids: Vec<String>,
    },
}

/// One immutable selection-transforming stage.
///
/// A stage appends to the chain and never overwrites an earlier membership
/// decision (I12.13 `Selection integrity`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionStage {
    /// Stable stage identity; content recorded under one identity is immutable.
    pub stage_id: String,
    /// Contiguous zero-based position of this stage in the chain.
    pub ordinal: usize,
    /// Derivation of the input membership; absent exactly at ordinal zero.
    pub input_link: Option<SelectionStageLink>,
    /// Stage category.
    pub stage: SelectionStageKind,
    /// Exact transformer identity and configuration revision.
    pub transformer_identity_and_config_revision: String,
    /// Input membership in the exact order the transformer received it.
    pub input_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical input membership.
    pub input_digest: String,
    /// Output membership in the exact order the transformer emitted it.
    pub output_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical output membership.
    pub output_digest: String,
    /// Exactly one row per input member, plus one row that explains every
    /// output member this stage introduced through a `Derived` or `Admitted`
    /// relation.
    pub member_dispositions: Vec<SelectionMemberDisposition>,
    /// Counterevidence or minority items this stage suppressed.
    pub suppressed_counterevidence_refs: Vec<String>,
    /// Budget or policy forced omissions this stage made.
    pub budget_or_policy_omission_refs: Vec<String>,
    /// Closed untrusted-influence state of this stage.
    pub untrusted_input_influenced_membership: SelectionInfluenceState,
    /// Evidence backing a `Present` or `Unknown` influence statement.
    pub influence_evidence_refs: Vec<String>,
    pub disclosure_closure_ref: String,
    pub state_fence: StateFence,
}

/// Receipt of candidate-set membership through all selection transformations.
///
/// The receipt records history, not permission. A well-formed record of known or
/// unknown untrusted influence validates so it can be audited; whether that
/// history may be relied on is a separate policy decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelectionIntegrityReceipt {
    /// Closed schema identity of this receipt family.
    pub schema: String,
    /// Contract version this receipt was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Chain identity of this selection history.
    pub selection_id: String,
    /// Shared root context this chain was compiled for.
    pub root_context_ref: String,
    /// Exact versioned context recipe revision that produced the chain.
    pub recipe_revision: String,
    /// Immutable initial candidate membership in retrieval order.
    pub initial_candidate_members: Vec<SelectionMember>,
    /// Lowercase SHA-256 over the canonical initial candidate membership.
    pub initial_candidate_digest: String,
    pub admitted_candidate_refs: Vec<String>,
    pub rejected_candidate_refs: Vec<String>,
    pub transformation_stages: Vec<SelectionStage>,
    /// Final membership. Empty is a legitimate all-rejected result.
    pub final_output_refs: Vec<String>,
    /// Chain influence ceiling; it may never be weaker than any stage state.
    pub chain_untrusted_influence: SelectionInfluenceState,
    pub state_fence: StateFence,
    pub revision: u64,
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

/// Exact pre-migration v1 selection receipt wire.
///
/// v1 carried one receipt-level `untrusted_structure_changed_membership` Boolean
/// and stages with no identity, ordinal, digest, per-member disposition or
/// influence state. Old bytes deserialize here explicitly and are never
/// reinterpreted as a stage-continuous chain; see
/// [`SELECTION_INTEGRITY_LEGACY_V1_DISPOSITION`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacySelectionIntegrityReceiptV1 {
    pub selection_id: String,
    pub initial_candidate_refs: Vec<String>,
    pub admitted_candidate_refs: Vec<String>,
    pub rejected_candidate_refs: Vec<String>,
    pub transformation_stages: Vec<LegacySelectionStageV1>,
    pub final_output_refs: Vec<String>,
    pub untrusted_structure_changed_membership: bool,
    pub state_fence: StateFence,
    pub revision: u64,
}

/// Exact pre-migration v1 stage wire, which recorded no member relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacySelectionStageV1 {
    pub stage: SelectionStageKind,
    pub input_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub disclosure_closure_ref: String,
    pub state_fence: StateFence,
}
