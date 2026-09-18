//! Finite erasure-scope contract skeleton (issue #1130, contract-only).
//!
//! This module freezes the *scope* of one admitted erasure operation before any
//! destructive effect: the closed target denominator, per-target owner and
//! disposition, holds, approvals, sequencing intent, and identity rules. It is
//! pure types plus [`ErasureScopeSnapshot::validate`] plus a canonical digest.
//! No I/O, no Store/Blob/Governor/Kernel writes.
//!
//! Explicit typed gaps (escalations, not invention) are encoded as `Option`
//! refs documented with their missing vocabulary; [`ErasureScopeSnapshot::validate`]
//! fails closed wherever a gap would otherwise become a proof claim.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_security_contracts::PurgeLocation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// One of the closed 7 erasure-target families.
///
/// Canonical payload denominator from `I05-14-retention-and-erasure.md:3-13`
/// (`I15-14-privacy-erasure.md`, `A12-08-privacy-erasure.md:3` carry the same
/// set): canonical payload; derived projections/indexes; blob store; ORS
/// pending copies; backup catalog and future restore path; Route Continuation
/// State; provider-side data when the API supports deletion.
///
/// The 7 families cover the 8 [`PurgeLocation`] variants read-only (the
/// derived family maps to both `Projection` and `Index`); this type never
/// redefines that enum.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErasureFamily {
    CanonicalPayload,
    DerivedProjectionsIndexes,
    BlobStore,
    OrsPendingCopies,
    BackupCatalogAndRestorePath,
    RouteContinuationState,
    ProviderSideData,
}

impl ErasureFamily {
    /// All 7 families of the closed denominator, in canonical order.
    pub const ALL: [Self; 7] = [
        Self::CanonicalPayload,
        Self::DerivedProjectionsIndexes,
        Self::BlobStore,
        Self::OrsPendingCopies,
        Self::BackupCatalogAndRestorePath,
        Self::RouteContinuationState,
        Self::ProviderSideData,
    ];

    /// Exact enforceable [`PurgeLocation`] variants for this family.
    ///
    /// Read-only reference into `eliot-security-contracts`
    /// (`surface_types.rs:311-320`); the derived family is the only one
    /// covering two locations.
    #[must_use]
    pub const fn locations(&self) -> &'static [PurgeLocation] {
        match self {
            Self::CanonicalPayload => &[PurgeLocation::CanonicalPayload],
            Self::DerivedProjectionsIndexes => &[PurgeLocation::Projection, PurgeLocation::Index],
            Self::BlobStore => &[PurgeLocation::Blob],
            Self::OrsPendingCopies => &[PurgeLocation::OperationalRecovery],
            Self::BackupCatalogAndRestorePath => &[PurgeLocation::BackupRestorePath],
            Self::RouteContinuationState => &[PurgeLocation::RouteContinuation],
            Self::ProviderSideData => &[PurgeLocation::ProviderCopy],
        }
    }

    /// Owning effect boundary for this family.
    ///
    /// Mechanical owners bind at composition per #1130 ("How to do it" item 2:
    /// Governor admits, Kernel/ORS fences and orders, the sole Store/Blob
    /// owners execute payload/key effects); this label records which boundary
    /// a per-target effect belongs to without creating a second owner.
    #[must_use]
    pub const fn owner(&self) -> TargetOwner {
        match self {
            Self::CanonicalPayload => TargetOwner::CanonicalStore,
            Self::DerivedProjectionsIndexes => TargetOwner::DerivedProjectionIndex,
            Self::BlobStore => TargetOwner::BlobStore,
            Self::OrsPendingCopies => TargetOwner::OperationalRecovery,
            Self::BackupCatalogAndRestorePath => TargetOwner::BackupRestorePath,
            Self::RouteContinuationState => TargetOwner::RouteContinuation,
            Self::ProviderSideData => TargetOwner::ProviderAdapter,
        }
    }
}

/// Owning effect boundary of one scope target.
///
/// One label per [`ErasureFamily`]; [`ScopeTarget::validate`] rejects a target
/// whose owner differs from its family owner, so no effect can be claimed
/// under the wrong owner.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetOwner {
    CanonicalStore,
    DerivedProjectionIndex,
    BlobStore,
    OperationalRecovery,
    BackupRestorePath,
    RouteContinuation,
    ProviderAdapter,
}

/// Typed hold terms for a retention-blocked target.
///
/// `I05-14-retention-and-erasure.md:22`: the retention-blocked state records a
/// hold/policy reference plus next review or expiry while ordinary use remains
/// unavailable where policy permits. `I15-14-privacy-erasure.md:13`: retain a
/// non-revealing receipt where lawful.
///
/// Explicit gap: owner identity vocabulary, protected-minimum shape, and
/// inaccessible-influence state have no erasure-doc vocabulary, so they are
/// recorded as validated refs (or `None` when not declared) rather than
/// invented structures.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HoldTerms {
    /// Explicit hold owner ref (I05-14:22 hold/policy reference).
    pub holder_owner_ref: String,
    /// Legal basis ref for the hold.
    pub legal_basis_ref: String,
    /// Governing retention policy ref.
    pub policy_ref: String,
    /// Next review or expiry record ref (I05-14:22).
    pub review_or_expiry_ref: String,
    /// Protected-minimum record ref, when declared. `None` means the minimum
    /// was not declared — an explicit open gap, never an assumed empty set.
    pub protected_minimum_ref: Option<String>,
}

impl HoldTerms {
    fn validate(&self) -> Result<(), ScopeError> {
        text(&self.holder_owner_ref, "hold.holder_owner_ref")?;
        text(&self.legal_basis_ref, "hold.legal_basis_ref")?;
        text(&self.policy_ref, "hold.policy_ref")?;
        text(&self.review_or_expiry_ref, "hold.review_or_expiry_ref")?;
        if let Some(minimum) = &self.protected_minimum_ref {
            text(minimum, "hold.protected_minimum_ref")?;
        }
        Ok(())
    }
}

/// Per-target disposition.
///
/// Byte deletion, key destruction, and influence revocation are separate
/// observable outcomes; one cannot impersonate another (#1130 "How to do it").
/// `Redacted` carries only a non-revealing tombstone/purge ref and never
/// deleted content (I05-14:22). `RetentionBlocked` is the I05-14:22
/// `RETENTION_BLOCKED` axis as a typed hold — distinct from `Redacted`.
/// `UnavailableExternal` records the I15-14:15 notify-owner step for provider
/// APIs without deletion support. `UnknownOutcome` keeps an uncertain target
/// explicit per the generic ORS `UNKNOWN_OUTCOME` → `RECONCILING` rule
/// (`A13-06-operational-recovery-state.md:15`,
/// `I14-20-canonical-runtime-lifecycle-vocabulary.md:28-37`); it reconciles
/// the same target/effect identity before retry and never reads as complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(deny_unknown_fields)]
pub enum TargetDisposition {
    DeleteBytes,
    DestroyKey,
    RevokeInfluence,
    Redacted { tombstone_ref: String },
    RetentionBlocked(HoldTerms),
    UnavailableExternal { notify_owner_ref: String },
    UnknownOutcome { detail_ref: Option<String> },
}

impl TargetDisposition {
    fn validate(&self) -> Result<(), ScopeError> {
        match self {
            Self::DeleteBytes | Self::DestroyKey | Self::RevokeInfluence => Ok(()),
            Self::Redacted { tombstone_ref } => text(tombstone_ref, "disposition.tombstone_ref"),
            Self::RetentionBlocked(terms) => terms.validate(),
            Self::UnavailableExternal { notify_owner_ref } => {
                text(notify_owner_ref, "disposition.notify_owner_ref")
            }
            Self::UnknownOutcome { detail_ref } => {
                if let Some(detail) = detail_ref {
                    text(detail, "disposition.detail_ref")?;
                }
                Ok(())
            }
        }
    }

    /// Whether this disposition closes its target.
    ///
    /// Holds, unavailable-external, and unknown outcomes stay open, so
    /// [`ErasureScopeSnapshot::fully_dispositioned`] cannot report a false
    /// complete result (I05-14:22, I15-14:13, I15-14:15).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        match self {
            Self::DeleteBytes
            | Self::DestroyKey
            | Self::RevokeInfluence
            | Self::Redacted { .. } => true,
            Self::RetentionBlocked(_)
            | Self::UnavailableExternal { .. }
            | Self::UnknownOutcome { .. } => false,
        }
    }
}

/// One frozen denominator entry: family, exact location, owner, disposition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeTarget {
    pub family: ErasureFamily,
    pub location: PurgeLocation,
    pub owner: TargetOwner,
    pub disposition: TargetDisposition,
}

impl ScopeTarget {
    fn validate(&self) -> Result<(), ScopeError> {
        if !self.family.locations().contains(&self.location) {
            return Err(ScopeError::LocationOutsideFamily);
        }
        if self.owner != self.family.owner() {
            return Err(ScopeError::OwnerMismatch);
        }
        self.disposition.validate()
    }
}

/// Residency-domain binding.
///
/// Explicit typed gap: the erasure docs carry zero residency-domain vocabulary
/// (no hits in I05-14 / I15-14 / A12-08; T3.md:157-159 notes the same
/// absence), so there is no domain catalogue to bind against. `None` leaves
/// the gap open without claiming anything. `validate` fails closed on any
/// claim that this snapshot proves cross-domain co-residence — such a proof
/// cannot be expressed and is rejected rather than recorded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidencyBinding {
    /// Residency-domain record ref, when the residency owner defines one.
    /// A ref is recorded, never a proof.
    pub residency_domain_ref: Option<String>,
    /// Asserts this erasure proves co-residence across domains. Always
    /// rejected: no vocabulary exists to prove it (fail-closed, no invention).
    pub claims_cross_domain_coresidence: bool,
}

impl ResidencyBinding {
    fn validate(&self) -> Result<(), ScopeError> {
        if self.claims_cross_domain_coresidence {
            return Err(ScopeError::UnsupportedResidencyProof);
        }
        if let Some(domain) = &self.residency_domain_ref {
            text(domain, "residency.residency_domain_ref")?;
        }
        Ok(())
    }
}

/// Data-scope class determining the approving owner.
///
/// `I15-14-privacy-erasure.md:3`: System Owner for installation data,
/// `WorkScope` Owner / authorized Human for scope data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataScopeClass {
    InstallationData,
    WorkScopeData,
}

impl DataScopeClass {
    /// Owner rule from I15-14:3, enforced by [`ApprovalBinding::validate`].
    #[must_use]
    pub const fn permits(&self, approver: &ApproverKind) -> bool {
        match (self, approver) {
            (Self::InstallationData, ApproverKind::SystemOwner)
            | (Self::WorkScopeData, ApproverKind::WorkScopeOwner | ApproverKind::AuthorizedHuman) => {
                true
            }
            (Self::InstallationData, _) | (Self::WorkScopeData, ApproverKind::SystemOwner) => false,
        }
    }
}

/// Who approved the erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApproverKind {
    SystemOwner,
    WorkScopeOwner,
    AuthorizedHuman,
}

/// Approval binding for one erasure scope.
///
/// Explicit gap: the approval packet shape (verifiers, deadline, fence
/// binding) has no erasure-doc vocabulary, so this type keeps the existing
/// `approval_digest: String` binding (64 lowercase hex, same rule as
/// `ErasureRequest`) and carries required verifiers as refs on the snapshot.
/// No new crypto is invented.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub scope_class: DataScopeClass,
    pub approver_kind: ApproverKind,
    pub approver_ref: String,
    pub approval_digest: String,
}

impl ApprovalBinding {
    fn validate(&self) -> Result<(), ScopeError> {
        if !self.scope_class.permits(&self.approver_kind) {
            return Err(ScopeError::ApproverScopeMismatch);
        }
        text(&self.approver_ref, "approval.approver_ref")?;
        digest(&self.approval_digest, "approval.approval_digest")?;
        Ok(())
    }
}

/// The 8-step erasure process order.
///
/// `I15-14-privacy-erasure.md:8-15`: identify dependency/backup/provider
/// copies; stop new influence/access; create purge plan; remove
/// payload/projections/cache/ORS/provider copy; update restore purge ledger;
/// retain non-revealing receipt where lawful; verify absence/recovery
/// behavior; notify owner of unavailable external deletion.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErasureSequenceStep {
    IdentifyCopies,
    StopNewInfluence,
    CreatePurgePlan,
    RemovePayloadAndCopies,
    UpdateRestorePurgeLedger,
    RetainNonRevealingReceipt,
    VerifyAbsence,
    NotifyOwnerOfUnavailable,
}

impl ErasureSequenceStep {
    /// Frozen 8-step order; the tombstone commits before
    /// `RemovePayloadAndCopies` (purge-ledger-before-cutover, A12-08:5;
    /// no-resurrection, I05-14:24).
    pub const ORDERED: [Self; 8] = [
        Self::IdentifyCopies,
        Self::StopNewInfluence,
        Self::CreatePurgePlan,
        Self::RemovePayloadAndCopies,
        Self::UpdateRestorePurgeLedger,
        Self::RetainNonRevealingReceipt,
        Self::VerifyAbsence,
        Self::NotifyOwnerOfUnavailable,
    ];

    /// Position of this step in [`Self::ORDERED`].
    #[must_use]
    pub fn ordinal(&self) -> usize {
        Self::ORDERED
            .iter()
            .position(|step| step == self)
            .unwrap_or(usize::MAX)
    }
}

/// Observable child-effect kind for one derived effect identity.
///
/// One child effect identity per canonical redaction/revocation, Blob
/// deletion, key destruction, index/cache removal, derivative influence
/// revocation, and external/provider withdrawal (#1130 "How to do it").
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectKind {
    CanonicalRedaction,
    BlobDeletion,
    KeyDestruction,
    IndexCacheRemoval,
    InfluenceRevocation,
    ExternalWithdrawal,
}

/// Child effect identity: shape only, not catalogue binding.
///
/// The versioned closure query plus per-owner child packet come from this
/// owner (T1.md:397, T3.md:206); until that catalogue exists this type defines
/// only the identity shape `(erasure_id, target_ordinal, effect_kind)` so
/// reconciliation can name the exact target/effect being retried without
/// inventing packet contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChildEffectId {
    pub erasure_id: String,
    pub target_ordinal: u32,
    pub effect_kind: EffectKind,
}

impl ChildEffectId {
    /// Constructs the identity shape for one frozen target ordinal.
    /// Pure naming; performs no lookup and binds no catalogue.
    pub fn for_target(
        erasure_id: &str,
        target_ordinal: u32,
        effect_kind: EffectKind,
    ) -> Result<Self, ScopeError> {
        text(erasure_id, "child_effect.erasure_id")?;
        Ok(Self {
            erasure_id: erasure_id.to_string(),
            target_ordinal,
            effect_kind,
        })
    }

    /// Derives exactly one child effect identity per frozen snapshot target.
    ///
    /// The caller supplies one [`EffectKind`] per target in snapshot order, so
    /// this constructor enforces the one-identity-per-target denominator
    /// without inventing a location-to-kind catalogue: byte deletion, key
    /// destruction, canonical redaction, index/cache removal, influence
    /// revocation and external withdrawal stay distinct because the caller
    /// names a distinct kind per target. A length mismatch, an invalid
    /// snapshot, or an ordinal overflow fails closed; the returned vector is
    /// in target order so reconciliation retries the same
    /// `(erasure_id, target_ordinal)` without duplication or skipping.
    pub fn for_snapshot(
        snapshot: &ErasureScopeSnapshot,
        kinds: &[EffectKind],
    ) -> Result<Vec<Self>, ScopeError> {
        snapshot.validate()?;
        if kinds.len() != snapshot.targets.len() {
            return Err(ScopeError::EffectDenominatorMismatch);
        }
        let mut effects = Vec::with_capacity(snapshot.targets.len());
        for (ordinal, kind) in kinds.iter().enumerate() {
            let target_ordinal: u32 =
                u32::try_from(ordinal).map_err(|_| ScopeError::EffectDenominatorMismatch)?;
            effects.push(Self::for_target(
                &snapshot.erasure_id,
                target_ordinal,
                *kind,
            )?);
        }
        Ok(effects)
    }
}

/// Frozen erasure scope for one admitted operation (contract shapes only).
///
/// Freezes, before mutation (#1130 "How to do it"): request
/// principal/authority, purpose/legal basis, target identities, current
/// source/derivative graph revision, privacy/retention domain, key/blob
/// owners (per-target [`TargetOwner`]), legal holds (per-target
/// [`TargetDisposition::RetentionBlocked`]), required verifiers as refs (packet
/// shape is an explicit gap, see [`ApprovalBinding`]), deadline as a ref (no
/// clock semantics invented), and the invalidation set. Fence/epoch binding
/// reuses [`StateFence`]; receipts stay immutable per
/// `I05-19-write-submission-execution-and-receipts.md:61-63`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErasureScopeSnapshot {
    pub erasure_id: String,
    pub subject_ref: String,
    pub principal_ref: String,
    pub authority_ref: String,
    pub purpose_ref: String,
    pub legal_basis_ref: String,
    /// Frozen target/derivative denominator with per-target owner+disposition.
    /// Must cover all 7 [`ErasureFamily`] variants exactly once per location.
    pub targets: Vec<ScopeTarget>,
    /// Frozen source/derivative graph revision the denominator was computed at.
    pub graph_revision: u64,
    /// Frozen subject/scope revision the request was admitted against; binds
    /// to `ErasureRequest.expected_revision` (I05-19: revalidate revisions).
    pub subject_revision: u64,
    pub privacy_retention_domain_ref: String,
    pub residency: ResidencyBinding,
    pub approval: ApprovalBinding,
    /// Required verifiers as refs; packet shape is an explicit gap.
    pub required_verifier_refs: Vec<String>,
    /// Deadline record ref; `None` leaves deadline unbound rather than
    /// inventing clock semantics.
    pub deadline_ref: Option<String>,
    pub state_fence: StateFence,
    pub invalidation_set: Vec<String>,
    /// Frozen process order; must equal [`ErasureSequenceStep::ORDERED`].
    pub planned_order: Vec<ErasureSequenceStep>,
}

impl ErasureScopeSnapshot {
    /// Fail-closed validation of the frozen scope.
    pub fn validate(&self) -> Result<(), ScopeError> {
        text(&self.erasure_id, "erasure_id")?;
        text(&self.subject_ref, "subject_ref")?;
        text(&self.principal_ref, "principal_ref")?;
        text(&self.authority_ref, "authority_ref")?;
        text(&self.purpose_ref, "purpose_ref")?;
        text(&self.legal_basis_ref, "legal_basis_ref")?;
        text(
            &self.privacy_retention_domain_ref,
            "privacy_retention_domain_ref",
        )?;
        if self.targets.is_empty() {
            return Err(ScopeError::EmptyDenominator);
        }
        let mut seen_locations: Vec<(ErasureFamily, PurgeLocation)> = Vec::new();
        let mut seen_families = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if seen_locations.contains(&(target.family, target.location)) {
                return Err(ScopeError::DuplicateTarget);
            }
            seen_locations.push((target.family, target.location));
            seen_families.insert(target.family);
        }
        for family in ErasureFamily::ALL {
            if !seen_families.contains(&family) {
                return Err(ScopeError::MissingFamily);
            }
        }
        self.residency.validate()?;
        self.approval.validate()?;
        let mut seen_verifiers = BTreeSet::new();
        for verifier in &self.required_verifier_refs {
            text(verifier, "required_verifier_refs")?;
            if !seen_verifiers.insert(verifier) {
                return Err(ScopeError::DuplicateVerifier);
            }
        }
        if let Some(deadline) = &self.deadline_ref {
            text(deadline, "deadline_ref")?;
        }
        self.state_fence
            .validate()
            .map_err(|_| ScopeError::InvalidField("state_fence"))?;
        let mut seen_invalidations = BTreeSet::new();
        for entry in &self.invalidation_set {
            text(entry, "invalidation_set")?;
            if !seen_invalidations.insert(entry) {
                return Err(ScopeError::DuplicateInvalidation);
            }
        }
        if self.planned_order.as_slice() != ErasureSequenceStep::ORDERED {
            return Err(ScopeError::StepOrderViolation);
        }
        Ok(())
    }

    /// Canonical digest of the frozen scope (same canonical-JSON + SHA-256
    /// rule as `ErasureRequest::request_digest`).
    pub fn scope_digest(&self) -> Result<String, ScopeError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self).map_err(|_| ScopeError::Canonicalization)?;
        Ok(sha256_hex(&bytes))
    }

    /// Identity rule: exact replay of the same `erasure_id` with identical
    /// frozen content is idempotent; changed scope/graph/hold/purpose/target
    /// under one erasure identity is `IDENTITY_CONFLICT` (#1130 "How to do
    /// it"); comparing across different identities is a caller error.
    pub fn check_identity_conflict(&self, other: &Self) -> Result<(), ScopeError> {
        if self.erasure_id != other.erasure_id {
            return Err(ScopeError::DifferentIdentity);
        }
        if self.scope_digest()? != other.scope_digest()? {
            return Err(ScopeError::IdentityConflict);
        }
        Ok(())
    }

    /// True only when every target carries a terminal disposition.
    ///
    /// Held, unavailable-external, and unknown targets keep this false so no
    /// caller can report complete erasure while targets remain open
    /// (I05-14:22, I15-14:13, I15-14:15).
    #[must_use]
    pub fn fully_dispositioned(&self) -> bool {
        self.targets
            .iter()
            .all(|target| target.disposition.is_terminal())
    }
}

fn text(value: &str, field: &'static str) -> Result<(), ScopeError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(ScopeError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn digest(value: &str, field: &'static str) -> Result<(), ScopeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ScopeError::InvalidField(field))
    }
}

/// Scope validation failures; every variant fails closed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("invalid erasure scope field: {0}")]
    InvalidField(&'static str),
    #[error("erasure scope has an empty target denominator")]
    EmptyDenominator,
    #[error("erasure scope is missing a target family from the closed denominator")]
    MissingFamily,
    #[error("erasure scope contains a duplicate target")]
    DuplicateTarget,
    #[error("erasure scope location is outside its family")]
    LocationOutsideFamily,
    #[error("erasure scope target owner does not match its family")]
    OwnerMismatch,
    #[error("erasure scope planned order is not the frozen 8-step order")]
    StepOrderViolation,
    #[error("erasure scope claims an unexpressible cross-domain co-residence proof")]
    UnsupportedResidencyProof,
    #[error("erasure scope approver kind does not match the data scope class")]
    ApproverScopeMismatch,
    #[error("erasure scope contains a duplicate verifier ref")]
    DuplicateVerifier,
    #[error("erasure scope contains a duplicate invalidation entry")]
    DuplicateInvalidation,
    #[error("erasure scope cannot be canonically serialized")]
    Canonicalization,
    #[error("erasure identity reuse with changed scope")]
    IdentityConflict,
    #[error("erasure identity comparison across different identities")]
    DifferentIdentity,
    #[error("erasure child-effect denominator does not match the frozen targets")]
    EffectDenominatorMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ErasureRequest;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        let lineage = match EpochLineageId::new(TEST_LINEAGE) {
            Ok(lineage) => lineage,
            Err(error) => panic!("valid test lineage: {error:?}"),
        };
        let Some(ordinal) = std::num::NonZeroU64::new(7) else {
            panic!("nonzero test epoch ordinal")
        };
        let epoch = match EpochId::new(lineage, ordinal) {
            Ok(epoch) => epoch,
            Err(error) => panic!("valid test epoch: {error:?}"),
        };
        let generation = match ResourceGeneration::new(3) {
            Ok(generation) => generation,
            Err(error) => panic!("valid test generation: {error:?}"),
        };
        StateFence::new(epoch, generation)
    }

    fn test_approval() -> ApprovalBinding {
        ApprovalBinding {
            scope_class: DataScopeClass::WorkScopeData,
            approver_kind: ApproverKind::WorkScopeOwner,
            approver_ref: "workscope-owner:test".to_string(),
            approval_digest: "ab".repeat(32),
        }
    }

    fn closed_targets() -> Vec<ScopeTarget> {
        let mut targets = Vec::new();
        for family in ErasureFamily::ALL {
            for location in family.locations() {
                targets.push(ScopeTarget {
                    family,
                    location: *location,
                    owner: family.owner(),
                    disposition: TargetDisposition::DeleteBytes,
                });
            }
        }
        targets
    }

    fn test_snapshot() -> ErasureScopeSnapshot {
        ErasureScopeSnapshot {
            erasure_id: "erasure-1130-a".to_string(),
            subject_ref: "subject:test".to_string(),
            principal_ref: "principal:test".to_string(),
            authority_ref: "authority:test".to_string(),
            purpose_ref: "purpose:test".to_string(),
            legal_basis_ref: "basis:test".to_string(),
            targets: closed_targets(),
            graph_revision: 11,
            subject_revision: 4,
            privacy_retention_domain_ref: "privacy-domain:test".to_string(),
            residency: ResidencyBinding {
                residency_domain_ref: None,
                claims_cross_domain_coresidence: false,
            },
            approval: test_approval(),
            required_verifier_refs: vec!["verifier:test-a".to_string()],
            deadline_ref: None,
            state_fence: test_fence(),
            invalidation_set: vec!["invalidation:test".to_string()],
            planned_order: ErasureSequenceStep::ORDERED.to_vec(),
        }
    }

    #[test]
    fn accepts_closed_seven_family_denominator_with_owner_and_disposition() {
        let snapshot = test_snapshot();
        assert!(snapshot.validate().is_ok());
        assert_eq!(snapshot.targets.len(), 8);
        for family in ErasureFamily::ALL {
            let Some(member) = snapshot
                .targets
                .iter()
                .find(|target| target.family == family)
            else {
                panic!("each family is represented")
            };
            assert_eq!(member.owner, family.owner());
            assert!(member.disposition.is_terminal());
        }
    }

    #[test]
    fn digest_is_stable_and_idempotent_for_exact_replay() {
        let first = test_snapshot();
        let replay = test_snapshot();
        let first_digest = match first.scope_digest() {
            Ok(digest) => digest,
            Err(error) => panic!("scope digest of first snapshot: {error:?}"),
        };
        let replay_digest = match replay.scope_digest() {
            Ok(digest) => digest,
            Err(error) => panic!("scope digest of replay snapshot: {error:?}"),
        };
        assert_eq!(first_digest, replay_digest);
        assert!(first.check_identity_conflict(&replay).is_ok());
    }

    #[test]
    fn rejects_empty_denominator() {
        let mut snapshot = test_snapshot();
        snapshot.targets.clear();
        assert_eq!(snapshot.validate(), Err(ScopeError::EmptyDenominator));
    }

    #[test]
    fn rejects_duplicate_and_unknown_targets() {
        let mut snapshot = test_snapshot();
        snapshot.targets.push(snapshot.targets[0].clone());
        assert_eq!(snapshot.validate(), Err(ScopeError::DuplicateTarget));

        let mut outside = test_snapshot();
        outside.targets[0].location = PurgeLocation::Blob;
        assert_eq!(outside.validate(), Err(ScopeError::LocationOutsideFamily));

        let mut missing = test_snapshot();
        missing
            .targets
            .retain(|target| target.family != ErasureFamily::ProviderSideData);
        assert_eq!(missing.validate(), Err(ScopeError::MissingFamily));

        let mut wrong_owner = test_snapshot();
        wrong_owner.targets[0].owner = TargetOwner::BlobStore;
        assert_eq!(wrong_owner.validate(), Err(ScopeError::OwnerMismatch));
    }

    #[test]
    fn hold_disposition_is_distinct_from_redacted_with_refs_and_expiry() {
        let redacted = TargetDisposition::Redacted {
            tombstone_ref: "tombstone:test".to_string(),
        };
        let held = TargetDisposition::RetentionBlocked(HoldTerms {
            holder_owner_ref: "owner:test".to_string(),
            legal_basis_ref: "basis:test".to_string(),
            policy_ref: "policy:test".to_string(),
            review_or_expiry_ref: "review:test".to_string(),
            protected_minimum_ref: None,
        });
        assert_ne!(redacted, held);
        assert!(redacted.is_terminal());
        assert!(!held.is_terminal());
        assert!(redacted.validate().is_ok());
        assert!(held.validate().is_ok());

        let mut snapshot = test_snapshot();
        snapshot.targets[0].disposition = held;
        assert!(snapshot.validate().is_ok());
        assert!(!snapshot.fully_dispositioned());

        let incomplete_hold = TargetDisposition::RetentionBlocked(HoldTerms {
            holder_owner_ref: "owner:test".to_string(),
            legal_basis_ref: "basis:test".to_string(),
            policy_ref: "policy:test".to_string(),
            review_or_expiry_ref: String::new(),
            protected_minimum_ref: None,
        });
        assert_eq!(
            incomplete_hold.validate(),
            Err(ScopeError::InvalidField("hold.review_or_expiry_ref"))
        );
    }

    #[test]
    fn changed_scope_graph_or_hold_under_one_identity_conflicts() {
        let base = test_snapshot();
        let mut changed_disposition = test_snapshot();
        changed_disposition.targets[2].disposition =
            TargetDisposition::UnknownOutcome { detail_ref: None };
        assert_eq!(
            base.check_identity_conflict(&changed_disposition),
            Err(ScopeError::IdentityConflict)
        );

        let mut changed_graph = test_snapshot();
        changed_graph.graph_revision = 12;
        assert_eq!(
            base.check_identity_conflict(&changed_graph),
            Err(ScopeError::IdentityConflict)
        );

        let other_identity = ErasureScopeSnapshot {
            erasure_id: "erasure-1130-b".to_string(),
            ..test_snapshot()
        };
        assert_eq!(
            base.check_identity_conflict(&other_identity),
            Err(ScopeError::DifferentIdentity)
        );
    }

    #[test]
    fn tombstone_first_ordering_type_enforces_frozen_step_order() {
        assert_eq!(ErasureSequenceStep::ORDERED.len(), 8);
        assert_eq!(ErasureSequenceStep::IdentifyCopies.ordinal(), 0);
        assert_eq!(ErasureSequenceStep::NotifyOwnerOfUnavailable.ordinal(), 7);
        assert!(
            ErasureSequenceStep::RemovePayloadAndCopies.ordinal()
                > ErasureSequenceStep::CreatePurgePlan.ordinal()
        );

        let mut reordered = test_snapshot();
        reordered.planned_order.reverse();
        assert_eq!(reordered.validate(), Err(ScopeError::StepOrderViolation));
    }

    #[test]
    fn unknown_and_unavailable_targets_stay_explicit_and_not_complete() {
        let mut snapshot = test_snapshot();
        snapshot.targets[3].disposition = TargetDisposition::UnknownOutcome {
            detail_ref: Some("ors-observation:test".to_string()),
        };
        snapshot.targets[6].disposition = TargetDisposition::UnavailableExternal {
            notify_owner_ref: "owner:test".to_string(),
        };
        assert!(snapshot.validate().is_ok());
        assert!(!snapshot.fully_dispositioned());
        assert!(test_snapshot().fully_dispositioned());
    }

    #[test]
    fn residency_rejects_cross_domain_coresidence_proof_and_approver_scope_is_enforced() {
        let mut snapshot = test_snapshot();
        snapshot.residency.claims_cross_domain_coresidence = true;
        assert_eq!(
            snapshot.validate(),
            Err(ScopeError::UnsupportedResidencyProof)
        );

        let open_gap = ResidencyBinding {
            residency_domain_ref: None,
            claims_cross_domain_coresidence: false,
        };
        assert!(open_gap.validate().is_ok());

        let mut wrong_approver = test_snapshot();
        wrong_approver.approval.approver_kind = ApproverKind::WorkScopeOwner;
        wrong_approver.approval.scope_class = DataScopeClass::InstallationData;
        assert_eq!(
            wrong_approver.validate(),
            Err(ScopeError::ApproverScopeMismatch)
        );

        let system_approval = ApprovalBinding {
            scope_class: DataScopeClass::InstallationData,
            approver_kind: ApproverKind::SystemOwner,
            approver_ref: "system-owner:test".to_string(),
            approval_digest: "cd".repeat(32),
        };
        assert!(system_approval.validate().is_ok());
        assert!(DataScopeClass::InstallationData.permits(&ApproverKind::SystemOwner));
        assert!(!DataScopeClass::InstallationData.permits(&ApproverKind::AuthorizedHuman));
        assert!(DataScopeClass::WorkScopeData.permits(&ApproverKind::AuthorizedHuman));
    }

    #[test]
    fn child_effect_identity_covers_only_shape() {
        let first = match ChildEffectId::for_target("erasure-1130-a", 3, EffectKind::BlobDeletion) {
            Ok(first) => first,
            Err(error) => panic!("valid child effect shape: {error:?}"),
        };
        let replay = match ChildEffectId::for_target("erasure-1130-a", 3, EffectKind::BlobDeletion)
        {
            Ok(replay) => replay,
            Err(error) => panic!("valid child effect shape: {error:?}"),
        };
        assert_eq!(first, replay);
        assert!(ChildEffectId::for_target("", 0, EffectKind::KeyDestruction).is_err());
    }

    #[test]
    fn derives_one_child_effect_per_frozen_target() {
        let snapshot = test_snapshot();
        let kinds = vec![
            EffectKind::CanonicalRedaction,
            EffectKind::IndexCacheRemoval,
            EffectKind::IndexCacheRemoval,
            EffectKind::BlobDeletion,
            EffectKind::KeyDestruction,
            EffectKind::InfluenceRevocation,
            EffectKind::InfluenceRevocation,
            EffectKind::ExternalWithdrawal,
        ];
        assert_eq!(kinds.len(), snapshot.targets.len());
        let effects = match ChildEffectId::for_snapshot(&snapshot, &kinds) {
            Ok(effects) => effects,
            Err(error) => panic!("child effects derive: {error:?}"),
        };
        assert_eq!(effects.len(), snapshot.targets.len());
        for (ordinal, (effect, kind)) in effects.iter().zip(kinds.iter()).enumerate() {
            let expected_ordinal = match u32::try_from(ordinal) {
                Ok(expected_ordinal) => expected_ordinal,
                Err(error) => panic!("target ordinal fits u32: {error:?}"),
            };
            assert_eq!(effect.erasure_id, snapshot.erasure_id);
            assert_eq!(effect.target_ordinal, expected_ordinal);
            assert_eq!(effect.effect_kind, *kind);
        }
        let replay = match ChildEffectId::for_snapshot(&test_snapshot(), &kinds) {
            Ok(replay) => replay,
            Err(error) => panic!("child effect replay derives: {error:?}"),
        };
        assert_eq!(effects, replay);
    }

    #[test]
    fn rejects_child_effect_denominator_mismatch() {
        let snapshot = test_snapshot();
        let short = vec![EffectKind::BlobDeletion];
        assert_eq!(
            ChildEffectId::for_snapshot(&snapshot, &short),
            Err(ScopeError::EffectDenominatorMismatch)
        );
        let mut oversized = vec![EffectKind::BlobDeletion; snapshot.targets.len()];
        oversized.push(EffectKind::KeyDestruction);
        assert_eq!(
            ChildEffectId::for_snapshot(&snapshot, &oversized),
            Err(ScopeError::EffectDenominatorMismatch)
        );
    }

    fn bound_request(snapshot: &ErasureScopeSnapshot) -> ErasureRequest {
        ErasureRequest {
            request_id: "request-1130-a".to_string(),
            subject_ref: snapshot.subject_ref.clone(),
            scope: "scope:test".to_string(),
            locations: vec![
                PurgeLocation::CanonicalPayload,
                PurgeLocation::Projection,
                PurgeLocation::Index,
                PurgeLocation::Blob,
                PurgeLocation::OperationalRecovery,
                PurgeLocation::BackupRestorePath,
                PurgeLocation::RouteContinuation,
                PurgeLocation::ProviderCopy,
            ],
            expected_revision: snapshot.subject_revision,
            approval_digest: snapshot.approval.approval_digest.clone(),
            evidence: Vec::new(),
            state_fence: snapshot.state_fence.clone(),
        }
    }

    #[test]
    fn request_binds_to_frozen_snapshot_and_rejects_scope_drift() {
        let snapshot = test_snapshot();
        let request = bound_request(&snapshot);
        let first = match request.bind_scope_snapshot(&snapshot) {
            Ok(first) => first,
            Err(error) => panic!("binding holds: {error:?}"),
        };
        assert_eq!(first.len(), 64);
        let replay = match request.bind_scope_snapshot(&test_snapshot()) {
            Ok(replay) => replay,
            Err(error) => panic!("replay binds: {error:?}"),
        };
        assert_eq!(replay, first);

        let mut drifted_subject = test_snapshot();
        drifted_subject.subject_ref = "subject:other".to_string();
        assert!(request.bind_scope_snapshot(&drifted_subject).is_err());

        let mut drifted_revision = test_snapshot();
        drifted_revision.subject_revision += 1;
        assert!(request.bind_scope_snapshot(&drifted_revision).is_err());

        let mut narrowed = test_snapshot();
        narrowed
            .targets
            .retain(|target| target.location != PurgeLocation::Projection);
        assert!(narrowed.validate().is_ok());
        assert!(request.bind_scope_snapshot(&narrowed).is_err());
    }
}
