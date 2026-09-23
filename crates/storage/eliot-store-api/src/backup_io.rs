//! Owner-neutral coherent snapshot and isolated-restore contracts (issue #950).
//!
//! This module defines the smallest additive structural surface for binding a
//! coherent canonical snapshot capture, paging it under one owner-issued
//! consistency point, restoring versioned canonical batches into an
//! externally admitted isolated destination, and reconciling same-operation
//! replay identity. It deliberately contains no database, filesystem,
//! credential, backup-library, Kernel, or proof-authority implementation.
//!
//! Every type here is structural only and grants no read, restore, or effect
//! authority by itself. An admission handle is opaque external data, never
//! self-authenticating: shape validity alone is not authority. A timestamp or
//! a sequence of independent reads is not snapshot authority; only an
//! owner-issued [`SnapshotHandle`] binds a capture. Unavailable consistency
//! is explicit ([`SnapshotCompleteness::Partial`],
//! [`SnapshotCompleteness::Expired`], [`SnapshotCompleteness::Unsupported`]),
//! never a silent success.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CONTRACT_VERSION, ContractVersion, OperationId, OperationIdentity, OrderingHeadExpectation,
    RequestMeta, ResourceGeneration, RevisionHeadExpectation, ScopeRevisionView, StoreError,
    StoreMutationDisposition, canonical_json_bytes, sha256_hex, unique, validate_digest,
    validate_text,
};

/// Stable contract name for the backup-I/O surface.
pub const BACKUP_IO_CONTRACT_NAME: &str = "eliot.storage.backup-io.v1";
/// Versioned schema tag for snapshot capture documents.
pub const BACKUP_IO_SNAPSHOT_SCHEMA_V1: &str = "eliot.storage.backup-io.snapshot.v1";
/// Versioned schema tag for isolated-restore documents.
pub const BACKUP_IO_RESTORE_SCHEMA_V1: &str = "eliot.storage.backup-io.restore.v1";
/// Maximum members in one snapshot denominator.
pub const MAX_SNAPSHOT_MEMBERS: usize = 1024;
/// Maximum members in one snapshot page.
pub const MAX_SNAPSHOT_PAGE_MEMBERS: usize = 256;
/// Maximum cumulative snapshot bytes.
pub const MAX_SNAPSHOT_BYTES: u64 = 8_388_608;
/// Maximum snapshot pages under one consistency point.
pub const MAX_SNAPSHOT_PAGES: u64 = 4096;
/// Maximum reference-type members in one snapshot denominator.
pub const MAX_DENOMINATOR_REFERENCES: usize = 1024;
/// Maximum privacy/proof handles carried by one snapshot begin request.
pub const MAX_PROOF_HANDLES: usize = 16;
/// Maximum members in one canonical restore batch.
pub const MAX_RESTORE_MEMBERS: usize = 1024;

/// Maximum cumulative snapshot work units accepted by [`SnapshotBounds`].
const MAX_SNAPSHOT_WORK: u64 = 1_000_000;
/// Maximum snapshot capture duration in milliseconds accepted by [`SnapshotBounds`].
const MAX_SNAPSHOT_DURATION_MS: u64 = 3_600_000;

/// Capability name for coherent snapshot capture.
pub const BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT: &str = "coherent_snapshot";
/// Capability name for isolated restore.
pub const BACKUP_IO_CAPABILITY_ISOLATED_RESTORE: &str = "isolated_restore";
/// Capability name for reference validation.
pub const BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION: &str = "reference_validation";
/// Capability name for purge validation.
pub const BACKUP_IO_CAPABILITY_PURGE_VALIDATION: &str = "purge_validation";
/// Capability name for rebuild validation.
pub const BACKUP_IO_CAPABILITY_REBUILD_VALIDATION: &str = "rebuild_validation";
/// Capability name for operation reconciliation.
pub const BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION: &str = "operation_reconciliation";

/// Closed capability vocabulary for the backup-I/O surface.
///
/// This list is pure discovery data. It registers nothing with the Store
/// wire and grants no authority; advertisement happens only from an accepted
/// concrete backend.
pub const ALL_BACKUP_IO_CAPABILITIES: &[&str] = &[
    BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT,
    BACKUP_IO_CAPABILITY_ISOLATED_RESTORE,
    BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION,
    BACKUP_IO_CAPABILITY_PURGE_VALIDATION,
    BACKUP_IO_CAPABILITY_REBUILD_VALIDATION,
    BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION,
];

/// Reports whether a capability name belongs to the closed backup-I/O vocabulary.
#[must_use]
pub fn is_backup_io_capability(name: &str) -> bool {
    ALL_BACKUP_IO_CAPABILITIES.contains(&name)
}

/// Closed backup-I/O capability discriminator.
///
/// Structural only; a value of this enum performs no capture and no restore.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupIoCapability {
    CoherentSnapshot,
    IsolatedRestore,
    ReferenceValidation,
    PurgeValidation,
    RebuildValidation,
    OperationReconciliation,
}

impl BackupIoCapability {
    /// Returns the stable capability name for this discriminator.
    #[must_use]
    pub fn capability_name(&self) -> &'static str {
        match self {
            Self::CoherentSnapshot => BACKUP_IO_CAPABILITY_COHERENT_SNAPSHOT,
            Self::IsolatedRestore => BACKUP_IO_CAPABILITY_ISOLATED_RESTORE,
            Self::ReferenceValidation => BACKUP_IO_CAPABILITY_REFERENCE_VALIDATION,
            Self::PurgeValidation => BACKUP_IO_CAPABILITY_PURGE_VALIDATION,
            Self::RebuildValidation => BACKUP_IO_CAPABILITY_REBUILD_VALIDATION,
            Self::OperationReconciliation => BACKUP_IO_CAPABILITY_OPERATION_RECONCILIATION,
        }
    }
}

/// Closed snapshot member discriminator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotMemberType {
    Record,
    Reference,
    Blob,
}

/// Closed blob-residency domain discriminator.
///
/// Equal bytes under different domains remain distinct logical objects; the
/// domain is part of the member identity (see [`SnapshotMember::logical_identity`]).
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlobResidencyDomain {
    InlineCanonical,
    ContentBlob,
    ExternalReference,
}

/// Closed restore-destination discriminator.
///
/// Only [`DestinationClass::IsolatedRestore`] can ever validate; the active,
/// source, and foreign classes exist so refusals stay typed and explicit.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DestinationClass {
    IsolatedRestore,
    Active,
    Source,
    Foreign,
}

/// Closed snapshot-completeness discriminator.
///
/// Unavailable consistency is explicit here: only [`SnapshotCompleteness::Complete`]
/// can ever satisfy an is-complete check.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotCompleteness {
    Complete,
    Partial,
    Expired,
    Unsupported,
}

impl SnapshotCompleteness {
    /// Reports whether this state is authoritative completeness.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Closed restore-conflict discriminator.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RestoreConflictKind {
    ExpectedState,
    Ordering,
    Schema,
}

/// Closed same-operation reconciliation outcome.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationOutcome {
    ReplayIdentity,
    IdentityConflict,
    RevisionConflict,
    OrderingConflict,
    SchemaConflict,
}

/// Source installation/store/schema/generation bound into a snapshot capture.
///
/// Structural only; binding these fields describes a capture, it does not
/// authorize reading the source.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSourceIdentity {
    pub installation_id: String,
    pub store_id: String,
    pub schema: String,
    pub generation: ResourceGeneration,
}

impl SnapshotSourceIdentity {
    /// Validates the source binding without granting source access.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.installation_id, "snapshot.installation_id")?;
        validate_text(&self.store_id, "snapshot.store_id")?;
        validate_text(&self.schema, "snapshot.schema")?;
        if self.generation.value() == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.generation",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Closed event-sequence interval covered by a snapshot capture.
///
/// A pair of independent sequence reads is not snapshot authority; the
/// interval only describes the capture bound by a [`SnapshotHandle`].
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventInterval {
    pub first_sequence: u64,
    pub last_sequence: u64,
}

impl EventInterval {
    /// Validates a non-zero, ordered event interval.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.first_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.first_sequence",
                reason: "must be non-zero",
            });
        }
        if self.last_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.last_sequence",
                reason: "must be non-zero",
            });
        }
        if self.first_sequence > self.last_sequence {
            return Err(StoreError::InvalidField {
                field: "snapshot.event_interval",
                reason: "first_sequence must not exceed last_sequence",
            });
        }
        Ok(())
    }
}

/// Blob-residency identity for one snapshot member.
///
/// Structural only; proving byte durability never establishes semantic
/// reference authority, which still requires the canonical transition path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobResidency {
    pub domain: BlobResidencyDomain,
    pub residency_digest: String,
    pub byte_count: u64,
}

impl BlobResidency {
    /// Validates the residency digest and byte count.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.residency_digest, "snapshot.residency_digest")?;
        if self.byte_count == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.byte_count",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// One member of a snapshot denominator.
///
/// Structural only; membership describes capture content, it does not carry
/// the member's former active authority anywhere.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMember {
    pub member_id: String,
    pub member_type: SnapshotMemberType,
    pub content_digest: String,
    pub residency: BlobResidency,
    pub reference_digest: Option<String>,
}

impl SnapshotMember {
    /// Returns the domain-qualified logical identity of this member.
    ///
    /// Same bytes in different residency domains are distinct logical
    /// objects, so the domain is part of the identity and members must never
    /// be merged on content digest alone.
    #[must_use]
    pub fn logical_identity(&self) -> String {
        format!("{:?}:{}", self.residency.domain, self.content_digest)
    }

    /// Validates the member shape and the reference-digest coupling.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.member_id, "snapshot.member_id")?;
        validate_digest(&self.content_digest, "snapshot.content_digest")?;
        self.residency.validate()?;
        match (&self.member_type, &self.reference_digest) {
            (SnapshotMemberType::Reference, Some(digest)) => {
                validate_digest(digest, "snapshot.reference_digest")?;
            }
            (SnapshotMemberType::Reference, None) => {
                return Err(StoreError::InvalidField {
                    field: "snapshot.reference_digest",
                    reason: "reference member requires a reference digest",
                });
            }
            (_, Some(_)) => {
                return Err(StoreError::InvalidField {
                    field: "snapshot.reference_digest",
                    reason: "only reference members carry a reference digest",
                });
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Exact member/type/reference and blob-residency denominator of a capture.
///
/// Structural only; the denominator describes what the capture must contain,
/// it does not authenticate the capture.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDenominator {
    pub members: Vec<SnapshotMember>,
    pub is_complete: bool,
}

impl SnapshotDenominator {
    /// Returns the number of denominator members.
    #[must_use]
    pub fn member_count(&self) -> u64 {
        self.members.len() as u64
    }

    /// Returns the summed member byte count, saturating on overflow.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.members.iter().fold(0_u64, |total, member| {
            total.saturating_add(member.residency.byte_count)
        })
    }

    /// Validates member closure, uniqueness, and byte/reference ceilings.
    ///
    /// An empty member list is a valid shape here; whether a known-zero
    /// count proves anything is decided by the validation receipts, which
    /// require a complete authoritative denominator.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.members.len() > MAX_SNAPSHOT_MEMBERS {
            return Err(StoreError::PayloadTooLarge);
        }
        unique(
            self.members.iter().map(|member| member.member_id.clone()),
            "snapshot.members",
        )?;
        for member in &self.members {
            member.validate()?;
        }
        let references = self
            .members
            .iter()
            .filter(|member| member.member_type == SnapshotMemberType::Reference)
            .count();
        if references > MAX_DENOMINATOR_REFERENCES {
            return Err(StoreError::PayloadTooLarge);
        }
        if self.total_bytes() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        Ok(())
    }
}

/// Maximum count/bytes/pages/work/duration envelope for a capture.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBounds {
    pub max_members: u64,
    pub max_bytes: u64,
    pub max_pages: u64,
    pub max_work: u64,
    pub max_duration_ms: u64,
}

impl SnapshotBounds {
    /// Validates non-zero bounds within the frozen ceilings.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.max_members == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.max_members",
                reason: "must be non-zero",
            });
        }
        if self.max_bytes == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.max_bytes",
                reason: "must be non-zero",
            });
        }
        if self.max_pages == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.max_pages",
                reason: "must be non-zero",
            });
        }
        if self.max_work == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.max_work",
                reason: "must be non-zero",
            });
        }
        if self.max_duration_ms == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.max_duration_ms",
                reason: "must be non-zero",
            });
        }
        if self.max_members > MAX_SNAPSHOT_MEMBERS as u64
            || self.max_bytes > MAX_SNAPSHOT_BYTES
            || self.max_pages > MAX_SNAPSHOT_PAGES
            || self.max_work > MAX_SNAPSHOT_WORK
            || self.max_duration_ms > MAX_SNAPSHOT_DURATION_MS
        {
            return Err(StoreError::PayloadTooLarge);
        }
        Ok(())
    }
}

/// Closed request binding one coherent snapshot capture.
///
/// Structural only; a valid request describes a capture and computes its
/// immutable digest, it does not perform the capture or grant read access.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBeginRequest {
    pub contract_version: ContractVersion,
    pub operation: OperationIdentity,
    pub source: SnapshotSourceIdentity,
    pub scope: ScopeRevisionView,
    pub event_interval: EventInterval,
    pub denominator: SnapshotDenominator,
    pub bounds: SnapshotBounds,
    pub expires_at_unix_ms: i64,
    pub privacy_proof_refs: Vec<String>,
}

impl SnapshotBeginRequest {
    /// Computes the immutable canonical digest of this begin request.
    #[must_use = "the computed digest must be bound into a snapshot handle"]
    pub fn compute_digest(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    /// Validates every capture binding, including non-empty revision heads.
    ///
    /// A snapshot with no revision heads is not coherent, so an empty head
    /// list is rejected here.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(StoreError::InvalidField {
                field: "contract_version",
                reason: "does not match the store API contract",
            });
        }
        self.operation.validate()?;
        self.source.validate()?;
        self.scope.validate()?;
        if self.scope.revision_heads.is_empty() {
            return Err(StoreError::Empty {
                field: "snapshot.revision_heads",
            });
        }
        self.event_interval.validate()?;
        self.denominator.validate()?;
        self.bounds.validate()?;
        if self.expires_at_unix_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.expires_at_unix_ms",
                reason: "must be positive",
            });
        }
        if self.privacy_proof_refs.is_empty() {
            return Err(StoreError::Empty {
                field: "snapshot.privacy_proof_refs",
            });
        }
        if self.privacy_proof_refs.len() > MAX_PROOF_HANDLES {
            return Err(StoreError::PayloadTooLarge);
        }
        unique(
            self.privacy_proof_refs.iter().cloned(),
            "snapshot.privacy_proof_refs",
        )?;
        for reference in &self.privacy_proof_refs {
            validate_text(reference, "snapshot.proof_ref")?;
        }
        Ok(())
    }
}

/// Opaque owner-issued consistency point binding one capture.
///
/// A bare timestamp can never construct this handle: the consistency point
/// is owner-issued evidence, and the digest binds the exact begin request.
/// The handle is structural data, not a read capability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotHandle {
    pub consistency_point: String,
    pub snapshot_digest: String,
    pub operation_id: OperationId,
    pub idempotency_key: String,
}

impl SnapshotHandle {
    /// Validates the handle shape without treating it as authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.consistency_point, "snapshot.consistency_point")?;
        validate_digest(&self.snapshot_digest, "snapshot.snapshot_digest")?;
        validate_text(&self.idempotency_key, "snapshot.idempotency_key")
    }
}

/// Opaque continuation cursor for one snapshot page.
///
/// The cursor carries no authority; a page is accepted only when the cursor
/// belongs to the page handle and continuation preserves cumulative bounds.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCursor {
    pub handle_digest: String,
    pub page_index: u64,
    pub cumulative_members: u64,
    pub cumulative_bytes: u64,
}

impl SnapshotCursor {
    /// Validates the cursor shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.handle_digest, "snapshot.handle_digest")
    }
}

/// One bounded page of a snapshot capture under a single consistency point.
///
/// Structural only; pages never cross snapshots and cumulative bounds never
/// reset along a continuation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPage {
    pub handle: SnapshotHandle,
    pub cursor: SnapshotCursor,
    pub members: Vec<SnapshotMember>,
    pub cumulative_bytes: u64,
    pub cumulative_work: u64,
    pub is_last: bool,
    pub predecessor_digest: String,
    pub next_cursor: Option<SnapshotCursor>,
}

impl SnapshotPage {
    /// Validates handle/cursor binding, member closure, and cursor chaining.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.handle.validate()?;
        self.cursor.validate()?;
        if self.cursor.handle_digest != self.handle.snapshot_digest {
            return Err(StoreError::InvalidField {
                field: "snapshot.cursor",
                reason: "cursor does not belong to this snapshot handle",
            });
        }
        if self.members.is_empty() {
            return Err(StoreError::Empty {
                field: "snapshot.members",
            });
        }
        if self.members.len() > MAX_SNAPSHOT_PAGE_MEMBERS {
            return Err(StoreError::PayloadTooLarge);
        }
        unique(
            self.members.iter().map(|member| member.member_id.clone()),
            "snapshot.members",
        )?;
        for member in &self.members {
            member.validate()?;
        }
        let member_bytes: u64 = self.members.iter().fold(0_u64, |total, member| {
            total.saturating_add(member.residency.byte_count)
        });
        if self.cumulative_bytes < member_bytes {
            return Err(StoreError::InvalidField {
                field: "snapshot.cumulative_bytes",
                reason: "below the member byte total",
            });
        }
        validate_digest(&self.predecessor_digest, "snapshot.predecessor_digest")?;
        match (&self.is_last, &self.next_cursor) {
            (true, Some(_)) => Err(StoreError::InvalidField {
                field: "snapshot.next_cursor",
                reason: "terminal page must not carry a next cursor",
            }),
            (true, None) => Ok(()),
            (false, Some(cursor)) => cursor.validate(),
            (false, None) => Err(StoreError::InvalidField {
                field: "snapshot.next_cursor",
                reason: "non-terminal page requires a next cursor",
            }),
        }
    }

    /// Validates this page against the begin request that opened the capture.
    pub fn validate_for_begin(&self, begin: &SnapshotBeginRequest) -> Result<(), StoreError> {
        if self.handle.snapshot_digest != begin.compute_digest()? {
            return Err(StoreError::InvalidField {
                field: "snapshot.snapshot_digest",
                reason: "page handle does not match the begin-request digest",
            });
        }
        if self.cursor.cumulative_members > begin.bounds.max_members
            || self.cumulative_bytes > begin.bounds.max_bytes
        {
            return Err(StoreError::PayloadTooLarge);
        }
        Ok(())
    }

    /// Validates continuation against the previous page of the same capture.
    ///
    /// The handle must stay on one owner-issued consistency point, the page
    /// index must advance by exactly one, and cumulative bounds must never
    /// reset.
    pub fn validate_continuation(&self, previous: &SnapshotPage) -> Result<(), StoreError> {
        if self.handle.snapshot_digest != previous.handle.snapshot_digest {
            return Err(StoreError::InvalidField {
                field: "snapshot.snapshot_digest",
                reason: "continuation crossed to a different snapshot handle",
            });
        }
        if self.cursor.page_index != previous.cursor.page_index + 1 {
            return Err(StoreError::InvalidField {
                field: "snapshot.page_index",
                reason: "continuation must advance exactly one page",
            });
        }
        if self.cumulative_bytes < previous.cumulative_bytes {
            return Err(StoreError::InvalidField {
                field: "snapshot.cumulative_bytes",
                reason: "continuation must not reset cumulative bounds",
            });
        }
        if self.cursor.cumulative_members < previous.cursor.cumulative_members {
            return Err(StoreError::InvalidField {
                field: "snapshot.cumulative_members",
                reason: "continuation must not reset cumulative bounds",
            });
        }
        Ok(())
    }
}

/// Owner-issued receipt closing a snapshot capture.
///
/// Structural only; [`SnapshotEndReceipt::is_complete`] is explicit so
/// expired or unsupported captures can never pass a completeness check.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEndReceipt {
    pub handle: SnapshotHandle,
    pub operation: OperationIdentity,
    pub member_count: u64,
    pub byte_count: u64,
    pub completeness: SnapshotCompleteness,
    pub validation_revision: u64,
}

impl SnapshotEndReceipt {
    /// Reports whether this receipt closes a complete capture.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.completeness.is_complete()
    }

    /// Validates the receipt shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.handle.validate()?;
        self.operation.validate()?;
        if self.validation_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "snapshot.validation_revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// External admission evidence for an isolated destination.
///
/// The admission handle is opaque external data, never self-authenticating:
/// a well-formed value without current external admission proves nothing.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationEvidence {
    pub admission_handle: String,
    pub admitted_at_unix_ms: i64,
    pub purge_policy_revision: u64,
}

impl IsolationEvidence {
    /// Validates the admission evidence shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.admission_handle, "restore.admission_handle")?;
        if self.admitted_at_unix_ms <= 0 {
            return Err(StoreError::InvalidField {
                field: "restore.admitted_at_unix_ms",
                reason: "must be positive",
            });
        }
        if self.purge_policy_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Isolated destination for a canonical restore.
///
/// Structural only; the destination must differ from the source and active
/// installation, and candidate source records never carry their old active
/// authority into the destination.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolatedDestination {
    pub destination_id: String,
    pub destination_class: DestinationClass,
    pub source_store_id: String,
    pub source_installation_id: String,
    pub evidence: IsolationEvidence,
    pub target_schema: String,
}

impl IsolatedDestination {
    /// Validates isolation: class, separation from source, and admission.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.destination_id, "restore.destination_id")?;
        if self.destination_id == self.source_store_id
            || self.destination_id == self.source_installation_id
        {
            return Err(StoreError::InvalidField {
                field: "restore.destination_id",
                reason: "must differ from source/active installation",
            });
        }
        if self.destination_class != DestinationClass::IsolatedRestore {
            return Err(StoreError::InvalidField {
                field: "restore.destination_class",
                reason: "restore destination must be isolated",
            });
        }
        self.evidence.validate()?;
        validate_text(&self.target_schema, "restore.target_schema")
    }
}

/// Bounded canonical restore batch into an isolated destination.
///
/// Structural only; archive content is referenced solely as an opaque member
/// digest, never as a second archive format.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRestoreBatch {
    pub contract_version: ContractVersion,
    pub operation: OperationIdentity,
    pub source: SnapshotSourceIdentity,
    pub destination: IsolatedDestination,
    pub archive_member_digest: String,
    pub target_schema: String,
    pub purge_policy_revision: u64,
    pub expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub expected_ordering_heads: Vec<OrderingHeadExpectation>,
    pub member_count: u64,
}

impl CanonicalRestoreBatch {
    /// Validates the restore batch, checking destination admission first.
    ///
    /// The destination (including its external admission evidence) is
    /// validated before anything else: shape validity alone is not authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.destination.validate()?;
        if self.contract_version != CONTRACT_VERSION {
            return Err(StoreError::InvalidField {
                field: "contract_version",
                reason: "does not match the store API contract",
            });
        }
        self.operation.validate()?;
        self.source.validate()?;
        validate_digest(&self.archive_member_digest, "restore.archive_member_digest")?;
        validate_text(&self.target_schema, "restore.target_schema")?;
        if self.target_schema != self.destination.target_schema {
            return Err(StoreError::InvalidField {
                field: "restore.target_schema",
                reason: "must match the isolated destination schema",
            });
        }
        if self.purge_policy_revision == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "must be non-zero",
            });
        }
        if self.purge_policy_revision != self.destination.evidence.purge_policy_revision {
            return Err(StoreError::InvalidField {
                field: "restore.purge_policy_revision",
                reason: "must match the destination purge policy",
            });
        }
        if self.expected_revision_heads.is_empty() {
            return Err(StoreError::Empty {
                field: "restore.expected_revision_heads",
            });
        }
        unique(
            self.expected_revision_heads
                .iter()
                .map(|head| head.key.clone()),
            "restore.expected_revision_heads",
        )?;
        unique(
            self.expected_ordering_heads
                .iter()
                .map(|head| head.scope.clone()),
            "restore.expected_ordering_heads",
        )?;
        for head in &self.expected_revision_heads {
            head.validate()?;
        }
        for head in &self.expected_ordering_heads {
            head.validate()?;
        }
        if self.member_count == 0 {
            return Err(StoreError::InvalidField {
                field: "restore.member_count",
                reason: "must be non-zero",
            });
        }
        if self.member_count > MAX_RESTORE_MEMBERS as u64 {
            return Err(StoreError::PayloadTooLarge);
        }
        Ok(())
    }
}

/// Owner-issued snapshot validation receipt.
///
/// Structural only; a possible-mutation or unknown disposition never passes
/// as success, and a known-zero unresolved count requires a complete
/// authoritative denominator. These types cannot themselves authenticate a
/// caller or establish current external admission.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotValidationReceipt {
    pub operation: OperationIdentity,
    pub handle: SnapshotHandle,
    pub denominator: SnapshotDenominator,
    pub resolved_members: u64,
    pub unresolved_members: u64,
    pub completeness: SnapshotCompleteness,
    pub disposition: StoreMutationDisposition,
}

impl SnapshotValidationReceipt {
    /// Reports proven success: complete, committed-or-proven-absent, nothing unresolved.
    #[must_use]
    pub fn is_proven_success(&self) -> bool {
        self.completeness.is_complete()
            && matches!(
                self.disposition,
                StoreMutationDisposition::Committed | StoreMutationDisposition::ProvenNotApplied
            )
            && self.unresolved_members == 0
    }

    /// Validates count closure and the known-zero completeness rule.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        self.handle.validate()?;
        self.denominator.validate()?;
        if self
            .resolved_members
            .saturating_add(self.unresolved_members)
            != self.denominator.member_count()
        {
            return Err(StoreError::InvalidField {
                field: "snapshot.member_counts",
                reason: "resolved and unresolved counts must sum to the denominator",
            });
        }
        if self.unresolved_members == 0
            && !(self.completeness.is_complete() && self.denominator.is_complete)
        {
            return Err(StoreError::InvalidField {
                field: "snapshot.completeness",
                reason: "known-zero requires complete authoritative denominator",
            });
        }
        if self.completeness.is_complete()
            && !matches!(
                self.disposition,
                StoreMutationDisposition::Committed | StoreMutationDisposition::ProvenNotApplied
            )
        {
            return Err(StoreError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Owner-issued restore validation receipt.
///
/// Structural only; same success contour as [`SnapshotValidationReceipt`]:
/// unknown or possible-mutation dispositions never validate as success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreValidationReceipt {
    pub operation: OperationIdentity,
    pub destination: IsolatedDestination,
    pub archive_member_digest: String,
    pub resolved_members: u64,
    pub unresolved_members: u64,
    pub denominator_members: u64,
    pub completeness: SnapshotCompleteness,
    pub disposition: StoreMutationDisposition,
}

impl RestoreValidationReceipt {
    /// Reports proven success: complete, committed-or-proven-absent, nothing unresolved.
    #[must_use]
    pub fn is_proven_success(&self) -> bool {
        self.completeness.is_complete()
            && matches!(
                self.disposition,
                StoreMutationDisposition::Committed | StoreMutationDisposition::ProvenNotApplied
            )
            && self.unresolved_members == 0
    }

    /// Validates count closure and the known-zero completeness rule.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        self.destination.validate()?;
        validate_digest(&self.archive_member_digest, "restore.archive_member_digest")?;
        if self
            .resolved_members
            .saturating_add(self.unresolved_members)
            != self.denominator_members
        {
            return Err(StoreError::InvalidField {
                field: "restore.member_counts",
                reason: "resolved and unresolved counts must sum to the denominator",
            });
        }
        if self.unresolved_members == 0 && !self.completeness.is_complete() {
            return Err(StoreError::InvalidField {
                field: "restore.completeness",
                reason: "known-zero requires complete authoritative denominator",
            });
        }
        if self.completeness.is_complete()
            && !matches!(
                self.disposition,
                StoreMutationDisposition::Committed | StoreMutationDisposition::ProvenNotApplied
            )
        {
            return Err(StoreError::InvalidReceipt);
        }
        Ok(())
    }
}

/// Same-operation reconciliation record binding two canonical request digests.
///
/// Structural only; the outcome must match digest equality, and the record
/// performs no mutation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupOperationReconciliation {
    pub operation: OperationIdentity,
    pub first_digest: String,
    pub second_digest: String,
    pub outcome: ReconciliationOutcome,
}

impl BackupOperationReconciliation {
    /// Validates identity, digests, and outcome/digest-equality consistency.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate()?;
        validate_digest(&self.first_digest, "reconciliation.first_digest")?;
        validate_digest(&self.second_digest, "reconciliation.second_digest")?;
        let replay = self.first_digest == self.second_digest;
        let consistent = (replay && self.outcome == ReconciliationOutcome::ReplayIdentity)
            || (!replay && self.outcome == ReconciliationOutcome::IdentityConflict);
        if !consistent {
            return Err(StoreError::InvalidField {
                field: "reconciliation.outcome",
                reason: "outcome must match digest equality",
            });
        }
        Ok(())
    }
}

/// Reconciles two identities for the same operation.
///
/// Equal canonical request hashes reconcile as [`ReconciliationOutcome::ReplayIdentity`];
/// the same operation id with a changed hash is
/// [`ReconciliationOutcome::IdentityConflict`]. Reconciliation across
/// different operation ids is refused: this function is same-operation only.
pub fn reconcile_same_operation(
    first: &OperationIdentity,
    second: &OperationIdentity,
) -> Result<ReconciliationOutcome, StoreError> {
    first.validate()?;
    second.validate()?;
    if first.operation_id != second.operation_id {
        return Err(StoreError::InvalidField {
            field: "operation_id",
            reason: "reconciliation is same-operation only",
        });
    }
    if first.canonical_request_hash == second.canonical_request_hash {
        Ok(ReconciliationOutcome::ReplayIdentity)
    } else {
        Ok(ReconciliationOutcome::IdentityConflict)
    }
}

/// Maps a restore conflict kind to its typed reconciliation outcome.
#[must_use]
pub fn classify_restore_conflict(kind: RestoreConflictKind) -> ReconciliationOutcome {
    match kind {
        RestoreConflictKind::ExpectedState => ReconciliationOutcome::RevisionConflict,
        RestoreConflictKind::Ordering => ReconciliationOutcome::OrderingConflict,
        RestoreConflictKind::Schema => ReconciliationOutcome::SchemaConflict,
    }
}

/// Coherent canonical snapshot port with fail-closed default bodies.
///
/// Implementations validate inputs first and then refuse without
/// manufacturing durable evidence: no successful default body exists, and
/// support is advertised only from an accepted concrete backend.
#[allow(async_fn_in_trait)]
pub trait CanonicalSnapshotPort: Send + Sync {
    /// Opens a coherent capture under one owner-issued consistency point.
    async fn begin_snapshot(
        &self,
        ctx: &RequestMeta,
        request: SnapshotBeginRequest,
    ) -> Result<SnapshotHandle, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        request.validate()?;
        Err(StoreError::Unavailable)
    }

    /// Reads one bounded page of an open capture.
    async fn read_snapshot_page(
        &self,
        ctx: &RequestMeta,
        handle: SnapshotHandle,
        cursor: SnapshotCursor,
    ) -> Result<SnapshotPage, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        handle.validate()?;
        cursor.validate()?;
        Err(StoreError::Unavailable)
    }

    /// Closes a capture with an owner-issued end receipt.
    async fn end_snapshot(
        &self,
        ctx: &RequestMeta,
        handle: SnapshotHandle,
    ) -> Result<SnapshotEndReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        handle.validate()?;
        Err(StoreError::Unavailable)
    }
}

/// Isolated-restore port with fail-closed default bodies.
///
/// Implementations validate inputs first and then refuse without
/// manufacturing durable evidence: no successful default body exists, and
/// support is advertised only from an accepted concrete backend.
#[allow(async_fn_in_trait)]
pub trait IsolatedRestorePort: Send + Sync {
    /// Prepares an isolated destination from externally admitted evidence.
    async fn prepare_isolated_destination(
        &self,
        ctx: &RequestMeta,
        destination: IsolatedDestination,
    ) -> Result<IsolationEvidence, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        destination.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Restores one bounded canonical batch into an isolated destination.
    async fn restore_canonical_batch(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        batch.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Validates a canonical restore batch without applying it.
    async fn validate_restore(
        &self,
        ctx: &RequestMeta,
        batch: CanonicalRestoreBatch,
    ) -> Result<RestoreValidationReceipt, StoreError> {
        ctx.validate().map_err(StoreError::Foundation)?;
        batch.validate()?;
        Err(StoreError::Unavailable)
    }

    /// Reconciles two identities for the same operation.
    async fn reconcile_operation(
        &self,
        first: OperationIdentity,
        second: OperationIdentity,
    ) -> Result<BackupOperationReconciliation, StoreError> {
        let outcome = reconcile_same_operation(&first, &second)?;
        let reconciliation = BackupOperationReconciliation {
            first_digest: first.canonical_request_hash.clone(),
            second_digest: second.canonical_request_hash.clone(),
            operation: first,
            outcome,
        };
        reconciliation.validate()?;
        Ok(reconciliation)
    }
}
