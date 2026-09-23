//! Bounded canonical snapshot and isolated-restore ports (issue #950).
//!
//! This module is the store-neutral capture/restore contract consumed by the
//! #975 Store EBP wire. It owns only closed shapes and fail-closed port
//! defaults: operation/request binding, source installation/store/schema/
//! generation identity, canonical revision and ordering heads, event interval,
//! exact member/type/reference and blob-residency denominator, scope/fence,
//! privacy/proof bounds, snapshot expiry and immutable digests.
//!
//! The module performs no reads, no writes, no digest computation over live
//! bytes, and mints no authority. A separate Surreal adapter implements the
//! operations (#951/#952); Kernel composition authorizes them (#959/#960).
//! Digests travel as opaque owner-issued strings: this module compares them
//! for equality but never re-derives one, so equal bytes under different
//! residency obligations remain distinct logical objects (I5.13).

use eliot_contracts::{ContractVersion, OperationId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{OperationIdentity, OrderingHead, RevisionHead, StoreError, TransitionClass};

/// Contract revision of the store backup port surface.
///
/// 1.1.0: isolated restore carries the provisional restore admission
/// slot (issues #952/#975 R2/R3) and completion receipts repeat the
/// presented decision digest.
pub const STORE_BACKUP_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 1, 0);
/// Largest member population admitted in one backup page.
pub const MAX_STORE_BACKUP_PAGE_MEMBERS: usize = 256;
/// Largest residency disposition set admitted on one completion receipt.
pub const MAX_STORE_BACKUP_RESIDENCIES: usize = 64;
/// Largest page population admitted on one evidence pack binding set.
pub const MAX_STORE_BACKUP_EVIDENCE_BINDINGS: usize = 65_536;
/// Largest stable domain label admitted on a residency disposition.
pub const MAX_STORE_BACKUP_DOMAIN_BYTES: usize = 128;

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

/// Store-neutral backup scope binding (issue #950).
///
/// Binds the capture source (installation/store/schema generation), the
/// owner-issued consistency point, the exact residency denominator digest,
/// and the admitted isolated destination. The destination pair must differ
/// from the source pair: restore never targets the active source.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupScope {
    /// Owning installation identity of the capture source.
    pub installation_id: String,
    /// Canonical store identity of the capture source.
    pub store_id: String,
    /// Expected schema generation of source and destination.
    pub schema_generation: String,
    /// Fence both endpoints must share.
    pub state_fence: StateFence,
    /// Owner-issued immutable consistency point; never a timestamp alone.
    pub consistency_point: String,
    /// Digest of the exact residency denominator this capture covers.
    pub residency_denominator_digest: String,
    /// Admitted isolated destination installation; differs from the source.
    pub dest_installation_id: String,
    /// Admitted isolated destination store; differs from the source.
    pub dest_store_id: String,
}

impl StoreBackupScope {
    /// Validates the closed scope binding without granting any authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.installation_id, "backup.installation_id")?;
        validate_text(&self.store_id, "backup.store_id")?;
        validate_text(&self.schema_generation, "backup.schema_generation")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        validate_digest(
            &self.residency_denominator_digest,
            "backup.residency_denominator_digest",
        )?;
        validate_text(&self.dest_installation_id, "backup.dest_installation_id")?;
        validate_text(&self.dest_store_id, "backup.dest_store_id")?;
        if self.dest_installation_id == self.installation_id && self.dest_store_id == self.store_id
        {
            return Err(StoreError::InvalidField {
                field: "backup.destination",
                reason: "isolated destination must differ from the capture source",
            });
        }
        Ok(())
    }
}

/// Per-residency capture disposition (issue #950).
///
/// One entry per residency domain carries its own bytes/digest/domain triple.
/// Entries are keyed by `residency_digest` only: equal content under
/// different obligations is never merged.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResidencyDisposition {
    /// Opaque owner-issued residency-key digest for this domain.
    pub residency_digest: String,
    /// Stable retention/erasure domain label for this residency.
    pub domain: String,
    /// Member population captured under this residency.
    pub member_count: u64,
    /// Total member bytes captured under this residency.
    pub member_bytes: u64,
    /// Content digest over the ordered member set of this residency.
    pub content_digest: String,
}

impl ResidencyDisposition {
    /// Validates one closed per-residency disposition.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.residency_digest, "backup.residency_digest")?;
        validate_text(&self.domain, "backup.domain")?;
        if self.domain.len() > MAX_STORE_BACKUP_DOMAIN_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        validate_digest(&self.content_digest, "backup.content_digest")?;
        Ok(())
    }
}

/// Owner-issued capture consistency handle returned by `backup_begin`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupConsistency {
    /// Stable mutation identity of the capture operation.
    pub operation_id: OperationId,
    /// Fence the capture is bound to.
    pub state_fence: StateFence,
    /// Owner-issued immutable consistency point for every page.
    pub consistency_point: String,
}

impl StoreBackupConsistency {
    /// Validates the closed consistency handle.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        Ok(())
    }
}

/// Request opening one bounded coherent canonical snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupBeginRequest {
    /// Stable mutation identity minted by Kernel admission.
    pub identity: OperationIdentity,
    /// Source, denominator and admitted isolated destination.
    pub scope: StoreBackupScope,
    /// Maximum members returned per page.
    pub max_members_per_page: u32,
    /// Maximum member bytes returned per page.
    pub max_bytes_per_page: u64,
    /// Maximum pages admitted for this capture.
    pub max_pages: u32,
}

impl StoreBackupBeginRequest {
    /// Validates the closed begin request.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.identity.validate()?;
        self.scope.validate()?;
        if self.max_members_per_page == 0
            || usize::try_from(self.max_members_per_page).unwrap_or(usize::MAX)
                > MAX_STORE_BACKUP_PAGE_MEMBERS
        {
            return Err(StoreError::InvalidField {
                field: "backup.max_members_per_page",
                reason: "must be within the bounded page population",
            });
        }
        if self.max_bytes_per_page == 0 {
            return Err(StoreError::InvalidField {
                field: "backup.max_bytes_per_page",
                reason: "must be non-zero",
            });
        }
        if self.max_pages == 0 {
            return Err(StoreError::InvalidField {
                field: "backup.max_pages",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// Request reading one page of an open capture.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupPageRequest {
    /// Capture operation this page continues.
    pub operation_id: OperationId,
    /// Owner-issued consistency point from `backup_begin`.
    pub consistency_point: String,
    /// Zero-based page cursor.
    pub cursor: u64,
    /// Maximum members returned on this page.
    pub max_members: u32,
    /// Maximum member bytes returned on this page.
    pub max_bytes: u64,
}

impl StoreBackupPageRequest {
    /// Validates the closed page request.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        if self.max_members == 0
            || usize::try_from(self.max_members).unwrap_or(usize::MAX)
                > MAX_STORE_BACKUP_PAGE_MEMBERS
        {
            return Err(StoreError::InvalidField {
                field: "backup.max_members",
                reason: "must be within the bounded page population",
            });
        }
        if self.max_bytes == 0 {
            return Err(StoreError::InvalidField {
                field: "backup.max_bytes",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

/// One captured member reference carried on a backup page.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupMember {
    /// Immutable digest of this member's canonical bytes.
    pub member_digest: String,
    /// Versioned content digest of this member's payload.
    pub content_digest: String,
    /// Residency domain digest this member was captured under.
    pub residency_digest: String,
    /// Member byte length.
    pub member_bytes: u64,
}

impl StoreBackupMember {
    /// Validates one closed member reference.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.member_digest, "backup.member_digest")?;
        validate_digest(&self.content_digest, "backup.content_digest")?;
        validate_digest(&self.residency_digest, "backup.residency_digest")?;
        Ok(())
    }
}

/// One bounded capture page bound to its consistency point.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupPage {
    /// Capture operation this page belongs to.
    pub operation_id: OperationId,
    /// Fence this page is bound to.
    pub state_fence: StateFence,
    /// Owner-issued consistency point shared by every page.
    pub consistency_point: String,
    /// Zero-based cursor of this page.
    pub cursor: u64,
    /// Cursor of the next page, or `None` when the capture is complete.
    pub next_cursor: Option<u64>,
    /// Member references on this page in deterministic logical order.
    pub members: Vec<StoreBackupMember>,
    /// Cumulative member population including this page.
    pub cumulative_members: u64,
    /// Cumulative member bytes including this page.
    pub cumulative_bytes: u64,
}

impl StoreBackupPage {
    /// Validates one closed capture page.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        if self.members.len() > MAX_STORE_BACKUP_PAGE_MEMBERS {
            return Err(StoreError::PayloadTooLarge);
        }
        for member in &self.members {
            member.validate()?;
        }
        if let Some(next) = self.next_cursor
            && next <= self.cursor
        {
            return Err(StoreError::InvalidField {
                field: "backup.next_cursor",
                reason: "continuation must advance beyond the current cursor",
            });
        }
        let page_members = u64::try_from(self.members.len()).unwrap_or(u64::MAX);
        if self.cumulative_members < page_members {
            return Err(StoreError::InvalidField {
                field: "backup.cumulative_members",
                reason: "cumulative population must cover this page",
            });
        }
        let page_bytes = self.members.iter().fold(0_u64, |total, member| {
            total.saturating_add(member.member_bytes)
        });
        if self.cumulative_bytes < page_bytes {
            return Err(StoreError::InvalidField {
                field: "backup.cumulative_bytes",
                reason: "cumulative bytes must cover this page",
            });
        }
        Ok(())
    }
}

/// Request closing one capture and issuing its completion receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupEndRequest {
    /// Capture operation being closed.
    pub operation_id: OperationId,
    /// Owner-issued consistency point the capture ran under.
    pub consistency_point: String,
}

impl StoreBackupEndRequest {
    /// Validates the closed end request.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        Ok(())
    }
}

/// Owner-issued capture completion receipt (issue #950).
///
/// Binds the stable operation identity, the fence, the consistency point,
/// the whole-snapshot digest, the scope residency denominator, and the exact
/// per-residency bytes/digest/domain dispositions. A partial capture stays
/// explicitly partial: it never reports complete.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupCompletionReceipt {
    /// Stable mutation identity of the capture operation.
    pub operation_id: OperationId,
    /// Fence the capture ran under.
    pub state_fence: StateFence,
    /// Owner-issued consistency point the capture ran under.
    pub consistency_point: String,
    /// Whole-snapshot digest over the ordered member set.
    pub snapshot_digest: String,
    /// Residency denominator digest named by the capture scope.
    pub scope_residency_digest: String,
    /// Total captured member population.
    pub member_count: u64,
    /// Total captured member bytes.
    pub total_bytes: u64,
    /// Exact per-residency bytes/digest/domain dispositions.
    pub residencies: Vec<ResidencyDisposition>,
    /// Canonical revision heads observed at the consistency point.
    pub revision_heads: Vec<RevisionHead>,
    /// Ordering heads observed at the consistency point.
    pub ordering_heads: Vec<OrderingHead>,
    /// Whether the capture closed over a partial denominator.
    pub partial: bool,
    /// Presented admission decision digest repeated from the restore
    /// admission (issues #952/#975 R2). `None` on capture receipts, which
    /// are not admitted restores; `Some` on every restore receipt, so the
    /// committed receipt repeats the exact admitted decision digest it
    /// executed under. `Option` with a serde default keeps previously
    /// completed capture receipts readable.
    #[serde(default)]
    pub admission_decision_digest: Option<String>,
}

impl StoreBackupCompletionReceipt {
    /// Validates the closed completion receipt.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.consistency_point, "backup.consistency_point")?;
        validate_digest(&self.snapshot_digest, "backup.snapshot_digest")?;
        if let Some(digest) = &self.admission_decision_digest {
            validate_digest(digest, "backup.admission_decision_digest")?;
        }
        validate_digest(
            &self.scope_residency_digest,
            "backup.scope_residency_digest",
        )?;
        if self.residencies.len() > MAX_STORE_BACKUP_RESIDENCIES {
            return Err(StoreError::PayloadTooLarge);
        }
        if self.residencies.is_empty() && self.member_count > 0 {
            return Err(StoreError::InvalidField {
                field: "backup.residencies",
                reason: "non-empty capture requires per-residency dispositions",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut summed_members = 0_u64;
        let mut summed_bytes = 0_u64;
        for residency in &self.residencies {
            residency.validate()?;
            if !seen.insert(residency.residency_digest.clone()) {
                return Err(StoreError::Duplicate {
                    field: "backup.residencies",
                });
            }
            summed_members = summed_members.saturating_add(residency.member_count);
            summed_bytes = summed_bytes.saturating_add(residency.member_bytes);
        }
        if summed_members != self.member_count || summed_bytes != self.total_bytes {
            return Err(StoreError::InvalidField {
                field: "backup.denominator",
                reason: "per-residency dispositions must sum to the receipt totals",
            });
        }
        for head in &self.revision_heads {
            head.validate()?;
        }
        for head in &self.ordering_heads {
            head.validate()?;
        }
        Ok(())
    }
}

/// Admitted restore operation class marker (issues #952/#975 R3).
///
/// The single operation class reserved for isolated restore. It is
/// carried per operation on [`StoreRestoreAdmission`], never granted
/// through a normal-write capability, and never reinterpreted from a
/// reserved request: a restore without exactly this class refuses before
/// any provider I/O.
pub const RESTORE_OPERATION_CLASS: &str = "backup.restore";

/// PROVISIONAL restore admission carried by one isolated restore
/// (issues #952/#975 R2/R3).
///
/// This is the operation-class admission slot the restore executes under:
/// it binds the stable restore identity, the fixed `RecoverySchema`
/// transition class, the fixed [`RESTORE_OPERATION_CLASS`], the admitted
/// isolated destination, the shared fence, the capture denominator, and
/// the source snapshot. The store bridge recomputes
/// [`Self::decision_digest`] and refuses any mismatch, then executes
/// exactly the presented plan and repeats the digest in the restore
/// receipt. The bridge never mints, widens, or reinterprets this
/// admission.
///
/// PROVISIONAL — not proof of Governor issuance: recomputation verifies
/// self-consistency only. Any transport peer can mint a fully consistent
/// struct, so this admission alone authorizes nothing; the bridge
/// additionally binds it to independent canonical anchors (the completed
/// live source-capture row, the deployment-provisioned destination
/// record, the frame-enforced session capability and transport identity)
/// and refuses replays under a rotated digest. The future Governor
/// minter (#959/#960) replaces provisional minting with a durable
/// admission anchor the bridge reads back: a committed coordination row
/// keyed by the restore operation identity carrying the Governor's
/// decision digest over the exact operation/destination/payload-digest/
/// fence tuple below. Until that anchor exists, no restore is admittable
/// by this struct, and no claim in this module asserts otherwise.
///
/// Minter gap (exact): the Governor-side minter does not exist yet, so
/// no caller can honestly produce an admitted instance today. What this
/// contract verifies: closed shape, fixed class markers,
/// identity/destination/fence/denominator/snapshot cross-bindings against
/// the request and scope, and equality of the recomputed decision digest.
/// What it cannot supply: issuance itself — which must arrive through the
/// Governor owner, never through session capability, reserved-write
/// relabeling, or a caller-fabricated digest. Verification here is
/// deliberately not weakened to fake admittability.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRestoreAdmission {
    /// Stable restore operation identity; must equal the request identity.
    pub identity: OperationIdentity,
    /// Transition class the restore executes under; must be `RecoverySchema`.
    pub transition_class: TransitionClass,
    /// Admitted operation class; must be [`RESTORE_OPERATION_CLASS`].
    pub operation_class: String,
    /// Admitted isolated destination installation; must equal the scope dest.
    pub dest_installation_id: String,
    /// Admitted isolated destination store; must equal the scope dest and
    /// must differ from both the capture source and the serving store.
    pub dest_store_id: String,
    /// Fence both endpoints share; must equal the scope fence.
    pub state_fence: StateFence,
    /// Capture denominator digest; must equal the scope denominator.
    pub residency_denominator_digest: String,
    /// Source snapshot digest; must equal the request source digest.
    pub source_snapshot_digest: String,
    /// Decision digest over every field above, recomputed by
    /// [`Self::decision_digest`] and compared for equality downstream.
    /// Recomputation proves self-consistency, never issuance.
    pub admission_decision_digest: String,
}

impl StoreRestoreAdmission {
    /// Recomputes the admission decision digest over the bound fields.
    ///
    /// Pure over closed inputs, so equal bytes under different bindings
    /// stay distinct and no digest is ever accepted from a caller without
    /// recomputation. This binds the fields to each other; it does not
    /// bind them to any issuer.
    pub fn decision_digest(&self) -> Result<String, StoreError> {
        use eliot_contracts::{canonical_json_bytes, sha256_hex};
        let fence_bytes = canonical_json_bytes(&self.state_fence)
            .map_err(|_| StoreError::InvalidField {
                field: "backup.admission_decision_digest",
                reason: "fence bytes are not canonical",
            })?;
        let mut material = Vec::with_capacity(fence_bytes.len() + 256);
        material.extend_from_slice(b"backup-restore-admission:v1\n");
        material.extend_from_slice(self.identity.operation_id.to_string().as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.identity.idempotency_key.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.identity.canonical_request_hash.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(b"recovery_schema\n");
        material.extend_from_slice(self.operation_class.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.dest_installation_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.dest_store_id.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(&fence_bytes);
        material.push(b'\n');
        material.extend_from_slice(self.residency_denominator_digest.as_bytes());
        material.push(b'\n');
        material.extend_from_slice(self.source_snapshot_digest.as_bytes());
        Ok(sha256_hex(&material))
    }

    /// Validates the closed restore admission without granting authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.identity.validate()?;
        if self.transition_class != TransitionClass::RecoverySchema {
            return Err(StoreError::InvalidField {
                field: "backup.transition_class",
                reason: "isolated restore executes only under RecoverySchema",
            });
        }
        if self.operation_class != RESTORE_OPERATION_CLASS {
            return Err(StoreError::InvalidField {
                field: "backup.operation_class",
                reason: "isolated restore requires the admitted restore operation class",
            });
        }
        validate_text(&self.dest_installation_id, "backup.dest_installation_id")?;
        validate_text(&self.dest_store_id, "backup.dest_store_id")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(
            &self.residency_denominator_digest,
            "backup.residency_denominator_digest",
        )?;
        validate_digest(
            &self.source_snapshot_digest,
            "backup.source_snapshot_digest",
        )?;
        let recomputed = self.decision_digest()?;
        if recomputed != self.admission_decision_digest {
            return Err(StoreError::IdentityConflict);
        }
        Ok(())
    }
}

/// Request restoring validated canonical records into an admitted isolated
/// destination (issue #950).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreIsolatedRestoreRequest {
    /// Stable mutation identity of the restore operation.
    pub identity: OperationIdentity,
    /// Capture operation that produced the source snapshot.
    pub source_operation_id: OperationId,
    /// Whole-snapshot digest of the source capture.
    pub source_snapshot_digest: String,
    /// Admitted isolated destination scope; differs from the source.
    pub scope: StoreBackupScope,
    /// Provisional restore admission this execution presents. Session
    /// capability alone never authorizes a restore; and this struct alone
    /// proves no issuance (see [`StoreRestoreAdmission`]).
    pub admission: StoreRestoreAdmission,
    /// Expected member population from the source receipt.
    pub expected_member_count: u64,
    /// Maximum members applied per batch.
    pub max_members_per_batch: u32,
}

impl StoreIsolatedRestoreRequest {
    /// Validates the closed isolated-restore request.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.identity.validate()?;
        self.scope.validate()?;
        self.admission.validate()?;
        validate_digest(
            &self.source_snapshot_digest,
            "backup.source_snapshot_digest",
        )?;
        if self.admission.identity != self.identity {
            return Err(StoreError::IdentityConflict);
        }
        if self.admission.dest_installation_id != self.scope.dest_installation_id
            || self.admission.dest_store_id != self.scope.dest_store_id
        {
            return Err(StoreError::IdentityConflict);
        }
        if self.admission.state_fence != self.scope.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        if self.admission.residency_denominator_digest != self.scope.residency_denominator_digest
        {
            return Err(StoreError::IdentityConflict);
        }
        if self.admission.source_snapshot_digest != self.source_snapshot_digest {
            return Err(StoreError::IdentityConflict);
        }
        if self.max_members_per_batch == 0
            || usize::try_from(self.max_members_per_batch).unwrap_or(usize::MAX)
                > MAX_STORE_BACKUP_PAGE_MEMBERS
        {
            return Err(StoreError::InvalidField {
                field: "backup.max_members_per_batch",
                reason: "must be within the bounded page population",
            });
        }
        Ok(())
    }
}

/// Request validating one captured snapshot without restoring it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupValidationRequest {
    /// Capture or restore operation that produced the snapshot.
    pub operation_id: OperationId,
    /// Whole-snapshot digest under validation.
    pub snapshot_digest: String,
}

impl StoreBackupValidationRequest {
    /// Validates the closed validation request.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.snapshot_digest, "backup.snapshot_digest")?;
        Ok(())
    }
}

/// Closed validation outcome: unavailable validation never reports success.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoreBackupValidationOutcome {
    /// Complete authoritative denominator observed.
    Complete,
    /// Partial denominator observed; not restorable as complete.
    Partial,
    /// Known-empty denominator with complete authoritative accounting.
    KnownEmpty,
    /// Validation unsupported for this snapshot class.
    Unsupported,
    /// Validation conflicts with current purge/reference state.
    Conflict,
}

/// Owner-issued validation receipt for one snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupValidationReceipt {
    /// Operation that produced the snapshot under validation.
    pub operation_id: OperationId,
    /// Fence the validation ran under.
    pub state_fence: StateFence,
    /// Whole-snapshot digest that was validated.
    pub snapshot_digest: String,
    /// Closed validation outcome.
    pub outcome: StoreBackupValidationOutcome,
    /// Members with verified digests.
    pub checked_members: u64,
    /// Members without authoritative evidence.
    pub unresolved_members: u64,
}

impl StoreBackupValidationReceipt {
    /// Validates the closed validation receipt.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_digest(&self.snapshot_digest, "backup.snapshot_digest")?;
        if matches!(self.outcome, StoreBackupValidationOutcome::Complete)
            && self.unresolved_members > 0
        {
            return Err(StoreError::InvalidField {
                field: "backup.unresolved_members",
                reason: "complete validation requires zero unresolved members",
            });
        }
        if matches!(self.outcome, StoreBackupValidationOutcome::KnownEmpty)
            && (self.checked_members > 0 || self.unresolved_members > 0)
        {
            return Err(StoreError::InvalidField {
                field: "backup.known_empty",
                reason: "known-empty validation requires a zero denominator",
            });
        }
        Ok(())
    }
}

/// Request observing the status of one backup operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupStatusRequest {
    /// Backup operation under observation.
    pub operation_id: OperationId,
}

impl StoreBackupStatusRequest {
    /// Validates the closed status request.
    pub fn validate(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Closed backup lifecycle phase.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoreBackupPhase {
    /// Capture opened; pages outstanding.
    Capturing,
    /// Restore batches outstanding against the isolated destination.
    Restoring,
    /// Closed with a completion receipt.
    Completed,
    /// Consistency point expired before completion.
    Expired,
    /// No durable evidence for this operation.
    Unknown,
}

/// Owner-issued status report for one backup operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupStatusReport {
    /// Backup operation under observation.
    pub operation_id: OperationId,
    /// Fence the report is bound to.
    pub state_fence: StateFence,
    /// Closed lifecycle phase.
    pub phase: StoreBackupPhase,
    /// Durably completed members.
    pub completed_members: u64,
    /// Durably completed bytes.
    pub completed_bytes: u64,
}

impl StoreBackupStatusReport {
    /// Validates the closed status report.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        Ok(())
    }
}

/// Request reconciling one uncertain backup mutation by exact identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBackupReconcileRequest {
    /// Backup operation under reconciliation.
    pub operation_id: OperationId,
    /// Admitted canonical request digest of that operation.
    pub canonical_request_hash: String,
}

impl StoreBackupReconcileRequest {
    /// Validates the closed reconcile request.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(
            &self.canonical_request_hash,
            "backup.canonical_request_hash",
        )?;
        Ok(())
    }
}

/// Closed reconciliation outcome for one backup operation.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StoreBackupReconciliation {
    /// Durably committed under the exact admitted identity.
    Committed,
    /// Changed input under the same operation identity.
    Conflict,
    /// No durable evidence; outcome remains unknown, never success.
    Unknown,
}

/// One restore binding carried in the consumer evidence pack.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBinding {
    /// Immutable digest of the member's canonical bytes.
    pub member_digest: String,
    /// Versioned content digest of the member's payload.
    pub content_digest: String,
    /// Residency domain digest the member restores under.
    pub residency_digest: String,
}

impl RestoreBinding {
    /// Validates one closed restore binding.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_digest(&self.member_digest, "backup.member_digest")?;
        validate_digest(&self.content_digest, "backup.content_digest")?;
        validate_digest(&self.residency_digest, "backup.residency_digest")?;
        Ok(())
    }
}

/// Consumer evidence pack carried by the Store backup wire (issue #975).
///
/// Mirrors the author's blob-side `ConsumerEvidencePack` field contract in
/// store-neutral vocabulary: the owner-issued completion receipt, the exact
/// per-member restore bindings, and the destination scope binding the receipt
/// was completed against. The wire transports this pack verbatim and adds
/// transport identity around it; it never re-derives a digest.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreEvidencePack {
    receipt: StoreBackupCompletionReceipt,
    bindings: Vec<RestoreBinding>,
    dest_installation_id: String,
    dest_store_id: String,
    scope_residency_digest: String,
}

impl StoreEvidencePack {
    /// Assembles the pack from a completed capture.
    ///
    /// Re-checks receipt/binding consistency here: member counts match, every
    /// binding sits under the scope residency digest named by the receipt,
    /// every binding residency is covered by a receipt disposition, and the
    /// destination binding equals the scope the receipt was completed
    /// against.
    pub fn assemble(
        receipt: StoreBackupCompletionReceipt,
        bindings: Vec<RestoreBinding>,
        scope: &StoreBackupScope,
    ) -> Result<Self, StoreError> {
        receipt.validate()?;
        scope.validate()?;
        let binding_count = u64::try_from(bindings.len()).unwrap_or(u64::MAX);
        if receipt.member_count != binding_count {
            return Err(StoreError::InvalidField {
                field: "backup.evidence",
                reason: "binding population must equal the receipt member count",
            });
        }
        if bindings.len() > MAX_STORE_BACKUP_EVIDENCE_BINDINGS {
            return Err(StoreError::PayloadTooLarge);
        }
        if receipt.scope_residency_digest != scope.residency_denominator_digest {
            return Err(StoreError::InvalidField {
                field: "backup.evidence",
                reason: "receipt denominator must equal the admitted scope denominator",
            });
        }
        for binding in &bindings {
            binding.validate()?;
            if binding.residency_digest != scope.residency_denominator_digest
                && !receipt
                    .residencies
                    .iter()
                    .any(|residency| residency.residency_digest == binding.residency_digest)
            {
                return Err(StoreError::InvalidField {
                    field: "backup.evidence",
                    reason: "every binding must sit under a receipt residency disposition",
                });
            }
        }
        Ok(Self {
            receipt,
            bindings,
            dest_installation_id: scope.dest_installation_id.clone(),
            dest_store_id: scope.dest_store_id.clone(),
            scope_residency_digest: scope.residency_denominator_digest.clone(),
        })
    }

    /// Owner-issued completion receipt carried by this pack.
    #[must_use]
    pub fn receipt(&self) -> &StoreBackupCompletionReceipt {
        &self.receipt
    }

    /// Exact per-member restore bindings carried by this pack.
    #[must_use]
    pub fn bindings(&self) -> &[RestoreBinding] {
        &self.bindings
    }

    /// Admitted isolated destination installation carried by this pack.
    #[must_use]
    pub fn dest_installation_id(&self) -> &str {
        &self.dest_installation_id
    }

    /// Admitted isolated destination store carried by this pack.
    #[must_use]
    pub fn dest_store_id(&self) -> &str {
        &self.dest_store_id
    }

    /// Scope residency digest the receipt was completed against.
    #[must_use]
    pub fn scope_residency_digest(&self) -> &str {
        &self.scope_residency_digest
    }

    /// Validates the closed evidence pack.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.receipt.validate()?;
        for binding in &self.bindings {
            binding.validate()?;
        }
        let binding_count = u64::try_from(self.bindings.len()).unwrap_or(u64::MAX);
        if self.receipt.member_count != binding_count {
            return Err(StoreError::InvalidField {
                field: "backup.evidence",
                reason: "binding population must equal the receipt member count",
            });
        }
        validate_text(&self.dest_installation_id, "backup.dest_installation_id")?;
        validate_text(&self.dest_store_id, "backup.dest_store_id")?;
        validate_digest(
            &self.scope_residency_digest,
            "backup.scope_residency_digest",
        )?;
        Ok(())
    }
}

/// Store backup port surface implemented by the canonical adapter (#951/#952).
///
/// Additive dedicated trait so existing [`crate::CanonicalStoreClient`]
/// implementations remain buildable: every method has a fail-closed default
/// that validates the closed request shape and then refuses with
/// [`StoreError::UnknownOperation`] without effects. Granting no read,
/// restore or effect authority by itself, these declarations never
/// authenticate a caller or establish external admission.
#[allow(async_fn_in_trait)]
pub trait CanonicalBackupPorts: Send + Sync {
    /// Opens one bounded coherent canonical snapshot.
    async fn backup_begin(
        &self,
        request: StoreBackupBeginRequest,
    ) -> Result<StoreBackupConsistency, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Reads one page of an open capture under its consistency point.
    async fn backup_page(
        &self,
        request: StoreBackupPageRequest,
    ) -> Result<StoreBackupPage, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Closes one capture and issues its completion receipt.
    async fn backup_end(
        &self,
        request: StoreBackupEndRequest,
    ) -> Result<StoreBackupCompletionReceipt, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Restores validated canonical records into the admitted isolated
    /// destination only.
    async fn backup_isolated_restore(
        &self,
        request: StoreIsolatedRestoreRequest,
    ) -> Result<StoreBackupCompletionReceipt, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Validates one captured snapshot without restoring it.
    async fn backup_validate(
        &self,
        request: StoreBackupValidationRequest,
    ) -> Result<StoreBackupValidationReceipt, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Observes the status of one backup operation.
    async fn backup_status(
        &self,
        request: StoreBackupStatusRequest,
    ) -> Result<StoreBackupStatusReport, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }

    /// Reconciles one uncertain backup mutation by exact identity.
    async fn backup_reconcile(
        &self,
        request: StoreBackupReconcileRequest,
    ) -> Result<StoreBackupReconciliation, StoreError> {
        request.validate()?;
        Err(StoreError::UnknownOperation)
    }
}
