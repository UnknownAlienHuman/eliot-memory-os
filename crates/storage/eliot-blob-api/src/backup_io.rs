//! Provider-neutral sealed-blob backup values: destination scope and capture
//! evidence (issue #956, slice 1).
//!
//! The F restore lane (`bins/eliot-kernel/src/backup_restore.rs`) refuses a
//! sealed-blob archive without an admitted destination blob scope
//! (`BLOB_SCOPE_BINDING = "blob-destination-scope"`) and consumes
//! per-residency sealed capture evidence. These values are that lane's
//! Blob-owner vocabulary: [`BlobBackupScope`] binds one isolated destination
//! (root generation plus destination key lineage/generation plus the exact
//! residency-key digest under import), and [`SealedBlobCaptureRecord`] binds
//! one captured sealed member (locator plus sealed/plaintext digests plus the
//! envelope crypto descriptor plus the residency-key digest).
//!
//! # Authority boundary
//!
//! Both types have private fields and validate through the real owner
//! contracts on every construction path: [`BlobRootLease::validate`],
//! [`CryptoDescriptor::validate`], [`ObjectResidencyKey::validate`],
//! [`BlobLocator::validate`], and [`ObjectResidencyKey::key_digest`]. There
//! is no caller-asserted scope: issuance recomputes the residency digest from
//! the validated residency identity, and verification re-checks every binding.
//! Neither type mints authority — key possession is proven separately by the
//! Blob owner resolving the descriptor through its real key port
//! (`eliot-blob/src/backup_io.rs`), and decryptability stays attested by the
//! envelope owner, never by ciphertext equality here.

use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};

use super::{
    BlobError, BlobHash, BlobId, BlobLocator, BlobRootLease, CryptoDescriptor, ObjectResidencyKey,
};

fn validate_hex_field(value: &str, field: &'static str) -> Result<(), BlobError> {
    BlobHash::new(value).map_err(|_| BlobError::InvalidField {
        field,
        reason: "must be lowercase hex",
    })?;
    Ok(())
}

/// Owner-issued destination scope for sealed-blob backup import.
///
/// Binds the admitted destination root generation, the destination key
/// lineage/generation that re-sealed envelopes must carry, and the exact
/// residency-key digest of the residency identity under import. Equal content
/// in different residency domains yields different digests, so the scope can
/// never authorize cross-domain coalescing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobBackupScope {
    dest_root_generation: u64,
    dest_key_lineage: BlobId,
    dest_key_generation: u64,
    residency_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobBackupScopeWire {
    dest_root_generation: u64,
    dest_key_lineage: BlobId,
    dest_key_generation: u64,
    residency_digest: String,
}

impl BlobBackupScope {
    /// Issues a destination scope from owner-validated inputs.
    ///
    /// Validates the destination root lease, the destination crypto
    /// descriptor, and the residency identity through their real owner
    /// contracts, then derives the residency digest from the validated
    /// residency — the caller supplies no digest text.
    pub fn issue(
        lease: &BlobRootLease,
        crypto: &CryptoDescriptor,
        residency: &ObjectResidencyKey,
    ) -> Result<Self, BlobError> {
        lease.validate()?;
        crypto.validate()?;
        residency.validate()?;
        let scope = Self {
            dest_root_generation: lease.root_generation,
            dest_key_lineage: crypto.key_lineage.clone(),
            dest_key_generation: crypto.key_generation,
            residency_digest: residency.key_digest()?,
        };
        scope.validate()?;
        Ok(scope)
    }

    fn validate(&self) -> Result<(), BlobError> {
        if self.dest_root_generation == 0 || self.dest_key_generation == 0 {
            return Err(BlobError::InvalidField {
                field: "backup_scope.generation",
                reason: "must be greater than zero",
            });
        }
        validate_hex_field(&self.residency_digest, "backup_scope.residency_digest")?;
        Ok(())
    }

    /// Re-verifies this scope against live owner-validated inputs.
    ///
    /// Generation drift of the destination root refuses with
    /// [`BlobError::StaleFence`]; a rotated destination key binding refuses as
    /// a field mismatch; a residency digest that no longer matches the exact
    /// residency identity refuses as [`BlobError::IntegrityMismatch`].
    pub fn verify_against(
        &self,
        lease: &BlobRootLease,
        crypto: &CryptoDescriptor,
        residency: &ObjectResidencyKey,
    ) -> Result<(), BlobError> {
        lease.validate()?;
        crypto.validate()?;
        residency.validate()?;
        if lease.root_generation != self.dest_root_generation {
            return Err(BlobError::StaleFence);
        }
        if crypto.key_lineage != self.dest_key_lineage
            || crypto.key_generation != self.dest_key_generation
        {
            return Err(BlobError::InvalidField {
                field: "backup_scope.crypto",
                reason: "does not match the issued destination key binding",
            });
        }
        if residency.key_digest()? != self.residency_digest {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Admitted destination root generation.
    #[must_use]
    pub fn dest_root_generation(&self) -> u64 {
        self.dest_root_generation
    }

    /// Destination key lineage re-sealed envelopes must carry.
    #[must_use]
    pub fn dest_key_lineage(&self) -> &BlobId {
        &self.dest_key_lineage
    }

    /// Destination key generation; always greater than zero.
    #[must_use]
    pub fn dest_key_generation(&self) -> u64 {
        self.dest_key_generation
    }

    /// Exact residency-key digest of the residency identity under import.
    #[must_use]
    pub fn residency_digest(&self) -> &str {
        &self.residency_digest
    }
}

impl<'de> Deserialize<'de> for BlobBackupScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobBackupScopeWire::deserialize(deserializer)?;
        let value = Self {
            dest_root_generation: wire.dest_root_generation,
            dest_key_lineage: wire.dest_key_lineage,
            dest_key_generation: wire.dest_key_generation,
            residency_digest: wire.residency_digest,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Per-residency sealed capture evidence for one blob member.
///
/// Records the exact [`BlobLocator`] captured, the sealed-envelope and
/// plaintext digests observed by the envelope owner, the envelope
/// [`CryptoDescriptor`], and the residency-key digest derived from the
/// validated locator. The crypto key lineage must equal the locator's
/// residency encryption-key domain: an envelope bound to a foreign lineage
/// cannot ride on this residency's evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SealedBlobCaptureRecord {
    locator: BlobLocator,
    sealed_sha256: String,
    plaintext_sha256: String,
    crypto: CryptoDescriptor,
    residency_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedBlobCaptureRecordWire {
    locator: BlobLocator,
    sealed_sha256: String,
    plaintext_sha256: String,
    crypto: CryptoDescriptor,
    residency_digest: String,
}

impl SealedBlobCaptureRecord {
    /// Records capture evidence from owner-validated inputs.
    ///
    /// Validates the locator and crypto descriptor through their real owner
    /// contracts, binds the envelope lineage to the locator's residency
    /// key-lineage domain, checks both digest shapes, and derives the
    /// residency digest from the validated locator.
    pub fn capture(
        locator: BlobLocator,
        sealed_sha256: String,
        plaintext_sha256: String,
        crypto: CryptoDescriptor,
    ) -> Result<Self, BlobError> {
        let record = Self {
            residency_digest: locator.residency_key_digest()?,
            locator,
            sealed_sha256,
            plaintext_sha256,
            crypto,
        };
        record.validate()?;
        Ok(record)
    }

    /// Re-validates the recorded evidence bindings.
    pub fn validate(&self) -> Result<(), BlobError> {
        self.locator.validate()?;
        self.crypto.validate()?;
        if self.crypto.key_lineage != self.locator.residency.encryption_key_domain_id {
            return Err(BlobError::InvalidField {
                field: "capture.crypto_lineage",
                reason: "must equal the locator residency key lineage",
            });
        }
        validate_hex_field(&self.sealed_sha256, "capture.sealed_sha256")?;
        validate_hex_field(&self.plaintext_sha256, "capture.plaintext_sha256")?;
        if self.locator.residency_key_digest()? != self.residency_digest {
            return Err(BlobError::IntegrityMismatch);
        }
        Ok(())
    }

    /// Exact locator captured.
    #[must_use]
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Digest of the sealed envelope bytes.
    #[must_use]
    pub fn sealed_sha256(&self) -> &str {
        &self.sealed_sha256
    }

    /// Plaintext digest attested by the envelope owner.
    #[must_use]
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    /// Envelope crypto descriptor bound to the residency key lineage.
    #[must_use]
    pub fn crypto(&self) -> &CryptoDescriptor {
        &self.crypto
    }

    /// Residency-key digest derived from the validated locator.
    #[must_use]
    pub fn residency_digest(&self) -> &str {
        &self.residency_digest
    }
}

impl<'de> Deserialize<'de> for SealedBlobCaptureRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = SealedBlobCaptureRecordWire::deserialize(deserializer)?;
        let value = Self {
            locator: wire.locator,
            sealed_sha256: wire.sealed_sha256,
            plaintext_sha256: wire.plaintext_sha256,
            crypto: wire.crypto,
            residency_digest: wire.residency_digest,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Predecessor marker for page zero. It is not 64-hex, so it can never equal
/// a real page digest and a continuation can never claim a genesis start.
pub const BLOB_BACKUP_GENESIS: &str = "GENESIS";

fn valid_operation_id(value: &str, field: &'static str) -> Result<(), BlobError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(BlobError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

/// One fenced denominator member: the exact locator plus the durable
/// metadata binding the service read path requires.
///
/// The locator alone never authorizes a read: `expected_metadata_sha256` and
/// `expected_ready_receipt_id` pin the exact durable metadata the member was
/// fenced against, so a replaced or drifted payload refuses instead of
/// sealing under a stale identity. Both bindings come from canonical capture
/// with the locator, never from a later scan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FencedBlobMember {
    locator: BlobLocator,
    expected_metadata_sha256: String,
    expected_ready_receipt_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedBlobMemberWire {
    locator: BlobLocator,
    expected_metadata_sha256: String,
    expected_ready_receipt_id: String,
}

impl FencedBlobMember {
    /// Fixes one denominator member from the externally fenced capture
    /// denominator. The locator validates through the owner contract; both
    /// metadata bindings validate as shapes here and are re-proved by the
    /// service read itself.
    pub fn member(
        locator: BlobLocator,
        expected_metadata_sha256: String,
        expected_ready_receipt_id: String,
    ) -> Result<Self, BlobError> {
        let member = Self {
            locator,
            expected_metadata_sha256,
            expected_ready_receipt_id,
        };
        member.validate()?;
        Ok(member)
    }

    fn validate(&self) -> Result<(), BlobError> {
        self.locator.validate()?;
        validate_hex_field(
            &self.expected_metadata_sha256,
            "backup_fence.expected_metadata_sha256",
        )?;
        valid_operation_id(
            &self.expected_ready_receipt_id,
            "backup_fence.expected_ready_receipt_id",
        )?;
        Ok(())
    }

    /// Exact locator captured.
    #[must_use]
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Durable metadata digest the service read must match.
    #[must_use]
    pub fn expected_metadata_sha256(&self) -> &str {
        &self.expected_metadata_sha256
    }

    /// Ready receipt identity the service read must match.
    #[must_use]
    pub fn expected_ready_receipt_id(&self) -> &str {
        &self.expected_ready_receipt_id
    }
}

impl<'de> Deserialize<'de> for FencedBlobMember {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = FencedBlobMemberWire::deserialize(deserializer)?;
        let value = Self {
            locator: wire.locator,
            expected_metadata_sha256: wire.expected_metadata_sha256,
            expected_ready_receipt_id: wire.expected_ready_receipt_id,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// Fenced export denominator: the exact finite member set one backup
/// operation must account for.
///
/// The member list comes from canonical capture (the externally fenced
/// residency/locator denominator), never from a filesystem scan or a
/// content-hash list. Equal content under different residency domains stays
/// two distinct members; an exact duplicate locator refuses. Bounds are part
/// of the fence: pages that would exceed them refuse instead of silently
/// combining newer material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobBackupFence {
    operation_id: String,
    source_root_generation: u64,
    members: Vec<FencedBlobMember>,
    max_members_per_page: u32,
    max_bytes_per_member: u64,
    max_total_sealed_bytes: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobBackupFenceWire {
    operation_id: String,
    source_root_generation: u64,
    members: Vec<FencedBlobMember>,
    max_members_per_page: u32,
    max_bytes_per_member: u64,
    max_total_sealed_bytes: u64,
}

impl BlobBackupFence {
    /// Fixes the denominator for one backup operation. Every member
    /// validates through the owner contract here, before any byte is read.
    pub fn fence(
        operation_id: String,
        source_root_generation: u64,
        members: Vec<FencedBlobMember>,
        max_members_per_page: u32,
        max_bytes_per_member: u64,
        max_total_sealed_bytes: u64,
    ) -> Result<Self, BlobError> {
        let fence = Self {
            operation_id,
            source_root_generation,
            members,
            max_members_per_page,
            max_bytes_per_member,
            max_total_sealed_bytes,
        };
        fence.validate()?;
        Ok(fence)
    }

    fn validate(&self) -> Result<(), BlobError> {
        valid_operation_id(&self.operation_id, "backup_fence.operation_id")?;
        if self.source_root_generation == 0 {
            return Err(BlobError::InvalidField {
                field: "backup_fence.source_root_generation",
                reason: "must be greater than zero",
            });
        }
        if self.max_members_per_page == 0
            || self.max_bytes_per_member == 0
            || self.max_total_sealed_bytes == 0
        {
            return Err(BlobError::InvalidField {
                field: "backup_fence.bounds",
                reason: "page, member, and total bounds must be greater than zero",
            });
        }
        for member in &self.members {
            member.validate()?;
        }
        for (index, member) in self.members.iter().enumerate() {
            if self.members[..index]
                .iter()
                .any(|seen| seen.locator() == member.locator())
            {
                return Err(BlobError::DuplicateIdentity("backup_fence"));
            }
        }
        Ok(())
    }

    /// Operation this denominator belongs to.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Source root generation frozen at fence time; drift refuses pages.
    #[must_use]
    pub fn source_root_generation(&self) -> u64 {
        self.source_root_generation
    }

    /// Exact finite member set.
    #[must_use]
    pub fn members(&self) -> &[FencedBlobMember] {
        &self.members
    }

    /// Number of fenced members; may be zero only as an explicitly fenced
    /// known-empty denominator, never as an unaccounted gap.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Member at `index`, or `None` past the fence end.
    #[must_use]
    pub fn member(&self, index: usize) -> Option<&FencedBlobMember> {
        self.members.get(index)
    }

    /// Locates the fenced member for an exact locator, or `None` when the
    /// locator is outside the fenced denominator.
    #[must_use]
    pub fn find_member(&self, locator: &BlobLocator) -> Option<&FencedBlobMember> {
        self.members
            .iter()
            .find(|member| member.locator() == locator)
    }

    /// Page-size ceiling for this fence.
    #[must_use]
    pub fn max_members_per_page(&self) -> u32 {
        self.max_members_per_page
    }

    /// Per-member plaintext byte ceiling for this fence.
    #[must_use]
    pub fn max_bytes_per_member(&self) -> u64 {
        self.max_bytes_per_member
    }

    /// Cumulative sealed-byte ceiling for the whole operation.
    #[must_use]
    pub fn max_total_sealed_bytes(&self) -> u64 {
        self.max_total_sealed_bytes
    }
}

impl<'de> Deserialize<'de> for BlobBackupFence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobBackupFenceWire::deserialize(deserializer)?;
        let value = Self {
            operation_id: wire.operation_id,
            source_root_generation: wire.source_root_generation,
            members: wire.members,
            max_members_per_page: wire.max_members_per_page,
            max_bytes_per_member: wire.max_bytes_per_member,
            max_total_sealed_bytes: wire.max_total_sealed_bytes,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

/// One bounded page window over the fenced denominator.
///
/// A page names its exact member index window plus the running cumulative
/// totals before it, so continuation binds one snapshot and cumulative
/// limits: the next page starts where this one ends, carries the chained
/// predecessor digest, and adds checked totals. Expired continuations and
/// mixed generations cannot be stitched into a complete result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BlobBackupPage {
    operation_id: String,
    page_index: u32,
    start_index: usize,
    member_count: usize,
    predecessor: String,
    cumulative_members_before: u64,
    cumulative_bytes_before: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobBackupPageWire {
    operation_id: String,
    page_index: u32,
    start_index: usize,
    member_count: usize,
    predecessor: String,
    cumulative_members_before: u64,
    cumulative_bytes_before: u64,
}

impl BlobBackupPage {
    /// Opens one page window. Page zero must carry the genesis predecessor;
    /// later pages carry the previous page's digest. Any other predecessor
    /// shape refuses: timestamps or caller text never chain pages.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        fence: &BlobBackupFence,
        page_index: u32,
        start_index: usize,
        len: usize,
        predecessor: String,
        cumulative_members_before: u64,
        cumulative_bytes_before: u64,
    ) -> Result<Self, BlobError> {
        let page = Self {
            operation_id: fence.operation_id.clone(),
            page_index,
            start_index,
            member_count: len,
            predecessor,
            cumulative_members_before,
            cumulative_bytes_before,
        };
        page.validate_for(fence)?;
        Ok(page)
    }

    fn validate_for(&self, fence: &BlobBackupFence) -> Result<(), BlobError> {
        valid_operation_id(&self.operation_id, "backup_page.operation_id")?;
        if self.operation_id != fence.operation_id {
            return Err(BlobError::InvalidField {
                field: "backup_page.operation_id",
                reason: "page does not belong to this fence",
            });
        }
        if self.member_count == 0 || self.member_count as u64 > u64::from(fence.max_members_per_page)
        {
            return Err(BlobError::InvalidField {
                field: "backup_page.window",
                reason: "page must be non-empty and within the fenced page bound",
            });
        }
        let end = self.start_index.checked_add(self.member_count).ok_or(
            BlobError::InvalidField {
                field: "backup_page.window",
                reason: "page window overflows",
            },
        )?;
        if end > fence.member_count() {
            return Err(BlobError::InvalidField {
                field: "backup_page.window",
                reason: "page window escapes the fenced denominator",
            });
        }
        if self.page_index == 0 {
            if self.predecessor != BLOB_BACKUP_GENESIS {
                return Err(BlobError::InvalidField {
                    field: "backup_page.predecessor",
                    reason: "page zero must carry the genesis predecessor",
                });
            }
            if self.start_index != 0
                || self.cumulative_members_before != 0
                || self.cumulative_bytes_before != 0
            {
                return Err(BlobError::InvalidField {
                    field: "backup_page.window",
                    reason: "page zero starts the fence with empty cumulative totals",
                });
            }
        } else if validate_hex_field(&self.predecessor, "backup_page.predecessor").is_err() {
            return Err(BlobError::InvalidField {
                field: "backup_page.predecessor",
                reason: "continuation pages carry the previous page digest",
            });
        }
        Ok(())
    }

    /// Page ordinal; page zero starts the chain.
    #[must_use]
    pub fn page_index(&self) -> u32 {
        self.page_index
    }

    /// First fence index covered by this page.
    #[must_use]
    pub fn start_index(&self) -> usize {
        self.start_index
    }

    /// Number of fence members covered by this page.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// One-past-the-end fence index of this page.
    #[must_use]
    pub fn end_index(&self) -> usize {
        self.start_index + self.member_count
    }

    /// Chained predecessor: genesis for page zero, previous digest after.
    #[must_use]
    pub fn predecessor(&self) -> &str {
        &self.predecessor
    }

    /// Exact fence indexes covered, in order.
    #[must_use]
    pub fn member_indexes(&self) -> Vec<usize> {
        (self.start_index..self.start_index + self.member_count).collect()
    }

    /// Cumulative sealed members completed before this page.
    #[must_use]
    pub fn cumulative_members_before(&self) -> u64 {
        self.cumulative_members_before
    }

    /// Cumulative sealed bytes completed before this page.
    #[must_use]
    pub fn cumulative_bytes_before(&self) -> u64 {
        self.cumulative_bytes_before
    }

    /// Page digest over the exact covered member identities plus the
    /// predecessor. The next page carries this digest; equality of digest
    /// text is never assumed, it is recomputed here from validated members.
    pub fn page_digest(&self, fence: &BlobBackupFence) -> Result<String, BlobError> {
        self.validate_for(fence)?;
        let identities: Vec<(&str, String)> = self
            .member_indexes()
            .iter()
            .map(|index| {
                let locator = fence.members[*index].locator();
                Ok((
                    locator.hash.as_str(),
                    locator.residency_key_digest()?,
                ))
            })
            .collect::<Result<_, BlobError>>()?;
        let canonical = serde_json::to_vec(&serde_json::json!({
            "operation_id": self.operation_id,
            "page_index": self.page_index,
            "members": identities,
            "predecessor": self.predecessor,
        }))
        .map_err(|error| BlobError::InvalidContract(error.to_string()))?;
        Ok(sha256_hex(&canonical))
    }
}

impl<'de> Deserialize<'de> for BlobBackupPage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = BlobBackupPageWire::deserialize(deserializer)?;
        if wire.member_count == 0 {
            return Err(de::Error::custom("page must be non-empty"));
        }
        if wire.page_index == 0 && wire.predecessor != BLOB_BACKUP_GENESIS {
            return Err(de::Error::custom(
                "page zero must carry the genesis predecessor",
            ));
        }
        Ok(Self {
            operation_id: wire.operation_id,
            page_index: wire.page_index,
            start_index: wire.start_index,
            member_count: wire.member_count,
            predecessor: wire.predecessor,
            cumulative_members_before: wire.cumulative_members_before,
            cumulative_bytes_before: wire.cumulative_bytes_before,
        })
    }
}

/// Observed completion of one executed page: the page digest recomputed by
/// the owner at execution time plus the sealed-byte total it produced.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageCompletion {
    page_index: u32,
    predecessor: String,
    page_digest: String,
    member_count: usize,
    sealed_bytes: u64,
}

impl PageCompletion {
    /// Records one executed page. The digest must equal the page digest the
    /// owner recomputes over the fence; a caller-supplied digest that does
    /// not match refuses.
    pub fn for_page(
        page: &BlobBackupPage,
        fence: &BlobBackupFence,
        sealed_bytes: u64,
    ) -> Result<Self, BlobError> {
        let page_digest = page.page_digest(fence)?;
        Ok(Self {
            page_index: page.page_index,
            predecessor: page.predecessor.clone(),
            page_digest,
            member_count: page.member_count,
            sealed_bytes,
        })
    }

    /// Page ordinal this completion covers.
    #[must_use]
    pub fn page_index(&self) -> u32 {
        self.page_index
    }

    /// Predecessor the executed page carried.
    #[must_use]
    pub fn predecessor(&self) -> &str {
        &self.predecessor
    }

    /// Owner-recomputed page digest.
    #[must_use]
    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    /// Members sealed in this page.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Sealed bytes produced by this page.
    #[must_use]
    pub fn sealed_bytes(&self) -> u64 {
        self.sealed_bytes
    }
}

fn verify_completion_chain(completions: &[PageCompletion]) -> Result<(), BlobError> {
    for (position, completion) in completions.iter().enumerate() {
        let expected_index = u32::try_from(position).map_err(|_| BlobError::InvalidField {
            field: "backup_pages.chain",
            reason: "page ordinal overflows",
        })?;
        if completion.page_index != expected_index {
            return Err(BlobError::InvalidField {
                field: "backup_pages.chain",
                reason: "page completions must form a contiguous zero-based chain",
            });
        }
        validate_hex_field(completion.page_digest.as_str(), "backup_pages.page_digest")
            .map_err(|_| BlobError::InvalidField {
                field: "backup_pages.page_digest",
                reason: "page digests must be lowercase hex",
            })?;
        if position == 0 {
            if completion.predecessor != BLOB_BACKUP_GENESIS {
                return Err(BlobError::InvalidField {
                    field: "backup_pages.chain",
                    reason: "the chain starts with the genesis predecessor",
                });
            }
        } else if completions[position - 1].page_digest != completion.predecessor {
            return Err(BlobError::IntegrityMismatch);
        }
    }
    Ok(())
}

/// Cancelled-operation evidence: completed page prefix preserved without any
/// completion claim.
///
/// Carries the chained completed pages, the covered member/byte totals, and
/// the resume index. There is deliberately no path from this type to a
/// completion receipt: resuming re-executes pages through the owner and a
/// fresh `complete` call re-verifies the full denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBackupPartial {
    operation_id: String,
    completed: Vec<PageCompletion>,
    completed_members: u64,
    completed_bytes: u64,
    next_start_index: usize,
    fence_member_count: usize,
}

impl BlobBackupPartial {
    /// Preserves the executed page prefix after cancellation. The completions
    /// must chain from genesis; anything else refuses instead of recording a
    /// gapped prefix as resumable evidence.
    pub fn cancel_after(
        fence: &BlobBackupFence,
        completed: Vec<PageCompletion>,
    ) -> Result<Self, BlobError> {
        verify_completion_chain(&completed)?;
        let mut completed_members: u64 = 0;
        let mut completed_bytes: u64 = 0;
        for completion in &completed {
            completed_members = completed_members
                .checked_add(completion.member_count as u64)
                .ok_or(BlobError::InvalidField {
                    field: "backup_partial.totals",
                    reason: "member totals overflow",
                })?;
            completed_bytes = completed_bytes
                .checked_add(completion.sealed_bytes)
                .ok_or(BlobError::InvalidField {
                    field: "backup_partial.totals",
                    reason: "byte totals overflow",
                })?;
        }
        let next_start_index = usize::try_from(completed_members).map_err(|_| {
            BlobError::InvalidField {
                field: "backup_partial.totals",
                reason: "member totals overflow",
            }
        })?;
        if next_start_index > fence.member_count() {
            return Err(BlobError::InvalidField {
                field: "backup_partial.window",
                reason: "completed prefix escapes the fenced denominator",
            });
        }
        Ok(Self {
            operation_id: fence.operation_id.clone(),
            completed,
            completed_members,
            completed_bytes,
            next_start_index,
            fence_member_count: fence.member_count(),
        })
    }

    /// Operation the partial evidence belongs to.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Chained completed page prefix.
    #[must_use]
    pub fn completed(&self) -> &[PageCompletion] {
        &self.completed
    }

    /// Members sealed before cancellation.
    #[must_use]
    pub fn completed_members(&self) -> u64 {
        self.completed_members
    }

    /// Sealed bytes produced before cancellation.
    #[must_use]
    pub fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    /// Resume index: the next fence member still unsealed.
    #[must_use]
    pub fn next_start_index(&self) -> usize {
        self.next_start_index
    }

    /// Fenced denominator size at cancel time.
    #[must_use]
    pub fn fence_member_count(&self) -> usize {
        self.fence_member_count
    }
}

/// Completion receipt over one fully-verified export.
///
/// Issuable only through [`Self::complete`], which requires every fenced
/// member matched by exactly one validated capture record, a contiguous
/// chained page-completion chain covering the whole denominator, and a
/// single-residency destination scope binding every record. Partial,
/// expired, or mixed-generation material cannot produce this receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBackupCompletionReceipt {
    operation_id: String,
    member_count: usize,
    total_sealed_bytes: u64,
    manifest_sha256: String,
    scope_residency_digest: String,
}

impl BlobBackupCompletionReceipt {
    /// Issues the completion receipt after full verification. The manifest
    /// digest is recomputed here over fence-ordered sealed digests; the
    /// caller supplies records and page evidence, never digest text.
    pub fn complete(
        fence: &BlobBackupFence,
        records: &[SealedBlobCaptureRecord],
        completions: &[PageCompletion],
        scope: &BlobBackupScope,
    ) -> Result<Self, BlobError> {
        if records.len() != fence.member_count() {
            return Err(BlobError::PlanGap(
                "backup export does not cover the fenced denominator".to_owned(),
            ));
        }
        for record in records {
            record.validate()?;
            if record.residency_digest() != scope.residency_digest() {
                return Err(BlobError::IntegrityMismatch);
            }
        }
        for member in fence.members() {
            let matches = records
                .iter()
                .filter(|record| record.locator() == member.locator())
                .count();
            if matches != 1 {
                return Err(BlobError::PlanGap(
                    "backup export must hold exactly one record per fenced member".to_owned(),
                ));
            }
        }
        verify_completion_chain(completions)?;
        let covered: usize = completions.iter().map(PageCompletion::member_count).sum();
        if covered != fence.member_count() {
            return Err(BlobError::PlanGap(
                "page completions must cover the whole fenced denominator".to_owned(),
            ));
        }
        let mut total_sealed_bytes: u64 = 0;
        for completion in completions {
            total_sealed_bytes = total_sealed_bytes
                .checked_add(completion.sealed_bytes)
                .ok_or(BlobError::InvalidField {
                    field: "backup_receipt.totals",
                    reason: "byte totals overflow",
                })?;
        }
        if total_sealed_bytes > fence.max_total_sealed_bytes {
            return Err(BlobError::InvalidField {
                field: "backup_receipt.bounds",
                reason: "sealed total exceeds the fenced byte bound",
            });
        }
        let mut manifest_input = String::new();
        for member in fence.members() {
            let record = records
                .iter()
                .find(|record| record.locator() == member.locator())
                .ok_or_else(|| {
                    BlobError::PlanGap(
                        "backup export must hold exactly one record per fenced member".to_owned(),
                    )
                })?;
            manifest_input.push_str(record.sealed_sha256());
            manifest_input.push('\n');
        }
        Ok(Self {
            operation_id: fence.operation_id.clone(),
            member_count: fence.member_count(),
            total_sealed_bytes,
            manifest_sha256: sha256_hex(manifest_input.as_bytes()),
            scope_residency_digest: scope.residency_digest().to_owned(),
        })
    }

    /// Operation this receipt completes.
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Fenced members covered.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// Total sealed bytes across all pages.
    #[must_use]
    pub fn total_sealed_bytes(&self) -> u64 {
        self.total_sealed_bytes
    }

    /// Manifest digest recomputed over fence-ordered sealed digests.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Destination residency domain this export is bound to.
    #[must_use]
    pub fn scope_residency_digest(&self) -> &str {
        &self.scope_residency_digest
    }
}
