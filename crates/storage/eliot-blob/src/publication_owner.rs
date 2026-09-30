//! The production `PublicationPort` over the one S-04 blob CAS owner
//! (issue #959, checklist item A23).
//!
//! [`BlobArchivePublicationOwner`] is the production implementation of
//! [`eliot_backup::PublicationPort`]. It binds one admitted capture
//! publication operation to the single-owner filesystem CAS this crate
//! already owns, so one publication operation yields one immutable archive
//! and one owner-issued durable receipt.
//!
//! # What the owner surface is
//!
//! The port is synchronous and the publication runs through this crate's own
//! synchronous owner path, `BlobStoreCore::stage_sync`, which is exactly what
//! the `BlobStoreClient::stage` future resolves to. No executor, no blocking
//! bridge and no second store is introduced: the async client port boxes this
//! same call, so binding the port here needs no new mechanism at all.
//!
//! # Where durability comes from
//!
//! The port's own contract is the specification, and it forbids a
//! self-attested flag:
//!
//! > There is deliberately no durability field here. Durability is evidence
//! > the OWNER issues — it is `PublicationReceipt::durable` — and a note this
//! > owner wrote about its own publication would be a self-attested flag, not
//! > proof.
//! > (`crates/storage/eliot-backup/src/lib.rs`, `PublishedArchive`)
//!
//! So `durable` is never read off the fact that this owner's own write
//! returned `Ok`. It is read off the owner's own durable record for the exact
//! operation identity: the S-04 commit marker
//! `transactions/<blake3(operation_id, idempotency_key)>.commit`, which the
//! owner writes only after the payload and metadata reached
//! `PublishState::MetadataDurable`, and which the API defines as the record
//! that makes a publication ready:
//!
//! > Durable publication state. `READY` is issued only after payload, metadata
//! > and the commit marker are durably present; recovery resumes the exact
//! > state.
//! > (`crates/storage/eliot-blob-api/src/lib.rs`, `PublishState`)
//!
//! The digest reported to the coordinator is the one inside the metadata that
//! marker names, re-read through the owner and re-verified against the
//! owner's own issuer anchor. No digest is accepted from the caller, and
//! equality of two archives is never consulted to decide anything.
//!
//! # How a lost response reconciles
//!
//! [`PublicationPort::reconcile`] performs no publish at all. The commit
//! marker path is derived from the operation identity and the bound
//! idempotency key, so the owner can answer "did operation X publish, and
//! which digest is durably recorded" from its own durable record alone. The
//! answers are the port's own states:
//!
//! * a commit marker names the operation and no unproven publication
//!   obligation is recorded against it — the owner's durable receipt, with
//!   the owner-recorded archive digest;
//! * a publication obligation the owner never proved, or a stage journal
//!   without a commit marker, means the owner holds an unsettled publication
//!   for this exact operation: the outcome is [`PublicationError::Unknown`]
//!   and must be reconciled, never republished;
//! * no record exists for the operation — the owner durably published nothing
//!   under this identity, which is a [`PublicationError::Refused`].
//!
//! # Owner boundary
//!
//! The owner is bound to one publication operation: the operation identity
//! and idempotency key are supplied once, by the composition owner, and
//! [`PublicationPort::publish_once`] refuses any other pair. A second
//! operation is a second owner, exactly as "exactly one `publish_once` call
//! happens per admitted capture operation" requires. The owner shares the
//! claimed root behind the same `Arc` as the service it is bound to, so it
//! never claims a root, never creates a second receipt issuer and never
//! writes outside the one CAS root.
//!
//! Blob durability proves bytes only, never semantic meaning: the receipt
//! says these exact archive bytes are durably recorded under this operation,
//! and nothing more (`crates/storage/AGENTS.md`).

use std::sync::Arc;

use eliot_backup::{PublicationError, PublicationPort, PublicationReceipt};
use eliot_blob_api::{
    BlobError, BlobHash, BlobLocator, BlobPolicyBinding, BlobReadyReceipt, BlobReceiptContext,
    BlobRootLease, BlobStageRequest, ObjectResidencyKey, VersionedContentDigest,
};
use eliot_platform::WorkScopePath;
use eliot_receipts::{EffectClass, OperationId};

use super::{
    BlobAeadPort, BlobCompressionPort, BlobKeyPort, BlobLiveSetPort, BlobPathState,
    BlobPlatformPort, BlobStoreCore, BlobStoreService, MAX_JOURNAL_BYTES, ResidencyScope,
    StageJournal, decode_commit, sha256_hex, valid_operation_text,
};

/// Store-side identities bound once for one publication operation.
///
/// The composition owner supplies the one root lease, the stage context (a
/// reversible-mutation effect), the blob policy binding, the residency
/// template and the publication operation identity. The template's content
/// digest algorithm/version are reused; its digest value is replaced at
/// publication with the BLAKE3 of the exact archive bytes, which is the
/// content identity the owner addresses. Nothing here is a caller default:
/// every field is validated, and an absent or foreign residency domain, lease
/// or fence refuses instead of being inferred.
pub struct BlobArchivePublicationBinding {
    operation_id: String,
    idempotency_key: String,
    root_lease: BlobRootLease,
    stage_context: BlobReceiptContext,
    policy: BlobPolicyBinding,
    residency: ObjectResidencyKey,
}

impl BlobArchivePublicationBinding {
    /// Binds the store-side identities of one publication operation after
    /// validating each one.
    ///
    /// # Errors
    ///
    /// Returns `BlobError` when the operation identity is not usable text,
    /// the lease does not validate, the stage context is not a
    /// reversible-mutation context bound to that lease fence, or the policy
    /// does not serve the residency template.
    pub fn new(
        operation_id: &str,
        idempotency_key: &str,
        root_lease: BlobRootLease,
        stage_context: BlobReceiptContext,
        policy: BlobPolicyBinding,
        residency: ObjectResidencyKey,
    ) -> Result<Self, BlobError> {
        valid_operation_text(operation_id, "publication.operation_id")?;
        valid_operation_text(idempotency_key, "publication.idempotency_key")?;
        root_lease.validate()?;
        root_lease.validate_context(&stage_context)?;
        stage_context.validate_for(EffectClass::ReversibleMutation)?;
        policy.validate_for_residency(&residency)?;
        Ok(Self {
            operation_id: operation_id.to_owned(),
            idempotency_key: idempotency_key.to_owned(),
            root_lease,
            stage_context,
            policy,
            residency,
        })
    }
}

/// What the owner's own durable record proves about one publication.
///
/// Both fields are read out of the owner: the locator and archive digest come
/// from the metadata the commit marker names, and the digest is the owner's
/// own SHA-256 over the exact bytes it stored, never a value supplied by a
/// caller.
struct OwnerPublicationRecord {
    locator: BlobLocator,
    archive_sha256: String,
    /// The owner's own durability verdict. It is set only where the commit
    /// marker for this exact operation was read, decoded, bound to this
    /// operation identity, matched against the metadata it names and had that
    /// metadata's owner-issued receipt re-verified. An owner that cannot prove
    /// that much returns an error instead of a record, so this value is never
    /// asserted at a receipt construction site.
    durable: bool,
}

/// The production `PublicationPort` over the single-owner blob CAS.
///
/// `P`, `C`, `K`, `A` and `L` are the owner's injected platform, compression,
/// key, AEAD and live-set ports. The owner borrows the claimed root behind
/// the service's shared `Arc`; it never claims a root and never issues a
/// second receipt.
pub struct BlobArchivePublicationOwner<P, C, K, A, L> {
    core: Arc<BlobStoreCore<P, C, K, A, L>>,
    binding: BlobArchivePublicationBinding,
}

impl<P, C, K, A, L> BlobArchivePublicationOwner<P, C, K, A, L>
where
    P: BlobPlatformPort,
    C: BlobCompressionPort,
    K: BlobKeyPort,
    A: BlobAeadPort,
    L: BlobLiveSetPort,
{
    /// Attaches the publication port to the shared store handle and the
    /// publication operation binding.
    ///
    /// The handle is shared, never re-owned: this owner performs no root
    /// claim of its own, so it cannot create a second blob root, receipt
    /// issuer or canonical writer.
    #[must_use]
    pub fn bind(
        store: &BlobStoreService<P, C, K, A, L>,
        binding: BlobArchivePublicationBinding,
    ) -> Self {
        Self {
            core: Arc::clone(&store.core),
            binding,
        }
    }

    /// Publishes the exact archive bytes once through the owner's own
    /// synchronous stage path.
    ///
    /// The operation identity is rebound onto the bound stage context exactly
    /// as the owner's tombstone CAS step rebinds its own derived identity: the
    /// request/fence/authority bindings are the composition owner's and are
    /// never rewritten here.
    fn stage(&self, bytes: &[u8]) -> Result<BlobReadyReceipt, PublicationError> {
        if bytes.is_empty() {
            return Err(PublicationError::Refused(
                "an empty archive is not a publication".to_owned(),
            ));
        }
        let digest = BlobHash::new(blake3::hash(bytes).to_hex().to_string()).map_err(|error| {
            PublicationError::Refused(format!("archive content identity: {error}"))
        })?;
        let template = &self.binding.residency;
        let residency = ObjectResidencyKey {
            scope_domain_id: template.scope_domain_id.clone(),
            access_domain_id: template.access_domain_id.clone(),
            confidentiality_domain_id: template.confidentiality_domain_id.clone(),
            encryption_key_domain_id: template.encryption_key_domain_id.clone(),
            retention_domain_id: template.retention_domain_id.clone(),
            erasure_domain_id: template.erasure_domain_id.clone(),
            content_digest: VersionedContentDigest {
                algorithm: template.content_digest.algorithm.clone(),
                version: template.content_digest.version,
                digest,
            },
        };
        let mut context = self.binding.stage_context.clone();
        context.operation.operation_id = OperationId::new(self.binding.operation_id.clone())
            .map_err(|error| {
                PublicationError::Refused(format!("publication operation identity: {error}"))
            })?;
        self.binding
            .idempotency_key
            .clone_into(&mut context.operation.idempotency_key);
        self.core
            .stage_sync(BlobStageRequest {
                context,
                root_lease: self.binding.root_lease.clone(),
                bytes: bytes.to_vec(),
                policy: self.binding.policy.clone(),
                residency,
            })
            .map_err(|error| match error {
                // The owner cannot prove its own publication outcome here. It
                // is its own unknown answer, never a refusal: a caller that
                // read it as "nothing was written" would blind-retry and
                // publish the same operation twice.
                BlobError::UnknownPublishOutcome { operation_id, .. } => {
                    PublicationError::Unknown(operation_id)
                }
                other => PublicationError::Refused(other.to_string()),
            })
    }

    /// The owner's own durable record for the bound publication operation.
    ///
    /// Reads the operation's commit marker and its stage journal through the
    /// owner, requires both to name this exact operation identity, and
    /// re-reads the metadata the marker names, re-verifying that metadata's
    /// receipt against the owner's own issuer anchor. The reported digest is
    /// the owner's own digest over the bytes it stored.
    fn owner_record(&self) -> Result<OwnerPublicationRecord, PublicationError> {
        self.core
            .ensure_lease(&self.binding.root_lease)
            .map_err(|error| self.refuse(error))?;
        let commit_path = self.operation_path("commit")?;
        let stage_path = self.operation_path("stage")?;
        self.core
            .contained(&commit_path)
            .map_err(|error| self.refuse(error))?;
        self.core
            .contained(&stage_path)
            .map_err(|error| self.refuse(error))?;
        let committed = self
            .core
            .platform_stat(&commit_path)
            .map_err(|error| self.refuse(error))?
            != BlobPathState::Missing;
        let journal = self.owner_journal(&stage_path)?;
        // The owner's own fence comes first: a publication/durability
        // boundary it never proved, recorded against this operation, outranks
        // the commit marker's presence. Byte presence is never promotion.
        if journal
            .as_ref()
            .is_some_and(|journal| journal.pending_publication.is_some())
        {
            return Err(PublicationError::Unknown(self.binding.operation_id.clone()));
        }
        if !committed {
            // A journal without a commit marker is a publication the owner
            // started and has not settled: unknown, never a second publish.
            return Err(if journal.is_some() {
                PublicationError::Unknown(self.binding.operation_id.clone())
            } else {
                self.absent_record()
            });
        }
        self.committed_record(&commit_path)
    }

    /// The owner's own stage journal for this operation, when it holds one.
    ///
    /// An absent journal is `None`. A present journal is decoded and
    /// validated, and must name this exact operation identity: an operation
    /// record that names another operation is a corrupt recovery record, not
    /// a licence to promote anything.
    fn owner_journal(
        &self,
        stage_path: &WorkScopePath,
    ) -> Result<Option<StageJournal>, PublicationError> {
        if self
            .core
            .platform_stat(stage_path)
            .map_err(|error| self.refuse(error))?
            == BlobPathState::Missing
        {
            return Ok(None);
        }
        let bytes = self
            .core
            .read_bounded_file(stage_path, MAX_JOURNAL_BYTES)
            .map_err(|error| self.refuse(error))?;
        let journal: StageJournal = serde_json::from_slice(&bytes)
            .map_err(|_| self.refuse(BlobError::MetadataPayloadMismatch))?;
        journal.validate().map_err(|error| self.refuse(error))?;
        if journal.operation_id != self.binding.operation_id
            || journal.idempotency_key != self.binding.idempotency_key
        {
            return Err(self.refuse(BlobError::IdempotencyConflict));
        }
        Ok(Some(journal))
    }

    /// The owner's refusal to answer, carrying the owner's own cause.
    fn refuse(&self, cause: impl std::fmt::Display) -> PublicationError {
        PublicationError::Refused(format!(
            "blob owner refused the publication read for operation {}: {cause}",
            self.binding.operation_id
        ))
    }

    /// Reads the metadata the commit marker names.
    fn committed_record(
        &self,
        commit_path: &WorkScopePath,
    ) -> Result<OwnerPublicationRecord, PublicationError> {
        let bytes = self
            .core
            .read_bounded_file(commit_path, MAX_JOURNAL_BYTES)
            .map_err(|error| {
                PublicationError::Refused(format!("blob owner commit record unreadable: {error}"))
            })?;
        let commit = decode_commit(&bytes).map_err(|error| {
            PublicationError::Refused(format!("blob owner commit record invalid: {error}"))
        })?;
        if commit.operation_id != self.binding.operation_id
            || commit.idempotency_key != self.binding.idempotency_key
        {
            return Err(PublicationError::Refused(
                "blob owner commit marker does not name the bound publication operation".to_owned(),
            ));
        }
        let scope = ResidencyScope {
            digest: commit.residency_sha256.clone(),
        };
        let (stored, metadata_bytes) =
            self.core
                .load_metadata(&commit.locator, &scope)
                .map_err(|error| {
                    PublicationError::Refused(format!(
                        "blob owner could not read the committed object: {error}"
                    ))
                })?;
        if sha256_hex(&metadata_bytes) != commit.metadata_sha256 {
            return Err(PublicationError::Refused(
                "blob owner commit marker does not match the metadata it names".to_owned(),
            ));
        }
        self.core
            .verify_metadata_receipt(&stored)
            .map_err(|error| {
                PublicationError::Refused(format!(
                    "blob owner metadata receipt did not verify: {error}"
                ))
            })?;
        Ok(OwnerPublicationRecord {
            locator: commit.locator,
            archive_sha256: stored.plaintext_sha256,
            durable: true,
        })
    }

    /// The derived owner record path for the bound operation.
    fn operation_path(&self, suffix: &str) -> Result<WorkScopePath, PublicationError> {
        BlobStoreCore::<P, C, K, A, L>::operation_path_from(
            &self.binding.operation_id,
            &self.binding.idempotency_key,
            suffix,
        )
        .map_err(|error| PublicationError::Refused(format!("publication operation path: {error}")))
    }

    /// The owner's answer for an operation it holds no record for.
    ///
    /// An owner either refuses a publication it did not durably record, or
    /// cannot prove whether it recorded one. The second is its own answer: a
    /// caller that read it as "nothing was written" would blind-retry and
    /// publish the same operation twice.
    fn absent_record(&self) -> PublicationError {
        PublicationError::Refused(format!(
            "blob owner durably published nothing for operation {}",
            self.binding.operation_id
        ))
    }
}

impl<P, C, K, A, L> PublicationPort for BlobArchivePublicationOwner<P, C, K, A, L>
where
    P: BlobPlatformPort,
    C: BlobCompressionPort,
    K: BlobKeyPort,
    A: BlobAeadPort,
    L: BlobLiveSetPort,
{
    /// Publishes the verified archive exactly once under the caller's
    /// operation identity and idempotency key.
    ///
    /// The owner's own stage path is idempotent by operation identity: a
    /// replay of the same operation resolves the existing commit record
    /// instead of writing a second object, so a repeated call can never
    /// publish twice. The receipt is then built from the owner's durable
    /// record, never from the fact that the stage call returned.
    fn publish_once(
        &mut self,
        operation_id: &str,
        idempotency_key: &str,
        bytes: &[u8],
    ) -> Result<PublicationReceipt, PublicationError> {
        if operation_id != self.binding.operation_id
            || idempotency_key != self.binding.idempotency_key
        {
            return Err(PublicationError::Refused(
                "publication operation identity does not match the owner's bound operation"
                    .to_owned(),
            ));
        }
        let published = self.stage(bytes)?;
        let record = self.owner_record()?;
        if record.locator != *published.locator() {
            return Err(PublicationError::Refused(
                "blob owner durable record does not name the object it just published".to_owned(),
            ));
        }
        Ok(PublicationReceipt {
            operation_id: operation_id.to_owned(),
            archive_sha256: record.archive_sha256,
            // The owner's own verdict from its durable record, never this
            // call's outcome.
            durable: record.durable,
        })
    }

    /// Reconciles a lost publication response for the bound operation.
    ///
    /// Performs no publish. The owner's own commit marker for that exact
    /// operation identity is the answer; a stage journal yields
    /// [`PublicationError::Unknown`] and no record at all yields
    /// [`PublicationError::Refused`]. Archive bytes are never re-read to
    /// decide any of it.
    fn reconcile(&mut self, operation_id: &str) -> Result<PublicationReceipt, PublicationError> {
        if operation_id != self.binding.operation_id {
            return Err(PublicationError::Refused(
                "reconcile identity does not match the owner's bound publication operation"
                    .to_owned(),
            ));
        }
        let record = self.owner_record()?;
        Ok(PublicationReceipt {
            operation_id: operation_id.to_owned(),
            archive_sha256: record.archive_sha256,
            // The owner's own verdict from its durable record. A stage journal
            // never reaches this point: it returned `Unknown` above.
            durable: record.durable,
        })
    }
}
