//! The owner-issued, operation-bound producer for destination manifest evidence
//! (issue #962, AUDIT-7).
//!
//! The Kernel-side projection of a Host manifest binding is
//! `DestinationManifestEvidence` (`bins/eliot-kernel/src/backup_restore_ports.rs`).
//! That type validates the shape of an admitted value, but a shape check is not
//! an issuer: the value it admits was built from three strings and a path the
//! CALLER supplied, and nothing in the tree could produce it from the
//! destination owner's own durable state. A caller that could write two
//! well-formed 64-hex digests had already decided the question the evidence is
//! supposed to answer. This module is that missing producer, and it is placed
//! beside [`RestoreJournalAdmission`](super::RestoreJournalAdmission)'s issuer
//! because the two answer the same question for the same operation with the
//! same discipline.
//!
//! What this module deliberately does not do:
//!
//! - It does not accept the three owner values as arguments. There is no
//!   constructor that takes a manifest digest, a roots digest, a registry
//!   revision or a destination reference from a caller, so there is no way to
//!   mint an admission out of a request field, a config value, or two strings
//!   typed at a call site.
//! - It does not accept an operation identity as an argument either. The
//!   operation is the [`RestorePlan`], and the plan id, the transaction and the
//!   destination are derived from it here, where that derivation lives. The
//!   derived triple travels outward as a
//!   [`DestinationAdmissionOperation`] that has no constructor outside this
//!   crate, so a coordinator cannot point the issuer at another operation's
//!   destination even by naming one.
//! - It does not add a second trust scheme. The binding is the existing
//!   [`OwnerTrustBinding`], validated by its own `validate`, and the owner
//!   reference an admission carries is the one the owner itself reported.
//! - It does not recompute any digest the owner recorded. The owner's record is
//!   checked with the crate's own recorded-value rules (a 64-hex owner digest is
//!   a 64-hex owner digest wherever it came from); re-deriving a checksum over
//!   values held in memory would replace the proof rather than check it.
//! - It does not add a directory, a lease or a staging area. Nothing here
//!   creates, reuses or removes a path, so there is no predictable name that
//!   could be mistaken for ownership of one; the destination is a reference the
//!   owner already admitted, and this module only ever reads.
//! - It does not stand in for the Host manifest binding. The owner behind this
//!   port is the destination owner that committed the active manifest
//!   configuration digest, the manifest-bound runtime-roots digest and the
//!   registry revision (#958). A port with no owner behind it issues nothing:
//!   [`RestoreDestinationAdmissionOwner`] has no default method, and an owner
//!   that holds no durable record for the operation it is asked about refuses
//!   instead of returning an empty record.
//!
//! [`DestinationManifestAdmission::issue_for_operation`] therefore produces a
//! value whose four owner-read members are exactly the ones the Kernel-side
//! admitting entry consumes, and
//! [`DestinationManifestAdmission::binds_owner_record`] re-reads both the
//! operation identity and the owner's own current record so a well-formed
//! admission borrowed from another operation, another destination or a rotated
//! registry fails closed instead of proceeding.
//!
//! Nothing here applies an effect, imports a byte, or reaches cutover; the
//! restore owner still refuses an unvalidated plan. A bundle that arrives with
//! no destination admission is NOT a supported rehearsal shape: the restore
//! owner refuses it with `KernelRestoreError::DestinationNotAdmitted` before it
//! compiles a plan and before it constructs a destination root, so this issuer
//! is the only way that shape can ever be replaced by an admitted one.

use super::{BackupError, OwnerTrustBinding, RestorePlan, RestoreTransaction, digest, text};

/// Fence subject used for every destination-admission binding refusal.
///
/// One named subject so a caller deciding between "the archive is unusable" and
/// "the destination admission is not this operation's" is deciding on a
/// distinguishable fact rather than on two spellings of one message.
const DESTINATION_ADMISSION_SUBJECT: &str = "destination manifest admission";

/// The exact operation and destination one destination admission is bound to.
///
/// Every value is derived from a [`RestorePlan`] by this crate, and the struct
/// has no constructor any other crate can reach: an owner receives one to read,
/// and nobody can hand the issuer an operation of their own choosing. The
/// destination is the plan's own `RestoreContext::target_id`, which is the
/// destination the restore engine itself will construct under — it is not
/// accepted from a request, a config value or a fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationAdmissionOperation {
    plan_id: String,
    transaction: RestoreTransaction,
    destination_ref: String,
}

impl DestinationAdmissionOperation {
    /// Derives the operation this plan names.
    ///
    /// The transaction is the crate's own stable identity for this plan, bundle
    /// and target context, so two operations that differ in any of them produce
    /// different operations and therefore different admissions.
    fn of(plan: &RestorePlan) -> Result<Self, BackupError> {
        let transaction = plan.transaction()?;
        let operation = Self {
            plan_id: plan.plan_id.clone(),
            transaction,
            destination_ref: plan.target.target_id.clone(),
        };
        operation.validate()?;
        Ok(operation)
    }

    fn validate(&self) -> Result<(), BackupError> {
        text(&self.plan_id, "destination.plan_id")?;
        text(&self.destination_ref, "destination.destination_ref")?;
        text(
            &self.transaction.transaction_id,
            "destination.transaction_id",
        )
    }

    /// The plan identity this operation was derived from.
    #[must_use]
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    /// The stable transaction identity of the exact plan/bundle/context triple.
    #[must_use]
    pub const fn transaction(&self) -> &RestoreTransaction {
        &self.transaction
    }

    /// The exact destination this operation restores into.
    #[must_use]
    pub fn destination_ref(&self) -> &str {
        &self.destination_ref
    }
}

/// One destination owner's durable record, as the owning owner read it at issue
/// time.
///
/// The owner produces this from its own persisted state: the active manifest's
/// own configuration digest, the digest of the manifest-bound runtime roots, and
/// the registry revision it observed when it admitted this destination for this
/// operation. Nothing here is caller-presented, and a value the caller supplies
/// for a *different* operation does not appear in this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableDestinationRecord {
    /// The composition-boundary receipt reference of the owner that read the
    /// record: its identity plus the binding that authenticated it.
    pub persistent_owner: OwnerTrustBinding,
    /// The destination owner's own recorded configuration digest for the active
    /// manifest (64 lowercase hex, as the owner recorded it).
    pub manifest_digest: String,
    /// The destination owner's own recorded digest over the manifest-bound
    /// runtime roots (64 lowercase hex, as the owner recorded it).
    pub roots_digest: String,
    /// The registry revision the owner observed for this destination.
    pub registry_revision: u64,
    /// The exact destination identity the owner admitted. It must be the
    /// destination this operation derives, so a record for another destination
    /// cannot be issued as this one.
    pub destination_ref: String,
}

impl DurableDestinationRecord {
    /// Checks the owner's ORIGINAL recorded values with the crate's own rules.
    ///
    /// This is a shape check on what the owner committed, not a re-derivation:
    /// a digest is compared against the recorded-value rule and is never
    /// recomputed here, because a fresh checksum over in-memory values would
    /// replace the owner's proof instead of checking it.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InvalidField`] when the owner recorded a
    /// malformed identity or a digest that is not 64 lowercase hex.
    pub fn validate(&self) -> Result<(), BackupError> {
        self.persistent_owner.validate()?;
        digest(&self.manifest_digest, "destination.manifest_digest")?;
        digest(&self.roots_digest, "destination.roots_digest")?;
        text(&self.destination_ref, "destination.destination_ref")
    }
}

/// The durable owner of the destination manifest evidence behind one restore
/// operation.
///
/// The only production source of a [`DestinationManifestAdmission`]. An
/// implementation must answer from its own persisted state, read at call time,
/// for the operation this crate derived — which it cannot be handed a different
/// one of. An implementation that echoes a presented value is not an owner, and
/// the binding check will not rescue it: the check re-reads the owner's record
/// and compares it field by field against the admitted value and the operation,
/// so a value that was never committed to that record cannot agree with it.
///
/// There is deliberately no default method. A missing capability is expressed
/// by a type that does not implement this trait, which issues nothing, rather
/// than by an implementation that returns an empty record.
pub trait RestoreDestinationAdmissionOwner {
    /// Reads the owner's durable destination record for `operation`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`BackupError`] when the owner holds no durable record
    /// for that operation or destination, when the record is incomplete, or when
    /// the owner's own state cannot be read. Absence of a record is never
    /// reported as an empty record, and the owner's error is never replaced with
    /// a synthesized value.
    fn durable_destination_record(
        &self,
        operation: &DestinationAdmissionOperation,
    ) -> Result<DurableDestinationRecord, BackupError>;
}

/// The owner-issued, operation-bound destination admission.
///
/// Every owner-read member is copied from the owner's durable record for the
/// operation this crate derived from the plan, and the operation identity is
/// carried beside them, so this value states both WHAT the owner admitted and
/// WHICH restore operation and destination it admitted it for. There is no
/// constructor that takes either: [`Self::issue_for_operation`] is the only way
/// to obtain one, and it reads the owner.
///
/// This is the owner-side value the Kernel-side projection
/// `DestinationManifestEvidence` consumes, not a second copy of it: that type
/// additionally binds the Kernel's own work root and is validated by the Kernel
/// restore owner, and it cannot stand in for the Host manifest binding this
/// admission names as its issuer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationManifestAdmission {
    /// The owner that issued this admission and the binding that authenticated
    /// it, exactly as the owner reported it.
    pub persistent_owner: OwnerTrustBinding,
    /// The owner's own recorded configuration digest for the active manifest.
    pub manifest_digest: String,
    /// The owner's own recorded digest over the manifest-bound runtime roots.
    pub roots_digest: String,
    /// The registry revision the owner observed at admission time.
    pub registry_revision: u64,
    /// The exact destination identity the owner admitted.
    pub destination_ref: String,
    /// The exact operation and destination this admission is bound to.
    operation: DestinationAdmissionOperation,
}

impl DestinationManifestAdmission {
    /// Issues the owner-issued destination admission for `plan`'s operation.
    ///
    /// Every owner-read member is copied from the owner's durable record for
    /// the operation derived from `plan`; none is an argument, so no caller can
    /// select the manifest digest, the roots digest, the registry revision or the
    /// destination. The record must name exactly the destination this operation
    /// derives, and the result is immediately re-proved against a fresh read of
    /// the same owner for the same operation, so an owner whose record is not
    /// stable across the issue refuses instead of issuing.
    ///
    /// This issues an admission; it applies no effect, stages no byte and reaches
    /// no cutover.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::FenceMismatch`] when the owner's record does not
    /// name this operation's destination or when the re-read record does not
    /// agree with the one issued, [`BackupError::InvalidField`] when a recorded
    /// value is malformed, and the owner's own typed error otherwise.
    pub fn issue_for_operation<O>(owner: &O, plan: &RestorePlan) -> Result<Self, BackupError>
    where
        O: RestoreDestinationAdmissionOwner + ?Sized,
    {
        let operation = DestinationAdmissionOperation::of(plan)?;
        let record = owner.durable_destination_record(&operation)?;
        record.validate()?;
        if record.destination_ref != operation.destination_ref {
            return Err(BackupError::FenceMismatch {
                subject: DESTINATION_ADMISSION_SUBJECT.to_owned(),
            });
        }
        let admission = Self {
            persistent_owner: record.persistent_owner,
            manifest_digest: record.manifest_digest,
            roots_digest: record.roots_digest,
            registry_revision: record.registry_revision,
            destination_ref: record.destination_ref,
            operation,
        };
        admission.validate()?;
        admission.binds_owner_record(owner, plan)?;
        Ok(admission)
    }

    /// Requires that this admission still agrees with the owner's current record
    /// for the operation `plan` names.
    ///
    /// This is the operation-and-destination binding. The admission's own
    /// operation must be exactly the one `plan` derives — same plan identity,
    /// same transaction, same destination — and the owner binding, manifest
    /// digest, roots digest, registry revision and destination must equal what
    /// the owner durably holds for that same operation right now. A structurally
    /// valid admission issued for a different operation or a different
    /// destination, or one whose registry has moved under it, fails closed with
    /// this crate's existing typed fence error, and the owner's own error is
    /// passed through rather than collapsed into one.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::FenceMismatch`] on any difference from the derived
    /// operation or from the owner's current record,
    /// [`BackupError::InvalidField`] when a recorded value is malformed, and the
    /// owner's own typed error when that record cannot be read.
    pub fn binds_owner_record<O>(&self, owner: &O, plan: &RestorePlan) -> Result<(), BackupError>
    where
        O: RestoreDestinationAdmissionOwner + ?Sized,
    {
        self.validate()?;
        let operation = DestinationAdmissionOperation::of(plan)?;
        if self.operation != operation {
            return Err(BackupError::FenceMismatch {
                subject: DESTINATION_ADMISSION_SUBJECT.to_owned(),
            });
        }
        let current = owner.durable_destination_record(&operation)?;
        current.validate()?;
        let agrees = self.persistent_owner == current.persistent_owner
            && self.manifest_digest == current.manifest_digest
            && self.roots_digest == current.roots_digest
            && self.registry_revision == current.registry_revision
            && self.destination_ref == current.destination_ref;
        if agrees {
            Ok(())
        } else {
            Err(BackupError::FenceMismatch {
                subject: DESTINATION_ADMISSION_SUBJECT.to_owned(),
            })
        }
    }

    /// Validates this admission's own recorded values and operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::InvalidField`] when any member is malformed, using
    /// the crate's existing recorded-value rules.
    pub fn validate(&self) -> Result<(), BackupError> {
        self.persistent_owner.validate()?;
        digest(&self.manifest_digest, "destination.manifest_digest")?;
        digest(&self.roots_digest, "destination.roots_digest")?;
        text(&self.destination_ref, "destination.destination_ref")?;
        self.operation.validate()
    }

    /// The owner that issued this admission and the binding that authenticated it.
    #[must_use]
    pub const fn owner(&self) -> &OwnerTrustBinding {
        &self.persistent_owner
    }

    /// The owner's own recorded configuration digest for the active manifest.
    ///
    /// This is read out of the owner's durable record, never derived here and
    /// never accepted from a caller.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// The owner's own recorded digest over the manifest-bound runtime roots.
    ///
    /// This is read out of the owner's durable record, never derived here and
    /// never accepted from a caller.
    #[must_use]
    pub fn roots_digest(&self) -> &str {
        &self.roots_digest
    }

    /// The registry revision the owner observed when it admitted this
    /// destination.
    ///
    /// A point-in-time observation carried as data, not a fence: it can advance
    /// the instant after this returns, and nothing downstream may read it as
    /// "the revision during restore". Comparing the observed revision against a
    /// later one is the composition's decision, made where the owner is
    /// reachable.
    #[must_use]
    pub const fn registry_revision(&self) -> u64 {
        self.registry_revision
    }

    /// The exact destination identity the owner admitted.
    #[must_use]
    pub fn destination_ref(&self) -> &str {
        &self.destination_ref
    }

    /// The exact operation and destination this admission is bound to.
    #[must_use]
    pub const fn operation(&self) -> &DestinationAdmissionOperation {
        &self.operation
    }
}
