//! The owner port that issues [`RestoreJournalAdmission`] from durable owner
//! state (#962).
//!
//! A supplied journal object is not an admitted durable journal. The struct
//! declaration alone never made one, so before this module the four
//! owner-issued fields had no producer anywhere in the tree and every consumer
//! either refused or was handed a fixture. This module is the missing
//! half: it names the durable owner that may issue the admission, derives
//! every field from that owner's own state read at issue time, and binds the
//! result to the exact operation so a well-formed admission presented for
//! another operation or another installation is refused.
//!
//! What this module deliberately does not do:
//!
//! - It does not accept the four references as arguments. There is no
//!   constructor that takes `database_ref`, `installation_ref`,
//!   `journal_identity_ref` or `admission_receipt_ref` from a caller, so there
//!   is no way to mint an admission out of a request field, a config value, or
//!   a self-chosen trust binding.
//! - It does not add a second trust scheme. The binding is the existing
//!   [`OwnerTrustBinding`], and the production test remains the existing
//!   `require_production_admitted` in the restore owner: this module never
//!   relaxes it and never sets `fixture_proof_only` other than to `false`, the
//!   only value that admits a production durable-recovery claim.
//! - It does not recompute any digest the owner recorded. The record is the
//!   owner's own; this crate checks the recorded value, it does not replace the
//!   proof by re-deriving a fresh checksum over what it holds.
//!
//! Existence and shape prove nothing. [`RestoreJournalAdmission::binds_owner_record`]
//! re-reads the owner's durable record for the named operation and requires
//! exact agreement on the owner binding, both roots, the generation, the
//! journal identity and the receipt, so an admission that is well formed but
//! borrowed from a different operation or installation fails closed.

use eliot_contracts::ResourceGeneration;

use super::{BackupError, OwnerTrustBinding, RestoreJournalAdmission, text};

/// One durable journal record, as the owning owner read it at issue time.
///
/// The owner produces this from its own persisted state: the installation
/// registry it committed, the durable roots bound to that registry, and the
/// journal row it wrote for this exact operation. Nothing here is
/// caller-presented, and a value that a caller supplies for a *different*
/// operation does not appear in this record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableJournalRecord {
    /// The composition-boundary receipt reference of the owner that read the
    /// record: its identity plus the binding that authenticated it.
    pub persistent_owner: OwnerTrustBinding,
    /// The durable database the journal is admitted against.
    pub database_ref: String,
    /// The exact installation identity the journal is admitted against.
    pub installation_ref: String,
    /// The committed authority generation of that installation.
    pub generation: ResourceGeneration,
    /// The journal identity committed for this operation.
    pub journal_identity_ref: String,
    /// The admission receipt committed for this operation.
    pub admission_receipt_ref: String,
}

/// The durable owner of the journal behind one restore operation.
///
/// The only production source of a [`RestoreJournalAdmission`]. An
/// implementation must answer from its own persisted state, read at call time;
/// an implementation that echoes a presented value is not an owner and the
/// binding check below will not rescue it, because there is nothing else to
/// compare against.
pub trait RestoreJournalAdmissionOwner {
    /// Reads the owner's durable journal record for `operation_id`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`BackupError`] when the owner holds no durable record
    /// for the operation, when the record is incomplete, or when the owner's
    /// own state cannot be read. Absence of a record is never reported as an
    /// empty record.
    fn durable_journal_record(
        &self,
        operation_id: &str,
    ) -> Result<DurableJournalRecord, BackupError>;
}

impl RestoreJournalAdmission {
    /// Issues the owner-issued admission for one operation.
    ///
    /// Every field is copied from the owner's durable record for
    /// `operation_id`; none is an argument, so no caller can select the
    /// database, the installation, the generation, the journal identity or the
    /// receipt. `fixture_proof_only` is `false` because the record came from a
    /// durable owner rather than a fixture, and the result is immediately
    /// re-proved against a fresh read of the same owner, so an owner whose
    /// record is not stable across the issue refuses instead of issuing.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the owner holds no
    /// durable record for the operation,
    /// [`BackupError::RestoreJournalMismatch`] when the re-read record does not
    /// agree with the one issued, and the owner's own typed error otherwise.
    pub fn issue_for_operation<O>(
        owner: &O,
        operation_id: &str,
    ) -> Result<Self, BackupError>
    where
        O: RestoreJournalAdmissionOwner + ?Sized,
    {
        text(operation_id, "journal.operation_id")?;
        let record = owner.durable_journal_record(operation_id)?;
        let admission = Self {
            persistent_owner: record.persistent_owner,
            database_ref: record.database_ref,
            installation_ref: record.installation_ref,
            generation: record.generation,
            journal_identity_ref: record.journal_identity_ref,
            admission_receipt_ref: record.admission_receipt_ref,
            fixture_proof_only: false,
        };
        admission.validate()?;
        admission.binds_owner_record(owner, operation_id)?;
        Ok(admission)
    }

    /// Requires that this admission still agrees with the owner's durable
    /// record for `operation_id`.
    ///
    /// This is the operation and installation binding. A structurally valid
    /// admission whose owner binding, database, installation, generation,
    /// journal identity or receipt differs from what the owner holds for *this*
    /// operation fails closed, as does an admission that never admitted a
    /// production durable journal. Both refusals are the crate's existing
    /// typed journal errors, not a generic code.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the admission is
    /// fixture-only, [`BackupError::RestoreJournalMismatch`] on any difference
    /// from the owner's current durable record, and the owner's own typed
    /// error when that record cannot be read.
    pub fn binds_owner_record<O>(&self, owner: &O, operation_id: &str) -> Result<(), BackupError>
    where
        O: RestoreJournalAdmissionOwner + ?Sized,
    {
        if !self.admits_production_durable_recovery() {
            return Err(BackupError::RestoreJournalRequired);
        }
        text(operation_id, "journal.operation_id")?;
        self.validate()?;
        let current = owner.durable_journal_record(operation_id)?;
        let agrees = self.persistent_owner == current.persistent_owner
            && self.database_ref == current.database_ref
            && self.installation_ref == current.installation_ref
            && self.generation == current.generation
            && self.journal_identity_ref == current.journal_identity_ref
            && self.admission_receipt_ref == current.admission_receipt_ref;
        if agrees {
            Ok(())
        } else {
            Err(BackupError::RestoreJournalMismatch)
        }
    }
}
