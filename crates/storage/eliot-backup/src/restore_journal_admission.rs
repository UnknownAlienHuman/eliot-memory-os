//! The owner-issued, operation-bound issuer for [`RestoreJournalAdmission`].
//!
//! A supplied journal object is not an admitted durable journal. The struct
//! declaration alone never made one, so before this module the four
//! owner-issued references had no producer anywhere in the tree and every
//! consumer either refused or was handed a fixture. This module is the missing
//! half: it names the durable owner that may issue the admission, derives every
//! field from that owner's own state read at issue time, and binds the result
//! to the exact operation so a well-formed admission presented for another
//! operation or another installation is refused.
//!
//! What this module deliberately does not do:
//!
//! - It does not accept the four references as arguments. There is no
//!   constructor that takes `database_ref`, `installation_ref`,
//!   `journal_identity_ref` or `admission_receipt_ref` from a caller, so there
//!   is no way to mint an admission out of a request field, a config value, or
//!   a self-chosen trust binding.
//! - It does not accept an operation identity as an argument either. The
//!   operation is the [`RestorePlan`], and both the journal identity and the
//!   transaction are derived from that plan by the crate's own plan identity
//!   helpers, so a caller cannot point the issuer at a stream of its own
//!   choosing.
//! - It does not add a second trust scheme. The binding is the existing
//!   [`OwnerTrustBinding`], and the production test remains the existing
//!   `require_production_admitted` in the restore owner: this module never
//!   relaxes it and never sets `fixture_proof_only` other than to `false`, the
//!   only value that admits a production durable-recovery claim.
//! - It does not recompute any digest the owner recorded. The journal row is
//!   read through the accepted [`RestoreJournalPort`] seam and compared field by
//!   field; re-deriving a fresh checksum over values held in memory would
//!   replace the proof rather than check it.
//! - It does not create a journal. [`RestoreJournalAdmissionOwner`] is a read
//!   seam over state the owner already committed, and the row it must agree
//!   with is written by the existing compare-and-swap, not here.
//!
//! Existence and shape prove nothing. [`RestoreJournalAdmission::binds_owner_record`]
//! re-reads the owner's own record for the exact operation this plan names and
//! requires exact agreement on the owner binding, the database, the
//! installation, the generation, the journal identity, the receipt and the
//! transaction, so an admission that is well formed but borrowed from a
//! different operation or installation fails closed.
//!
//! The live journal is a corroboration of that record, not a substitute for it.
//! When a row already exists under this operation's key it must carry this
//! transaction; a fresh operation has none, because the engine creates it when
//! the engine starts. The primary proof is always the owner's durable record.
//!
//! This crate supplies no owner of its own. The durable owner of a restore
//! journal is the composition that holds that journal together with the
//! installation registry it admits against, and it answers on the real store;
//! a port with no owner behind it issues nothing, which is why the issuer takes
//! the owner rather than a state value and why a missing record is a refusal
//! instead of an empty admission.

use eliot_contracts::ResourceGeneration;

use super::{
    BackupError, OwnerTrustBinding, RestoreJournalAdmission, RestoreJournalPort, RestorePlan,
    RestoreTransaction,
};

/// One durable journal record, as the owning owner read it at issue time.
///
/// The owner produces this from its own persisted state: the database and the
/// installation registry it committed, the authority generation that registry
/// currently carries, and the admission receipt it wrote for this exact stream.
/// Nothing here is caller-presented, and a value the caller supplies for a
/// *different* operation does not appear in this record.
///
/// The `transaction` is load-bearing rather than descriptive. The journal row
/// the engine writes is created *during* the restore, so an admission issued
/// before the first run legitimately has no row to read; the owner's own
/// durable record of the operation it admitted is therefore the primary proof,
/// and it is only meaningful if it names WHICH operation was admitted. An owner
/// that records a journal key without the transaction has recorded a stream, not
/// an operation, and every admission minted from it would be reusable across
/// operations.
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
    /// The exact restore transaction this owner durably admitted.
    ///
    /// The owner must read this from its own committed state for this journal
    /// key, never recompute it from a value handed in alongside.
    pub transaction: RestoreTransaction,
}

/// The durable owner of the journal behind one restore operation.
///
/// The only production source of a [`RestoreJournalAdmission`]. An
/// implementation must answer from its own persisted state, read at call time,
/// for the journal identity the plan derives. An implementation that echoes a
/// presented value is not an owner, and the binding check below will not rescue
/// it: the check compares that answer, transaction included, against a second
/// read of the same owner, so a value that was never committed durably cannot
/// agree with itself across the two reads of a live store.
pub trait RestoreJournalAdmissionOwner {
    /// Reads the owner's durable journal record for `journal_key`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`BackupError`] when the owner holds no durable record
    /// for that journal, when the record is incomplete, or when the owner's own
    /// state cannot be read. Absence of a record is never reported as an empty
    /// record, and the owner's error is never replaced with a synthesized
    /// value.
    fn durable_journal_record(
        &self,
        journal_key: &str,
    ) -> Result<DurableJournalRecord, BackupError>;
}

/// The exact operation one journal admission is bound to.
///
/// Both values are derived from the plan, never supplied: the journal key is
/// the crate's own stream identity for this plan/bundle pair, and the
/// transaction is the stable identity for this plan, bundle and context.
struct AdmittedJournalOperation {
    journal_key: String,
    transaction: RestoreTransaction,
}

impl AdmittedJournalOperation {
    fn of(plan: &RestorePlan) -> Result<Self, BackupError> {
        Ok(Self {
            journal_key: plan.journal_key()?,
            transaction: plan.transaction()?,
        })
    }

    /// Requires that the live journal is not some OTHER operation's stream.
    ///
    /// The row is read through the accepted [`RestoreJournalPort`] seam the
    /// restore engine writes through, so the admission can only ever be issued
    /// against the journal that really holds this exact transaction.
    ///
    /// Absence is NOT a refusal, and the reason is ordering, not leniency.
    /// [`RestorePlan::execute_with_journal`] creates the first row itself, at
    /// the moment the engine starts, so a fresh operation has no row at all
    /// until after the composition must already hold an admission: the
    /// engine's own entry refuses an operation that is not already admitted.
    /// Requiring a row here would make the fresh production path unreachable
    /// and leave only the resume path issuable, which is exactly the kind of
    /// "works because a row happened to exist" proof this artifact exists to
    /// remove.
    ///
    /// So the live journal is a *corroboration*, not the primary proof: when a
    /// row is present it must carry this exact transaction, and a row for
    /// another operation is refused. When no row is present the primary proof
    /// is the owner's own durable record, which
    /// [`DurableJournalRecord::transaction`] pins to this operation.
    fn refuses_foreign_stream<J>(&self, journal: &mut J) -> Result<(), BackupError>
    where
        J: RestoreJournalPort + ?Sized,
    {
        let Some(row) = journal.load(&self.journal_key)? else {
            return Ok(());
        };
        if row.journal_key != self.journal_key || row.transaction != self.transaction {
            return Err(BackupError::RestoreJournalMismatch);
        }
        Ok(())
    }
}

impl RestoreJournalAdmission {
    /// Issues the owner-issued admission for the journal behind `plan`.
    ///
    /// Every field is copied from the owner's durable record for the journal
    /// identity this plan derives; none is an argument, so no caller can select
    /// the database, the installation, the generation, the journal identity or
    /// the receipt. The owner's recorded `transaction` must equal the one this
    /// plan derives, so a record that admitted a different operation under the
    /// same stream cannot mint this one. `fixture_proof_only` is `false`
    /// because the record came from a durable owner rather than a fixture, and
    /// the result is immediately re-proved against a fresh read of both the
    /// same owner and the same live journal, so an owner whose record is not
    /// stable across the issue refuses instead of issuing.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalMismatch`] when the owner's record
    /// does not name this plan's transaction, or when the live journal already
    /// holds a different operation under this key, and the owner's own typed
    /// error when its record cannot be read.
    pub fn issue_for_operation<O, J>(
        owner: &O,
        journal: &mut J,
        plan: &RestorePlan,
    ) -> Result<Self, BackupError>
    where
        O: RestoreJournalAdmissionOwner + ?Sized,
        J: RestoreJournalPort + ?Sized,
    {
        let operation = AdmittedJournalOperation::of(plan)?;
        let record = owner.durable_journal_record(&operation.journal_key)?;
        if record.transaction != operation.transaction
            || record.journal_identity_ref != operation.journal_key
        {
            return Err(BackupError::RestoreJournalMismatch);
        }
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
        operation.refuses_foreign_stream(journal)?;
        admission.binds_owner_record(owner, journal, plan)?;
        Ok(admission)
    }

    /// Requires that this admission still agrees with the durable journal and
    /// the owner's record for the operation `plan` names.
    ///
    /// This is the operation and installation binding. The journal identity
    /// must be the one this plan derives, the live journal must not already
    /// hold a different operation under it, and the owner binding, database,
    /// installation, generation, receipt AND transaction must equal what the
    /// owner durably holds for that same journal. A structurally valid
    /// admission issued for a different operation, or one whose installation
    /// has moved under the registry, fails closed, as does an admission that
    /// never admitted a production durable journal. Both refusals are the
    /// crate's existing typed journal errors, not a generic code, and the
    /// owner's own error is passed through rather than collapsed into one.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the admission is
    /// fixture-only, [`BackupError::RestoreJournalMismatch`] on any difference
    /// from the durable journal or the owner's current record, and the owner's
    /// own typed error when that record cannot be read.
    pub fn binds_owner_record<O, J>(
        &self,
        owner: &O,
        journal: &mut J,
        plan: &RestorePlan,
    ) -> Result<(), BackupError>
    where
        O: RestoreJournalAdmissionOwner + ?Sized,
        J: RestoreJournalPort + ?Sized,
    {
        if !self.admits_production_durable_recovery() {
            return Err(BackupError::RestoreJournalRequired);
        }
        self.validate()?;
        let operation = AdmittedJournalOperation::of(plan)?;
        if self.journal_identity_ref != operation.journal_key {
            return Err(BackupError::RestoreJournalMismatch);
        }
        operation.refuses_foreign_stream(journal)?;
        let current = owner.durable_journal_record(&operation.journal_key)?;
        let agrees = current.journal_identity_ref == operation.journal_key
            && current.transaction == operation.transaction
            && self.persistent_owner == current.persistent_owner
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
