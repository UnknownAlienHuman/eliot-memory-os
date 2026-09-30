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
//!   operation is the [`RestorePlan`], and both the journal stream key and the
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
//!   seam over state the owner already committed: the stream binding it reads
//!   is written by the owner itself through its own store, never here, and this
//!   module writes no journal row at all.
//!
//! Existence and shape prove nothing. [`RestoreJournalAdmission::binds_owner_record`]
//! re-reads both the durable journal and the owner's record for the exact
//! operation this plan names, and requires exact agreement on the owner
//! binding, the database, the installation, the generation, the journal
//! identity and the receipt, so an admission that is well formed but borrowed
//! from a different operation or installation fails closed.
//!
//! ## The journal identity and the stream key are two facts
//!
//! [`RestoreJournalAdmission::journal_identity_ref`] carries the durable
//! CHANNEL's namespace identity: a fixed property of every row the store's
//! restore-journal adapter writes, and of nothing else. It is not
//! [`RestorePlan::journal_key`], which is the plan-derived per-execution STREAM
//! key and changes for every plan/bundle pair. Asking one field to carry both
//! makes the owner-issued path unsatisfiable, so the operation binding is
//! carried by the fields that actually have a per-operation derivation: the
//! owner's admission receipt, which is the transaction identity the owner
//! committed for this stream, and the live journal row this plan's stream must
//! hold. Both are compared here, so nothing is lost by the split.
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
    /// The journal identity of the durable channel this operation is admitted
    /// against: the namespace identity every row of that channel's restore
    /// journal carries.
    ///
    /// It is a fixed property of the CHANNEL, so it is the same value for
    /// every execution, archive and plan, and it is deliberately NOT
    /// [`RestorePlan::journal_key`], which is the per-execution STREAM key and
    /// can never equal a fixed channel name. The per-operation binding is
    /// carried by `admission_receipt_ref` and re-proved against the live
    /// journal row by [`RestoreJournalAdmission::binds_owner_record`].
    pub journal_identity_ref: String,
    /// The admission receipt committed for this operation.
    pub admission_receipt_ref: String,
}

/// The durable owner of the journal behind one restore operation.
///
/// The only production source of a [`RestoreJournalAdmission`]. An
/// implementation must answer from its own persisted state, read at call time,
/// for the journal stream the plan derives. An implementation that echoes a
/// presented value is not an owner, and the binding check below will not rescue
/// it: the check compares that answer against the owner's own second read and
/// against the live journal, so a value that was never committed for this stream
/// cannot agree with them.
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

    /// Requires that the live journal is this operation's own durable journal.
    ///
    /// The row is read through the accepted [`RestoreJournalPort`] seam the
    /// restore engine writes through, so the admission can only ever be issued
    /// against a journal that really holds this exact transaction.
    ///
    /// A stream that holds no journal row yet is the exact-new stream, and that
    /// is not an absence of proof here: the caller has already required the
    /// owner's record for this stream and required its receipt to be this plan's
    /// transaction, so the stream is durably adopted by this owner for this
    /// exact operation before this method runs. The engine's genesis
    /// compare-and-swap then writes the first row under that same adoption, and
    /// the ORS owner refuses a stream bound to anything else. A stream that was
    /// never adopted never reaches this method, because the owner read that
    /// precedes it is a refusal.
    fn is_journal_of<J>(&self, journal: &mut J) -> Result<(), BackupError>
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
    /// stream this plan derives; none is an argument, so no caller can select
    /// the database, the installation, the generation, the journal identity or
    /// the receipt. `fixture_proof_only` is `false` because the record came from
    /// a durable owner rather than a fixture, and the result is immediately
    /// re-proved against a fresh read of both the same owner and the same live
    /// journal, so an owner whose record is not stable across the issue refuses
    /// instead of issuing.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the owner holds no
    /// durable record for this stream, [`BackupError::RestoreJournalMismatch`]
    /// when the re-read record does not agree with the one issued, and the
    /// owner's own typed error otherwise.
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
        admission.binds_owner_record(owner, journal, plan)?;
        Ok(admission)
    }

    /// Requires that this admission still agrees with the durable journal and
    /// the owner's record for the operation `plan` names.
    ///
    /// This is the operation and installation binding. The admission receipt
    /// must be the transaction this plan derives, which is the identity the
    /// owner durably committed for this stream and the identity the ORS owner
    /// refuses to rebind; the live journal must be this operation's own stream
    /// and must hold this exact transaction whenever it holds a row at all; and
    /// the owner binding, database, installation, generation, journal identity
    /// and receipt must equal what the owner durably holds for that same
    /// journal. A structurally valid admission issued for a different
    /// operation, or one whose installation has moved under the registry, fails
    /// closed, as does an admission that never admitted a production durable
    /// journal. Both refusals are the crate's existing typed journal errors,
    /// not a generic code, and the owner's own error is passed through rather
    /// than collapsed into one.
    ///
    /// The owner read comes first because it is what proves the stream is
    /// durably adopted at all, and the receipt comparison right after it is
    /// what proves that adoption is THIS plan's transaction. The
    /// journal-identity comparison is left where the namespace is named: the
    /// owner's record is compared field by field here, and the channel
    /// namespace itself is compared by the consumer that owns that constant.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the admission is
    /// fixture-only or the owner holds no durable record for this stream,
    /// [`BackupError::RestoreJournalMismatch`] on any difference from the
    /// durable journal or the owner's current record, and the owner's own typed
    /// error when that record cannot be read.
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
        // The owner's record can only be read for a stream the owner has
        // durably adopted, so this read is itself the proof that the journal
        // behind this admission exists as an adopted persistent owner.
        let current = owner.durable_journal_record(&operation.journal_key)?;
        // The receipt is the transaction identity the owner committed for this
        // stream, so requiring it to be this plan's transaction is the operation
        // binding. It is the successor of the journal-identity comparison this
        // check used to make: the journal identity names the durable CHANNEL,
        // which is fixed across executions, and so never carried a per-operation
        // derivation at all.
        if self.admission_receipt_ref != operation.transaction.transaction_id {
            return Err(BackupError::RestoreJournalMismatch);
        }
        operation.is_journal_of(journal)?;
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
