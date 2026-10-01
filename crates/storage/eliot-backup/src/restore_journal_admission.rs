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
//!   operation is the [`RestorePlan`], and both the stream identity and the
//!   transaction are derived from that plan by the crate's own plan identity
//!   helpers — the stream through
//!   [`RestoreJournalAdmissionOwner::issue_journal_stream`], which publishes it
//!   outward rather than taking it from a caller — so a caller cannot point the
//!   issuer at a stream of its own choosing.
//! - It does not add a second trust scheme. The binding is the existing
//!   [`OwnerTrustBinding`], and the production test remains the existing
//!   `require_production_admitted` in the restore owner: this module never
//!   relaxes it and never sets `fixture_proof_only` other than to `false`, the
//!   only value that admits a production durable-recovery claim.
//! - It does not compare the journal identity to a value it derives.
//!   `journal_identity_ref` names the durable CHANNEL the owner answers for,
//!   and the owner is the authority on that name. Requiring it to equal the
//!   plan's own derived stream key demanded two incompatible meanings of one
//!   field and made every honest admission unsatisfiable. The per-execution
//!   stream is proved by reading the live journal under it, not by that field.
//! - It does not recompute any digest the owner recorded. The journal row is
//!   read through the accepted [`RestoreJournalPort`] seam and compared field by
//!   field; re-deriving a fresh checksum over values held in memory would
//!   replace the proof rather than check it.
//! - It does not run a restore, and it does not start one. The only row it
//!   ever writes is the one genesis row the engine's own first act would have
//!   written, through the same accepted [`RestoreJournalPort`] seam, for the
//!   same transaction, carrying no intent, no receipt and no effect — see
//!   [`RestoreJournalAdmissionOwner::issue_journal_stream`]. Every check below
//!   it remains a read over committed state.
//!
//! Existence and shape prove nothing. [`RestoreJournalAdmission::binds_owner_record`]
//! re-reads both the durable journal and the owner's record for the exact
//! operation this plan names, and requires exact agreement on the owner
//! binding, the database, the installation, the generation, the journal
//! identity and the receipt, so an admission that is well formed but borrowed
//! from a different operation or installation fails closed.
//!
//! Agreement with the owner alone is not enough for the receipt, and is not
//! treated as enough here. An owner that answers the same way twice agrees with
//! itself whatever operation it was asked about, so a receipt compared only with
//! the owner's own re-read carries no operation identity at all. The receipt is
//! therefore held to the durable transaction identity on the journal row this
//! plan's own derived stream key resolves to — a content comparison against THAT
//! operation — at issue time and at every re-proof. The other three references
//! have no such per-operation value in this crate to compare against: the
//! database label, the installation identity and the durable channel name are
//! single facts about the store this owner serves, identical for every stream it
//! answers, and the owner is their authority. Binding those three to durable
//! per-operation state is the OWNER's write side, not this crate's.
//!
//! ## Why the owner also ISSUES the stream, rather than only reading one
//!
//! An admission admits an EXISTING durable journal, so the row it is admitted
//! against has to exist before admission. The only producer of that row was the
//! engine's own genesis compare-and-swap, which runs after admission — a circle
//! in which a first run always refuses and, because no first run ever succeeds,
//! no resume can exist either. The entry was unreachable for success, not merely
//! first-run-blocked.
//!
//! [`RestoreJournalAdmissionOwner::issue_journal_stream`] is what breaks it, and
//! it breaks it in the only direction that keeps admission honest: the OWNER
//! establishes the stream and publishes the identity it filed it under. No
//! caller, and no coordinator, ever derives that identity — the derivation
//! lives with the plan, and it is handed out here rather than reconstructed at
//! the call site, because a key the owner did not issue is not the owner's key.
//!
//! What is established is exactly what the engine would have written as its own
//! first act, for the same transaction, through the same accepted
//! [`RestoreJournalPort`] seam: one genesis row at revision 0 with no intent, no
//! receipt and no effect. The engine then reads that row on its way in and
//! continues from it, so this changes no byte the engine would have written and
//! no decision it would have made. It is a capability that was missing, not a
//! check that was removed.
//!
//! This crate supplies no owner of its own. The durable owner of a restore
//! journal is the composition that holds that journal together with the
//! installation registry it admits against, and it answers on the real store;
//! a port with no owner behind it issues nothing, which is why the issuer takes
//! the owner rather than a state value and why a missing record is a refusal
//! instead of an empty admission.

use eliot_contracts::ResourceGeneration;

use super::{
    BackupError, OwnerTrustBinding, RestoreJournalAdmission, RestoreJournalPort,
    RestoreJournalRecord, RestoreJournalState, RestorePhase, RestorePlan, RestoreTransaction,
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
    ///
    /// Read by the owner from durable state it committed for this database — the
    /// store's own set-once installation binding — rather than from the live
    /// composition the read was issued from. A process is not the database, so
    /// what the durable bytes belong to is the owner's durable statement and not
    /// a live cell value.
    pub installation_ref: String,
    /// The committed authority generation of that installation.
    pub generation: ResourceGeneration,
    /// The journal identity committed for this operation: the durable CHANNEL
    /// the owner's record was read through.
    ///
    /// This is NOT the per-execution stream key. A channel is fixed across
    /// every execution the owner issues for; the stream key is derived from
    /// the plan (`sha256(plan_id, bundle_sha256)`) and differs for every
    /// plan/bundle pair, so it can never equal a fixed channel name. The
    /// admission's `journal_identity_ref` therefore carries ONE meaning — the
    /// durable channel — and consumers that need to know which store admitted a
    /// restore compare it against that channel's own name, which is exactly
    /// what a composition-side channel check must do. The per-execution stream
    /// this record was read under is the `journal_key` argument
    /// [`RestoreJournalAdmissionOwner::durable_journal_record`] was called with,
    /// and it is proved by that read rather than by this field;
    /// [`RestoreJournalAdmission::binds_owner_record`] supplies the operation
    /// itself and reads the same stream.
    pub journal_identity_ref: String,
    /// The admission receipt committed for this operation.
    pub admission_receipt_ref: String,
}

/// The durable owner of the journal behind one restore operation.
///
/// The only production source of a [`RestoreJournalAdmission`]. An
/// implementation must answer from its own persisted state, read at call time,
/// for the stream the plan derives. An implementation that echoes a presented
/// value is not an owner, and the binding check below will not rescue it: the
/// check compares that answer against the durable journal row, so a value that
/// was never committed to that row cannot agree with it.
///
/// The owner also ISSUES that stream through
/// [`Self::issue_journal_stream`], because the row an admission admits has to
/// exist before admission. The two halves are deliberately asymmetric — the
/// owner writes exactly the genesis row the engine would have written and
/// nothing else, then answers from durable state — because that is the only
/// direction in which the admission is derived from a row that really exists on
/// a first run.
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

    /// Issues the journal stream identity for `plan`'s operation, and returns
    /// the identity the owner filed that stream under.
    ///
    /// This is the owner's own write side, and it is deliberately narrow:
    ///
    /// - The identity is derived from `plan` HERE, where that derivation lives,
    ///   and published outward. A caller receives the key; it never computes
    ///   one, and no caller-supplied key is accepted, so a coordinator cannot
    ///   point the admission at a stream of its own choosing.
    /// - A stream the owner has not established is established by one genesis
    ///   compare-and-swap through the accepted [`RestoreJournalPort`] seam the
    ///   restore engine itself writes through — so the same owner binding, the
    ///   same seal and the same writer fence apply, and the ORS stream-binding
    ///   row is written by that same owner path rather than constructed here.
    ///   It is the exact row [`RestorePlan::execute_with_journal`] writes as its
    ///   own first act: the plan's own transaction, revision 0, phase
    ///   `Pending`, state `Ready`, and no intent, receipt or effect. A stream
    ///   the owner already established is left untouched, which is the resume
    ///   case.
    /// - A stream that already exists for a DIFFERENT transaction is
    ///   [`BackupError::RestoreJournalMismatch`], never adopted: the owner's
    ///   stream is never taken over and its history is never rewritten.
    /// - The returned identity is only produced after a fresh read proves the
    ///   row is durable and holds this operation's own transaction, so what
    ///   comes back is a verified durable fact, not a derivation.
    ///
    /// No target effect happens here. This writes one journal row that records
    /// which stream an operation runs in; it applies nothing, imports nothing
    /// and reaches no cutover, and the engine still refuses a plan whose own
    /// validation fails.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalMismatch`] when the stream exists
    /// for another transaction or the establishment cannot be committed, and
    /// passes the port's own typed error through otherwise.
    fn issue_journal_stream<J>(
        &self,
        journal: &mut J,
        plan: &RestorePlan,
    ) -> Result<String, BackupError>
    where
        J: RestoreJournalPort + ?Sized,
    {
        AdmittedJournalOperation::of(plan)?.establish_stream(journal)
    }
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

    /// Returns this operation's own durable journal row, read at issue time.
    ///
    /// The row is read through the accepted [`RestoreJournalPort`] seam the
    /// restore engine writes through, so the admission can only ever be issued
    /// against a journal that really holds this exact transaction, and the
    /// owner-reported record can only be compared against a row that exists.
    fn durable_row<J>(&self, journal: &mut J) -> Result<RestoreJournalRecord, BackupError>
    where
        J: RestoreJournalPort + ?Sized,
    {
        let row = journal
            .load(&self.journal_key)?
            .ok_or(BackupError::RestoreJournalRequired)?;
        if row.journal_key != self.journal_key || row.transaction != self.transaction {
            return Err(BackupError::RestoreJournalMismatch);
        }
        Ok(row)
    }

    /// Requires that the live journal is this operation's own durable journal.
    fn is_journal_of<J>(&self, journal: &mut J) -> Result<(), BackupError>
    where
        J: RestoreJournalPort + ?Sized,
    {
        self.durable_row(journal).map(|_| ())
    }

    /// Requires that `receipt_ref` is THIS operation's own admission receipt.
    ///
    /// This is the one of the four owner-issued references whose exact value is
    /// recoverable from durable owner state this crate already holds: `row` is
    /// the durable journal row this operation's own derived stream key resolved
    /// to, and the transaction identity on it is the operation identity the
    /// journal owner durably committed for that stream. The check therefore
    /// compares the reference's CONTENT with THAT operation — not its shape, not
    /// its non-emptiness, and not the owner's own second reading of itself.
    ///
    /// Before this check the receipt was only ever compared with the owner's own
    /// re-read of itself, so the reference's operation identity rested entirely
    /// on the owner agreeing with the owner. A receipt borrowed from a different
    /// operation now refuses, because the durable row under this plan's own
    /// stream holds a different transaction identity.
    fn binds_admission_receipt(
        &self,
        row: &RestoreJournalRecord,
        receipt_ref: &str,
    ) -> Result<(), BackupError> {
        if row.transaction.transaction_id != receipt_ref
            || self.transaction.transaction_id != receipt_ref
        {
            return Err(BackupError::RestoreJournalMismatch);
        }
        Ok(())
    }

    /// Durably establishes this operation's own journal stream and returns the
    /// stream identity it was filed under.
    ///
    /// An unstarted stream is established by the single genesis
    /// compare-and-swap the engine performs as its own first act, written
    /// through the accepted [`RestoreJournalPort`] seam and carrying no intent,
    /// no receipt and no effect; the engine then reads that row on its way in
    /// and continues from it. A stream already holding this transaction is the
    /// resume case and is left exactly as it stands, so establishing a stream is
    /// never able to rewrite history. A stream holding any other transaction is
    /// refused, never adopted.
    fn establish_stream<J>(&self, journal: &mut J) -> Result<String, BackupError>
    where
        J: RestoreJournalPort + ?Sized,
    {
        if journal.load(&self.journal_key)?.is_none() {
            journal.compare_and_swap(
                &self.journal_key,
                0,
                RestoreJournalRecord {
                    journal_key: self.journal_key.clone(),
                    transaction: self.transaction.clone(),
                    revision: 0,
                    completed_phases: 0,
                    phase: RestorePhase::Pending,
                    state: RestoreJournalState::Ready,
                    intent: None,
                    receipt: None,
                    final_receipt: None,
                },
            )?;
        }
        // The identity is issued only once a fresh read proves the row is
        // durable and is this operation's own, so what the owner hands back is
        // a verified durable fact rather than a derivation. A stream that
        // already held another transaction refuses here, typed and without
        // writing anything further.
        self.is_journal_of(journal)?;
        Ok(self.journal_key.clone())
    }
}

impl RestoreJournalAdmission {
    /// Issues the owner-issued admission for the journal behind `plan`.
    ///
    /// Every field is copied from the owner's durable record for the journal
    /// identity the OWNER issued for this operation; none is an argument, so no
    /// caller can select the database, the installation, the generation, the
    /// journal identity or the receipt. `fixture_proof_only` is `false` because
    /// the record came from a durable owner rather than a fixture, and the
    /// result is immediately re-proved against a fresh read of both the same
    /// owner and the same live journal, so an owner whose record is not stable
    /// across the issue refuses instead of issuing.
    ///
    /// The stream identity is the owner's to issue, not this issuer's to derive
    /// and not the caller's to supply:
    /// [`RestoreJournalAdmissionOwner::issue_journal_stream`] establishes the
    /// stream and publishes the key it filed it under, that key must be this
    /// plan's own derived stream, and the owner's record is then read under
    /// that published key.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalMismatch`] when the owner's issued
    /// stream is not this plan's own, when the re-read record does not agree
    /// with the one issued, or when the stream could not be established,
    /// [`BackupError::RestoreJournalRequired`] when the journal holds no
    /// durable row for this operation, and the owner's own typed error
    /// otherwise.
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
        let issued_stream_key = owner.issue_journal_stream(journal, plan)?;
        if issued_stream_key != operation.journal_key {
            return Err(BackupError::RestoreJournalMismatch);
        }
        let record = owner.durable_journal_record(&issued_stream_key)?;
        // The receipt is the one owner-issued reference this crate can hold to
        // the exact operation with a durable fact of its own: the transaction
        // identity on the journal row this plan's own derived stream resolved
        // to. Reading that row here means a receipt borrowed from another
        // operation is refused at ISSUE time, before the value is ever copied
        // into an admission, instead of only being caught by the later re-proof.
        let issued_row = operation.durable_row(journal)?;
        operation.binds_admission_receipt(&issued_row, &record.admission_receipt_ref)?;
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
    /// This is the operation and installation binding. The live journal must
    /// already hold this exact transaction under the stream this plan derives,
    /// the journal identity must be the channel this owner reports for that
    /// exact stream, and the owner binding, database, installation, generation
    /// and receipt must equal what the owner durably holds for that same
    /// journal. A structurally valid admission issued for a different
    /// operation, or one whose installation has moved under the registry, fails
    /// closed, as does an admission that never admitted a production durable
    /// journal. Both refusals are the crate's existing typed journal errors,
    /// not a generic code, and the owner's own error is passed through rather
    /// than collapsed into one.
    ///
    /// ## Why the journal identity is checked against the OWNER and not the plan
    ///
    /// `journal_identity_ref` names the durable CHANNEL an admission was issued
    /// for, and the channel is one fixed name for every stream the owner serves
    /// — the owner's own value, reported at issue time and re-read here. It is
    /// NOT the per-execution stream key: that key is
    /// `sha256(plan_id, bundle_sha256)`, a different value for every
    /// plan/bundle pair, so requiring the channel field to equal it made the
    /// re-proof unsatisfiable for every owner that issues an honest channel
    /// identity. It is compared here against what the owner reports for the
    /// exact stream this plan names, which is the strongest statement the field
    /// can carry: an admission borrowed from another channel, another store or
    /// another owner refuses.
    ///
    /// The per-execution binding is not weakened by that change and is not
    /// carried by this field: `is_journal_of` reads the live journal UNDER
    /// `operation.journal_key` and requires that row to hold this plan's own
    /// transaction, and the owner record compared against this admission is read
    /// under that same key, so its writer, destination, archive, class and
    /// writer-fence-digest are all proved for this stream.
    ///
    /// # Errors
    ///
    /// Returns [`BackupError::RestoreJournalRequired`] when the admission is
    /// fixture-only or the journal holds no row for this operation,
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
        // The live journal must hold this exact transaction under the stream
        // this plan derives, and the owner's record for that same stream must
        // still be the one this admission names. Both are reads of durable
        // state; neither is re-derived. The row is kept so the receipt below is
        // compared against that same durable read instead of against a second
        // load of the same key.
        let row = operation.durable_row(journal)?;
        // The admission's own receipt must be the transaction identity on THAT
        // row. This is a content comparison against the exact operation; the
        // field-by-field agreement below would otherwise accept any receipt the
        // owner happened to report for itself, because an owner that is stable
        // across two of its own reads agrees with itself whatever the operation.
        operation.binds_admission_receipt(&row, &self.admission_receipt_ref)?;
        let current = owner.durable_journal_record(&operation.journal_key)?;
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
