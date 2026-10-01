//! Startup recovery owner for the durable staged write envelopes (#1925,
//! I5.2/I5.6, A1).
//!
//! This module owns the READ side of the same
//! [`RecoveryPayloadEnvelope`](crate::RecoveryPayloadEnvelope) that the reserved
//! write route stages through
//! [`OperationalRecoveryStore::accept_after_stage`](crate::OperationalRecoveryStore::accept_after_stage).
//! After a restart the owner must be able to ENUMERATE the staged records ORS
//! durably holds, VALIDATE each against its own recorded integrity value, and
//! RECONCILE each by operation identity into either its canonical receipt or a
//! visible Recovery Problem.
//!
//! # What the owner does, and what it deliberately does not
//!
//! - **Enumerate.** [`StagedEnvelopeRecoveryCursor`] pages the staged-envelope
//!   table by operation identity through
//!   [`OperationalRecoveryStore::scan_staged_envelopes`]. Each entry names the
//!   row by its exact key and carries the owning reservation's identity and
//!   lifecycle position. Stored payload bytes are never read into a projection
//!   and never leave ORS.
//! - **Validate.** Each enumerated identity is handed to the store's EXISTING
//!   owner read [`OperationalRecoveryStore::verify_staged_envelope`], which
//!   decodes the stored row and runs
//!   [`RecoveryPayloadEnvelope::validate`](crate::RecoveryPayloadEnvelope::validate).
//!   That gate compares the ciphertext against the digest the envelope itself
//!   RECORDED at stage time, so the expected value is the owner's own durable
//!   record — never a digest this module recomputed and compared with itself.
//!   This module performs no integrity arithmetic of its own and cannot introduce
//!   a second integrity scheme.
//! - **Reconcile.** A validated envelope is matched back to its reservation by
//!   exact operation identity. A reservation that carries a durable
//!   `terminal_receipt_id` — committed (`Finalized`) or terminally rejected
//!   (`Released`), both of which record the receipt identity — is reported as
//!   reconciled into that canonical receipt only after the store has re-read the
//!   durable Ordering Scope receipts ORS recorded with it through its own
//!   existing binding check
//!   ([`OperationalRecoveryStore::verify_staged_terminal_receipt`]). The
//!   PRESENCE of a receipt id is never the evidence: a reservation whose
//!   recorded receipt is absent from, or disagrees with, its own durable scope
//!   receipt is a failed check, not a reconciled operation (A13.6). A
//!   reservation that has not reached its receipt is reported as still staged;
//!   it is NOT called a problem, because a healthy pending stage is not a
//!   fault.
//! - **Record a problem.** A decode failure, hash mismatch, missing record
//!   binding, or envelope/token/idempotency divergence makes
//!   `verify_staged_envelope` retain a durable [`RecoveryProblem`] and fail
//!   with [`OrsError::RecoveryProblemRetained`]. The owner reports that durable
//!   record. Plaintext fallback and deletion are impossible from here: this
//!   module never holds a payload, never removes a staged row, and never
//!   re-derives a digest.
//!
//! # Failed checks stay failed checks
//!
//! An unreadable ORS, a page whose continuation does not advance, or a
//! `RecoveryProblemRecordFailed` (the durable problem itself could not be
//! written) propagate as the store's own [`OrsError`]. The owner never
//! substitutes an empty or "clean" report for a check it could not perform.
//! A scan that stopped at the whole-scan bound is reported `truncated`, which
//! the caller must not read as exhaustive coverage.
//!
//! A staged row whose owner index does not resolve is neither of those: it is a
//! fault on ONE row, so the store retains the durable problem it can bind and
//! reports the row as [`StagedWriteReconciliation::UnresolvedReservation`]
//! (or [`StagedWriteReconciliation::RecoveryProblem`]) instead of abandoning
//! every other row the pass had not yet reached. It is never skipped, and never
//! reported as reconciled, staged, or absent.

use crate::{
    MAX_RECOVERY_PAGE, OpaqueLabel, OperationIdentity, OperationalRecoveryStore, OrsError,
    RecoveryProblem, ReservationState,
};

/// Exclusive, key-ordered cursor over the staged write envelopes ORS durably
/// holds.
///
/// This is the same shape and the same boundedness contract as
/// [`RecoveryCursor`](crate::RecoveryCursor): `limit` must be within
/// `1..=MAX_RECOVERY_PAGE`, and `after_operation_id` is exclusive. It is
/// deliberately NOT bound to a [`RecoveryInventorySnapshot`](crate::RecoveryInventorySnapshot):
/// the staged-envelope table has no independently revisioned source in that
/// snapshot, and adding one would change the snapshot's serialized shape. The
/// consequence is stated rather than hidden — the cursor is stable per page and
/// reports a continuation, and the driver below stops with `truncated` set
/// instead of claiming coverage it did not reach.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEnvelopeRecoveryCursor {
    /// Exclusive lower bound; `None` starts at the first key.
    pub after_operation_id: Option<OperationIdentity>,
    /// Whole-scan budget this page may consume.
    pub limit: u16,
}

impl StagedEnvelopeRecoveryCursor {
    /// Constructs a cursor under the hard page ceiling.
    pub fn new(
        after_operation_id: Option<OperationIdentity>,
        limit: u16,
    ) -> Result<Self, OrsError> {
        if limit == 0 || limit > MAX_RECOVERY_PAGE {
            return Err(OrsError::InvalidCursorLimit);
        }
        Ok(Self {
            after_operation_id,
            limit,
        })
    }

    pub(crate) fn continue_after(&self, after_operation_id: OperationIdentity) -> Self {
        Self {
            after_operation_id: Some(after_operation_id),
            limit: self.limit,
        }
    }
}

/// How one enumerated staged envelope row resolves to the reservation that owns
/// it, through the owner's own durable operation index.
///
/// The binding is a CLOSED outcome, not a field that may be blank: a staged row
/// either resolves to the reservation whose recorded operation identity is that
/// row's exact key, or it does not resolve at all. There is no third spelling in
/// which a row is enumerated and quietly reported as an owned, clean record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagedEnvelopeReservationBinding {
    /// The owner's own durable operation index resolved this row to a
    /// reservation whose recorded operation identity IS this row's key.
    Resolved {
        /// Reservation this operation identity resolves to, read in the same
        /// read snapshot as the row.
        reservation_id: OperationIdentity,
        /// Lifecycle position of that reservation.
        reservation_state: ReservationState,
    },
    /// The owner's own durable operation index did not resolve this row to a
    /// reservation (issue #1925, A13.6).
    ///
    /// `problem` is the durable [`RecoveryProblem`] ORS retained for this exact
    /// staged operation identity, whenever the durable bindings a problem record
    /// must carry were recoverable. It is `None` only where the reservation that
    /// would carry them — the authority epoch, state fence and recovery owner —
    /// is itself what is missing: ORS does not invent those bindings, so the row
    /// is reported under its own key with `cause` instead. Either way the row is
    /// REPORTED, never skipped, and it can never become a clean or reconciled
    /// outcome.
    Unresolved {
        /// Reservation identity the durable operation index named, when it named
        /// one. `None` when the index row itself is absent.
        reservation_id: Option<OperationIdentity>,
        /// The durable problem ORS retained for this staged operation identity,
        /// when it could be bound.
        ///
        /// Boxed: [`RecoveryProblem`] is the one large variant payload in this
        /// enum, and the `Resolved` arm beside it is small. Boxing keeps the
        /// whole enumeration entry small enough to hold a page of them, which is
        /// what the bounded scan exists to do. The indirection costs nothing on
        /// the resolution path, because the common arm never touches it.
        problem: Option<Box<RecoveryProblem>>,
        /// Bounded operator-visible cause owned by ORS, never payload text.
        cause: OpaqueLabel,
    },
}

/// One staged write envelope as the startup owner enumerated it.
///
/// A reference to durable owner state, never a payload. Enumeration reads only
/// the row's KEY plus the owning reservation's identity and lifecycle
/// position; the row's stored bytes are never read into a projection, decoded,
/// interpreted, or returned. That is deliberate: a row whose bytes do not decode
/// must still be enumerated so the owner can turn it into a durable Recovery
/// Problem instead of losing it, and the durable problem already carries the
/// stored-bytes and payload fingerprints through the owner's existing
/// `retain_staging_problem` path.
///
/// The recorded `payload_sha256` and `payload_length` are deliberately absent
/// here: an entry is produced before validation, so a row that does not decode
/// has no trustworthy recorded bindings to report. They are restated only on a
/// `StagedWriteReconciliation::Reconciled` outcome, i.e. only after the owner
/// validated them.
///
/// The recorded `terminal_receipt_id` is absent for the same reason. A receipt
/// id sitting in a reservation row is a RECORDED VALUE, not a checked receipt,
/// so reporting it here would hand the caller a presence it could mistake for
/// the reconciliation it is not. The owner reads it back through
/// [`OperationalRecoveryStore::verify_staged_terminal_receipt`], which compares
/// it against the durable Ordering Scope receipts ORS committed with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEnvelopeRecoveryEntry {
    /// Exact key the staged envelope is enumerated under. It is also the key of
    /// any Recovery Problem ORS retained for this row, so the operator finds the
    /// record under the identity the row is actually stored at.
    pub operation_id: OperationIdentity,
    /// What that exact key resolves to through the owner's own durable index.
    pub reservation: StagedEnvelopeReservationBinding,
}

/// One bounded page of enumerated staged write envelopes.
///
/// `next_cursor` is `None` exactly when the table was exhausted within this
/// page's budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedEnvelopeRecoveryPage {
    pub records: Vec<StagedEnvelopeRecoveryEntry>,
    pub next_cursor: Option<StagedEnvelopeRecoveryCursor>,
}

/// Outcome of reconciling one enumerated staged write envelope by operation
/// identity.
///
/// `Staged` exists because the honest third outcome must be nameable: an
/// envelope that validated and whose reservation simply has not reached its
/// receipt yet is neither reconciled nor faulty, and calling it a Recovery
/// Problem would be a false alarm while calling it reconciled would be a false
/// claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagedWriteReconciliation {
    /// Validated against its recorded integrity bindings, and its reservation's
    /// canonical terminal receipt was re-read from the durable Ordering Scope
    /// receipts ORS committed with it and matched exactly.
    Reconciled {
        operation_id: OperationIdentity,
        reservation_id: OperationIdentity,
        terminal_receipt_id: OpaqueLabel,
        payload_sha256: String,
        payload_length: u64,
    },
    /// Validated against its recorded integrity bindings, and still awaiting
    /// its canonical receipt. The staged record stays exactly as durable.
    Staged {
        operation_id: OperationIdentity,
        reservation_id: OperationIdentity,
        state: ReservationState,
    },
    /// The owner's own durable operation index did not resolve this staged row
    /// to a reservation, so no receipt comparison was possible at all
    /// (issue #1925, A13.6).
    ///
    /// This is deliberately NOT a clean outcome and NOT a skipped row: the pass
    /// reports it under the exact key the staged row is stored at, together with
    /// the owner's own bounded cause, so the record is visible, locatable, and
    /// never mistaken for a reconciled or an absent operation.
    UnresolvedReservation {
        operation_id: OperationIdentity,
        /// Bounded operator-visible cause owned by ORS, never payload text.
        cause: OpaqueLabel,
    },
    /// Validation failed and ORS retained a durable Recovery Problem for this
    /// operation. The staged row is untouched and remains available for
    /// explicit disposition.
    RecoveryProblem { problem: RecoveryProblem },
}

/// Bounded startup report over the durable staged write envelopes.
#[derive(Clone, Debug)]
pub struct StagedWriteRecoveryReport {
    /// Whole-scan ceiling the owner ran under.
    pub scan_limit: u16,
    /// Staged envelopes enumerated and examined.
    pub scanned: u64,
    /// True when the whole-scan bound stopped the enumeration before the staged
    /// envelope table was exhausted. A truncated report has proved nothing
    /// about the rows it did not reach.
    pub truncated: bool,
    /// One entry per enumerated staged envelope, in operation-identity order.
    pub reconciliations: Vec<StagedWriteReconciliation>,
}

/// Enumerates, validates and reconciles every durable staged write envelope
/// under the store's own whole-scan `limit`.
///
/// This is the production startup recovery owner for the envelope
/// `accept_after_stage` stages. It reads, it validates, and it records a
/// Recovery Problem for a record that fails validation; it never writes a
/// reservation lifecycle position, never releases a reservation, never retries
/// an operation, and never removes a staged row.
pub fn recover_staged_write_envelopes(
    store: &impl OperationalRecoveryStore,
    limit: u16,
) -> Result<StagedWriteRecoveryReport, OrsError> {
    if limit == 0 || limit > MAX_RECOVERY_PAGE {
        return Err(OrsError::InvalidCursorLimit);
    }
    let mut after_operation_id: Option<OperationIdentity> = None;
    let mut scanned: u64 = 0;
    let mut truncated = false;
    let mut reconciliations: Vec<StagedWriteReconciliation> = Vec::new();
    loop {
        // The whole-scan budget is spent across pages, not reset per page, so a
        // multi-page enumeration cannot exceed the ceiling the caller set.
        let consumed = u16::try_from(scanned).map_err(|_| {
            OrsError::Storage(
                "staged envelope enumeration overflowed the bounded counter".to_owned(),
            )
        })?;
        let remaining = limit.checked_sub(consumed).ok_or_else(|| {
            OrsError::Storage(
                "staged envelope enumeration exceeded the whole-scan bound".to_owned(),
            )
        })?;
        if remaining == 0 {
            // A continuation cursor was still outstanding, so the table was not
            // exhausted: coverage is incomplete and stays visible as such. The
            // rows already examined keep their outcomes.
            truncated = true;
            break;
        }
        let cursor = StagedEnvelopeRecoveryCursor::new(after_operation_id.clone(), remaining)?;
        let page = store.scan_staged_envelopes(cursor)?;
        for entry in &page.records {
            scanned = scanned.checked_add(1).ok_or_else(|| {
                OrsError::Storage(
                    "staged envelope enumeration overflowed the bounded counter".to_owned(),
                )
            })?;
            reconciliations.push(reconcile_one_staged_envelope(store, entry)?);
        }
        match page.next_cursor {
            Some(next) => {
                // A continuation must strictly advance past the key it followed,
                // or the page did not make progress and coverage would be
                // reported as larger than it is.
                if next.after_operation_id.as_ref() <= after_operation_id.as_ref() {
                    return Err(OrsError::IntegrityProblem {
                        record_type: "recovery_envelope",
                        reason: "staged envelope continuation cursor does not advance".to_owned(),
                    });
                }
                after_operation_id = next.after_operation_id;
            }
            None => break,
        }
    }
    Ok(StagedWriteRecoveryReport {
        scan_limit: limit,
        scanned,
        truncated,
        reconciliations,
    })
}

/// Validates and reconciles one enumerated staged write envelope.
///
/// The integrity decision belongs entirely to the store's existing
/// `verify_staged_envelope` owner read, which validates the recorded digest
/// value and retains the durable Recovery Problem on failure, and to the
/// store's existing `verify_staged_terminal_receipt` binding check, which
/// re-reads the durable scope receipts a recorded terminal receipt must match.
/// This function only classifies those typed outcomes.
fn reconcile_one_staged_envelope(
    store: &impl OperationalRecoveryStore,
    entry: &StagedEnvelopeRecoveryEntry,
) -> Result<StagedWriteReconciliation, OrsError> {
    let (reservation_id, reservation_state) = match &entry.reservation {
        // The owner's own index did not resolve this row. ORS already retained
        // the durable problem for this exact staged operation identity where it
        // could be bound, so that record is reported rather than re-derived.
        StagedEnvelopeReservationBinding::Unresolved {
            problem: Some(problem),
            ..
        } => {
            return Ok(StagedWriteReconciliation::RecoveryProblem {
                problem: problem.as_ref().clone(),
            });
        }
        // No reservation resolved, so there is no receipt to compare and no
        // durable binding a problem record could carry. The row is still
        // reported, under its own key and with the owner's own cause.
        StagedEnvelopeReservationBinding::Unresolved { cause, .. } => {
            return Ok(StagedWriteReconciliation::UnresolvedReservation {
                operation_id: entry.operation_id.clone(),
                cause: cause.clone(),
            });
        }
        StagedEnvelopeReservationBinding::Resolved {
            reservation_id,
            reservation_state,
        } => (reservation_id, *reservation_state),
    };
    let envelope = match store.verify_staged_envelope(&entry.operation_id) {
        Ok(envelope) => envelope,
        // A durable Recovery Problem is retained for this operation. Read the
        // retained record back so the startup report carries the owner's own
        // durable problem rather than a synthesized one. The staged row is
        // untouched: the store's problem retention never deletes it, and this
        // owner never issues a removal.
        Err(OrsError::RecoveryProblemRetained { .. }) => {
            let problem = store
                .load_recovery_problem(&entry.operation_id)?
                .ok_or_else(|| OrsError::IntegrityProblem {
                    record_type: "recovery_problem",
                    reason: "a retained recovery problem is absent for the operation it was \
                             retained for"
                        .to_owned(),
                })?;
            return Ok(StagedWriteReconciliation::RecoveryProblem { problem });
        }
        // Every other typed failure is a failed check and propagates unchanged.
        // In particular `RecoveryProblemRecordFailed` means NO durable problem
        // exists for this operation, so the pass must fail rather than report
        // the operation as clean or absent.
        Err(error) => return Err(error),
    };
    // A canonical receipt is the reconciliation evidence, so it is only
    // reported once the store has re-read the durable Ordering Scope receipts it
    // was committed with and found them bound to that exact receipt identity
    // (A13.6). Whether the canonical owner committed the write (`Finalized`) or
    // terminally rejected it (`Released`), both dispositions record the receipt,
    // and the durable scope receipt is what decides the question — not the
    // presence of an id and not the spelling of the terminal state. The digest
    // and length restated below are the envelope's OWN recorded values, already
    // checked by the owner read above.
    match store.verify_staged_terminal_receipt(&entry.operation_id)? {
        Some(terminal_receipt_id) => Ok(StagedWriteReconciliation::Reconciled {
            operation_id: entry.operation_id.clone(),
            reservation_id: reservation_id.clone(),
            terminal_receipt_id,
            payload_sha256: envelope.payload_sha256,
            payload_length: envelope.payload_length,
        }),
        None => Ok(StagedWriteReconciliation::Staged {
            operation_id: entry.operation_id.clone(),
            reservation_id: reservation_id.clone(),
            state: reservation_state,
        }),
    }
}
