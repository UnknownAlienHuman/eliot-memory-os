//! Receipt-driven release, expiry, reconciliation, cancellation and the legacy
//! compatibility disposition for the admission-reservation saga
//! (#1678 W7, REQ8, REQ10; A10, A12).
//!
//! Stage, admit and activate are owned by `admission_reservation_stage.rs`.
//! This module owns everything that takes a reservation OUT of that journey:
//! the receipt-backed release, the receipt-backed expiry, the durable move to
//! `RECONCILING`, the three-way cancellation routing, and the explicit
//! compatibility disposition of a legacy generic `AdmissionReservation`
//! operational row.
//!
//! Every one of those is exactly one transition through the one existing
//! [`OperationalRecoveryStore`] owner. None of them adds a state, a table, a
//! timer, a digest scheme or an in-memory stand-in.
//!
//! # What the spec requires of this half
//!
//! - **I14.20** — "Release, expiry and recovery reuse the same reservation
//!   identity and produce a receipt; an active reservation attached to a
//!   nonterminal attempt cannot be expired as cleanup." The reservation identity
//!   is therefore never re-derived here: each owner transitions the row the
//!   caller named, and the durable snapshot it returns is the receipt-backed
//!   readback of that same identity.
//! - **#1678 section 8** — "A staged inactive reservation may expire or release
//!   only through one exact owner transition with disposition evidence", and
//!   "An active reservation attached to a nonterminal or unknown-effect attempt
//!   cannot be removed by generic TTL cleanup." Expiry therefore takes the
//!   attempt's disposition as an explicit typed input
//!   ([`AdmissionReservationAttemptDisposition`]) and refuses anything that is
//!   not a proven terminal/no-attempt disposition *before* any store access, and
//!   it then refuses an `ACTIVE` durable row on its own authority.
//! - **I14.20:94-96** — `ACTIVE → RELEASED | RECONCILING` are required edges, so
//!   the typed owner's transition table accepts an `ACTIVE` row as the source of
//!   a release or a reconciliation. [`release_admission_reservation`] is
//!   therefore the path that takes an active reservation to `RELEASED`, and
//!   [`reconcile_admission_reservation`] the one that hands it to recovery. I14.20:99
//!   keeps expiry narrower than both, and that asymmetry is enforced twice: the
//!   owner's table has no `ACTIVE → EXPIRED` edge, and
//!   [`expire_admission_reservation`] refuses an `ACTIVE` row before the write.
//! - **#1678 section 8** — "Cancellation before canonical commit, after
//!   canonical commit but before activation, and after activation are different
//!   cuts with different evidence. Do not flatten them into one delete
//!   operation." [`cancel_admission_reservation`] derives the cut from the
//!   durable row, refuses a caller-claimed cut the row does not prove, retains
//!   the owner-declared reason for that exact cut, and refuses the
//!   after-activation cut — which is a release the owning execution/recovery
//!   path must make through [`release_admission_reservation`], not a saga
//!   cancellation. There is no second state machine and no second delete path.
//! - **#1678 section 8** — "Release active claims only after the owning
//!   execution/recovery path proves the applicable terminal/cleanup
//!   disposition. Unknown process/provider effect, live descendants, uncertain
//!   cleanup or lost terminal receipt keeps the reservation active/reconciling
//!   and continues to exclude overlapping work." That is why the two edges out
//!   of `ACTIVE` are not self-service: a release keeps the terminal/recovery
//!   evidence on the row, and a reconcile keeps excluding overlapping work
//!   while it is `RECONCILING`.
//! - **#1678 A10** — the transition retains the exact terminal or recovery
//!   evidence and charges/releases capacity once. The cross-check below
//!   compares the echoed row BY VALUE against the durable row this call read, so
//!   a disposition can never drop, rewrite or substitute the claims, the
//!   retained canonical commit, or either owner receipt.
//! - **#1678 A12** — "Legacy reservation records receive an explicit
//!   migration/quarantine/refusal disposition and never silently become
//!   active." [`disposition_admission_reservation_row`] is the only entry point
//!   for a durable `AdmissionReservation` row that does not carry the current
//!   typed `AdmissionReservationRecord`, and it never returns authority.
//! - **REQ10 / I14.6** — "Crash/retry reuses the same reservation identity;
//!   release/expiry is receipted and cannot cancel a running attempt silently."
//!   These owners hold no capacity model and no attempt history: they transition
//!   the row the caller already owns and leave every retained claim and
//!   reference exactly as it was recorded.
//!
//! # The shape every owner follows
//!
//! `validate the request and the durable row` → `one typed store call` →
//! `cross-check the store's echoed row BY VALUE` → `read the same identity
//! back`. The typed store call is where CAS, epoch, fence, source-state and
//! same-identity replay are decided, so none of them is re-decided here; what
//! this module adds is the pre-write validation of the request and the
//! post-write comparison of what the store persisted against the row this call
//! actually read.

use crate::{
    AdmissionReservationDisposition, AdmissionReservationSnapshot, AdmissionReservationState,
    OpaqueLabel, OperationIdentity, OperationalCurrentRecoveryEntry, OperationalPhase,
    OperationalRecoveryStore, OrsError,
};

/// The owning execution/recovery path's disposition of the attempt an
/// `ACTIVE` reservation is attached to (#1678 W7, REQ8, A9/A10).
///
/// This is an explicit typed INPUT to
/// [`expire_admission_reservation`] and is never inferred by this owner. I14.20:99
/// fixes the rule it encodes: "an active reservation attached to a nonterminal
/// attempt cannot be expired as cleanup", and #1678 section 8 extends it to an
/// "unknown-effect attempt". It is necessary but NOT sufficient: an `ACTIVE`
/// durable row is refused by expiry on its own authority as well, so no
/// disposition here — including [`Self::NotAttached`] — can expire an activated
/// reservation. Disposing of one is [`release_admission_reservation`]'s path.
///
/// ORS reads no attempt execution state, because the reservation row holds
/// none: the durable evidence for the disposition travels as the disposition's
/// own `AdmissionReservationClaimRef`, the same way every other claim reference
/// on this record does. A caller therefore cannot reach expiry by asserting
/// that an attempt is finished; it must present the terminal or cleanup evidence
/// reference with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionReservationAttemptDisposition {
    /// No attempt was ever activated against this reservation, so no effect
    /// exists that a cleanup could disturb. The durable row decides whether
    /// that is true: an `ACTIVE` row proves an attempt WAS attached, whatever
    /// this input claims.
    NotAttached,
    /// The owning execution/recovery path proved the attempt's terminal
    /// disposition and completed its cleanup. That proof is the disposition's
    /// evidence reference.
    Terminal,
    /// The attempt is still live, or dispatch was not yet handed off.
    Nonterminal,
    /// Process/provider effect, live descendants, cleanup completeness or the
    /// terminal receipt itself is unknown.
    UnknownEffect,
}

impl AdmissionReservationAttemptDisposition {
    /// Whether this disposition proves the attached attempt can no longer hold
    /// the reservation's claims, so a TTL cleanup may remove them.
    pub const fn permits_expiry(self) -> bool {
        matches!(self, Self::NotAttached | Self::Terminal)
    }
}

/// Which cancellation cut a caller is disposing of (#1678 section 8).
///
/// The three cuts are separate dispositions with separate evidence, not one
/// delete operation spelled three ways. [`cancel_admission_reservation`] accepts
/// a cut, DERIVES the cut the durable row actually proves, and refuses any cut
/// the row does not prove.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionReservationCancellationCut {
    /// No canonical admission has committed for this saga identity: the
    /// reservation is still `STAGED_INACTIVE` and carries no canonical
    /// admission or activation receipt.
    BeforeCanonicalCommit,
    /// The canonical owner committed the `ADMITTED` decision and it is
    /// retained on the row, but this reservation never activated.
    AfterCanonicalCommitBeforeActivation,
    /// The reservation activated, so its attempt may be live and its claims
    /// may still be in use. This cut is distinct precisely because it is NOT a
    /// saga cancellation: I14.20:96 routes an activated reservation to
    /// `RELEASED` or `RECONCILING` through the owning execution/recovery path
    /// (see [`release_admission_reservation`]), never through this owner, and it
    /// is never expired at all (I14.20:99).
    AfterActivation,
}

impl AdmissionReservationCancellationCut {
    /// Owner-declared disposition reason retained by a cancelled row.
    ///
    /// This closed vocabulary is what keeps the cuts from flattening into one
    /// another: the reason a released row retains names the exact cut that was
    /// proven, so a later readback can tell a pre-commit cancellation from a
    /// post-commit one without re-deriving anything. The owner refuses a
    /// disposition whose reason does not name its cut.
    pub const fn disposition_reason(self) -> &'static str {
        match self {
            Self::BeforeCanonicalCommit => "cancel-before-canonical-commit",
            Self::AfterCanonicalCommitBeforeActivation => {
                "cancel-after-canonical-commit-before-activation"
            }
            Self::AfterActivation => "cancel-after-activation",
        }
    }
}

/// The lifecycle target one receipt-backed disposition transitions to.
///
/// This is the same selection the store's own private transition spec makes;
/// it exists only so the identical validate → store call → BY VALUE cross-check
/// → readback sequence is written once instead of once per target. It is not a
/// state machine and it is private: no caller can reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispositionTarget {
    /// `RELEASED`.
    Released,
    /// `EXPIRED`.
    Expired,
    /// `RECONCILING`.
    Reconciling,
}

impl DispositionTarget {
    /// The typed lifecycle state this target commits.
    const fn state(self) -> AdmissionReservationState {
        match self {
            Self::Released => AdmissionReservationState::Released,
            Self::Expired => AdmissionReservationState::Expired,
            Self::Reconciling => AdmissionReservationState::Reconciling,
        }
    }

    /// Performs the one typed store transition for this target.
    fn apply<S: OperationalRecoveryStore + ?Sized>(
        self,
        store: &S,
        disposition: AdmissionReservationDisposition,
    ) -> Result<AdmissionReservationSnapshot, OrsError> {
        match self {
            Self::Released => store.release_kernel_admission_reservation(disposition),
            Self::Expired => store.expire_kernel_admission_reservation(disposition),
            Self::Reconciling => store.reconcile_kernel_admission_reservation(disposition),
        }
    }
}

/// Releases the exact reservation with its receipt-backed disposition evidence.
///
/// Spec: #1678 section 8 — "A staged inactive reservation may expire or release
/// only through one exact owner transition with disposition evidence." I14.20 —
/// "Release, expiry and recovery reuse the same reservation identity and
/// produce a receipt." I14.20:96 — `ACTIVE → RELEASED`. I14.6 — "release/expiry
/// is receipted and cannot cancel a running attempt silently."
///
/// This is one exact owner transition to `RELEASED` through
/// [`OperationalRecoveryStore::release_kernel_admission_reservation`]. It
/// validates the request and the durable row, calls the typed owner, compares
/// the store's echoed row BY VALUE against both, and reads the same reservation
/// identity back out of the owner before returning it.
///
/// An `ACTIVE` row is a legal source here: this is the path that takes an
/// active reservation to `RELEASED`, so the owning execution/recovery path can
/// discharge its claims once it has proven the applicable terminal/cleanup
/// disposition and retained that evidence on the row. I14.6's "cannot cancel a
/// running attempt silently" still holds — the transition is receipted, the
/// reason and evidence travel with it, and I14.20:99 keeps it out of the expiry
/// path entirely, so no generic TTL cleanup can reach an active reservation
/// through this call either.
///
/// Claims, the retained canonical commit and both owner receipts are carried
/// through unchanged, so the released row still holds the exact terminal or
/// recovery evidence (A10) and the capacity this reservation charged is released
/// exactly once. Nothing is provisioned, launched or deleted here.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when the request is incomplete, invalid or
/// names a blank identity; [`OrsError::ReservationNotFound`] when no reservation
/// exists under the named identity; [`OrsError::InvalidTransition`] when the
/// durable row is already released or expired, i.e. in no legal source state
/// (I14.20:94-96 gives `STAGED_INACTIVE`, `RECONCILING` and `ACTIVE` — never
/// `RELEASED` or `EXPIRED` — as a disposition source);
/// [`OrsError::IntegrityProblem`] when the store's echoed row or the readback
/// does not carry the facts this call validated; and the store's own typed
/// errors otherwise — [`OrsError::DuplicateConflict`] for a stale expected ORS
/// receipt or a same-identity changed-content request, [`OrsError::FenceMismatch`]
/// for a foreign epoch or stale fence, [`OrsError::InvalidExpiry`] when the
/// transition time precedes the durable row's last update.
pub fn release_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    disposition: &AdmissionReservationDisposition,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    apply_receipt_backed_disposition(store, disposition, DispositionTarget::Released)
}

/// Expires the exact reservation, refusing generic TTL cleanup of a live
/// attempt.
///
/// Spec: #1678 section 8 — "A staged inactive reservation may expire or release
/// only through one exact owner transition with disposition evidence" and "An
/// active reservation attached to a nonterminal or unknown-effect attempt cannot
/// be removed by generic TTL cleanup." I14.20:99 — "an active reservation
/// attached to a nonterminal attempt cannot be expired as cleanup."
///
/// This is one exact owner transition to `EXPIRED` through
/// [`OperationalRecoveryStore::expire_kernel_admission_reservation`], reached
/// only when `attempt` proves that no attempt can still hold the reservation's
/// claims ([`AdmissionReservationAttemptDisposition::permits_expiry`]). A
/// nonterminal or unknown-effect attempt is refused with
/// [`OrsError::UnsafeExpiry`] before any store access at all, so no generic
/// cleanup loop can reach the write. An `ACTIVE` durable row is then refused on
/// its own authority, also with [`OrsError::UnsafeExpiry`]: a caller cannot reach
/// expiry by asserting [`AdmissionReservationAttemptDisposition::NotAttached`]
/// against a row that already holds an activation receipt. That refusal is
/// enforced a third time, at the typed owner's own transition table, which has no
/// `ACTIVE → EXPIRED` edge (I14.20:94-96). An active reservation is therefore
/// only ever disposed of through [`release_admission_reservation`], or parked at
/// `RECONCILING` through [`reconcile_admission_reservation`], and keeps
/// excluding overlapping work until then.
///
/// The declared expiry boundary is re-checked against the durable row before
/// the write, and the terminal/cleanup evidence travels as the disposition's
/// own `AdmissionReservationClaimRef` and is compared BY VALUE on the echoed row
/// (A10).
///
/// # Errors
///
/// Returns [`OrsError::UnsafeExpiry`] when the attempt is
/// [`AdmissionReservationAttemptDisposition::Nonterminal`] or
/// [`AdmissionReservationAttemptDisposition::UnknownEffect`], and when the
/// durable row is `ACTIVE` (I14.20:99); [`OrsError::InvalidField`] when the
/// request is incomplete or invalid; [`OrsError::ReservationNotFound`] when no
/// reservation exists under the named identity; [`OrsError::InvalidExpiry`] when
/// the observed time has not reached the durable row's `expires_at_ms`;
/// [`OrsError::InvalidTransition`] when the durable row is in no legal source
/// state; [`OrsError::IntegrityProblem`] when the echoed row or readback does not
/// carry the validated facts; and the store's own typed errors otherwise.
pub fn expire_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    attempt: AdmissionReservationAttemptDisposition,
    disposition: &AdmissionReservationDisposition,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    // Two independent refusals, both before the expiry write: the caller's own
    // typed statement, and the durable row itself. A TTL sweep cannot present a
    // terminal disposition it does not hold, and — because I14.20:99 forbids
    // expiring an active reservation as cleanup — it cannot reach the expiry
    // write for a live attempt even by asserting `NotAttached`.
    if !attempt.permits_expiry() {
        return Err(OrsError::UnsafeExpiry);
    }
    let current = store
        .load_kernel_admission_reservation(&disposition.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    if current.record().state == AdmissionReservationState::Active {
        return Err(OrsError::UnsafeExpiry);
    }
    apply_receipt_backed_disposition(store, disposition, DispositionTarget::Expired)
}

/// Moves the exact reservation to `RECONCILING` with its receipt-backed
/// evidence, without disposing of it.
///
/// Spec: I14.21 — "if unknown → pause Ordering Scope, preserve operation and
/// open Problem State; Human/Doctor chooses evidence-backed reconciliation; no
/// blind duplicate effect." I14.20 — "`RECONCILING` cannot create a new effect."
/// I14.20:96 — `ACTIVE → RECONCILING`, which is what an unknown effect on an
/// activated reservation must reach. #1678 section 5 — a missing, unavailable,
/// inconclusive or conflicting outcome keeps the reservation
/// inactive/reconciling and blocks launch.
///
/// This is the durable move used after a possible canonical commit, once the
/// owner's receipt readback has classified the outcome as unknown, and after an
/// unknown effect on an activation. It is one exact transition to `RECONCILING`
/// through
/// [`OperationalRecoveryStore::reconcile_kernel_admission_reservation`], it
/// retains the evidence it is given, and it neither releases capacity nor
/// admits, activates, provisions or launches anything. Because the row is
/// `RECONCILING` afterwards, it keeps excluding overlapping work while it waits
/// for the evidence-backed decision.
///
/// # Errors
///
/// The same typed set as [`release_admission_reservation`]; this target carries
/// no expiry-boundary requirement.
pub fn reconcile_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    disposition: &AdmissionReservationDisposition,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    apply_receipt_backed_disposition(store, disposition, DispositionTarget::Reconciling)
}

/// Cancels the exact reservation through the cut the caller names — and only
/// when the durable row proves that exact cut.
///
/// Spec: #1678 section 8 — "Cancellation before canonical commit, after
/// canonical commit but before activation, and after activation are different
/// cuts with different evidence. Do not flatten them into one delete
/// operation." I14.6 — "release/expiry is receipted and cannot cancel a running
/// attempt silently."
///
/// The three cuts are told apart by the durable row, not by the caller:
///
/// - [`AdmissionReservationCancellationCut::BeforeCanonicalCommit`] requires a
///   row that carries no canonical admission and no activation receipt, so
///   nothing canonical exists to reconcile;
/// - [`AdmissionReservationCancellationCut::AfterCanonicalCommitBeforeActivation`]
///   requires the retained canonical `ADMITTED` commit to be on the row and no
///   activation receipt, so the commit is preserved as evidence on the released
///   row instead of being flattened away;
/// - [`AdmissionReservationCancellationCut::AfterActivation`] is REFUSED, and
///   the durable row — not this owner — is what proves it: an `ACTIVE` row
///   carries an activation receipt. The cut is distinct from the two above
///   because an activated reservation is not a saga to unwind, and I14.20:96
///   gives it a different, narrower exit than "cancel": it can only be
///   `RELEASED` by the owning execution/recovery path through
///   [`release_admission_reservation`], or parked at `RECONCILING` through
///   [`reconcile_admission_reservation`], and never `EXPIRED` (I14.20:99). Its
///   claims stay reserved until that path proves a terminal disposition, so
///   nothing here can cancel a live attempt silently (I14.6).
///
/// `disposition.reason` must be the owner-declared reason for `cut`
/// ([`AdmissionReservationCancellationCut::disposition_reason`]), so the
/// durable row always names the cut it was released under. A released cut is one
/// exact `RELEASED` transition, so capacity is released once and the retained
/// evidence survives on the row (A10).
///
/// # Errors
///
/// Returns [`OrsError::ReconciliationMismatch`] when the durable row proves a
/// different cut than the caller claimed; [`OrsError::InvalidField`] when the
/// disposition reason does not name the claimed cut; [`OrsError::InvalidTransition`]
/// for the after-activation cut and for a row that is already released or
/// expired; [`OrsError::ReservationNotFound`] when no reservation exists under
/// the named identity; plus the same integrity and store errors as
/// [`release_admission_reservation`].
pub fn cancel_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    cut: AdmissionReservationCancellationCut,
    disposition: &AdmissionReservationDisposition,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    // A cancelled row always retains the reason that names its own cut, so the
    // three cuts stay distinguishable on the durable record.
    if disposition.reason.as_str() != cut.disposition_reason() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_cancellation.reason",
            reason: "cancellation must retain the owner-declared reason for its cut",
        });
    }
    let current = store
        .load_kernel_admission_reservation(&disposition.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    let record = current.record();
    record.validate()?;
    if record.reservation_id != disposition.reservation_id {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the loaded row does not carry the cancelled reservation identity".to_owned(),
        });
    }
    if matches!(
        record.state,
        AdmissionReservationState::Released | AdmissionReservationState::Expired
    ) {
        return Err(OrsError::InvalidTransition);
    }
    // The cut is derived from what the row durably holds, and only the exact
    // marker of each cut decides it. An activation receipt is the exact marker of
    // "after activation"; the retained canonical commit is the exact marker of
    // "committed but not activated", and it is retained on `RECONCILING` as well
    // as `STAGED_INACTIVE`, so a possible-commit cut is classified here too
    // rather than being flattened into "before commit".
    let proven = if record.activation_receipt.is_some() {
        AdmissionReservationCancellationCut::AfterActivation
    } else if record.canonical_admission.is_some() || record.canonical_admission_receipt.is_some() {
        AdmissionReservationCancellationCut::AfterCanonicalCommitBeforeActivation
    } else {
        AdmissionReservationCancellationCut::BeforeCanonicalCommit
    };
    // The after-activation cut is refused whichever cut the caller claimed. The
    // durable row proves it — an activated row carries an activation receipt,
    // and `ACTIVE` is durably only ever moved by the owning
    // execution/recovery path (I14.20:96) — so an activated reservation's
    // attempt may still be live and its claims stay reserved until that path
    // proves a terminal disposition and releases it.
    if proven == AdmissionReservationCancellationCut::AfterActivation {
        return Err(OrsError::InvalidTransition);
    }
    if proven != cut {
        return Err(OrsError::ReconciliationMismatch);
    }
    apply_receipt_backed_disposition(store, disposition, DispositionTarget::Released)
}

/// The explicit compatibility disposition of one durable `AdmissionReservation`
/// operational row (#1678 A12).
///
/// A12 requires that a legacy record "receive an explicit
/// migration/quarantine/refusal disposition and never silently become active",
/// and #1678 section 2 requires that legacy generic
/// `AdmissionReservation`/activation/release rows "not be silently deserialized
/// as the stronger current typed owner record" nor "retain two writable
/// reservation authorities". These variants are that disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionReservationRowDisposition {
    /// The row already carries the current typed
    /// `AdmissionReservationRecord`: it is under the typed owner, and its
    /// authority is exactly what its own state and the launch-prerequisite
    /// verifier say — never more.
    ///
    /// The snapshot is boxed so this disposition stays small: the two legacy
    /// variants carry only identities, a phase, a digest and a reason, so an
    /// unboxed snapshot would make every quarantine/refusal result carry ~1.4 KB
    /// it never uses. `AdmissionReservationSnapshot` is a single owner readback
    /// that consumers immediately dereference, so the indirection costs one
    /// pointer and changes nothing they do.
    Migrated {
        /// Exact typed owner record and store-issued receipt read back under the
        /// row's identity.
        snapshot: Box<AdmissionReservationSnapshot>,
    },
    /// The row carries only the retired opaque operational-input payload. It is
    /// retained as evidence, is never deserialized into the typed record, and
    /// can never serve as a reservation. It is also never adopted in place: ORS
    /// offers no adoption write path, because the typed stage refuses a
    /// reservation identity that already has any durable row, so a legacy row
    /// can only be quarantined here.
    Quarantined {
        /// Stable reservation identity the legacy row was keyed under.
        reservation_id: OperationIdentity,
        /// ORS mutation identity the legacy row last recorded.
        record_id: OperationIdentity,
        /// Operational phase the legacy row recorded.
        phase: OperationalPhase,
        /// Digest of the exact legacy payload bytes, retained as evidence.
        payload_sha256: String,
    },
    /// The legacy row recorded an authority-bearing phase that its retired
    /// opaque payload can never prove. It is refused rather than quarantined so
    /// it can never be read as reservation authority, and the refusal is the
    /// disposition: nothing here repairs, rewrites or migrates it.
    Refused {
        /// Stable reservation identity the legacy row was keyed under.
        reservation_id: OperationIdentity,
        /// ORS mutation identity the legacy row last recorded.
        record_id: OperationIdentity,
        /// Operational phase the legacy row recorded.
        phase: OperationalPhase,
        /// Digest of the exact legacy payload bytes, retained as evidence.
        payload_sha256: String,
        /// Bounded operator-visible reason for the refusal.
        reason: OpaqueLabel,
    },
}

/// Classifies one durable `AdmissionReservation` operational row and returns its
/// explicit compatibility disposition (#1678 A12).
///
/// `entry` is the owner's own payload-free summary of the row, as produced by
/// [`OperationalRecoveryStore::scan_operational_current`], so a restart pass
/// already enumerating operational rows needs no second read path and no second
/// table. The typed read is what decides the class: a row that carries the
/// current typed record is [`AdmissionReservationRowDisposition::Migrated`], and
/// a row the typed owner refuses — because it holds the retired opaque
/// operational-input payload instead of a typed record — is quarantined, or
/// refused when it claims an authority-bearing phase.
///
/// Two properties hold for every outcome. First, no outcome is ever authority:
/// the only snapshot this function returns is the typed owner's own readback of
/// a current typed record, and a legacy row yields no snapshot at all. Second,
/// the two halves are cross-checked BY VALUE against each other — the typed
/// readback's reservation identity, current ORS operation identity and receipt
/// subject must agree with the enumerated row — so one owner's read cannot be
/// passed off as another's.
///
/// Which reservation key a row occupies is decided by the typed owner, not
/// here: `load_kernel_admission_reservation` resolves the row under the
/// reservation kind, so a summary of a different operational kind is reported
/// as [`OrsError::ReservationNotFound`] instead of being classified.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no durable
/// `AdmissionReservation` row exists under the summary's subject identity, and
/// [`OrsError::IntegrityProblem`] when the typed readback and the enumerated
/// summary disagree. Every other failure keeps its own typed variant.
pub fn disposition_admission_reservation_row<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    entry: &OperationalCurrentRecoveryEntry,
) -> Result<AdmissionReservationRowDisposition, OrsError> {
    match store.load_kernel_admission_reservation(&entry.subject_id) {
        Ok(Some(snapshot)) => {
            if snapshot.record().reservation_id != entry.subject_id
                || snapshot.record().operation_id != entry.record_id
                || snapshot.receipt().subject_id() != &entry.subject_id
            {
                return Err(OrsError::IntegrityProblem {
                    record_type: "admission_reservation",
                    reason: "the typed reservation does not match its enumerated operational row"
                        .to_owned(),
                });
            }
            Ok(AdmissionReservationRowDisposition::Migrated {
                snapshot: Box::new(snapshot),
            })
        }
        Ok(None) => Err(OrsError::ReservationNotFound),
        // A durable reservation row the typed owner refuses is the retired
        // opaque operational-input shape, whatever the specific refusal was: the
        // row carries no current typed record, so the typed read can never serve
        // it as a reservation. Classifying it here keeps that fail-closed — it is
        // quarantined or refused, never adopted — and it is never deserialized
        // into a typed record. Every other failure stays typed and propagating.
        Err(OrsError::IntegrityProblem { .. }) => {
            if entry.phase == OperationalPhase::Active {
                return Ok(AdmissionReservationRowDisposition::Refused {
                    reservation_id: entry.subject_id.clone(),
                    record_id: entry.record_id.clone(),
                    phase: entry.phase,
                    payload_sha256: entry.payload_sha256.clone(),
                    reason: OpaqueLabel::new(
                        "legacy admission reservation row claims an active phase its opaque \
                         payload cannot prove",
                    )?,
                });
            }
            Ok(AdmissionReservationRowDisposition::Quarantined {
                reservation_id: entry.subject_id.clone(),
                record_id: entry.record_id.clone(),
                phase: entry.phase,
                payload_sha256: entry.payload_sha256.clone(),
            })
        }
        Err(error) => Err(error),
    }
}

/// Performs one receipt-backed disposition: validate, call the typed owner once,
/// compare the echoed row BY VALUE, then read the same identity back.
fn apply_receipt_backed_disposition<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    disposition: &AdmissionReservationDisposition,
    target: DispositionTarget,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    validate_disposition_request(disposition)?;

    // The exact row this transition will move, read before the write. The CAS
    // precondition, the epoch and the fence are enforced by the typed owner
    // against the row it holds at write time; what this read adds is the
    // candidate the echoed row is later compared against.
    let current = store
        .load_kernel_admission_reservation(&disposition.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    let observed = current.record();
    observed.validate()?;
    if observed.reservation_id != disposition.reservation_id {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the loaded row does not carry the dispositioned reservation identity"
                .to_owned(),
        });
    }
    // A row already at the target is left to the typed owner, which compares the
    // whole persisted request and so distinguishes an exact replay from a
    // same-identity changed-content request. Only a row in no legal source
    // state at all is refused here, before the write, and the set is exactly the
    // store's own: `ACTIVE` is a legal source for `RELEASED` and `RECONCILING`
    // (I14.20:96) and never for `EXPIRED` (I14.20:99).
    let legal_source = matches!(
        observed.state,
        AdmissionReservationState::StagedInactive | AdmissionReservationState::Reconciling
    ) || (observed.state == AdmissionReservationState::Active
        && target != DispositionTarget::Expired);
    if observed.state != target.state() && !legal_source {
        return Err(OrsError::InvalidTransition);
    }
    // The declared expiry boundary is re-checked against the durable row, so an
    // early expiry never reaches the write.
    if target == DispositionTarget::Expired && disposition.now_ms < observed.expires_at_ms {
        return Err(OrsError::InvalidExpiry);
    }

    let persisted = target.apply(store, disposition.clone())?;

    // The store's own echoed row is cross-checked BY VALUE against the request
    // validated above and the durable row read before the write, so "released"
    // means the persisted row carries exactly the evidence that was checked and
    // still carries every claim and receipt it held.
    let echoed = persisted.record();
    echoed.validate()?;
    if echoed.state != target.state()
        || echoed.reservation_id != disposition.reservation_id
        || echoed.operation_id != disposition.operation_id
        || echoed.updated_at_ms != disposition.now_ms
        || echoed.created_at_ms != observed.created_at_ms
        || echoed.disposition_reason.as_ref() != Some(&disposition.reason)
        || echoed.disposition_evidence.as_ref() != Some(&disposition.evidence)
        || echoed.authority_epoch != disposition.authority_epoch
        || echoed.state_fence != disposition.state_fence
        || echoed.claims != observed.claims
        || echoed.work_item_id != observed.work_item_id
        || echoed.proposed_attempt_id != observed.proposed_attempt_id
        || echoed.canonical_admission != observed.canonical_admission
        || echoed.canonical_admission_receipt != observed.canonical_admission_receipt
        || echoed.activation_receipt != observed.activation_receipt
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the dispositioned row does not carry the evidence this call validated"
                .to_owned(),
        });
    }

    // Durably read the SAME identity back. This is the receipt-producing
    // readback the caller returns: a replay after a lost response lands on the
    // identical row with the identical receipt, and this read releases nothing,
    // launches nothing and mutates nothing.
    let readback = store
        .load_kernel_admission_reservation(&disposition.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    if readback != persisted {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "readback returned a different dispositioned reservation".to_owned(),
        });
    }
    Ok(readback)
}

/// Validates one receipt-backed disposition request before any write.
///
/// The evidence is a digest-bound owner reference and the immutable authority
/// binding is validated with the existing epoch/fence validators against the
/// ORIGINAL recorded fence. The reason is an owner-held opaque label, so it is
/// shape-checked as one rather than interpreted.
fn validate_disposition_request(
    disposition: &AdmissionReservationDisposition,
) -> Result<(), OrsError> {
    if disposition.now_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_disposition.now_ms",
            reason: "disposition time must be greater than zero",
        });
    }
    if disposition.reservation_id.as_str().trim().is_empty()
        || disposition.operation_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_disposition.identity",
            reason: "reservation and transition operation identities must be non-blank",
        });
    }
    // The evidence content is compared, not merely present: this validates the
    // owner reference's shape and its exact claim digest, and the same value is
    // compared BY VALUE against the persisted row after the write.
    disposition.evidence.validate()?;
    disposition.authority_epoch.validate()?;
    disposition
        .state_fence
        .validate_against_lineage(&disposition.authority_epoch)?;
    Ok(())
}
