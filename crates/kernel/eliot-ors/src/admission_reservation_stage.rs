//! One frozen operation/identity model for the admission-reservation saga
//! (#1678 REQ1, REQ2, REQ3, REQ6; W1, W2, W4, W5; A1, A2, A4, A7).
//!
//! This module is the Kernel-side coordinator contract for the durable
//! reservation lifecycle. It holds the three halves of the saga that are
//! purely about the ORS reservation row itself:
//!
//! - the **stage** half ([`stage_admission_reservation_inactive`]) produces a
//!   durable, immutable `StagedInactive` reservation BEFORE any semantic
//!   admission effect;
//! - the **admit** half ([`prove_canonical_admission_for_reservation`]) proves the
//!   canonical owner's committed `ADMITTED` decision and its launch outbox belong
//!   to that same reservation, read back and compared BY VALUE;
//! - the **activate** half ([`activate_admission_reservation_from_owner_evidence`])
//!   moves that same reservation to `Active` only from owner evidence.
//!
//! None of the three halves creates a process, provider or environment effect.
//! Staging reserves/account charges only; admitting commits canonical state and
//! the launch outbox; activation is still not a process start. All three go
//! through the one typed [`OperationalRecoveryStore`] owner, read the same
//! reservation identity back, and reuse the existing identity/validator types
//! rather than minting parallel ones.
//!
//! # What the admit half is allowed to do
//!
//! I14.6 fixes the order: "ORS first stages inactive claims; canonical state
//! records `ADMITTED` and the launch outbox; Kernel then activates the exact
//! reservation." The admit half is the middle step and it is deliberately NOT a
//! write path. The canonical owner commits the `ADMITTED` decision, its
//! admitted attempt identity and the launch outbox in ONE store transaction
//! under ONE operation identity; this half only:
//!
//! 1. re-reads the exact staged reservation and proves it is the row the caller
//!    named, under the caller's current Authority Epoch lineage and State Fence;
//! 2. proves the exact launch outbox row for that operation was committed by
//!    the same owner ([`verify_launch_outbox_intent`]);
//! 3. builds the retained commit record from the canonical owner's OWN
//!    `WriteReceipt` ([`canonical_admission_from_owner_commit`]) — never
//!    fabricated in Kernel, never inferred from a successful transport call;
//! 4. hands that retained commit to the activate half, which is what makes it
//!    durable on the row, so a restart reads the committed decision back
//!    instead of re-asking the canonical owner.
//!
//! The commit is retained with the ACTIVE row rather than the staged one,
//! because `AdmissionReservationRecord::validate` refuses a `StagedInactive`
//! row carrying any admission or activation receipt: a staged reservation is
//! inert (I14.20) and must never hold admission authority.
//!
//! A lost response, a timeout or a possible commit is NOT resolved here and
//! never mints a second admission: the caller keeps the ORIGINAL operation
//! identity and hands the SAME operation to [`reconcile_canonical_admission`],
//! which resolves it through the owner's receipt readback. A missing,
//! unavailable or inconclusive answer leaves the reservation inactive and blocks
//! launch, per I5.19 ("an unknown commit is never assumed to be a non-commit").
//!
//! # What the stage half is allowed to do
//!
//! The stage half is exactly:
//!
//! 1. derive one **stable, re-derivable** reservation identity
//!    ([`admission_reservation_identity`]) and one proposed-attempt identity
//!    ([`proposed_attempt_identity`]);
//! 2. stage one `StagedInactive` record carrying the complete immutable
//!    resource / lane / environment / effect / quota / State Fence / Authority
//!    Epoch claims through the existing typed ORS owner;
//! 3. durably read that same reservation identity back.
//!
//! It does not admit, release, expire or reconcile anything. Those are the
//! canonical-admission and disposition owners.
//!
//! # What the activate half is allowed to do
//!
//! The activate half is exactly one transition:
//!
//! 1. re-read the exact reservation identity and prove it is the
//!    `StagedInactive` (or `Reconciling`) row the caller believes it is, under
//!    the caller's current Authority Epoch lineage and State Fence;
//! 2. check the owner-issued canonical admission receipt and the ORS activation
//!    receipt are both well-formed and distinct;
//! 3. CAS the row to `Active` through the typed owner, and read that same
//!    identity back.
//!
//! It admits nothing, launches nothing, provisions nothing, allocates no
//! environment and fabricates no canonical receipt. The canonical admission
//! receipt arrives as evidence from the canonical owner; this module only
//! refuses to activate without it.
//!
//! # Why the identity is derived, not minted
//!
//! A2 requires that a restart after stage but before canonical admission
//! reloads *the same* reservation ID. A freshly minted UUID per attempt cannot
//! satisfy that, so the identity here is a pure function of immutable inputs
//! that the owner already holds durably. The derivation is deterministic and
//! content-addressed: the same work item, proposed attempt, admission revision,
//! claim set, fence and epoch always produce the same identity, on any
//! process, after any crash. The activation operation identity
//! ([`activation_operation_identity`]) follows the same rule for the same
//! reason: an activation replay after a lost response must reuse the one ORS
//! operation identity rather than mint a second activation (A7).
//!
//! # Why the completeness check is independent
//!
//! A1 requires the staged record to carry the *complete* claim set, and the
//! brief requires that completeness be judged against an INDEPENDENT expected
//! set — never against a copy of the same caller list. [`StagedClaimRole`] is
//! therefore a closed, owner-declared enumeration of the seven roles a staged
//! row must bind, and [`verify_staged_claim_completeness`] walks that closed set
//! to decide completeness. A caller cannot satisfy the check by handing back the
//! same list it was given, because the list is fixed here, in the owner, and a
//! missing role is a typed refusal rather than a shorter loop.
//!
//! Five of those roles are claim references (`AdmissionReservationClaims` carries
//! exactly five) and two — the State Fence and the Authority Epoch — are the
//! authority bindings the record holds alongside its claims. All seven are named
//! here so the completeness decision has one closed denominator to walk; the two
//! authority roles are validated as part of that walk rather than assumed from it.

use eliot_contracts::EpochId;
use eliot_receipts::ReceiptIdentity;
use serde::{Deserialize, Serialize};

use crate::{
    AdmissionReservationActivatedOutcome, AdmissionReservationActivationEvidence,
    AdmissionReservationActivationRequest, AdmissionReservationCanonicalAdmission,
    AdmissionReservationClaimRef, AdmissionReservationClaims, AdmissionReservationRecord,
    AdmissionReservationSnapshot, AdmissionReservationStage, AdmissionReservationState,
    EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, OperationalMutationReceipt,
    OperationalRecoveryStore, OrsError, StateFenceSnapshot, model::sha256_hex,
};

/// One committed canonical `WriteReceipt` as the canonical owner issued it.
///
/// This is the owner's own receipt, carried whole. Every value below is copied
/// verbatim from it — nothing here is recomputed, re-derived, or synthesized in
/// Kernel, and the receipt is not a claim that a transport call returned
/// success: it is the terminal artifact the canonical store created inside the
/// transaction that also committed the `ADMITTED` decision and the launch
/// outbox row. It is validated with the canonical owner's own
/// `WriteReceipt::validate()` against the ORIGINAL recorded value, and its
/// `commit_id` is the store-issued commit identity that the outbox row shares.
pub type CanonicalWriteReceipt = eliot_store_api::WriteReceipt;

/// Derives the owner-issued canonical admission receipt for one committed
/// `ADMITTED` write from the canonical owner's own receipt (#1678 W3, REQ4).
///
/// This is the only way a caller obtains the receipt reference the retained
/// commit carries, and it is never a caller assertion: the reference is the
/// identity of the store-owned reconciliation envelope the canonical owner
/// issued inside the transaction that committed this exact operation
/// ([`eliot_store_api::WriteReceipt::require_reconciliation_envelope`]). A
/// value no owner issued cannot enter the saga here, so Kernel never fabricates
/// this receipt and never infers it from a successful transport response.
///
/// The receipt must be a committed receipt for `operation_id`, and its
/// envelope must pass the owner's own `validate()`, which also binds the
/// envelope to this receipt's operation, idempotency key and State Fence. That
/// binding is the owner's check, not a second comparison scheme here.
///
/// # Errors
///
/// Returns [`OrsError::ReconciliationMismatch`] when the receipt is not a
/// committed receipt for `operation_id`, or when it carries no store-owned
/// reconciliation envelope to derive the reference from. Returns
/// [`OrsError::Contract`] when the owner's own `validate()` refuses the receipt
/// or its envelope.
pub fn canonical_admission_receipt_from_owner_receipt(
    receipt: &CanonicalWriteReceipt,
    operation_id: &OperationIdentity,
) -> Result<ReceiptIdentity, OrsError> {
    receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != operation_id.as_str()
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    let envelope = receipt
        .require_reconciliation_envelope()
        .map_err(|_| OrsError::ReconciliationMismatch)?;
    envelope
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    Ok(envelope.identity.clone())
}

/// Builds the retained canonical-commit record from the owner's own receipt.
///
/// This is the only way a caller obtains an
/// [`AdmissionReservationCanonicalAdmission`], and it takes the canonical
/// owner's `WriteReceipt` for the exact operation — not a copy of some fields,
/// not a caller assertion. Every retained value is read out of that receipt:
/// the operation identity, the idempotency key, the admission-decision and
/// mutation-plan digests, the store-issued `commit_id`, the commit time, and —
/// via [`canonical_admission_receipt_from_owner_receipt`] — the owner-issued
/// admission receipt reference derived from the receipt's own reconciliation
/// envelope. Nothing is defaulted and nothing is caller-supplied, so what the
/// reservation row retains is exactly what the canonical owner committed.
///
/// The commit time is taken from the receipt's own `committed_at` string,
/// which the store issues as Unix milliseconds. A receipt that is not
/// `committed`, or whose `committed_at` is not a positive integer, cannot back
/// an `ADMITTED` decision and is refused here rather than defaulted to the
/// caller's clock.
///
/// # Errors
///
/// Returns [`OrsError::ReconciliationMismatch`] when the receipt does not carry
/// a committed `ADMITTED` decision for a named operation: a non-committed
/// status, an absent commit id, an absent/non-numeric commit time, or a receipt
/// whose operation is not the named one. Returns [`OrsError::Contract`] when
/// the owner's own `validate()` refuses the receipt or its envelope.
pub fn canonical_admission_from_owner_commit(
    receipt: &CanonicalWriteReceipt,
    operation_id: &str,
    launch_outbox_operation_id: &OperationIdentity,
    launch_outbox_id: &str,
) -> Result<AdmissionReservationCanonicalAdmission, OrsError> {
    receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != operation_id
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    let Some(commit_id) = receipt.commit_id.clone() else {
        return Err(OrsError::ReconciliationMismatch);
    };
    let Some(committed_at_marker) = receipt.committed_at.clone() else {
        return Err(OrsError::ReconciliationMismatch);
    };
    // The admission receipt is derived from the owner's own receipt, never
    // accepted from the caller: the operation identity the envelope is derived
    // for is the same named operation this commit is built for.
    let operation_identity =
        OperationIdentity::new(operation_id).map_err(|_| OrsError::InvalidField {
            field: "canonical_admission.operation_id",
            reason: "canonical operation identity must be non-blank",
        })?;
    let admission_receipt =
        canonical_admission_receipt_from_owner_receipt(receipt, &operation_identity)?;
    let retained = AdmissionReservationCanonicalAdmission {
        operation_id: operation_identity,
        idempotency_key: receipt.idempotency_key.clone(),
        admission_digest: receipt.admission_digest.clone(),
        mutation_plan_digest: receipt.mutation_plan_digest.clone(),
        commit_id: commit_id.as_str().to_owned(),
        launch_outbox_operation_id: launch_outbox_operation_id.clone(),
        launch_outbox_id: launch_outbox_id.to_owned(),
        admission_receipt,
        committed_at_marker,
    };
    retained.validate()?;
    Ok(retained)
}

/// Reads the committed launch outbox back and compares it BY VALUE against the
/// evidence the reservation retained (#1678 A3, REQ5).
///
/// A3 requires that the committed outbox entry "is read back before
/// activation; response loss never mints a second admission". The read is the
/// canonical owner's own `WriteReceipt` for the original operation identity —
/// the same artifact the first commit produced — and it is resolved by
/// identity through the existing receipt readback. There is no second read
/// path and no outbox table owned here.
///
/// The comparison is by VALUE, not existence. The readback must agree with the
/// retained evidence on the admission-decision digest, the mutation-plan
/// digest, the commit id, the operation identity, and the commit time. An
/// admitted decision whose committed content does not match the retained
/// evidence is a typed [`OrsError::ReconciliationMismatch`], not a pass: that
/// is the case where the receipt under this operation identity is not the one
/// the reservation was staged against, and activating on it would authorize
/// work from a different commit.
///
/// Absent receipt is likewise a refusal, never a default. Per I5.19 an unknown
/// commit is never assumed to be a non-commit, so a missing receipt leaves the
/// reservation inactive and the launch blocked; the caller retries under the
/// original operation identity rather than admitting again.
///
/// # Errors
///
/// Returns [`OrsError::ReconciliationMismatch`] when the owner has no committed
/// receipt for the retained operation identity, or when the receipt's content
/// disagrees with the retained evidence on any compared field.
pub fn launch_outbox_readback(
    readback: Option<&CanonicalWriteReceipt>,
    retained: &AdmissionReservationCanonicalAdmission,
) -> Result<(), OrsError> {
    let receipt = readback.ok_or(OrsError::ReconciliationMismatch)?;
    receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    retained.validate()?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != retained.operation_id.as_str()
        || receipt.idempotency_key != retained.idempotency_key
        || receipt.admission_digest != retained.admission_digest
        || receipt.mutation_plan_digest != retained.mutation_plan_digest
        || receipt
            .commit_id
            .as_ref()
            .map(eliot_store_api::CommitId::as_str)
            != Some(retained.commit_id.as_str())
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    // The commit marker is compared as the owner recorded it, byte for byte, not
    // as a re-derived instant: a receipt for the same digests under a different
    // commit marker is a different observation of the commit and is refused
    // rather than accepted as "close enough".
    if receipt.committed_at.as_deref() != Some(retained.committed_at_marker.as_str()) {
        return Err(OrsError::ReconciliationMismatch);
    }
    Ok(())
}

/// The canonical owner's committed launch outbox row, as the owner issued it.
///
/// The `outbox_id` is the row identity taken verbatim from the owner's own
/// `WriteReceipt::outbox_refs` — the list the store populated from the
/// outbox rows it created inside the same transaction that issued the receipt.
/// ORS keeps no outbox table, issues no outbox identity, and reads no outbox
/// API: every value here is the canonical owner's own evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalLaunchOutboxIntent {
    /// Outbox row identity, as the store issued it on the receipt.
    pub outbox_id: String,
    /// Operation identity the store committed the row under.
    pub operation_id: String,
}

/// Proves the canonical owner committed the exact launch intent for this
/// operation, and nothing else (#1678 W3/A3).
///
/// A3 requires the launch outbox to be committed "under its original identity"
/// and read back before activation. The proof is the canonical owner's OWN
/// receipt for that operation: `WriteReceipt::outbox_refs` is the store's own
/// enumeration of the outbox rows its transaction created, and exactly one of
/// them is the launch row that store issued under
/// [`eliot_store_api::OutboxIntentKind::Launch`].
///
/// The row is selected by the store's own prefix classifier, never by a
/// caller-supplied id, so an event-projection row can never be adopted as
/// launch authority. The check is also scoped to THIS operation: a receipt
/// whose operation identity is not the one being proven, or which is not a
/// committed receipt at all, proves nothing.
///
/// # Errors
///
/// Returns [`OrsError::ReconciliationMismatch`] when the receipt is not a
/// committed receipt for `operation_id`, or when the owner committed no launch
/// row for it.
pub fn verify_launch_outbox_intent(
    receipt: &CanonicalWriteReceipt,
    operation_id: &OperationIdentity,
) -> Result<CanonicalLaunchOutboxIntent, OrsError> {
    receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        || receipt.operation_id.as_str() != operation_id.as_str()
    {
        return Err(OrsError::ReconciliationMismatch);
    }
    // The store's own launch-row naming is the only spelling accepted, and the
    // row must be one the receipt itself enumerates: a launch row the owner did
    // not record against this operation is not this operation's launch intent.
    let prefix = format!("{}-", eliot_store_api::OutboxIntentKind::Launch.id_prefix());
    let outbox_id = receipt
        .outbox_refs
        .iter()
        .map(eliot_store_api::OutboxId::as_str)
        .find(|outbox_id| outbox_id.starts_with(&prefix))
        .ok_or(OrsError::ReconciliationMismatch)?;
    Ok(CanonicalLaunchOutboxIntent {
        outbox_id: outbox_id.to_owned(),
        operation_id: operation_id.as_str().to_owned(),
    })
}

/// Everything the admit half needs from the canonical owner for one operation.
///
/// The owner's own receipt for the ORIGINAL operation identity is the whole of
/// it, read back by the caller through the owner's receipt readback. The
/// admission receipt reference the retained commit carries is derived from that
/// receipt's own reconciliation envelope by
/// [`canonical_admission_receipt_from_owner_receipt`], never supplied beside
/// it: a caller cannot claim an `ADMITTED` decision by spelling one here, and
/// cannot pair the owner's receipt with a different admission reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalAdmissionCommit {
    /// The canonical owner's `WriteReceipt` for the committed `ADMITTED`
    /// write. This is the owner-issued artifact; the retained record is built
    /// from it verbatim.
    pub receipt: CanonicalWriteReceipt,
}

/// Proves the committed canonical `ADMITTED` decision and its launch outbox
/// belong to one exact staged reservation, and returns the retained commit
/// that reservation will carry once it activates (#1678 W3, REQ4, A3).
///
/// This is the middle of the I14.6 saga. It is deliberately NOT a write path:
/// the `ADMITTED` decision, its admitted attempt identity and the launch outbox
/// were already committed by the canonical owner in its own store transaction,
/// and ORS never mints or fabricates any part of them. The retained commit
/// becomes durable with the ACTIVE row, because
/// [`AdmissionReservationRecord::validate`] refuses a `StagedInactive` row that
/// carries an admission or activation receipt — a staged reservation is inert
/// (I14.20) and must stay free of admission authority.
///
/// What this function does, before anything is written:
///
/// 1. re-reads the exact reservation identity through the typed owner and
///    refuses anything that is not the `StagedInactive` (or `Reconciling`) row
///    the caller named, under the caller's current Authority Epoch lineage and
///    State Fence — a foreign epoch, a stale fence, or a different work
///    item/attempt fails **before** any mutation;
/// 2. proves the store committed the exact launch intent for this operation,
///    selected by the store's own launch-kind naming;
/// 3. builds the retained commit from the canonical owner's OWN `WriteReceipt`,
///    refusing a receipt that is not a committed `ADMITTED` decision for the
///    named operation;
/// 4. returns that retained commit plus the exact ORS receipt the caller must
///    present as the activation CAS precondition, so the activation that
///    follows commits the canonical evidence and the active row together.
///
/// The returned commit is then passed verbatim to
/// [`activate_admission_reservation_from_owner_evidence`], which is what makes
/// it durable. Nothing here activates, launches, provisions or allocates.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no reservation exists under
/// the named identity, [`OrsError::DuplicateConflict`] when the row is not the
/// row the caller described, [`OrsError::FenceMismatch`] on a foreign epoch or
/// stale fence, [`OrsError::InvalidExpiry`] when the declared expiry has already
/// elapsed, and [`OrsError::ReconciliationMismatch`] when the owner's receipt is
/// not a committed `ADMITTED` decision for this operation or the exact launch
/// intent is not proven for it.
#[allow(
    clippy::too_many_arguments,
    reason = "the admit half binds the reservation, work and attempt identities, the canonical operation, the owner's commit evidence, and the caller's current authority and fence; collapsing them would hide which identity each check compares"
)]
pub fn prove_canonical_admission_for_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    reservation_id: &OperationIdentity,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
    operation_id: &OperationIdentity,
    commit: &CanonicalAdmissionCommit,
    authority_epoch: &EpochLineage,
    state_fence: &StateFenceSnapshot,
    now_ms: i64,
) -> Result<ProvenCanonicalAdmission, OrsError> {
    if now_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_admit.now_ms",
            reason: "admit time must be greater than zero",
        });
    }
    if reservation_id.as_str().trim().is_empty()
        || work_item_id.as_str().trim().is_empty()
        || proposed_attempt_id.as_str().trim().is_empty()
        || operation_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_admit.identity",
            reason: "reservation, work item, proposed attempt and operation identities must be non-blank",
        });
    }
    authority_epoch.validate()?;
    state_fence.validate_against_lineage(authority_epoch)?;

    // Pre-mutation identity check: nothing may activate until the durable row,
    // its immutable binding and the caller's current authority all agree.
    let current = store
        .load_kernel_admission_reservation(reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    let staged = current.record();
    staged.validate()?;
    verify_staged_claim_completeness(staged)?;
    if staged.state != AdmissionReservationState::StagedInactive
        && staged.state != AdmissionReservationState::Reconciling
    {
        return Err(OrsError::InvalidTransition);
    }
    if staged.work_item_id != *work_item_id || staged.proposed_attempt_id != *proposed_attempt_id {
        return Err(OrsError::DuplicateConflict);
    }
    if staged.authority_epoch != *authority_epoch || staged.state_fence != *state_fence {
        return Err(OrsError::FenceMismatch);
    }
    if now_ms >= staged.expires_at_ms {
        return Err(OrsError::InvalidExpiry);
    }

    // The launch intent is proven for THIS operation from the owner's own
    // receipt, and the retained commit — including the admission receipt
    // derived from that receipt's own reconciliation envelope — is built from
    // that same owner-issued receipt: never from a Kernel assertion and never
    // inferred from a successful transport call.
    let launch = verify_launch_outbox_intent(&commit.receipt, operation_id)?;
    let retained = canonical_admission_from_owner_commit(
        &commit.receipt,
        operation_id.as_str(),
        operation_id,
        launch.outbox_id.as_str(),
    )?;

    // A reservation that already activated carries the committed decision on its
    // row. That retained copy is compared BY VALUE against this one, so a second
    // or conflicting commit under one saga identity can never be adopted.
    if let Some(existing) = &staged.canonical_admission
        && *existing != retained
    {
        return Err(OrsError::DuplicateConflict);
    }
    Ok(ProvenCanonicalAdmission {
        reservation_id: reservation_id.clone(),
        canonical_admission: retained,
        expected_current_receipt: current.receipt().clone(),
    })
}

/// One proven canonical `ADMITTED` commit, ready to be committed onto the
/// reservation by the activation that follows it.
///
/// This carries no launch authority by itself. `expected_current_receipt` is
/// the exact ORS receipt observed while proving the commit, and is the CAS
/// precondition the activation presents, so the canonical evidence and the
/// resulting active row are committed against the row this proof read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvenCanonicalAdmission {
    /// Reservation identity the commit was proven against.
    pub reservation_id: OperationIdentity,
    /// The canonical owner's committed `ADMITTED` decision and launch outbox
    /// intent, read back and verified BY VALUE.
    pub canonical_admission: AdmissionReservationCanonicalAdmission,
    /// Exact current ORS receipt observed while proving the commit.
    pub expected_current_receipt: OperationalMutationReceipt,
}

/// Resolves the ORIGINAL canonical admission operation after a lost response
/// or restart, and returns whether this saga may proceed to activation
/// (#1678 REQ5).
///
/// This is the reconcile half. It never re-admits: it asks the caller for the
/// owner's readback of the SAME operation identity and applies the I14.21
/// disposition to it. The launch intent is re-proven from that same receipt by
/// [`verify_launch_outbox_intent`] rather than supplied separately, so the
/// caller cannot assert an outbox row the owner's own receipt does not carry.
/// The outcomes are the four the spec fixes:
///
/// - **committed ADMITTED + exact launch intent** — [`CanonicalAdmissionResolution::Committed`]:
///   eligible for activation after current revalidation;
/// - **proven noncommit, lawful same-identity retry** —
///   [`CanonicalAdmissionResolution::ProvenNonCommit`]: the caller may retry only
///   under the existing write policy, under this SAME operation identity;
/// - **rejected / rolled back / terminal** —
///   [`CanonicalAdmissionResolution::TerminalFailure`]: retain the exact terminal
///   evidence and disposition the reservation without launch;
/// - **missing / unavailable / inconclusive / conflicting** —
///   [`CanonicalAdmissionResolution::Unknown`]: keep the reservation inactive or
///   reconciling and block launch.
///
/// An absent receipt is `Unknown`, never a presumed non-commit (I5.19: an
/// unknown commit is never assumed to be a non-commit). A receipt whose content
/// disagrees with the owner's retained evidence is `Unknown`, not a pass: a
/// receipt for a different commit is not proof of this operation.
///
/// # Errors
///
/// Returns [`OrsError::Contract`] when the owner's own `validate()` refuses the
/// presented receipt. Every other condition is a typed resolution value, not an
/// error, because an unknown outcome is a disposition the caller must carry,
/// not a failure of this function.
pub fn reconcile_canonical_admission(
    readback: Option<&CanonicalWriteReceipt>,
    operation_id: &str,
) -> Result<CanonicalAdmissionResolution, OrsError> {
    if operation_id.trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_reconcile.operation_id",
            reason: "canonical operation identity must be non-blank",
        });
    }
    // Missing, unavailable or inconclusive: the outcome is UNKNOWN, never a
    // presumed non-commit. The reservation stays inactive/reconciling and
    // launch is blocked until an evidence-backed disposition arrives.
    let Some(receipt) = readback else {
        return Ok(CanonicalAdmissionResolution::Unknown {
            reason: CanonicalAdmissionUnknownReason::ReceiptAbsent,
        });
    };
    receipt
        .validate()
        .map_err(|error| OrsError::Contract(error.to_string()))?;
    // A receipt for a different operation is not proof of THIS operation.
    if receipt.operation_id.as_str() != operation_id {
        return Ok(CanonicalAdmissionResolution::Unknown {
            reason: CanonicalAdmissionUnknownReason::OperationMismatch,
        });
    }
    let Ok(reconciled_operation) = OperationIdentity::new(operation_id) else {
        return Ok(CanonicalAdmissionResolution::Unknown {
            reason: CanonicalAdmissionUnknownReason::OperationMismatch,
        });
    };
    match receipt.status {
        eliot_store_api::WriteReceiptStatus::Committed => {
            // Committed is eligible for activation only when the exact launch
            // intent for this operation is also proven: a committed `ADMITTED`
            // decision without its launch outbox is not the complete I14.6 step
            // 3, so it stays Unknown rather than becoming activation authority.
            if verify_launch_outbox_intent(receipt, &reconciled_operation).is_err() {
                return Ok(CanonicalAdmissionResolution::Unknown {
                    reason: CanonicalAdmissionUnknownReason::LaunchIntentUnproven,
                });
            }
            Ok(CanonicalAdmissionResolution::Committed)
        }
        eliot_store_api::WriteReceiptStatus::Rejected
        | eliot_store_api::WriteReceiptStatus::Cancelled => {
            // Terminal non-commit. Whether the SAME identity may be retried is
            // decided solely by the owner's resubmission disposition, never by the
            // status name. `Resubmission::None` is the store's own "known rollback,
            // same identity may be retried" classification — the same mapping the
            // canonical owner's commit-recovery classifier applies to these exact
            // fields — so this branch is grounded in the store's disposition and
            // not invented here. Anything else means the store requires a NEW
            // identity, which ends this saga's identity.
            if receipt.resubmission == eliot_store_api::Resubmission::None {
                Ok(CanonicalAdmissionResolution::ProvenNonCommit)
            } else {
                Ok(CanonicalAdmissionResolution::TerminalFailure {
                    error_code: receipt.error_code.as_ref().map(ToString::to_string),
                })
            }
        }
        // Dead-lettered: the store requires a new identity, so this saga's
        // identity can never be admitted again. Terminal, with the exact
        // evidence retained by the caller.
        eliot_store_api::WriteReceiptStatus::DeadLetter => {
            Ok(CanonicalAdmissionResolution::TerminalFailure {
                error_code: receipt.error_code.as_ref().map(ToString::to_string),
            })
        }
    }
}

/// Typed disposition of one canonical admission operation's outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalAdmissionResolution {
    /// Proven committed `ADMITTED` with the exact launch intent. Eligible for
    /// activation after current revalidation.
    Committed,
    /// Proven terminal non-commit under the store's own "same identity may be
    /// retried" disposition. Retry only under this operation identity, and only
    /// under the existing write policy.
    ProvenNonCommit,
    /// Terminal rejection/rollback/dead-letter. Retain the exact evidence and
    /// disposition the reservation without launch; the same identity is dead.
    TerminalFailure {
        /// The store's exact error code, when it issued one.
        error_code: Option<String>,
    },
    /// Missing, unavailable, inconclusive or conflicting. Keep the reservation
    /// inactive/reconciling and block launch.
    Unknown {
        /// Exactly why the outcome could not be established.
        reason: CanonicalAdmissionUnknownReason,
    },
}

/// Why one canonical admission outcome could not be established.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalAdmissionUnknownReason {
    /// The owner has no receipt for the operation identity at all.
    ReceiptAbsent,
    /// The owner's receipt is for a different operation than the one
    /// reconciled.
    OperationMismatch,
    /// A committed `ADMITTED` decision has no proven launch outbox row for this
    /// operation.
    LaunchIntentUnproven,
}

/// Wire revision of this stage identity contract.
///
/// A change to the derived-identity preimage or to the claim-role set is a
/// breaking change for every reservation staged under the old revision, so the
/// revision travels inside the preimage: two different revisions can never
/// collide on one reservation identity.
pub const ADMISSION_RESERVATION_STAGE_VERSION: u16 = 1;

/// Domain separator binding a derived identity to this exact contract and
/// revision. Without it a derived digest could collide with any other ORS
/// identity derived from the same immutable inputs.
const RESERVATION_IDENTITY_DOMAIN: &str = "eliot.ors.admission-reservation.identity.v1";

/// Domain separator binding a proposed-attempt identity to this saga half.
const PROPOSED_ATTEMPT_DOMAIN: &str = "eliot.ors.admission-reservation.attempt.v1";

/// The exact immutable inputs one reservation identity is derived from.
///
/// Every field is an owner-held commitment, never an observed-at-call-time
/// value. In particular `now_unix_ms` is deliberately absent: including the
/// clock would make the identity differ per attempt and break the A2
/// restart-stability rule.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReservationIdentityInput {
    /// Work item whose admission is being reserved.
    pub work_item_id: OperationIdentity,
    /// Attempt identity proposed before canonical admission.
    pub proposed_attempt_id: OperationIdentity,
    /// Exact semantic admission revision this reservation is bound to.
    pub semantic_admission_revision: String,
    /// Complete immutable claim set the reservation reserves.
    pub claims: AdmissionReservationClaims,
    /// Exact State Fence observed for this admission proposal.
    pub state_fence: StateFenceSnapshot,
    /// Authority epoch owning this exact admission proposal.
    pub authority_epoch: EpochLineage,
}

/// Derives the stable reservation identity for one admission proposal.
///
/// The result is a pure function of [`AdmissionReservationIdentityInput`], so
/// the same proposal re-derives the same `reservation_id` on any process and
/// after any crash. This is what makes A2 satisfiable: a restart recomputes this
/// value and reads back the row staged under it instead of minting a new
/// identity.
///
/// # Errors
///
/// Returns [`OrsError`] when the inputs are not shape-valid (blank identity,
/// malformed claim digest, fence/epoch disagreement) or when the canonical
/// preimage cannot be encoded. It never returns a reservation identity for a
/// proposal the owner would refuse to admit.
pub fn admission_reservation_identity(
    input: &AdmissionReservationIdentityInput,
) -> Result<OperationIdentity, OrsError> {
    // Validate the preimage with the existing validators BEFORE hashing it, so
    // an identity is never derived from content the record itself would
    // reject. `validate()` re-derives the fence digest from the ORIGINAL
    // recorded canonical JSON; it never recomputes a fence to trust it.
    input.claims.validate()?;
    input.authority_epoch.validate()?;
    input
        .state_fence
        .validate_against_lineage(&input.authority_epoch)?;
    if input.work_item_id.as_str().trim().is_empty()
        || input.proposed_attempt_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.identity",
            reason: "work item and proposed attempt identities must be non-blank",
        });
    }
    crate::model::validate_text(
        &input.semantic_admission_revision,
        "admission_reservation.semantic_admission_revision",
    )?;
    let preimage = serde_json::to_vec(&(
        RESERVATION_IDENTITY_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        &input.work_item_id,
        &input.proposed_attempt_id,
        &input.semantic_admission_revision,
        &input.claims,
        &input.state_fence,
        &input.authority_epoch,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!("admission-reservation:{}", sha256_hex(&preimage)))
}

/// Derives the ORS stage operation identity for one reservation identity.
///
/// The stage operation is bound to the reservation identity and its immutable
/// first-stage revision, so a retry or a crash-restart reuses the same ORS
/// operation identity rather than minting a second one. Later lifecycle
/// transitions (W3-W8) use their own fresh operation identities and are not
/// produced here.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when `reservation_id` is blank.
pub fn stage_operation_identity(
    reservation_id: &OperationIdentity,
) -> Result<OperationIdentity, OrsError> {
    if reservation_id.as_str().trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.reservation_id",
            reason: "reservation identity must be non-blank",
        });
    }
    OperationIdentity::new(format!("{}:stage", reservation_id.as_str()))
}

/// Derives the proposed-attempt identity for one reservation proposal.
///
/// The attempt identity is derived from the same immutable preimage as the
/// reservation identity, so it is equally stable across a crash: recovery
/// recomputes it rather than minting a new attempt underneath a durable
/// reservation.
///
/// # Errors
///
/// Returns [`OrsError`] under the same conditions as
/// [`admission_reservation_identity`], because both are derived from the same
/// validated preimage.
pub fn proposed_attempt_identity(
    input: &AdmissionReservationIdentityInput,
) -> Result<OperationIdentity, OrsError> {
    let _ = admission_reservation_identity(input)?;
    let preimage = serde_json::to_vec(&(
        PROPOSED_ATTEMPT_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        &input.work_item_id,
        &input.semantic_admission_revision,
        &input.claims,
        &input.state_fence,
        &input.authority_epoch,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!("admission-attempt:{}", sha256_hex(&preimage)))
}

/// Owner-declared, closed set of claim roles one staged reservation must
/// carry (W2).
///
/// This enum is the independent expected set. It is fixed here, in the owner,
/// and [`verify_staged_claim_completeness`] iterates it; a caller's own list is
/// never used as its own reference. Every variant is a distinct, non-blank
/// owner reference, so completeness is decidable without interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedClaimRole {
    /// Complete resource-claim set.
    Resource,
    /// Exact scheduler lane.
    Lane,
    /// Exact environment.
    Environment,
    /// Complete effect-claim set.
    Effect,
    /// Exact pessimistic cost and quota view.
    QuotaView,
    /// Exact State Fence.
    StateFence,
    /// Authority epoch lineage.
    AuthorityEpoch,
}

/// The closed, owner-declared expected role set. A reservation is complete only
/// when every one of these is bound.
const REQUIRED_STAGED_CLAIM_ROLES: &[StagedClaimRole] = &[
    StagedClaimRole::Resource,
    StagedClaimRole::Lane,
    StagedClaimRole::Environment,
    StagedClaimRole::Effect,
    StagedClaimRole::QuotaView,
    StagedClaimRole::StateFence,
    StagedClaimRole::AuthorityEpoch,
];

/// Verifies that one staged record carries every required claim role.
///
/// The check walks [`REQUIRED_STAGED_CLAIM_ROLES`], the owner's own closed
/// expectation, and resolves each role to the reference the record actually
/// holds. A role that resolves to nothing, or to a reference that fails its
/// existing validator, is a typed refusal — completeness is never inferred
/// from the length or the shape of a caller-supplied list.
///
/// Fence and epoch are compared BY VALUE against what the record holds and
/// validated with the existing validators: the State Fence digest is checked
/// with [`StateFenceSnapshot::validate`] against the ORIGINAL recorded
/// canonical JSON, and the epoch with [`EpochLineage::validate`] plus the
/// lineage-bound fence check. Neither digest is recomputed in order to be
/// trusted.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] naming the first unbound role, or the
/// underlying owner error when a bound role's existing validator refuses it.
pub fn verify_staged_claim_completeness(
    record: &AdmissionReservationRecord,
) -> Result<(), OrsError> {
    for role in REQUIRED_STAGED_CLAIM_ROLES {
        match *role {
            // The five claim-reference roles each contribute an OWNER REFERENCE the
            // record must bind; a role whose reference is blank or fails its
            // existing validator is a typed refusal.
            StagedClaimRole::Resource => require_claim_reference(*role, &record.claims.resources)?,
            StagedClaimRole::Lane => require_claim_reference(*role, &record.claims.lane)?,
            StagedClaimRole::Environment => {
                require_claim_reference(*role, &record.claims.environment)?;
            }
            StagedClaimRole::Effect => require_claim_reference(*role, &record.claims.effects)?,
            StagedClaimRole::QuotaView => {
                require_claim_reference(*role, &record.claims.quota_view)?;
            }
            // The two authority roles are NOT claim references — the record carries a
            // `StateFenceSnapshot` and an `EpochLineage` beside its claims. They are
            // named in the same closed set so completeness has ONE denominator to
            // walk, and each is validated BY VALUE against what the record holds: the
            // fence with `validate_against_lineage` against the ORIGINAL recorded
            // canonical JSON, and the epoch with `EpochLineage::validate`. Neither
            // digest is recomputed here in order to be trusted.
            StagedClaimRole::StateFence => {
                record
                    .state_fence
                    .validate_against_lineage(&record.authority_epoch)?;
            }
            StagedClaimRole::AuthorityEpoch => {
                record.authority_epoch.validate()?;
            }
        }
    }
    Ok(())
}

/// Requires one claim role to be bound to a usable, non-blank owner reference.
fn require_claim_reference(
    role: StagedClaimRole,
    reference: &AdmissionReservationClaimRef,
) -> Result<(), OrsError> {
    reference.validate()?;
    if reference.reference.as_str().trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: match role {
                StagedClaimRole::Resource => "admission_reservation.claim.resources",
                StagedClaimRole::Lane => "admission_reservation.claim.lane",
                StagedClaimRole::Environment => "admission_reservation.claim.environment",
                StagedClaimRole::Effect => "admission_reservation.claim.effects",
                StagedClaimRole::QuotaView => "admission_reservation.claim.quota_view",
                StagedClaimRole::StateFence => "admission_reservation.state_fence",
                StagedClaimRole::AuthorityEpoch => "admission_reservation.authority_epoch",
            },
            reason: "every staged claim role must name a non-blank owner reference",
        });
    }
    Ok(())
}

/// The complete set of inputs for one stage-and-read-back operation.
///
/// This is the single request the coordinator accepts. It carries the complete
/// claim set and the expiry boundary, and it names the reservation by the
/// DERIVED identity so a replay and a crash-restart converge on one row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationStageRequest {
    /// Stable, re-derivable reservation identity.
    pub reservation_id: OperationIdentity,
    /// Work item whose admission is being reserved.
    pub work_item_id: OperationIdentity,
    /// Stable proposed attempt identity.
    pub proposed_attempt_id: OperationIdentity,
    /// ORS operation identity for this first stage.
    pub operation_id: OperationIdentity,
    /// Exact complete owner-defined claims (resource, lane, environment,
    /// effect, quota).
    pub claims: AdmissionReservationClaims,
    /// Epoch captured by the caller.
    pub authority_epoch: EpochLineage,
    /// Exact State Fence captured with the epoch.
    pub state_fence: StateFenceSnapshot,
    /// Exact expiry boundary in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Stage time in Unix milliseconds.
    pub now_unix_ms: i64,
}

/// Result of one stage-and-read-back: the durable snapshot plus the exact
/// identity that was staged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionReservationStagedOutcome {
    /// Reservation identity that was staged, for the caller to persist or
    /// re-derive after a crash.
    pub reservation_id: OperationIdentity,
    /// Durable ORS snapshot read back for that exact identity.
    pub snapshot: AdmissionReservationSnapshot,
}

/// Stages one `StagedInactive` reservation and reads it back, creating no
/// process, provider or environment effect.
///
/// This is the stage half of the #1678 saga and the only public entry point
/// that produces a staged reservation. It:
///
/// 1. validates the request and the completeness of every required claim role
///    against the owner's closed expected set;
/// 2. stages the typed `StagedInactive` record through the existing
///    [`OperationalRecoveryStore`] owner — no second store, no in-memory
///    stand-in, no file the owner does not own;
/// 3. reads the same reservation identity back out of the owner and returns
///    that durable snapshot.
///
/// It performs no canonical admission, no launch, no provisioning, no
/// environment allocation and no external effect. Those belong to the
/// admit/activate half, which is a separate owner.
///
/// # Errors
///
/// Returns [`OrsError::DuplicateConflict`] when this exact reservation identity
/// is already durable under DIFFERENT content — a same-identity
/// different-content conflict refuses and never overwrites. An exact replay
/// returns the existing snapshot unchanged and charges nothing twice.
///
/// Returns [`OrsError::InvalidField`] when the request is incomplete or
/// malformed, and any storage/validation error the typed owner raises.
pub fn stage_admission_reservation_inactive<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    request: &AdmissionReservationStageRequest,
) -> Result<AdmissionReservationStagedOutcome, OrsError> {
    if request.now_unix_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_stage.now_unix_ms",
            reason: "stage time must be greater than zero",
        });
    }
    if request.expires_at_ms <= request.now_unix_ms {
        return Err(OrsError::InvalidExpiry);
    }
    // The immutable binding is validated BEFORE the write with the existing
    // validators, by value, against the ORIGINAL recorded fence and epoch.
    request.claims.validate()?;
    request.authority_epoch.validate()?;
    request
        .state_fence
        .validate_against_lineage(&request.authority_epoch)?;
    if request.reservation_id.as_str().trim().is_empty()
        || request.work_item_id.as_str().trim().is_empty()
        || request.proposed_attempt_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_stage.identity",
            reason: "reservation, work item and proposed attempt identities must be non-blank",
        });
    }

    let candidate = AdmissionReservationRecord {
        reservation_id: request.reservation_id.clone(),
        work_item_id: request.work_item_id.clone(),
        proposed_attempt_id: request.proposed_attempt_id.clone(),
        stage_operation_id: request.operation_id.clone(),
        operation_id: request.operation_id.clone(),
        claims: request.claims.clone(),
        authority_epoch: request.authority_epoch.clone(),
        state_fence: request.state_fence.clone(),
        canonical_admission_receipt: None,
        canonical_admission: None,
        activation_receipt: None,
        expires_at_ms: request.expires_at_ms,
        state: AdmissionReservationState::StagedInactive,
        disposition_reason: None,
        disposition_evidence: None,
        last_transition: None,
        created_at_ms: request.now_unix_ms,
        updated_at_ms: request.now_unix_ms,
    };
    candidate.validate()?;
    verify_staged_claim_completeness(&candidate)?;

    let staged = store.stage_kernel_admission_reservation(AdmissionReservationStage {
        reservation_id: request.reservation_id.clone(),
        work_item_id: request.work_item_id.clone(),
        proposed_attempt_id: request.proposed_attempt_id.clone(),
        operation_id: request.operation_id.clone(),
        claims: request.claims.clone(),
        authority_epoch: request.authority_epoch.clone(),
        state_fence: request.state_fence.clone(),
        expires_at_ms: request.expires_at_ms,
        now_ms: request.now_unix_ms,
    })?;
    // The store's own echoed row is compared against the candidate this function
    // validated BEFORE the write, field by field. The store is a different owner
    // from the validator, so this is a real cross-check rather than a
    // self-comparison, and it is what makes "the claims were staged" mean "the
    // claims the store holds are the claims that were checked" instead of merely
    // "a write returned successfully".
    if staged.record().claims != candidate.claims
        || staged.record().state_fence != candidate.state_fence
        || staged.record().authority_epoch != candidate.authority_epoch
        || staged.record().state != candidate.state
        || staged.record().work_item_id != candidate.work_item_id
        || staged.record().proposed_attempt_id != candidate.proposed_attempt_id
        || staged.record().operation_id != candidate.operation_id
        || staged.record().expires_at_ms != candidate.expires_at_ms
        || staged.record().canonical_admission.is_some()
        || staged.record().canonical_admission_receipt.is_some()
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the staged row does not carry the claims this call validated".to_owned(),
        });
    }

    // Durably read the SAME identity back. This is the A2 restart path: the
    // caller re-derives `reservation_id` and lands on the identical row, and
    // this read performs no launch, provisioning or allocation.
    let readback = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::DuplicateConflict)?;
    if readback.record().reservation_id != request.reservation_id {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "readback returned a different reservation identity".to_owned(),
        });
    }
    Ok(AdmissionReservationStagedOutcome {
        reservation_id: request.reservation_id.clone(),
        snapshot: readback,
    })
}

/// Reloads one staged reservation by its stable identity, creating no effect.
///
/// This is the A2 recovery entry point: after a restart, the coordinator
/// re-derives `reservation_id` and calls this to prove the reservation is
/// durable and still `StagedInactive` before any canonical admission is even
/// attempted. It provisions nothing, launches nothing and mutates nothing.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no reservation exists under
/// that identity, and propagates any owner validation error for a record that
/// is present but malformed.
pub fn reload_staged_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    reservation_id: &OperationIdentity,
    now_unix_ms: i64,
) -> Result<AdmissionReservationSnapshot, OrsError> {
    if now_unix_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_reload.now_unix_ms",
            reason: "read time must be greater than zero",
        });
    }
    let snapshot = store
        .load_kernel_admission_reservation(reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    snapshot.record().validate()?;
    verify_staged_claim_completeness(snapshot.record())?;
    Ok(snapshot)
}

/// Builds the ORS epoch lineage for one canonical [`EpochId`] and its
/// observed predecessor.
///
/// This is the ONLY conversion between the canonical `EpochId` contour and the
/// ORS `EpochLineage` contour used by the reservation. It reuses the existing
/// `EpochId` lineage identity verbatim (no parallel representation) and drops
/// a predecessor that is equal to the current epoch, because `EpochLineage`
/// would then describe a non-succession.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when the lineage label is not a usable
/// `OpaqueLabel`, and [`OrsError::InvalidEpochLineage`] when the resulting
/// lineage does not strictly advance its same-lineage predecessor.
pub fn epoch_lineage_for(
    epoch: &EpochId,
    predecessor: Option<&EpochIdentity>,
) -> Result<EpochLineage, OrsError> {
    let current = EpochIdentity {
        lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str())?,
        epoch: epoch.sequence.get(),
    };
    let prior = predecessor.filter(|prior| *prior != &current).cloned();
    let lineage = EpochLineage {
        current,
        predecessor: prior,
    };
    lineage.validate()?;
    Ok(lineage)
}

/// Domain separator binding a derived activation identity to this exact
/// contract revision. Without it a derived activation digest could collide
/// with any other ORS identity derived from the same immutable inputs.
const ACTIVATION_OPERATION_DOMAIN: &str = "eliot.ors.admission-reservation.activation.v1";

/// Derives the ORS operation identity for the activation of one reservation.
///
/// The identity is bound to the RESERVATION it activates and to this contract
/// revision only. That is deliberate and it is the whole point of this function:
/// the owner evidence (the canonical admission receipt and the activation
/// receipt) is the CONTENT of the activation, and it is deliberately NOT part of
/// the identity preimage.
///
/// If the identity were derived from the owner evidence, changed evidence under
/// one reservation would mint a *different* operation identity, and the store's
/// same-identity-changed-content conflict check — which fires only when the
/// replayed operation identity equals the row's current one — would never fire.
/// The result would be a second activation carrying different content under a
/// fresh identity, which is exactly what A6 forbids ("same identity with changed
/// content conflicts"). With the identity bound to the reservation alone, an
/// exact replay presents the SAME operation and returns the original snapshot,
/// while changed evidence presents the SAME operation against different content
/// and is refused by the owner as a conflict.
///
/// # Errors
///
/// Returns [`OrsError::InvalidField`] when `reservation_id` is blank, and
/// [`OrsError::Encoding`] when the canonical preimage cannot be encoded.
pub fn activation_operation_identity(
    reservation_id: &OperationIdentity,
) -> Result<OperationIdentity, OrsError> {
    if reservation_id.as_str().trim().is_empty() {
        return Err(OrsError::InvalidField {
            field: "admission_reservation.reservation_id",
            reason: "reservation identity must be non-blank",
        });
    }
    let preimage = serde_json::to_vec(&(
        ACTIVATION_OPERATION_DOMAIN,
        ADMISSION_RESERVATION_STAGE_VERSION,
        reservation_id,
    ))
    .map_err(|error| OrsError::Encoding(error.to_string()))?;
    OperationIdentity::new(format!(
        "admission-reservation-activation:{}",
        sha256_hex(&preimage)
    ))
}

/// Activates the exact reservation from owner evidence and returns the durable
/// activation receipt (REQ6, A4, A7).
///
/// This is the activate half of the #1678 saga and the only public entry point
/// that produces an active reservation. It:
///
/// 1. re-reads the exact reservation identity from the typed owner and refuses
///    anything that is not the `StagedInactive` (or `Reconciling`) row the
///    caller named, under the caller's current Authority Epoch lineage and
///    State Fence — a foreign epoch, a stale fence, a different work item,
///    attempt or claim set fails **before** any mutation;
/// 2. validates the two owner receipts with the existing
///    [`AdmissionReservationActivationEvidence`] validator, so a malformed or
///    non-distinct receipt pair never reaches the write;
/// 3. CAS-transitions the row to `Active` through the same typed owner, using
///    the current ORS receipt it just read as the expected receipt;
/// 4. reads the SAME identity back out of the owner and returns that durable
///    snapshot, from which the caller takes the committed activation and
///    canonical admission receipts.
///
/// The function admits nothing, launches nothing, provisions nothing and
/// allocates no environment. It is the mechanical prerequisite #1701 consumes,
/// not a process start.
///
/// # Errors
///
/// Returns [`OrsError::ReservationNotFound`] when no reservation exists under
/// the named identity, [`OrsError::DuplicateConflict`] when the durable row is
/// not the row the caller described (different work item, attempt, claims,
/// epoch or fence) or when the expected ORS receipt no longer matches the
/// current one, [`OrsError::FenceMismatch`] when the caller's Authority Epoch
/// or State Fence does not match the durable row, [`OrsError::InvalidExpiry`]
/// when the declared expiry boundary has already elapsed, and
/// [`OrsError::InvalidField`] when the request is incomplete or malformed.
///
/// An **exact replay** — the same operation identity, the same expected
/// receipt, the same owner evidence — returns the original active snapshot
/// unchanged: the second activation is refused as a same-identity
/// different-content conflict only when the content actually differs.
pub fn activate_admission_reservation_from_owner_evidence<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    request: &AdmissionReservationActivationRequest,
) -> Result<AdmissionReservationActivatedOutcome, OrsError> {
    if request.now_ms <= 0 {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_activation.now_ms",
            reason: "activation time must be greater than zero",
        });
    }
    if request.reservation_id.as_str().trim().is_empty()
        || request.work_item_id.as_str().trim().is_empty()
        || request.proposed_attempt_id.as_str().trim().is_empty()
        || request.operation_id.as_str().trim().is_empty()
    {
        return Err(OrsError::InvalidField {
            field: "admission_reservation_activation.identity",
            reason: "reservation, work item, proposed attempt and operation identities must be non-blank",
        });
    }
    // The immutable binding is validated BEFORE the write with the existing
    // validators, by value, against the ORIGINAL recorded fence and epoch.
    request.claims.validate()?;
    request.authority_epoch.validate()?;
    request
        .state_fence
        .validate_against_lineage(&request.authority_epoch)?;
    AdmissionReservationActivationEvidence {
        canonical_admission_receipt: request.canonical_admission_receipt.clone(),
        activation_receipt: request.activation_receipt.clone(),
    }
    .validate()?;

    // Re-read the exact row the caller believes it is activating. This is the
    // pre-mutation identity check: nothing is written until the durable row,
    // its immutable binding and the caller's current authority all agree.
    let current = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    let staged = current.record();
    staged.validate()?;
    verify_staged_claim_completeness(staged)?;
    if staged.state != AdmissionReservationState::StagedInactive
        && staged.state != AdmissionReservationState::Reconciling
    {
        return Err(OrsError::InvalidTransition);
    }
    if staged.work_item_id != request.work_item_id
        || staged.proposed_attempt_id != request.proposed_attempt_id
        || staged.claims != request.claims
    {
        return Err(OrsError::DuplicateConflict);
    }
    if staged.authority_epoch != request.authority_epoch
        || staged.state_fence != request.state_fence
    {
        return Err(OrsError::FenceMismatch);
    }
    if request.now_ms >= staged.expires_at_ms {
        return Err(OrsError::InvalidExpiry);
    }
    // The CAS precondition is the receipt this call actually observed, not a
    // value the caller may have invented: the store compares the request's
    // `expected_current_receipt` against the row it holds at write time and
    // refuses a mismatch.
    if current.receipt() != &request.expected_current_receipt {
        return Err(OrsError::DuplicateConflict);
    }

    let activated =
        store.activate_kernel_admission_reservation(AdmissionReservationActivationRequest {
            reservation_id: request.reservation_id.clone(),
            work_item_id: request.work_item_id.clone(),
            proposed_attempt_id: request.proposed_attempt_id.clone(),
            operation_id: request.operation_id.clone(),
            claims: request.claims.clone(),
            canonical_admission_receipt: request.canonical_admission_receipt.clone(),
            canonical_admission: request.canonical_admission.clone(),
            activation_receipt: request.activation_receipt.clone(),
            expected_current_receipt: request.expected_current_receipt.clone(),
            authority_epoch: request.authority_epoch.clone(),
            state_fence: request.state_fence.clone(),
            now_ms: request.now_ms,
        })?;
    // The store's own echoed row is cross-checked against the facts this call
    // verified BEFORE the write, so "the reservation is active" means the
    // persisted row carries the evidence that was checked, not merely that a
    // write returned successfully.
    let persisted = activated.record();
    persisted.validate()?;
    if persisted.state != AdmissionReservationState::Active
        || persisted.reservation_id != request.reservation_id
        || persisted.canonical_admission_receipt.as_ref()
            != Some(&request.canonical_admission_receipt)
        || persisted.activation_receipt.as_ref() != Some(&request.activation_receipt)
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "the activated row does not carry the owner evidence this call validated"
                .to_owned(),
        });
    }

    // Durably read the SAME identity back. This is the A7 restart path: a
    // replay after a lost response lands on the identical active row and its
    // original activation receipt, and this read launches nothing.
    let readback = store
        .load_kernel_admission_reservation(&request.reservation_id)?
        .ok_or(OrsError::ReservationNotFound)?;
    if readback.record().state != AdmissionReservationState::Active
        || readback.record().activation_receipt.as_ref() != Some(&request.activation_receipt)
    {
        return Err(OrsError::IntegrityProblem {
            record_type: "admission_reservation",
            reason: "readback returned a different active reservation identity".to_owned(),
        });
    }
    Ok(AdmissionReservationActivatedOutcome::from_store(
        request.reservation_id.clone(),
        readback,
    ))
}
