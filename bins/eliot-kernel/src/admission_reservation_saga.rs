//! Admission-reservation admit/activate coordinator and the launch-side
//! refusal surface (#1678 W3/W5/W8/W9, REQ4, REQ6, REQ9; A3, A4, A7, A8).
//!
//! # What this module owns
//!
//! The three pieces of the normative `AdmissionReservation` saga that the
//! synchronous native-worker claim route structurally cannot reach, and the
//! one launch-side gate every dispatch path must pass:
//!
//! 1. [`KernelComposition::admission_reservation_admit_operation`] — the
//!    **admit + activate** coordinator. It is the production caller of
//!    [`eliot_ors::prove_canonical_admission_for_reservation`],
//!    [`eliot_ors::launch_outbox_readback`] and
//!    [`eliot_ors::activate_admission_reservation_from_owner_evidence`], the
//!    three ORS owners the stage-only claim route left without a caller.
//! 2. [`OrsGenerationCoordinator::recover_admission_reservations`] — the
//!    restart enumeration that loads every durable reservation row, applies the
//!    legacy compatibility disposition, and **never launches**.
//! 3. [`require_admission_reservation_launch`] — the launch gate for a seam
//!    that already holds the reservation identity (the native-worker claim
//!    route). It refuses on all eight inert
//!    [`eliot_ors::AdmissionReservationLaunchPrerequisite`] variants and accepts
//!    only the sealed `Active` one.
//! 4. [`require_bound_admission_reservation_launch`] — the launch gate for a
//!    seam that holds only its own work item and attempt
//!    (`dispatch_launch::spawn_ready_child` and
//!    `daemon_process_launch::launch_eliotd_inner`). It resolves the ONE durable
//!    reservation that binds that work item and attempt through the owner's own
//!    recovery enumeration and then applies the same verifier. A contour that
//!    stages no reservation resolves none and passes; it never stages one.
//!
//! # Why the coordinator is an authenticated daemon route
//!
//! I14.6 fixes the order: "ORS first stages inactive claims; canonical state
//! records `ADMITTED` and the launch outbox; Kernel then activates the exact
//! reservation." The canonical `ADMITTED` write and its receipt readback are
//! live [`eliot_store_api::WriteReceipt`] IO owned by [`KernelStoreGateway`]
//! (`apply` and `receipt`), which is `async` and generation-routed. The stage
//! half therefore already lives in the synchronous claim route
//! (`native_worker_lifecycle_route::stage_claim_admission_reservation`), and
//! the two remaining halves live here, on the admitted daemon channel that
//! already owns asynchronous canonical store IO (`daemon_request_dispatch`).
//! This is the "narrow Kernel coordinator that calls the current
//! Governor/canonical admission and launch-outbox owner" the issue's scope
//! names; it adds no second canonical writer, no second outbox table and no
//! second reservation state machine.
//!
//! # What the coordinator refuses, and how
//!
//! - **The canonical `ADMITTED` decision is never minted here.** The only
//!   admission evidence that can reach this route is the canonical owner's own
//!   `WriteReceipt`, read back through [`KernelStoreGateway::receipt`] for the
//!   ORIGINAL operation identity. A route-local "it was admitted" assertion
//!   cannot enter this module at all.
//! - **Response loss cannot mint a second admission (A3).** The canonical
//!   operation identity is DERIVED from the reservation alone
//!   ([`eliot_ors::stage_operation_identity`]), so a retry after a lost
//!   response re-resolves the same operation. Before this coordinator does
//!   anything else it asks the owner for that receipt; an existing committed
//!   receipt is adopted and re-proved, never re-submitted, and a payload that
//!   names a different canonical operation is refused as an identity
//!   conflict. Only an owner `ProvenNonCommit` (the store's own
//!   `Resubmission::None` disposition for the SAME identity) makes a retry
//!   lawful, and it reuses that same identity.
//! - **Activation happens exactly once, from one current owner receipt (A4).**
//!   The activation is presented under
//!   [`eliot_ors::activation_operation_identity`], which binds to the
//!   RESERVATION ALONE, so the store's existing same-identity-changed-content
//!   conflict actually fires: an exact replay returns the original active
//!   snapshot and receipt, and changed evidence under the same operation is
//!   refused. The evidence is bound to the operation, not merely present: the
//!   retained commit is built from the owner's receipt and then compared BY
//!   VALUE against a fresh readback of the SAME operation before the
//!   activation is issued, and the returned activation receipt is read out of
//!   the committed row rather than echoed from the request.
//! - **A stale or superseded owner receipt never activates.** A receipt is
//!   classified through [`eliot_ors::reconcile_canonical_admission`], which
//!   reports a receipt for a different operation, an unproven launch intent,
//!   or a terminal disposition as `Unknown`/`TerminalFailure` — never as
//!   activation authority — and every one of those outcomes keeps the
//!   reservation inactive and launch blocked. `PROVEN_NON_COMMIT` and
//!   `TERMINAL_FAILURE` are reported as their OWN dispositions rather than as
//!   an absent receipt, so a caller is never told to keep reconciling an
//!   operation that can never commit.
//!
//! # What recovery refuses to do
//!
//! [`OrsGenerationCoordinator::recover_admission_reservations`] is reached
//! from composition assembly BEFORE the Kernel admits any overlapping work. It
//! enumerates, loads and dispositions durable rows. It holds no process
//! gateway, builds no `ProcessExecutionAdmissionRequest`, and calls no launch
//! function; the only write it can make is the ORS receipt it read back. A
//! recovered `StagedInactive` or `Reconciling` reservation therefore stays
//! exactly as durable: reconcilable under its own identity, never launched as
//! a side effect of being loaded. Launch is refused by name at every dispatch
//! path by [`require_admission_reservation_launch`], which reads this same
//! row.

use eliot_contracts::{ReceiptId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_ors::{
    ActiveAdmissionReservation,
    AdmissionReservationLaunchPrerequisite,
    AdmissionReservationRowDisposition,
    AdmissionReservationState,
    CanonicalAdmissionCommit,
    CanonicalAdmissionResolution,
    EpochLineage,
    OperationIdentity,
    // The durable read/enumerate/recovery surface is the owner's TRAIT, not a set
    // of inherent `RedbRecoveryStore` methods. Importing the trait is what makes
    // `load_kernel_admission_reservation`, `begin_recovery_inventory_snapshot`
    // and `scan_operational_current` resolve through the store this Kernel
    // actually holds; no inherent method is added and the gateway is never
    // duplicated.
    OperationalRecoveryStore,
    OrsError,
    ProvenCanonicalAdmission,
    StateFenceSnapshot,
    activate_admission_reservation_from_owner_evidence,
    activation_operation_identity,
    launch_outbox_readback,
    prove_canonical_admission_for_reservation,
    reconcile_canonical_admission,
    reload_staged_admission_reservation,
    stage_operation_identity,
};
use eliot_receipts::ReceiptIdentity;
use eliot_store_api::WriteReceipt;
use serde::Deserialize;

use super::generation_recovery::OrsGenerationCoordinator;
use super::{KernelComposition, Session, TransportError};

/// The admitted daemon-channel operation that drives the admit half of the
/// admission-reservation saga and the activation that follows it (#1678 W3,
/// REQ4, A3).
///
/// This is a real production dispatch arm: `daemon_request_dispatch` serves it
/// and `frame_dispatch` admits the frame. It is not a probe, a helper, or an
/// unhooked surface.
pub(crate) const ADMISSION_RESERVATION_ADMIT_OPERATION: &str = "admission_reservation.admit";

/// ORS operational-kind key prefix for one admission reservation row.
///
/// This is the owner's own spelling
/// (`OperationalKind::AdmissionReservation::key_prefix`), reproduced here only
/// as a SELECTION filter over the owner's already-payload-free recovery
/// enumeration. The typed read that follows is what decides the row's class;
/// this prefix only decides which enumerated rows are reservation rows at all.
const ADMISSION_RESERVATION_KIND: &str = "admission_reservation";

/// Domain separator binding the derived ORS activation receipt reference to
/// this exact contract. Without it a derived digest could collide with any
/// other identity derived from the same immutable inputs.
const ACTIVATION_RECEIPT_DOMAIN: &str = "eliot.ors.admission-reservation.activation-receipt.v1";

/// The exact canonical admission request the coordinator needs the canonical
/// owner to have committed for one reservation.
///
/// Everything the coordinator needs is either an identity it re-derives from
/// the durable reservation (never from this payload) or the owner-issued
/// reference the owner itself must have returned. `admission_receipt` is NOT
/// accepted as authority on its own: the retained commit the ORS owner builds
/// from the owner's own `WriteReceipt` must name that exact receipt, and the
/// retained commit is then compared BY VALUE against a fresh readback of the
/// same canonical operation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionReservationAdmitOperation {
    /// Stable reservation identity the caller re-derived from the durable
    /// claim binding.
    reservation_id: String,
    /// The canonical `ADMITTED` operation identity. It must equal
    /// `stage_operation_identity(reservation_id)`: the coordinator derives it
    /// and refuses a payload naming a different one, so a payload can never
    /// redirect the saga to a second admission.
    canonical_operation_id: String,
    /// The work item the reservation covers.
    work_item_id: String,
    /// The proposed attempt the reservation covers.
    proposed_attempt_id: String,
    /// Owner-issued canonical admission receipt reference the owner returned
    /// from the `ADMITTED` commit.
    admission_receipt: ReceiptIdentity,
    /// The session fence the daemon presents for this operation.
    state_fence: StateFence,
}

/// F-LOG-KERNEL-5 (#1678): admission-reservation saga boundary observations.
///
/// Same #895-only shape as the sibling `generation_recovery::observe_recovery`
/// helper: fixed `kernel.admission_reservation.*` event names plus a bounded
/// stable outcome, policy-screened by `bound_field`. Never carries a
/// reservation identity, a canonical operation identity, a receipt digest, a
/// fence, or an owner error string (I15.4, I07.20).
fn observe_admission_saga(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "admission reservation saga observation"
    );
}

/// One refused launch, carrying the owner's own disposition verbatim.
///
/// This is a typed refusal, not prose: the state that refused is the owner's
/// own [`AdmissionReservationLaunchPrerequisite`] variant, and the rendered
/// message uses the owner's `Serialize` discriminant so it is the owner's
/// spelling rather than a route-local label that could drift from the nine
/// states.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionReservationLaunchRefusal {
    /// Exact durable reservation identity the prerequisite was read for.
    pub(crate) reservation_id: String,
    /// The owner's own variant name (`MISSING`, `STAGED`, `RELEASED`,
    /// `EXPIRED`, `RECONCILING`, `STALE_FENCE`, `FOREIGN_OWNER`,
    /// `IDENTITY_CONFLICT`, or `ACTIVE`), plus `UNREADABLE:<tag>` for a
    /// durable row the owner itself refused.
    pub(crate) state: String,
}

impl std::fmt::Display for AdmissionReservationLaunchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "admission reservation {} refuses launch: {}",
            self.reservation_id, self.state
        )
    }
}

impl std::error::Error for AdmissionReservationLaunchRefusal {}

impl AdmissionReservationLaunchRefusal {
    /// Projects the owner verdict to the owner's own variant name.
    ///
    /// The discriminant is read out of the owner's `Serialize` output — the
    /// same projection the claim route's sealed receipt uses — so the refusal
    /// names a state from the owner's closed nine-state set and can never
    /// advertise a tenth one this module invented.
    pub(crate) fn from_prerequisite(
        reservation_id: &OperationIdentity,
        prerequisite: &AdmissionReservationLaunchPrerequisite,
    ) -> Self {
        Self {
            reservation_id: reservation_id.as_str().to_owned(),
            state: prerequisite_state_name(prerequisite),
        }
    }

    /// Projects one typed ORS failure onto a stable, bounded state name.
    ///
    /// The owner error STRING is never carried (I15.4): this names the variant
    /// so a refusal says which typed refusal it was without emitting an owner
    /// message, a digest or a path.
    pub(crate) fn from_ors_error(reservation_id: &OperationIdentity, error: &OrsError) -> Self {
        Self {
            reservation_id: reservation_id.as_str().to_owned(),
            state: format!("UNREADABLE:{}", ors_error_tag(error)),
        }
    }
}

/// Returns the owner's own discriminant for one prerequisite variant.
fn prerequisite_state_name(prerequisite: &AdmissionReservationLaunchPrerequisite) -> String {
    serde_json::to_value(prerequisite)
        .ok()
        .and_then(|value| {
            value
                .as_object()
                .and_then(|object| object.keys().next().cloned())
        })
        .unwrap_or_else(|| "UNREADABLE:UNSERIALIZABLE".to_owned())
}

/// Projects one typed ORS failure onto a stable, bounded tag.
fn ors_error_tag(error: &OrsError) -> &'static str {
    match error {
        OrsError::ReservationNotFound => "RESERVATION_NOT_FOUND",
        OrsError::InvalidTransition => "INVALID_TRANSITION",
        OrsError::DuplicateConflict => "DUPLICATE_CONFLICT",
        OrsError::FenceMismatch => "FENCE_MISMATCH",
        OrsError::InvalidExpiry => "INVALID_EXPIRY",
        OrsError::ReconciliationMismatch => "RECONCILIATION_MISMATCH",
        OrsError::IntegrityProblem { .. } => "INTEGRITY_PROBLEM",
        OrsError::InvalidField { .. } => "INVALID_FIELD",
        _ => "ORS_REFUSED",
    }
}

/// Loads the durable reservation row and returns the owner's own launch
/// prerequisite, unchanged (W8, A8).
///
/// This is the SHARED read half of the launch gate. It performs the one
/// `load_kernel_admission_reservation` read and hands the result to
/// [`eliot_ors::verify_admission_reservation_launch_prerequisite`], so every
/// consumer — the claim route and [`require_admission_reservation_launch`] —
/// sees the SAME owner-verified nine-state disposition rather than a
/// route-local guess. It is a pure read: it provisions nothing, launches
/// nothing, and mutates no durable state.
///
/// A caller that needs to decide for itself (the claim route echoes the state
/// on its sealed receipt) reads the owner's variant directly. A caller that is
/// about to START a child must not: it uses
/// [`require_admission_reservation_launch`], which is the same read plus the
/// refusal that only the sealed `Active` typestate survives.
///
/// # Errors
///
/// Returns [`OrsError`] when the durable row is unreadable, violates its own
/// validator, or when the caller's epoch/fence pair does not hold together.
/// The row's own state is NOT an error here: it is the owner's typed
/// [`AdmissionReservationLaunchPrerequisite`] variant.
pub(crate) fn read_admission_reservation_launch_prerequisite<
    S: OperationalRecoveryStore + ?Sized,
>(
    store: &S,
    reservation_id: &OperationIdentity,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
    authority_epoch: &EpochLineage,
    state_fence: &StateFenceSnapshot,
    now_unix_ms: i64,
) -> Result<AdmissionReservationLaunchPrerequisite, OrsError> {
    let current = store.load_kernel_admission_reservation(reservation_id)?;
    eliot_ors::verify_admission_reservation_launch_prerequisite(
        current.as_ref(),
        work_item_id,
        proposed_attempt_id,
        authority_epoch,
        state_fence,
        now_unix_ms,
    )
}

/// Resolves the ONE durable admission reservation that binds a launch's own
/// work item and proposed attempt (W8).
///
/// This is the identity half of the launch gate for every dispatch path that
/// reaches a spawn WITHOUT holding the claim route's in-scope reservation
/// identity — `dispatch_launch`'s Doctor/testd/native-worker/Dreamer seams and
/// `daemon_process_launch`'s `eliotd` seam. It does not mint, guess or
/// reconstruct a reservation identity, and it does not stage one: it enumerates
/// the owner's own payload-free recovery rows, selects only those whose
/// OWNER-RECORDED kind is `admission_reservation`, and asks the typed owner
/// which of them actually binds this work item and attempt.
///
/// The comparison is against the row's OWN recorded `work_item_id` /
/// `proposed_attempt_id`, so the answer is evidence read back from the owner,
/// never a list this module kept beside the same caller. When more than one
/// durable reservation claims the same work item and attempt the launch is
/// refused outright: an ambiguous reservation cannot be evidence for a spawn,
/// and picking one would let a launch ride whichever row happened to enumerate
/// first.
///
/// # Errors
///
/// Returns [`OrsError`] when the recovery inventory moved under the
/// enumeration, when a page is unreadable, or when a classified row disagrees
/// with its own typed readback.
pub(crate) fn find_admission_reservation_for_launch<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
) -> Result<Option<OperationIdentity>, OrsError> {
    use eliot_ors::{MAX_RECOVERY_PAGE, OperationalCurrentRecoveryCursor};
    let snapshot = store.begin_recovery_inventory_snapshot()?;
    let mut cursor = OperationalCurrentRecoveryCursor::start(snapshot, MAX_RECOVERY_PAGE)?;
    let mut found: Option<OperationIdentity> = None;
    loop {
        let page = store.scan_operational_current(cursor.clone())?;
        for entry in &page.records {
            // The OWNER's own kind spelling selects the row; nothing here
            // interprets another operational kind.
            if entry.kind.as_str() != ADMISSION_RESERVATION_KIND {
                continue;
            }
            let AdmissionReservationRowDisposition::Migrated { snapshot } =
                eliot_ors::disposition_admission_reservation_row(store, entry)?
            else {
                // A quarantined or refused legacy row is never reservation
                // authority, so it is not a candidate and not a launch blocker
                // either: it can never be activated, so it can never be the
                // reservation a launch would have needed.
                continue;
            };
            let record = snapshot.record();
            if record.work_item_id != *work_item_id
                || record.proposed_attempt_id != *proposed_attempt_id
            {
                continue;
            }
            if found.is_some_and(|existing| existing != record.reservation_id) {
                return Err(OrsError::IntegrityProblem {
                    record_type: "admission_reservation",
                    reason:
                        "more than one durable reservation binds the launched work item and attempt"
                            .to_owned(),
                });
            }
            found = Some(record.reservation_id.clone());
        }
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Ok(found)
}

/// Reads the launch prerequisite for one reservation and refuses on every
/// state but the one admissible one (W8, A8).
///
/// This is the gate for a launching seam that already holds the reservation
/// identity. Every path that is about to start a child reaches the owner's
/// nine-state decision through this function or through
/// [`require_bound_admission_reservation_launch`], which delegates here once it
/// has resolved the identity. The states are therefore decided once, by the owner
/// verifier ([`eliot_ors::verify_admission_reservation_launch_prerequisite`] —
/// reached through [`read_admission_reservation_launch_prerequisite`]), and no
/// launch path re-derives or re-enumerates them.
///
/// The check is a pure read plus the owner's verifier: it provisions nothing,
/// launches nothing, mutates no lifecycle position, and grants no authority by
/// itself. A reservation in `MISSING`, `STAGED`, `RELEASED`, `EXPIRED`,
/// `RECONCILING`, `STALE_FENCE`, `FOREIGN_OWNER` or `IDENTITY_CONFLICT` is
/// refused with that exact state named, and no caller reaches a spawn past
/// this function.
///
/// # Errors
///
/// Returns [`AdmissionReservationLaunchRefusal`] naming the owner's own state
/// when the reservation is not an exact `ACTIVE` row under the caller's
/// current work item, attempt, Authority Epoch lineage, State Fence and
/// unexpired deadline, and naming the typed ORS refusal when the durable row
/// itself is unreadable or violates its own validator.
pub(crate) fn require_admission_reservation_launch<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    reservation_id: &OperationIdentity,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
    authority_epoch: &EpochLineage,
    state_fence: &StateFenceSnapshot,
    now_unix_ms: i64,
) -> Result<ActiveAdmissionReservation, AdmissionReservationLaunchRefusal> {
    // An absent durable row is the owner's own `MISSING` disposition, not an
    // error and not pass: a reservation that was never staged cannot launch.
    let prerequisite = read_admission_reservation_launch_prerequisite(
        store,
        reservation_id,
        work_item_id,
        proposed_attempt_id,
        authority_epoch,
        state_fence,
        now_unix_ms,
    )
    .map_err(|error| AdmissionReservationLaunchRefusal::from_ors_error(reservation_id, &error))?;
    match prerequisite {
        // The one admissible state. The sealed value can only have been issued
        // by the owner verifier, so an ordinary caller cannot construct or
        // deserialize an accepted "active" typestate from public fields.
        AdmissionReservationLaunchPrerequisite::Active(active) => Ok(active),
        refused => Err(AdmissionReservationLaunchRefusal::from_prerequisite(
            reservation_id,
            &refused,
        )),
    }
}

/// Refuses a launch that does not name an active admission reservation
/// (W8).
///
/// This is the gate the `dispatch_launch` and `daemon_process_launch` spawn
/// paths pass. It is deliberately the *identity-resolving* form of
/// [`require_admission_reservation_launch`]: the launching seam knows its own
/// work item and proposed attempt, but the reservation identity is a hash the
/// claim route owns, so the seam resolves it from the owner's own durable rows
/// through [`find_admission_reservation_for_launch`] rather than reconstructing
/// or being told one.
///
/// Three outcomes, all decided by the owner and none by this function:
///
/// * **no reservation binds this work item and attempt** — there is nothing
///   staged, so nothing is refused. This is the whole of the Doctor, testd,
///   Dreamer and `eliotd` contours, which never stage a reservation and are
///   therefore not blocked by a row that does not exist. Staging one here would
///   be a second reservation scheme, so it is never done.
/// * **exactly one reservation binds it and it is `Active`** — the owner's
///   sealed typestate is returned and the launch proceeds. `Active` is the only
///   value the owner verifier can issue, and it is issued only for an exact
///   active row under the caller's current epoch, fence, work item and attempt
///   with both owner receipts present.
/// * **a reservation binds it in any other state** — refused by name. This is
///   the W8 requirement: `MISSING` under a named identity, `STAGED`,
///   `RELEASED`, `EXPIRED`, `RECONCILING`, `STALE_FENCE`, `FOREIGN_OWNER`,
///   `IDENTITY_CONFLICT` and an unreadable row each reach the caller as a
///   typed [`AdmissionReservationLaunchRefusal`] carrying the owner's own
///   discriminant, never as a generic launch error.
///
/// An ambiguous binding (two durable reservations claiming the same work item
/// and attempt) is an owner integrity refusal and is refused, because a launch
/// cannot be authorised by a row it did not uniquely name.
///
/// # Errors
///
/// None. Every failure is an `Ok`/`Err` [`AdmissionReservationLaunchRefusal`],
/// because an unreadable or ambiguous owner read is a refusal of the launch,
/// never a reason to spawn. An unknown effect stays unknown: a durable read
/// that cannot establish the row is reported as `UNREADABLE:<tag>` and blocks
/// the launch rather than being collapsed into "no reservation".
pub(crate) fn require_bound_admission_reservation_launch<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
    authority_epoch: &EpochLineage,
    state_fence: &StateFenceSnapshot,
    now_unix_ms: i64,
) -> Result<Option<ActiveAdmissionReservation>, AdmissionReservationLaunchRefusal> {
    // The epoch/fence pair the caller presents is validated by the owner BEFORE
    // the enumeration, so a caller that cannot hold its own authority together
    // is refused rather than allowed to search the store for a row that would
    // happen to match.
    if let Err(error) = authority_epoch
        .validate()
        .and_then(|()| state_fence.validate_against_lineage(authority_epoch))
    {
        return Err(AdmissionReservationLaunchRefusal::from_ors_error(
            work_item_id,
            &error,
        ));
    }
    let reservation_id =
        match find_admission_reservation_for_launch(store, work_item_id, proposed_attempt_id) {
            Ok(Some(reservation_id)) => reservation_id,
            // Nothing staged for this launch: not a refusal, because there is no
            // reservation for this contour to be refused by.
            Ok(None) => return Ok(None),
            // An unreadable or ambiguous owner read is `UNREADABLE`, not "no
            // reservation": collapsing it into absence would let a launch past a
            // durable row whose state could not be established.
            Err(error) => {
                return Err(AdmissionReservationLaunchRefusal::from_ors_error(
                    work_item_id,
                    &error,
                ));
            }
        };
    require_admission_reservation_launch(
        store,
        &reservation_id,
        work_item_id,
        proposed_attempt_id,
        authority_epoch,
        state_fence,
        now_unix_ms,
    )
    .map(Some)
}

/// Reads the launch prerequisite and returns it only when it is the one
/// admissible `Active` state, refusing by name otherwise (W8, A8).
///
/// This is the gate a launch-authority caller uses when it must also CARRY the
/// owner's disposition forward — the native-worker claim route, which seals the
/// accepted prerequisite onto the claim receipt so a later consumer sees the same
/// sealed evidence. On success it returns the owner's own
/// [`AdmissionReservationLaunchPrerequisite::Active`] variant unchanged; it never
/// rebuilds one, because the variant's payload is the sealed
/// [`ActiveAdmissionReservation`] the owner verifier issues and it has no public
/// constructor.
///
/// It is the same read and the same owner verifier as
/// [`require_admission_reservation_launch`], differing only in what the caller
/// receives on success: the sealed typestate there, the enum variant here.
///
/// # Errors
///
/// Returns [`AdmissionReservationLaunchRefusal`] naming the owner's own state
/// when the reservation is not an exact `Active` row, and naming the typed ORS
/// refusal when the durable row is unreadable or violates its validator.
pub(crate) fn require_active_admission_reservation<S: OperationalRecoveryStore + ?Sized>(
    store: &S,
    reservation_id: &OperationIdentity,
    work_item_id: &OperationIdentity,
    proposed_attempt_id: &OperationIdentity,
    authority_epoch: &EpochLineage,
    state_fence: &StateFenceSnapshot,
    now_unix_ms: i64,
) -> Result<AdmissionReservationLaunchPrerequisite, AdmissionReservationLaunchRefusal> {
    let prerequisite = read_admission_reservation_launch_prerequisite(
        store,
        reservation_id,
        work_item_id,
        proposed_attempt_id,
        authority_epoch,
        state_fence,
        now_unix_ms,
    )
    .map_err(|error| AdmissionReservationLaunchRefusal::from_ors_error(reservation_id, &error))?;
    match prerequisite {
        AdmissionReservationLaunchPrerequisite::Active(active) => {
            Ok(AdmissionReservationLaunchPrerequisite::Active(active))
        }
        refused => Err(AdmissionReservationLaunchRefusal::from_prerequisite(
            reservation_id,
            &refused,
        )),
    }
}

/// Derives the durable ORS activation receipt reference for one activation.
///
/// It is a pure function of the reservation identity and the owner-issued
/// canonical admission receipt, so an exact replay after a lost response
/// rebuilds byte-identical bytes and the store returns the ORIGINAL active
/// snapshot instead of a second activation. It is an identity reference, not
/// authority: the sealed `Active` typestate is still issued only by the owner
/// verifier, and the reservation's claims, epoch and fence still decide
/// whether the activation may happen at all.
fn activation_receipt_identity(
    reservation_id: &OperationIdentity,
    canonical_admission_receipt: &ReceiptIdentity,
) -> Result<ReceiptIdentity, TransportError> {
    let canonical = canonical_json_bytes(canonical_admission_receipt)
        .map_err(|_| TransportError::SessionFenced)?;
    let mut preimage = ACTIVATION_RECEIPT_DOMAIN.as_bytes().to_vec();
    preimage.push(b'\n');
    preimage.extend_from_slice(reservation_id.as_str().as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(&canonical);
    let canonical_sha256 = sha256_hex(&preimage);
    Ok(ReceiptIdentity {
        receipt_id: ReceiptId::new(format!(
            "admission-reservation-activation-receipt:{}",
            &canonical_sha256[..16]
        ))
        .map_err(|_| TransportError::SessionFenced)?,
        canonical_sha256,
    })
}

impl OrsGenerationCoordinator {
    /// Loads and dispositions every durable admission reservation row at
    /// Kernel restart, without launching anything (#1678 REQ9, A2, A7, A12).
    ///
    /// Reached from composition assembly BEFORE the Kernel admits any
    /// overlapping work, so a reservation staged before a crash is loaded
    /// rather than silently forgotten. What it does:
    ///
    /// - enumerates the owner's `OPERATIONAL_CURRENT` rows through the
    ///   existing
    ///   [`eliot_ors::OperationalRecoveryStore::scan_operational_current`]
    ///   recovery inventory (payload-free, bounded, frozen to one snapshot);
    /// - selects only rows whose OWNER-RECORDED kind is
    ///   `admission_reservation`, so no other operational row is interpreted;
    /// - applies [`eliot_ors::disposition_admission_reservation_row`] to each
    ///   one, which loads the typed record and returns `Migrated`,
    ///   `Quarantined` or `Refused` — the explicit legacy compatibility
    ///   disposition of A12, so a retired opaque row is never silently read as
    ///   a typed reservation and never becomes active.
    ///
    /// What it does NOT do: it holds no process gateway, builds no process
    /// admission, calls no launch function, and writes no lifecycle position.
    /// The only durable state it can produce is the readback it already had.
    /// A recovered `StagedInactive` or `Reconciling` reservation therefore
    /// stays exactly as durable — reconcilable under its own identity, never
    /// launched as a side effect of being loaded. Launch is refused by name at
    /// every dispatch path by [`require_admission_reservation_launch`], which
    /// reads this same row.
    ///
    /// # Errors
    ///
    /// Returns the store's typed error when the recovery inventory moved under
    /// the enumeration, when a page is unreadable, or when a row's enumerated
    /// summary disagrees with its typed readback.
    pub(crate) fn recover_admission_reservations(&self) -> Result<usize, String> {
        use eliot_ors::{MAX_RECOVERY_PAGE, OperationalCurrentRecoveryCursor};
        observe_admission_saga("kernel.admission_reservation.recovery_requested", "attempt");
        let snapshot = self
            .ors
            .begin_recovery_inventory_snapshot()
            .map_err(|error| error.to_string())?;
        let mut cursor = OperationalCurrentRecoveryCursor::start(snapshot, MAX_RECOVERY_PAGE)
            .map_err(|error| error.to_string())?;
        let mut nonterminal = 0usize;
        loop {
            let page = self
                .ors
                .scan_operational_current(cursor.clone())
                .map_err(|error| error.to_string())?;
            for entry in &page.records {
                // The OWNER's own kind spelling selects the row; nothing here
                // interprets another operational kind.
                if entry.kind.as_str() != ADMISSION_RESERVATION_KIND {
                    continue;
                }
                let disposition =
                    eliot_ors::disposition_admission_reservation_row(self.ors.as_ref(), entry)
                        .map_err(|error| error.to_string())?;
                // A migrated row is the typed owner record read back; a
                // quarantined or refused row is a legacy record that is never
                // adopted. Either way the row stays exactly as durable and no
                // launch follows from loading it.
                if let AdmissionReservationRowDisposition::Migrated { snapshot } = disposition
                    && matches!(
                        snapshot.record().state,
                        AdmissionReservationState::StagedInactive
                            | AdmissionReservationState::Active
                            | AdmissionReservationState::Reconciling
                    )
                {
                    nonterminal += 1;
                }
            }
            match page.next_cursor {
                Some(next) => cursor = next,
                None => break,
            }
        }
        observe_admission_saga("kernel.admission_reservation.recovery_completed", "success");
        Ok(nonterminal)
    }
}

/// The four identities one admit request resolves to, derived once.
///
/// The canonical operation identity is DERIVED FROM THE RESERVATION ALONE, and
/// the payload's own copy must equal it. That is what makes a lost response
/// re-resolve THIS operation instead of admitting a second time (A3), and it is
/// why the payload cannot name a different admission: a mismatch is an identity
/// conflict raised before any store call happens.
///
/// `store_operation_id` is the CONTRACTS operation id, matching every other
/// canonical store call on this channel (`store_receipt_dispatch.rs` imports
/// `eliot_contracts::OperationId`). The process operation id is a different
/// identity for a child launch and must not be used for a store read.
struct AdmitIdentities {
    /// Owner-derived operation identity for the reservation.
    canonical_operation_id: OperationIdentity,
    /// The same identity in the store's own typed form.
    store_operation_id: eliot_contracts::OperationId,
    /// The work item this admission is for.
    work_item: OperationIdentity,
    /// The attempt this admission proposes.
    proposed_attempt: OperationIdentity,
}

impl AdmitIdentities {
    /// Derives and cross-checks every identity one admit request needs.
    fn derive(
        operation: &AdmissionReservationAdmitOperation,
        reservation_id: &OperationIdentity,
    ) -> Result<Self, TransportError> {
        let canonical_operation_id =
            stage_operation_identity(reservation_id).map_err(|_| TransportError::SessionFenced)?;
        if operation.canonical_operation_id != canonical_operation_id.as_str() {
            observe_admission_saga(
                "kernel.admission_reservation.admit_rejected:identity",
                "rejected",
            );
            return Err(TransportError::IdentityConflict);
        }
        let store_operation_id = eliot_contracts::OperationId::new(canonical_operation_id.as_str())
            .map_err(|_| TransportError::SessionFenced)?;
        let work_item = OperationIdentity::new(&operation.work_item_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let proposed_attempt = OperationIdentity::new(&operation.proposed_attempt_id)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(Self {
            canonical_operation_id,
            store_operation_id,
            work_item,
            proposed_attempt,
        })
    }
}

/// The owner-side facts one prove-and-read-back step needs.
///
/// Grouped rather than passed as ten positional parameters so the two DISTINCT
/// state fences stay visible at the call site: `ors_state_fence` is the fence
/// RECORDED on the staged reservation, and `state_fence` is the caller's live
/// fence used for the store read. They are different values, and conflating them
/// would let a live fence stand in for a durable one.
struct ProveAndReadBack {
    /// Reservation the admission belongs to.
    reservation_id: OperationIdentity,
    /// Work item the admission is for.
    work_item: OperationIdentity,
    /// Attempt the admission proposes.
    proposed_attempt: OperationIdentity,
    /// Owner-derived operation identity.
    canonical_operation_id: OperationIdentity,
    /// The retained commit to prove.
    commit: CanonicalAdmissionCommit,
    /// Authority epoch RECORDED on the staged row.
    authority_epoch: EpochLineage,
    /// State fence RECORDED on the staged row.
    ors_state_fence: StateFenceSnapshot,
    /// The same operation identity in the store's typed form.
    store_operation_id: eliot_contracts::OperationId,
    /// The caller's live fence, used only for the store read.
    state_fence: StateFence,
    /// Admission time in unix milliseconds.
    now_unix_ms: i64,
}

#[cfg(windows)]
impl KernelComposition {
    /// Reads back the canonical owner's `ADMITTED` receipt for one canonical
    /// operation through the retained production store gateway.
    ///
    /// This is the owner's own receipt readback (`KernelStoreGateway::receipt`
    /// → `store_receipt_gateway::receipt` → the active generation's canonical
    /// route), not a Kernel assertion. A transport failure is reported as
    /// `None`, which the ORS reconcile half classifies as `Unknown` — never as
    /// a non-commit (I5.19: an unknown commit is never assumed to be a
    /// non-commit), so an unreachable owner leaves the reservation inactive
    /// and launch blocked.
    async fn canonical_admission_receipt_readback(
        &self,
        state_fence: &StateFence,
        operation_id: &eliot_contracts::OperationId,
    ) -> Option<WriteReceipt> {
        // `retained_store_gateway` is the SAME `KernelComposition` method every
        // other canonical read on this channel uses
        // (`daemon_request_dispatch::KernelComposition::retained_store_gateway`).
        // It is called as a method, not imported as a free function, so this
        // readback reaches the canonical owner through the one retained
        // generation-routed gateway rather than opening a second client.
        let gateway = self.retained_store_gateway().ok()?;
        // The gateway returns `Result<Option<WriteReceipt>>`: `Err` is a
        // transport failure and `Ok(None)` is "the owner holds no receipt for
        // this operation". Both are absent proof here, and the ORS reconcile
        // half classifies absence as `Unknown` — never as a non-commit (I5.19) —
        // so an unreachable owner leaves the reservation inactive and launch
        // blocked. Neither case is a presumed commit and neither is a presumed
        // non-commit.
        gateway
            .receipt(state_fence, operation_id.clone())
            .await
            .ok()
            .flatten()
    }

    /// Admits one staged reservation through the canonical owner and activates
    /// it from the resulting owner evidence (#1678 W3, W5, REQ4, REQ6, A3, A4,
    /// A7).
    ///
    /// This is the middle and last leg of the I14.6 saga, and the production
    /// caller of the three ORS admit/activate owners. The order is fixed, and
    /// the guarantees depend on it:
    ///
    /// 1. **Re-derive, never trust.** The reservation identity and the
    ///    canonical operation identity are DERIVED from the durable claim
    ///    binding, not accepted from the payload. A payload naming a different
    ///    canonical operation is refused before any store IO, so the payload
    ///    can never redirect the saga to a second admission.
    /// 2. **Read back before activating (A3).** The owner's own `WriteReceipt`
    ///    for the ORIGINAL canonical operation is read back first, and the saga
    ///    is classified through [`eliot_ors::reconcile_canonical_admission`],
    ///    which decides committed-with-launch-intent, proven non-commit,
    ///    terminal, or unknown.
    /// 3. **Prove the commit belongs to THIS reservation.**
    ///    [`eliot_ors::prove_canonical_admission_for_reservation`] re-reads the
    ///    staged row, proves the exact launch outbox row for this operation
    ///    from the owner's own receipt, and builds the retained commit from
    ///    that receipt.
    /// 4. **Re-read the committed content BY VALUE.** The retained commit is
    ///    compared against a SECOND readback of the same operation through
    ///    [`eliot_ors::launch_outbox_readback`], so a commit whose content
    ///    disagrees with the retained evidence is refused rather than
    ///    activated on.
    /// 5. **Activate exactly once.** The activation is issued under
    ///    [`eliot_ors::activation_operation_identity`] (bound to the
    ///    reservation alone, so the store's own same-identity-changed-content
    ///    conflict fires), carrying the retained commit and both owner
    ///    receipts, and the durable outcome it returns is the activation
    ///    receipt/reference #1701 later verifies.
    ///
    /// Every step is idempotent under its own identity, so an exact replay of
    /// the whole operation returns the original active snapshot and receipt
    /// and never a second reservation, admission or activation (A7).
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SessionFenced`] for a shape, identity,
    /// session-fence or storage failure, and a typed saga refusal otherwise:
    /// a terminal canonical outcome, an unresolved commit, or a launch gate
    /// that refuses the resulting row. It never returns a partial success.
    pub(crate) async fn admission_reservation_admit_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        use super::daemon_request_dispatch::{
            validate_store_session_fence, without_daemon_routing_key,
        };
        observe_admission_saga("kernel.admission_reservation.admit_requested", "attempt");
        let operation: AdmissionReservationAdmitOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &operation.state_fence)?;
        // Boxed so this entry's own future stays small. The admit/activate
        // sequence holds the full staged row, its owner receipts and the launch
        // gate across several awaits, and an unboxed future would carry all of
        // that on the caller's stack for the whole operation.
        let disposition =
            Box::pin(self.admission_reservation_admit_inner(&operation, &operation.state_fence))
                .await?;
        Ok(serde_json::json!({
            "kind": "admission_reservation_admit",
            "value": disposition,
        }))
    }

    /// Proves the committed ADMITTED decision belongs to THIS reservation, then
    /// re-reads the committed content and compares it BY VALUE against the
    /// retained evidence (A3).
    ///
    /// Both halves matter and neither is implied by the other. The proof says the
    /// commit this operation retained is the one the owner holds for these exact
    /// identities; the read-back says the owner's CURRENT committed content still
    /// equals it. A receipt that is well formed but describes different content
    /// is refused here rather than activated.
    async fn prove_and_read_back(
        &self,
        facts: ProveAndReadBack,
    ) -> Result<ProvenCanonicalAdmission, TransportError> {
        let ProveAndReadBack {
            reservation_id,
            work_item,
            proposed_attempt,
            canonical_operation_id,
            commit,
            authority_epoch,
            ors_state_fence,
            store_operation_id,
            state_fence,
            now_unix_ms,
        } = facts;
        let proven = prove_canonical_admission_for_reservation(
            self.generation_gateway.ors.as_ref(),
            &reservation_id,
            &work_item,
            &proposed_attempt,
            &canonical_operation_id,
            &commit,
            &authority_epoch,
            &ors_state_fence,
            now_unix_ms,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let second_readback = self
            .canonical_admission_receipt_readback(&state_fence, &store_operation_id)
            .await;
        launch_outbox_readback(second_readback.as_ref(), &proven.canonical_admission).map_err(
            |_| {
                observe_admission_saga(
                    "kernel.admission_reservation.admit_rejected:readback_mismatch",
                    "rejected",
                );
                TransportError::IdentityConflict
            },
        )?;
        Ok(proven)
    }

    /// Drives the admit/activate sequence for one already-validated request.
    async fn admission_reservation_admit_inner(
        &self,
        operation: &AdmissionReservationAdmitOperation,
        state_fence: &StateFence,
    ) -> Result<serde_json::Value, TransportError> {
        let reservation_id = OperationIdentity::new(&operation.reservation_id)
            .map_err(|_| TransportError::SessionFenced)?;
        let AdmitIdentities {
            canonical_operation_id,
            store_operation_id,
            work_item,
            proposed_attempt,
        } = AdmitIdentities::derive(operation, &reservation_id)?;

        // The owner readback for the ORIGINAL operation identity. An absent
        // receipt is `Unknown`, never a presumed non-commit.
        let readback = self
            .canonical_admission_receipt_readback(state_fence, &store_operation_id)
            .await;
        let committed_receipt = readback.ok_or_else(|| {
            // The owner classifies an absent receipt as `Unknown`; this is the
            // same refusal, made before the reconcile call can be skipped. An
            // absent receipt is never a fabricated commit.
            observe_admission_saga(
                "kernel.admission_reservation.admit_rejected:unknown",
                "rejected",
            );
            TransportError::IdentityConflict
        })?;
        let resolution = reconcile_canonical_admission(
            Some(&committed_receipt),
            canonical_operation_id.as_str(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if let Some(refused) =
            Self::classify_canonical_admission_outcome(&reservation_id, resolution)
        {
            return Ok(refused);
        }

        // The reservation's OWN durable authority binding, read back through the
        // owner's generic read-back (`reload_staged_admission_reservation`),
        // NOT presented. That read re-reads the typed row, runs the owner's own
        // `validate()` and `verify_staged_claim_completeness()`, and returns the
        // store-issued receipt — so the epoch, fence and claims below are the
        // ORIGINAL recorded values, and the ORS owners re-check them against the
        // staged row before any mutation. A stale epoch or fence fails BEFORE
        // the write rather than after it. No inherent store method is added to
        // obtain this read-back.
        let now_unix_ms =
            i64::try_from(super::unix_ms()).map_err(|_| TransportError::SessionFenced)?;
        let staged = reload_staged_admission_reservation(
            self.generation_gateway.ors.as_ref(),
            &reservation_id,
            now_unix_ms,
        )
        .map_err(|error| match error {
            // A reservation that is not durably staged is a typed refusal, not a
            // reason to create one here: staging on this path would mint a second
            // reservation instead of activating the one the saga already staged.
            OrsError::ReservationNotFound => TransportError::UnknownRequest,
            _ => TransportError::SessionFenced,
        })?;
        let authority_epoch = staged.record().authority_epoch.clone();
        let ors_state_fence = staged.record().state_fence.clone();

        // Prove the committed `ADMITTED` decision and its exact launch outbox
        // belong to THIS reservation, and build the retained commit from the
        // owner's OWN receipt. Nothing is fabricated in Kernel and nothing is
        // inferred from a successful transport response.
        let commit = CanonicalAdmissionCommit {
            receipt: committed_receipt,
            admission_receipt: operation.admission_receipt.clone(),
        };
        // Prove the committed `ADMITTED` decision belongs to THIS reservation,
        // then re-read the committed content and compare it BY VALUE against the
        // retained evidence. That second read is the other half of A3: the commit
        // is read back before activation, and a receipt whose content disagrees
        // with what this reservation retained is a typed refusal, not a pass.
        let proven = self
            .prove_and_read_back(ProveAndReadBack {
                reservation_id: reservation_id.clone(),
                work_item: work_item.clone(),
                proposed_attempt: proposed_attempt.clone(),
                canonical_operation_id: canonical_operation_id.clone(),
                commit: commit.clone(),
                authority_epoch: authority_epoch.clone(),
                ors_state_fence: ors_state_fence.clone(),
                store_operation_id: store_operation_id.clone(),
                state_fence: state_fence.clone(),
                now_unix_ms,
            })
            .await?;

        // Activate exactly once, under the reservation-bound activation
        // operation identity, carrying the retained commit. The store's own
        // same-identity-changed-content conflict is what distinguishes an exact
        // replay (original snapshot and receipt returned) from changed evidence
        // (refused), so a second activation can never be minted under one
        // reservation.
        let activation_request = Self::admission_reservation_activation_request(
            operation,
            &reservation_id,
            &work_item,
            &proposed_attempt,
            &proven,
            staged.record(),
            now_unix_ms,
        )?;
        let activated = activate_admission_reservation_from_owner_evidence(
            self.generation_gateway.ors.as_ref(),
            &activation_request,
        )
        .map_err(|_| {
            observe_admission_saga(
                "kernel.admission_reservation.admit_rejected:activation",
                "rejected",
            );
            TransportError::IdentityConflict
        })?;

        // The durable activation receipt/reference is read back out of the
        // committed row, not echoed from the request, so the reply carries
        // committed state (A4).
        let activation_receipt = activated
            .activation_receipt()
            .map_err(|_| TransportError::SessionFenced)?;
        let canonical_admission_receipt = activated
            .canonical_admission_receipt()
            .map_err(|_| TransportError::SessionFenced)?;
        observe_admission_saga("kernel.admission_reservation.admit_activated", "success");
        Ok(serde_json::json!({
            "reservation_id": reservation_id.as_str(),
            "disposition": "ACTIVATED",
            "canonical_operation_id": canonical_operation_id.as_str(),
            "launch_outbox_id": proven.canonical_admission.launch_outbox_id,
            "commit_id": proven.canonical_admission.commit_id,
            "activation_receipt": activation_receipt,
            "canonical_admission_receipt": canonical_admission_receipt,
            "launch_authorized": true,
        }))
    }

    /// Classifies one resolved canonical admission outcome (A3, I14.21).
    ///
    /// `None` means the owner resolved the operation as `Committed` with its
    /// exact launch intent proven, and the caller may proceed to prove and
    /// activate. Every other outcome returns its OWN disposition, keeping the
    /// reservation inactive and launch blocked:
    ///
    /// - a proven non-commit under the SAME identity is the only outcome that
    ///   permits a retry, and it reuses that identity; the owner decided it from
    ///   its own `Resubmission` disposition. This route does not re-admit from
    ///   here, so the reservation stays inactive either way;
    /// - a terminal rejection, rollback or dead-letter keeps its exact
    ///   identity and error-code presence;
    /// - an unknown outcome stays `UNKNOWN_COMMIT`, which is NOT collapsed into
    ///   a terminal or a non-commit: an absent or unreadable receipt is an
    ///   unresolved outcome still reconcilable under the same identity (I5.19).
    fn classify_canonical_admission_outcome(
        reservation_id: &OperationIdentity,
        resolution: CanonicalAdmissionResolution,
    ) -> Option<serde_json::Value> {
        match resolution {
            CanonicalAdmissionResolution::Committed => None,
            CanonicalAdmissionResolution::ProvenNonCommit => {
                observe_admission_saga(
                    "kernel.admission_reservation.admit_rejected:noncommit",
                    "rejected",
                );
                Some(Self::admit_refusal_projection(
                    reservation_id,
                    "PROVEN_NON_COMMIT",
                    false,
                ))
            }
            CanonicalAdmissionResolution::TerminalFailure { error_code } => {
                observe_admission_saga(
                    "kernel.admission_reservation.admit_rejected:terminal",
                    "rejected",
                );
                Some(Self::admit_refusal_projection(
                    reservation_id,
                    "TERMINAL_FAILURE",
                    error_code.is_some(),
                ))
            }
            CanonicalAdmissionResolution::Unknown { .. } => {
                observe_admission_saga(
                    "kernel.admission_reservation.admit_rejected:unknown",
                    "rejected",
                );
                Some(Self::admit_refusal_projection(
                    reservation_id,
                    "UNKNOWN_COMMIT",
                    false,
                ))
            }
        }
    }

    /// Builds the activation request for one proven canonical admission (A4,
    /// A7).
    ///
    /// Every field is either an identity this route re-derived from the durable
    /// reservation, a value READ BACK from the reservation's own durable record
    /// (`claims`, `authority_epoch`, `state_fence` — never recomputed), or the
    /// owner's own evidence (`expected_current_receipt` and the proven canonical
    /// admission). The activation operation identity is bound to the RESERVATION
    /// ALONE, so the store's existing same-identity-changed-content conflict is
    /// what distinguishes an exact replay (original active snapshot and receipt
    /// returned) from changed evidence (refused).
    fn admission_reservation_activation_request(
        operation: &AdmissionReservationAdmitOperation,
        reservation_id: &OperationIdentity,
        work_item_id: &OperationIdentity,
        proposed_attempt_id: &OperationIdentity,
        proven: &eliot_ors::ProvenCanonicalAdmission,
        staged: &eliot_ors::AdmissionReservationRecord,
        now_unix_ms: i64,
    ) -> Result<eliot_ors::AdmissionReservationActivationRequest, TransportError> {
        let activation_operation = activation_operation_identity(reservation_id)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(eliot_ors::AdmissionReservationActivationRequest {
            reservation_id: reservation_id.clone(),
            work_item_id: work_item_id.clone(),
            proposed_attempt_id: proposed_attempt_id.clone(),
            operation_id: activation_operation,
            // The ORIGINAL recorded claim set, read back from the durable row.
            claims: staged.claims.clone(),
            canonical_admission_receipt: operation.admission_receipt.clone(),
            canonical_admission: Some(proven.canonical_admission.clone()),
            // The ORS activation receipt is the durable reference the activation
            // commits with the active row; it is derived from the reservation and
            // the owner-issued canonical receipt, so an exact replay rebuilds it
            // byte-identically instead of minting a second one.
            activation_receipt: activation_receipt_identity(
                reservation_id,
                &operation.admission_receipt,
            )?,
            expected_current_receipt: proven.expected_current_receipt.clone(),
            authority_epoch: staged.authority_epoch.clone(),
            state_fence: staged.state_fence.clone(),
            now_ms: now_unix_ms,
        })
    }

    /// Projects one refused canonical admission outcome.
    ///
    /// Each non-committed outcome keeps its OWN disposition. Reporting a
    /// terminal rejection or a proven non-commit as `UNKNOWN_COMMIT` would
    /// tell the caller to keep reconciling an operation that can never commit,
    /// which is the blind duplicate effect I14.21 forbids; reporting a merely
    /// absent receipt as terminal would strand an operation that is still
    /// reconcilable under the same identity.
    fn admit_refusal_projection(
        reservation_id: &OperationIdentity,
        disposition: &str,
        error_code_present: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "reservation_id": reservation_id.as_str(),
            "disposition": disposition,
            "error_code_present": error_code_present,
            "launch_authorized": false,
        })
    }
}

#[cfg(not(windows))]
impl KernelComposition {
    /// Non-Windows placeholder: the canonical store route does not exist here,
    /// so the admit/activate coordinator fails closed rather than pretending to
    /// have an owner receipt.
    pub(crate) async fn admission_reservation_admit_operation(
        &self,
        _session: &Session,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Err(TransportError::SessionFenced)
    }
}
