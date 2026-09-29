//! Retained solo-slice live pointer (issue #2567, AUD6 wiring).
//!
//! Architecture: I10.15 owns the fabric and admission saga; this module is
//! wiring, not a second scheduler, task store, attempt journal, write
//! authority, provider runner, or recovery path. It holds the composition's
//! single in-memory live binding for the solo slice: refreshed when a drive,
//! poll, or restore admits (or re-admits) an attempt, consulted on every
//! status/cancel/ingest readback. The durable projection under the daemon
//! state root stays the truth — a restart clears this pointer and control
//! calls fall back to the persisted projection — so the pointer can refuse a
//! same-operation identity divergence but can never invent, revive, or widen
//! an attempt.
//!
//! The pointer embeds the frozen solo route binding
//! ([`crate::agent_fabric::solo_slice_port_freeze`]) it was retained under,
//! so the route an attempt was admitted on travels with the live slot. No
//! owner RPC happens here and no lock is held across an await (these paths
//! are synchronous and bounded), keeping daemon health, shutdown, and
//! cancellation pollable while the slot is consulted.

use eliot_governor::CompositionError;

use crate::DaemonError;
use crate::agent_fabric::{FabricError, SoloSlicePortFreeze, solo_slice_port_freeze};
use crate::solo_agent_driver::{SOLO_RECIPE_ID, SoloAttemptStatus, SoloDriveOutcome};

/// In-memory live binding of the admitted solo slice.
///
/// At most one exists per daemon: it names the exact durable attempt the
/// live slot serves plus the frozen route binding it was admitted under. It
/// is never persisted and never crosses a restart; the state-root projection
/// remains the only durable record.
#[derive(Clone, Debug)]
pub struct SoloSliceLivePointer {
    /// Exact external-effect operation identity driving the live slot.
    pub operation_id: String,
    /// Registered attempt identity bound to the operation.
    pub attempt_id: String,
    /// Stable dispatch identity retained at the handoff.
    pub dispatch_id: String,
    /// Frozen recipe the attempt was admitted under.
    pub recipe_id: &'static str,
    /// Frozen six-port table the attempt was admitted under.
    pub port_freeze: [SoloSlicePortFreeze; 6],
}

/// Maps a poisoned live-pointer slot to the typed recovery rejection.
pub(crate) fn slice_slot_poisoned() -> DaemonError {
    DaemonError::Composition(CompositionError::Recovery(
        "solo slice live pointer lock poisoned".to_owned(),
    ))
}

/// Retains the live pointer after a successful admitted drive.
///
/// The outcome already carries the correlated identities plus retention
/// evidence; this binds them to the frozen solo route without re-reading any
/// owner. The caller stores the pointer on the composition's single slot.
#[must_use]
pub fn retain_solo_slice_live(outcome: &SoloDriveOutcome) -> SoloSliceLivePointer {
    SoloSliceLivePointer {
        operation_id: outcome.operation_id.clone(),
        attempt_id: outcome.attempt_id.clone(),
        dispatch_id: outcome.dispatch_id.clone(),
        recipe_id: SOLO_RECIPE_ID,
        port_freeze: solo_slice_port_freeze(),
    }
}

/// Rebuilds the live pointer from a durable readback plus a known dispatch.
///
/// Used where only a status is at hand (runtime poll tick, post-restart
/// restore): the operation/attempt identities come from the retained
/// projection the status just read, never from a fresh claim. `dispatch_id`
/// must be carried from the existing slot or the drive outcome; callers pass
/// nothing invented.
#[must_use]
pub fn pointer_from_solo_status(
    status: &SoloAttemptStatus,
    dispatch_id: &str,
) -> SoloSliceLivePointer {
    SoloSliceLivePointer {
        operation_id: status.operation_id.clone(),
        attempt_id: status.attempt_id.clone(),
        dispatch_id: dispatch_id.to_owned(),
        recipe_id: SOLO_RECIPE_ID,
        port_freeze: solo_slice_port_freeze(),
    }
}

/// Refuses a same-operation identity or route divergence against the live pointer.
///
/// Reads the retained attempt: when the slot names this operation but the
/// durable projection serves a different attempt, the projection moved under
/// a live slot and control refuses instead of acting on the wrong attempt.
/// The pointer's frozen recipe and port table are re-pinned on every consult
/// as well, so a revision move under a live attempt refuses instead of
/// serving silently. A missing slot (restart) or a different operation
/// (settled history) defers to the durable projection unchanged. Lifecycle
/// evolution (retention, acknowledgement, result, cancellation) is normal
/// and never trips this gate: only the attempt identity and the frozen route
/// binding are pinned here.
pub fn check_retained_solo_slice(
    slot: Option<&SoloSliceLivePointer>,
    status: &SoloAttemptStatus,
) -> Result<(), DaemonError> {
    let Some(live) = slot else {
        return Ok(());
    };
    if live.operation_id != status.operation_id {
        return Ok(());
    }
    if live.attempt_id != status.attempt_id {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(format!(
                "solo slice live pointer binds attempt {} but the retained projection serves {} for operation {}",
                live.attempt_id, status.attempt_id, status.operation_id
            )),
        ));
    }
    if live.recipe_id != SOLO_RECIPE_ID {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            format!(
                "solo slice live pointer retained under recipe {}; only {SOLO_RECIPE_ID} is served",
                live.recipe_id
            ),
        )));
    }
    if live.port_freeze != solo_slice_port_freeze() {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo slice freeze moved under the live attempt; settle or re-admit under the current freeze"
                .to_owned(),
        )));
    }
    Ok(())
}
