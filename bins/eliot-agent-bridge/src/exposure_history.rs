//! Exposure-history entry-lifecycle join for issue #1745 (R7).
//!
//! This seam binds one evaluated tool on one surface to its owner-joined
//! turn/run/attempt/surface identities and packages owner-populated entries
//! as replay-safe revisions for the existing observation/receipt/outbox path.
//! It sets no stage itself: every registered/advertised/eligible/selected/
//! called/transport/delivery/retry/use/outcome fact arrives populated only by
//! its respective owner through the matching `record_*` stager, with its
//! source reference and unknown coverage intact. Unknown stays unknown —
//! nothing is inferred from another stage, `None` never coerces to `false`,
//! and model-authored success flags without an owner source fail validation
//! at the entry boundary. Observable use needs a public
//! action/decision/verifier link carried by the use owner's source reference.
//!
//! This boundary performs no store write and owns no second ledger: the
//! observation/receipt/outbox owner persists `FirstRevision` and
//! `SuccessorRevision` entries alongside the retained prior and reconciles
//! the original event on `IdempotentReplay` (lost acknowledgements reconcile
//! the original event; unavailable writeback stays a visible pending
//! obligation on the owning seam).

#![forbid(unsafe_code)]

use eliot_agent_bridge_core::BridgeError;
use eliot_receipts::tool_exposure::{
    ExposureHistoryRevision, ExposureIdentities, ToolExposureError, ToolExposureHistoryEntry,
    persist_exposure_history_revision,
};

/// Opens a fresh exposure-history entry with owner-joined identities (I7.24).
///
/// Tool identity, definition version, joining route, and the owner-supplied
/// turn/run/attempt/surface identities arrive from their owners — this seam
/// mints none of them. All ten stages stay explicitly unresolved unknown
/// coverage; each stage owner then populates only its own stage with its
/// source reference before the revision persists. The surface identity is
/// always required: history about no surface proves nothing. The owning seam
/// holding the turn/run/attempt identities is the STITCH caller.
///
/// # Errors
///
/// Returns a typed [`BridgeError`] when an identity, version, or route text
/// is blank or carries control characters, or when the surface identity is
/// missing.
pub fn open_exposure_history_entry(
    tool_definition: String,
    definition_version: String,
    route_fingerprint: Option<String>,
    identities: ExposureIdentities,
) -> Result<ToolExposureHistoryEntry, Box<BridgeError>> {
    ToolExposureHistoryEntry::unpopulated(
        tool_definition,
        definition_version,
        route_fingerprint,
        identities,
    )
    .map_err(|error| Box::new(map_history_error(&error, "history.identities")))
}

/// Packages one owner-populated history entry as a replay-safe revision for
/// the existing observation/receipt/outbox path (I7.24).
///
/// The entry is classified against the recorded prior on its revision
/// lineage — tool definition and version, route, and the owner-joined
/// turn/run/attempt/surface identities — then bound to its lineage and
/// content digests. An identical redelivery yields the identical key and
/// reconciles the original event instead of executing again; any recorded
/// difference persists as a linked successor revision, never as a rewrite, so
/// a replay produces neither duplicate execution nor false usage evidence.
/// The observation/receipt/outbox owner performs the durable write and is the
/// STITCH caller.
///
/// # Errors
///
/// Returns a typed [`BridgeError`] when either revision is inconsistent, the
/// two entries belong to different revision lineages, or canonical bytes
/// cannot be produced.
pub fn package_exposure_history_revision(
    previous: Option<&ToolExposureHistoryEntry>,
    current: &ToolExposureHistoryEntry,
) -> Result<ExposureHistoryRevision, Box<BridgeError>> {
    persist_exposure_history_revision(previous, current)
        .map_err(|error| Box::new(map_history_error(&error, "history.revision")))
}

/// Maps an exposure-history validation failure into the bridge's typed error
/// (I7.20), mirroring
/// `bins/eliot-agent-bridge/src/lib.rs::BridgeRunner::map_exposure_history_error`.
/// [`ToolExposureError::InvalidField`] carries its stable field path and
/// reason across the boundary losslessly; unreachable variants fail closed on
/// the joining stage instead of inventing a mapping.
fn map_history_error(error: &ToolExposureError, stage: &'static str) -> BridgeError {
    match *error {
        ToolExposureError::InvalidField { field, reason } => {
            BridgeError::InvalidContract { field, reason }
        }
        _ => BridgeError::InvalidContract {
            field: stage,
            reason: "exposure history fact failed its owner validation",
        },
    }
}
