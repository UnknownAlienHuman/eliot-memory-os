//! `ControlBoard` status read consumer (issue #1213).
//!
//! Bins-local composition helper for the `eliot controlboard status` operator
//! command: decode one served board and project it to terminal JSON. The
//! serving runtime (Ramanujan/Kernel lane) produces the board with
//! [`read_controlboard_status`](eliot_runtime_status::read_controlboard_status),
//! frames it with the owner transport, and answers the
//! [`CONTROLBOARD_STATUS_OPERATION`](eliot_runtime_status::CONTROLBOARD_STATUS_OPERATION)
//! request; this module only consumes. No `ControlBoard` handle, cache, or
//! canonical state lives here: every call renders exactly the board it was
//! given, dispositions reproduced verbatim with no health synthesis.
//!
//! Decode trusts the transport envelope correlation already enforced by the
//! `transact` path and checks the two contract identities with the owner's
//! own constants and message type. Anything else is refused with a typed
//! decode error; decode/binding failures stay non-success and never become a
//! board.

use eliot_runtime_status::{
    ControlBoardTransportMessage, RenderedControlBoard, CONTROLBOARD_CONSUMER_CONTRACT,
    CONTROLBOARD_TRANSPORT_CONTRACT,
};

/// Re-exported operation selector so the composition root names the exact
/// contract operation without repeating its spelling.
pub use eliot_runtime_status::CONTROLBOARD_STATUS_OPERATION as STATUS_OPERATION;

/// Typed decode/binding failure. Any variant refuses the board instead of
/// projecting partial, inferred, or mismatched evidence.
#[derive(Debug, thiserror::Error)]
pub enum ControlBoardStatusError {
    /// The served value is not the agreed transport message, or a contract
    /// identity does not match the owner constants.
    #[error("controlboard status decode refused: {0}")]
    Decode(String),
}

/// Decodes one served transact payload into the reconciled board it carries.
///
/// The payload is the `Json` result body the authenticated transact path
/// already correlated to this request. Deserialization uses the owner's
/// message type and the contract checks use the owner's constants; this
/// function duplicates no serializer, framing, or handshake logic.
pub fn decode_status_response(
    value: serde_json::Value,
) -> Result<RenderedControlBoard, ControlBoardStatusError> {
    let message: ControlBoardTransportMessage = serde_json::from_value(value)
        .map_err(|error| ControlBoardStatusError::Decode(error.to_string()))?;
    if message.contract != CONTROLBOARD_TRANSPORT_CONTRACT {
        return Err(ControlBoardStatusError::Decode(format!(
            "transport contract mismatch: {}",
            message.contract
        )));
    }
    if message.board.contract != CONTROLBOARD_CONSUMER_CONTRACT {
        return Err(ControlBoardStatusError::Decode(format!(
            "consumer lineage mismatch: {}",
            message.board.contract
        )));
    }
    Ok(message.board)
}

/// Projects one reconciled board to terminal JSON.
///
/// Every row keeps its typed disposition label plus the exact observer and
/// projection identity fields; counts, unexpected entries, expiry, and
/// invalidation are reproduced verbatim. No health, readiness, support, or
/// product scalar is synthesized: a rendered label is an observation state,
/// never a verdict.
pub fn render_status_json(
    board: &RenderedControlBoard,
) -> Result<serde_json::Value, ControlBoardStatusError> {
    let rows: Result<Vec<serde_json::Value>, ControlBoardStatusError> = board
        .rows
        .iter()
        .map(|row| {
            Ok(serde_json::json!({
                "entry_id": row.entry_id,
                "disposition": row.disposition.label(),
                "summary": row.summary,
                "installation": row.installation.as_str(),
                "observed_at": row.observed_at.get(),
                "source_digest": row.source_digest.as_str(),
                "recovery_owner": row.recovery_owner.as_str(),
                "view_revision": row.view_revision,
                "contour_digest": row.contour_digest,
            }))
        })
        .collect();
    let view_fence = serde_json::to_value(&board.view_fence)
        .map_err(|error| ControlBoardStatusError::Decode(error.to_string()))?;
    Ok(serde_json::json!({
        "contract": "eliot.controlboard.status",
        "contract_version": "1.0.0",
        "board_contract": board.contract,
        "view_revision": board.view_revision,
        "view_fence": view_fence,
        "contour_digest": board.contour_digest,
        "observed_count": board.observed_count,
        "missing_count": board.missing_count,
        "unexpected_observed": board.unexpected_observed,
        "expiry": board.expiry,
        "invalidation": board.invalidation,
        "rows": rows?,
    }))
}

/// Request payload for the status operation. The operation carries no
/// caller parameters: the serving runtime reconciles the full frozen
/// denominator on every request.
#[must_use]
pub fn status_request_payload() -> serde_json::Value {
    serde_json::json!({})
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "small pure consumer tests use explicit fixtures"
)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
    use eliot_runtime_status::{
        build_controlboard_frame, open_controlboard_frame, ControlBoardInstallation,
        ControlBoardObservationTime, ControlBoardRecoveryOwner, ControlBoardRowDisposition,
        ControlBoardSourceDigest, RenderedControlBoardRow,
    };

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("test epoch");
        StateFence::new(epoch, ResourceGeneration::new(7).expect("test generation"))
    }

    fn row(
        entry_id: &str,
        disposition: ControlBoardRowDisposition,
        summary: Option<&str>,
    ) -> RenderedControlBoardRow {
        RenderedControlBoardRow {
            entry_id: entry_id.to_owned(),
            disposition,
            summary: summary.map(str::to_owned),
            installation: ControlBoardInstallation::new("installation-consumer-test")
                .expect("installation"),
            observed_at: ControlBoardObservationTime::new(1_786_000_000_002).expect("observed_at"),
            source_digest: ControlBoardSourceDigest::new("cd".repeat(32)).expect("digest"),
            recovery_owner: ControlBoardRecoveryOwner::new("recovery-owner-consumer")
                .expect("recovery owner"),
            view_revision: 9,
            contour_digest: "ef".repeat(32),
        }
    }

    fn board() -> RenderedControlBoard {
        RenderedControlBoard {
            contract: CONTROLBOARD_CONSUMER_CONTRACT.to_owned(),
            view_revision: 9,
            view_fence: fence(),
            contour_digest: "ef".repeat(32),
            rows: vec![
                row(
                    "item-stale",
                    ControlBoardRowDisposition::Stale,
                    Some("stale evidence"),
                ),
                row("ghost-component", ControlBoardRowDisposition::Missing, None),
            ],
            observed_count: 1,
            missing_count: 1,
            unexpected_observed: vec!["extra-entry".to_owned()],
            expiry: "re-read required after fence or generation change".to_owned(),
            invalidation: "revision/fence change, generation rotation, owner rebind".to_owned(),
        }
    }

    fn message_value(board: &RenderedControlBoard) -> serde_json::Value {
        serde_json::to_value(&ControlBoardTransportMessage {
            contract: CONTROLBOARD_TRANSPORT_CONTRACT.to_owned(),
            board: board.clone(),
        })
        .expect("message serializes")
    }

    #[test]
    fn decode_accepts_owner_contracts() {
        let board = decode_status_response(message_value(&board())).expect("owner board decodes");
        assert_eq!(board.contract, CONTROLBOARD_CONSUMER_CONTRACT);
        assert_eq!(board.rows.len(), 2);
        assert_eq!(board.contour_digest, "ef".repeat(32));
    }

    #[test]
    fn decode_refuses_foreign_contracts_and_shapes() {
        let mut forged_transport = message_value(&board());
        forged_transport["contract"] = serde_json::json!("forged.transport/v9");
        assert!(decode_status_response(forged_transport).is_err());

        let mut foreign_board = board();
        foreign_board.contract = "forged.board/v9".to_owned();
        assert!(decode_status_response(message_value(&foreign_board)).is_err());

        assert!(decode_status_response(serde_json::json!({"contract": "x"})).is_err());
        assert!(decode_status_response(serde_json::json!([])).is_err());
    }

    #[test]
    fn frame_loopback_through_owner_handshake_decodes() {
        // Real consumer proof through the exact shared handshake: the owner
        // frame builder (serving side) feeds the owner frame opener, and the
        // opened board decodes and renders with labels intact. No pipe, no
        // duplicated framing.
        let sent = board();
        let connection_id = "connection-consumer-test";
        let request_id = RequestId::new("req-consumer-1").expect("request id");
        let frame =
            build_controlboard_frame(&sent, connection_id, &request_id).expect("build frame");
        let opened =
            open_controlboard_frame(&frame, connection_id, &request_id).expect("open frame");
        assert_eq!(opened, sent);
        let rendered = render_status_json(&opened).expect("render opened board");
        assert_eq!(rendered["rows"][0]["disposition"], "STALE");
        assert_eq!(rendered["rows"][1]["disposition"], "MISSING");
    }

    #[test]
    fn render_preserves_labels_fields_and_no_health_scalar() {
        let rendered = render_status_json(&board()).expect("board renders");
        assert_eq!(rendered["contract"], "eliot.controlboard.status");
        assert_eq!(rendered["board_contract"], CONTROLBOARD_CONSUMER_CONTRACT);
        assert_eq!(rendered["observed_count"], 1);
        assert_eq!(rendered["missing_count"], 1);
        let rows = rendered["rows"].as_array().expect("rows array");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entry_id"], "item-stale");
        assert_eq!(rows[0]["disposition"], "STALE");
        assert_eq!(rows[0]["summary"], "stale evidence");
        assert_eq!(rows[0]["installation"], "installation-consumer-test");
        assert_eq!(rows[0]["observed_at"], 1_786_000_000_002u64);
        assert_eq!(rows[0]["source_digest"], "cd".repeat(32));
        assert_eq!(rows[0]["recovery_owner"], "recovery-owner-consumer");
        assert_eq!(rows[1]["disposition"], "MISSING");
        assert_eq!(rows[1]["summary"], serde_json::Value::Null);
        for key in ["healthy", "health", "readiness", "support", "product"] {
            assert!(
                rendered.get(key).is_none(),
                "rendered board must not synthesize {key}"
            );
        }
    }

    #[test]
    fn status_operation_selector_is_owner_constant() {
        assert_eq!(
            STATUS_OPERATION,
            eliot_runtime_status::CONTROLBOARD_STATUS_OPERATION
        );
        assert_eq!(STATUS_OPERATION, "controlboard.status");
        assert!(status_request_payload()
            .as_object()
            .expect("object")
            .is_empty());
    }
}
