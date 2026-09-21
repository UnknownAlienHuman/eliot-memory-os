//! Producer-side transport for the reconciled `ControlBoard` board.
//!
//! Issue #1213 transport follow-through: [`RenderedControlBoard`] is produced
//! in-process by [`read_controlboard_status`](super::read_controlboard_status)
//! but Operator/CLI surfaces live across the process boundary. This module is
//! the exact producer/surface handshake that carries one reconciled board over
//! the existing `eliot-ipc` EBP/1 transport from the runtime-status-owning
//! process. It owns no pipe, process, authentication, admission, or lifecycle
//! state; it only frames, versions, and validates one board message.
//!
//! Handshake (shared with the surface owner; both sides enforce every line):
//!
//! * EBP/1 wire via [`eliot_ipc::encode_frame`] / [`eliot_ipc::decode_frame`]
//!   under caller-supplied [`TransportLimits`](eliot_ipc::TransportLimits):
//!   four-byte little-endian length prefix, oversize-before-alloc, trailing
//!   bytes rejected. Partial, zero-length, oversize, and trailing inputs stay
//!   distinct [`TransportError`](eliot_ipc::TransportError) observations.
//! * [`ProtocolVersion::CURRENT`](eliot_protocol::ProtocolVersion) major line
//!   with [`EncodingProfile::JsonV1`](eliot_protocol::EncodingProfile).
//! * [`FrameKind::Response`](eliot_protocol::FrameKind) with
//!   [`MessageType::Result`](eliot_protocol::MessageType), correlated to the
//!   incoming request via `connection_id` plus `request_id`. This mirrors the
//!   CLI `transact_async` path (`Request`/`Execute` with
//!   `{"operation": "controlboard.status", ...}`), so the serving process
//!   answers exactly the request it was asked.
//! * [`ProtocolPayload::Json`](eliot_protocol::ProtocolPayload) carrying one
//!   [`ControlBoardTransportMessage`] whose `contract` must equal
//!   [`CONTROLBOARD_TRANSPORT_CONTRACT`], and whose board `contract` must equal
//!   [`CONTROLBOARD_CONSUMER_CONTRACT`](super::CONTROLBOARD_CONSUMER_CONTRACT).
//! * Non-authoritative trace bindings (`controlboard.contract`,
//!   `controlboard.contour_digest`, `controlboard.view_revision`) for
//!   correlation only; they never authenticate anything.
//! * Structured inline ceiling enforced by `encode_frame`/`decode_frame`
//!   (256 KiB hard cap for `Response` bodies): an over-ceiling board fails
//!   closed as oversize and is never truncated or split inline.
//!
//! No health synthesis in transit: decode returns the board byte-equal or
//! refuses it. Dispositions, summaries, typed fields, and the contour digest
//! are reproduced exactly; nothing here upgrades, merges, or greens them.
//!
//! Secret handling: the wire carries the reconciled board only. Session,
//! credential, challenge, access-digest, token, and nonce fields never enter
//! the envelope by construction.

use std::collections::BTreeMap;

use eliot_contracts::RequestId;
use eliot_ipc::{TransportError, TransportLimits, decode_frame, encode_frame};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::controlboard_consumer::{CONTROLBOARD_CONSUMER_CONTRACT, RenderedControlBoard};

/// Stable contract identity for the transported board message.
pub const CONTROLBOARD_TRANSPORT_CONTRACT: &str = "eliot.runtime-status.controlboard-transport/v1";

/// Operation selector the surface owner sends to request one board. It fits
/// the CLI `transact_async` operation bound and names no authority.
pub const CONTROLBOARD_STATUS_OPERATION: &str = "controlboard.status";

/// Maximum characters for the connection identity bound into a frame.
const MAX_CONNECTION_CHARS: usize = 1024;

/// One board message as carried by the `Json` payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBoardTransportMessage {
    /// Always [`CONTROLBOARD_TRANSPORT_CONTRACT`].
    pub contract: String,
    /// The reconciled board, reproduced byte-equal or not at all.
    pub board: RenderedControlBoard,
}

/// Fail-closed transport failure. Any variant refuses the board instead of
/// moving partial, inferred, or mismatched evidence across the boundary.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ControlBoardTransportError {
    /// A required binding field is empty, carries control characters, or is
    /// oversized.
    #[error("invalid controlboard transport binding: {field}")]
    InvalidBinding {
        /// Binding field that failed shape validation.
        field: &'static str,
    },
    /// Canonical JSON encoding of the board message failed.
    #[error("controlboard transport encoding failed: {detail}")]
    EncodingFailed {
        /// Underlying encoding failure detail (diagnostic only).
        detail: String,
    },
    /// The `eliot-ipc` framing, ceiling, or wire-shape boundary refused the
    /// bytes. Terminal wire observations (partial, zero-length, oversize,
    /// trailing) stay distinct inside this variant.
    #[error("controlboard transport failed: {0}")]
    Transport(TransportError),
    /// The decoded frame is not the exact agreed handshake: version line,
    /// kind, message type, connection/request correlation, or request-identity
    /// absence does not match.
    #[error("controlboard transport handshake mismatch: {detail}")]
    HandshakeMismatch {
        /// What did not match (diagnostic only, never persisted).
        detail: String,
    },
    /// The payload contract is not this transport (or not the reconciled
    /// consumer lineage this transport carries).
    #[error("controlboard transport contract mismatch: {actual}")]
    ContractMismatch {
        /// Contract identity actually carried by the payload.
        actual: String,
    },
    /// The frame payload is not the agreed `Json` envelope.
    #[error("controlboard transport payload is not typed JSON")]
    NotJsonPayload,
}

fn bound_connection_id(connection_id: &str) -> Result<(), ControlBoardTransportError> {
    if connection_id.trim().is_empty() || connection_id.chars().any(char::is_control) {
        return Err(ControlBoardTransportError::InvalidBinding {
            field: "connection_id",
        });
    }
    if connection_id.chars().count() > MAX_CONNECTION_CHARS {
        return Err(ControlBoardTransportError::InvalidBinding {
            field: "connection_id",
        });
    }
    Ok(())
}

fn trace_context(board: &RenderedControlBoard) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "controlboard.contract".to_owned(),
            CONTROLBOARD_TRANSPORT_CONTRACT.to_owned(),
        ),
        (
            "controlboard.contour_digest".to_owned(),
            board.contour_digest.clone(),
        ),
        (
            "controlboard.view_revision".to_owned(),
            board.view_revision.to_string(),
        ),
    ])
}

fn validate_controlboard_frame(
    frame: &Frame,
    connection_id: &str,
    request_id: &RequestId,
) -> Result<(), ControlBoardTransportError> {
    frame
        .validate()
        .map_err(|error| ControlBoardTransportError::HandshakeMismatch {
            detail: error.to_string(),
        })?;
    if frame.protocol_version != ProtocolVersion::CURRENT {
        return Err(ControlBoardTransportError::HandshakeMismatch {
            detail: "protocol_version is not the admitted EBP/1 line".to_owned(),
        });
    }
    if frame.connection_id != connection_id {
        return Err(ControlBoardTransportError::HandshakeMismatch {
            detail: "connection_id does not match the served request".to_owned(),
        });
    }
    if frame.request_id.as_ref() != Some(request_id) {
        return Err(ControlBoardTransportError::HandshakeMismatch {
            detail: "request_id does not match the served request".to_owned(),
        });
    }
    if frame.kind != FrameKind::Response || frame.message_type != MessageType::Result {
        return Err(ControlBoardTransportError::HandshakeMismatch {
            detail: "frame is not a correlated Response/Result".to_owned(),
        });
    }
    if frame.request_identity.is_some() {
        return Err(ControlBoardTransportError::HandshakeMismatch {
            detail: "response must not open a new request identity".to_owned(),
        });
    }
    Ok(())
}

/// Frames one reconciled board as a correlated `Response`/`Result` message.
///
/// The board `contract` must be the reconciled consumer lineage; anything else
/// fails closed before any byte is emitted. The structured inline ceiling is
/// enforced by `encode_frame`: an over-ceiling board is refused, never
/// truncated.
pub fn encode_controlboard_response(
    board: &RenderedControlBoard,
    connection_id: &str,
    request_id: &RequestId,
    limits: TransportLimits,
) -> Result<Vec<u8>, ControlBoardTransportError> {
    if board.contract != CONTROLBOARD_CONSUMER_CONTRACT {
        return Err(ControlBoardTransportError::ContractMismatch {
            actual: board.contract.clone(),
        });
    }
    bound_connection_id(connection_id)?;
    let message = ControlBoardTransportMessage {
        contract: CONTROLBOARD_TRANSPORT_CONTRACT.to_owned(),
        board: board.clone(),
    };
    let payload = serde_json::to_value(&message).map_err(|error| {
        ControlBoardTransportError::EncodingFailed {
            detail: error.to_string(),
        }
    })?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.to_owned(),
        request_id: Some(request_id.clone()),
        kind: FrameKind::Response,
        message_type: MessageType::Result,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: trace_context(board),
    };
    encode_frame(&frame, limits).map_err(ControlBoardTransportError::Transport)
}

/// Decodes one wire image into the reconciled board it carries, or refuses it.
///
/// Every handshake line is re-checked: wire shape and ceilings via
/// `decode_frame`, frame validity, version line, correlation, payload shape,
/// transport contract, and consumer lineage. The returned board equals the
/// produced board exactly; decode never adjusts a disposition, summary, typed
/// field, or digest.
pub fn decode_controlboard_response(
    wire: &[u8],
    connection_id: &str,
    request_id: &RequestId,
    limits: TransportLimits,
) -> Result<RenderedControlBoard, ControlBoardTransportError> {
    bound_connection_id(connection_id)?;
    let frame = decode_frame(wire, limits).map_err(ControlBoardTransportError::Transport)?;
    validate_controlboard_frame(&frame, connection_id, request_id)?;
    let value = match &frame.payload {
        ProtocolPayload::Json(value) => value.clone(),
        _ => return Err(ControlBoardTransportError::NotJsonPayload),
    };
    let message: ControlBoardTransportMessage = serde_json::from_value(value).map_err(|error| {
        ControlBoardTransportError::EncodingFailed {
            detail: error.to_string(),
        }
    })?;
    if message.contract != CONTROLBOARD_TRANSPORT_CONTRACT {
        return Err(ControlBoardTransportError::ContractMismatch {
            actual: message.contract,
        });
    }
    if message.board.contract != CONTROLBOARD_CONSUMER_CONTRACT {
        return Err(ControlBoardTransportError::ContractMismatch {
            actual: message.board.contract,
        });
    }
    Ok(message.board)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
    use eliot_ipc::TransportLimits;
    use eliot_protocol::ProtocolError;

    use super::super::controlboard_consumer::{
        CONTROLBOARD_CONSUMER_CONTRACT, ControlBoardInstallation, ControlBoardObservationTime,
        ControlBoardRecoveryOwner, ControlBoardRowDisposition, ControlBoardSourceDigest,
        RenderedControlBoard, RenderedControlBoardRow,
    };
    use super::*;

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
            installation: ControlBoardInstallation::new("installation-transport-test")
                .expect("installation"),
            observed_at: ControlBoardObservationTime::new(1_786_000_000_002).expect("observed_at"),
            source_digest: ControlBoardSourceDigest::new("cd".repeat(32)).expect("digest"),
            recovery_owner: ControlBoardRecoveryOwner::new("recovery-owner-transport")
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
                row(
                    "item-unavailable",
                    ControlBoardRowDisposition::Unavailable,
                    Some("unavailable evidence"),
                ),
                row(
                    "item-not-running",
                    ControlBoardRowDisposition::NotRunning,
                    Some("not-running evidence"),
                ),
                row(
                    "item-conflicted",
                    ControlBoardRowDisposition::Conflicted,
                    Some("conflicted evidence"),
                ),
                row(
                    "item-partial",
                    ControlBoardRowDisposition::Partial,
                    Some("partial evidence"),
                ),
                row(
                    "item-unknown",
                    ControlBoardRowDisposition::Unknown,
                    Some("summary for item-unknown"),
                ),
                row(
                    "item-unsupported",
                    ControlBoardRowDisposition::Unsupported,
                    Some("unsupported evidence"),
                ),
                row("ghost-component", ControlBoardRowDisposition::Missing, None),
            ],
            observed_count: 7,
            missing_count: 1,
            unexpected_observed: vec!["extra-entry".to_owned()],
            expiry: "re-read required after fence or generation change".to_owned(),
            invalidation: "revision/fence change, generation rotation, owner rebind".to_owned(),
        }
    }

    fn connection_id() -> String {
        "connection-transport-test".to_owned()
    }

    fn request_id() -> RequestId {
        RequestId::new("req-transport-1").expect("request id")
    }

    #[test]
    fn round_trip_preserves_every_row_label_field_and_digest() {
        let sent = board();
        let wire = encode_controlboard_response(
            &sent,
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect("wire");
        assert!(!wire.is_empty());
        let received = decode_controlboard_response(
            &wire,
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect("board");
        // Byte-equal fidelity: rows, dispositions, summaries, typed fields,
        // counts, unexpected entries, and the contour digest all survive.
        assert_eq!(received, sent);
        assert_eq!(received.contour_digest, "ef".repeat(32));
        assert_eq!(received.observed_count, 7);
        assert_eq!(received.missing_count, 1);
        let labels: Vec<&str> = received
            .rows
            .iter()
            .map(|row| row.disposition.label())
            .collect();
        assert_eq!(
            labels,
            vec![
                "STALE",
                "UNAVAILABLE",
                "NOT_RUNNING",
                "CONFLICTED",
                "PARTIAL",
                "UNKNOWN",
                "UNSUPPORTED",
                "MISSING",
            ]
        );
        let ghost = received
            .rows
            .iter()
            .find(|row| row.entry_id == "ghost-component")
            .expect("ghost row");
        assert_eq!(ghost.summary, None);
    }

    #[test]
    fn handshake_mismatches_fail_closed() {
        let sent = board();
        let wire = encode_controlboard_response(
            &sent,
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect("wire");
        let other_request = RequestId::new("req-other").expect("other request id");
        // Wrong connection, wrong request, and empty connection all refuse.
        assert!(matches!(
            decode_controlboard_response(
                &wire,
                "connection-other",
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::HandshakeMismatch { .. })
        ));
        assert!(matches!(
            decode_controlboard_response(
                &wire,
                &connection_id(),
                &other_request,
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::HandshakeMismatch { .. })
        ));
        assert!(matches!(
            decode_controlboard_response(&wire, "", &request_id(), TransportLimits::default()),
            Err(ControlBoardTransportError::InvalidBinding { .. })
        ));
        // Truncated, empty, and garbage wire images refuse as transport
        // errors with their distinct terminal observations preserved.
        assert!(matches!(
            decode_controlboard_response(
                &wire[..wire.len() / 2],
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::Transport(_))
        ));
        assert!(matches!(
            decode_controlboard_response(
                &[],
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::Transport(_))
        ));
        assert!(matches!(
            decode_controlboard_response(
                b"not-a-frame",
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::Transport(_))
        ));
    }

    #[test]
    fn wrong_kind_and_version_fail_closed() {
        let sent = board();
        let wire = encode_controlboard_response(
            &sent,
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect("wire");
        let message = ControlBoardTransportMessage {
            contract: CONTROLBOARD_TRANSPORT_CONTRACT.to_owned(),
            board: sent,
        };
        let payload = serde_json::to_value(&message).expect("payload");
        // An Event frame carrying the same payload is not the agreed
        // Response/Result handshake.
        let event = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id(),
            request_id: None,
            kind: FrameKind::Event,
            message_type: MessageType::Event,
            request_identity: None,
            payload: ProtocolPayload::Json(payload.clone()),
            trace_context: BTreeMap::new(),
        };
        let event_wire = encode_frame(&event, TransportLimits::default()).expect("event wire");
        assert!(matches!(
            decode_controlboard_response(
                &event_wire,
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::HandshakeMismatch { .. })
        ));
        // A frame off the admitted EBP major line fails closed on both sides:
        // emission refuses it, and a wire image carrying it is refused on
        // receipt as well.
        let off_line = Frame {
            protocol_version: ProtocolVersion {
                major: ProtocolVersion::CURRENT.major.saturating_add(1),
                minor: 0,
            },
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id(),
            request_id: Some(request_id()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(payload),
            trace_context: BTreeMap::new(),
        };
        assert!(
            encode_frame(&off_line, TransportLimits::default()).is_err(),
            "off-line frame must be refused at emission"
        );
        let off_line_wire =
            rewire_with_version(&wire, ProtocolVersion::CURRENT.major.saturating_add(1), 0);
        // The codec layer rejects the off-line version during decode
        // (`Frame::validate` inside `decode_body`); the explicit handshake
        // check below it is defense-in-depth for the same line. Either
        // refusal is fail-closed.
        assert!(
            matches!(
                decode_controlboard_response(
                    &off_line_wire,
                    &connection_id(),
                    &request_id(),
                    TransportLimits::default()
                ),
                Err(ControlBoardTransportError::Transport(_)
                    | ControlBoardTransportError::HandshakeMismatch { .. },)
            ),
            "off-line wire must be refused"
        );
    }

    /// Re-stamps the EBP version on one wire image without touching any other
    /// byte of the handshake. Test scaffolding only: it reuses the transport's
    /// own length-prefix framing, never a parallel codec.
    fn rewire_with_version(wire: &[u8], major: u16, minor: u16) -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&wire[4..]).expect("wire body is JSON");
        value["protocol_version"] = serde_json::json!({"major": major, "minor": minor});
        let body = serde_json::to_vec(&value).expect("wire body re-encodes");
        let mut rewired = u32::try_from(body.len())
            .expect("re-stamped body fits the length prefix")
            .to_le_bytes()
            .to_vec();
        rewired.extend_from_slice(&body);
        rewired
    }

    #[test]
    fn contract_mismatches_fail_closed_on_both_sides() {
        // Encode refuses a board outside the reconciled consumer lineage.
        let mut foreign = board();
        foreign.contract = "forged.board/v9".to_owned();
        assert_eq!(
            encode_controlboard_response(
                &foreign,
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::ContractMismatch {
                actual: "forged.board/v9".to_owned()
            })
        );
        // Decode refuses a payload outside this transport contract.
        let forged = ControlBoardTransportMessage {
            contract: "forged.transport/v9".to_owned(),
            board: board(),
        };
        let forged_frame = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id(),
            request_id: Some(request_id()),
            kind: FrameKind::Response,
            message_type: MessageType::Result,
            request_identity: None,
            payload: ProtocolPayload::Json(serde_json::to_value(&forged).expect("forged")),
            trace_context: BTreeMap::new(),
        };
        let forged_wire =
            encode_frame(&forged_frame, TransportLimits::default()).expect("forged wire");
        assert_eq!(
            decode_controlboard_response(
                &forged_wire,
                &connection_id(),
                &request_id(),
                TransportLimits::default()
            ),
            Err(ControlBoardTransportError::ContractMismatch {
                actual: "forged.transport/v9".to_owned()
            })
        );
    }

    #[test]
    fn over_ceiling_board_is_refused_never_truncated() {
        let mut oversized = board();
        oversized.rows[0].summary = Some("s".repeat(300 * 1024));
        let error = encode_controlboard_response(
            &oversized,
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect_err("over-ceiling board must fail");
        assert!(
            matches!(
                error,
                ControlBoardTransportError::Transport(TransportError::Protocol(
                    ProtocolError::OversizeFrame { .. }
                ))
            ),
            "over-ceiling board must surface oversize, got: {error}"
        );
    }

    #[test]
    fn no_secret_material_on_the_wire() {
        let wire = encode_controlboard_response(
            &board(),
            &connection_id(),
            &request_id(),
            TransportLimits::default(),
        )
        .expect("wire");
        let text = String::from_utf8_lossy(&wire);
        for needle in [
            "session_id",
            "credential",
            "challenge",
            "access_digest",
            "secret",
            "token",
            "nonce",
            "password",
            "private_key",
            "authorization",
        ] {
            assert!(
                !text.contains(needle),
                "secret-like text on the wire: {needle}"
            );
        }
    }
}
