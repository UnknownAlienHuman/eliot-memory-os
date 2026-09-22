//! Authenticated Kernel-side client for Host-issued restore-destination
//! authorization over the existing Host runtime-control pipe (issue #962).
//!
//! Architecture: A12.2 Principal, Session, and Visibility (identity is
//! established by the installation boundary, never self-declared);
//! A13.2 Kernel and Failure Domains (Host Supervisor outside the Kernel
//! failure domain); I1.8 Exact Ownership and Call Paths; I5.27 canonical
//! operation identity (fresh transport identity per call, stable mutation
//! identity for reconciliation); I14.21 unknown-commit recovery (timeout
//! after send stays `Unknown` for reconcile replay, never a blind retry).
//! Implementation: I7.2/I7.3 framed IPC (existing `FrameKind::Control`
//! Start/Ready envelopes over the existing pipe).
//!
//! What this file owns: the bounded reverse owner operation the #962 wire
//! was missing — a Kernel-side client that requests one destination
//! authorization from the Host owner and returns the Host-issued receipt.
//! No new pipe family, transport, or authentication is introduced: the
//! existing pipe (`HOST_RUNTIME_CONTROL_PIPE`), the existing frame
//! envelope, the existing version policy, and the existing OS peer
//! authorities are reused. The server side keeps requiring Builtin
//! Administrators; this client mirrors that policy when verifying the
//! Host server peer (`connect_authenticated`), so an unprivileged pipe
//! squatter cannot feed forged bytes. Digest-bound request/response
//! correlation (`response_matches_request`) binds every receipt to the
//! exact fresh request: a recorded response never satisfies a new call.
//!
//! Capability cell: Host-control backup delivery (authenticated request,
//! correlated receipt).
//! Forbidden authority: no pipe/ACL/authentication redesign, no new wire
//! family, no credential handling, no semantic interpretation of the
//! delivered authorization (the Kernel restore adapter verifies, journals,
//! and pins it before any effect), no test fake behind a production path.

use std::time::Duration;

use eliot_host_service::runtime_control::{
    HostRestoreDestinationReceipt, HostRuntimeControlRequest, HostRuntimeControlResponse,
    decode_runtime_control_response_frame, response_matches_request,
    runtime_control_request_frame,
};
use eliot_ipc::{NamedPipeTransport, TransportLimits};
use eliot_protocol::Frame;

use super::HOST_RUNTIME_CONTROL_PIPE;

/// Bounded connect timeout: failure happens before any byte is sent, so a
/// timeout here proves no effect and needs no reconciliation.
pub const HOST_RESTORE_DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounded full-exchange timeout: expiry after the request is sent leaves a
/// possible Host-side issuance, so it reports `Unknown`. The coordinator
/// retries with a fresh admitted request for the same descriptors — never
/// success, never blind retry (issuance is effect-free read-only, so a
/// fresh request duplicates nothing).
pub const HOST_RESTORE_DESTINATION_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
/// Fixed per-connection correlation label. Each call owns its transport
/// connection, so the label only needs to be constant within it; request
/// correlation travels in the digest-bound envelope, never in this label.
const CONNECTION_ID: &str = "host-restore-destination";

/// Failure of one authenticated restore-destination delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreDestinationDeliveryError {
    /// Transport, peer-authentication, or framing failure. A connect
    /// failure proves nothing was sent; a post-send failure is reported
    /// as `Unknown` instead.
    Transport(String),
    /// The channel refused: invalid request, digest mismatch, unexpected
    /// response kind, or peer-policy violation. Fail closed, do not retry
    /// blindly; a fresh admitted request is a new call.
    Rejected(String),
    /// The Host answered `Unknown`: the issuance outcome is undecided
    /// (timeout after send, queue loss, lost response). Retry with a fresh
    /// admitted request for the same descriptors; never treat this as
    /// success or as proof of non-issuance.
    Unknown {
        /// Opaque owner pending reference binding the undecided request.
        pending_ref: String,
    },
}

impl std::fmt::Display for RestoreDestinationDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "restore destination delivery failed: {detail}"),
            Self::Rejected(detail) => write!(f, "restore destination refused: {detail}"),
            Self::Unknown { pending_ref } => write!(
                f,
                "restore destination outcome unknown: {pending_ref}"
            ),
        }
    }
}

/// Authenticated client for Host-issued restore-destination authorization.
///
/// Stateless: every call connects, verifies the Host server peer against
/// the established Host-service expectation, exchanges exactly one
/// digest-bound request/response pair, and drops the connection. There is
/// no retained handle to go stale and no test constructor: production
/// callers always reach the real pipe.
pub struct HostRestoreDestinationClient;

impl HostRestoreDestinationClient {
    /// Exchanges one digest-bound authorization request for the Host-issued
    /// receipt over the authenticated Host pipe.
    pub async fn exchange(
        request: &HostRuntimeControlRequest,
    ) -> Result<HostRestoreDestinationReceipt, RestoreDestinationDeliveryError> {
        use RestoreDestinationDeliveryError::{Rejected, Transport, Unknown};
        let expectation =
            eliot_platform_windows::NamedPipePeerExpectation::new_for_builtin_administrators()
                .map_err(|error| Transport(error.to_string()))?;
        let mut transport = NamedPipeTransport::connect_authenticated(
            HOST_RUNTIME_CONTROL_PIPE,
            HOST_RESTORE_DESTINATION_CONNECT_TIMEOUT,
            &expectation,
        )
        .await
        .map_err(|error| Transport(error.to_string()))?;
        let limits = TransportLimits::default();
        let frame = runtime_control_request_frame(CONNECTION_ID, request)
            .map_err(|_| Rejected("restore destination request failed validation".to_owned()))?;
        let outcome = tokio::time::timeout(
            HOST_RESTORE_DESTINATION_RESPONSE_TIMEOUT,
            Self::round_trip(&mut transport, frame, limits),
        )
        .await
        .map_err(|_| Unknown {
            pending_ref: "restore-destination-response-timeout".to_owned(),
        })??;
        if !response_matches_request(request, &outcome) {
            return Err(Rejected(
                "restore destination response does not bind the request".to_owned(),
            ));
        }
        match outcome {
            HostRuntimeControlResponse::DestinationAuthorized { receipt } => Ok(receipt),
            HostRuntimeControlResponse::Unknown { pending_ref } => Err(Unknown {
                pending_ref: pending_ref.as_str().to_owned(),
            }),
            _ => Err(Rejected(
                "restore destination response kind is not authorized".to_owned(),
            )),
        }
    }

    /// Sends one frame and awaits the correlated response frame. Any
    /// transport failure after the send point is already mapped by the
    /// caller to `Unknown`.
    async fn round_trip(
        transport: &mut NamedPipeTransport,
        frame: Frame,
        limits: TransportLimits,
    ) -> Result<HostRuntimeControlResponse, RestoreDestinationDeliveryError> {
        transport
            .send_frame(&frame, limits)
            .await
            .map_err(|error| {
                RestoreDestinationDeliveryError::Unknown {
                    pending_ref: format!("restore-destination-send-uncertain:{error}"),
                }
            })?;
        let reply = transport
            .receive_frame(limits)
            .await
            .map_err(|error| {
                RestoreDestinationDeliveryError::Unknown {
                    pending_ref: format!("restore-destination-receive-uncertain:{error}"),
                }
            })?;
        decode_runtime_control_response_frame(&reply).map_err(|_| {
            RestoreDestinationDeliveryError::Rejected(
                "restore destination response failed validation".to_owned(),
            )
        })
    }
}
