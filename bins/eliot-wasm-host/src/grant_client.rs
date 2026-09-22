//! WASM grant client (issue #1955, I14.19).
//!
//! Builds the caller-known grant-request bundle from verified local
//! observations (component identity plus artifact/interface digests
//! recomputed from real bytes) and dispatches it toward the Kernel grant
//! route. No transport is bound yet — that registration span belongs to
//! Beauvoir's lane (see `CONTROL/1955-kernel-grant-handoff.md`) — so
//! dispatch fails closed with [`GrantClientError::NoTransport`]; request
//! BUILDING is real, tested logic, and the dispatch function is its single
//! fill-in point. Transport/session facts (caller principal, connection,
//! fence, epoch) are deliberately absent here: the route binds those at
//! the boundary from Kernel observation, exactly like the host-request
//! connection gate does. Nothing is fabricated to look admitted.

use std::fmt;

use eliot_wasm_runtime::Sha256Digest;

/// Caller-known grant-request bundle: observations this host can verify
/// locally. Digests always recompute from bytes; nonces and deadlines are
/// caller-chosen (uniqueness/freshness), never authority.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GrantClientBundle {
    /// Requested component identity.
    pub component_id: String,
    /// SHA-256 of the real component artifact bytes.
    pub artifact_digest: Sha256Digest,
    /// SHA-256 of the real WIT world bytes.
    pub interface_digest: Sha256Digest,
    /// Caller nonce for exactly-once issuance.
    pub nonce: String,
    /// Absolute deadline (unix ms) the grant must not outlive.
    pub deadline_unix_ms: u64,
}

/// Fail-closed grant-client errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantClientError {
    /// A local observation was blank, empty, or otherwise unusable.
    InvalidField {
        /// Stable field name.
        field: &'static str,
    },
    /// A served grant failed wire, digest, echo, or deadline checks.
    Denied {
        /// Stable field name.
        field: &'static str,
    },
    /// A served grant is past its deadline.
    Expired,
    /// No grant transport is bound; Beauvoir's registration span owns it.
    NoTransport,
}

impl fmt::Display for GrantClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(formatter, "GRANT_CLIENT_INVALID:{field}"),
            Self::Denied { field } => write!(formatter, "GRANT_CLIENT_DENIED:{field}"),
            Self::Expired => formatter.write_str("GRANT_CLIENT_EXPIRED"),
            Self::NoTransport => formatter.write_str("GRANT_CLIENT_NO_TRANSPORT"),
        }
    }
}

impl std::error::Error for GrantClientError {}

/// Builds a grant-request bundle from verified local observations.
/// Empty inputs, blank identities, and zero deadlines fail closed.
pub fn build_grant_bundle(
    component_id: &str,
    artifact_bytes: &[u8],
    wit_bytes: &[u8],
    nonce: &str,
    deadline_unix_ms: u64,
) -> Result<GrantClientBundle, GrantClientError> {
    if component_id.trim().is_empty() {
        return Err(GrantClientError::InvalidField {
            field: "component_id",
        });
    }
    if artifact_bytes.is_empty() || wit_bytes.is_empty() {
        return Err(GrantClientError::InvalidField { field: "bytes" });
    }
    if nonce.trim().is_empty() {
        return Err(GrantClientError::InvalidField { field: "nonce" });
    }
    if deadline_unix_ms == 0 {
        return Err(GrantClientError::InvalidField {
            field: "deadline_unix_ms",
        });
    }
    Ok(GrantClientBundle {
        component_id: component_id.to_owned(),
        artifact_digest: Sha256Digest::of_bytes(artifact_bytes),
        interface_digest: Sha256Digest::of_bytes(wit_bytes),
        nonce: nonce.to_owned(),
        deadline_unix_ms,
    })
}

/// Dispatches one bundle toward the Kernel grant route.
///
/// Single fill-in point for Beauvoir's registration span: when the route
/// lands, this serializes the bundle into it and awaits the issued grant.
/// Until then it fails closed — a missing transport is never papered over
/// with a fabricated grant.
pub fn request_grant(_bundle: &GrantClientBundle) -> Result<(), GrantClientError> {
    Err(GrantClientError::NoTransport)
}

/// Authenticated channel binding for grant transport. Every value is
/// threaded from installer/channel records by the composition — the
/// Kernel SID/session/artifact triple is verified against the live
/// front-door server before anything is sent, mirroring the daemon
/// kernel client. Nothing here is minted locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantChannel {
    /// Local front-door pipe name.
    pub pipe_name: String,
    /// Expected Kernel server SID.
    pub kernel_sid: String,
    /// Expected Kernel server session id.
    pub kernel_session_id: u32,
    /// Expected Kernel artifact SHA-256 (lowercase hex).
    pub kernel_artifact_sha256: String,
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
}

impl GrantChannel {
    /// Validates channel shape without touching I/O.
    pub fn validate(&self) -> Result<(), GrantClientError> {
        let denied = |field: &'static str| GrantClientError::Denied { field };
        if self.pipe_name.trim().is_empty() {
            return Err(denied("channel"));
        }
        if self.kernel_sid.trim().is_empty() {
            return Err(denied("channel"));
        }
        if self.kernel_artifact_sha256.len() != 64
            || !self
                .kernel_artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(denied("channel"));
        }
        if self.connect_timeout_ms == 0 {
            return Err(denied("channel"));
        }
        Ok(())
    }
}

/// Closed private operation name for grant issuance. Must equal the
/// server module's `WASM_PORT_GRANT_OPERATION` exactly; any drift fails
/// at the dispatch map, never silently.
pub const GRANT_ISSUE_OPERATION: &str = "wasm_port_grant_issue";

/// Expected wire identities of a served grant. These literals must match
/// the server module's `WASM_PORT_GRANT_WIRE_ID` / `WASM_PORT_GRANT_WIRE_VERSION`
/// exactly; any drift fails closed here. (Wire identifiers duplicate by
/// nature across a process boundary; compatibility is pinned by the digest
/// recomputation below, not by shared code.)
const GRANT_WIRE_ID: &str = "eliot.wasm.port-grant";
const GRANT_WIRE_VERSION: u16 = 1;

/// Wire mirror of the served grant, field-for-field with the server shape
/// (same names; key order normalized by the canonical scheme). Parsed
/// strictly and digest-verified — never trusted from the wire.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantWireMirror {
    wire_id: String,
    wire_version: u16,
    request_sha256: String,
    caller_principal: String,
    caller_connection: String,
    component_id: String,
    artifact_digest: String,
    interface_digest: String,
    state_fence: eliot_contracts::StateFence,
    authority_epoch: eliot_contracts::EpochId,
    nonce: String,
    deadline_unix_ms: u64,
    host_executable_path: String,
    host_artifact_digest: String,
    grant_sha256: String,
}

/// Accepted grant observations for admission construction: digests parsed
/// into typed form, fence/epoch threaded, caller echoes verified. The
/// artifact/interface/host digests remain caller-asserted claims bound
/// tamper-evident — the consumer re-hashes real bytes against them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedGrant {
    /// Admitted component identity.
    pub component_id: String,
    /// Caller-asserted artifact digest, typed.
    pub artifact_digest: Sha256Digest,
    /// Caller-asserted interface digest, typed.
    pub interface_digest: Sha256Digest,
    /// Kernel-observed fence at issuance.
    pub fence: eliot_contracts::StateFence,
    /// Kernel-observed epoch at issuance.
    pub epoch: eliot_contracts::EpochId,
    /// Caller nonce echoed from issuance.
    pub nonce: String,
    /// Deadline echoed from issuance.
    pub deadline_unix_ms: u64,
    /// Installation-approved host binary path, caller-asserted.
    pub host_executable_path: String,
    /// Caller-asserted host digest, typed.
    pub host_artifact_digest: Sha256Digest,
}

/// Accepts one served grant response: parses the wire bytes strictly,
/// checks wire identity/version, recomputes the canonical digest (never
/// trusting the carried one), binds the response to the expected
/// authenticated channel (`expected_connection` — the connection this
/// host actually used) and component, and enforces the deadline. Any
/// deviation fails closed.
pub fn accept_grant(
    response_bytes: &[u8],
    expected_connection: &str,
    expected_component: &str,
    now_unix_ms: u64,
) -> Result<AcceptedGrant, GrantClientError> {
    let denied = |field: &'static str| GrantClientError::Denied { field };
    let mirror: GrantWireMirror =
        serde_json::from_slice(response_bytes).map_err(|_| denied("response"))?;
    if mirror.wire_id != GRANT_WIRE_ID || mirror.wire_version != GRANT_WIRE_VERSION {
        return Err(denied("wire"));
    }
    let mut unsigned = mirror.clone();
    unsigned.grant_sha256.clear();
    let recomputed = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&unsigned).map_err(|_| denied("canonical-bytes"))?,
    );
    if recomputed != mirror.grant_sha256 {
        return Err(denied("grant_sha256"));
    }
    if mirror.caller_connection != expected_connection {
        return Err(denied("caller_connection"));
    }
    if mirror.component_id != expected_component {
        return Err(denied("component"));
    }
    if mirror.deadline_unix_ms <= now_unix_ms {
        return Err(GrantClientError::Expired);
    }
    let hex_digest =
        |hex: &str, field: &'static str| Sha256Digest::new(hex).map_err(|_| denied(field));
    Ok(AcceptedGrant {
        component_id: mirror.component_id,
        artifact_digest: hex_digest(&mirror.artifact_digest, "artifact_digest")?,
        interface_digest: hex_digest(&mirror.interface_digest, "interface_digest")?,
        fence: mirror.state_fence,
        epoch: mirror.authority_epoch,
        nonce: mirror.nonce,
        deadline_unix_ms: mirror.deadline_unix_ms,
        host_executable_path: mirror.host_executable_path,
        host_artifact_digest: hex_digest(&mirror.host_artifact_digest, "host_artifact_digest")?,
    })
}

/// Requests one grant over an authenticated front-door channel: connects
/// and authenticates the live Kernel server (SID/session/artifact triple
/// verified before anything is sent), binds the peer, sends the op frame
/// carrying the admitted request identity, and accepts the response
/// through [`accept_grant`]. Every failure — including no listener —
/// fails closed with stage-taxonomy denials. The frame identity threads
/// owner-retained facts (fence, nonce, deadline, correlation); session
/// principal and connection binding stay server-derived from the
/// authenticated session the route just proved, never caller-claimed.
#[cfg(windows)]
pub fn request_grant_via_transport(
    bundle: &GrantClientBundle,
    channel: &GrantChannel,
    channel_fence: &eliot_contracts::StateFence,
) -> Result<AcceptedGrant, GrantClientError> {
    channel.validate()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| GrantClientError::Denied { field: "runtime" })?;
    runtime.block_on(transport::request_grant_inner(
        bundle,
        channel,
        channel_fence,
    ))
}

#[cfg(not(windows))]
/// Non-Windows builds have no front-door transport: fail closed without
/// attempting I/O.
pub fn request_grant_via_transport(
    _bundle: &GrantClientBundle,
    _channel: &GrantChannel,
    _channel_fence: &eliot_contracts::StateFence,
) -> Result<AcceptedGrant, GrantClientError> {
    Err(GrantClientError::Denied { field: "transport" })
}

#[cfg(windows)]
mod transport {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId, StateFence};
    use eliot_ipc::{DeliveryOutcome, NamedPipeTransport, TransportLimits};
    use eliot_platform_windows::{KernelFrontDoorAclMode, KernelFrontDoorServerExpectation};
    use eliot_protocol::{
        EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
        RequestIdentity,
    };
    use eliot_receipts::RequestBinding;

    use super::{
        AcceptedGrant, GRANT_ISSUE_OPERATION, GrantChannel, GrantClientBundle, accept_grant,
    };
    use crate::GrantClientError;

    static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    /// Product/source identity this client declares on its frames. A
    /// caller-declared product label, never authority: the fence, the
    /// session binding, and admission all come from owner records and
    /// the authenticated session.
    pub const GRANT_CLIENT_SERVICE: &str = "eliot-wasm-host";

    /// Connection identity for one client instance: process-unique,
    /// echoed by the server for correlation (mirrors the daemon client).
    pub fn connection_identity() -> String {
        format!("wasm-host-grant:{}", std::process::id())
    }

    /// Builds the admitted request identity for one grant frame from
    /// owner-retained facts: the fence threads the owner snapshot fence
    /// (dispatch material, validated — never minted here), the request id
    /// repeats the frame correlation id (the protocol cross-checks
    /// equality), idempotency repeats the bundle nonce (the caller-chosen
    /// exactly-once key), the deadline repeats the bundle deadline, and
    /// the cancellation id binds connection/operation/sequence. Session
    /// and task ids stay absent: the server attaches session binding from
    /// the authenticated session it just proved (server-derived, never
    /// caller-claimed).
    pub fn grant_request_identity(
        bundle: &GrantClientBundle,
        channel_fence: &StateFence,
        connection_id: &str,
        sequence: u64,
        request_id: &RequestId,
        now_unix_ms: u64,
    ) -> Result<RequestIdentity, GrantClientError> {
        let denied = |field: &'static str| GrantClientError::Denied { field };
        let now_ms = i64::try_from(now_unix_ms).map_err(|_| denied("clock"))?;
        Ok(RequestIdentity {
            request: RequestBinding {
                metadata: eliot_contracts::RequestMetadata {
                    request_id: request_id.clone(),
                    session_id: None,
                    task_id: None,
                    product_id: ProductId::new(GRANT_CLIENT_SERVICE)
                        .map_err(|_| denied("product"))?,
                    source_id: SourceId::new(GRANT_CLIENT_SERVICE).map_err(|_| denied("source"))?,
                    state_fence: channel_fence.clone(),
                    clock: ClockReading {
                        valid_time_ms: Some(now_ms),
                        known_time_ms: Some(now_ms),
                        transaction_sequence: None,
                        monotonic_ns: None,
                    },
                },
                state_fence: channel_fence.clone(),
            },
            idempotency_key: bundle.nonce.clone(),
            deadline_unix_ms: bundle.deadline_unix_ms,
            cancellation_id: format!("{connection_id}:{GRANT_ISSUE_OPERATION}:{sequence}:cancel"),
        })
    }

    /// Builds the grant-issue op frame: operation string plus the bundle
    /// payload plus the admitted request identity. Pure constructor — no
    /// I/O; every identity value threads owner-retained facts, and the
    /// frame self-validates before return so a malformed frame fails
    /// closed here instead of at the gate.
    pub fn grant_issue_frame(
        bundle: &GrantClientBundle,
        channel_fence: &StateFence,
        connection_id: &str,
        sequence: u64,
    ) -> Result<(Frame, String), GrantClientError> {
        let denied = |field: &'static str| GrantClientError::Denied { field };
        let request_id = RequestId::new(format!(
            "{connection_id}:{GRANT_ISSUE_OPERATION}:{sequence}"
        ))
        .map_err(|_| denied("request-id"))?;
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| denied("clock"))?;
        let identity = grant_request_identity(
            bundle,
            channel_fence,
            connection_id,
            sequence,
            &request_id,
            now_unix_ms,
        )?;
        let payload = serde_json::json!({
            "operation": GRANT_ISSUE_OPERATION,
            "request": serde_json::to_value(bundle).map_err(|_| denied("payload"))?,
        });
        let frame = Frame {
            protocol_version: ProtocolVersion::CURRENT,
            encoding_profile: EncodingProfile::JsonV1,
            connection_id: connection_id.to_owned(),
            request_id: Some(request_id.clone()),
            kind: FrameKind::Request,
            message_type: MessageType::Execute,
            request_identity: Some(identity),
            payload: ProtocolPayload::Json(payload),
            trace_context: BTreeMap::new(),
        };
        frame.validate().map_err(|_| denied("frame"))?;
        Ok((frame, request_id.to_string()))
    }

    pub async fn request_grant_inner(
        bundle: &GrantClientBundle,
        channel: &GrantChannel,
        channel_fence: &StateFence,
    ) -> Result<AcceptedGrant, GrantClientError> {
        let denied = |field: &'static str| GrantClientError::Denied { field };
        let expectation = KernelFrontDoorServerExpectation::new(
            channel.kernel_sid.as_str(),
            channel.kernel_session_id,
            channel.kernel_artifact_sha256.as_str(),
            KernelFrontDoorAclMode::SystemAndLocalServiceWithOptionalUserClient,
        )
        .map_err(|_| denied("expectation"))?;
        let mut transport = NamedPipeTransport::connect_authenticated_kernel_front_door(
            channel.pipe_name.as_str(),
            std::time::Duration::from_millis(channel.connect_timeout_ms),
            &expectation,
        )
        .await
        .map_err(|_| denied("connect"))?;
        match transport.peer_identity() {
            eliot_ipc::PeerIdentity::Authenticated {
                process_id,
                user_identity,
                session_identity,
                ..
            } if *process_id != 0
                && user_identity == channel.kernel_sid.as_str()
                && session_identity == &channel.kernel_session_id.to_string() => {}
            _ => return Err(denied("peer")),
        }
        let connection_id = connection_identity();
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let (frame, request_id) =
            grant_issue_frame(bundle, channel_fence, &connection_id, sequence)?;
        let limits = TransportLimits::default();
        if transport
            .send_frame(&frame, limits)
            .await
            .map_err(|_| denied("send"))?
            != DeliveryOutcome::Delivered
        {
            return Err(denied("delivery"));
        }
        let response = transport
            .receive_frame(limits)
            .await
            .map_err(|_| denied("receive"))?;
        response.validate().map_err(|_| denied("response"))?;
        if response.connection_id != connection_id
            || response
                .request_id
                .as_ref()
                .map(|request_id| request_id.as_str().to_owned())
                != Some(request_id)
            || response.kind != FrameKind::Response
            || response.message_type != MessageType::Result
            || response.request_identity.is_some()
        {
            return Err(denied("correlation"));
        }
        let eliot_protocol::ProtocolPayload::Json(value) = response.payload else {
            return Err(denied("response"));
        };
        let bytes = serde_json::to_vec(&value).map_err(|_| denied("response"))?;
        let now_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .map_err(|_| denied("clock"))?;
        accept_grant(&bytes, &connection_id, &bundle.component_id, now_unix_ms)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn bundle_binds_recomputed_digests() {
        let bundle = build_grant_bundle(
            "component-1956",
            b"artifact-bytes",
            b"wit-bytes",
            "nonce-1",
            9_999_999_999_999,
        )
        .expect("bundle");
        assert_eq!(
            bundle.artifact_digest,
            Sha256Digest::of_bytes(b"artifact-bytes")
        );
        assert_eq!(
            bundle.interface_digest,
            Sha256Digest::of_bytes(b"wit-bytes")
        );
    }

    #[test]
    fn blank_inputs_fail_closed() {
        assert!(matches!(
            build_grant_bundle("", b"a", b"w", "n", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"", b"w", "n", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"a", b"w", "", 1),
            Err(GrantClientError::InvalidField { .. })
        ));
        assert!(matches!(
            build_grant_bundle("c", b"a", b"w", "n", 0),
            Err(GrantClientError::InvalidField { .. })
        ));
    }

    #[test]
    fn dispatch_without_transport_fails_closed() {
        let bundle = build_grant_bundle("c", b"a", b"w", "n", 1).expect("bundle");
        assert_eq!(request_grant(&bundle), Err(GrantClientError::NoTransport));
        assert_eq!(
            GrantClientError::NoTransport.to_string(),
            "GRANT_CLIENT_NO_TRANSPORT"
        );
    }

    #[cfg(windows)]
    fn test_channel() -> GrantChannel {
        GrantChannel {
            pipe_name: "definitely-not-a-pipe-1956".to_owned(),
            kernel_sid: "S-1-5-18".to_owned(),
            kernel_session_id: 1,
            kernel_artifact_sha256: "a".repeat(64),
            connect_timeout_ms: 250,
        }
    }

    #[cfg(windows)]
    fn test_fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::new(1).expect("gen"))
    }

    #[test]
    #[cfg(windows)]
    fn grant_frame_carries_operation_and_bundle() {
        use crate::grant_client::transport::grant_issue_frame;
        use eliot_protocol::ProtocolPayload;
        let bundle = build_grant_bundle(
            "component-1956",
            b"artifact-bytes",
            b"wit-bytes",
            "nonce-9",
            9_999_999_999_999,
        )
        .expect("bundle");
        let (frame, request_id) =
            grant_issue_frame(&bundle, &test_fence(), "conn-test", 7).expect("frame");
        assert_eq!(request_id, format!("conn-test:{GRANT_ISSUE_OPERATION}:7"));
        // The frame carries the admitted request identity the gate
        // requires: fence-bound, correlation-matched, self-validating.
        let identity = frame.request_identity.as_ref().expect("identity bound");
        assert_eq!(
            identity.request.metadata.request_id.as_str(),
            request_id.as_str()
        );
        assert_eq!(identity.idempotency_key.as_str(), "nonce-9");
        assert_eq!(identity.deadline_unix_ms, 9_999_999_999_999);
        assert!(identity.cancellation_id.as_str().contains("conn-test"));
        frame.validate().expect("frame self-validates");
        let ProtocolPayload::Json(payload) = frame.payload else {
            panic!("grant frame carries JSON");
        };
        assert_eq!(
            payload.get("operation").and_then(|value| value.as_str()),
            Some(GRANT_ISSUE_OPERATION)
        );
        let request = payload.get("request").expect("request payload");
        assert_eq!(
            request.get("component_id").and_then(|value| value.as_str()),
            Some("component-1956")
        );
        assert_eq!(
            request.get("nonce").and_then(|value| value.as_str()),
            Some("nonce-9")
        );
    }

    #[test]
    #[cfg(windows)]
    fn mismatched_identity_fails_frame_validation() {
        use crate::grant_client::transport::grant_issue_frame;
        let bundle = build_grant_bundle(
            "component-1956",
            b"artifact-bytes",
            b"wit-bytes",
            "nonce-9",
            9_999_999_999_999,
        )
        .expect("bundle");
        let (mut frame, _) =
            grant_issue_frame(&bundle, &test_fence(), "conn-test", 7).expect("frame");
        // A substituted request id breaks the identity correlation gate.
        frame.request_id =
            Some(eliot_contracts::RequestId::new("conn-test:substituted:9").expect("request id"));
        assert!(frame.validate().is_err());
        // A stripped identity breaks the gate requirement itself.
        let (mut frame, _) =
            grant_issue_frame(&bundle, &test_fence(), "conn-test", 7).expect("frame");
        frame.request_identity = None;
        assert!(frame.validate().is_err());
    }

    #[test]
    #[cfg(windows)]
    fn bad_channel_fails_before_io() {
        let bundle = build_grant_bundle("c", b"a", b"w", "n", 1).expect("bundle");
        let mut channel = test_channel();
        channel.pipe_name.clear();
        assert_eq!(
            request_grant_via_transport(&bundle, &channel, &test_fence()),
            Err(GrantClientError::Denied { field: "channel" })
        );
        let mut channel = test_channel();
        channel.kernel_artifact_sha256 = "ZZZ".to_owned();
        assert_eq!(
            request_grant_via_transport(&bundle, &channel, &test_fence()),
            Err(GrantClientError::Denied { field: "channel" })
        );
    }

    #[test]
    #[cfg(windows)]
    fn unconnectable_pipe_fails_closed_fast() {
        // No listener exists: a real connect attempt must fail closed with
        // connect taxonomy (never hang, never fabricate).
        let bundle = build_grant_bundle("c", b"a", b"w", "n", 1).expect("bundle");
        let started = std::time::Instant::now();
        assert_eq!(
            request_grant_via_transport(&bundle, &test_channel(), &test_fence()),
            Err(GrantClientError::Denied { field: "connect" })
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "connect failure must be bounded"
        );
    }

    fn sample_response() -> Vec<u8> {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let fence = StateFence::new(epoch.clone(), ResourceGeneration::new(1).expect("gen"));
        let mut mirror = GrantWireMirror {
            wire_id: GRANT_WIRE_ID.to_owned(),
            wire_version: GRANT_WIRE_VERSION,
            request_sha256: "a".repeat(64),
            caller_principal: "S-1-5-18".to_owned(),
            caller_connection: "conn-1956".to_owned(),
            component_id: "component-1956".to_owned(),
            artifact_digest: "b".repeat(64),
            interface_digest: "c".repeat(64),
            state_fence: fence,
            authority_epoch: epoch,
            nonce: "nonce-1".to_owned(),
            deadline_unix_ms: 9_999_999_999_999,
            host_executable_path: "C:\\Kernel\\eliot-wasm-host.exe".to_owned(),
            host_artifact_digest: "d".repeat(64),
            grant_sha256: String::new(),
        };
        let mut unsigned = mirror.clone();
        unsigned.grant_sha256.clear();
        mirror.grant_sha256 = eliot_contracts::sha256_hex(
            &eliot_contracts::canonical_json_bytes(&unsigned).expect("canonical"),
        );
        serde_json::to_vec(&mirror).expect("response bytes")
    }

    #[test]
    fn served_grant_parses_and_binds_channel() {
        let accepted = accept_grant(&sample_response(), "conn-1956", "component-1956", 1_000_000)
            .expect("accept");
        assert_eq!(accepted.component_id, "component-1956");
        assert_eq!(accepted.nonce, "nonce-1");
        assert_eq!(
            accepted.host_executable_path,
            "C:\\Kernel\\eliot-wasm-host.exe"
        );
    }

    #[test]
    fn served_grant_mismatch_fails_closed() {
        // Tampered byte breaks the recomputed digest.
        let mut tampered = sample_response();
        let tamper_at = tampered.len() / 2;
        tampered[tamper_at] = if tampered[tamper_at] == b'0' {
            b'1'
        } else {
            b'0'
        };
        assert!(matches!(
            accept_grant(&tampered, "conn-1956", "component-1956", 1_000_000),
            Err(GrantClientError::Denied { .. })
        ));
        // Foreign channel or component is not bound here.
        assert!(matches!(
            accept_grant(
                &sample_response(),
                "conn-foreign",
                "component-1956",
                1_000_000
            ),
            Err(GrantClientError::Denied { .. })
        ));
        assert!(matches!(
            accept_grant(
                &sample_response(),
                "conn-1956",
                "other-component",
                1_000_000
            ),
            Err(GrantClientError::Denied { .. })
        ));
        // Expired grant.
        assert_eq!(
            accept_grant(
                &sample_response(),
                "conn-1956",
                "component-1956",
                9_999_999_999_999
            ),
            Err(GrantClientError::Expired)
        );
        // Non-JSON bytes.
        assert!(matches!(
            accept_grant(b"not-json", "conn-1956", "component-1956", 1_000_000),
            Err(GrantClientError::Denied { .. })
        ));
    }
}
