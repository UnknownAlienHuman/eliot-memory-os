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
#[derive(Clone, Debug, Eq, PartialEq)]
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
