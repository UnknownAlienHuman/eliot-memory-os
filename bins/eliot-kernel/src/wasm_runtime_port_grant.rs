//! Typed WASM port-grant issuance and validation (issue #1955, I14.19).
//!
//! The `eliot-wasm-host` binary performs governed calls only through a
//! complete Kernel-admitted port grant. This module is the legitimate
//! server side of that grant: it issues and validates digest-bound grant
//! artifacts over actual Kernel-observed facts, using only owner
//! primitives (canonical JSON digests, fence/epoch coherence, deadline
//! checks — the same scheme as the host-request receipt family). It mints
//! no permits (P-07 dispatch authority stays untouched and uncalled), no
//! Governor observations (manifest contents stay caller-asserted and are
//! re-hashed downstream by `from_owners`-equivalents), and no keys.
//!
//! Authority actually exercised here: none beyond attestation. Every
//! Kernel-side fact (`observed` and `host` below — fence, epoch,
//! connection, clock, installation-approved binary binding) is THREADED
//! from Kernel/installation state by the composing caller (the binary
//! pair comes from `RuntimeLaunchDescriptor::wasm_host_artifact_binding`,
//! B2/installer lane); this module echoes it into the grant and checks
//! coherence, never inventing it. Registration of this issue/validate
//! pair into a dispatch route and any composition wiring belongs to
//! Beauvoir's shared-Kernel registration/composition span (see
//! `CONTROL/1955-kernel-grant-handoff.md`); this file owns only the pure
//! grant logic and its proof.

use std::fmt;

use eliot_contracts::{EpochId, StateFence, canonical_json_bytes};
use eliot_protocol::{HostRequestAdmissionReceipt, HostRequestEnvelope};
use serde::{Deserialize, Serialize};

/// Wire identity for grant requests issued by WASM host callers.
pub const WASM_GRANT_REQUEST_WIRE_ID: &str = "eliot.wasm.port-grant-request";
/// Wire version for grant requests.
pub const WASM_GRANT_REQUEST_WIRE_VERSION: u16 = 1;
/// Wire identity for issued port grants.
pub const WASM_PORT_GRANT_WIRE_ID: &str = "eliot.wasm.port-grant";
/// Wire version for issued port grants.
pub const WASM_PORT_GRANT_WIRE_VERSION: u16 = 1;
/// Closed private operation name the dispatch route registers for grant
/// issuance. Beauvoir's registration span adds exactly this string to the
/// operation map; no other spelling is admitted.
pub const WASM_PORT_GRANT_OPERATION: &str = "wasm_port_grant_issue";

/// Fail-closed grant errors. No reason strings cross trust boundaries
/// beyond stable field names; denial taxonomy lives with the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WasmGrantError {
    /// A field failed a structural or digest check.
    InvalidField {
        /// Stable field name.
        field: &'static str,
    },
    /// The request deadline already passed at issue time.
    Expired,
    /// A threaded Kernel observation disagrees with the request.
    ObservationMismatch {
        /// Stable field name.
        field: &'static str,
    },
}

impl fmt::Display for WasmGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField { field } => write!(formatter, "WASM_GRANT_INVALID:{field}"),
            Self::Expired => formatter.write_str("WASM_GRANT_EXPIRED"),
            Self::ObservationMismatch { field } => {
                write!(formatter, "WASM_GRANT_OBSERVATION_MISMATCH:{field}")
            }
        }
    }
}

impl std::error::Error for WasmGrantError {}

/// Caller-presented grant request: who calls, for which component bytes,
/// under which fence, with what nonce and deadline. Caller-asserted fields
/// (digests) are bound tamper-evident but NOT verified here — the consumer
/// re-hashes real bytes against them, exactly like the contour admission
/// does. Transport/session authentication stays with the dispatch route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmGrantRequest {
    /// Wire identity, must equal [`WASM_GRANT_REQUEST_WIRE_ID`].
    pub wire_id: String,
    /// Wire version, must equal [`WASM_GRANT_REQUEST_WIRE_VERSION`].
    pub wire_version: u16,
    /// Authenticated caller principal (echoed from the session owner).
    pub caller_principal: String,
    /// Kernel-created transport connection identity.
    pub caller_connection: String,
    /// Requested component identity.
    pub component_id: String,
    /// Caller-asserted SHA-256 hex of the component artifact bytes.
    pub artifact_digest: String,
    /// Caller-asserted SHA-256 hex of the WIT world bytes.
    pub interface_digest: String,
    /// Fence the caller observed.
    pub state_fence: StateFence,
    /// Epoch the caller observed.
    pub authority_epoch: EpochId,
/// Caller nonce; exactly one issuance per nonce per caller.
    pub nonce: String,
    /// Absolute deadline (unix ms) the grant must not outlive.
    pub deadline_unix_ms: u64,
    /// Lowercase SHA-256 over every field except this one.
    pub request_sha256: String,
}

/// Host binary facts threaded from the installation-approved launch
/// descriptor (`RuntimeLaunchDescriptor::wasm_host_artifact_binding`,
/// B2/installer lane) by the composing caller — never caller-asserted.
/// The grant carries them so the installed-binary lane and the P03
/// launch-time re-hash verify the same pair the Kernel observed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostBinaryFacts {
    /// Installation-approved host executable path.
    pub executable_path: String,
    /// SHA-256 hex of the host image bytes at descriptor admission.
    pub artifact_digest: String,
}

/// Kernel-observed facts threaded by the composing caller (Kernel state,
/// never minted here). Registration owns how these are read; this module
/// only echoes and coherence-checks them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelObservedGrantFacts {
    /// Current Kernel fence.
    pub state_fence: StateFence,
    /// Current Kernel authority epoch.
    pub authority_epoch: EpochId,
    /// Transport connection identity the request arrived on.
    pub connection_id: String,
    /// Current Kernel clock (unix ms) for deadline checks.
    pub now_unix_ms: u64,
}

/// Issued port grant: the request echoed against Kernel observations, all
/// digest-bound. Verifiable without trusting transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmPortGrant {
    /// Wire identity, must equal [`WASM_PORT_GRANT_WIRE_ID`].
    pub wire_id: String,
    /// Wire version, must equal [`WASM_PORT_GRANT_WIRE_VERSION`].
    pub wire_version: u16,
    /// Digest of the exact admitted request.
    pub request_sha256: String,
    /// Caller principal echoed from the request.
    pub caller_principal: String,
    /// Transport connection echoed from Kernel observation.
    pub caller_connection: String,
    /// Component identity echoed from the request.
    pub component_id: String,
    /// Caller-asserted artifact digest, bound (verified downstream).
    pub artifact_digest: String,
    /// Caller-asserted interface digest, bound (verified downstream).
    pub interface_digest: String,
    /// Kernel-observed fence at issuance.
    pub state_fence: StateFence,
    /// Kernel-observed epoch at issuance.
    pub authority_epoch: EpochId,
    /// Caller nonce echoed from the request.
    pub nonce: String,
    /// Deadline echoed from the request.
    pub deadline_unix_ms: u64,
    /// Installation-approved host binary path echoed from the request.
    pub host_executable_path: String,
    /// SHA-256 hex of the host binary bytes, caller-asserted and bound
    /// (verified at resolution and re-hashed at launch, never trusted
    /// from this digest alone).
    pub host_artifact_digest: String,
    /// Lowercase SHA-256 over every field except this one.
    pub grant_sha256: String,
}

/// Canonical bytes covered by a digest field: every field except the digest
/// itself. Mirrors the receipt family's scheme exactly.
fn unsigned_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, WasmGrantError> {
    canonical_json_bytes(value).map_err(|_| WasmGrantError::InvalidField {
        field: "canonical-bytes",
    })
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bounded(value: &str, field: &'static str) -> Result<(), WasmGrantError> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
    {
        return Err(WasmGrantError::InvalidField { field });
    }
    Ok(())
}

impl WasmGrantRequest {
    /// Returns canonical bytes covered by `request_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, WasmGrantError> {
        let mut unsigned = self.clone();
        unsigned.request_sha256.clear();
        unsigned_bytes(&unsigned)
    }

    /// Computes the canonical request digest.
    pub fn compute_digest(&self) -> Result<String, WasmGrantError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Validates shape and self digest without admitting anything.
    pub fn validate(&self) -> Result<(), WasmGrantError> {
        if self.wire_id != WASM_GRANT_REQUEST_WIRE_ID
            || self.wire_version != WASM_GRANT_REQUEST_WIRE_VERSION
        {
            return Err(WasmGrantError::InvalidField { field: "wire" });
        }
        bounded(&self.caller_principal, "caller_principal")?;
        bounded(&self.caller_connection, "caller_connection")?;
        bounded(&self.component_id, "component_id")?;
        bounded(&self.nonce, "nonce")?;
        if !is_hex64(&self.artifact_digest) {
            return Err(WasmGrantError::InvalidField {
                field: "artifact_digest",
            });
        }
        if !is_hex64(&self.interface_digest) {
            return Err(WasmGrantError::InvalidField {
                field: "interface_digest",
            });
        }
        if self.deadline_unix_ms == 0 {
            return Err(WasmGrantError::InvalidField {
                field: "deadline_unix_ms",
            });
        }
        if self.request_sha256 != self.compute_digest()? {
            return Err(WasmGrantError::InvalidField {
                field: "request_sha256",
            });
        }
        Ok(())
    }
}

impl WasmPortGrant {
    /// Returns canonical bytes covered by `grant_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, WasmGrantError> {
        let mut unsigned = self.clone();
        unsigned.grant_sha256.clear();
        unsigned_bytes(&unsigned)
    }

    /// Computes the canonical grant digest.
    pub fn compute_digest(&self) -> Result<String, WasmGrantError> {
        Ok(eliot_contracts::sha256_hex(
            &self.canonical_unsigned_bytes()?,
        ))
    }

    /// Validates shape and self digest without trusting transport.
    pub fn validate(&self) -> Result<(), WasmGrantError> {
        if self.wire_id != WASM_PORT_GRANT_WIRE_ID
            || self.wire_version != WASM_PORT_GRANT_WIRE_VERSION
        {
            return Err(WasmGrantError::InvalidField { field: "wire" });
        }
        bounded(&self.caller_principal, "caller_principal")?;
        bounded(&self.caller_connection, "caller_connection")?;
        bounded(&self.component_id, "component_id")?;
        bounded(&self.nonce, "nonce")?;
        bounded(&self.host_executable_path, "host_executable_path")?;
        if !is_hex64(&self.artifact_digest)
            || !is_hex64(&self.interface_digest)
            || !is_hex64(&self.request_sha256)
            || !is_hex64(&self.host_artifact_digest)
        {
            return Err(WasmGrantError::InvalidField { field: "digest" });
        }
        if self.deadline_unix_ms == 0 {
            return Err(WasmGrantError::InvalidField {
                field: "deadline_unix_ms",
            });
        }
        if self.grant_sha256 != self.compute_digest()? {
            return Err(WasmGrantError::InvalidField {
                field: "grant_sha256",
            });
        }
        Ok(())
    }
}

/// Issues one port grant for a validated request against Kernel-observed
/// facts plus installation-observed host binary facts. Denies expired
/// requests, digest breaks, and any disagreement between the request and
/// Kernel observation (connection, fence, epoch lineage). The host binary
/// pair arrives via `host` (threaded from
/// `RuntimeLaunchDescriptor::wasm_host_artifact_binding` by the composing
/// caller — never caller-asserted) and is shape-checked here; its truth is
/// proven at resolution and launch re-hash, not by this digest. Issues no
/// permits, no Governor observations, no keys: the grant attests transport
/// + freshness and carries caller digests for downstream re-hashing. The
/// allow decision itself belongs to the live policy/capability owner —
/// this constructor runs only after that owner allows.
pub fn issue_wasm_port_grant(
    request: &WasmGrantRequest,
    observed: &KernelObservedGrantFacts,
    host: &HostBinaryFacts,
) -> Result<WasmPortGrant, WasmGrantError> {
    request.validate()?;
    if request.deadline_unix_ms <= observed.now_unix_ms {
        return Err(WasmGrantError::Expired);
    }
    if request.caller_connection != observed.connection_id {
        return Err(WasmGrantError::ObservationMismatch {
            field: "caller_connection",
        });
    }
    if request.state_fence != observed.state_fence {
        return Err(WasmGrantError::ObservationMismatch {
            field: "state_fence",
        });
    }
    if !request
        .authority_epoch
        .is_same_authority(&observed.authority_epoch)
    {
        return Err(WasmGrantError::ObservationMismatch {
            field: "authority_epoch",
        });
    }
    bounded(&host.executable_path, "host_executable_path")?;
    if !is_hex64(&host.artifact_digest) {
        return Err(WasmGrantError::InvalidField {
            field: "host_artifact_digest",
        });
    }
    let mut grant = WasmPortGrant {
        wire_id: WASM_PORT_GRANT_WIRE_ID.to_owned(),
        wire_version: WASM_PORT_GRANT_WIRE_VERSION,
        request_sha256: request.request_sha256.clone(),
        caller_principal: request.caller_principal.clone(),
        caller_connection: observed.connection_id.clone(),
        component_id: request.component_id.clone(),
        artifact_digest: request.artifact_digest.clone(),
        interface_digest: request.interface_digest.clone(),
        state_fence: observed.state_fence.clone(),
        authority_epoch: observed.authority_epoch.clone(),
        nonce: request.nonce.clone(),
        deadline_unix_ms: request.deadline_unix_ms,
        host_executable_path: host.executable_path.clone(),
        host_artifact_digest: host.artifact_digest.clone(),
        grant_sha256: String::new(),
    };
    grant.grant_sha256 = grant.compute_digest()?;
    Ok(grant)
}

/// Session facts threaded from the transport session guard by the
/// composing caller (principal + connection the request arrived on).
/// Registration owns how these are read; the handler only matches them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerSession {
    /// Authenticated caller principal.
    pub principal: String,
    /// Transport connection identity.
    pub connection_id: String,
}

/// Handles one grant request against the live admission decision plus
/// session, Kernel, and host-binary observations: the dedicated Kernel
/// entry the dispatch route calls for [`WASM_PORT_GRANT_OPERATION`].
/// Composes only existing owners and this module's pure issue path — no
/// permits minted, no Governor observations minted, no keys touched:
///
/// - live admission decision: the receipt must validate and bind the
///   admitted envelope ([`HostRequestAdmissionReceipt::validate`] +
///   `validate_envelope`, both existing owner checks). No receipt from
///   the admitted path means no grant, ever — same-generation/fence
///   authorization is proven by this binding, not by caller strings;
/// - envelope freshness: the admitted envelope's fence must equal the
///   current Kernel fence (single-snapshot discipline; a stale caller
///   re-admits instead of executing against a rotated fence);
/// - session binding: principal and connection must match the request's
///   caller claims (an authenticated stranger's request for another
///   principal fails here);
/// - host binary binding: threaded from the installation-approved
///   descriptor (never caller-asserted), shape-checked at issue;
/// - Kernel attestation + digest-bound issuance over threaded
///   [`KernelObservedGrantFacts`].
pub fn handle_wasm_port_grant(
    receipt: &HostRequestAdmissionReceipt,
    envelope: &HostRequestEnvelope,
    session: &HandlerSession,
    kernel: &KernelObservedGrantFacts,
    request: &WasmGrantRequest,
    host: &HostBinaryFacts,
) -> Result<WasmPortGrant, WasmGrantError> {
    receipt
        .validate_envelope(envelope)
        .map_err(|_| WasmGrantError::InvalidField {
            field: "admission-receipt",
        })?;
    if envelope.state_fence != kernel.state_fence {
        return Err(WasmGrantError::ObservationMismatch {
            field: "envelope-fence",
        });
    }
    bounded(&session.principal, "session.principal")?;
    bounded(&session.connection_id, "session.connection")?;
    if session.principal != request.caller_principal {
        return Err(WasmGrantError::ObservationMismatch {
            field: "caller_principal",
        });
    }
    if session.connection_id != request.caller_connection {
        return Err(WasmGrantError::ObservationMismatch {
            field: "caller_connection",
        });
    }
    issue_wasm_port_grant(request, kernel, host)
}

/// Expected caller binding for grant validation.
pub struct WasmGrantExpectation<'a> {
    /// Principal the grant must name.
    pub caller_principal: &'a str,
    /// Connection the grant must name.
    pub caller_connection: &'a str,
    /// Component the grant must name.
    pub component_id: &'a str,
    /// Clock for the deadline check.
    pub now_unix_ms: u64,
}

/// Validates one grant against the expected caller binding: shape, self
/// digest, echo bindings, and deadline. Pure — no state, no transport.
pub fn validate_wasm_port_grant(
    grant: &WasmPortGrant,
    expected: &WasmGrantExpectation<'_>,
) -> Result<(), WasmGrantError> {
    grant.validate()?;
    if grant.caller_principal != expected.caller_principal
        || grant.caller_connection != expected.caller_connection
        || grant.component_id != expected.component_id
    {
        return Err(WasmGrantError::ObservationMismatch {
            field: "caller-binding",
        });
    }
    if grant.deadline_unix_ms <= expected.now_unix_ms {
        return Err(WasmGrantError::Expired);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn test_fence() -> StateFence {
        use eliot_contracts::{EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
    }

    fn test_epoch() -> EpochId {
        test_fence().authority_epoch.clone()
    }

    fn sealed_request() -> WasmGrantRequest {
        let mut request = WasmGrantRequest {
            wire_id: WASM_GRANT_REQUEST_WIRE_ID.to_owned(),
            wire_version: WASM_GRANT_REQUEST_WIRE_VERSION,
            caller_principal: "S-1-5-18".to_owned(),
            caller_connection: "conn-1956".to_owned(),
            component_id: "component-1956".to_owned(),
            artifact_digest: "a".repeat(64),
            interface_digest: "b".repeat(64),
            state_fence: test_fence(),
            authority_epoch: test_epoch(),
            nonce: "nonce-1956".to_owned(),
            deadline_unix_ms: 9_999_999_999_999,
            request_sha256: String::new(),
        };
        request.request_sha256 = request.compute_digest().expect("seal");
        request
    }

    fn observed() -> KernelObservedGrantFacts {
        KernelObservedGrantFacts {
            state_fence: test_fence(),
            authority_epoch: test_epoch(),
            connection_id: "conn-1956".to_owned(),
            now_unix_ms: 1_000_000,
        }
    }

    fn host_facts() -> HostBinaryFacts {
        HostBinaryFacts {
            executable_path: "C:\\Kernel\\eliot-wasm-host.exe".to_owned(),
            artifact_digest: "e".repeat(64),
        }
    }

    /// Admitted transport envelope + receipt pair from the real owner
    /// constructors: the receipt exists only because the envelope passed
    /// the closed admission shape — the live decision the handler honors.
    fn admitted_pair() -> (
        eliot_protocol::HostRequestEnvelope,
        eliot_protocol::HostRequestAdmissionReceipt,
    ) {
        use eliot_protocol::{HostRequestEnvelope, HostRequestIdentity, HostRequestKind};
        let identity = HostRequestIdentity {
            request_id: must_request_id("hostreq-1956-1"),
            idempotency_key: "idem-1956-1".to_owned(),
            cancellation_id: "cancel-1956-1".to_owned(),
            parent_operation_id: None,
            deadline_unix_ms: 9_999_999_999_999,
            capability: "wasm.port-grant".to_owned(),
            session_id: Some("session-1956".to_owned()),
            task_id: None,
            work_scope_id: None,
            payload_schema_id: "wasm.port-grant-request.v1".to_owned(),
            payload_sha256: "d".repeat(64),
        };
        let envelope = HostRequestEnvelope {
            wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-1956".to_owned(),
            identity,
            state_fence: test_fence(),
            descriptor_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("admitted envelope");
        let receipt =
            eliot_protocol::HostRequestAdmissionReceipt::issue(&envelope).expect("receipt");
        (envelope, receipt)
    }

    fn must_request_id(value: &str) -> eliot_contracts::RequestId {
        eliot_contracts::RequestId::new(value).expect("request id")
    }

    #[test]
    fn issue_then_validate_round_trips() {
        let grant = issue_wasm_port_grant(&sealed_request(), &observed(), &host_facts()).expect("issue");
        assert_eq!(grant.request_sha256, sealed_request().request_sha256);
        assert_eq!(grant.caller_connection, "conn-1956");
        validate_wasm_port_grant(
            &grant,
            &WasmGrantExpectation {
                caller_principal: "S-1-5-18",
                caller_connection: "conn-1956",
                component_id: "component-1956",
                now_unix_ms: 1_000_000,
            },
        )
        .expect("validate");
        // Deterministic recomputation, not canned: re-issue is identical.
        let again = issue_wasm_port_grant(&sealed_request(), &observed(), &host_facts()).expect("issue");
        assert_eq!(grant.grant_sha256, again.grant_sha256);
    }

    #[test]
    fn tampered_grant_field_fails_validation() {
        let mut grant = issue_wasm_port_grant(&sealed_request(), &observed(), &host_facts()).expect("issue");
        grant.artifact_digest = "c".repeat(64);
        assert!(validate_wasm_port_grant(
            &grant,
            &WasmGrantExpectation {
                caller_principal: "S-1-5-18",
                caller_connection: "conn-1956",
                component_id: "component-1956",
                now_unix_ms: 1_000_000,
            },
        )
        .is_err());
    }

    #[test]
    fn handler_binds_session_before_issuing() {
        let session = HandlerSession {
            principal: "S-1-5-18".to_owned(),
            connection_id: "conn-1956".to_owned(),
        };
        let (envelope, receipt) = admitted_pair();
        let grant = handle_wasm_port_grant(
            &receipt,
            &envelope,
            &session,
            &observed(),
            &sealed_request(),
            &host_facts(),
        )
        .expect("handler issues");
        assert_eq!(grant.caller_principal, "S-1-5-18");
        assert_eq!(
            grant.host_executable_path,
            "C:\\Kernel\\eliot-wasm-host.exe"
        );
        assert_eq!(grant.host_artifact_digest, "e".repeat(64));
        let stranger = HandlerSession {
            principal: "S-1-5-19".to_owned(),
            connection_id: "conn-1956".to_owned(),
        };
        assert_eq!(
            handle_wasm_port_grant(
                &receipt,
                &envelope,
                &stranger,
                &observed(),
                &sealed_request(),
                &host_facts(),
            ),
            Err(WasmGrantError::ObservationMismatch {
                field: "caller_principal"
            })
        );
    }

    #[test]
    fn handler_denies_without_live_admission() {
        let session = HandlerSession {
            principal: "S-1-5-18".to_owned(),
            connection_id: "conn-1956".to_owned(),
        };
        // Tampered receipt no longer binds the envelope: no live admission
        // decision exists, so no grant issues.
        let (envelope, mut receipt) = admitted_pair();
        receipt.request_sha256 = "f".repeat(64);
        assert_eq!(
            handle_wasm_port_grant(
                &receipt,
                &envelope,
                &session,
                &observed(),
                &sealed_request(),
                &host_facts(),
            ),
            Err(WasmGrantError::InvalidField {
                field: "admission-receipt"
            })
        );
        // Envelope from a rotated fence: the admission belongs to another
        // snapshot, so the current Kernel fence refuses it.
        let (mut stale_envelope, _) = admitted_pair();
        let mut rotated = test_fence();
        rotated.resource_generation =
            eliot_contracts::ResourceGeneration::new(2).expect("generation");
        stale_envelope.state_fence = rotated;
        stale_envelope.envelope_sha256 = stale_envelope
            .compute_digest()
            .expect("reseal envelope");
        let stale_receipt =
            eliot_protocol::HostRequestAdmissionReceipt::issue(&stale_envelope)
                .expect("stale receipt");
        assert_eq!(
            handle_wasm_port_grant(
                &stale_receipt,
                &stale_envelope,
                &session,
                &observed(),
                &sealed_request(),
                &host_facts(),
            ),
            Err(WasmGrantError::ObservationMismatch {
                field: "envelope-fence"
            })
        );
    }

    #[test]
    fn expired_and_foreign_observations_fail_closed() {
        let mut stale = sealed_request();
        stale.deadline_unix_ms = 500_000;
        stale.request_sha256 = stale.compute_digest().expect("reseal");
        assert_eq!(
            issue_wasm_port_grant(&stale, &observed(), &host_facts()),
            Err(WasmGrantError::Expired)
        );
        let mut foreign_connection = observed();
        foreign_connection.connection_id = "conn-foreign".to_owned();
        assert_eq!(
            issue_wasm_port_grant(&sealed_request(), &foreign_connection, &host_facts()),
            Err(WasmGrantError::ObservationMismatch {
                field: "caller_connection"
            })
        );
        let mut foreign_fence = observed();
        let mut rotated = test_fence();
        rotated.resource_generation =
            eliot_contracts::ResourceGeneration::new(2).expect("generation");
        foreign_fence.state_fence = rotated;
        assert_eq!(
            issue_wasm_port_grant(&sealed_request(), &foreign_fence, &host_facts()),
            Err(WasmGrantError::ObservationMismatch {
                field: "state_fence"
            })
        );
        let grant = issue_wasm_port_grant(&sealed_request(), &observed(), &host_facts()).expect("issue");
        assert_eq!(
            validate_wasm_port_grant(
                &grant,
                &WasmGrantExpectation {
                    caller_principal: "S-1-5-18",
                    caller_connection: "conn-foreign",
                    component_id: "component-1956",
                    now_unix_ms: 1_000_000,
                },
            ),
            Err(WasmGrantError::ObservationMismatch {
                field: "caller-binding"
            })
        );
    }
}
