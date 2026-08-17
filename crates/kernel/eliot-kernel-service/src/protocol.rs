//! Host↔Kernel protocol records.

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_ipc::TransportError;
use eliot_kernel_core::AuthoritySnapshotBindingWire;
use eliot_platform::{PlatformHandle, PortError, SecretReference};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessExecutionView, ProcessStartReceipt,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_runtime_contracts::{HealthVector, ServiceProcessState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{KernelServiceError, KernelServiceState, validate_text};

fn handle(value: &PlatformHandle, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value.as_str(), field)
}

/// Stable identity for the Host↔Kernel lifecycle control wire.
pub const KERNEL_CONTROL_WIRE_ID: &str = "eliot.kernel.host-control";
/// Current version of the Host↔Kernel lifecycle control wire.
pub const KERNEL_CONTROL_WIRE_VERSION: u16 = 1;
/// Canonical authenticated Kernel front-door pipe.
pub const KERNEL_CONTROL_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";

/// One authenticated Host lifecycle command.  The command is repeated with
/// the complete handshake so reconnects cannot silently inherit stale Host
/// identity, generation, or nonce state.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelControlRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Host-owned request identity.
    pub message_id: PlatformHandle,
    /// Strict in-connection sequence.
    pub sequence: u64,
    /// Process identity proven by the authenticated pipe peer.
    pub peer_process_id: u32,
    /// Approved generation bound to this control exchange.
    pub generation: ResourceGeneration,
    /// Complete Host lineage binding.
    pub handshake: HostKernelHandshake,
    /// One closed lifecycle command.
    pub command: KernelControlCommand,
    /// Digest over all fields except this digest.
    pub payload_digest: String,
}

impl KernelControlRequest {
    /// Returns canonical bytes covered by `payload_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, KernelServiceError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            wire_id: &'a str,
            wire_version: u16,
            message_id: &'a PlatformHandle,
            sequence: u64,
            peer_process_id: u32,
            generation: ResourceGeneration,
            handshake: &'a HostKernelHandshake,
            command: &'a KernelControlCommand,
        }
        serde_json::to_vec(&Unsigned {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            message_id: &self.message_id,
            sequence: self.sequence,
            peer_process_id: self.peer_process_id,
            generation: self.generation,
            handshake: &self.handshake,
            command: &self.command,
        })
        .map_err(|_| KernelServiceError::InvalidField {
            field: "control.payload_digest",
            reason: "cannot canonicalize request",
        })
    }

    /// Computes the canonical lowercase SHA-256 digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical digest.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.payload_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the bounded control request and its independent digest.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != KERNEL_CONTROL_WIRE_ID
            || self.wire_version != KERNEL_CONTROL_WIRE_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.wire",
                reason: "unsupported control wire",
            });
        }
        handle(&self.message_id, "control.message_id")?;
        if self.sequence == 0 || self.peer_process_id == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "control.sequence_or_peer",
                reason: "sequence and peer process identity must be non-zero",
            });
        }
        if self.generation.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "control.generation",
                reason: "must be non-zero",
            });
        }
        self.handshake.validate()?;
        if self.payload_digest.len() != 64
            || !self
                .payload_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.compute_digest()? != self.payload_digest
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.payload_digest",
                reason: "must be the matching lowercase SHA-256 digest",
            });
        }
        Ok(())
    }
}

/// Typed response to one authenticated Host lifecycle command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelControlResponse {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Echoed request identity.
    pub message_id: PlatformHandle,
    /// Echoed request digest.
    pub request_digest: String,
    /// Accepted Kernel lifecycle state.
    pub state: KernelServiceState,
    /// Receipt returned only after the Ready command is validated.
    pub receipt: Option<KernelReadyReceipt>,
    /// Stable rejection detail, when the command was not accepted.
    pub error: Option<String>,
    /// Digest over all fields except this digest.
    pub payload_digest: String,
}

impl KernelControlResponse {
    /// Returns canonical bytes covered by `payload_digest`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, KernelServiceError> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            wire_id: &'a str,
            wire_version: u16,
            message_id: &'a PlatformHandle,
            request_digest: &'a str,
            state: KernelServiceState,
            receipt: &'a Option<KernelReadyReceipt>,
            error: &'a Option<String>,
        }
        serde_json::to_vec(&Unsigned {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            message_id: &self.message_id,
            request_digest: &self.request_digest,
            state: self.state,
            receipt: &self.receipt,
            error: &self.error,
        })
        .map_err(|_| KernelServiceError::InvalidField {
            field: "control.payload_digest",
            reason: "cannot canonicalize response",
        })
    }

    /// Computes the canonical lowercase SHA-256 digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical digest.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.payload_digest = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the response envelope and digest.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != KERNEL_CONTROL_WIRE_ID
            || self.wire_version != KERNEL_CONTROL_WIRE_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.wire",
                reason: "unsupported control wire",
            });
        }
        handle(&self.message_id, "control.message_id")?;
        if self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.request_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if let Some(error) = &self.error {
            validate_text(error, "control.error")?;
        }
        if self.payload_digest.len() != 64
            || !self
                .payload_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || self.compute_digest()? != self.payload_digest
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.payload_digest",
                reason: "must be the matching lowercase SHA-256 digest",
            });
        }
        Ok(())
    }
}

/// Encodes one control request as a bounded authenticated EBP control frame.
pub fn control_request_frame(
    connection_id: impl Into<String>,
    request: &KernelControlRequest,
) -> Result<Frame, TransportError> {
    request
        .validate()
        .map_err(|_error| TransportError::SessionFenced)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: None,
        kind: FrameKind::Control,
        message_type: MessageType::Start,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(request).map_err(|_| TransportError::SessionFenced)?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

/// Decodes one control request from the authenticated EBP control lane.
pub fn decode_control_request_frame(frame: &Frame) -> Result<KernelControlRequest, TransportError> {
    frame.validate()?;
    if frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Start
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(TransportError::SessionFenced);
    };
    let request: KernelControlRequest =
        serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(request)
}

/// Encodes one typed control response.
pub fn control_response_frame(
    connection_id: impl Into<String>,
    response: &KernelControlResponse,
) -> Result<Frame, TransportError> {
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id: connection_id.into(),
        request_id: None,
        kind: FrameKind::Control,
        message_type: MessageType::Ready,
        request_identity: None,
        payload: ProtocolPayload::Json(
            serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
        ),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

/// Decodes one typed control response.
pub fn decode_control_response_frame(
    frame: &Frame,
) -> Result<KernelControlResponse, TransportError> {
    frame.validate()?;
    if frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Ready
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(TransportError::SessionFenced);
    };
    let response: KernelControlResponse =
        serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(response)
}

/// Versioned, secret-free one-shot process-authority handoff.
///
/// This record contains only identities, bindings, policy references and a
/// Credential Manager locator. It is not authority and cannot be used without
/// the matching secret and durable ORS snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct ProcessAuthorityHandoffDescriptor {
    pub contract_version: u16,
    pub handoff_id: PlatformHandle,
    pub handoff_nonce: PlatformHandle,
    pub authority_id: eliot_process::DispatchAuthorityId,
    pub snapshot_binding: AuthoritySnapshotBindingWire,
    pub state_fence: StateFence,
    pub generation: ResourceGeneration,
    pub revision_policy_binding: PlatformHandle,
    pub dispatch_key: SecretReference,
    pub descriptor_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub contour_refs: Vec<PlatformHandle>,
}

impl ProcessAuthorityHandoffDescriptor {
    /// Current descriptor schema revision.
    pub const CONTRACT_VERSION: u16 = 1;
    /// Maximum number of contour references admitted in one handoff.
    pub const MAX_CONTOUR_REFS: usize = 32;

    /// Returns the canonical secret-free bytes covered by `descriptor_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, KernelServiceError> {
        let mut unsigned = self.clone();
        unsigned.descriptor_sha256.clear();
        serde_json::to_vec(&unsigned).map_err(|_| KernelServiceError::InvalidField {
            field: "descriptor_sha256",
            reason: "cannot canonicalize descriptor",
        })
    }

    /// Computes the descriptor digest through the one canonical procedure.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Returns a descriptor with its checked canonical digest populated.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.descriptor_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Verifies the explicit descriptor digest without performing other checks.
    pub fn verify_digest(&self) -> Result<(), KernelServiceError> {
        if self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.compute_digest()? != self.descriptor_sha256 {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "descriptor digest mismatch",
            });
        }
        Ok(())
    }

    /// Validates syntax, digest material, time bounds, and exact fence bindings.
    pub fn validate(&self, now_ms: i64) -> Result<(), KernelServiceError> {
        if self.contract_version != Self::CONTRACT_VERSION {
            return Err(KernelServiceError::InvalidField {
                field: "contract_version",
                reason: "unsupported version",
            });
        }
        for (value, field) in [
            (&self.handoff_id, "handoff_id"),
            (&self.handoff_nonce, "handoff_nonce"),
            (&self.revision_policy_binding, "revision_policy_binding"),
        ] {
            handle(value, field)?;
        }
        if self.contour_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "contour_refs",
                reason: "must not be empty",
            });
        }
        if self.contour_refs.len() > Self::MAX_CONTOUR_REFS {
            return Err(KernelServiceError::InvalidField {
                field: "contour_refs",
                reason: "exceeds the bounded contour reference limit",
            });
        }
        let mut unique_refs = BTreeSet::new();
        for value in &self.contour_refs {
            handle(value, "contour_refs")?;
            if !unique_refs.insert(value.as_str()) {
                return Err(KernelServiceError::InvalidField {
                    field: "contour_refs",
                    reason: "references must be unique",
                });
            }
        }
        if self.issued_at_ms < 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms <= now_ms
        {
            return Err(KernelServiceError::InvalidField {
                field: "expires_at_ms",
                reason: "descriptor is expired or has invalid bounds",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "state_fence",
            })?;
        let exact_epoch = self.state_fence.authority_epoch.value();
        let exact_state_fence =
            eliot_ors::StateFenceSnapshot::capture(&self.state_fence, exact_epoch).map_err(
                |_| KernelServiceError::HandshakeMismatch {
                    field: "state_fence",
                },
            )?;
        if self.state_fence.resource_generation != self.generation
            || self.snapshot_binding.authority_id != self.authority_id
            || self.snapshot_binding.authority_epoch.current.epoch != exact_epoch
            || self.snapshot_binding.state_fence != exact_state_fence
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "authority_binding",
            });
        }
        if self.dispatch_key.provider.as_str() != "windows-credential-manager" {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "dispatch_key.provider",
            });
        }
        handle(&self.dispatch_key.key, "dispatch_key.key")?;
        if self.descriptor_sha256.len() != 64
            || !self
                .descriptor_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(KernelServiceError::InvalidField {
                field: "descriptor_sha256",
                reason: "must be a SHA-256 digest",
            });
        }
        AuthoritySnapshotBindingWire::validate(&self.snapshot_binding)?;
        self.verify_digest()
    }
}

#[cfg(test)]
mod descriptor_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, TaskRevision};
    use eliot_ors::{
        EpochIdentity, EpochLineage, OpaqueLabel, OperationIdentity, StateFenceSnapshot,
    };

    fn descriptor() -> ProcessAuthorityHandoffDescriptor {
        let authority_id =
            eliot_process::DispatchAuthorityId::new("authority-1").expect("authority");
        let epoch = EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new("lineage-1").expect("lineage"),
                epoch: 1,
            },
            predecessor: None,
        };
        let state_fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        let snapshot_fence =
            StateFenceSnapshot::capture(&state_fence, state_fence.authority_epoch.value())
                .expect("snapshot fence");
        let binding = AuthoritySnapshotBindingWire {
            authority_id: authority_id.clone(),
            record_id: OperationIdentity::new("snapshot-record").expect("record"),
            authority_epoch: epoch,
            state_fence: snapshot_fence,
            created_at_ms: 100,
            cleanup_after_ms: Some(200),
        };
        ProcessAuthorityHandoffDescriptor {
            contract_version: ProcessAuthorityHandoffDescriptor::CONTRACT_VERSION,
            handoff_id: PlatformHandle::new("handoff-1").expect("handoff"),
            handoff_nonce: PlatformHandle::new("nonce-1").expect("nonce"),
            authority_id,
            snapshot_binding: binding,
            state_fence,
            generation: ResourceGeneration::genesis(),
            revision_policy_binding: PlatformHandle::new("policy-1").expect("policy"),
            dispatch_key: SecretReference::new("windows-credential-manager", "dispatch-key-1")
                .expect("reference"),
            descriptor_sha256: String::new(),
            issued_at_ms: 100,
            expires_at_ms: 1_000,
            contour_refs: vec![
                PlatformHandle::new("portable_dev").expect("contour"),
                PlatformHandle::new("authority_descriptor").expect("descriptor contour"),
            ],
        }
    }

    #[test]
    fn descriptor_checked_digest_round_trip_is_secret_free() {
        let descriptor = descriptor().with_computed_digest().expect("digest");
        descriptor.validate(500).expect("valid descriptor");
        let bytes = serde_json::to_vec(&descriptor).expect("wire");
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(!text.contains("KernelDispatchKey"));
        assert!(!text.contains("ProcessRequest"));
        assert!(!text.contains("raw-secret"));
        let round_trip: ProcessAuthorityHandoffDescriptor =
            serde_json::from_slice(&bytes).expect("round trip");
        round_trip.validate(500).expect("round trip validation");
    }

    #[test]
    fn contract_v1_digest_preserves_legacy_json_field_order() {
        let descriptor = descriptor();
        assert_eq!(
            descriptor.compute_digest().expect("legacy digest"),
            "7df4185c6311ec6f0f9395076f8dde4c55dd0a4c0c578af23b18f3a14544b570"
        );
    }

    #[test]
    fn descriptor_rejects_unknown_duplicate_blank_and_malformed_inputs() {
        let descriptor = descriptor().with_computed_digest().expect("digest");
        let mut unknown = serde_json::to_value(&descriptor).expect("value");
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProcessAuthorityHandoffDescriptor>(unknown).is_err());

        let mut duplicate = descriptor.clone();
        duplicate
            .contour_refs
            .push(duplicate.contour_refs[0].clone());
        assert!(duplicate.validate(500).is_err());
        let mut blank = serde_json::to_value(&descriptor).expect("blank value");
        blank["contour_refs"][0] = serde_json::json!(" ");
        let blank: ProcessAuthorityHandoffDescriptor =
            serde_json::from_value(blank).expect("blank wire shape");
        assert!(blank.validate(500).is_err());
        let mut oversized = descriptor.clone();
        oversized.contour_refs = (0..=ProcessAuthorityHandoffDescriptor::MAX_CONTOUR_REFS)
            .map(|index| PlatformHandle::new(format!("contour-{index}")))
            .collect::<Result<Vec<_>, _>>()
            .expect("contours");
        assert!(oversized.validate(500).is_err());
        let mut malformed = descriptor;
        malformed.descriptor_sha256 = "not-a-digest".to_owned();
        assert!(malformed.validate(500).is_err());

        let mut uppercase = malformed;
        uppercase.descriptor_sha256 = "A".repeat(64);
        assert!(uppercase.validate(500).is_err());
    }

    #[test]
    fn wire_binding_revalidates_nested_fence_and_identity() {
        let descriptor = descriptor();
        descriptor
            .snapshot_binding
            .validate()
            .expect("wire binding");
        let mut wrong_authority = descriptor.snapshot_binding.clone();
        wrong_authority.authority_id =
            eliot_process::DispatchAuthorityId::new("other").expect("other authority");
        assert!(wrong_authority.validate().is_ok());
        let expected = eliot_kernel_core::AuthoritySnapshotBinding::from_wire(
            descriptor.snapshot_binding.clone(),
            &descriptor.authority_id,
        )
        .expect("expected binding");
        assert!(
            eliot_kernel_core::AuthoritySnapshotBinding::from_wire_exact(
                wrong_authority,
                &expected,
            )
            .is_err()
        );
        let mut broken_fence = descriptor.snapshot_binding;
        broken_fence.state_fence.sha256 = "00".repeat(32);
        assert!(broken_fence.validate().is_err());
    }

    #[test]
    fn descriptor_rejects_same_epoch_and_generation_with_different_fence_content() {
        let mut descriptor = descriptor();
        descriptor.state_fence.task_revision = Some(TaskRevision::new(2).expect("task revision"));
        descriptor = descriptor.with_computed_digest().expect("digest");
        assert!(descriptor.validate(500).is_err());
    }
}

/// Host-approved, store-neutral canonical-store bootstrap descriptor.
///
/// These values are an admission prerequisite, not caller-supplied store
/// authority.  The Kernel/store client binds every EBP handshake and request
/// to the exact pipe, store generation, schema generation, and state fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStoreBootstrapRequirement {
    /// Stable Kernel route identity selected by Host.
    pub route_identity: PlatformHandle,
    /// Canonical authenticated local-store pipe identity selected by Host.
    pub canonical_pipe_identity: PlatformHandle,
    /// Store module generation selected by Kernel/Host cutover.
    pub store_generation: ResourceGeneration,
    /// Authority/resource fence captured for this store binding.
    pub state_fence: StateFence,
    /// Host-issued launch nonce for this store lineage.
    pub launch_nonce: PlatformHandle,
    /// Transport connection identity selected for this session.
    pub connection_id: PlatformHandle,
    /// Expected authenticated peer SID for the store process.
    pub expected_peer_sid: PlatformHandle,
    /// Expected authenticated peer session id for the store process.
    pub expected_peer_session_id: u32,
    /// Host-approved store artifact digest echoed by the store handshake.
    pub approved_artifact_hash: PlatformHandle,
    /// Host-approved store configuration digest echoed by the store handshake.
    pub approved_config_hash: PlatformHandle,
    /// Bounded connection timeout selected by Host, in milliseconds.
    pub timeout_ms: u64,
}

/// Store-neutral name for the Host handoff descriptor.
pub type StoreBootstrapDescriptor = HostStoreBootstrapRequirement;

/// Closed Kernel process-execution operation set for authenticated clients.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "operation", content = "payload")]
#[allow(clippy::large_enum_variant)]
pub enum ProcessExecutionRequest {
    /// Admit and start one exact process intent.
    Start(ProcessExecutionAdmissionRequest),
    /// Inspect one admitted operation.
    Inspect {
        /// Exact operation identity to inspect.
        operation_id: OperationId,
    },
    /// Cancel one admitted operation.
    Cancel {
        /// Exact operation identity to cancel.
        operation_id: OperationId,
    },
    /// Reconcile one operation after an unknown delivery/result boundary.
    Reconcile {
        /// Exact operation identity to reconcile.
        operation_id: OperationId,
    },
}

impl ProcessExecutionRequest {
    /// Validates the closed operation payload.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::Start(request) => request
                .validate()
                .map_err(|error| KernelServiceError::Platform(error.to_string())),
            Self::Inspect { operation_id }
            | Self::Cancel { operation_id }
            | Self::Reconcile { operation_id } => {
                if operation_id.as_str().trim().is_empty() {
                    return Err(KernelServiceError::InvalidField {
                        field: "operation_id",
                        reason: "must be non-blank",
                    });
                }
                Ok(())
            }
        }
    }

    /// Returns the exact operation identity when one is present.
    pub fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::Start(request) => Some(request.intent().operation_id()),
            Self::Inspect { operation_id }
            | Self::Cancel { operation_id }
            | Self::Reconcile { operation_id } => Some(operation_id),
        }
    }
}

/// Provider-neutral response projection; no child handle or permit crosses
/// the Kernel front door.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "result", content = "payload")]
pub enum ProcessExecutionResponse {
    /// Exact receipt after a child was admitted and resumed.
    Started(ProcessStartReceipt),
    /// Current non-authoritative operation projection.
    Status(ProcessExecutionView),
    /// Exact cancellation projection.
    Cancelled(CancellationReceipt),
    /// Observation-only reconciliation evidence.
    Reconciled(ProcessEvidence),
    /// Bounded provider-neutral rejection.
    Rejected(ProcessExecutionRejection),
}

/// Stable error projection for cross-process callers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionRejection {
    /// Stable category, never a raw child/provider error.
    pub code: String,
    /// Bounded diagnostic detail.
    pub detail: String,
}

impl ProcessExecutionRejection {
    /// Converts a process execution error into a bounded transport projection.
    pub fn from_error(error: &ProcessExecutionError) -> Self {
        Self {
            code: match error {
                ProcessExecutionError::UnknownOutcome => "UNKNOWN_OUTCOME",
                ProcessExecutionError::NotFound => "NOT_FOUND",
                ProcessExecutionError::Contract(_) => "CONTRACT_REJECTED",
                ProcessExecutionError::Unavailable(_) => "UNAVAILABLE",
                ProcessExecutionError::EvidenceSink(_) => "EVIDENCE_REJECTED",
            }
            .to_owned(),
            detail: error.to_string().chars().take(512).collect(),
        }
    }
}

impl HostStoreBootstrapRequirement {
    /// Validates the complete Host-approved store binding.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.route_identity, "store_bootstrap.route_identity")?;
        if self.route_identity.as_str() != crate::STORE_ROUTE_IDENTITY {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "route_identity",
            });
        }
        handle(
            &self.canonical_pipe_identity,
            "store_bootstrap.canonical_pipe_identity",
        )?;
        handle(&self.launch_nonce, "store_bootstrap.launch_nonce")?;
        handle(&self.connection_id, "store_bootstrap.connection_id")?;
        handle(&self.expected_peer_sid, "store_bootstrap.expected_peer_sid")?;
        handle(
            &self.approved_artifact_hash,
            "store_bootstrap.approved_artifact_hash",
        )?;
        handle(
            &self.approved_config_hash,
            "store_bootstrap.approved_config_hash",
        )?;
        for (value, field) in [
            (
                &self.approved_artifact_hash,
                "store_bootstrap.approved_artifact_hash",
            ),
            (
                &self.approved_config_hash,
                "store_bootstrap.approved_config_hash",
            ),
        ] {
            if value.as_str().len() != 64
                || !value
                    .as_str()
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(KernelServiceError::InvalidField {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        self.state_fence
            .validate()
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if self.store_generation.value() == 0
            || self.store_generation != self.state_fence.resource_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_generation",
            });
        }
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(KernelServiceError::InvalidField {
                field: "store_bootstrap.timeout_ms",
                reason: "must be between 1 and 300000 milliseconds",
            });
        }
        eliot_ipc::validate_pipe_name(self.canonical_pipe_identity.as_str())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        Ok(())
    }

    /// Returns the exact authority epoch bound by this requirement.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.state_fence.authority_epoch
    }

    /// Returns the Host-approved bounded connection timeout.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

/// A bounded restart budget owned by Host for one Kernel lineage.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartBudget {
    /// Number of starts still allowed before quarantine.
    pub remaining: u32,
    /// Maximum starts admitted for this lineage.
    pub maximum: u32,
}

impl RestartBudget {
    /// Creates a budget, rejecting an inconsistent remaining count.
    pub const fn new(maximum: u32, remaining: u32) -> Result<Self, KernelServiceError> {
        if maximum == 0 || remaining > maximum {
            return Err(KernelServiceError::InvalidField {
                field: "restart_budget",
                reason: "maximum must be non-zero and remaining must not exceed maximum",
            });
        }
        Ok(Self { remaining, maximum })
    }

    /// Consumes one permitted restart without wrapping.
    pub const fn consume(self) -> Result<Self, KernelServiceError> {
        if self.remaining == 0 {
            return Err(KernelServiceError::RestartBudgetExhausted);
        }
        Ok(Self {
            remaining: self.remaining - 1,
            maximum: self.maximum,
        })
    }
}

/// A Host-observed process identity and lifecycle snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    /// Exact physical process lineage identity.
    pub process_id: PlatformHandle,
    /// Host-owned Job Object identity.
    pub job_object_id: PlatformHandle,
    /// Current process state; survival alone does not imply readiness.
    pub state: ServiceProcessState,
    /// Six-dimensional process health evidence.
    pub health: HealthVector,
    /// Opaque evidence references proving the observation.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl ProcessObservation {
    /// Validates the non-secret observation envelope.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.process_id, "process_observation.process_id")?;
        handle(&self.job_object_id, "process_observation.job_object_id")?;
        if self.evidence_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "process_observation.evidence_refs",
                reason: "at least one evidence reference is required",
            });
        }
        for evidence in &self.evidence_refs {
            handle(evidence, "process_observation.evidence_refs")?;
        }
        Ok(())
    }
}

/// The immutable Host lineage and activation binding presented to Kernel.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelHandshake {
    /// Host installation identity.
    pub installation_id: PlatformHandle,
    /// Host installation epoch that owns this process.
    pub host_epoch: AuthorityEpoch,
    /// Kernel authority epoch proposed for this activation.
    pub kernel_epoch: AuthorityEpoch,
    /// Exact activation identity shared by Host state and Kernel.
    pub activation_id: PlatformHandle,
    /// Approved immutable Kernel artifact hash/reference.
    pub artifact_hash: PlatformHandle,
    /// Immutable configuration hash/reference.
    pub config_hash: PlatformHandle,
    /// One-time activation nonce. It is consumed exactly once.
    pub activation_nonce: PlatformHandle,
    /// Host-owned Kernel Job Object identity.
    pub job_object_id: PlatformHandle,
    /// Candidate/active authenticated local IPC identity.
    pub pipe_identity: PlatformHandle,
    /// Restart budget for this lineage.
    pub restart_budget: RestartBudget,
    /// Containment action required if the previous lineage is suspect.
    pub containment_action: Option<ContainmentAction>,
}

impl HostKernelHandshake {
    /// Validates all identity and epoch invariants before a candidate starts.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (value, field) in [
            (&self.installation_id, "handshake.installation_id"),
            (&self.activation_id, "handshake.activation_id"),
            (&self.artifact_hash, "handshake.artifact_hash"),
            (&self.config_hash, "handshake.config_hash"),
            (&self.activation_nonce, "handshake.activation_nonce"),
            (&self.job_object_id, "handshake.job_object_id"),
            (&self.pipe_identity, "handshake.pipe_identity"),
        ] {
            handle(value, field)?;
        }
        if self.host_epoch.value() == 0 || self.kernel_epoch.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "handshake.epoch",
                reason: "must be non-zero",
            });
        }
        if self.host_epoch.value() > self.kernel_epoch.value() {
            return Err(KernelServiceError::InvalidField {
                field: "handshake.kernel_epoch",
                reason: "must not precede host epoch",
            });
        }
        if let Some(containment) = &self.containment_action {
            containment.validate()?;
        }
        Ok(())
    }
}

/// A Host containment action reference, not an instruction to perform OS work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentAction {
    /// Stable action identity recorded by Host/Watchdog.
    pub action_id: PlatformHandle,
    /// Evidence that the prior lineage was contained or marked suspect.
    pub evidence_ref: PlatformHandle,
}

impl ContainmentAction {
    /// Validates the action envelope.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.action_id, "containment.action_id")?;
        handle(&self.evidence_ref, "containment.evidence_ref")
    }
}

/// Receipt proving that a Kernel candidate consumed its Host handoff nonce.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReadyReceipt {
    /// Activation identity echoed from the handshake.
    pub activation_id: PlatformHandle,
    /// Activation nonce echoed from the handshake.
    pub activation_nonce: PlatformHandle,
    /// Process and Job Object observation at readiness time.
    pub process: ProcessObservation,
    /// Kernel health vector at readiness time.
    pub health: HealthVector,
    /// Kernel-side readiness evidence references.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl KernelReadyReceipt {
    /// Validates readiness without inferring success from process existence.
    pub fn validate(&self, handshake: &HostKernelHandshake) -> Result<(), KernelServiceError> {
        handle(&self.activation_id, "ready.activation_id")?;
        handle(&self.activation_nonce, "ready.activation_nonce")?;
        if self.activation_id != handshake.activation_id {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_id",
            });
        }
        if self.activation_nonce != handshake.activation_nonce {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_nonce",
            });
        }
        self.process.validate()?;
        if self.process.job_object_id != handshake.job_object_id {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        if self.process.state != ServiceProcessState::Ready
            || !self.process.health.is_fully_healthy()
            || !self.health.is_fully_healthy()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if self.evidence_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "ready.evidence_refs",
                reason: "at least one readiness evidence reference is required",
            });
        }
        for evidence in &self.evidence_refs {
            handle(evidence, "ready.evidence_refs")?;
        }
        Ok(())
    }
}

/// Control messages accepted by the Kernel service boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum KernelControlCommand {
    /// Begin reconciliation of one Host activation lineage.
    Reconcile(HostKernelHandshake),
    /// Enter side-by-side candidate mode without authority.
    Shadow,
    /// Record that Host prepared the exclusive handoff.
    PrepareHandoff,
    /// Begin consuming the one-time activation nonce.
    Activate,
    /// Publish a complete readiness receipt.
    Ready(KernelReadyReceipt),
    /// Close normal admission while retaining recovery control.
    Degrade(PlatformHandle),
    /// Drain normal work before stopping.
    Drain,
    /// Record a clean stop.
    Stop,
    /// Record a bounded failure and its recovery reference.
    Fail(PlatformHandle),
}

impl From<PortError> for KernelServiceError {
    fn from(error: PortError) -> Self {
        Self::Platform(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;

    fn handle_value(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("test handle")
    }

    fn requirement() -> HostStoreBootstrapRequirement {
        let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        HostStoreBootstrapRequirement {
            route_identity: handle_value(crate::STORE_ROUTE_IDENTITY),
            canonical_pipe_identity: handle_value(r"\\.\pipe\eliot\store"),
            store_generation: ResourceGeneration::genesis(),
            state_fence: fence,
            launch_nonce: handle_value("nonce-1"),
            connection_id: handle_value("connection-1"),
            expected_peer_sid: handle_value("S-1-5-18"),
            expected_peer_session_id: 0,
            approved_artifact_hash: handle_value(&"a".repeat(64)),
            approved_config_hash: handle_value(&"b".repeat(64)),
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn store_bootstrap_accepts_system_session_zero() {
        assert!(requirement().validate().is_ok());
    }

    #[test]
    fn store_bootstrap_rejects_generation_or_digest_substitution() {
        let mut wrong_generation = requirement();
        wrong_generation.store_generation = ResourceGeneration::new(2).expect("generation");
        assert!(wrong_generation.validate().is_err());

        let mut wrong_digest = requirement();
        wrong_digest.approved_config_hash = handle_value(&"C".repeat(64));
        assert!(wrong_digest.validate().is_err());
    }

    #[test]
    fn process_wire_operation_has_no_caller_projection() {
        let operation = ProcessExecutionRequest::Inspect {
            operation_id: OperationId::new("op-1").expect("operation"),
        };
        let value = serde_json::to_value(operation).expect("json");
        assert!(value.get("caller").is_none());
        assert_eq!(value["operation"], "Inspect");
    }

    fn control_handshake() -> HostKernelHandshake {
        HostKernelHandshake {
            installation_id: handle_value("installation-1"),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: AuthorityEpoch::new(1).expect("kernel epoch"),
            activation_id: handle_value("activation-1"),
            artifact_hash: handle_value("artifact-1"),
            config_hash: handle_value("config-1"),
            activation_nonce: handle_value("nonce-1"),
            job_object_id: handle_value("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle_value(KERNEL_CONTROL_PIPE),
            restart_budget: RestartBudget::new(1, 1).expect("budget"),
            containment_action: None,
        }
    }

    #[test]
    fn control_wire_digest_and_unknown_fields_are_fail_closed() {
        let request = KernelControlRequest {
            wire_id: KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: KERNEL_CONTROL_WIRE_VERSION,
            message_id: handle_value("message-1"),
            sequence: 1,
            peer_process_id: 42,
            generation: ResourceGeneration::new(1).expect("generation"),
            handshake: control_handshake(),
            command: KernelControlCommand::Shadow,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .expect("digest");
        let frame = control_request_frame("control-1", &request).expect("frame");
        let decoded = decode_control_request_frame(&frame).expect("decode");
        assert_eq!(decoded, request);
        let mut tampered = request;
        tampered.sequence = 2;
        assert!(tampered.validate().is_err());
        let mut json = serde_json::to_value(decoded).expect("json");
        json["unknown"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<KernelControlRequest>(json).is_err());
    }

    fn ready_receipt(handshake: &HostKernelHandshake) -> KernelReadyReceipt {
        KernelReadyReceipt {
            activation_id: handshake.activation_id.clone(),
            activation_nonce: handshake.activation_nonce.clone(),
            process: ProcessObservation {
                process_id: handle_value("pid:42:start:1"),
                job_object_id: handshake.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle_value("process-evidence-1")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle_value("ready-evidence-1")],
        }
    }

    #[test]
    fn ready_receipt_rejects_nonce_job_health_and_evidence_substitution() {
        let handshake = control_handshake();
        let receipt = ready_receipt(&handshake);
        assert!(receipt.validate(&handshake).is_ok());

        let mut wrong_nonce = receipt.clone();
        wrong_nonce.activation_nonce = handle_value("nonce-other");
        assert!(wrong_nonce.validate(&handshake).is_err());

        let mut wrong_job = receipt.clone();
        wrong_job.process.job_object_id = handle_value("Local\\Eliot-Other-Job");
        assert!(wrong_job.validate(&handshake).is_err());

        let mut unhealthy = receipt.clone();
        unhealthy.health.liveness = eliot_runtime_contracts::HealthDimension::Degraded;
        assert!(unhealthy.validate(&handshake).is_err());

        let mut missing_evidence = receipt;
        missing_evidence.evidence_refs.clear();
        assert!(missing_evidence.validate(&handshake).is_err());
    }
}
