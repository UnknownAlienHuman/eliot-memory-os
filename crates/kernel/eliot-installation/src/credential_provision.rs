//! Secret-free durable contract for `LocalService` Store credential provisioning.

use eliot_contracts::ResourceGeneration;
use eliot_ipc::TransportError;
use eliot_platform::PlatformHandle;
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{InstallationError, handle, sha256_handle, sha256_hex};

/// Stable one-shot Host credential-control wire.
pub const HOST_CREDENTIAL_CONTROL_WIRE: &str = "eliot.host.store-credential.v1";

/// Single existing EBP named-pipe family used by Host for one-shot installer
/// credential control. Authority comes from pipe-handle peer proof, not name.
pub const HOST_CREDENTIAL_CONTROL_PIPE: &str = r"\\.\pipe\eliot-host-store-credential-v1";

/// Exact Windows SID of the built-in `LocalService` principal.
pub const LOCAL_SERVICE_SID: &str = "S-1-5-19";

/// Validates the one canonical Credential Manager target admitted for Store.
///
/// The target is an opaque `PlatformHandle` at the wire boundary, but its
/// namespace and unpredictable token are part of the installation authority.
/// Callers must compare the exact validated value; no target may be derived,
/// defaulted or substituted at runtime.
pub fn validate_store_credential_target(value: &str) -> Result<(), String> {
    let target_token = value.strip_prefix("eliot/store/v1/");
    if target_token.is_none_or(|token| {
        token.len() != 32
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err("must be an unpredictable reserved Store credential target".to_owned());
    }
    Ok(())
}

/// Credential provider admitted for the production Store process.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialProvider {
    /// Current-token Windows Credential Manager.
    WindowsCredentialManager,
}

/// OS principal scope which owns the credential and performs every readback.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialScope {
    /// The built-in `LocalService` account (`S-1-5-19`).
    LocalService,
}

/// Immutable Store credential effect payload retained by the installation plan.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialProvisionPlan {
    /// Exact protected Host state root containing the non-secret ownership marker.
    pub host_state_root: PlatformHandle,
    /// Exact canonical `EliotHost` executable registered with SCM.
    pub expected_host_executable: PlatformHandle,
    /// Unpredictable Credential Manager target; never credential bytes.
    ///
    /// It must remain unavailable to other `LocalService` processes until the
    /// exact authenticated Host request. `WinCred` has no create-only write, so
    /// this non-public target plus the create-new marker is the final race
    /// trust boundary; any observed target is rejected and never overwritten.
    pub target: PlatformHandle,
    /// Exact provider implementation.
    pub provider: StoreCredentialProvider,
    /// Exact token scope.
    pub scope: StoreCredentialScope,
    /// Exact principal SID required at Host and Store readback.
    pub expected_principal_sid: PlatformHandle,
    /// Store generation receiving the credential reference.
    pub generation: ResourceGeneration,
    /// Digest of the exact Store configuration, never its secret.
    pub config_digest: PlatformHandle,
}

impl StoreCredentialProvisionPlan {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.host_state_root, "credential.host_state_root")?;
        handle(
            &self.expected_host_executable,
            "credential.expected_host_executable",
        )?;
        if !std::path::Path::new(self.expected_host_executable.as_str()).is_absolute() {
            return Err(InstallationError::InvalidField {
                field: "credential.expected_host_executable".to_owned(),
                reason: "must be an absolute canonical path".to_owned(),
            });
        }
        handle(&self.target, "credential.target")?;
        if let Err(reason) = validate_store_credential_target(self.target.as_str()) {
            return Err(InstallationError::InvalidField {
                field: "credential.target".to_owned(),
                reason,
            });
        }
        handle(
            &self.expected_principal_sid,
            "credential.expected_principal_sid",
        )?;
        if self.expected_principal_sid.as_str() != LOCAL_SERVICE_SID {
            return Err(InstallationError::ProfileViolation(
                "Store credential provisioning requires exact LocalService SID S-1-5-19".to_owned(),
            ));
        }
        sha256_handle(&self.config_digest, "credential.config_digest")
    }
}

/// Retained identity of the create-new, protected, non-secret ownership marker.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialOwnershipMarkerIdentity {
    /// Digest of the canonical UTF-16 marker path.
    pub canonical_path_digest: PlatformHandle,
    /// NTFS volume serial number.
    pub volume_serial_number: u32,
    /// Stable file index on that volume.
    pub file_index: u64,
    /// Digest of the marker owner, protected DACL and descriptor control.
    pub security_descriptor_digest: PlatformHandle,
}

/// Authoritative Host observation captured before credential intent commit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialAbsentSnapshot {
    /// Exact durable Host owner epoch serving the control endpoint.
    pub host_owner_epoch: PlatformHandle,
    /// Exact live SCM Host PID/start/image identity digest.
    pub host_process_identity: PlatformHandle,
    /// Retained identity of the protected Host state root.
    pub host_state_root: CredentialOwnershipMarkerIdentity,
    /// Canonical path digest of the not-yet-created marker.
    pub marker_path_digest: PlatformHandle,
    /// Explicit marker absence observation.
    pub marker_absent: bool,
    /// Explicit Credential Manager target absence under the same Host token.
    pub target_absent: bool,
}

impl StoreCredentialAbsentSnapshot {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(
            &self.host_owner_epoch,
            "credential_snapshot.host_owner_epoch",
        )?;
        sha256_handle(
            &self.host_process_identity,
            "credential_snapshot.host_process_identity",
        )?;
        self.host_state_root.validate()?;
        sha256_handle(
            &self.marker_path_digest,
            "credential_snapshot.marker_path_digest",
        )?;
        if !self.marker_absent || !self.target_absent {
            return Err(InstallationError::InvalidField {
                field: "credential_snapshot.absence".to_owned(),
                reason: "marker and credential target must both be authoritatively absent"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

impl CredentialOwnershipMarkerIdentity {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        sha256_handle(
            &self.canonical_path_digest,
            "credential.marker.canonical_path_digest",
        )?;
        if self.file_index == 0 {
            return Err(InstallationError::InvalidField {
                field: "credential.marker.file_index".to_owned(),
                reason: "must be non-zero".to_owned(),
            });
        }
        sha256_handle(
            &self.security_descriptor_digest,
            "credential.marker.security_descriptor_digest",
        )
    }
}

/// Durable lifecycle of one `LocalService` credential plus its ownership marker.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreCredentialLifecycle {
    /// Provision intent exists; no terminal delete intent has been committed.
    Active,
    /// Delete intent was committed before contacting Host.
    DeleteIntentCommitted,
    /// Host acknowledged deletion; authoritative absence is not yet durable.
    DeleteExecuted,
    /// Host proved both target and exact marker absent.
    Deleted,
}

impl StoreCredentialLifecycle {
    pub(crate) const fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Active, Self::DeleteIntentCommitted)
                | (Self::DeleteIntentCommitted, Self::DeleteExecuted)
                | (Self::DeleteExecuted, Self::Deleted)
        )
    }
}

/// Secret-free receipt issued by the exact authenticated `LocalService` Host.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAccessReceipt {
    /// Installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact credential effect identity.
    pub effect_id: PlatformHandle,
    /// Store generation receiving the credential.
    pub generation: ResourceGeneration,
    /// Store configuration digest.
    pub config_digest: PlatformHandle,
    /// Credential Manager target reference.
    pub target: PlatformHandle,
    /// Exact provider.
    pub provider: StoreCredentialProvider,
    /// Exact `LocalService` scope.
    pub scope: StoreCredentialScope,
    /// Exact `LocalService` SID observed by Host.
    pub principal_sid: PlatformHandle,
    /// Durable Host owner epoch which served the one-shot request.
    pub host_owner_epoch: PlatformHandle,
    /// Exact live SCM Host PID/start/image identity digest.
    pub host_process_identity: PlatformHandle,
    /// Exact create-new marker identity.
    pub marker: CredentialOwnershipMarkerIdentity,
    /// Digest of the complete credential envelope, never credential bytes.
    pub credential_envelope_digest: PlatformHandle,
    /// Digest of the authenticated request.
    pub request_digest: PlatformHandle,
    /// Digest of the response fields excluding this digest.
    pub response_digest: PlatformHandle,
}

impl CredentialAccessReceipt {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.transaction_id, "credential_receipt.transaction_id")?;
        handle(&self.effect_id, "credential_receipt.effect_id")?;
        sha256_handle(&self.config_digest, "credential_receipt.config_digest")?;
        handle(&self.target, "credential_receipt.target")?;
        if self.principal_sid.as_str() != LOCAL_SERVICE_SID {
            return Err(InstallationError::ProfileViolation(
                "credential receipt principal is not LocalService".to_owned(),
            ));
        }
        handle(
            &self.host_owner_epoch,
            "credential_receipt.host_owner_epoch",
        )?;
        sha256_handle(
            &self.host_process_identity,
            "credential_receipt.host_process_identity",
        )?;
        self.marker.validate()?;
        sha256_handle(
            &self.credential_envelope_digest,
            "credential_receipt.credential_envelope_digest",
        )?;
        sha256_handle(&self.request_digest, "credential_receipt.request_digest")?;
        sha256_handle(&self.response_digest, "credential_receipt.response_digest")?;
        let expected = credential_matching_response_digest(
            &self.request_digest,
            &self.host_owner_epoch,
            &self.host_process_identity,
            &self.marker,
            &self.credential_envelope_digest,
        )?;
        if self.response_digest != expected {
            return Err(InstallationError::InvalidField {
                field: "credential_receipt.response_digest".to_owned(),
                reason: "receipt field binding mismatch".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn matches_intent(&self, intent: &HostCredentialControlIntent) -> bool {
        self.transaction_id == intent.transaction_id
            && self.effect_id == intent.effect_id
            && self.generation == intent.provision.generation
            && self.config_digest == intent.provision.config_digest
            && self.target == intent.provision.target
            && self.provider == intent.provision.provider
            && self.scope == intent.provision.scope
            && self.principal_sid == intent.provision.expected_principal_sid
    }
}

/// Durable credential-specific progress owned by one installation effect.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreCredentialProgress {
    /// Intent-before-delete lifecycle.
    pub lifecycle: StoreCredentialLifecycle,
    /// Present only after authenticated Host create/reconcile evidence.
    pub receipt: Option<CredentialAccessReceipt>,
}

/// One Host operation on the credential and its exact ownership marker.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HostCredentialControlOperation {
    /// Observe marker/target absence before intent commit.
    Inspect,
    /// Create marker first, then credential, with same-token readback.
    Provision,
    /// Re-read marker and credential after an unknown delivery or restart.
    Reconcile,
    /// Delete credential and marker after durable delete intent.
    Delete,
}

/// Secret-free part of one authenticated Host credential request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialControlIntent {
    /// Stable wire discriminator.
    pub wire: PlatformHandle,
    /// Requested operation.
    pub operation: HostCredentialControlOperation,
    /// Installation transaction identity.
    pub transaction_id: PlatformHandle,
    /// Exact effect identity.
    pub effect_id: PlatformHandle,
    /// Immutable credential plan.
    pub provision: StoreCredentialProvisionPlan,
    /// Durable installation plan digest.
    pub installation_plan_digest: PlatformHandle,
    /// Operation-independent binding retained by marker and envelope HMACs.
    pub effect_binding_digest: PlatformHandle,
    /// Digest of these fields, excluding itself.
    pub request_digest: PlatformHandle,
}

impl HostCredentialControlIntent {
    /// Creates and binds one exact secret-free Host request.
    pub fn new(
        operation: HostCredentialControlOperation,
        transaction_id: PlatformHandle,
        effect_id: PlatformHandle,
        provision: StoreCredentialProvisionPlan,
        installation_plan_digest: PlatformHandle,
    ) -> Result<Self, InstallationError> {
        let effect_binding_digest = digest_json(
            &(
                transaction_id.as_str(),
                effect_id.as_str(),
                &provision,
                installation_plan_digest.as_str(),
            ),
            "host_credential_control.effect_binding_digest",
        )?;
        let mut value = Self {
            wire: PlatformHandle::new(HOST_CREDENTIAL_CONTROL_WIRE).map_err(|error| {
                InstallationError::InvalidField {
                    field: "host_credential_control.wire".to_owned(),
                    reason: error.to_string(),
                }
            })?,
            operation,
            transaction_id,
            effect_id,
            provision,
            installation_plan_digest,
            effect_binding_digest,
            request_digest: PlatformHandle::new("pending").map_err(|error| {
                InstallationError::InvalidField {
                    field: "host_credential_control.request_digest".to_owned(),
                    reason: error.to_string(),
                }
            })?,
        };
        value.request_digest = PlatformHandle::new(value.computed_digest()?).map_err(|error| {
            InstallationError::InvalidField {
                field: "host_credential_control.request_digest".to_owned(),
                reason: error.to_string(),
            }
        })?;
        value.validate()?;
        Ok(value)
    }

    fn computed_digest(&self) -> Result<String, InstallationError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            wire: &'a PlatformHandle,
            operation: HostCredentialControlOperation,
            transaction_id: &'a PlatformHandle,
            effect_id: &'a PlatformHandle,
            provision: &'a StoreCredentialProvisionPlan,
            installation_plan_digest: &'a PlatformHandle,
            effect_binding_digest: &'a PlatformHandle,
        }
        serde_json::to_vec(&DigestInput {
            wire: &self.wire,
            operation: self.operation,
            transaction_id: &self.transaction_id,
            effect_id: &self.effect_id,
            provision: &self.provision,
            installation_plan_digest: &self.installation_plan_digest,
            effect_binding_digest: &self.effect_binding_digest,
        })
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| InstallationError::InvalidField {
            field: "host_credential_control".to_owned(),
            reason: error.to_string(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        if self.wire.as_str() != HOST_CREDENTIAL_CONTROL_WIRE {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.wire".to_owned(),
                reason: "unsupported wire".to_owned(),
            });
        }
        handle(
            &self.transaction_id,
            "host_credential_control.transaction_id",
        )?;
        handle(&self.effect_id, "host_credential_control.effect_id")?;
        self.provision.validate()?;
        sha256_handle(
            &self.installation_plan_digest,
            "host_credential_control.installation_plan_digest",
        )?;
        sha256_handle(
            &self.effect_binding_digest,
            "host_credential_control.effect_binding_digest",
        )?;
        let expected_binding = digest_json(
            &(
                self.transaction_id.as_str(),
                self.effect_id.as_str(),
                &self.provision,
                self.installation_plan_digest.as_str(),
            ),
            "host_credential_control.effect_binding_digest",
        )?;
        if self.effect_binding_digest != expected_binding {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.effect_binding_digest".to_owned(),
                reason: "effect binding mismatch".to_owned(),
            });
        }
        sha256_handle(
            &self.request_digest,
            "host_credential_control.request_digest",
        )?;
        if self.computed_digest()? != self.request_digest.as_str() {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.request_digest".to_owned(),
                reason: "request digest mismatch".to_owned(),
            });
        }
        Ok(())
    }
}

/// Runtime-only one-shot request. `ownership_key` must never be persisted or logged.
///
/// This type deliberately has no `Debug`, `Clone`, `JsonSchema` or durable owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostCredentialControlRequest {
    /// Secret-free durable intent.
    pub intent: HostCredentialControlIntent,
    /// 256-bit marker MAC key, present after intent CAS only.
    pub ownership_key: Vec<u8>,
    /// Exact prior receipt required for delete and optionally pinned on retry.
    pub expected_receipt: Option<CredentialAccessReceipt>,
}

impl HostCredentialControlRequest {
    /// Validates the request without exposing its key.
    pub fn validate(&self) -> Result<(), InstallationError> {
        self.intent.validate()?;
        if self.intent.operation == HostCredentialControlOperation::Inspect {
            if !self.ownership_key.is_empty() {
                return Err(InstallationError::InvalidField {
                    field: "host_credential_control.ownership_key".to_owned(),
                    reason: "inspect must not carry ownership key bytes".to_owned(),
                });
            }
        } else if self.ownership_key.len() != 32 {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.ownership_key".to_owned(),
                reason: "mutating/reconcile requests require exactly 256 bits".to_owned(),
            });
        }
        if self.intent.operation == HostCredentialControlOperation::Delete
            && self.expected_receipt.as_ref().is_none_or(|receipt| {
                receipt.validate().is_err() || !receipt.matches_intent(&self.intent)
            })
        {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.expected_receipt".to_owned(),
                reason: "delete requires the exact prior Host receipt".to_owned(),
            });
        }
        if matches!(
            self.intent.operation,
            HostCredentialControlOperation::Inspect | HostCredentialControlOperation::Provision
        ) && self.expected_receipt.is_some()
        {
            return Err(InstallationError::InvalidField {
                field: "host_credential_control.expected_receipt".to_owned(),
                reason: "inspect/provision cannot carry a prior receipt".to_owned(),
            });
        }
        Ok(())
    }
}

impl Drop for HostCredentialControlRequest {
    fn drop(&mut self) {
        self.ownership_key.fill(0);
    }
}

/// Typed response from the authenticated `LocalService` Host endpoint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HostCredentialControlResponse {
    /// Marker and target were both absent under the retained Host contour.
    Absent {
        /// Independently observed precondition.
        snapshot: StoreCredentialAbsentSnapshot,
        /// Digest of the exact request and response classification.
        response_digest: PlatformHandle,
    },
    /// Exact marker and credential envelope matched the committed request.
    Matching {
        /// Secret-free exact access receipt.
        receipt: CredentialAccessReceipt,
    },
    /// Credential and marker were both authoritatively absent after delete.
    Deleted {
        /// Digest binding request, Host epoch and both absence observations.
        absence_digest: PlatformHandle,
    },
    /// Host could not safely classify ownership or external state.
    Unknown {
        /// Stable non-secret recovery reference.
        pending_ref: PlatformHandle,
    },
}

impl HostCredentialControlResponse {
    /// Validates typed response fields before the coordinator consumes them.
    pub fn validate(&self) -> Result<(), InstallationError> {
        match self {
            Self::Absent {
                snapshot,
                response_digest,
            } => {
                snapshot.validate()?;
                sha256_handle(response_digest, "host_credential_response.response_digest")
            }
            Self::Matching { receipt } => receipt.validate(),
            Self::Deleted { absence_digest } => {
                sha256_handle(absence_digest, "host_credential_response.absence_digest")
            }
            Self::Unknown { pending_ref } => {
                handle(pending_ref, "host_credential_response.pending_ref")
            }
        }
    }
}

/// Binds an absent response to the exact request and independently observed
/// Host snapshot.
pub fn credential_absent_response_digest(
    request_digest: &PlatformHandle,
    snapshot: &StoreCredentialAbsentSnapshot,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(request_digest.as_str(), snapshot, "ABSENT"),
        "credential_absent_response",
    )
}

/// Binds every public matching receipt field that is not already part of the
/// immutable request.
pub fn credential_matching_response_digest(
    request_digest: &PlatformHandle,
    host_owner_epoch: &PlatformHandle,
    host_process_identity: &PlatformHandle,
    marker: &CredentialOwnershipMarkerIdentity,
    credential_envelope_digest: &PlatformHandle,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            request_digest.as_str(),
            host_owner_epoch.as_str(),
            host_process_identity.as_str(),
            marker,
            credential_envelope_digest.as_str(),
            "MATCHING",
        ),
        "credential_matching_response",
    )
}

/// Binds terminal Host absence to the delete request and exact prior marker.
pub fn credential_deleted_response_digest(
    request_digest: &PlatformHandle,
    host_owner_epoch: &PlatformHandle,
    host_process_identity: &PlatformHandle,
    marker: &CredentialOwnershipMarkerIdentity,
) -> Result<PlatformHandle, InstallationError> {
    digest_json(
        &(
            request_digest.as_str(),
            host_owner_epoch.as_str(),
            host_process_identity.as_str(),
            marker,
            "DELETED",
        ),
        "credential_deleted_response",
    )
}

fn digest_json<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<PlatformHandle, InstallationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| InstallationError::InvalidField {
        field: field.to_owned(),
        reason: error.to_string(),
    })?;
    PlatformHandle::new(sha256_hex(&bytes)).map_err(|error| InstallationError::InvalidField {
        field: field.to_owned(),
        reason: error.to_string(),
    })
}

/// Encodes one runtime-only credential request after its durable intent exists.
pub fn credential_control_request_frame(
    connection_id: impl Into<String>,
    request: &HostCredentialControlRequest,
) -> Result<Frame, TransportError> {
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    control_frame(
        connection_id.into(),
        MessageType::Start,
        serde_json::to_value(request).map_err(|_| TransportError::SessionFenced)?,
    )
}

/// Decodes one authenticated Host request without logging or cloning its key.
pub fn decode_credential_control_request_frame(
    frame: &Frame,
) -> Result<HostCredentialControlRequest, TransportError> {
    let payload = control_payload(frame, MessageType::Start)?;
    let request: HostCredentialControlRequest =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    request
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(request)
}

/// Encodes one secret-free typed Host response.
pub fn credential_control_response_frame(
    connection_id: impl Into<String>,
    response: &HostCredentialControlResponse,
) -> Result<Frame, TransportError> {
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    control_frame(
        connection_id.into(),
        MessageType::Ready,
        serde_json::to_value(response).map_err(|_| TransportError::SessionFenced)?,
    )
}

/// Decodes one authenticated secret-free Host response.
pub fn decode_credential_control_response_frame(
    frame: &Frame,
) -> Result<HostCredentialControlResponse, TransportError> {
    let payload = control_payload(frame, MessageType::Ready)?;
    let response: HostCredentialControlResponse =
        serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
    response
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(response)
}

fn control_frame(
    connection_id: String,
    message_type: MessageType,
    payload: serde_json::Value,
) -> Result<Frame, TransportError> {
    let frame = Frame {
        protocol_version: ProtocolVersion::CURRENT,
        encoding_profile: EncodingProfile::JsonV1,
        connection_id,
        request_id: None,
        kind: FrameKind::Control,
        message_type,
        request_identity: None,
        payload: ProtocolPayload::Json(payload),
        trace_context: std::collections::BTreeMap::new(),
    };
    frame.validate()?;
    Ok(frame)
}

fn control_payload(
    frame: &Frame,
    message_type: MessageType,
) -> Result<serde_json::Value, TransportError> {
    frame.validate()?;
    if frame.kind != FrameKind::Control
        || frame.message_type != message_type
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err(TransportError::SessionFenced);
    }
    let ProtocolPayload::Json(payload) = &frame.payload else {
        return Err(TransportError::SessionFenced);
    };
    Ok(payload.clone())
}

impl StoreCredentialProgress {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
        }
        if self.lifecycle == StoreCredentialLifecycle::Deleted && self.receipt.is_none() {
            return Err(InstallationError::InvalidField {
                field: "credential_progress.receipt".to_owned(),
                reason: "deleted lifecycle requires the exact prior ownership receipt".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_delete_lifecycle_is_strictly_intent_before_effect() {
        assert!(
            StoreCredentialLifecycle::Active
                .can_transition(StoreCredentialLifecycle::DeleteIntentCommitted)
        );
        assert!(
            StoreCredentialLifecycle::DeleteIntentCommitted
                .can_transition(StoreCredentialLifecycle::DeleteExecuted)
        );
        assert!(
            StoreCredentialLifecycle::DeleteExecuted
                .can_transition(StoreCredentialLifecycle::Deleted)
        );
        assert!(
            !StoreCredentialLifecycle::Active
                .can_transition(StoreCredentialLifecycle::DeleteExecuted)
        );
        assert!(
            !StoreCredentialLifecycle::DeleteIntentCommitted
                .can_transition(StoreCredentialLifecycle::Deleted)
        );
        assert!(
            !StoreCredentialLifecycle::Deleted.can_transition(StoreCredentialLifecycle::Active)
        );
    }
}
