//! Host↔Kernel protocol records.

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, sha256_hex};
use eliot_ipc::TransportError;
use eliot_kernel_core::AuthoritySnapshotBindingWire;
use eliot_platform::{KernelActivationNonce, PlatformHandle, PortError, SecretReference};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessEvidence, ProcessExecutionAdmissionRequest,
    ProcessExecutionError, ProcessExecutionView, ProcessStartReceipt,
};
use eliot_protocol::{
    EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolVersion,
};
use eliot_runtime_contracts::{HealthVector, ProvisionedSupervisionAuthority, ServiceProcessState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

use crate::{KernelServiceError, KernelServiceState, validate_text};

fn handle(value: &PlatformHandle, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value.as_str(), field)
}

/// Stable identity for the Host↔Kernel lifecycle control wire.
pub const KERNEL_CONTROL_WIRE_ID: &str = "eliot.kernel.host-control";
/// Current version of the Host↔Kernel lifecycle control wire.
pub const KERNEL_CONTROL_WIRE_VERSION: u16 = 2;
/// Canonical authenticated Kernel front-door pipe.
pub const KERNEL_CONTROL_PIPE: &str = r"\\.\pipe\eliot\kernel\frontdoor";
/// Stable identity for the Kernel-owned `eliotd` launch descriptor.
pub const ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID: &str = "eliot.kernel.eliotd-launch";
/// Version of the exact `eliotd` child launch contract.
pub const ELIOTD_LAUNCH_DESCRIPTOR_WIRE_VERSION: u16 = 1;
/// Adapter-only hashed selector for a Phase-A pending runtime authority.
/// Runtime artifact/config/descriptor/bootstrap fields must never admit it.
const PHASE_B_PENDING_SCM_DIGEST: &str =
    "287ddc2779dd75cc92d2dadd6f06b4dba2eefa5d63538db7be11523687f7ba8c";
/// Legacy all-zero runtime digest, retained only as a rejection sentinel.
const LEGACY_PHASE_B_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const PROBE_BINDING_PREFIXES: [&str; 5] = [
    "kernel-probe-request:",
    "kernel-probe-generation:",
    "kernel-probe-authority-epoch:",
    "kernel-probe-config:",
    "kernel-probe-artifact:",
];

/// Immutable, secret-free launch material for the Kernel-owned `eliotd`
/// child.  The descriptor is loaded from an independently digest-bound file;
/// it is not inferred from the Kernel executable, current directory, or
/// environment.  Host/installer must add this descriptor to the approved
/// generation before the integrated service can start.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotdLaunchDescriptor {
    /// Descriptor wire identity.
    pub wire_id: String,
    /// Descriptor wire version.
    pub wire_version: u16,
    /// Absolute approved `eliotd.exe` path.
    pub executable: PlatformHandle,
    /// Lowercase SHA-256 digest of the approved executable bytes.
    pub executable_sha256: String,
    /// Exact child argv, excluding argv[0].
    pub arguments: Vec<PlatformHandle>,
    /// Absolute approved child working directory.
    pub working_directory: PlatformHandle,
    /// Exact protected daemon configuration path consumed by `eliotd`.
    pub config_descriptor: PlatformHandle,
    /// Lowercase SHA-256 digest of the exact daemon configuration bytes.
    pub config_descriptor_sha256: String,
    /// Public launch-correlation nonce carried through the explicit argv
    /// contract. It is not a secret or an authority credential; authenticated
    /// process/Job/pipe evidence remains the authority proof.
    pub launch_nonce: PlatformHandle,
    /// Kernel authority epoch bound to this child generation.
    pub authority_epoch: AuthorityEpoch,
    /// Kernel resource generation bound to this child generation.
    pub generation: ResourceGeneration,
    /// Lowercase SHA-256 digest over all descriptor fields except this field.
    pub descriptor_sha256: String,
}

impl EliotdLaunchDescriptor {
    /// Current descriptor contract version.
    pub const CONTRACT_VERSION: u16 = ELIOTD_LAUNCH_DESCRIPTOR_WIRE_VERSION;

    /// Returns canonical bytes covered by `descriptor_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, KernelServiceError> {
        let mut unsigned = self.clone();
        unsigned.descriptor_sha256.clear();
        serde_json::to_vec(&unsigned).map_err(|_| KernelServiceError::InvalidField {
            field: "eliotd.descriptor_sha256",
            reason: "cannot canonicalize descriptor",
        })
    }

    /// Computes the canonical descriptor digest.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the canonical descriptor digest.
    pub fn with_computed_digest(mut self) -> Result<Self, KernelServiceError> {
        self.descriptor_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the exact launch contour without opening any path.
    ///
    /// Physical no-follow path identity and executable bytes are proven by
    /// Kernel immediately before process-authority issuance.  This method
    /// only validates the closed wire shape and required explicit argv
    /// bindings.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.wire_id != ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID
            || self.wire_version != Self::CONTRACT_VERSION
        {
            return Err(KernelServiceError::InvalidField {
                field: "eliotd.wire",
                reason: "unsupported launch descriptor wire",
            });
        }
        for (value, field) in [
            (&self.executable, "eliotd.executable"),
            (&self.working_directory, "eliotd.working_directory"),
            (&self.config_descriptor, "eliotd.config_descriptor"),
        ] {
            handle(value, field)?;
            if !is_absolute_windows_path(value.as_str()) {
                return Err(KernelServiceError::InvalidField {
                    field,
                    reason: "must be an absolute Windows path",
                });
            }
        }
        validate_launch_nonce(&self.launch_nonce)?;
        validate_runtime_digest(&self.executable_sha256, "eliotd.executable_sha256")?;
        validate_runtime_digest(
            &self.config_descriptor_sha256,
            "eliotd.config_descriptor_sha256",
        )?;
        validate_runtime_digest(&self.descriptor_sha256, "eliotd.descriptor_sha256")?;
        let expected_arguments = [
            "--config-descriptor",
            self.config_descriptor.as_str(),
            "--config-descriptor-sha256",
            self.config_descriptor_sha256.as_str(),
            "--launch-nonce",
            self.launch_nonce.as_str(),
            "--executable-sha256",
            self.executable_sha256.as_str(),
        ];
        if self.arguments.len() != expected_arguments.len()
            || self
                .arguments
                .iter()
                .map(PlatformHandle::as_str)
                .ne(expected_arguments)
        {
            return Err(KernelServiceError::InvalidField {
                field: "eliotd.arguments",
                reason: "must be the exact canonical ordered 8-value child argv",
            });
        }
        for argument in &self.arguments {
            handle(argument, "eliotd.arguments")?;
            if argument.as_str().chars().any(char::is_control) {
                return Err(KernelServiceError::InvalidField {
                    field: "eliotd.arguments",
                    reason: "must not contain control characters",
                });
            }
        }
        if self.generation.value() == 0 || self.authority_epoch.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "eliotd.generation",
                reason: "generation and authority epoch must be non-zero",
            });
        }
        if self.compute_digest()? != self.descriptor_sha256 {
            return Err(KernelServiceError::InvalidField {
                field: "eliotd.descriptor_sha256",
                reason: "descriptor digest mismatch",
            });
        }
        Ok(())
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn validate_runtime_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if value == PHASE_B_PENDING_SCM_DIGEST {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "the SCM pending selector is adapter-only and cannot be a runtime digest",
        });
    }
    if value == LEGACY_PHASE_B_ZERO_DIGEST {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "legacy zero digest cannot be a runtime artifact or publication proof",
        });
    }
    validate_digest(value, field)
}

fn validate_launch_nonce(value: &PlatformHandle) -> Result<(), KernelServiceError> {
    handle(value, "eliotd.launch_nonce")?;
    let nonce = value.as_str();
    let suffix = nonce
        .strip_prefix("eliotd:")
        .ok_or(KernelServiceError::InvalidField {
            field: "eliotd.launch_nonce",
            reason: "must use the opaque eliotd launch-correlation format",
        })?;
    if suffix.len() < 32
        || suffix.len() > 120
        || suffix
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':')))
    {
        return Err(KernelServiceError::InvalidField {
            field: "eliotd.launch_nonce",
            reason: "must be bounded opaque text with at least 32 safe bytes",
        });
    }
    Ok(())
}

fn is_absolute_windows_path(value: &str) -> bool {
    value.len() >= 3 && value.as_bytes()[1] == b':' && matches!(value.as_bytes()[2], b'\\' | b'/')
        || Path::new(value).is_absolute()
}

/// Handle-bound process identity carried as an inert Host claim.
///
/// Kernel never treats this projection as proof.  It compares it with the
/// process identity observed by the authenticated named-pipe adapter before
/// admitting any lifecycle command.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProcessBinding {
    /// Process identifier observed by Host before launch/connect.
    pub process_id: u32,
    /// Handle-bound process creation time in Windows 100-nanosecond units.
    pub start_time_100ns: u64,
    /// Canonical process image path observed by Host.
    pub image_path: String,
}

/// Host-observed identity of the Store process and its owner Job.
///
/// This is an inert handoff projection.  Kernel must re-observe the process
/// through the Windows adapter and prove current membership in the named Job
/// before it uses the binding for named-pipe authentication.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreProcessBinding {
    /// Handle-bound Store process identity observed by Host after launch.
    pub process: HostProcessBinding,
    /// Exact owner-scoped Windows Job identity selected by Host.
    pub job: PlatformHandle,
}

impl StoreProcessBinding {
    /// Validates the bounded, inert wire projection.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        self.process.validate()?;
        handle(&self.job, "store_process_binding.job")?;
        if self.job.as_str().encode_utf16().count() > 240
            || self.job.as_str().chars().any(char::is_control)
        {
            return Err(KernelServiceError::InvalidField {
                field: "store_process_binding.job",
                reason: "must be a bounded Windows Job identity",
            });
        }
        Ok(())
    }
}

/// One typed post-launch Store handoff on the existing Host↔Kernel control
/// wire.  The descriptor remains immutable; this value binds its exact
/// approved contents to Host's fresh Store process/Job observation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreBootstrapHandoff {
    /// The immutable descriptor bytes already admitted by Host and Kernel.
    pub requirement: HostStoreBootstrapRequirement,
    /// Fresh process/Job evidence captured after the Store was launched.
    pub process_binding: StoreProcessBinding,
}

impl StoreBootstrapHandoff {
    /// Validates both descriptor and fresh process/Job projection.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        self.requirement.validate()?;
        self.process_binding.validate()
    }
}

/// Typed Store-only same-lineage rebind handoff. It is distinct from
/// `StoreBootstrapHandoff` and binds the immutable requirement, fresh
/// Store PID/start/image/Job, current Kernel candidate/generation/authority
/// epoch, operation/request digest and Store fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRebindHandoff {
    /// Host-owned stable rebind operation identity.
    pub operation_id: PlatformHandle,
    /// Digest of the original rebind request payload.
    pub request_digest: String,
    /// Immutable original bootstrap requirement.
    pub requirement: HostStoreBootstrapRequirement,
    /// Fresh Store process/Job evidence after relaunch.
    pub process_binding: StoreProcessBinding,
    /// Digest of the current active Kernel candidate binding.
    pub candidate_binding_digest: String,
    /// Current Kernel generation.
    pub generation: ResourceGeneration,
    /// Current Kernel authority epoch.
    pub authority_epoch: AuthorityEpoch,
    /// Store proof-fence digest binding fresh peer evidence.
    pub store_fence: String,
}

impl StoreRebindHandoff {
    /// Validates the bounded rebind handoff without OS observation.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.operation_id, "store_rebind.operation_id")?;
        if self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind.request_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        self.requirement.validate()?;
        self.process_binding.validate()?;
        if self.candidate_binding_digest.len() != 64
            || !self
                .candidate_binding_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind.candidate_binding_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.store_fence.len() != 64
            || !self
                .store_fence
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind.store_fence",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if self.generation.value() == 0
            || self.generation != self.requirement.store_generation
            || self.requirement.state_fence.resource_generation != self.generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.generation",
            });
        }
        if self.authority_epoch.value() == 0
            || self.authority_epoch != self.requirement.state_fence.authority_epoch
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.authority_epoch",
            });
        }
        Ok(())
    }

    /// Returns canonical digest over requirement plus fresh binding and fence.
    pub fn compute_requirement_digest(&self) -> Result<String, KernelServiceError> {
        serde_json::to_vec(&self.requirement)
            .map(|b| sha256_hex(&b))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "store_rebind.requirement",
                reason: "cannot canonicalize requirement",
            })
    }

    /// Returns the canonical non-circular request digest.
    pub fn canonical_request_digest(&self) -> Result<String, KernelServiceError> {
        #[derive(serde::Serialize)]
        struct Canonical<'a> {
            operation_id: &'a PlatformHandle,
            requirement: &'a HostStoreBootstrapRequirement,
            process_binding: &'a StoreProcessBinding,
            candidate_binding_digest: &'a str,
            generation: ResourceGeneration,
            authority_epoch: AuthorityEpoch,
            store_fence: &'a str,
        }
        let canonical = Canonical {
            operation_id: &self.operation_id,
            requirement: &self.requirement,
            process_binding: &self.process_binding,
            candidate_binding_digest: &self.candidate_binding_digest,
            generation: self.generation,
            authority_epoch: self.authority_epoch,
            store_fence: &self.store_fence,
        };
        serde_json::to_vec(&canonical)
            .map(|b| sha256_hex(&b))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "store_rebind.request_digest",
                reason: "cannot canonicalize rebind",
            })
    }

    /// Validates that the request digest equals the canonical digest.
    pub fn validate_canonical_digest(&self) -> Result<(), KernelServiceError> {
        let expected = self.canonical_request_digest()?;
        if self.request_digest != expected {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_rebind.request_digest",
            });
        }
        Ok(())
    }
}

/// Digest-only reconciliation query for a rebind whose delivery was unknown.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRebindQuery {
    /// Exact rebind operation identity.
    pub operation_id: PlatformHandle,
    /// Digest of the original rebind request.
    pub request_digest: String,
}

impl StoreRebindQuery {
    /// Validates the bounded reconciliation identity.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.operation_id, "store_rebind_query.operation_id")?;
        if self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind_query.request_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        Ok(())
    }
}

/// Bound receipt for a successful Store rebind.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRebindReceipt {
    /// Echoed rebind operation identity.
    pub operation_id: PlatformHandle,
    /// Echoed rebind request digest.
    pub request_digest: String,
    /// Digest of the immutable requirement.
    pub requirement_digest: String,
    /// Fresh Store process/Job binding.
    pub process_binding: StoreProcessBinding,
    /// Candidate binding digest at rebind time.
    pub candidate_binding_digest: String,
    /// Generation at rebind time.
    pub generation: ResourceGeneration,
    /// Authority epoch at rebind time.
    pub authority_epoch: AuthorityEpoch,
    /// Store proof-fence digest binding fresh peer evidence.
    pub store_fence: String,
}

impl StoreRebindReceipt {
    /// Validates the receipt shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.operation_id, "store_rebind_receipt.operation_id")?;
        for (value, field) in [
            (&self.request_digest, "store_rebind_receipt.request_digest"),
            (
                &self.requirement_digest,
                "store_rebind_receipt.requirement_digest",
            ),
            (
                &self.candidate_binding_digest,
                "store_rebind_receipt.candidate_binding_digest",
            ),
            (&self.store_fence, "store_rebind_receipt.store_fence"),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(KernelServiceError::InvalidField {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        self.process_binding.validate()?;
        if self.generation.value() == 0 || self.authority_epoch.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "store_rebind_receipt.generation_or_epoch",
                reason: "must be non-zero",
            });
        }
        Ok(())
    }
}

impl HostProcessBinding {
    /// Validates the bounded, inert wire projection.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        if self.process_id == 0
            || self.start_time_100ns == 0
            || self.image_path.trim().is_empty()
            || self.image_path.chars().any(char::is_control)
            || self.image_path.len() > 32_767
        {
            return Err(KernelServiceError::InvalidField {
                field: "host_process_binding",
                reason: "must contain a bounded non-zero process identity",
            });
        }
        Ok(())
    }
}

/// Inert projection of the Host-created Kernel Job binding.
///
/// The Kernel reconstructs the platform binding and calls
/// `RecoverableJobObject::open`; these fields alone never grant Job authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobBinding {
    /// Exact object-manager Job identity.
    pub job: HostJobIdentity,
    /// Root process and executable identity retained by Host.
    pub root: HostJobRoot,
}

/// Inert Job object name projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobIdentity {
    /// Exact Windows object-manager name.
    pub name: String,
}

/// Inert root process/file projection for one Host Job binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostJobRoot {
    /// Root process identity observed by Host.
    pub process: HostProcessBinding,
    /// Root executable file-object identity observed by Host.
    pub executable: HostFileIdentity,
}

/// Inert file-object identity projection.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFileIdentity {
    /// Volume serial number.
    pub volume_serial_number: u32,
    /// File index on the volume.
    pub file_index: u64,
}

impl HostJobBinding {
    /// Validates only bounded shape; the Kernel must still reopen the Job.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle_text(&self.job.name, "host_job_binding.job.name")?;
        if self.job.name.len() > 480 {
            return Err(KernelServiceError::InvalidField {
                field: "host_job_binding.job.name",
                reason: "exceeds the bounded Job name length",
            });
        }
        self.root.process.validate()?;
        if self.root.executable.volume_serial_number == 0 || self.root.executable.file_index == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "host_job_binding.root.executable",
                reason: "must contain a non-zero file identity",
            });
        }
        Ok(())
    }
}

fn handle_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value, field)
}

/// One authenticated Host lifecycle command.  Every request repeats the exact
/// nonce-free candidate binding so reconnects cannot silently inherit stale
/// Host, process, Job, generation, or pipe identity.  Activation authority is
/// carried only by [`KernelControlCommand::Activate`].
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
    /// Complete nonce-free Host/candidate lineage binding.
    pub candidate: HostKernelCandidateBinding,
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
            candidate: &'a HostKernelCandidateBinding,
            command: &'a KernelControlCommand,
        }
        serde_json::to_vec(&Unsigned {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            message_id: &self.message_id,
            sequence: self.sequence,
            peer_process_id: self.peer_process_id,
            generation: self.generation,
            candidate: &self.candidate,
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
        self.candidate.validate()?;
        if let KernelControlCommand::BootstrapStore(handoff) = &self.command {
            handoff.validate()?;
        }
        if let KernelControlCommand::RebindStore(handoff) = &self.command {
            handoff.validate()?;
            handoff.validate_canonical_digest()?;
            if handoff.candidate_binding_digest != self.candidate.compute_digest()? {
                return Err(KernelServiceError::HandshakeMismatch {
                    field: "store_rebind.candidate_binding",
                });
            }
            if handoff.generation != self.generation
                || handoff.authority_epoch != self.candidate.kernel_epoch
            {
                return Err(KernelServiceError::HandshakeMismatch {
                    field: "store_rebind.generation_or_epoch",
                });
            }
            if self.payload_digest != handoff.request_digest {
                return Err(KernelServiceError::HandshakeMismatch {
                    field: "store_rebind.request_digest",
                });
            }
        }
        if let KernelControlCommand::ReconcileRebindStore(query) = &self.command {
            query.validate()?;
        }
        if let KernelControlCommand::Activate(permit) = &self.command {
            permit.validate(&self.candidate, self.generation)?;
        }
        if self.payload_digest.len() != 64
            || !self
                .payload_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "control.payload_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if !matches!(&self.command, KernelControlCommand::RebindStore(_))
            && self.compute_digest()? != self.payload_digest
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
    /// Receipt returned only after Kernel-owned readiness observation.
    pub receipt: Option<KernelReadyReceipt>,
    /// Exact receipt returned after one activation permit is consumed, or
    /// after a nonce-free operation-identity reconciliation finds it.
    pub activation_receipt: Option<KernelActivationReceipt>,
    /// Bound receipt returned after a successful Store rebind or its
    /// digest-only reconciliation.
    pub store_rebind_receipt: Option<StoreRebindReceipt>,
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
            activation_receipt: &'a Option<KernelActivationReceipt>,
            store_rebind_receipt: &'a Option<StoreRebindReceipt>,
            error: &'a Option<String>,
        }
        serde_json::to_vec(&Unsigned {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            message_id: &self.message_id,
            request_digest: &self.request_digest,
            state: self.state,
            receipt: &self.receipt,
            activation_receipt: &self.activation_receipt,
            store_rebind_receipt: &self.store_rebind_receipt,
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
    /// Installer-provisioned public supervision authority. The reference is
    /// Kernel-root-relative and contains no signing bytes.
    pub supervision_authority: ProvisionedSupervisionAuthority,
    pub descriptor_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub contour_refs: Vec<PlatformHandle>,
}

impl ProcessAuthorityHandoffDescriptor {
    /// Current descriptor schema revision.
    pub const CONTRACT_VERSION: u16 = 2;
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

    /// Validates syntax, digest material, and exact fence bindings without
    /// applying the one-shot admission expiry.
    ///
    /// Recovery must be able to inspect an immutable descriptor after its
    /// admission interval has elapsed.  The durable ORS handoff and exact
    /// replay snapshot decide whether that is a permitted restart; callers
    /// admitting a fresh Reserved handoff must additionally require
    /// `expires_at_ms > now_ms`.
    pub fn validate_structure(&self) -> Result<(), KernelServiceError> {
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
        if self.issued_at_ms < 0 || self.expires_at_ms <= self.issued_at_ms {
            return Err(KernelServiceError::InvalidField {
                field: "expires_at_ms",
                reason: "descriptor has invalid bounds",
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
        self.supervision_authority
            .validate()
            .map_err(|_| KernelServiceError::InvalidField {
                field: "supervision_authority",
                reason: "invalid installer-provisioned supervision authority",
            })?;
        if self.supervision_authority.authority_generation != self.generation {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "supervision_authority.authority_generation",
            });
        }
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

    /// Validates syntax, digest material, time bounds, and exact fence
    /// bindings for a fresh one-shot admission.
    pub fn validate(&self, now_ms: i64) -> Result<(), KernelServiceError> {
        self.validate_structure()?;
        if self.expires_at_ms <= now_ms {
            return Err(KernelServiceError::InvalidField {
                field: "expires_at_ms",
                reason: "descriptor is expired",
            });
        }
        Ok(())
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

    fn supervision_authority() -> ProvisionedSupervisionAuthority {
        let signer = eliot_runtime_contracts::Ed25519SupervisionLeaseSigner::from_secret_key(
            "eliot-kernel",
            "supervision-key-1",
            [0x39; 32],
        )
        .expect("test signer");
        let anchor = eliot_runtime_contracts::SupervisionTrustAnchor::new(
            "installation-1",
            "eliot-kernel",
            "supervision-key-1",
            signer.public_key().to_vec(),
        )
        .expect("test trust anchor");
        let reference = eliot_runtime_contracts::SupervisionSealedKeyReference::new(
            "supervision-key-1.sealed",
            "S-1-5-80-1-2-3-4-5",
            eliot_runtime_contracts::SupervisionSealedKeyFileIdentity {
                canonical_path_digest: "1".repeat(64),
                volume_serial_number: 7,
                file_index: 11,
                security_descriptor_digest: "2".repeat(64),
            },
            "3".repeat(64),
        )
        .expect("test key reference");
        ProvisionedSupervisionAuthority::new(
            "supervision-lease-1",
            "candidate-1",
            ResourceGeneration::genesis(),
            reference,
            anchor,
        )
        .expect("test provisioned authority")
    }

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
            supervision_authority: supervision_authority(),
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
    fn descriptor_structure_survives_expiry_for_recovery_inspection() {
        let mut descriptor = descriptor().with_computed_digest().expect("digest");
        descriptor.expires_at_ms = 200;
        descriptor = descriptor.with_computed_digest().expect("updated digest");
        descriptor
            .validate_structure()
            .expect("expired descriptor remains structurally inspectable");
        assert!(descriptor.validate(500).is_err());
    }

    #[test]
    fn contract_v2_digest_binds_the_mandatory_supervision_authority() {
        let descriptor = descriptor();
        assert_eq!(
            descriptor.compute_digest().expect("legacy digest"),
            "265d5db706b25550cf62599bdd749a8259f1cdffff8765bf09daf364f98670bf"
        );
    }

    #[test]
    fn descriptor_rejects_unknown_duplicate_blank_and_malformed_inputs() {
        let descriptor = descriptor().with_computed_digest().expect("digest");
        let mut legacy = serde_json::to_value(&descriptor).expect("legacy value");
        legacy["contract_version"] = serde_json::json!(1);
        legacy
            .as_object_mut()
            .expect("descriptor object")
            .remove("supervision_authority");
        assert!(
            serde_json::from_value::<ProcessAuthorityHandoffDescriptor>(legacy).is_err(),
            "v1 bytes without the provisioned authority must require explicit migration"
        );
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

/// Computes the semantic Store configuration identity from the exact JSON
/// bytes consumed by `eliot-store-surreal`.
///
/// The physical file SHA-256 is intentionally not used here. The Store's
/// launch-config contract hashes the ordered operational projection and
/// excludes its own `approved_config_hash` field, so harmless JSON whitespace
/// or object-key order changes do not change this identity. This helper keeps
/// that projection in the Host↔Kernel protocol crate without making Host
/// depend on the Store composition crate.
#[allow(
    clippy::too_many_lines,
    reason = "the semantic Store digest keeps the wire projection and its digest domain in one auditable boundary"
)]
pub fn semantic_store_config_hash_from_json(
    bytes: &[u8],
) -> Result<PlatformHandle, KernelServiceError> {
    fn invalid(reason: &'static str) -> KernelServiceError {
        KernelServiceError::InvalidField {
            field: "store_config.runtime_launch",
            reason,
        }
    }

    fn required_field(
        value: &serde_json::Value,
        field: &'static str,
    ) -> Result<serde_json::Value, KernelServiceError> {
        value
            .get(field)
            .cloned()
            .ok_or_else(|| invalid("missing field"))
    }

    fn exact_object(value: &serde_json::Value, fields: &[&str]) -> Result<(), KernelServiceError> {
        let Some(object) = value.as_object() else {
            return Err(invalid("must be an object"));
        };
        if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        {
            return Err(invalid("contains an unknown or missing field"));
        }
        Ok(())
    }

    #[derive(Serialize)]
    struct OrderedInstallationEpoch {
        installation: serde_json::Value,
        lineage_id: serde_json::Value,
        sequence: serde_json::Value,
    }
    #[derive(Serialize)]
    struct OrderedStateFence {
        authority_epoch: serde_json::Value,
        resource_generation: serde_json::Value,
        task_revision: serde_json::Value,
        policy_revision: serde_json::Value,
        integration_revision: serde_json::Value,
    }
    #[derive(Serialize)]
    struct OrderedRuntimeStateRoots {
        profile: serde_json::Value,
        profile_anchor_root: serde_json::Value,
        installation_root: serde_json::Value,
        host_state_root: serde_json::Value,
        kernel_ors_root: serde_json::Value,
        kernel_work_root: serde_json::Value,
        store_data_root: serde_json::Value,
        store_work_root: serde_json::Value,
        store_temp_root: serde_json::Value,
        watchdog_state_root: serde_json::Value,
        roots_digest: serde_json::Value,
    }
    #[derive(Serialize)]
    struct OrderedRuntimeLaunch {
        profile: serde_json::Value,
        portable_root: serde_json::Value,
        installation_epoch: OrderedInstallationEpoch,
        generation: serde_json::Value,
        authority_generation: serde_json::Value,
        authority_state_fence: OrderedStateFence,
        authority_descriptor_path: serde_json::Value,
        authority_descriptor_digest: serde_json::Value,
        runtime_state_roots: OrderedRuntimeStateRoots,
        kernel_work_root: serde_json::Value,
        kernel_artifact_digest: serde_json::Value,
        eliotd_executable_path: serde_json::Value,
        eliotd_artifact_digest: serde_json::Value,
        eliotd_config_path: serde_json::Value,
        eliotd_config_digest: serde_json::Value,
        eliotd_descriptor_path: serde_json::Value,
        eliotd_descriptor_digest: serde_json::Value,
        eliotd_launch_nonce: serde_json::Value,
        store_config_path: serde_json::Value,
        store_credential_target: serde_json::Value,
        store_bridge_executable_path: serde_json::Value,
        store_bridge_artifact_digest: serde_json::Value,
        store_bootstrap_descriptor_path: serde_json::Value,
        store_bootstrap_descriptor_digest: serde_json::Value,
        canonical_store_executable_path: serde_json::Value,
        canonical_store_artifact_digest: serde_json::Value,
        kernel_arguments: serde_json::Value,
        store_bridge_arguments: serde_json::Value,
        canonical_store_arguments: serde_json::Value,
        host_executable_path: serde_json::Value,
        host_artifact_digest: serde_json::Value,
        watchdog_executable_path: serde_json::Value,
        watchdog_artifact_digest: serde_json::Value,
        descriptor_digest: serde_json::Value,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the ordered RuntimeLaunch projection mirrors the Store consumer field-by-field"
    )]
    fn ordered_runtime_launch(
        value: &serde_json::Value,
    ) -> Result<OrderedRuntimeLaunch, KernelServiceError> {
        exact_object(
            value,
            &[
                "profile",
                "portable_root",
                "installation_epoch",
                "generation",
                "authority_generation",
                "authority_state_fence",
                "authority_descriptor_path",
                "authority_descriptor_digest",
                "runtime_state_roots",
                "kernel_work_root",
                "kernel_artifact_digest",
                "eliotd_executable_path",
                "eliotd_artifact_digest",
                "eliotd_config_path",
                "eliotd_config_digest",
                "eliotd_descriptor_path",
                "eliotd_descriptor_digest",
                "eliotd_launch_nonce",
                "store_config_path",
                "store_credential_target",
                "store_bridge_executable_path",
                "store_bridge_artifact_digest",
                "store_bootstrap_descriptor_path",
                "store_bootstrap_descriptor_digest",
                "canonical_store_executable_path",
                "canonical_store_artifact_digest",
                "kernel_arguments",
                "store_bridge_arguments",
                "canonical_store_arguments",
                "host_executable_path",
                "host_artifact_digest",
                "watchdog_executable_path",
                "watchdog_artifact_digest",
                "descriptor_digest",
            ],
        )?;
        let epoch = required_field(value, "installation_epoch")?;
        exact_object(&epoch, &["installation", "lineage_id", "sequence"])?;
        let fence = required_field(value, "authority_state_fence")?;
        exact_object(
            &fence,
            &[
                "authority_epoch",
                "resource_generation",
                "task_revision",
                "policy_revision",
                "integration_revision",
            ],
        )?;
        let roots = required_field(value, "runtime_state_roots")?;
        exact_object(
            &roots,
            &[
                "profile",
                "profile_anchor_root",
                "installation_root",
                "host_state_root",
                "kernel_ors_root",
                "kernel_work_root",
                "store_data_root",
                "store_work_root",
                "store_temp_root",
                "watchdog_state_root",
                "roots_digest",
            ],
        )?;
        let field = |object: &serde_json::Value, name: &'static str| required_field(object, name);
        Ok(OrderedRuntimeLaunch {
            profile: field(value, "profile")?,
            portable_root: field(value, "portable_root")?,
            installation_epoch: OrderedInstallationEpoch {
                installation: field(&epoch, "installation")?,
                lineage_id: field(&epoch, "lineage_id")?,
                sequence: field(&epoch, "sequence")?,
            },
            generation: field(value, "generation")?,
            authority_generation: field(value, "authority_generation")?,
            authority_state_fence: OrderedStateFence {
                authority_epoch: field(&fence, "authority_epoch")?,
                resource_generation: field(&fence, "resource_generation")?,
                task_revision: field(&fence, "task_revision")?,
                policy_revision: field(&fence, "policy_revision")?,
                integration_revision: field(&fence, "integration_revision")?,
            },
            authority_descriptor_path: field(value, "authority_descriptor_path")?,
            authority_descriptor_digest: field(value, "authority_descriptor_digest")?,
            runtime_state_roots: OrderedRuntimeStateRoots {
                profile: field(&roots, "profile")?,
                profile_anchor_root: field(&roots, "profile_anchor_root")?,
                installation_root: field(&roots, "installation_root")?,
                host_state_root: field(&roots, "host_state_root")?,
                kernel_ors_root: field(&roots, "kernel_ors_root")?,
                kernel_work_root: field(&roots, "kernel_work_root")?,
                store_data_root: field(&roots, "store_data_root")?,
                store_work_root: field(&roots, "store_work_root")?,
                store_temp_root: field(&roots, "store_temp_root")?,
                watchdog_state_root: field(&roots, "watchdog_state_root")?,
                roots_digest: field(&roots, "roots_digest")?,
            },
            kernel_work_root: field(value, "kernel_work_root")?,
            kernel_artifact_digest: field(value, "kernel_artifact_digest")?,
            eliotd_executable_path: field(value, "eliotd_executable_path")?,
            eliotd_artifact_digest: field(value, "eliotd_artifact_digest")?,
            eliotd_config_path: field(value, "eliotd_config_path")?,
            eliotd_config_digest: field(value, "eliotd_config_digest")?,
            eliotd_descriptor_path: field(value, "eliotd_descriptor_path")?,
            eliotd_descriptor_digest: field(value, "eliotd_descriptor_digest")?,
            eliotd_launch_nonce: field(value, "eliotd_launch_nonce")?,
            store_config_path: field(value, "store_config_path")?,
            store_credential_target: field(value, "store_credential_target")?,
            store_bridge_executable_path: field(value, "store_bridge_executable_path")?,
            store_bridge_artifact_digest: field(value, "store_bridge_artifact_digest")?,
            store_bootstrap_descriptor_path: field(value, "store_bootstrap_descriptor_path")?,
            store_bootstrap_descriptor_digest: field(value, "store_bootstrap_descriptor_digest")?,
            canonical_store_executable_path: field(value, "canonical_store_executable_path")?,
            canonical_store_artifact_digest: field(value, "canonical_store_artifact_digest")?,
            kernel_arguments: field(value, "kernel_arguments")?,
            store_bridge_arguments: field(value, "store_bridge_arguments")?,
            canonical_store_arguments: field(value, "canonical_store_arguments")?,
            host_executable_path: field(value, "host_executable_path")?,
            host_artifact_digest: field(value, "host_artifact_digest")?,
            watchdog_executable_path: field(value, "watchdog_executable_path")?,
            watchdog_artifact_digest: field(value, "watchdog_artifact_digest")?,
            descriptor_digest: field(value, "descriptor_digest")?,
        })
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StoreConfigWire {
        store_pipe: String,
        launch_nonce: String,
        expected_client_sid: String,
        expected_client_session_id: u32,
        approved_artifact_hash: String,
        #[allow(dead_code)]
        approved_config_hash: String,
        endpoint: String,
        provider_bind_address: String,
        namespace: String,
        database: String,
        username: String,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
        schema_generation: String,
        blob_root: String,
        instance_id: String,
        credential_ref: String,
        runtime_launch: serde_json::Value,
    }
    #[derive(Serialize)]
    struct OperationalConfig {
        store_pipe: String,
        launch_nonce: String,
        expected_client_sid: String,
        expected_client_session_id: u32,
        approved_artifact_hash: String,
        endpoint: String,
        provider_bind_address: String,
        namespace: String,
        database: String,
        username: String,
        connect_timeout_ms: u64,
        query_timeout_ms: u64,
        schema_generation: String,
        blob_root: String,
        instance_id: String,
        credential_ref: String,
        runtime_launch: OrderedRuntimeLaunch,
    }

    let wire: StoreConfigWire =
        serde_json::from_slice(bytes).map_err(|_error| KernelServiceError::InvalidField {
            field: "store_config.json",
            reason: "must be valid Store launch JSON",
        })?;
    let projection = OperationalConfig {
        store_pipe: wire.store_pipe,
        launch_nonce: wire.launch_nonce,
        expected_client_sid: wire.expected_client_sid,
        expected_client_session_id: wire.expected_client_session_id,
        approved_artifact_hash: wire.approved_artifact_hash,
        endpoint: wire.endpoint,
        provider_bind_address: wire.provider_bind_address,
        namespace: wire.namespace,
        database: wire.database,
        username: wire.username,
        connect_timeout_ms: wire.connect_timeout_ms,
        query_timeout_ms: wire.query_timeout_ms,
        schema_generation: wire.schema_generation,
        blob_root: wire.blob_root,
        instance_id: wire.instance_id,
        credential_ref: wire.credential_ref,
        runtime_launch: ordered_runtime_launch(&wire.runtime_launch)?,
    };
    let canonical =
        serde_json::to_vec(&projection).map_err(|_error| KernelServiceError::InvalidField {
            field: "store_config.json",
            reason: "Store launch projection could not be serialized",
        })?;
    PlatformHandle::new(sha256_hex(&canonical)).map_err(|_error| KernelServiceError::InvalidField {
        field: "store_config.approved_config_hash",
        reason: "Store semantic digest is invalid",
    })
}

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
            validate_runtime_digest(value.as_str(), field)?;
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

/// Immutable Host lineage and candidate binding presented before authority.
///
/// This structure is intentionally incapable of carrying activation nonce
/// material.  It authenticates the candidate session through the named-pipe
/// peer plus exact Host process and Kernel Job/process observations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelCandidateBinding {
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
    /// Host-owned Kernel Job Object identity.
    pub job_object_id: PlatformHandle,
    /// Candidate/active authenticated local IPC identity.
    pub pipe_identity: PlatformHandle,
    /// Host process identity observed before it opened the control pipe.
    pub host_process: HostProcessBinding,
    /// Host-retained Kernel Job binding; Kernel must reopen and reobserve it.
    pub job_binding: HostJobBinding,
    /// Restart budget for this lineage.
    pub restart_budget: RestartBudget,
    /// Containment action required if the previous lineage is suspect.
    pub containment_action: Option<ContainmentAction>,
}

impl HostKernelCandidateBinding {
    /// Returns the canonical digest bound into the later activation permit.
    pub fn compute_digest(&self) -> Result<String, KernelServiceError> {
        serde_json::to_vec(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| KernelServiceError::InvalidField {
                field: "candidate.digest",
                reason: "cannot canonicalize candidate binding",
            })
    }

    /// Validates all identity and epoch invariants before a candidate starts.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (value, field) in [
            (&self.installation_id, "candidate.installation_id"),
            (&self.activation_id, "candidate.activation_id"),
            (&self.artifact_hash, "candidate.artifact_hash"),
            (&self.config_hash, "candidate.config_hash"),
            (&self.job_object_id, "candidate.job_object_id"),
            (&self.pipe_identity, "candidate.pipe_identity"),
        ] {
            handle(value, field)?;
        }
        self.host_process.validate()?;
        self.job_binding.validate()?;
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

/// Durable one-use permit for one exact candidate activation.
///
/// The nonce is a canonical typed 256-bit value.  The remaining fields bind
/// it to the committed Host journal append, the exact prior disposition, and
/// the candidate/generation/authority contour.  No other command can carry
/// this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelActivationPermit {
    /// Stable Host-owned activation operation identity.
    pub operation_id: PlatformHandle,
    /// Digest of [`HostKernelCandidateBinding`].
    pub candidate_binding_digest: String,
    /// Digest of the exact durable prior-Kernel disposition.
    pub prior_kernel_disposition_digest: String,
    /// Transaction identity of the committed `NonceIssued` append.
    pub journal_transaction_id: PlatformHandle,
    /// Sequence of the committed `NonceIssued` append.
    pub journal_sequence: u64,
    /// Approved runtime generation carried by the request.
    pub generation: ResourceGeneration,
    /// Strict Kernel authority epoch for this process generation.
    pub authority_epoch: AuthorityEpoch,
    /// Fresh one-use OS-generated activation authority.
    pub activation_nonce: KernelActivationNonce,
}

impl KernelActivationPermit {
    /// Validates the permit against the nonce-free candidate and request.
    pub fn validate(
        &self,
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> Result<(), KernelServiceError> {
        handle(&self.operation_id, "permit.operation_id")?;
        handle(
            &self.journal_transaction_id,
            "permit.journal_transaction_id",
        )?;
        for (value, field) in [
            (
                self.candidate_binding_digest.as_str(),
                "permit.candidate_binding_digest",
            ),
            (
                self.prior_kernel_disposition_digest.as_str(),
                "permit.prior_kernel_disposition_digest",
            ),
        ] {
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(KernelServiceError::InvalidField {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        if self.journal_sequence == 0
            || self.generation != generation
            || self.authority_epoch != candidate.kernel_epoch
            || self.candidate_binding_digest != candidate.compute_digest()?
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_permit",
            });
        }
        Ok(())
    }

    /// Returns a non-secret digest used by receipts and reconciliation.
    pub fn activation_nonce_digest(&self) -> String {
        sha256_hex(self.activation_nonce.as_handle().as_str().as_bytes())
    }
}

/// Kernel-authored evidence that one exact permit was consumed once.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelActivationReceipt {
    /// Stable Host-owned activation operation identity.
    pub operation_id: PlatformHandle,
    /// Digest of the exact nonce-free candidate binding.
    pub candidate_binding_digest: String,
    /// Digest of the exact durable prior-Kernel disposition.
    pub prior_kernel_disposition_digest: String,
    /// Transaction identity of the committed `NonceIssued` append.
    pub journal_transaction_id: PlatformHandle,
    /// Sequence of the committed `NonceIssued` append.
    pub journal_sequence: u64,
    /// Approved runtime generation consumed by the Kernel.
    pub generation: ResourceGeneration,
    /// Kernel authority epoch consumed by the Kernel.
    pub authority_epoch: AuthorityEpoch,
    /// Non-secret digest of the consumed nonce; raw material is never echoed.
    pub activation_nonce_digest: String,
}

impl KernelActivationReceipt {
    /// Issues the exact receipt after the Kernel accepts one permit.
    pub fn issue(permit: &KernelActivationPermit) -> Self {
        Self {
            operation_id: permit.operation_id.clone(),
            candidate_binding_digest: permit.candidate_binding_digest.clone(),
            prior_kernel_disposition_digest: permit.prior_kernel_disposition_digest.clone(),
            journal_transaction_id: permit.journal_transaction_id.clone(),
            journal_sequence: permit.journal_sequence,
            generation: permit.generation,
            authority_epoch: permit.authority_epoch,
            activation_nonce_digest: permit.activation_nonce_digest(),
        }
    }

    /// Validates a receipt against the exact permit without exposing nonce bytes.
    pub fn validate(&self, permit: &KernelActivationPermit) -> Result<(), KernelServiceError> {
        let expected = Self::issue(permit);
        if self != &expected {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_receipt",
            });
        }
        Ok(())
    }
}

/// Nonce-free lookup for an Activate request whose transport outcome was unknown.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelActivationQuery {
    /// Exact operation identity of the possibly consumed permit.
    pub operation_id: PlatformHandle,
    /// Digest of the original Activate request; the permit is never repeated.
    pub activate_request_digest: String,
}

impl KernelActivationQuery {
    /// Validates the bounded nonce-free reconciliation identity.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.operation_id, "activation_query.operation_id")?;
        if self.activate_request_digest.len() != 64
            || !self
                .activate_request_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(KernelServiceError::InvalidField {
                field: "activation_query.activate_request_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
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

/// Kernel-authored receipt proving live readiness for one activation lineage.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReadyReceipt {
    /// Activation identity echoed from the candidate binding.
    pub activation_id: PlatformHandle,
    /// Exact consumed activation operation identity.
    pub activation_operation_id: PlatformHandle,
    /// Non-secret digest retained from the one-use activation receipt.
    pub activation_nonce_digest: String,
    /// Process and Job Object observation at readiness time.
    pub process: ProcessObservation,
    /// Kernel health vector at readiness time.
    pub health: HealthVector,
    /// Kernel-side readiness evidence references.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl KernelReadyReceipt {
    /// Returns the evidence handles that bind one self-authored readiness
    /// receipt to the exact `ProbeReady` request and its authority contour.
    ///
    /// The response digest covers both `request_digest` and this receipt. The
    /// repeated handles keep the receipt fail-closed when it is retained as a
    /// standalone observation after the response envelope is gone.
    pub fn probe_binding_evidence(
        request: &KernelControlRequest,
    ) -> Result<Vec<PlatformHandle>, KernelServiceError> {
        request.validate()?;
        if !matches!(&request.command, KernelControlCommand::ProbeReady) {
            return Err(KernelServiceError::InvalidField {
                field: "ready.probe_command",
                reason: "readiness evidence requires ProbeReady",
            });
        }
        [
            format!("kernel-probe-request:{}", request.payload_digest),
            format!("kernel-probe-generation:{}", request.generation.value()),
            format!(
                "kernel-probe-authority-epoch:{}",
                request.candidate.kernel_epoch.value()
            ),
            format!(
                "kernel-probe-config:{}",
                request.candidate.config_hash.as_str()
            ),
            format!(
                "kernel-probe-artifact:{}",
                request.candidate.artifact_hash.as_str()
            ),
        ]
        .into_iter()
        .map(PlatformHandle::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(KernelServiceError::from)
    }

    /// Validates readiness without inferring success from process existence.
    pub fn validate(
        &self,
        candidate: &HostKernelCandidateBinding,
        activation: &KernelActivationReceipt,
    ) -> Result<(), KernelServiceError> {
        handle(&self.activation_id, "ready.activation_id")?;
        handle(
            &self.activation_operation_id,
            "ready.activation_operation_id",
        )?;
        if self.activation_id != candidate.activation_id {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_id",
            });
        }
        if self.activation_operation_id != activation.operation_id
            || self.activation_nonce_digest != activation.activation_nonce_digest
            || activation.candidate_binding_digest != candidate.compute_digest()?
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_receipt",
            });
        }
        self.process.validate()?;
        if self.process.job_object_id != candidate.job_object_id {
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

    /// Validates a receipt against the exact authenticated readiness request.
    ///
    /// This rejects a valid receipt replayed for another request, generation,
    /// authority fence, configuration, or approved artifact.
    pub fn validate_for_probe(
        &self,
        request: &KernelControlRequest,
        activation: &KernelActivationReceipt,
    ) -> Result<(), KernelServiceError> {
        self.validate(&request.candidate, activation)?;
        let expected = Self::probe_binding_evidence(request)?;
        for (prefix, binding) in PROBE_BINDING_PREFIXES.into_iter().zip(expected) {
            let mut matching = self
                .evidence_refs
                .iter()
                .filter(|evidence| evidence.as_str().starts_with(prefix));
            if matching.next() != Some(&binding) || matching.next().is_some() {
                return Err(KernelServiceError::ReadinessNotProven);
            }
        }
        Ok(())
    }
}

/// Control messages accepted by the Kernel service boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
#[allow(
    clippy::large_enum_variant,
    reason = "the one-use activation permit remains self-describing on the single control wire"
)]
pub enum KernelControlCommand {
    /// Bind the freshly launched Store process/Job and establish the one
    /// canonical Store route before ordinary lifecycle commands are admitted.
    BootstrapStore(StoreBootstrapHandoff),
    /// Rebind the Store with same lineage, same approved executable/config
    /// and Job, fresh PID/start/image and Store fence, without restarting
    /// Kernel.
    RebindStore(StoreRebindHandoff),
    /// Reconcile a `RebindStore` request by operation digest after unknown delivery.
    ReconcileRebindStore(StoreRebindQuery),
    /// Begin reconciliation of the request's nonce-free candidate binding.
    Reconcile,
    /// Enter side-by-side candidate mode without authority.
    Shadow,
    /// Record that Host prepared the exclusive handoff.
    PrepareHandoff,
    /// Consume the exact durably issued one-time activation permit.
    Activate(KernelActivationPermit),
    /// Reconcile an Activate request by operation identity after an unknown
    /// transport outcome.  This never retries or reissues the permit.
    ReconcileActivation(KernelActivationQuery),
    /// Ask Kernel to prove readiness from live observations and self-author a
    /// receipt.  No caller-shaped receipt is accepted on this wire.
    ProbeReady,
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

    fn eliotd_launch_descriptor() -> EliotdLaunchDescriptor {
        let nonce = "eliotd:0123456789abcdef0123456789abcdef";
        let executable_sha256 = "a".repeat(64);
        let config_descriptor_sha256 = "b".repeat(64);
        EliotdLaunchDescriptor {
            wire_id: ELIOTD_LAUNCH_DESCRIPTOR_WIRE_ID.to_owned(),
            wire_version: ELIOTD_LAUNCH_DESCRIPTOR_WIRE_VERSION,
            executable: handle_value(r"C:\Eliot\eliotd.exe"),
            executable_sha256: executable_sha256.clone(),
            arguments: vec![
                handle_value("--config-descriptor"),
                handle_value(r"C:\ProgramData\Eliot\governor\eliotd.json"),
                handle_value("--config-descriptor-sha256"),
                handle_value(&config_descriptor_sha256),
                handle_value("--launch-nonce"),
                handle_value(nonce),
                handle_value("--executable-sha256"),
                handle_value(&executable_sha256),
            ],
            working_directory: handle_value(r"C:\Eliot"),
            config_descriptor: handle_value(r"C:\ProgramData\Eliot\governor\eliotd.json"),
            config_descriptor_sha256,
            launch_nonce: handle_value(nonce),
            authority_epoch: AuthorityEpoch::new(1).expect("epoch"),
            generation: ResourceGeneration::new(1).expect("generation"),
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("descriptor digest")
    }

    #[test]
    fn eliotd_descriptor_uses_opaque_public_nonce_not_a_path_authority() {
        let descriptor = eliotd_launch_descriptor();
        assert!(descriptor.validate().is_ok());

        let mut substituted = descriptor.clone();
        substituted.launch_nonce = handle_value(r"eliotd:C:\ProgramData\authority.key");
        substituted.arguments[5] = substituted.launch_nonce.clone();
        substituted.descriptor_sha256 = substituted.compute_digest().expect("digest");
        assert!(substituted.validate().is_err());

        let mut short = descriptor;
        short.launch_nonce = handle_value("eliotd:short");
        short.arguments[5] = short.launch_nonce.clone();
        short.descriptor_sha256 = short.compute_digest().expect("digest");
        assert!(short.validate().is_err());
    }

    #[test]
    fn eliotd_descriptor_requires_exact_canonical_child_argv() {
        let descriptor = eliotd_launch_descriptor();

        let mut extra = descriptor.clone();
        extra.arguments.push(handle_value("--unexpected"));
        extra.descriptor_sha256 = extra.compute_digest().expect("extra digest");
        assert!(extra.validate().is_err());

        let mut reordered = descriptor.clone();
        reordered.arguments.swap(0, 2);
        reordered.descriptor_sha256 = reordered.compute_digest().expect("reordered digest");
        assert!(reordered.validate().is_err());

        let mut duplicated = descriptor;
        duplicated.arguments[6] = handle_value("--launch-nonce");
        duplicated.arguments[7] = duplicated.launch_nonce.clone();
        duplicated.descriptor_sha256 = duplicated.compute_digest().expect("duplicate digest");
        assert!(duplicated.validate().is_err());
    }

    #[test]
    fn runtime_digest_domains_reject_scm_selector_and_legacy_zero() {
        for reserved in [PHASE_B_PENDING_SCM_DIGEST, LEGACY_PHASE_B_ZERO_DIGEST] {
            assert!(validate_runtime_digest(reserved, "test.runtime").is_err());

            let mut descriptor = eliotd_launch_descriptor();
            descriptor.executable_sha256 = reserved.to_owned();
            descriptor.arguments[7] = handle_value(reserved);
            descriptor.descriptor_sha256 = descriptor.compute_digest().expect("descriptor digest");
            assert!(descriptor.validate().is_err());

            let mut bootstrap = requirement();
            bootstrap.approved_artifact_hash = handle_value(reserved);
            assert!(bootstrap.validate().is_err());

            let mut config_bootstrap = requirement();
            config_bootstrap.approved_config_hash = handle_value(reserved);
            assert!(config_bootstrap.validate().is_err());
        }
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

    fn semantic_store_config_value(endpoint: &str, provider: &str) -> serde_json::Value {
        let mut value = serde_json::from_str::<serde_json::Value>(
            r#"{
            "store_pipe": "\\\\.\\pipe\\eliot\\store",
            "launch_nonce": "nonce",
            "expected_client_sid": "S-1-5-18",
            "expected_client_session_id": 0,
            "approved_artifact_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "approved_config_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "endpoint": "endpoint-placeholder",
            "provider_bind_address": "provider-placeholder",
            "namespace": "eliot",
            "database": "runtime",
            "username": "root",
            "connect_timeout_ms": 1000,
            "query_timeout_ms": 2000,
            "schema_generation": "schema-1",
            "blob_root": "C:/eliot/blob",
            "instance_id": "instance-1",
            "credential_ref": "credential-1",
            "runtime_launch": {
                "profile": "portable_dev",
                "portable_root": null,
                "installation_epoch": {
                    "installation": "installation-1",
                    "lineage_id": "lineage-1",
                    "sequence": 1
                },
                "generation": "generation-1",
                "authority_generation": 1,
                "authority_state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1,
                    "task_revision": null,
                    "policy_revision": null,
                    "integration_revision": null
                },
                "authority_descriptor_path": "C:/eliot/authority.json",
                "authority_descriptor_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "runtime_state_roots": {
                    "profile": "portable_dev",
                    "profile_anchor_root": "C:/eliot",
                    "installation_root": "C:/eliot",
                    "host_state_root": "C:/eliot/host",
                    "kernel_ors_root": "C:/eliot/kernel/state",
                    "kernel_work_root": "C:/eliot/kernel/work",
                    "store_data_root": "C:/eliot/store/data",
                    "store_work_root": "C:/eliot/store/work",
                    "store_temp_root": "C:/eliot/store/tmp",
                    "watchdog_state_root": "C:/eliot/watchdog",
                    "roots_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                },
                "kernel_work_root": "C:/eliot/kernel/work",
                "kernel_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eliotd_executable_path": "C:/eliot/eliotd.exe",
                "eliotd_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eliotd_config_path": "C:/eliot/eliotd-governor.json",
                "eliotd_config_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eliotd_descriptor_path": "C:/eliot/eliotd.json",
                "eliotd_descriptor_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eliotd_launch_nonce": "eliotd:nonce",
                "store_config_path": "C:/eliot/generation.json",
                "store_credential_target": "eliot/store/v1/credential",
                "store_bridge_executable_path": "C:/eliot/eliot-store-surreal.exe",
                "store_bridge_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "store_bootstrap_descriptor_path": "C:/eliot/store-bootstrap.json",
                "store_bootstrap_descriptor_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "canonical_store_executable_path": "C:/eliot/surreal.exe",
                "canonical_store_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "kernel_arguments": [],
                "store_bridge_arguments": [],
                "canonical_store_arguments": [],
                "host_executable_path": "C:/eliot/eliot-host.exe",
                "host_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "watchdog_executable_path": "C:/eliot/eliot-watchdog.exe",
                "watchdog_artifact_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "descriptor_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
        }"#,
        )
        .expect("semantic Store config fixture");
        value["endpoint"] = serde_json::Value::String(endpoint.to_owned());
        value["provider_bind_address"] = serde_json::Value::String(provider.to_owned());
        value
    }

    #[test]
    fn semantic_store_config_hash_separates_physical_bytes_and_digest_field() {
        let first_value = semantic_store_config_value("ws://127.0.0.1:8000/rpc", "127.0.0.1:8000");
        let mut second_value = first_value.clone();
        second_value["approved_config_hash"] =
            serde_json::Value::String("different-but-ignored".to_owned());
        let first = serde_json::to_vec_pretty(&first_value).expect("first bytes");
        let second = serde_json::to_vec(&second_value).expect("second bytes");
        let first_semantic = semantic_store_config_hash_from_json(&first).expect("semantic hash");
        let second_semantic = semantic_store_config_hash_from_json(&second).expect("semantic hash");
        assert_eq!(first_semantic, second_semantic);
        assert_ne!(sha256_hex(&first), sha256_hex(&second));
        assert_ne!(first_semantic.as_str(), sha256_hex(&first));
    }

    #[test]
    fn semantic_store_config_hash_changes_for_operational_mutation() {
        let first = serde_json::to_vec(&semantic_store_config_value(
            "ws://127.0.0.1:8000/rpc",
            "127.0.0.1:8000",
        ))
        .expect("first bytes");
        let second = serde_json::to_vec(&semantic_store_config_value(
            "ws://127.0.0.1:8001/rpc",
            "127.0.0.1:8001",
        ))
        .expect("second bytes");
        let first_semantic = semantic_store_config_hash_from_json(&first).expect("semantic hash");
        let second_semantic = semantic_store_config_hash_from_json(&second).expect("semantic hash");
        assert_ne!(first_semantic, second_semantic);
    }

    #[test]
    fn store_handoff_rejects_process_reuse_image_and_job_substitution() {
        let handoff = StoreBootstrapHandoff {
            requirement: requirement(),
            process_binding: StoreProcessBinding {
                process: HostProcessBinding {
                    process_id: 41,
                    start_time_100ns: 42,
                    image_path: r"C:\Eliot\eliot-store-surreal.exe".to_owned(),
                },
                job: handle_value(r"Local\Eliot-Host-Store-test"),
            },
        };
        assert!(handoff.validate().is_ok());

        let mut pid_reuse = handoff.clone();
        pid_reuse.process_binding.process.start_time_100ns = 43;
        assert!(pid_reuse.validate().is_ok());
        assert_ne!(pid_reuse, handoff);

        let mut wrong_image = handoff.clone();
        wrong_image.process_binding.process.image_path = r"C:\Evil\store.exe".to_owned();
        assert!(wrong_image.validate().is_ok());
        assert_ne!(wrong_image, handoff);

        let mut outside_job = handoff;
        outside_job.process_binding.job = handle_value(r"Local\Other-Job");
        assert!(outside_job.validate().is_ok());
        assert_ne!(
            outside_job.process_binding.job,
            handle_value(r"Local\Eliot-Host-Store-test")
        );
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

    fn candidate_binding() -> HostKernelCandidateBinding {
        HostKernelCandidateBinding {
            installation_id: handle_value("installation-1"),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            kernel_epoch: AuthorityEpoch::new(1).expect("kernel epoch"),
            activation_id: handle_value("activation-1"),
            artifact_hash: handle_value("artifact-1"),
            config_hash: handle_value("config-1"),
            job_object_id: handle_value("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle_value(KERNEL_CONTROL_PIPE),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\\\eliot\\\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\\\eliot\\\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            restart_budget: RestartBudget::new(1, 1).expect("budget"),
            containment_action: None,
        }
    }

    fn activation_permit(
        candidate: &HostKernelCandidateBinding,
        generation: ResourceGeneration,
    ) -> KernelActivationPermit {
        KernelActivationPermit {
            operation_id: handle_value("activation-operation-1"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle_value("journal-transaction-1"),
            journal_sequence: 7,
            generation,
            authority_epoch: candidate.kernel_epoch,
            activation_nonce: KernelActivationNonce::new(handle_value(&"a".repeat(64)))
                .expect("activation nonce"),
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
            candidate: candidate_binding(),
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

    fn ready_receipt(
        candidate: &HostKernelCandidateBinding,
        activation: &KernelActivationReceipt,
    ) -> KernelReadyReceipt {
        KernelReadyReceipt {
            activation_id: candidate.activation_id.clone(),
            activation_operation_id: activation.operation_id.clone(),
            activation_nonce_digest: activation.activation_nonce_digest.clone(),
            process: ProcessObservation {
                process_id: handle_value("pid:42:start:1"),
                job_object_id: candidate.job_object_id.clone(),
                state: ServiceProcessState::Ready,
                health: HealthVector::healthy(),
                evidence_refs: vec![handle_value("process-evidence-1")],
            },
            health: HealthVector::healthy(),
            evidence_refs: vec![handle_value("ready-evidence-1")],
        }
    }

    fn probe_request(candidate: HostKernelCandidateBinding) -> KernelControlRequest {
        KernelControlRequest {
            wire_id: KERNEL_CONTROL_WIRE_ID.to_owned(),
            wire_version: KERNEL_CONTROL_WIRE_VERSION,
            message_id: handle_value("probe-message-1"),
            sequence: 5,
            peer_process_id: 7,
            generation: ResourceGeneration::new(3).expect("generation"),
            candidate,
            command: KernelControlCommand::ProbeReady,
            payload_digest: String::new(),
        }
        .with_computed_digest()
        .expect("probe digest")
    }

    fn bound_ready_receipt(
        request: &KernelControlRequest,
        activation: &KernelActivationReceipt,
    ) -> KernelReadyReceipt {
        let mut receipt = ready_receipt(&request.candidate, activation);
        receipt
            .evidence_refs
            .extend(KernelReadyReceipt::probe_binding_evidence(request).expect("probe bindings"));
        receipt
    }

    #[test]
    fn candidate_is_nonce_free_and_old_handshake_authority_shape_is_rejected() {
        let candidate = candidate_binding();
        let value = serde_json::to_value(&candidate).expect("candidate json");
        assert!(value.get("activation_nonce").is_none());
        let mut old = value;
        old["activation_nonce"] = serde_json::Value::String("legacy-authority".to_owned());
        assert!(serde_json::from_value::<HostKernelCandidateBinding>(old).is_err());
    }

    #[test]
    fn activation_permit_binds_candidate_journal_generation_and_authority() {
        let candidate = candidate_binding();
        let generation = ResourceGeneration::new(3).expect("generation");
        let permit = activation_permit(&candidate, generation);
        assert!(permit.validate(&candidate, generation).is_ok());
        let receipt = KernelActivationReceipt::issue(&permit);
        assert!(receipt.validate(&permit).is_ok());
        let mut wrong = permit;
        wrong.journal_sequence += 1;
        assert!(receipt.validate(&wrong).is_err());

        let mut restarted = candidate;
        restarted.job_binding.root.process.start_time_100ns += 1;
        assert_ne!(
            restarted.compute_digest().expect("restarted digest"),
            wrong.candidate_binding_digest
        );
        assert!(wrong.validate(&restarted, generation).is_err());
    }

    #[test]
    fn ready_receipt_rejects_activation_job_health_and_evidence_substitution() {
        let candidate = candidate_binding();
        let permit = activation_permit(&candidate, ResourceGeneration::new(3).expect("generation"));
        let activation = KernelActivationReceipt::issue(&permit);
        let receipt = ready_receipt(&candidate, &activation);
        assert!(receipt.validate(&candidate, &activation).is_ok());

        let mut wrong_activation = receipt.clone();
        wrong_activation.activation_nonce_digest = "c".repeat(64);
        assert!(wrong_activation.validate(&candidate, &activation).is_err());

        let mut wrong_job = receipt.clone();
        wrong_job.process.job_object_id = handle_value("Local\\Eliot-Other-Job");
        assert!(wrong_job.validate(&candidate, &activation).is_err());

        let mut unhealthy = receipt.clone();
        unhealthy.health.liveness = eliot_runtime_contracts::HealthDimension::Degraded;
        assert!(unhealthy.validate(&candidate, &activation).is_err());

        let mut missing_evidence = receipt;
        missing_evidence.evidence_refs.clear();
        assert!(missing_evidence.validate(&candidate, &activation).is_err());
    }

    #[test]
    fn probe_ready_is_unit_wire_and_cannot_carry_host_receipt() {
        let command = KernelControlCommand::ProbeReady;
        assert_eq!(
            serde_json::to_value(&command).expect("probe json"),
            serde_json::Value::String("PROBE_READY".to_owned())
        );
        let forged = serde_json::json!({
            "PROBE_READY": {
                "activation_id": "host-authored",
                "activation_nonce": "nonce-1"
            }
        });
        assert!(serde_json::from_value::<KernelControlCommand>(forged).is_err());
    }

    #[test]
    fn ready_receipt_is_bound_to_exact_probe_generation_and_fence() {
        let candidate = candidate_binding();
        let permit = activation_permit(&candidate, ResourceGeneration::new(3).expect("generation"));
        let activation = KernelActivationReceipt::issue(&permit);
        let request = probe_request(candidate);
        let receipt = bound_ready_receipt(&request, &activation);
        assert!(receipt.validate_for_probe(&request, &activation).is_ok());

        let mut stale_request = request.clone();
        stale_request.message_id = handle_value("probe-message-2");
        stale_request.sequence = 6;
        stale_request.payload_digest = stale_request.compute_digest().expect("stale digest");
        assert!(
            receipt
                .validate_for_probe(&stale_request, &activation)
                .is_err()
        );
        let repeated = bound_ready_receipt(&stale_request, &activation);
        assert!(
            repeated
                .validate_for_probe(&stale_request, &activation)
                .is_ok()
        );
        assert_ne!(request.payload_digest, stale_request.payload_digest);
        assert_ne!(receipt.evidence_refs, repeated.evidence_refs);
        assert_eq!(
            receipt.activation_nonce_digest,
            repeated.activation_nonce_digest
        );
        let mut next_repeat_request = stale_request.clone();
        next_repeat_request.message_id = handle_value("probe-message-3");
        next_repeat_request.sequence = 7;
        next_repeat_request.payload_digest = next_repeat_request
            .compute_digest()
            .expect("next repeat digest");
        let next_repeated = bound_ready_receipt(&next_repeat_request, &activation);
        assert!(
            next_repeated
                .validate_for_probe(&next_repeat_request, &activation)
                .is_ok()
        );
        assert!(
            repeated
                .validate_for_probe(&next_repeat_request, &activation)
                .is_err()
        );
        assert_ne!(repeated.evidence_refs, next_repeated.evidence_refs);
        assert_eq!(
            repeated.activation_nonce_digest,
            next_repeated.activation_nonce_digest
        );

        let mut other_generation = request.clone();
        other_generation.generation = ResourceGeneration::new(4).expect("generation");
        other_generation.payload_digest = other_generation.compute_digest().expect("digest");
        assert!(
            receipt
                .validate_for_probe(&other_generation, &activation)
                .is_err()
        );

        let mut other_fence = request.clone();
        other_fence.candidate.kernel_epoch = AuthorityEpoch::new(2).expect("epoch");
        other_fence.payload_digest = other_fence.compute_digest().expect("digest");
        assert!(
            receipt
                .validate_for_probe(&other_fence, &activation)
                .is_err()
        );

        let mut other_config = request.clone();
        other_config.candidate.config_hash = handle_value("config-2");
        other_config.payload_digest = other_config.compute_digest().expect("digest");
        assert!(
            receipt
                .validate_for_probe(&other_config, &activation)
                .is_err()
        );

        let mut ambiguous = receipt.clone();
        ambiguous
            .evidence_refs
            .push(handle_value("kernel-probe-authority-epoch:99"));
        assert!(ambiguous.validate_for_probe(&request, &activation).is_err());

        let mut substituted = receipt;
        substituted.evidence_refs.retain(|evidence| {
            !evidence
                .as_str()
                .starts_with("kernel-probe-authority-epoch:")
        });
        substituted
            .evidence_refs
            .push(handle_value("kernel-probe-authority-epoch:99"));
        assert!(
            substituted
                .validate_for_probe(&request, &activation)
                .is_err()
        );

        let mut non_probe = request;
        non_probe.command = KernelControlCommand::Drain;
        non_probe.payload_digest = non_probe.compute_digest().expect("digest");
        assert!(KernelReadyReceipt::probe_binding_evidence(&non_probe).is_err());
    }

    #[test]
    fn host_process_and_job_binding_are_required_and_bounded() {
        let mut missing_process = candidate_binding();
        missing_process.host_process.process_id = 0;
        assert!(missing_process.validate().is_err());

        let mut missing_root = candidate_binding();
        missing_root.job_binding.root.process.start_time_100ns = 0;
        assert!(missing_root.validate().is_err());

        let mut missing_file = candidate_binding();
        missing_file.job_binding.root.executable.file_index = 0;
        assert!(missing_file.validate().is_err());
    }
}
