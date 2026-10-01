//! Protected installation launch declaration for the A-09 user broker.
//!
//! Architecture anchors: A9 User Broker protected launch, A13.2 Kernel and
//! failure domains, ARCH-AUTH-01 explicit authority, ARCH-SEC-02 SID/session
//! binding, ARCH-RES-01 bounded startup. Implementation anchors: I1.3
//! optional and on-demand processes (broker authentication by installation,
//! SID, session, and launch nonce), B.8 Kernel ↔ User Broker, and I2.23
//! capability-family topology.
//!
//! This cell owns only the protected stable caller/launch binding bytes,
//! validation, and the retained `ProtectedPathLease`. It never mints Kernel authority, never governs
//! canonical store state, and never synthesizes Governor decisions or process
//! evidence.
//!
//! Schema `eliot.user-broker.launch-binding.v2` (`BrokerLaunchBinding`) keeps
//! stable binding fields only: installation/SID/session declaration, broker
//! artifact/generation binding, launch nonce, operator artifact, and the
//! installation epoch fence. Per-operation request authority (`request_id`,
//! `idempotency_key`, `cancellation_id`, absolute transport deadline) is
//! never stored here; every Kernel operation mints a fresh
//! [`eliot_protocol::RequestIdentity`] through the operation-identity issuer.
//! Kernel connection/challenge material stays owned by the Kernel client
//! declaration (`eliot-cli`); policy/config authority stays owned by Kernel
//! snapshots. Neither is copied into this broker-local binding.

#![forbid(unsafe_code)]

use std::fs;
use std::io::Read;

use eliot_installation::UserBrokerInstallationProfile;
use eliot_platform_windows::{ProtectedPathLease, WindowsPlatform};
use eliot_user_broker_core::{OperatorArtifact, RegistrationRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::CompositionError;
use super::operation_identity::validate_fence_value;
use crate::BrokerAdmissionRefusal;

/// Stable protected launch binding schema version.
pub(super) const LAUNCH_BINDING_SCHEMA: &str = "eliot.user-broker.launch-binding.v2";

const LAUNCH_CONFIG_RELATIVE_PATH: &str = "Eliot/user-broker/launch.json";

/// Fresh registration lease window minted per register operation, in ms.
pub(super) const REGISTRATION_LEASE_TTL_MS: u64 = 60_000;

/// Stable caller/launch binding. No per-operation request authority lives here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerLaunchBinding {
    /// Must equal [`LAUNCH_BINDING_SCHEMA`].
    pub(super) schema: String,
    /// Stable installation/SID/session/artifact/nonce declaration. The
    /// `observed_at`/`lease_expires_at` pair is declaration metadata;
    /// every register operation stamps a fresh window from these stable
    /// fields via [`fresh_registration_request`].
    pub(super) registration: RegistrationRequest,
    /// Stable operator artifact binding.
    pub(super) operator_artifact: OperatorArtifactConfig,
    /// Installation-owned User Broker profile bytes published by Host Phase
    /// B. The path is only a locator; admission requires exact retained bytes,
    /// the profile's self-binding, and exact launch identity equality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) installation_profile: Option<InstallationProfileBinding>,
    /// Stable installation epoch fence as exact JSON. This is epoch-scoped
    /// authority binding, not a per-operation identity: the lineage-aware
    /// epoch moves only through the operation-identity issuer from
    /// Kernel-issued registration receipts. Scalar authority epochs are
    /// never stored or coerced here. The value is always validated through
    /// the owning request-identity validator before use.
    pub(super) launch_authority_fence: Value,
}

/// Exact protected-file locator and digest for the immutable P-08 profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct InstallationProfileBinding {
    /// Absolute path supplied by the protected launch declaration.
    pub(super) path: String,
    /// SHA-256 over the exact canonical bytes published by Host Phase B.
    pub(super) digest: String,
}

/// Retained admitted profile bytes for this broker process lifetime.
pub(super) struct AdmittedInstallationProfile {
    pub(super) profile: UserBrokerInstallationProfile,
    pub(super) _lease: ProtectedPathLease,
    pub(super) _adapter_leases: Vec<ProtectedPathLease>,
}

/// Re-observes OpenCode processes through the native process owner and joins
/// each exact PID/start/image tuple to the immutable adapter pair already
/// admitted into this profile. The result is candidate evidence; callback
/// admission still needs an OS-observed peer join at the listener.
pub(super) fn observe_opencode_runtime(
    admitted: &AdmittedInstallationProfile,
    broker_process_id: u32,
) -> Result<Vec<crate::OpenCodeRuntimeProcessObservation>, CompositionError> {
    let Some(adapter) = admitted.profile.opencode_adapter.as_ref() else {
        return Ok(Vec::new());
    };
    let processes = eliot_platform_windows::parent_bound_process_identities_named("opencode.exe")
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    processes
        .into_iter()
        .map(|candidate| {
            let process = candidate.process;
            let executable_sha256 = observe_process_image_sha256(&process)?;
            // The live process identity is re-read directly by the native
            // process owner after hashing the exact image file.
            let live = eliot_platform_windows::parent_bound_process_identities_named("opencode.exe")
                .map_err(|error| CompositionError::Launch(error.to_string()))?;
            if !live.iter().any(|observed| {
                observed.process == process
                    && observed.parent_process_id == candidate.parent_process_id
            }) {
                return Err(CompositionError::Launch(
                    "OpenCode process or launch-parent identity changed during runtime observation"
                        .to_owned(),
                ));
            }
            Ok(crate::OpenCodeRuntimeProcessObservation {
                process,
                parent_process_id: candidate.parent_process_id,
                launched_by_broker: candidate.parent_process_id == broker_process_id,
                executable_sha256,
                adapter_artifact_sha256: adapter.artifact_digest.as_str().to_owned(),
                adapter_descriptor_sha256: adapter.descriptor_digest.as_str().to_owned(),
                installation_profile_sha256: admitted.profile.profile_sha256.as_str().to_owned(),
            })
        })
        .collect()
}

#[cfg(windows)]
fn observe_process_image_sha256(
    process: &eliot_platform_windows::ProcessIdentity,
) -> Result<String, CompositionError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    const MAX_OPENCODE_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
    let path = std::path::Path::new(&process.image_path);
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options
        .open(path)
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    let metadata = file
        .metadata()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_OPENCODE_IMAGE_BYTES
    {
        return Err(CompositionError::Launch(
            "OpenCode executable image is not a bounded regular file".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .filter(|length| *length <= MAX_OPENCODE_IMAGE_BYTES)
            .ok_or_else(|| {
                CompositionError::Launch("OpenCode executable image exceeded its bound".to_owned())
            })?;
        digest.update(&chunk[..read]);
    }
    if total != metadata.len() {
        return Err(CompositionError::Launch(
            "OpenCode executable image length changed during observation".to_owned(),
        ));
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(not(windows))]
fn observe_process_image_sha256(
    _process: &eliot_platform_windows::ProcessIdentity,
) -> Result<String, CompositionError> {
    Err(CompositionError::Launch(
        "native OpenCode process observation is unavailable on this platform".to_owned(),
    ))
}

/// The live process identity this broker is admitted as.
///
/// A process id alone is not a process: Windows reuses ids, and a broker that
/// only pinned its pid could be satisfied by an unrelated process that later
/// inherited the number. The binding therefore names the id, the observed
/// process start instant, and the SHA-256 of the exact executable image that
/// was running when the broker admitted itself. It is re-observed on every
/// authenticated broker operation, so a replaced image, a recycled id, or a
/// substituted process fails closed before any Kernel transaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerProcessBinding {
    /// The observable live-process identity, re-proven on every operation.
    pub(super) identity: BrokerProcessIdentity,
    /// Lowercase SHA-256 of the exact running executable image, observed once
    /// when the broker admitted itself against its protected declaration.
    pub(super) artifact_digest: String,
}

/// The cheap, per-operation half of the live process identity.
///
/// Re-proving the id, the start instant, and the running image path on every
/// authenticated operation is what makes a replaced image, a recycled
/// process id, or a substituted process fail closed. Re-hashing the image
/// bytes is deliberately *not* repeated here: it is proven once at admission
/// (and again on the next start), because the bytes a running process
/// executes cannot change underneath it without the start instant changing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BrokerProcessIdentity {
    /// Current OS process id.
    pub(super) process_id: u32,
    /// Observed process start instant, in 100 ns units since the Windows
    /// epoch. Zero is not a usable start observation and is refused.
    pub(super) process_start_100ns: u64,
    /// Image path the OS reports for this process id.
    pub(super) image_path: String,
}

impl BrokerProcessIdentity {
    /// Returns whether this observation is the same live process.
    pub(super) fn is_same_process(&self, other: &Self) -> bool {
        self.process_id == other.process_id
            && self.process_start_100ns == other.process_start_100ns
            && eliot_platform_windows::ordinal_eq_str(&self.image_path, &other.image_path)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct OperatorArtifactConfig {
    pub(super) image_id: String,
    pub(super) executable: String,
    pub(super) artifact_digest: String,
}

fn artifact_digest() -> Result<String, CompositionError> {
    let executable = std::env::current_exe().map_err(CompositionError::Durable)?;
    let bytes = fs::read(executable).map_err(CompositionError::Durable)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Observes the live process identity (id, start instant, running image).
///
/// The image path observed from the OS handle must be the executable this
/// process started from: an observed path that names anything else means the
/// id was inspected for a different process, which is refused rather than
/// interpreted. Nothing here mints authority — it only proves which process
/// the authenticated declaration is describing.
pub(super) fn current_process_identity() -> Result<BrokerProcessIdentity, CompositionError> {
    let executable = std::env::current_exe().map_err(CompositionError::Durable)?;
    let root = executable.parent().ok_or_else(|| {
        BrokerAdmissionRefusal::ProcessIdentityUnprovable.with_platform("executable has no parent")
    })?;
    let platform = WindowsPlatform::new(root)
        .map_err(|error| BrokerAdmissionRefusal::ProcessIdentityUnprovable.with_platform(error))?;
    let observed = platform
        .process_identity(std::process::id())
        .map_err(|error| BrokerAdmissionRefusal::ProcessIdentityUnprovable.with_platform(error))?;
    if observed.process_id == 0
        || observed.start_time_100ns == 0
        || !eliot_platform_windows::ordinal_eq_str(
            &observed.image_path,
            &executable.to_string_lossy(),
        )
    {
        return Err(BrokerAdmissionRefusal::ProcessIdentityUnprovable
            .with_platform("observed process image is not this executable"));
    }
    Ok(BrokerProcessIdentity {
        process_id: observed.process_id,
        process_start_100ns: observed.start_time_100ns,
        image_path: observed.image_path,
    })
}

/// Observes the complete admission binding: the live process identity plus
/// the digest of the exact image bytes that process is running.
pub(super) fn current_process_binding() -> Result<BrokerProcessBinding, CompositionError> {
    Ok(BrokerProcessBinding {
        identity: current_process_identity()?,
        artifact_digest: artifact_digest()?,
    })
}

fn validate_operator_artifact(config: &OperatorArtifactConfig) -> Result<(), CompositionError> {
    OperatorArtifact {
        image_id: config.image_id.clone(),
        executable: config.executable.clone(),
        artifact_digest: config.artifact_digest.clone(),
    }
    .validate()
    .map_err(|error| CompositionError::Launch(error.to_string()))
}

fn validate_registration_declaration(
    registration: &RegistrationRequest,
) -> Result<(), CompositionError> {
    registration
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    let expected_pid = std::process::id().to_string();
    if registration.broker_process_id != expected_pid {
        return Err(CompositionError::Launch(
            "protected broker process identity does not match current process".to_owned(),
        ));
    }
    if !registration
        .broker_artifact_digest
        .eq_ignore_ascii_case(&artifact_digest()?)
    {
        return Err(CompositionError::Launch(
            "protected broker artifact digest does not match current executable".to_owned(),
        ));
    }
    #[cfg(windows)]
    {
        let identity = eliot_platform_windows::current_process_named_pipe_expectation()
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        if registration.windows_sid != identity.expected_sid()
            || registration.interactive_session_id != identity.expected_session_id().to_string()
        {
            return Err(CompositionError::Launch(
                "protected broker SID/session does not match current token".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Validates one v2 binding without touching any external authority state.
pub(super) fn validate_launch_binding(
    binding: &BrokerLaunchBinding,
) -> Result<(), CompositionError> {
    if binding.schema != LAUNCH_BINDING_SCHEMA {
        return Err(CompositionError::Launch(format!(
            "protected launch binding schema is not {LAUNCH_BINDING_SCHEMA}"
        )));
    }
    validate_registration_declaration(&binding.registration)?;
    validate_operator_artifact(&binding.operator_artifact)?;
    if let Some(profile) = &binding.installation_profile {
        if !std::path::Path::new(&profile.path).is_absolute() {
            return Err(CompositionError::Launch(
                "protected User Broker profile path is not absolute".to_owned(),
            ));
        }
        validate_sha256(&profile.digest, "installation_profile.digest")?;
    }
    validate_fence_value(&binding.launch_authority_fence)
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    Ok(())
}

/// Parses and validates v2 binding bytes. Unknown-schema bytes are refused
/// with a typed error (fail-closed); they are never reinterpreted.
pub(super) fn parse_binding_bytes(bytes: &[u8]) -> Result<BrokerLaunchBinding, CompositionError> {
    let binding: BrokerLaunchBinding =
        serde_json::from_slice(bytes).map_err(CompositionError::Encoding)?;
    validate_launch_binding(&binding)?;
    Ok(binding)
}

/// Canonical digest of one validated binding (idempotency scope + evidence).
pub(super) fn binding_digest(binding: &BrokerLaunchBinding) -> Result<String, CompositionError> {
    let value = serde_json::to_value(binding).map_err(CompositionError::Encoding)?;
    let bytes = serde_json::to_vec(&canonical_json(&value)).map_err(CompositionError::Encoding)?;
    Ok(sha256_hex(&bytes))
}

/// Deterministic canonical form: object keys sorted recursively.
fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        Value::Object(object) => {
            let mut entries: Vec<(&String, &Value)> = object.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (key, item) in entries {
                sorted.insert(key.clone(), canonical_json(item));
            }
            Value::Object(sorted)
        }
        scalar => scalar.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Builds a fresh register-operation declaration from stable binding fields
/// with a current lease window. Stable caller identity (installation, SID,
/// session, artifact, nonce) is preserved; operation time is never reused
/// from the durable declaration bytes.
pub(super) fn fresh_registration_request(
    binding: &BrokerLaunchBinding,
    observed_at: u64,
    lease_expires_at: u64,
) -> Result<RegistrationRequest, CompositionError> {
    if observed_at == 0 || lease_expires_at <= observed_at {
        return Err(CompositionError::Launch(
            "fresh registration lease window is invalid".to_owned(),
        ));
    }
    let request = RegistrationRequest {
        installation_id: binding.registration.installation_id.clone(),
        windows_sid: binding.registration.windows_sid.clone(),
        interactive_session_id: binding.registration.interactive_session_id.clone(),
        boot_session_id: binding.registration.boot_session_id.clone(),
        broker_process_id: binding.registration.broker_process_id.clone(),
        broker_artifact_digest: binding.registration.broker_artifact_digest.clone(),
        protocol_generation: binding.registration.protocol_generation,
        launch_nonce: binding.registration.launch_nonce.clone(),
        observed_at,
        lease_expires_at,
    };
    request
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    Ok(request)
}

pub(super) fn load_protected_launch_binding() -> Result<
    (
        BrokerLaunchBinding,
        ProtectedPathLease,
        Option<AdmittedInstallationProfile>,
    ),
    CompositionError,
> {
    #[cfg(not(windows))]
    {
        Err(CompositionError::Kernel(
            "Windows protected broker launch configuration".to_owned(),
        ))
    }
    #[cfg(windows)]
    {
        let path = eliot_platform_windows::protected_program_data_path(LAUNCH_CONFIG_RELATIVE_PATH)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let lease = ProtectedPathLease::open_existing_absolute(&path)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let bytes = lease
            .read_bounded(64 * 1024)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let binding = parse_binding_bytes(&bytes)?;
        let profile = binding
            .installation_profile
            .as_ref()
            .map(load_admitted_installation_profile)
            .transpose()?;
        Ok((binding, lease, profile))
    }
}

#[cfg(windows)]
fn load_admitted_installation_profile(
    binding: &InstallationProfileBinding,
) -> Result<AdmittedInstallationProfile, CompositionError> {
    let lease = ProtectedPathLease::open_existing_absolute(std::path::Path::new(&binding.path))
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    let bytes = lease
        .read_bounded(1024 * 1024)
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if digest != binding.digest {
        return Err(CompositionError::Launch(
            "protected User Broker profile digest does not match exact retained bytes".to_owned(),
        ));
    }
    let profile: UserBrokerInstallationProfile =
        serde_json::from_slice(&bytes).map_err(CompositionError::Encoding)?;
    profile
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    let mut adapter_leases = Vec::new();
    if let Some(adapter) = &profile.opencode_adapter {
        for (path, digest, limit) in [
            (&adapter.artifact_path, &adapter.artifact_digest, 1024 * 1024),
            (
                &adapter.descriptor_path,
                &adapter.descriptor_digest,
                256 * 1024,
            ),
        ] {
            let artifact_lease = ProtectedPathLease::open_existing_absolute(
                std::path::Path::new(path.as_str()),
            )
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
            let artifact_bytes = artifact_lease
                .read_bounded(limit)
                .map_err(|error| CompositionError::Protected(error.to_string()))?;
            let observed_digest = format!("{:x}", Sha256::digest(&artifact_bytes));
            if observed_digest != digest.as_str() {
                return Err(CompositionError::Launch(
                    "installed OpenCode adapter bytes differ from the admitted profile digest"
                        .to_owned(),
                ));
            }
            if path == &adapter.descriptor_path {
                adapter
                    .validate_descriptor_bytes(&artifact_bytes)
                    .map_err(|error| CompositionError::Launch(error.to_string()))?;
            }
            adapter_leases.push(artifact_lease);
        }
    }
    Ok(AdmittedInstallationProfile {
        profile,
        _lease: lease,
        _adapter_leases: adapter_leases,
    })
}

fn validate_sha256(value: &str, field: &str) -> Result<(), CompositionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CompositionError::Launch(format!(
            "protected {field} is not lowercase SHA-256"
        )));
    }
    Ok(())
}

#[cfg(test)]
// Test fixtures panic on setup failure; that panic is the test signal.
// Production code above carries no unwrap/expect.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_fence() -> Value {
        serde_json::json!({
            "authority_epoch": {
                "lineage_id": "01234567-89ab-cdef-0123-456789abcdef",
                "sequence": 7,
            },
            "resource_generation": 3,
            "task_revision": null,
            "policy_revision": null,
            "integration_revision": null,
        })
    }

    fn live_registration() -> RegistrationRequest {
        let pid = std::process::id().to_string();
        let executable = std::env::current_exe().expect("current exe");
        let bytes = std::fs::read(executable).expect("exe bytes");
        let (windows_sid, interactive_session_id) = current_sid_session();
        RegistrationRequest {
            installation_id: "installation-test-1".to_owned(),
            windows_sid,
            interactive_session_id,
            boot_session_id: "boot-session-test-1".to_owned(),
            broker_process_id: pid,
            broker_artifact_digest: format!("{:x}", Sha256::digest(bytes)),
            protocol_generation: eliot_protocol::ProtocolVersion::CURRENT,
            launch_nonce: "launch-nonce-test-1".to_owned(),
            observed_at: 1_786_000_000_000,
            lease_expires_at: 1_786_000_060_000,
        }
    }

    fn current_sid_session() -> (String, String) {
        #[cfg(windows)]
        {
            let identity = eliot_platform_windows::current_process_named_pipe_expectation()
                .expect("current process pipe expectation");
            (
                identity.expected_sid().to_owned(),
                identity.expected_session_id().to_string(),
            )
        }
        #[cfg(not(windows))]
        {
            ("S-1-5-21-100-200-300-1001".to_owned(), "7".to_owned())
        }
    }

    fn test_binding() -> BrokerLaunchBinding {
        BrokerLaunchBinding {
            schema: LAUNCH_BINDING_SCHEMA.to_owned(),
            registration: live_registration(),
            operator_artifact: OperatorArtifactConfig {
                image_id: "image-test-1".to_owned(),
                executable: "C:\\Eliot\\operator.exe".to_owned(),
                artifact_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
            },
            installation_profile: None,
            launch_authority_fence: test_fence(),
        }
    }

    #[test]
    fn v2_binding_validates_against_live_process() {
        let binding = test_binding();
        validate_launch_binding(&binding).expect("live binding validates");
        let digest = binding_digest(&binding).expect("binding digest");
        assert_eq!(digest.len(), 64);
    }

    #[test]
    fn unknown_schema_is_refused() {
        let legacy_shaped = serde_json::json!({
            "registration": live_registration(),
            "request_identity": {
                "historical": "v1-historical-request",
            },
            "operator_artifact": {
                "image_id": "image-test-1",
                "executable": "C:\\Eliot\\operator.exe",
                "artifact_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
        });
        let legacy_bytes = serde_json::to_vec(&legacy_shaped).expect("legacy bytes");
        assert!(
            parse_binding_bytes(&legacy_bytes).is_err(),
            "legacy-shaped bytes must be refused fail-closed"
        );
        let mut unknown = test_binding();
        unknown.schema = "eliot.user-broker.launch-binding.v9".to_owned();
        let unknown_bytes = serde_json::to_vec(&unknown).expect("v9 bytes");
        assert!(
            parse_binding_bytes(&unknown_bytes).is_err(),
            "unknown schema version must be refused fail-closed"
        );
    }

    #[test]
    fn wrong_schema_version_fails_closed() {
        let mut binding = test_binding();
        binding.schema = "eliot.user-broker.launch-binding.v9".to_owned();
        assert!(validate_launch_binding(&binding).is_err());
    }

    #[test]
    fn fresh_registration_stamps_a_new_lease_window() {
        let binding = test_binding();
        let request = fresh_registration_request(&binding, 1_786_000_100_000, 1_786_000_160_000)
            .expect("fresh registration");
        assert_eq!(request.installation_id, "installation-test-1");
        assert_eq!(request.launch_nonce, "launch-nonce-test-1");
        assert_eq!(request.observed_at, 1_786_000_100_000);
        assert_eq!(request.lease_expires_at, 1_786_000_160_000);
        assert!(fresh_registration_request(&binding, 0, 1).is_err());
        assert!(fresh_registration_request(&binding, 10, 10).is_err());
    }
}
