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

use eliot_platform_windows::ProtectedPathLease;
use eliot_user_broker_core::{OperatorArtifact, RegistrationRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::CompositionError;
use super::operation_identity::validate_fence_value;

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
    /// Stable installation epoch fence as exact JSON. This is epoch-scoped
    /// authority binding, not a per-operation identity: the lineage-aware
    /// epoch moves only through the operation-identity issuer from
    /// Kernel-issued registration receipts. Scalar authority epochs are
    /// never stored or coerced here. The value is always validated through
    /// the owning request-identity validator before use.
    pub(super) launch_authority_fence: Value,
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
    (BrokerLaunchBinding, ProtectedPathLease),
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
        Ok((binding, lease))
    }
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
