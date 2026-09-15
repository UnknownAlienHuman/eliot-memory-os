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
//! validation, explicit v1→v2 migration, and the retained
//! `ProtectedPathLease`. It never mints Kernel authority, never governs
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
//!
//! A legacy v1 file (with an embedded full `RequestIdentity`) is never
//! silently reinterpreted: it is validated with the legacy rules, its stable
//! fields and epoch fence are extracted, its historical request authority is
//! dropped, its SHA-256 digest is retained as migration evidence, and the v2
//! bytes are published atomically when the protected contour permits it.

#![forbid(unsafe_code)]

use std::fs;

use eliot_platform_windows::ProtectedPathLease;
use eliot_protocol::RequestIdentity;
use eliot_user_broker_core::{OperatorArtifact, RegistrationRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::CompositionError;
use super::operation_identity::validate_fence_value;

/// Stable protected launch binding schema version.
pub(super) const LAUNCH_BINDING_SCHEMA: &str = "eliot.user-broker.launch-binding.v2";
/// Legacy protected launch schema marker (migration source only).
const LEGACY_LAUNCH_SCHEMA_HINT: &str = "request_identity";

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

/// Legacy v1 protected launch file: stable declaration plus one embedded
/// full per-operation [`RequestIdentity`]. Read-only migration source; its
/// request authority is never installed for a Kernel operation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyBrokerLaunchConfigV1 {
    registration: RegistrationRequest,
    request_identity: RequestIdentity,
    operator_artifact: OperatorArtifactConfig,
}

/// Evidence retained for one explicit v1→v2 migration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationEvidence {
    /// SHA-256 of the exact legacy v1 bytes that were migrated.
    pub v1_digest: String,
    /// Digest of the resulting v2 binding.
    pub binding_digest: String,
    /// Whether the v2 bytes were durably published back to the protected
    /// file. `false` still never revives v1 request authority: migration is
    /// applied in memory and no code path installs a legacy identity.
    pub durable_rewrite: bool,
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

/// Parses and validates v2 binding bytes. Legacy v1 bytes always fail here
/// because `request_identity` is not an admitted v2 field.
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

/// Migrates legacy v1 bytes to a v2 binding in memory. The legacy file is
/// validated with the legacy rules first; only the stable declaration, the
/// operator artifact, and the epoch fence cross the boundary. The historical
/// `request_id`, `idempotency_key`, `cancellation_id`, and absolute deadline
/// are dropped and never become authority again.
pub(super) fn migrate_v1_bytes(
    bytes: &[u8],
) -> Result<(BrokerLaunchBinding, MigrationEvidence), CompositionError> {
    let legacy: LegacyBrokerLaunchConfigV1 =
        serde_json::from_slice(bytes).map_err(CompositionError::Encoding)?;
    validate_registration_declaration(&legacy.registration)?;
    validate_operator_artifact(&legacy.operator_artifact)?;
    legacy
        .request_identity
        .validate()
        .map_err(|error| CompositionError::Launch(error.to_string()))?;
    // Only the epoch fence crosses the boundary, as exact JSON. Field access
    // needs no foundation type import; the fence is revalidated below.
    let fence = serde_json::to_value(&legacy.request_identity.request.state_fence)
        .map_err(CompositionError::Encoding)?;
    let binding = BrokerLaunchBinding {
        schema: LAUNCH_BINDING_SCHEMA.to_owned(),
        registration: legacy.registration,
        operator_artifact: legacy.operator_artifact,
        launch_authority_fence: fence,
    };
    validate_launch_binding(&binding)?;
    let digest = binding_digest(&binding)?;
    Ok((
        binding,
        MigrationEvidence {
            v1_digest: sha256_hex(bytes),
            binding_digest: digest,
            durable_rewrite: false,
        },
    ))
}

/// Returns true when the bytes look like a legacy v1 file rather than v2.
/// This is a routing hint only; parsing remains strict in both directions.
fn looks_like_v1(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .is_ok_and(|value| value.get(LEGACY_LAUNCH_SCHEMA_HINT).is_some())
}

pub(super) fn load_protected_launch_binding() -> Result<
    (
        BrokerLaunchBinding,
        ProtectedPathLease,
        Option<MigrationEvidence>,
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
        if looks_like_v1(&bytes) {
            let (binding, mut evidence) = migrate_v1_bytes(&bytes)?;
            evidence.durable_rewrite = rewrite_binding_atomically(&path, &binding)?;
            let digest = binding_digest(&binding)?;
            evidence.binding_digest = digest;
            return Ok((binding, lease, Some(evidence)));
        }
        let binding = parse_binding_bytes(&bytes)?;
        Ok((binding, lease, None))
    }
}

/// Publishes v2 bytes back to the protected launch file and proves the exact
/// bytes durable. Returns whether the durable rewrite succeeded; a failure
/// leaves the legacy file untouched and the caller proceeds with the
/// in-memory migrated binding (its legacy request authority stays inert).
#[cfg(windows)]
fn rewrite_binding_atomically(
    path: &std::path::Path,
    binding: &BrokerLaunchBinding,
) -> Result<bool, CompositionError> {
    let bytes = serde_json::to_vec(binding).map_err(CompositionError::Encoding)?;
    let parent = path
        .parent()
        .ok_or_else(|| CompositionError::Protected("launch file has no parent".to_owned()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CompositionError::Protected("launch file name missing".to_owned()))?;
    let scope = eliot_platform::WorkScopePath::new(file_name.to_string_lossy().into_owned())
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    let platform = eliot_platform_windows::WindowsPlatform::new(parent)
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    // The publish outcome classification is intentionally not trusted here:
    // the re-read below is the durability proof.
    let _ = platform.publish_atomic(&scope, &bytes);
    let fresh = ProtectedPathLease::open_existing_absolute(path)
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    fresh
        .verify_stable_identity()
        .and_then(|()| fresh.verify_path_identity())
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    let current = fresh
        .read_bounded(64 * 1024)
        .map_err(|error| CompositionError::Protected(error.to_string()))?;
    Ok(current == bytes)
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

    fn test_request_identity() -> RequestIdentity {
        serde_json::from_value(serde_json::json!({
            "request": {
                "metadata": {
                    "request_id": "v1-historical-request",
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-user-broker",
                    "source_id": "user-broker-transport",
                    "state_fence": test_fence(),
                    "clock": {
                        "valid_time_ms": 1_786_000_000_000i64,
                        "known_time_ms": 1_786_000_000_000i64,
                        "transaction_sequence": null,
                        "monotonic_ns": null,
                    },
                },
                "state_fence": test_fence(),
            },
            "idempotency_key": "v1-historical-idempotency",
            "deadline_unix_ms": 1,
            "cancellation_id": "v1-historical-cancellation",
        }))
        .expect("test request identity")
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
    fn legacy_v1_bytes_never_parse_as_v2() {
        let legacy = serde_json::json!({
            "registration": live_registration(),
            "request_identity": test_request_identity(),
            "operator_artifact": {
                "image_id": "image-test-1",
                "executable": "C:\\Eliot\\operator.exe",
                "artifact_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
        });
        let bytes = serde_json::to_vec(&legacy).expect("legacy bytes");
        let parsed = parse_binding_bytes(&bytes);
        assert!(
            parsed.is_err(),
            "v1 bytes must never be silently read as v2, got {parsed:?}"
        );
        assert!(looks_like_v1(&bytes));
        assert!(!looks_like_v1(
            &serde_json::to_vec(&test_binding()).expect("v2 bytes")
        ));
    }

    #[test]
    fn migration_drops_historical_request_authority() {
        let legacy = serde_json::json!({
            "registration": live_registration(),
            "request_identity": test_request_identity(),
            "operator_artifact": {
                "image_id": "image-test-1",
                "executable": "C:\\Eliot\\operator.exe",
                "artifact_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
        });
        let bytes = serde_json::to_vec(&legacy).expect("legacy bytes");
        let (binding, evidence) = migrate_v1_bytes(&bytes).expect("migration");
        assert_eq!(binding.schema, LAUNCH_BINDING_SCHEMA);
        assert_eq!(binding.registration.installation_id, "installation-test-1");
        assert_eq!(binding.registration.launch_nonce, "launch-nonce-test-1");
        assert_eq!(binding.launch_authority_fence, test_fence());
        assert_eq!(evidence.v1_digest, sha256_hex(&bytes));
        assert!(!evidence.durable_rewrite);
        // No historical request authority survives in any serialized form.
        let rebound = serde_json::to_vec(&binding).expect("v2 bytes");
        let text = String::from_utf8(rebound).expect("utf8");
        for historical in [
            "v1-historical-request",
            "v1-historical-idempotency",
            "v1-historical-cancellation",
            "request_identity",
            "idempotency_key",
            "cancellation_id",
            "deadline_unix_ms",
        ] {
            assert!(
                !text.contains(historical),
                "migrated binding must not carry {historical}"
            );
        }
        let reparsed = parse_binding_bytes(&serde_json::to_vec(&binding).expect("bytes"))
            .expect("migrated binding reparses as v2");
        assert_eq!(reparsed, binding);
    }

    #[test]
    fn migration_rejects_a_tampered_legacy_file() {
        let mut registration = live_registration();
        registration.launch_nonce = String::new();
        let legacy = serde_json::json!({
            "registration": registration,
            "request_identity": test_request_identity(),
            "operator_artifact": {
                "image_id": "image-test-1",
                "executable": "C:\\Eliot\\operator.exe",
                "artifact_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            },
        });
        let bytes = serde_json::to_vec(&legacy).expect("legacy bytes");
        assert!(
            migrate_v1_bytes(&bytes).is_err(),
            "tampered v1 must fail closed"
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
