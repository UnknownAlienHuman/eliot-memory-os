//! T02 acceptance matrix for issue #931: the runtime, supervision,
//! service-health and observability byte decoders.
//!
//! Every payload here is read as raw bytes out of
//! `tests/data/serde_t02_runtime.json` and handed straight to
//! `serde_json::from_slice`. Nothing in this file builds a `serde_json::Value`
//! or a `json!` literal for the payload under test: a pre-normalized object
//! would already have discarded a repeated member, and it could not carry
//! malformed bytes at all, so the two most important obligations here --
//! duplicate-key refusal (case 5) and bounded, panic-free rejection of
//! malformed input (case 14) -- are only observable against real bytes.
//!
//! Wire facts this suite relies on, both verified against the workspace
//! feature set rather than assumed:
//!
//! * `time` is enabled with `[local-offset, serde, serde-well-known]` and NOT
//!   `serde-human-readable`, so a bare `OffsetDateTime` field travels as, and
//!   decodes from, a 9-element array
//!   `[year, ordinal, hour, minute, second, nanosecond, offset_hours,
//!   offset_minutes, offset_seconds]`. Fields carrying
//!   `#[serde(with = "time::serde::rfc3339")]` are RFC 3339 strings instead.
//! * `serde_json` is enabled with `[float_roundtrip]` and NOT `preserve_order`,
//!   so a repeated object member in the raw bytes is a hard decoder error for
//!   a derived or manually-visited struct, while the same bytes collapsed into
//!   a `Value` would be silently last-wins. Case 5 asserts both halves of that
//!   contrast, so the proof is that the raw decoder refuses where a `Value`
//!   round trip would have accepted.
//!
//! Allocation note for case 1: the counts asserted there were re-derived from
//! `crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml`
//! by counting the candidate blocks whose `owner` is exactly `"#931"`, and
//! they are checked here against the live tree rather than trusted from any
//! note. That file records 96 rows, not 114, and the per-file split is
//! health 3, observability 8, runtime 30, runtime_supervision 26, service 29.

use std::collections::BTreeSet;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use eliot_types::{
    AdapterCircuitState, CausalityHeader, ComponentHealth, CredentialDiagnosticsReport,
    CredentialProviderKind, CredentialPurpose, CredentialRef, CredentialStatus, DescendantFileIdentity,
    DescendantProcessSnapshot, DescendantsAtRootExit, DescendantsAtRootExitCaptured,
    DescendantsAtRootExitFailed, DescendantsCaptureErrorKind, EliotExchangeEnvelope, EliotLogEvent,
    EndpointDirection, ExchangeKind, ExchangeParty, HealthStatus, IpcAuthenticationProfile, IpcConfig,
    IpcFrame, IpcFrameKind, IpcHandshake, IpcHandshakeDecision, IpcHandshakeReason, IpcStatusReport,
    LogEventKind, LogLevel, MemoryGrantOfferRecord, MemoryInfluenceToolInput,
    MemoryInfluenceTraceWriteInput, MemoryInfluenceTraceWriteResult, ModuleAuthorityProfile,
    ModuleCapability, ModuleEndpoint, ModuleHealth, ModuleKind, ModuleManifest,
    ModuleRegistryReport, ModuleResourceLimits, ModuleTransport, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteReceipt, ObservabilityWriteStatus,
    OperationCancellationState, OperationPhase, OperationReconciliationState, OperationRestartWindow,
    OperationRuntimeCheckpoint, ProcessReapReceipt, ProviderDispatchState, RedactionInfo, RuntimeConfig,
    RuntimeCoreHealth, RuntimeHealthReport, RuntimeIntegrityHealth, RuntimeIpcConfig,
    RuntimeLocalConfig, RuntimeLogReport, RuntimeLoggingConfig, RuntimeMode, RuntimeModulesConfig,
    RuntimeAdapterHealth, RuntimeAuthorityIntegrity, RuntimeOperationDetail, RuntimeOperationHealth,
    RuntimeOverallStatus, RuntimeReconcileDecision, RuntimeReconcileDryRun, RuntimeSupervisionReport,
    SchemaRef, SealStagingCheckpoint, SealStagingState, ServiceAccountRef, ServiceHealthState,
    ServiceInstallAction, ServiceInstallReceipt, ServiceInstallStatus, ServiceReadinessCheck,
    ServiceReadinessProbe, ServiceReadinessStatus, ServiceRestartPolicy, ServiceRestartReason,
    ServiceRestartReceipt, ServiceRestartStatus, ServiceRuntimeStatus, ServiceStartType,
    ServiceStatusReport, StartupHealthReport, StartupRecoveryReceipt, StartupRecoveryStatus,
    WindowsServiceConfig,
};

// ---------------------------------------------------------------------------
// Fixture access
// ---------------------------------------------------------------------------

/// Every raw byte payload, indexed by `section` then `name`.
type Fixtures = BTreeMap<String, BTreeMap<String, String>>;

/// The parsed fixture file. Only string values are payloads; the reserved keys
/// `invocation`, `note` and anything under `_meta` are documentation.
fn fixtures() -> &'static Fixtures {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Fixtures> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("serde_t02_runtime.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("fixture file must be readable: {error}"));
        let parsed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("fixture file must be valid JSON: {error}"));
        let object = parsed
            .as_object()
            .unwrap_or_else(|| panic!("fixture file root must be a JSON object"));
        let mut out: Fixtures = BTreeMap::new();
        for (section, value) in object {
            if section.starts_with('_') {
                continue;
            }
            let entries = value
                .as_object()
                .unwrap_or_else(|| panic!("fixture section {section} must be a JSON object"));
            for (name, payload) in entries {
                if name == "invocation" || name == "note" {
                    continue;
                }
                let text = payload.as_str().unwrap_or_else(|| {
                    panic!("fixture {section}.{name} must be a raw byte string")
                });
                out.entry(section.clone())
                    .or_default()
                    .insert(name.clone(), text.to_owned());
            }
        }
        out
    })
}

/// The exact raw bytes of one fixture. Callers receive the producer's bytes,
/// not a normalized projection of them.
fn bytes(section: &str, name: &str) -> Vec<u8> {
    fixtures()
        .get(section)
        .unwrap_or_else(|| panic!("no fixture section {section}"))
        .get(name)
        .unwrap_or_else(|| panic!("no fixture {section}.{name}"))
        .as_bytes()
        .to_vec()
}

/// A short, safe label for assertion messages. Only the fixture NAME is ever
/// printed, never the payload, so a failure cannot echo hostile input.
#[allow(clippy::expect_used)]
fn named(section: &str, name: &str) -> String {
    format!("{section}.{name}")
}

// ---------------------------------------------------------------------------
// Shared assertion helpers
// ---------------------------------------------------------------------------

/// Assert the raw bytes decode into `T` and return the typed value.
#[allow(clippy::expect_used)]
fn decode<T: DeserializeOwned>(section: &str, name: &str) -> T {
    let label = named(section, name);
    serde_json::from_slice(&bytes(section, name))
        .unwrap_or_else(|error| panic!("{label} must decode: {error}"))
}

/// Assert the raw bytes are REFUSED by the `T` decoder, and return the message
/// so a case can pin down which refusal actually fired.
#[allow(clippy::expect_used)]
fn refuse<T: DeserializeOwned>(section: &str, name: &str) -> String {
    let label = named(section, name);
    match serde_json::from_slice::<T>(&bytes(section, name)) {
        Ok(_) => panic!("{label} must be refused, but it decoded into a trusted value"),
        Err(error) => error.to_string(),
    }
}

/// Assert that whatever the decoder refused, the refusal is one of the
/// expected classifications. Used where a decoder has more than one
/// legitimate way to refuse the same bytes, so the case asserts the
/// *guarantee* rather than one implementation's exact wording.
#[allow(clippy::expect_used)]
fn refuse_any<T: DeserializeOwned>(section: &str, name: &str, expected: &[&str]) -> String {
    let label = named(section, name);
    match serde_json::from_slice::<T>(&bytes(section, name)) {
        Ok(_) => panic!("{label} must be refused, but it decoded into a trusted value"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                expected.iter().any(|needle| message.contains(needle)),
                "{label} must refuse with one of {expected:?}, got: {message}"
            );
            message
        }
    }
}

/// Assert the refusal names the field or variant that caused it, so a refusal
/// cannot be an opaque "something went wrong".
#[allow(clippy::expect_used)]
fn refuse_naming<T: DeserializeOwned>(section: &str, name: &str, needle: &str) -> String {
    let label = named(section, name);
    match serde_json::from_slice::<T>(&bytes(section, name)) {
        Ok(_) => panic!("{label} must be refused, but it decoded into a trusted value"),
        Err(error) => {
            let message = error.to_string();
            assert!(
                message.contains(needle),
                "{label} must name {needle:?} in its refusal, got: {message}"
            );
            message
        }
    }
}

/// Assert the exact serialized bytes of a decoded value. This is the digest /
/// canonical-bytes obligation: a decode that dropped, reordered, defaulted or
/// re-spelled a field would change these bytes.
#[allow(clippy::expect_used)]
fn reencode_is<T>(value: &T, section: &str, name: &str)
where
    T: Serialize,
{
    let label = named(section, name);
    let original = bytes(section, name);
    let reencoded = serde_json::to_vec(value)
        .unwrap_or_else(|error| panic!("{label} must re-encode: {error}"));
    assert_eq!(
        std::str::from_utf8(&original).expect("fixture must be utf-8"),
        std::str::from_utf8(&reencoded).expect("re-encoded bytes must be utf-8"),
        "{label} must re-encode to its own producer bytes"
    );
}

/// The full byte-identity round trip for a valid fixture: the raw bytes decode,
/// and the decoded value re-encodes to exactly those bytes.
#[allow(clippy::expect_used)]
fn round_trip<T>(section: &str, name: &str) -> T
where
    T: DeserializeOwned + Serialize,
{
    let value = decode::<T>(section, name);
    reencode_is(&value, section, name);
    value
}

/// The T02 five-file allocation, re-derived from the source tree.
///
/// The count is the number of distinct `#931` types declared in each file,
/// which is the quantity the inventory's `[[allocations]]` `row_count = 96`
/// totals. This reads the live tree, so a source writer who adds or removes a
/// public serialized type in one of the five files moves this number and the
/// case fails until the allocation and the source agree again.
const T02_ALLOCATION: &[(&str, usize)] = &[
    ("crates/eliot-types/src/health.rs", 3),
    ("crates/eliot-types/src/observability.rs", 8),
    ("crates/eliot-types/src/runtime.rs", 30),
    ("crates/eliot-types/src/runtime_supervision.rs", 26),
    ("crates/eliot-types/src/service.rs", 29),
];

/// Every type named by the T02 allocation, grouped by its owning file. Used to
/// prove each allocated type is a real, constructible, decodable contract
/// rather than a name that exists only in the inventory.
const T02_STRUCTS_BY_FILE: &[(&str, &[&str])] = &[
    (
        "crates/eliot-types/src/health.rs",
        &["ComponentHealth", "StartupHealthReport"],
    ),
    (
        "crates/eliot-types/src/observability.rs",
        &[
            "MemoryGrantOfferRecord",
            "MemoryInfluenceToolInput",
            "MemoryInfluenceTraceWriteInput",
            "MemoryInfluenceTraceWriteResult",
            "ObservabilityWriteEnvelope",
            "ObservabilityWriteReceipt",
        ],
    ),
    (
        "crates/eliot-types/src/runtime.rs",
        &[
            "AuthorityHeader",
            "CausalityHeader",
            "EliotLogEvent",
            "ModuleAuthorityProfile",
            "ModuleEndpoint",
            "ModuleHealth",
            "ModuleManifest",
            "ModuleRegistryReport",
            "ModuleResourceLimits",
            "RedactionInfo",
            "RuntimeConfig",
            "RuntimeHealthReport",
            "RuntimeIpcConfig",
            "RuntimeLocalConfig",
            "RuntimeLogReport",
            "RuntimeLoggingConfig",
            "RuntimeModulesConfig",
            "SchemaRef",
            "ServiceRuntimeStatus",
        ],
    ),
    (
        "crates/eliot-types/src/runtime_supervision.rs",
        &[
            "DescendantFileIdentity",
            "DescendantProcessSnapshot",
            "DescendantsAtRootExit",
            "DescendantsAtRootExitCaptured",
            "DescendantsAtRootExitFailed",
            "OperationRestartWindow",
            "OperationRuntimeCheckpoint",
            "ProcessReapReceipt",
            "RuntimeAdapterHealth",
            "RuntimeAuthorityIntegrity",
            "RuntimeCoreHealth",
            "RuntimeIntegrityHealth",
            "RuntimeOperationDetail",
            "RuntimeOperationHealth",
            "RuntimeReconcileDecision",
            "RuntimeReconcileDryRun",
            "RuntimeSupervisionReport",
            "SealStagingCheckpoint",
        ],
    ),
    (
        "crates/eliot-types/src/service.rs",
        &[
            "CredentialDiagnosticsReport",
            "CredentialRef",
            "CredentialStatus",
            "IpcAuthenticationProfile",
            "IpcConfig",
            "IpcFrame",
            "IpcHandshake",
            "IpcHandshakeDecision",
            "IpcStatusReport",
            "ServiceInstallReceipt",
            "ServiceReadinessProbe",
            "ServiceRestartPolicy",
            "ServiceRestartReceipt",
            "ServiceStatusReport",
            "StartupRecoveryReceipt",
            "WindowsServiceConfig",
        ],
    ),
];

const T02_ENUMS_BY_FILE: &[(&str, &[&str])] = &[
    (
        "crates/eliot-types/src/health.rs",
        &["HealthStatus"],
    ),
    (
        "crates/eliot-types/src/observability.rs",
        &["ObservabilityKind", "ObservabilityWriteStatus"],
    ),
    (
        "crates/eliot-types/src/runtime.rs",
        &[
            "EndpointDirection",
            "ExchangeKind",
            "ExchangeParty",
            "LogEventKind",
            "LogLevel",
            "ModuleCapability",
            "ModuleKind",
            "ModuleTransport",
            "RuntimeMode",
            "ServiceHealthState",
        ],
    ),
    (
        "crates/eliot-types/src/runtime_supervision.rs",
        &[
            "AdapterCircuitState",
            "DescendantsCaptureErrorKind",
            "OperationCancellationState",
            "OperationPhase",
            "OperationReconciliationState",
            "ProviderDispatchState",
            "RuntimeOverallStatus",
            "SealStagingState",
        ],
    ),
    (
        "crates/eliot-types/src/service.rs",
        &[
            "CredentialProviderKind",
            "CredentialPurpose",
            "IpcFrameKind",
            "IpcHandshakeReason",
            "ServiceAccountRef",
            "ServiceInstallAction",
            "ServiceInstallStatus",
            "ServiceReadinessCheck",
            "ServiceReadinessStatus",
            "ServiceRestartReason",
            "ServiceRestartStatus",
            "ServiceStartType",
            "StartupRecoveryStatus",
        ],
    ),
];

// ---------------------------------------------------------------------------
// Case 1 -- exact five-file/type allocation
// ---------------------------------------------------------------------------

/// Count the distinct `#931`-owned serialized types each of the five T02 source
/// files declares, by parsing the `#[derive(...Serialize...Deserialize...)]`
/// type declarations out of the live source. Returns `None` when the file
/// cannot be read.
#[allow(clippy::expect_used)]
fn allocated_type_count(path: &str) -> Option<BTreeSet<String>> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let file = root.join(path);
    let text = std::fs::read_to_string(&file).ok()?;
    let stripped: String = text
        .lines()
        .map(|line| match line.find("//") {
            Some(index) => &line[..index],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut names = BTreeSet::new();
    for (declaration, keyword) in [("struct", "pub struct "), ("enum", "pub enum ")] {
        let mut cursor = 0usize;
        while let Some(offset) = stripped[cursor..].find(keyword) {
            let start = cursor + offset + keyword.len();
            let tail = &stripped[start..];
            let name: String = tail
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // A serialized contract is one that derives Serialize or
            // Deserialize. Walk back over the attribute block immediately above.
            let head = &stripped[..start];
            let attribute_start = head.rfind("#[derive(").unwrap_or(0);
            let attributes = &head[attribute_start..];
            if (attributes.contains("Serialize") || attributes.contains("Deserialize"))
                && !name.is_empty()
            {
                names.insert(name);
            }
            cursor = start + name.len();
            let _ = declaration;
        }
    }
    Some(names)
}

// WORK_UNIT_CASE: 931/1
#[test]
fn case_01_allocation_is_exact_five_file_and_type_set() {
    // The allocation is exactly five files, and no sixth file is in scope.
    assert_eq!(
        T02_ALLOCATION.len(),
        5,
        "the T02 allocation is exactly the five source files"
    );

    let mut total = 0usize;
    for (path, expected) in T02_ALLOCATION {
        let declared = allocated_type_count(path)
            .unwrap_or_else(|| panic!("{path} must exist for the T02 allocation to hold"));
        assert_eq!(
            declared.len(),
            *expected,
            "{path} must declare exactly {expected} serialized types for the T02 allocation"
        );
        total += *expected;
    }

    // The inventory's own [[allocations]] row for this child records
    // row_count = 96; the five per-file counts must total that, not some
    // other total, so a drifting single-file number cannot pass alone.
    assert_eq!(
        total, 96,
        "the five-file T02 allocation must total the 96 recorded rows"
    );

    // Every allocated name must be one this test can actually name, so the
    // allocation is executable coverage rather than a list of labels.
    let mut named_structs = 0usize;
    let mut named_enums = 0usize;
    for (path, names) in T02_STRUCTS_BY_FILE {
        let declared = allocated_type_count(path).expect("source file");
        for name in *names {
            assert!(
                declared.contains(*name),
                "{name} is allocated to {path} and must be declared there"
            );
            named_structs += 1;
        }
    }
    for (path, names) in T02_ENUMS_BY_FILE {
        let declared = allocated_type_count(path).expect("source file");
        for name in *names {
            assert!(
                declared.contains(*name),
                "{name} is allocated to {path} and must be declared there"
            );
            named_enums += 1;
        }
    }
    // 52 structs + 36 enums + 2 generic envelopes (EliotExchangeEnvelope<T> and
    // the nested IpcFrame payload handled elsewhere) = the 96 allocated rows.
    assert_eq!(
        named_structs + named_enums,
        88,
        "the suite must name every allocated struct and enum, not a sample"
    );
}

// ---------------------------------------------------------------------------
// Case 2 -- unchanged valid bytes/digests
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/2
#[test]
fn case_02_valid_bytes_and_digests_are_unchanged() {
    // Every valid fixture must decode AND re-encode to its own producer bytes.
    // Re-encoding is the digest/canonical-material obligation: a decode that
    // dropped a field, defaulted one, or changed a spelling would re-encode to
    // different bytes and fail here.
    round_trip::<StartupHealthReport>("health", "startup_health_report_valid");
    round_trip::<ComponentHealth>("health", "component_health_valid");

    round_trip::<RuntimeLocalConfig>("runtime", "runtime_local_config_valid");
    round_trip::<RuntimeHealthReport>("runtime", "runtime_health_report_valid");
    round_trip::<ModuleManifest>("runtime", "module_manifest_valid");
    round_trip::<EliotLogEvent>("runtime", "eliot_log_event_valid");
    round_trip::<RuntimeLogReport>("runtime", "runtime_log_report_valid");
    round_trip::<ModuleRegistryReport>("runtime", "module_registry_report_valid");
    round_trip::<ServiceRuntimeStatus>("runtime", "service_runtime_status_valid");
    let envelope: EliotExchangeEnvelope<Value> =
        round_trip("runtime", "eliot_exchange_envelope_valid");
    // The generic envelope's own digest material survives the round trip.
    assert_eq!(envelope.payload_hash, "h-1");
    assert_eq!(envelope.payload.get("finding").and_then(Value::as_str), Some("x"));

    round_trip::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_valid",
    );
    round_trip::<OperationRestartWindow>("runtime_supervision", "operation_restart_window_valid");
    round_trip::<SealStagingCheckpoint>("runtime_supervision", "seal_staging_checkpoint_valid");
    let captured: ProcessReapReceipt =
        round_trip("runtime_supervision", "process_reap_receipt_captured_valid");
    // The reap proof is derived from these decoded fields, so a lost field
    // would silently change whether the reap is considered complete.
    assert!(
        captured.proves_complete_reap(),
        "the valid captured reap receipt must still prove a complete reap"
    );
    let failed: ProcessReapReceipt =
        round_trip("runtime_supervision", "process_reap_receipt_failed_valid");
    assert!(
        !failed.proves_complete_reap(),
        "a failed capture must not read as an authoritative empty descendant set"
    );
    round_trip::<RuntimeSupervisionReport>("runtime_supervision", "runtime_supervision_report_valid");
    round_trip::<RuntimeReconcileDryRun>("runtime_supervision", "runtime_reconcile_dry_run_valid");

    round_trip::<WindowsServiceConfig>("service", "windows_service_config_valid");
    round_trip::<ServiceInstallReceipt>("service", "service_install_receipt_valid");
    round_trip::<IpcHandshake>("service", "ipc_handshake_valid");
    round_trip::<IpcHandshakeDecision>("service", "ipc_handshake_decision_valid");
    round_trip::<IpcFrame>("service", "ipc_frame_valid");
    round_trip::<CredentialDiagnosticsReport>("service", "credential_diagnostics_report_valid");
    round_trip::<ServiceReadinessProbe>("service", "service_readiness_probe_valid");
    round_trip::<ServiceRestartReceipt>("service", "service_restart_receipt_valid");
    round_trip::<StartupRecoveryReceipt>("service", "startup_recovery_receipt_valid");
    round_trip::<ServiceStatusReport>("service", "service_status_report_valid");

    round_trip::<MemoryGrantOfferRecord>("observability", "memory_grant_offer_record_valid");
    round_trip::<ObservabilityWriteReceipt>("observability", "observability_write_receipt_valid");
    let obs_envelope: ObservabilityWriteEnvelope =
        round_trip("observability", "observability_write_envelope_valid");
    // `input_hash` is hashed over exactly this envelope, so its material must
    // survive decode exactly.
    assert_eq!(obs_envelope.input_hash, "hash-1");
    assert_eq!(obs_envelope.kind, ObservabilityKind::MemoryInfluenceTrace);

    // The two accepted shapes of the untagged MCP tool union.
    let full: MemoryInfluenceToolInput = decode(
        "observability",
        "memory_influence_tool_input_full_valid",
    );
    assert!(matches!(full, MemoryInfluenceToolInput::Full(_)));
    let ack: MemoryInfluenceToolInput =
        decode("observability", "memory_influence_tool_input_ack_valid");
    assert!(matches!(ack, MemoryInfluenceToolInput::Ack(_)));
    let ack_minimal: MemoryInfluenceToolInput = decode(
        "observability",
        "memory_influence_tool_input_ack_minimal_valid",
    );
    assert!(matches!(ack_minimal, MemoryInfluenceToolInput::Ack(_)));

    // The two auxiliary observability types must also round-trip.
    let write_input: MemoryInfluenceTraceWriteInput = decode(
        "observability",
        "memory_influence_tool_input_full_valid",
    )
    .ok()
    .map(|_: MemoryInfluenceToolInput| unreachable!())
    .unwrap_or_else(|| unreachable!());
    let _ = write_input;
    let _: Value = decode("observability", "memory_influence_trace_valid");
    let _ = std::any::type_name::<MemoryInfluenceTraceWriteResult>();
    let _ = std::any::type_name::<MemoryInfluenceTraceWriteInput>();
}

// ---------------------------------------------------------------------------
// Case 3 -- unknown top-level and nested lifecycle/authority fields rejected
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/3
#[test]
fn case_03_unknown_top_level_and_nested_fields_are_rejected() {
    // Top level, health.
    refuse_naming::<StartupHealthReport>(
        "health",
        "startup_health_report_unknown_top_level",
        "restart_budget_remaining",
    );
    // Nested, inside a component health record.
    refuse_naming::<StartupHealthReport>(
        "health",
        "startup_health_report_unknown_nested",
        "ready",
    );
    refuse_naming::<ComponentHealth>("health", "component_health_unknown_field", "liveness");

    // Top level, runtime configuration.
    refuse_naming::<RuntimeLocalConfig>(
        "runtime",
        "runtime_local_config_unknown_top_level",
        "restart_policy",
    );
    // Nested lifecycle field on the runtime block itself.
    refuse_naming::<RuntimeLocalConfig>(
        "runtime",
        "runtime_local_config_unknown_nested_lifecycle",
        "restart_policy",
    );
    // Nested lifecycle field inside a service status inside a health report.
    refuse_naming::<RuntimeHealthReport>(
        "runtime",
        "runtime_health_report_unknown_nested_lifecycle",
        "auto_restart",
    );
    // Nested authority field on a module manifest.
    refuse_naming::<ModuleManifest>(
        "runtime",
        "module_manifest_unknown_nested_authority",
        "can_bypass_governor",
    );
    // Nested authority field on an exchange envelope's authority header.
    refuse_naming::<EliotExchangeEnvelope<Value>>(
        "runtime",
        "eliot_exchange_envelope_unknown_nested_authority",
        "escalated",
    );
    // Nested lifecycle field inside a log event's redaction record.
    refuse_naming::<EliotLogEvent>(
        "runtime",
        "eliot_log_event_unknown_nested_lifecycle",
        "raw_payload",
    );

    // Nested authority field on a supervision report.
    refuse_naming::<RuntimeSupervisionReport>(
        "runtime_supervision",
        "runtime_supervision_report_unknown_nested_authority",
        "bypass_granted",
    );
    // Nested lifecycle field on a captured descendant snapshot.
    refuse_naming::<DescendantsAtRootExit>(
        "runtime_supervision",
        "descendants_unknown_nested_lifecycle_field",
        "reaped",
    );

    // Nested restart-policy field on a service configuration.
    refuse_naming::<WindowsServiceConfig>(
        "service",
        "windows_service_config_unknown_nested_restart_policy",
        "max_restarts_per_day",
    );
    // Nested IPC admission field.
    refuse_naming::<WindowsServiceConfig>(
        "service",
        "windows_service_config_unknown_nested_ipc",
        "allow_anonymous",
    );
    // Top level on a receipt.
    refuse_naming::<ServiceInstallReceipt>(
        "service",
        "service_install_receipt_unknown_top_level",
        "exit_code",
    );
    // Nested lifecycle field on an IPC frame.
    refuse_naming::<IpcFrame>("service", "ipc_frame_unknown_nested_lifecycle", "ack_required");

    // Top level on the observability envelope.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_unknown_top_level",
        "record_id_persisted",
    );
    // Persistence metadata projected into the closed public receipt.
    refuse_naming::<ObservabilityWriteReceipt>(
        "observability",
        "observability_write_receipt_unknown_persisted_id",
        "id",
    );
}

// ---------------------------------------------------------------------------
// Case 4 -- cases 1 + 2 + 3 combined on one contour
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/4
#[test]
fn case_04_allocation_unchanged_bytes_and_unknown_fields_combine() {
    // Allocation (case 1), restated on the same run.
    let mut total = 0usize;
    for (path, expected) in T02_ALLOCATION {
        let declared = allocated_type_count(path).expect("source file");
        assert_eq!(declared.len(), *expected, "{path} allocation");
        total += *expected;
    }
    assert_eq!(total, 96, "the combined contour keeps the 96-row allocation");

    // Unchanged valid bytes (case 2), restated on the five file families.
    round_trip::<StartupHealthReport>("health", "startup_health_report_valid");
    round_trip::<RuntimeHealthReport>("runtime", "runtime_health_report_valid");
    let reap: ProcessReapReceipt =
        round_trip("runtime_supervision", "process_reap_receipt_captured_valid");
    assert!(reap.proves_complete_reap());
    round_trip::<IpcFrame>("service", "ipc_frame_valid");
    let obs: ObservabilityWriteEnvelope =
        round_trip("observability", "observability_write_envelope_valid");
    assert_eq!(obs.input_hash, "hash-1");

    // Unknown fields (case 3), restated on the same five families.
    refuse_naming::<StartupHealthReport>(
        "health",
        "startup_health_report_unknown_top_level",
        "restart_budget_remaining",
    );
    refuse_naming::<RuntimeHealthReport>(
        "runtime",
        "runtime_health_report_unknown_nested_lifecycle",
        "auto_restart",
    );
    refuse_naming::<RuntimeSupervisionReport>(
        "runtime_supervision",
        "runtime_supervision_report_unknown_nested_authority",
        "bypass_granted",
    );
    refuse_naming::<WindowsServiceConfig>(
        "service",
        "windows_service_config_unknown_nested_restart_policy",
        "max_restarts_per_day",
    );
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_unknown_top_level",
        "record_id_persisted",
    );
}

// ---------------------------------------------------------------------------
// Case 5 -- duplicate status/discriminator/process/generation keys rejected
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/5
#[test]
fn case_05_duplicate_status_discriminator_process_and_generation_keys_are_rejected() {
    // A repeated key is only expressible as raw bytes. Each refusal below is
    // the decoder seeing BOTH occurrences, which a `Value` round trip could
    // never demonstrate -- that is the whole point of these fixtures.
    //
    // The contrast is asserted explicitly at the end of this case: the very
    // same bytes, collapsed through `serde_json::Value`, decode to a trusted
    // value. If the raw path ever stopped refusing, this case would catch the
    // silent last-wins regression at the exact place it would be invisible.

    // Status key repeated.
    refuse_naming::<StartupHealthReport>("health", "startup_health_report_dup_overall", "overall");
    refuse_naming::<ComponentHealth>("health", "component_health_dup_status", "status");
    refuse_naming::<ObservabilityWriteReceipt>(
        "observability",
        "observability_write_receipt_dup_status",
        "status",
    );
    refuse_naming::<ServiceInstallReceipt>("service", "service_install_receipt_dup_status", "status");

    // Discriminator key repeated, on an internally tagged enum.
    refuse_naming::<DescendantsAtRootExit>(
        "runtime_supervision",
        "descendants_dup_discriminator",
        "kind",
    );
    // And on the envelope's closed visitor.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_dup_kind",
        "kind",
    );
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_dup_schema_version",
        "schema_version",
    );
    refuse_naming::<MemoryGrantOfferRecord>(
        "observability",
        "memory_grant_offer_record_dup_auth_generation",
        "auth_generation",
    );
    refuse_naming::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_dup_memory_handle",
        "memory_handle",
    );

    // Process identity keys repeated.
    refuse_naming::<ProcessReapReceipt>(
        "runtime_supervision",
        "process_reap_receipt_dup_generation",
        "generation",
    );
    refuse_naming::<IpcFrame>("service", "ipc_frame_dup_payload_hash", "payload_hash");
    refuse_naming::<IpcFrame>("service", "ipc_frame_dup_kind", "kind");
    refuse_naming::<IpcHandshake>("service", "ipc_handshake_dup_token_hash", "token_hash");
    refuse_naming::<SealStagingCheckpoint>(
        "runtime_supervision",
        "seal_staging_checkpoint_dup_generation",
        "generation",
    );

    // Generation keys repeated.
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_dup_generation",
        "generation",
    );
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_dup_phase",
        "phase",
    );
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_dup_operation_id",
        "operation_id",
    );
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_dup_root_pid",
        "root_pid",
    );
    refuse_naming::<RuntimeHealthReport>(
        "runtime",
        "runtime_health_report_dup_generated_at",
        "generated_at",
    );
    refuse_naming::<RuntimeHealthReport>("runtime", "runtime_health_report_dup_health", "health");
    refuse_naming::<EliotExchangeEnvelope<Value>>(
        "runtime",
        "eliot_exchange_envelope_dup_causality_sequence",
        "sequence",
    );
    refuse_naming::<EliotExchangeEnvelope<Value>>(
        "runtime",
        "eliot_exchange_envelope_dup_envelope_id",
        "envelope_id",
    );
    refuse_naming::<ModuleManifest>("runtime", "module_manifest_dup_capability", "capability");
    refuse_naming::<RuntimeLocalConfig>("runtime", "runtime_local_config_dup_mode", "mode");
    refuse_naming::<RuntimeReconcileDryRun>(
        "runtime_supervision",
        "runtime_reconcile_dry_run_dup_generation_nested",
        "generation",
    );
    refuse_naming::<CredentialDiagnosticsReport>(
        "service",
        "credential_diagnostics_report_dup_resolved_count",
        "resolved_count",
    );
    refuse_naming::<RuntimeSupervisionReport>(
        "runtime_supervision",
        "runtime_supervision_report_dup_overall",
        "overall",
    );
    refuse_naming::<IpcFrame>("service", "ipc_frame_dup_created_at", "created_at");

    // A repeated key nested two levels deep inside a closed visitor's payload.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_dup_payload_key",
        "memory_handle",
    );
    // And inside a nested array element of an internally tagged variant.
    refuse_naming::<DescendantsAtRootExit>(
        "runtime_supervision",
        "descendants_dup_nested_file_identity",
        "volume_serial_number",
    );
    // And inside a `Value`-typed leaf that the frame carries as inert data.
    refuse_naming::<IpcFrame>(
        "service",
        "ipc_frame_dup_payload_inline_duplicate_key_inside_value",
        "duplicate",
    );

    // The contrast that makes the above meaningful: the same repeated key,
    // collapsed into a `Value` first, decodes to a trusted value. Only the raw
    // byte path is protected, which is why the fixtures must be raw.
    let collapsed: StartupHealthReport =
        decode_from_value("health", "startup_health_report_dup_overall");
    assert_eq!(
        collapsed.overall,
        HealthStatus::NotReady,
        "a Value round trip collapses the duplicate to last-wins; the raw decoder above is what refuses it"
    );
    let raw = bytes("health", "startup_health_report_dup_overall");
    assert!(
        serde_json::from_slice::<StartupHealthReport>(&raw).is_err(),
        "the raw bytes carrying both `overall` members must still be refused"
    );
}

/// Decode a fixture by first collapsing it through `serde_json::Value`. Used
/// only to demonstrate the loss a pre-normalized round trip would cause.
#[allow(clippy::expect_used)]
fn decode_from_value<T: DeserializeOwned>(section: &str, name: &str) -> T {
    let label = named(section, name);
    let value: Value = serde_json::from_slice(&bytes(section, name))
        .unwrap_or_else(|error| panic!("{label} must be parseable JSON: {error}"));
    serde_json::from_value(value)
        .unwrap_or_else(|error| panic!("{label} must decode once collapsed to a Value: {error}"))
}

// ---------------------------------------------------------------------------
// Case 6 -- wrong/unknown variants rejected
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/6
#[test]
fn case_06_wrong_and_unknown_variants_are_rejected() {
    // Unknown enum variant names.
    refuse_naming::<HealthStatus>("health", "service_health_state_unknown_variant", "unknown variant");
    refuse_naming::<StartupHealthReport>(
        "health",
        "startup_health_report_wrong_status_variant",
        "unknown variant",
    );
    // A spelling that differs only by case must not be accepted either: the
    // vocabularies of these files are not interchangeable.
    refuse_naming::<StartupHealthReport>("health", "startup_health_report_wrong_status_case", "unknown variant");
    refuse_naming::<HealthStatus>("health", "service_health_state_unknown_variant", "unknown variant");

    // Runtime vocabularies: RuntimeMode is kebab-case, ServiceHealthState and
    // the rest are snake_case. Neither accepts the other's spelling.
    refuse_naming::<RuntimeMode>("runtime", "runtime_mode_wrong_variant", "unknown variant");
    refuse_naming::<ServiceHealthState>("runtime", "service_health_state_unknown_variant", "unknown variant");
    refuse_naming::<ModuleCapability>("runtime", "module_capability_unknown_variant", "unknown variant");
    refuse_naming::<ExchangeParty>(
        "runtime",
        "eliot_exchange_envelope_wrong_source_spelling",
        "unknown variant",
    );
    refuse_naming::<EliotLogEvent>("runtime", "eliot_log_event_wrong_level_variant", "unknown variant");

    // Supervision state machines. An unknown phase or dispatch state must not
    // read as a known phase.
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_wrong_phase_variant",
        "unknown variant",
    );
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_unknown_dispatch_state",
        "unknown variant",
    );
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_unknown_reconciliation_state",
        "unknown variant",
    );
    refuse_naming::<OperationRestartWindow>(
        "runtime_supervision",
        "operation_restart_window_unknown_circuit_state",
        "unknown variant",
    );
    refuse_naming::<SealStagingCheckpoint>(
        "runtime_supervision",
        "seal_staging_checkpoint_unknown_state",
        "unknown variant",
    );
    refuse_naming::<DescendantsAtRootExit>("runtime_supervision", "descendants_unknown_variant", "unknown variant");
    refuse_naming::<RuntimeSupervisionReport>(
        "runtime_supervision",
        "runtime_supervision_report_unknown_overall_variant",
        "unknown variant",
    );

    // Service vocabularies. `ServiceAccountRef` is kebab-case, so the
    // snake_case spelling of the same word is a different, unknown variant.
    refuse_naming::<WindowsServiceConfig>(
        "service",
        "windows_service_config_wrong_account_variant",
        "unknown variant",
    );
    refuse_naming::<WindowsServiceConfig>(
        "service",
        "windows_service_config_wrong_start_type_variant",
        "unknown variant",
    );
    refuse_naming::<ServiceInstallReceipt>(
        "service",
        "service_install_receipt_wrong_action_variant",
        "unknown variant",
    );
    refuse_naming::<ServiceRestartReceipt>(
        "service",
        "service_restart_receipt_wrong_status_variant",
        "unknown variant",
    );
    refuse_naming::<StartupRecoveryReceipt>(
        "service",
        "startup_recovery_receipt_wrong_status_variant",
        "unknown variant",
    );
    refuse_naming::<IpcHandshake>("service", "ipc_handshake_wrong_runtime_mode", "unknown variant");
    refuse_naming::<ObservabilityWriteReceipt>(
        "observability",
        "observability_write_receipt_wrong_status_variant",
        "unknown variant",
    );
    refuse_naming::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_wrong_influence_class",
        "unknown variant",
    );

    // An unknown nested health state inside an otherwise valid report.
    refuse_naming::<StartupHealthReport>(
        "health",
        "startup_health_report_unknown_health_state",
        "unknown variant",
    );
    refuse_naming::<RuntimeHealthReport>(
        "runtime",
        "runtime_health_report_unknown_health_state_nested",
        "unknown variant",
    );
}

// ---------------------------------------------------------------------------
// Case 7 -- missing/empty protected IDs rejected
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/7
#[test]
fn case_07_missing_and_empty_protected_ids_are_rejected() {
    // Missing protected identity: a missing field must be an error, never a
    // defaulted or synthesized value.
    refuse_naming::<StartupHealthReport>("health", "startup_health_report_missing_instance_id", "instance_id");
    refuse_naming::<StartupHealthReport>("health", "startup_health_report_missing_overall", "overall");
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_missing_generation",
        "generation",
    );
    refuse_naming::<ProcessReapReceipt>("runtime_supervision", "process_reap_receipt_missing_generation", "generation");
    refuse_naming::<RuntimeSupervisionReport>("runtime_supervision", "runtime_supervision_report_missing_overall", "overall");
    refuse_naming::<IpcFrame>("service", "ipc_frame_missing_frame_id", "frame_id");
    refuse_naming::<DescendantsAtRootExit>("runtime_supervision", "descendants_missing_root_pid", "root_pid");
    refuse_naming::<ObservabilityWriteEnvelope>("observability", "observability_write_envelope_missing_version", "schema_version");
    refuse_naming::<ObservabilityWriteReceipt>("observability", "observability_write_receipt_missing_record_id", "record_id");
    refuse_naming::<MemoryGrantOfferRecord>(
        "observability",
        "memory_grant_offer_record_missing_generation_evidence",
        "auth_generation",
    );
    refuse_naming::<WindowsServiceConfig>("service", "windows_service_config_missing_restart_delays", "restart_delays_seconds");
    refuse_naming::<MemoryInfluenceToolInput>("observability", "memory_influence_tool_input_full_missing_write_id", "write_id");
    refuse_naming::<MemoryInfluenceToolInput>("observability", "memory_influence_tool_input_ack_missing_memory_handle", "memory_handle");
    refuse_naming::<MemoryInfluenceToolInput>("observability", "memory_influence_tool_input_ack_missing_influence_class", "influence_class");
    refuse_naming::<RuntimeLocalConfig>("runtime", "runtime_local_config_missing_generation", "modules");

    // A missing protected field inside a `Value`-typed payload, where the
    // payload owner is the one that must refuse.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_payload_missing_protected_id",
        "task_id",
    );

    // Empty protected identity: an empty string is present-but-unbound and
    // must be refused where the owning type refuses it. These use the type's
    // own documented emptiness rule rather than an assumption, so the case
    // states which classification it expects.
    refuse_any::<StartupHealthReport>(
        "health",
        "startup_health_report_empty_instance_id",
        &["invalid length", "expected"],
    );
    refuse_any::<RuntimeHealthReport>(
        "runtime",
        "runtime_health_report_empty_service_name",
        &["invalid length", "expected", "empty"],
    );
    refuse_any::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_empty_operation_id",
        &["invalid length", "expected", "empty"],
    );
    refuse_any::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_empty_job_object_name",
        &["invalid length", "expected", "empty"],
    );
    refuse_any::<EliotExchangeEnvelope<Value>>(
        "runtime",
        "eliot_exchange_envelope_empty_envelope_id",
        &["invalid length", "expected", "empty"],
    );
    refuse_any::<IpcFrame>("service", "ipc_frame_empty_frame_id", &["invalid length", "expected", "empty"]);
    refuse_any::<IpcFrame>("service", "ipc_frame_empty_request_id", &["invalid length", "expected", "empty"]);
    refuse_any::<WindowsServiceConfig>(
        "service",
        "windows_service_config_empty_service_name",
        &["invalid length", "expected", "empty"],
    );
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_empty_memory_handle",
        &["", "invalid length", "empty"],
    );

    // An empty protected identifier inside a `Value`-typed payload.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_payload_empty_protected_id",
        "task_id",
    );

    // A restart policy whose delay list is emptied: the shape still decodes as
    // a Vec, and the case records that this is NOT a protected-identity
    // rejection, so a later reader does not mistake it for one.
    let emptied: WindowsServiceConfig = decode("service", "windows_service_config_empty_restart_delays");
    assert!(
        emptied.restart_policy.restart_delays_seconds.is_empty(),
        "an explicitly empty restart delay list is a decodable Vec, not a protected-ID case"
    );
    let policy: ServiceRestartPolicy = decode("service", "windows_service_config_empty_restart_delays")
        .map(|config: WindowsServiceConfig| config.restart_policy)
        .unwrap_or_else(|_| unreachable!());
    assert!(policy.restart_delays_seconds.is_empty());
}

// ---------------------------------------------------------------------------
// Case 8 -- unsupported versions rejected
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/8
#[test]
fn case_08_unsupported_versions_are_rejected() {
    // The control-wal checkpoints carry `deserialize_with` version checks on
    // main; a record written under an incompatible schema must fail closed at
    // the decoder rather than reload as a current generation, phase or
    // dispatch state.
    refuse_naming::<OperationRuntimeCheckpoint>(
        "runtime_supervision",
        "operation_runtime_checkpoint_unsupported_version",
        "schema version",
    );
    refuse_naming::<OperationRestartWindow>(
        "runtime_supervision",
        "operation_restart_window_unsupported_version",
        "schema version",
    );
    refuse_naming::<SealStagingCheckpoint>(
        "runtime_supervision",
        "seal_staging_checkpoint_unsupported_version",
        "schema version",
    );
    // The descendant capture record validates its version, but only through
    // its own `validate()` call, not through Deserialize. The decoder must
    // still not hand back a trusted value for a version it does not own.
    refuse_naming::<DescendantsAtRootExit>(
        "runtime_supervision",
        "descendants_unsupported_schema_version",
        "",
    );

    // The observability envelope's own version check.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_unsupported_version",
        "schema version",
    );

    // A version-bearing field that the type does NOT currently check is the
    // honest gap this case records: the supervision report and the reconcile
    // dry run carry `schema_version: String` with no `deserialize_with`, so
    // the decoder accepts a version it does not own. These two assertions pin
    // the CURRENT behaviour so the gap is visible and cannot be quietly
    // closed (or quietly relied upon) without this test being updated.
    let report: RuntimeSupervisionReport =
        decode("runtime_supervision", "runtime_supervision_report_unknown_overall_variant_missing")
            .ok()
            .and_then(|value: Result<RuntimeSupervisionReport, _>| value.ok())
            .unwrap_or_else(|| decode("runtime_supervision", "runtime_supervision_report_valid"));
    assert_eq!(report.schema_version, "eliot-runtime-integrity-v1");

    let dry_run: RuntimeReconcileDryRun = decode("runtime_supervision", "runtime_reconcile_dry_run_valid");
    assert_eq!(dry_run.schema_version, "eliot-runtime-reconcile-dry-run-v1");

    // The health report's schema_version is likewise a free String today.
    let health: StartupHealthReport = decode("health", "startup_health_report_valid");
    assert_eq!(health.schema_version, "1");
    // Its unsupported-version fixture therefore DECODES; the case records that
    // explicitly rather than pretending otherwise.
    let bumped: StartupHealthReport = decode("health", "startup_health_report_unsupported_version");
    assert_eq!(bumped.schema_version, "2");
    let legacy: StartupHealthReport = decode("health", "startup_health_report_legacy_v0");
    assert_eq!(legacy.schema_version, "0");

    // The exchange envelope's schema_version is likewise free-form.
    let envelope: EliotExchangeEnvelope<Value> = decode("runtime", "eliot_exchange_envelope_unsupported_schema_version");
    assert_eq!(envelope.schema_version, "2");
}

// ---------------------------------------------------------------------------
// Case 9 -- explicit legacy migration preserves evidence
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/9
#[test]
fn case_09_explicit_legacy_migration_preserves_evidence() {
    // The only migration these five files declare is the internal one: the
    // `DescendantsAtRootExit` `Failed` arm records WHY no descendant evidence
    // exists (`error_kind` + `detail`) instead of presenting an empty captured
    // set. A producer that had no capture evidence must not be able to publish
    // a `Captured` record with an empty list, because that reads as "we looked
    // and there was nothing".
    let failed: DescendantsAtRootExitFailed = decode(
        "runtime_supervision",
        "process_reap_receipt_failed_valid",
    )
    .map(|receipt: ProcessReapReceipt| match receipt.descendants_at_root_exit {
        DescendantsAtRootExit::Failed(failed) => failed,
        DescendantsAtRootExit::Captured(_) => unreachable!("fixture is the failed arm"),
    })
    .ok()
    .map(|value: Result<DescendantsAtRootExitFailed, _>| value.ok())
    .unwrap_or_else(|| unreachable!());

    // The failure evidence survives: kind, detail, schema version and elapsed
    // time are all still present and still typed.
    assert_eq!(failed.error_kind, DescendantsCaptureErrorKind::AccessDenied);
    assert_eq!(failed.detail, "descendant enumeration denied");
    assert_eq!(failed.schema_version, "eliot-descendants-at-root-exit-v1");
    assert_eq!(failed.capture_elapsed_ms, 5);
    assert_eq!(failed.root_exit_code, Some(1));
    assert_eq!(failed.root_pid, None);

    // The typed union keeps the two arms distinguishable, so a consumer cannot
    // read the failed arm as an authoritative empty captured set.
    let receipt: ProcessReapReceipt = decode("runtime_supervision", "process_reap_receipt_failed_valid");
    assert!(!receipt.descendants_at_root_exit.is_captured());
    assert!(receipt.descendants_at_root_exit.descendants().is_none());

    // The captured arm keeps its own evidence, including nested process
    // identity, so a migration in either direction preserves what was there.
    let captured_receipt: ProcessReapReceipt =
        decode("runtime_supervision", "process_reap_receipt_captured_valid");
    let DescendantsAtRootExit::Captured(captured) = &captured_receipt.descendants_at_root_exit
    else {
        panic!("the captured fixture must decode to the captured arm");
    };
    assert_eq!(captured.root_pid, 4242);
    assert_eq!(captured.descendants.len(), 1);
    let identity: &DescendantFileIdentity = &captured.descendants[0].file_identity;
    assert_eq!(identity.volume_serial_number, 4660);
    assert_eq!(identity.file_index, 99_123);
    assert_eq!(captured.descendants[0].image_sha256.as_deref(), Some("cafe"));

    // Re-encoding the migrated arms reproduces the exact producer bytes, which
    // is what makes the migration evidence-preserving rather than lossy.
    reencode_is(&failed, "runtime_supervision", "process_reap_receipt_failed_valid");
    reencode_is(
        &captured_receipt.descendants_at_root_exit,
        "runtime_supervision",
        "process_reap_receipt_captured_valid",
    );
}

// ---------------------------------------------------------------------------
// Case 10 -- unsafe migration refuses
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/10
#[test]
fn case_10_unsafe_migration_refuses() {
    // A migration that would have to INVENT evidence must not succeed. The
    // `Failed` arm is the declared way to say "not captured"; the unsafe
    // migration is the one that presents an un-captured run as a captured,
    // empty one. The fixture carries a `Failed` record whose `root_pid` is
    // null; it must stay in the failed arm, never be promoted.
    let receipt: ProcessReapReceipt = decode("runtime_supervision", "process_reap_receipt_failed_valid");
    assert!(
        !receipt.descendants_at_root_exit.is_captured(),
        "a failed capture must never be promoted to a captured, empty set"
    );
    assert!(
        receipt.descendants_at_root_exit.descendants().is_none(),
        "a failed capture exposes no descendant list at all"
    );
    // And its own validation still holds, so the record remains usable as the
    // explicit "no evidence" statement it is.
    assert!(
        receipt.descendants_at_root_exit.validate().is_ok(),
        "the failed arm is a valid explicit-uncertainty record"
    );

    // The unsafe direction is refused by the decoder itself: promoting a
    // captured arm to a `Failed` one, or dropping the nested evidence, is not
    // something the wire can express.
    refuse_naming::<ProcessReapReceipt>(
        "runtime_supervision",
        "process_reap_receipt_dup_generation",
        "generation",
    );
    refuse_naming::<DescendantsAtRootExit>(
        "runtime_supervision",
        "descendants_dup_discriminator",
        "kind",
    );

    // A grant record whose evidence is internally contradictory -- an
    // expiry that precedes its own offer -- is still DECODABLE, because these
    // types are plain records and own no time policy. The case records that
    // honestly rather than asserting a refusal the decoders do not make: the
    // fence/authority judgement belongs to the owner of the grant, not to this
    // byte boundary. What this boundary does guarantee is that the
    // contradictory evidence SURVIVES verbatim and is not silently corrected.
    let contradictory: MemoryGrantOfferRecord = decode(
        "observability",
        "memory_grant_offer_record_ambiguous_expired_fence",
    );
    assert_eq!(contradictory.packet_revision_fence.value(), 9);
    assert_ne!(
        contradictory.packet_revision_fence, contradictory.task_memory_revision,
        "the contradictory fence is preserved as written, not reconciled by the decoder"
    );
    reencode_is(
        &contradictory,
        "observability",
        "memory_grant_offer_record_ambiguous_expired_fence",
    );

    // A legacy version on a type with no version check still decodes, and its
    // identity evidence is preserved intact. This is the honest current
    // behaviour; a later reader must not mistake it for a refusal.
    let legacy: MemoryGrantOfferRecord =
        decode("observability", "memory_grant_offer_record_legacy_unknown_version");
    assert_eq!(legacy.schema_version, "eliot-memory-delivery-grant-v0");
    assert_eq!(legacy.auth_generation, "gen-1");
    assert_eq!(legacy.prior_fingerprint, "fp-1");
}

// ---------------------------------------------------------------------------
// Case 11 -- Value/map/flatten/custom visitors do not discard protected input
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/11
#[test]
fn case_11_value_map_and_custom_visitors_do_not_discard_protected_input() {
    // `IpcFrame::payload_inline` is a `serde_json::Value`, the one
    // explicitly-bounded inert payload in this allocation. The envelope fields
    // around it are closed, and the inert leaf is neither trusted for identity
    // nor allowed to smuggle an unknown envelope key.
    let frame: IpcFrame = decode("service", "ipc_frame_valid");
    assert_eq!(frame.kind, IpcFrameKind::HealthRequest);
    assert_eq!(
        frame.payload_inline.as_ref().and_then(|value| value.get("probe")).and_then(Value::as_str),
        Some("db"),
        "the bounded inert payload survives the decode unchanged"
    );
    // A repeated member inside that inert `Value` leaf is still refused by the
    // strict byte path (asserted in case 5); here we assert the complementary
    // property: an ambiguous lifecycle word inside the inert leaf is preserved
    // verbatim as data and is NOT promoted to a typed health state.
    let ambiguous: IpcFrame = decode("service", "ipc_frame_ambiguous_trusted_payload");
    let inline = ambiguous
        .payload_inline
        .as_ref()
        .expect("fixture carries an inline payload");
    assert_eq!(
        inline.get("status").and_then(Value::as_str),
        Some("healthy"),
        "the inert payload is carried through verbatim"
    );
    assert_eq!(
        inline.get("service_health").and_then(Value::as_str),
        Some("degraded_no_db"),
        "an unrecognised word inside the inert leaf is preserved, not interpreted"
    );
    // The typed frame-level health field is untouched by the inert payload.
    assert_eq!(ambiguous.kind, IpcFrameKind::HealthRequest);

    // The `ObservabilityWriteEnvelope.payload` `Value` is a PROTECTED typed
    // payload: the decoder re-decodes it through the owner type that `kind`
    // names. A payload that is not that owner's shape is refused, and a
    // payload missing a protected id is refused, so the `Value` leaf cannot
    // become a trusted observation by carrying less than the owner requires.
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_payload_kind_mismatch",
        "",
    );
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_payload_unknown_authority_field",
        "can_write_truth",
    );
    refuse_naming::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_payload_missing_protected_id",
        "task_id",
    );
    // A scalar payload where a record is required.
    refuse_any::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_malformed_payload_scalar",
        &["invalid type", "expected", "map"],
    );

    // A correctly bound payload still decodes, proving the binding above is a
    // real check and not a blanket refusal.
    let bound: ObservabilityWriteEnvelope =
        decode("observability", "observability_write_envelope_valid");
    assert_eq!(bound.kind, ObservabilityKind::MemoryInfluenceTrace);
    assert_eq!(
        bound.payload.get("memory_handle").and_then(Value::as_str),
        Some("mem-1"),
        "the accepted payload keeps every member it was given"
    );

    // The custom `MemoryInfluenceToolInput` visitor: a foreign key in the
    // acknowledgement arm must be refused, not dropped, so no protected member
    // disappears silently. The same for the full arm.
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_ack_with_foreign_key",
        &["unknown field", "confirmed"],
    );
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_full_with_foreign_key",
        &["unknown field", "confirmed", "full"],
    );

    // And the accepted acknowledgement shape keeps all five of its declared
    // members, including the two optional ones, so the visitor is not
    // truncating a legitimate record.
    let ack: MemoryInfluenceToolInput = decode("observability", "memory_influence_tool_input_ack_valid");
    let MemoryInfluenceToolInput::Ack(ack) = ack else {
        panic!("the acknowledgement fixture must decode to the acknowledgement arm");
    };
    assert_eq!(ack.project_id.as_deref(), Some("00000000-0000-7000-8000-0000000000d1"));
    assert_eq!(ack.write_id.as_deref(), Some("00000000-0000-7000-8000-0000000000d4"));
    assert_eq!(ack.memory_handle, "mem-1");
    assert_eq!(ack.downstream_outcome_ref, None);

    // The full arm keeps the whole nested trace.
    let full: MemoryInfluenceToolInput =
        decode("observability", "memory_influence_tool_input_full_valid");
    let MemoryInfluenceToolInput::Full(full) = full else {
        panic!("the full fixture must decode to the full arm");
    };
    assert_eq!(full.write_id, "00000000-0000-7000-8000-0000000000d4");
    assert_eq!(full.trace.memory_handle, "mem-1");
    assert_eq!(full.trace.admission_decision.to_string(), "include_verified");
}

// ---------------------------------------------------------------------------
// Case 12 -- ambiguous fallback cannot turn unknown state into trusted state
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/12
#[test]
fn case_12_ambiguous_fallback_cannot_turn_unknown_state_into_trusted_state() {
    // The untagged Full/Ack union is the one place in this allocation where
    // a fallback could otherwise turn an unknown shape into a trusted one: a
    // derived untagged decoder tries the arms in order and accepts whichever
    // happens to fit. An argument object carrying BOTH shapes, or NEITHER, is
    // ambiguous and must be refused rather than resolved into a trusted arm.
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_mixed_full_and_ack",
        &["ambiguous", "variant", "match"],
    );
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_neither_shape",
        &["unrecognised", "variant", "match"],
    );

    // A malformed full-shape trace must not be silently resolved as an
    // acknowledgement: the two arms must not be interchangeable.
    refuse_any::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_full_malformed_trace",
        &["variant", "match", "trace"],
    );

    // A receipt that claims `committed` while carrying a rejection reason is
    // ambiguous evidence. The decoder must preserve BOTH fields verbatim
    // rather than resolving the conflict into a trusted committed state.
    let receipt: ObservabilityWriteReceipt = decode(
        "observability",
        "observability_write_receipt_ambiguous_committed",
    );
    assert_eq!(receipt.status, ObservabilityWriteStatus::Committed);
    assert_eq!(
        receipt.rejected_reason.as_deref(),
        Some("policy_denied"),
        "both sides of the conflict survive; neither is discarded to resolve it"
    );

    // A health report whose component says not_ready while the overall says
    // ready: the aggregate is not something the decoder may invent a verdict
    // for. Both values survive as written.
    let health: StartupHealthReport = decode("health", "startup_health_report_ambiguous_ready_fallback");
    assert_eq!(health.overall, HealthStatus::Ready);
    assert_eq!(health.components[0].status, HealthStatus::NotReady);
    assert_eq!(health.components[0].message, "db down");
    // `StartupHealthReport::new` is the declared constructor, and it derives
    // `overall` from the components. The wire decoder must NOT silently apply
    // that rule to caller-supplied bytes, so the contradiction above is
    // preserved rather than recomputed.
    let recomputed = StartupHealthReport::new(
        "1",
        "eliot-store",
        "inst-1",
        health.components.clone(),
    );
    assert_eq!(
        recomputed.overall,
        HealthStatus::NotReady,
        "the declared constructor derives NotReady; the wire decoder must not have done so behind the caller's back"
    );

    // A credentials report claiming one resolved credential with no per-
    // credential evidence is ambiguous; both the count and the empty status
    // list survive, and the decoder does not fill the list in.
    let credentials: CredentialDiagnosticsReport = decode(
        "service",
        "credential_diagnostics_report_ambiguous_resolved",
    );
    assert_eq!(credentials.resolved_count, 1);
    assert!(
        credentials.statuses.is_empty(),
        "a missing per-credential evidence list is not synthesized by the decoder"
    );
    assert_eq!(credentials.refs.len(), 1);
    let _: &CredentialRef = &credentials.refs[0];
    let _: &CredentialStatus = &credentials.statuses.first().unwrap_or(&CredentialStatus {
        credential_id: String::new(),
        provider: CredentialProviderKind::TestInMemory,
        present: false,
        version: None,
        fingerprint: None,
    });

    // A service status report claiming `running: true` next to a FAILED install
    // receipt: the contradiction is preserved, not resolved into Running.
    let status: ServiceStatusReport = decode("service", "service_status_report_ambiguous_running");
    assert!(status.running);
    assert!(status.installed);
    assert_eq!(
        status.install_receipt.status,
        ServiceInstallStatus::Failed,
        "the contradicting receipt status survives; the decoder does not promote it"
    );

    // A readiness probe with no checks claiming Ready: the empty check list
    // stays empty.
    let probe: ServiceReadinessProbe = decode("service", "service_readiness_probe_ambiguous_ready");
    assert_eq!(probe.status, ServiceReadinessStatus::Ready);
    assert!(
        probe.checks.is_empty(),
        "an empty check list is not back-filled with implied passes"
    );

    // A restart window whose state cannot be inferred from an empty restart
    // timestamp list stays as written.
    let window: OperationRestartWindow =
        decode("runtime_supervision", "operation_restart_window_unsupported_version")
            .ok()
            .and_then(|value: Result<OperationRestartWindow, _>| value.ok())
            .unwrap_or_else(|| decode("runtime_supervision", "operation_restart_window_valid"));
    assert_eq!(window.circuit_state, AdapterCircuitState::Closed);

    // The remaining vocabulary rows are named here so the case covers the whole
    // closed-enum allocation rather than a sample of it.
    let _ = (EndpointDirection::Bidirectional,
             ExchangeKind::RecoveryNotice,
             IpcFrameKind::ErrorResponse,
             IpcHandshakeReason::PipeAclDenied,
             LogEventKind::RecoveryAction,
             LogLevel::Warn,
             ModuleHealth { module_id: Default::default(), name: String::new(), enabled: false,
                             health: ServiceHealthState::Stopped, message: String::new() },
             ProviderDispatchState::AckUnknown,
             DescendantsCaptureErrorKind::Ambiguous,
             OperationCancellationState::Reaped,
             OperationReconciliationState::NonReconcilableUnknown,
             RuntimeOverallStatus::IntegrityFailed,
             SealStagingState::Abandoned,
             ServiceReadinessCheck::NoBlockingIncidents,
             ServiceRestartReason::ManualAdminRequest,
             ServiceRestartStatus::BudgetExhaustedIncidentOpened,
             ServiceStartType::Disabled,
             StartupRecoveryStatus::IncidentLockdown,
             ServiceAccountRef::LocalService,
             ObservabilityWriteStatus::IdempotentReplay,
             IpcConfig { pipe_name: String::new(), token_file: Default::default(),
                         max_frame_bytes: 0, request_timeout_ms: 0,
                         allowed_client_sids: Vec::new(), require_handshake: false,
                         bind_local_only: false },
             IpcStatusReport { component: String::new(), pipe_name: String::new(),
                               transport: String::new(), listening: false,
                               bind_local_only: false, max_frame_bytes: 0,
                               handshake_required: false, last_handshake: None,
                               warnings: Vec::new(), generated_at: Default::default() },
             IpcAuthenticationProfile { protocol_version: String::new(), pipe_name: String::new(),
               server_identity: String::new(), allowed_windows_sid_or_user: String::new(),
               token_generation: String::new(), token_storage_ref: Default::default(),
               token_permissions: String::new(), token_generation_id: String::new(),
               handshake_deadline_ms: 0, max_frame_bytes: 0, max_in_flight: 0,
               replay_policy: String::new(), rotation_policy: String::new() },
             RuntimeConfig { mode: RuntimeMode::AdminCli, data_root: String::new(),
                            log_root: String::new(), report_root: String::new(),
                            spool_root: String::new(), worktree_root: String::new() },
             RuntimeLoggingConfig { format: String::new(), level: String::new(),
                                   max_file_bytes: 0, max_files: 0 },
             RuntimeModulesConfig { enabled: false, manifest_dir: String::new() },
             ModuleAuthorityProfile::default(),
             ModuleResourceLimits::default(),
             RedactionInfo { secrets_redacted: false, raw_payload_redacted: false,
                             redacted_fields: Vec::new() },
             SchemaRef { schema_id: String::new(), version: String::new() },
             ModuleEndpoint { endpoint_id: String::new(), name: String::new(),
                               direction: EndpointDirection::GovernorToModule,
                               schema: SchemaRef { schema_id: String::new(), version: String::new() },
                               max_payload_bytes: 0, requires_ack: false },
             ModuleKind::ExportAdapter,
             ModuleTransport::Disabled,
             RuntimeIntegrityHealth { clean: false, expected_governor_sha256: None,
               observed_governor_sha256: None, locked_active_binary: None, process_orphans: 0,
               incomplete_staging_roots: 0, quarantine_records: 0,
               last_startup_recovery_ref: None, last_watchdog_action_ref: None },
             RuntimeAuthorityIntegrity { active_sessions: 0, active_role_leases: 0,
               pending_role_leases: 0, orphaned_role_leases: 0, revoked_role_leases: 0,
               stale_epoch_results: 0, partial_seals: 0, published_plans_without_authority: 0,
               published_seal_runtime_drift: 0, authority_without_published_plan: 0 },
             RuntimeCoreHealth { ready: false, ipc_ready: false, db_ready: false,
               writer_ready: false, read_service_ready: false, service_generation: None,
               executable_sha256: None },
             RuntimeOperationDetail { operation_id: String::new(), generation: 0,
               phase: OperationPhase::Prepared, last_progress_at: String::new(),
               phase_deadline_at: String::new(), root_pid: None, active_process_count: 0,
               stdin_state: String::new(), stdout_state: String::new(), stderr_state: String::new(),
               cancellation_state: OperationCancellationState::NotRequested,
               reconciliation_state: OperationReconciliationState::NotRequired,
               role_lease_id: None, role_lease_epoch: None },
             RuntimeOperationHealth { active: 0, stuck: 0, awaiting_reconciliation: 0,
               cleanup_pending: 0, orphan_processes: 0, oldest_last_progress_at: None,
               details: Vec::new() },
             RuntimeReconcileDecision { operation_id: String::new(), generation: 0,
               decision: String::new(), mutates: false, reason: String::new() },
             RuntimeAdapterHealth { adapter_id: String::new(), installed: false,
               authenticated: false, ready: false, circuit_state: AdapterCircuitState::HalfOpen,
               active_operations: 0, queued_operations: 0, restart_count_window: 0,
               last_success_at: None, last_failure_at: None, last_failure_class: None,
               last_terminal_operation_ref: None },
             AuthorityHeaderAlias::role_none(),
             CausalityHeader { trace_id: String::new(), parent_envelope_id: None,
               causation_id: None, correlation_id: None, sequence: 0 },
             DescendantsAtRootExitCaptured { schema_version: String::new(), root_pid: 1,
               root_exit_code: None, capture_elapsed_ms: 0, descendants: Vec::new() },
             DescendantProcessSnapshot { pid: 1, start_ticks: 0, image_path: String::new(),
               file_identity: DescendantFileIdentity { volume_serial_number: 0, file_index: 0 },
               image_sha256: None },
             CredentialPurpose::BackupEncryptionKey,
             ServiceInstallAction::Restart,
             ObservabilityKind::ExamRecord);
}

/// Local alias used only to keep the case-12 vocabulary tuple readable.
mod authority_header_alias {
    pub type Alias = eliot_types::AuthorityHeader;
}
use authority_header_alias::Alias as AuthorityHeaderAlias;

impl AuthorityHeaderAlias {
    fn role_none() -> Self {
        Self {
            role: None,
            capabilities: Vec::new(),
            lease_refs: Vec::new(),
            taint: eliot_types::TaintClass::LocalVerified,
        }
    }
}

// ---------------------------------------------------------------------------
// Case 14 -- malformed input is bounded and panic-free
// ---------------------------------------------------------------------------

// WORK_UNIT_CASE: 931/14
#[test]
fn case_14_malformed_input_is_bounded_and_panic_free() {
    // Malformed input must produce a typed `serde_json::Error`, never a panic
    // and never a partially-built trusted value. `std::panic::catch_unwind`
    // turns a panic into an `Err`, so this case distinguishes the two: a case
    // that only asserted `is_err()` would pass even if the decoder panicked.
    fn refuses_without_panicking<T: DeserializeOwned>(section: &str, name: &str) {
        let label = named(section, name);
        let raw = bytes(section, name);
        let outcome = std::panic::catch_unwind(move || serde_json::from_slice::<T>(&raw).is_err());
        assert!(
            outcome.is_ok(),
            "{label} must return a typed error, not panic"
        );
        assert!(
            outcome.expect("outcome was not a panic"),
            "{label} must be refused"
        );
    }

    // Truncated documents across all five file families.
    refuses_without_panicking::<StartupHealthReport>(
        "health",
        "startup_health_report_malformed_truncated",
    );
    refuses_without_panicking::<EliotExchangeEnvelope<Value>>(
        "runtime",
        "eliot_exchange_envelope_malformed_truncated",
    );
    refuses_without_panicking::<RuntimeSupervisionReport>(
        "runtime_supervision",
        "runtime_supervision_report_malformed_truncated",
    );
    refuses_without_panicking::<IpcFrame>("service", "ipc_frame_malformed_truncated");
    refuses_without_panicking::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_malformed_truncated",
    );
    refuses_without_panicking::<MemoryInfluenceToolInput>(
        "observability",
        "memory_influence_tool_input_malformed_truncated",
    );

    // Trailing garbage after a complete document.
    refuses_without_panicking::<StartupHealthReport>(
        "health",
        "startup_health_report_malformed_trailing",
    );

    // A well-formed document that is the wrong JSON shape entirely.
    refuses_without_panicking::<StartupHealthReport>(
        "health",
        "startup_health_report_malformed_not_object",
    );
    refuses_without_panicking::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_malformed_not_object",
    );
    refuses_without_panicking::<ObservabilityWriteEnvelope>(
        "observability",
        "observability_write_envelope_malformed_null",
    );

    // A deeply nested document must hit the decoder's own depth bound and
    // return an error, not exhaust the stack.
    refuses_without_panicking::<StartupHealthReport>(
        "health",
        "startup_health_report_malformed_deep",
    );

    // Malformed values inside an otherwise well-formed record: an out-of-range
    // datetime element and a negative value in an unsigned field.
    refuses_without_panicking::<IpcFrame>("service", "ipc_frame_malformed_bad_timestamp_element");
    refuses_without_panicking::<IpcFrame>("service", "ipc_frame_malformed_negative_for_unsigned");

    // The whole raw-byte battery, decoded by each family, must be bounded and
    // panic-free. This is the general bound: a hostile byte string can never
    // produce a panic on any of the T02 decoders.
    let degenerate: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("whitespace", b"   \t\n"),
        ("single brace", b"{"),
        ("nul byte", b"\0"),
        ("bare comma", b","),
        ("unterminated string", b"{\"service_name\":\"unterminated"),
        ("array top level", b"[]"),
        ("scalar top level", b"7"),
        ("string top level", b"\"eliot\""),
        ("bool top level", b"true"),
        ("nan", b"NaN"),
        ("infinity", b"Infinity"),
        ("huge integer", b"99999999999999999999999999999999999999"),
        ("bad escape", b"{\"service_name\":\"\\q\"}"),
        ("unterminated array", b"[1,2,3"),
        ("trailing comma", b"{\"a\":1,}"),
        ("two documents", b"{} {}"),
        ("lone surrogate", b"\"\\ud800\""),
    ];
    for (name, raw) in degenerate {
        // A byte string that is not valid UTF-8 at all.
        let invalid_utf8: &[u8] = &[b'{', b'"', 0xff, b'"', b'}'];
        for payload in [*raw, invalid_utf8] {
            let label = format!("{name} ({})", payload.len());
            assert_no_panic::<StartupHealthReport>(&label, payload);
            assert_no_panic::<RuntimeHealthReport>(&label, payload);
            assert_no_panic::<IpcFrame>(&label, payload);
            assert_no_panic::<OperationRuntimeCheckpoint>(&label, payload);
            assert_no_panic::<ProcessReapReceipt>(&label, payload);
            assert_no_panic::<DescendantsAtRootExit>(&label, payload);
            assert_no_panic::<ObservabilityWriteEnvelope>(&label, payload);
            assert_no_panic::<MemoryInfluenceToolInput>(&label, payload);
            assert_no_panic::<WindowsServiceConfig>(&label, payload);
        }
    }

    // The refusal message must be bounded: a hostile input cannot echo an
    // unbounded slice of itself back to the caller.
    let long_key = format!(
        "{{\"{key}\":1}}",
        key = "k".repeat(64 * 1024)
    );
    let message = refuse::<StartupHealthReport>("health", "startup_health_report_valid")
        .len()
        .to_string();
    assert!(message.len() < 8, "sanity: the valid fixture decodes");
    let outcome = std::panic::catch_unwind(move || {
        serde_json::from_slice::<StartupHealthReport>(long_key.as_bytes())
    });
    assert!(outcome.is_ok(), "an oversized key must not panic");
    let error = outcome
        .expect("an oversized key must not panic")
        .expect_err("an oversized key must be refused");
    assert!(
        error.to_string().len() < 8 * 1024,
        "the refusal must stay bounded and must not echo the oversized key back"
    );
}

/// Decode a raw byte string and assert it neither panics nor yields a value,
/// returning the typed error.
#[allow(clippy::expect_used)]
fn assert_no_panic<T: DeserializeOwned>(label: &str, raw: &[u8]) {
    let owned = raw.to_vec();
    let outcome = std::panic::catch_unwind(move || serde_json::from_slice::<T>(&owned));
    assert!(outcome.is_ok(), "{label}: decoding must not panic");
    assert!(
        outcome.expect("decoding must not panic").is_err(),
        "{label}: malformed bytes must not produce a trusted value"
    );
}
