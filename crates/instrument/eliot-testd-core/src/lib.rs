//! Durable scheduling and lifecycle state for the instrument test daemon.
//!
//! The daemon deliberately keeps execution outside this crate.  It owns the
//! admission record, project-local ordering, leases, retry timing, and the
//! immutable transition journal.  A process adapter may therefore restart at
//! any point and recover exactly which work is safe to run next.

#![forbid(unsafe_code)]

pub use eliot_build_test_graph::{
    BUILD_ROOT_DIRECTORY, BuildFingerprint, BuildMode, CARGO_HOME_ENV, CARGO_TARGET_DIR_ENV,
    CandidateIdentity, FIXTURE_NAMESPACE_ENV, FIXTURE_ROOT_ENV, GovernedWorkEnvelope, LaneIdentity,
    RuntimeEnvironmentLease,
};
use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, ContractVersion, EpochId, RequestId, StateFence,
    canonical_json_bytes,
};
pub use eliot_instrument_api::KernelProcessAdmissionRequest;
use eliot_instrument_api::{
    ExecutionStatus, InstrumentInvocation, InstrumentKind, VerificationRun,
};
use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, OperationId, ProcessRequest, ResourceLimits,
};
use eliot_protocol::RequestIdentity;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

mod claim;
mod nextest_partition;
mod resources;
mod target_layout;
mod typed_evidence;

pub use claim::{
    ClaimBindingExpectation, ExpiredRunningReconciliation, reconcile_expired_running,
    validate_claim_binding,
};
pub use resources::{
    JobClass, NextestLanePlan, ResourceClaim, ResourceError, ResourceKind, ResourceLease,
    ResourceLeaseAllocator, ResourceWeight, SchedulingDecision, TestResourceProfile,
    scheduling_decision,
};
pub use target_layout::{
    BoundTargetRoots, BuildClass, TARGET_LAYOUT_REVISION, TargetLayoutBinding,
    bound_roots_conflict, derive_layout_path, verify_envelope_layout_binding,
    verify_layout_binding,
};
pub use typed_evidence::{
    AsyncProcessStreamSourceReadbackPort, EphemeralSourceBytes,
    ProcessStreamSourceReadbackFuture, ProcessStreamSourceReadbackObservation,
    ProcessStreamSourceReadbackPort, ProcessStreamSourceReadbackRequest, TestdArtifactBinding,
    TestdEvaluationObservation,
    TestdEvaluationStatus, TestdEvaluatorSlot, TestdEvidenceDisposition, TestdEvidenceError,
    TestdParserSlot, TestdParsingObservation, TestdParsingStatus, TestdProcessEvidenceBundle,
    TestdReadbackContext, TestdStreamDisposition, TestdStreamEvidenceBinding,
    TestdStreamResolution, TestdStreamSlot,
};

/// The admitted execution lane for a profile stage. `DecoderOnly` names an
/// in-process decoder over exact stored input artifacts; it never grants
/// process execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageExecutionKind {
    /// A registered adapter stage that still requires Kernel process
    /// admission before a process can be launched.
    Process,
    /// A registered decoder stage that consumes its exact stored artifact
    /// lineage without launching a process.
    DecoderOnly,
}

/// Kernel/runner-issued provider-registry freshness evidence retained with a
/// stage so Testd can independently re-observe the same dependencies before
/// replay. This record is deliberately data-only: it grants neither process
/// nor storage authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderRegistryFreshness {
    /// Exact provider-registry generation used by admission.
    pub generation: u64,
    /// Exact normative-pair digest used to build the provider registry.
    pub normative_pair_digest: String,
    /// Independent invalidation inputs used by `ProviderRegistry`.
    pub fingerprints: TestdProviderFingerprints,
}

/// Seven independent dependencies that can invalidate a provider selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderFingerprints {
    /// Source/worktree snapshot fingerprint.
    pub source: String,
    /// Cargo lockfile fingerprint.
    pub lock: String,
    /// Resolved toolchain fingerprint.
    pub toolchain: String,
    /// Closed environment projection fingerprint.
    pub env: String,
    /// Resolved executable identity fingerprint.
    pub exe: String,
    /// Compiled provider profile fingerprint.
    pub profile: String,
    /// Parser contract and generation fingerprint.
    pub parser: String,
}

impl TestdProviderRegistryFreshness {
    /// Rejects incomplete, malformed, or default-shaped freshness authority.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.generation == 0 || !is_binding_digest(&self.normative_pair_digest) {
            return Err(TestdError::InvalidBinding);
        }
        for (field, value) in [
            ("provider_source_fingerprint", self.fingerprints.source.as_str()),
            ("provider_lock_fingerprint", self.fingerprints.lock.as_str()),
            (
                "provider_toolchain_fingerprint",
                self.fingerprints.toolchain.as_str(),
            ),
            ("provider_environment_fingerprint", self.fingerprints.env.as_str()),
            ("provider_executable_fingerprint", self.fingerprints.exe.as_str()),
            ("provider_profile_fingerprint", self.fingerprints.profile.as_str()),
            ("provider_parser_fingerprint", self.fingerprints.parser.as_str()),
        ] {
            if value.trim().is_empty()
                || value.len() > 1024
                || value.chars().any(char::is_control)
            {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be non-empty, bounded, and control-free",
                });
            }
        }
        Ok(())
    }
}

/// Data-only projection of the accepted module-catalog lifecycle used to
/// create a provider registry. It is retained with a stage so the Kernel can
/// compare it with independently revalidated owner facts; this record alone
/// is never currentness authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProviderCatalogLifecycle {
    pub owner_revision: u64,
    pub catalog_revision: u64,
    pub catalog_digest: String,
    pub state_fence: StateFence,
    pub module_id: String,
    pub generation_id: String,
    pub artifact_digest: String,
    pub config_digest: String,
    pub protocol_digest: String,
    pub manifest_digest: String,
    pub admission_receipt: String,
}

impl TestdProviderCatalogLifecycle {
    /// Validates the complete, bounded owner-lifecycle projection.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.owner_revision == 0 || self.catalog_revision == 0 {
            return Err(TestdError::InvalidBinding);
        }
        self.state_fence
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        for (field, value) in [
            ("provider_catalog.module_id", self.module_id.as_str()),
            ("provider_catalog.generation_id", self.generation_id.as_str()),
            ("provider_catalog.admission_receipt", self.admission_receipt.as_str()),
        ] {
            validate_text(value, field)?;
        }
        for (field, value) in [
            ("provider_catalog.catalog_digest", self.catalog_digest.as_str()),
            ("provider_catalog.artifact_digest", self.artifact_digest.as_str()),
            ("provider_catalog.config_digest", self.config_digest.as_str()),
            ("provider_catalog.protocol_digest", self.protocol_digest.as_str()),
            ("provider_catalog.manifest_digest", self.manifest_digest.as_str()),
        ] {
            if !is_binding_digest(value) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        Ok(())
    }
}

/// Closed, durable identity of one profile stage admitted by the runner.
///
/// This carries identity and policy bindings only. In particular it contains
/// no executable path, argv, shell text, process request, or authority
/// evidence. Testd must resolve these identities against its current typed
/// profile/provider registry before allocating or starting work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentStageRequest {
    /// The owner-admitted instrument invocation for this stage.
    pub invocation: InstrumentInvocation,
    /// Exact admitted profile name.
    pub profile_name: String,
    /// Exact durable profile revision from the admitted stage plan.
    pub profile_revision: u64,
    /// Immutable profile digest.
    pub profile_digest: String,
    /// Immutable profile DAG digest.
    pub dag_digest: String,
    /// ProfileRegistry generation used to compile this stage.
    pub registry_generation: u64,
    /// Digest of the ProfileRegistry snapshot used to compile this stage.
    pub registry_digest: String,
    /// Separately retained ProviderRegistry currentness; it is never compared
    /// with the ProfileRegistry generation/digest above.
    #[serde(default)]
    pub provider_freshness: Option<TestdProviderRegistryFreshness>,
    /// Accepted catalog lifecycle projected by the runner. Kernel must
    /// compare this to the current catalog owner record before admission.
    #[serde(default)]
    pub provider_catalog_lifecycle: Option<TestdProviderCatalogLifecycle>,
    /// Exact admitted stage identifier.
    pub stage_id: String,
    /// Registered stage specification identity.
    pub spec: ContractId,
    /// Exact stage specification revision.
    pub spec_revision: ContractVersion,
    /// Immutable stage specification digest.
    pub spec_digest: String,
    /// Admitted instrument kind for this stage.
    pub kind: InstrumentKind,
    /// Registered parser identity used for evidence replay.
    pub parser: ContractId,
    /// Exact parser registry generation used for admission.
    pub parser_generation: u64,
    /// Registered evaluator identity selected for verification.
    pub evaluator: ContractId,
    /// Selected registered provider adapter identity.
    pub adapter: String,
    /// Exact selected provider adapter version.
    pub adapter_version: ContractVersion,
    /// Whether the stage requires a process or is decoder-only.
    pub execution: StageExecutionKind,
}

impl InstrumentStageRequest {
    /// Validates identity shape without granting execution authority.
    pub fn validate(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("profile_name", self.profile_name.as_str()),
            ("stage_id", self.stage_id.as_str()),
            ("adapter", self.adapter.as_str()),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be a non-empty control-free identity",
                });
            }
        }
        for (field, value) in [
            ("profile_digest", self.profile_digest.as_str()),
            ("dag_digest", self.dag_digest.as_str()),
            ("registry_digest", self.registry_digest.as_str()),
            ("spec_digest", self.spec_digest.as_str()),
        ] {
            if !is_binding_digest(value) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        self.invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if self.profile_name != self.invocation.profile || self.kind != self.invocation.kind {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(freshness) = &self.provider_freshness {
            freshness.validate()?;
        }
        if let Some(lifecycle) = &self.provider_catalog_lifecycle {
            lifecycle.validate()?;
        }
        if self.profile_name == TESTD_PRODUCTIVE_PROFILE
            && (self.provider_freshness.is_none() || self.provider_catalog_lifecycle.is_none())
        {
            return Err(TestdError::Invalid {
                field: "stage_request.provider_currentness",
                reason: "productive stages require provider freshness and accepted catalog lifecycle evidence",
            });
        }
        Ok(())
    }
}

// ---- Closed testd profile to executable binding registry (issue #20) ----
//
// Testd executes only admitted typed Instrument profiles bound to exact
// executable/environment/artifact/State Fence identities. This registry is
// the closed profile side of that binding: it maps one admitted profile
// name to its exact executable meaning. The Doctor design is mirrored
// (`RepairRecipeManifest` in `eliot-doctor-core`): a closed registry, a
// per-definition digest, resolution that fails closed on unregistered
// names, and no public constructor from free-form text.
//
// * `profile` is the closed name below; anything else is refused at
//   registration (`TestdStore::submit`) and at every Drive gate.
// * `package_artifact_digest` is the lowercase SHA-256 of the installed
//   tool file bytes, recorded at registration from the installed tool
//   itself (the Drive resolves the relative program through the platform
//   tool locator and hashes the file; no digest is hardcoded, because the
//   installed bytes differ per host).
// * `program_path` is relative and closed (`cargo` only): absolute paths
//   and parent traversal are refused, so no caller can redirect execution
//   by path.
// * `fixed_argv` is the complete argv. The probe and productive nextest
//   profiles take no caller slots, so any invocation-supplied argument is
//   refused at registration: there is no caller passthrough. The slotted
//   list/scoped profiles (issue #1802, step 4) are separate registry
//   entries with their own slot schema: invocation arguments must parse
//   as validated slots and the Drive seals exactly the rendered argv,
//   never raw caller text.
// * `env_allowlist` is the exact non-secret environment for the child.
//   Productive nextest profiles, including discovery, receive only the
//   explicitly registered feature gate below; no ambient environment is
//   inherited.
// * the working directory is never stored here: the Drive always uses the
//   generation root supplied with the admitted material, never a
//   caller-chosen directory.
// * the timeout/output caps are fixed below and bound into the definition
//   digest, so a widened execution window cannot substitute silently.
//
// Two digests separate the host-stable meaning from the installed bytes:
// [`testd_definition_digest`] covers the static fields only and is bound
// into the Kernel front-door admission (`TestdAdmission` in
// `eliot-kernel-service`); [`testd_binding_digest`] additionally covers
// the installed artifact digest and binds one Drive registration.

/// The retained harmless process probe profile.
///
/// A clean `cargo --version` exit is never promoted into a task verifier
/// result.
pub const TESTD_ADMITTED_PROFILE: &str = "cargo-test";
/// Separately registered productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE: &str = "cargo-nextest";
/// Exact registered adapter currently accepted by the productive owner path.
/// Other stage adapters need their own governed process-intent binding.
pub const TESTD_PRODUCTIVE_ADAPTER: &str = "eliot.instrument.nextest";
/// Separately registered dev-fast discovery profile (issue #1802, step 4):
/// `cargo nextest list --message-format json` with validated scope slots.
pub const TESTD_LIST_PROFILE: &str = "cargo-nextest-list";
/// Separately registered dev-fast scoped-run profile: the productive
/// nextest run with validated scope slots.
pub const TESTD_SCOPED_PROFILE: &str = "cargo-nextest-scoped";
/// Relative program for the admitted probe, resolved through the platform
/// tool locator at Drive time. Never absolute, never parent traversal.
pub const TESTD_PROFILE_PROGRAM: &str = "cargo";
/// Relative executable for the productive profile. Resolving the installed
/// subcommand directly pins nextest rather than hashing the cargo wrapper.
pub const TESTD_PRODUCTIVE_PROFILE_PROGRAM: &str = "cargo-nextest";
/// Fixed argv for the admitted probe. No caller slot exists.
pub const TESTD_PROFILE_ARGV: &[&str] = &["--version"];
/// Fixed machine-readable argv for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_ARGV: &[&str] = &[
    "run",
    "--message-format",
    "libtest-json-plus",
    "--message-format-version",
    "0.1",
];
/// Fixed discovery argv prefix for the list profile. Validated scope slots
/// render after it; the rendering equals the nextest owner's
/// `NextestCommand::list` output for the same slots.
pub const TESTD_LIST_PROFILE_ARGV: &[&str] = &["list", "--message-format", "json"];
/// Slot flag binding one Cargo package (`--package <name>`).
pub const TESTD_SLOT_PACKAGE: &str = "--package";
/// Slot flag binding one binary target (`--bin <name>`).
pub const TESTD_SLOT_BINARY: &str = "--bin";
/// Slot flag binding the scoped per-test retry count (`--retries <n>`,
/// scoped profile only).
pub const TESTD_SLOT_RETRIES: &str = "--retries";
/// Exact environment required by nextest 0.9.143's experimental libtest JSON
/// reporter. The value is owner-registered and is never read from ambient
/// process state.
pub const TESTD_PRODUCTIVE_PROFILE_ENVIRONMENT: &[(&str, &str)] =
    &[("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1")];
/// Bounded wall timeout for the probe, in milliseconds.
pub const TESTD_PROFILE_WALL_TIMEOUT_MS: u64 = 15_000;
/// Bounded CPU ceiling for the probe, in milliseconds.
pub const TESTD_PROFILE_CPU_TIME_MS: u64 = 5_000;
/// Bounded memory ceiling for the probe, in bytes.
pub const TESTD_PROFILE_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
/// Bounded stdout capture for the probe, in bytes.
pub const TESTD_PROFILE_STDOUT_BYTES: u64 = 64 * 1024;
/// Bounded stderr capture for the probe, in bytes.
pub const TESTD_PROFILE_STDERR_BYTES: u64 = 64 * 1024;
/// Bounded descendant ceiling for the probe.
pub const TESTD_PROFILE_MAX_DESCENDANTS: u32 = 4;
/// Independent wall timeout for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_WALL_TIMEOUT_MS: u64 = 15 * 60 * 1_000;
/// Independent CPU ceiling for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_CPU_TIME_MS: u64 = 10 * 60 * 1_000;
/// Independent memory ceiling for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Independent stdout capture bound for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_STDOUT_BYTES: u64 = 16 * 1024 * 1024;
/// Independent stderr capture bound for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_STDERR_BYTES: u64 = 16 * 1024 * 1024;
/// Independent descendant ceiling for the productive nextest profile.
pub const TESTD_PRODUCTIVE_PROFILE_MAX_DESCENDANTS: u32 = 32;
/// Discovery shares the productive nextest wall timeout and resource
/// envelope. Keep this name for the Testd worker's existing timeout lookup.
pub const TESTD_LIST_PROFILE_WALL_TIMEOUT_MS: u64 = TESTD_PRODUCTIVE_PROFILE_WALL_TIMEOUT_MS;

/// Closed executable binding for one admitted testd profile.
///
/// Values are produced only by [`testd_profile_binding`] against the
/// closed registry above. There is no public constructor from free-form
/// text, so an unregistered profile or widened argv/environment/limit
/// cannot be named here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdExecutableBinding {
    /// Closed admitted profile name.
    pub profile: String,
    /// Lowercase SHA-256 of the installed tool file bytes, recorded at
    /// registration from the installed tool itself.
    pub package_artifact_digest: String,
    /// Relative program path (`cargo` only).
    pub program_path: String,
    /// Complete fixed argv (`--version` only).
    pub fixed_argv: Vec<String>,
    /// Exact non-secret environment name/value bindings for this profile.
    pub env_allowlist: Vec<(String, String)>,
    /// Bounded wall timeout, in milliseconds.
    pub wall_timeout_ms: u64,
    /// Bounded CPU ceiling, in milliseconds.
    pub cpu_time_ms: Option<u64>,
    /// Bounded memory ceiling, in bytes.
    pub memory_bytes: Option<u64>,
    /// Bounded stdout capture, in bytes.
    pub stdout_bytes: u64,
    /// Bounded stderr capture, in bytes.
    pub stderr_bytes: u64,
    /// Bounded descendant ceiling.
    pub max_descendants: u32,
}

impl TestdExecutableBinding {
    /// Validates the closed binding shape.
    pub fn validate(&self) -> Result<(), TestdError> {
        if !is_admitted_testd_profile(&self.profile) {
            return Err(TestdError::Invalid {
                field: "profile",
                reason: "testd admits only registered probe or productive nextest profiles",
            });
        }
        if !is_binding_digest(&self.package_artifact_digest) {
            return Err(TestdError::Invalid {
                field: "package_artifact_digest",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        // Closed by equality: the admitted program is relative by
        // construction, so absolute paths and parent traversal have no
        // spelling that validates.
        let expected_program = if self.profile == TESTD_ADMITTED_PROFILE {
            TESTD_PROFILE_PROGRAM
        } else {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM
        };
        if self.program_path != expected_program {
            return Err(TestdError::Invalid {
                field: "program_path",
                reason: "testd admits only the closed relative cargo tool program",
            });
        }
        let expected_argv: Vec<String> = if self.profile == TESTD_ADMITTED_PROFILE {
            TESTD_PROFILE_ARGV.iter().map(ToString::to_string).collect()
        } else if self.profile == TESTD_PRODUCTIVE_PROFILE {
            TESTD_PRODUCTIVE_PROFILE_ARGV
                .iter()
                .map(ToString::to_string)
                .collect()
        } else {
            // Slotted profiles seal validated slots into argv: the prefix
            // must match exactly and the suffix must round-trip through
            // the slot schema, so no unvalidated text can reach the child.
            let prefix = testd_slotted_prefix(&self.profile).ok_or(TestdError::Invalid {
                field: "fixed_argv",
                reason: "the registered profile takes fixed argv; caller arguments are refused",
            })?;
            let prefix_len = prefix.len();
            if self.fixed_argv.len() < prefix_len
                || self.fixed_argv[..prefix_len]
                    .iter()
                    .zip(prefix.iter())
                    .any(|(observed, expected)| observed != expected)
            {
                return Err(TestdError::Invalid {
                    field: "fixed_argv",
                    reason: "the registered profile takes fixed argv; caller arguments are refused",
                });
            }
            let slots = parse_testd_slot_suffix(&self.profile, &self.fixed_argv[prefix_len..])?;
            render_testd_slotted_argv(&self.profile, &slots)?
        };
        if self.fixed_argv != expected_argv {
            return Err(TestdError::Invalid {
                field: "fixed_argv",
                reason: "the registered profile takes fixed argv; caller arguments are refused",
            });
        }
        let expected_environment: Vec<(String, String)> = if self.profile
            == TESTD_PRODUCTIVE_PROFILE
            || self.profile == TESTD_LIST_PROFILE
            || self.profile == TESTD_SCOPED_PROFILE
        {
            TESTD_PRODUCTIVE_PROFILE_ENVIRONMENT
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect()
        } else {
            Vec::new()
        };
        if self.env_allowlist != expected_environment {
            return Err(TestdError::Invalid {
                field: "env_allowlist",
                reason: "the admitted profile takes only its registered environment bindings",
            });
        }
        let (
            wall_timeout_ms,
            cpu_time_ms,
            memory_bytes,
            stdout_bytes,
            stderr_bytes,
            max_descendants,
        ) = profile_limits(&self.profile);
        if self.wall_timeout_ms != wall_timeout_ms
            || self.cpu_time_ms != cpu_time_ms
            || self.memory_bytes != memory_bytes
            || self.stdout_bytes != stdout_bytes
            || self.stderr_bytes != stderr_bytes
            || self.max_descendants != max_descendants
        {
            return Err(TestdError::Invalid {
                field: "resource_limits",
                reason: "the admitted profile takes fixed timeout and output caps",
            });
        }
        Ok(())
    }
}

fn profile_limits(profile: &str) -> (u64, Option<u64>, Option<u64>, u64, u64, u32) {
    if matches!(
        profile,
        TESTD_PRODUCTIVE_PROFILE | TESTD_LIST_PROFILE | TESTD_SCOPED_PROFILE
    ) {
        (
            TESTD_PRODUCTIVE_PROFILE_WALL_TIMEOUT_MS,
            Some(TESTD_PRODUCTIVE_PROFILE_CPU_TIME_MS),
            Some(TESTD_PRODUCTIVE_PROFILE_MEMORY_BYTES),
            TESTD_PRODUCTIVE_PROFILE_STDOUT_BYTES,
            TESTD_PRODUCTIVE_PROFILE_STDERR_BYTES,
            TESTD_PRODUCTIVE_PROFILE_MAX_DESCENDANTS,
        )
    } else {
        (
            TESTD_PROFILE_WALL_TIMEOUT_MS,
            Some(TESTD_PROFILE_CPU_TIME_MS),
            Some(TESTD_PROFILE_MEMORY_BYTES),
            TESTD_PROFILE_STDOUT_BYTES,
            TESTD_PROFILE_STDERR_BYTES,
            TESTD_PROFILE_MAX_DESCENDANTS,
        )
    }
}

/// Returns true only for the closed admitted testd profile name.
#[must_use]
pub fn is_admitted_testd_profile(profile: &str) -> bool {
    matches!(
        profile,
        TESTD_ADMITTED_PROFILE
            | TESTD_PRODUCTIVE_PROFILE
            | TESTD_LIST_PROFILE
            | TESTD_SCOPED_PROFILE
    )
}

/// Returns true only for the slotted list/scoped profiles, whose
/// invocations carry validated slot arguments instead of fixed argv.
#[must_use]
pub fn is_slotted_testd_profile(profile: &str) -> bool {
    matches!(profile, TESTD_LIST_PROFILE | TESTD_SCOPED_PROFILE)
}

/// Returns true for the productive nextest profiles whose attempts
/// require owner-observed tool identity, source observation, and
/// terminal publication: the unscoped productive run plus the slotted
/// list/scoped profiles. The harmless probe never qualifies.
#[must_use]
pub fn is_productive_testd_profile(profile: &str) -> bool {
    matches!(
        profile,
        TESTD_PRODUCTIVE_PROFILE | TESTD_LIST_PROFILE | TESTD_SCOPED_PROFILE
    )
}

/// Resolves the closed binding for one admitted profile.
///
/// The artifact digest is the caller's recorded SHA-256 of the installed
/// tool file bytes (see [`resolve_testd_tool_digest`] on the bins side);
/// it is shape-checked here and bound into [`testd_binding_digest`].
/// An unregistered profile fails with `Invalid` and can never execute.
/// Slotted profiles resolve with empty slots; callers with slot arguments
/// use [`testd_profile_binding_with_slots`].
pub fn testd_profile_binding(
    profile: &str,
    package_artifact_digest: &str,
) -> Result<TestdExecutableBinding, TestdError> {
    testd_profile_binding_with_slots(profile, package_artifact_digest, &[])
}

/// Resolves the closed binding for one admitted profile with validated
/// slot arguments.
///
/// The probe and productive profiles take fixed argv, so any slot
/// argument is refused for them. The slotted list/scoped profiles parse
/// the suffix through the slot schema and seal exactly the rendered argv
/// into the binding; unvalidated text can never reach the child.
pub fn testd_profile_binding_with_slots(
    profile: &str,
    package_artifact_digest: &str,
    slot_suffix: &[String],
) -> Result<TestdExecutableBinding, TestdError> {
    if !is_admitted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "testd admits only registered probe or productive nextest profiles",
        });
    }
    let fixed_argv: Vec<String> = if profile == TESTD_ADMITTED_PROFILE {
        if !slot_suffix.is_empty() {
            return Err(TestdError::Invalid {
                field: "fixed_argv",
                reason: "the registered profile takes fixed argv; caller arguments are refused",
            });
        }
        TESTD_PROFILE_ARGV.iter().map(ToString::to_string).collect()
    } else if profile == TESTD_PRODUCTIVE_PROFILE {
        if !slot_suffix.is_empty() {
            return Err(TestdError::Invalid {
                field: "fixed_argv",
                reason: "the registered profile takes fixed argv; caller arguments are refused",
            });
        }
        TESTD_PRODUCTIVE_PROFILE_ARGV
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        let slots = parse_testd_slot_suffix(profile, slot_suffix)?;
        render_testd_slotted_argv(profile, &slots)?
    };
    let binding = TestdExecutableBinding {
        profile: profile.to_owned(),
        package_artifact_digest: package_artifact_digest.to_owned(),
        program_path: if profile == TESTD_ADMITTED_PROFILE {
            TESTD_PROFILE_PROGRAM.to_owned()
        } else {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM.to_owned()
        },
        fixed_argv,
        env_allowlist: if profile == TESTD_PRODUCTIVE_PROFILE
            || profile == TESTD_LIST_PROFILE
            || profile == TESTD_SCOPED_PROFILE
        {
            TESTD_PRODUCTIVE_PROFILE_ENVIRONMENT
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect()
        } else {
            Vec::new()
        },
        wall_timeout_ms: profile_limits(profile).0,
        cpu_time_ms: profile_limits(profile).1,
        memory_bytes: profile_limits(profile).2,
        stdout_bytes: profile_limits(profile).3,
        stderr_bytes: profile_limits(profile).4,
        max_descendants: profile_limits(profile).5,
    };
    binding.validate()?;
    Ok(binding)
}

/// Canonical definition digest over the static binding fields.
///
/// Excludes the per-host artifact digest, so the value is stable across
/// hosts and can be bound into the Kernel front-door admission. The
/// canonical shape (field names and JSON representation) must stay
/// identical to `testd_profile_definition_digest` in
/// `crates/kernel/eliot-kernel-service/src/testd_front_door.rs`, which
/// mirrors these constants without a dependency: `canonical_json_bytes`
/// sorts object keys, so only the field set and values must agree.
pub fn testd_definition_digest() -> Result<String, TestdError> {
    testd_definition_digest_for_profile(TESTD_ADMITTED_PROFILE)
}

/// Canonical definition digest for one registered testd profile.
///
/// Slotted profiles digest with empty slots; callers with slot arguments
/// use [`testd_definition_digest_for_slots`].
pub fn testd_definition_digest_for_profile(profile: &str) -> Result<String, TestdError> {
    if !is_admitted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "testd admits only registered probe or productive nextest profiles",
        });
    }
    let argv: Vec<String> = if profile == TESTD_ADMITTED_PROFILE {
        TESTD_PROFILE_ARGV.iter().map(ToString::to_string).collect()
    } else if profile == TESTD_PRODUCTIVE_PROFILE {
        TESTD_PRODUCTIVE_PROFILE_ARGV
            .iter()
            .map(ToString::to_string)
            .collect()
    } else {
        let slots = parse_testd_slot_suffix(profile, &[])?;
        render_testd_slotted_argv(profile, &slots)?
    };
    canonical_definition_digest(profile, &argv)
}

/// Canonical definition digest for one slotted profile with validated
/// slot arguments.
///
/// The digest covers the sealed argv rendered from the slots, so the
/// Kernel front-door mirror agrees on the same suffix without accepting
/// executable authority from the caller. Fixed-argv profiles are refused
/// here; they digest through [`testd_definition_digest_for_profile`].
pub fn testd_definition_digest_for_slots(
    profile: &str,
    slot_suffix: &[String],
) -> Result<String, TestdError> {
    if !is_slotted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "only the slotted list and scoped profiles take slot arguments",
        });
    }
    let slots = parse_testd_slot_suffix(profile, slot_suffix)?;
    let argv = render_testd_slotted_argv(profile, &slots)?;
    canonical_definition_digest(profile, &argv)
}

fn canonical_definition_digest(profile: &str, argv: &[String]) -> Result<String, TestdError> {
    #[derive(Serialize)]
    struct Canonical<'a> {
        cpu_time_ms: Option<u64>,
        env_allowlist: &'a [(String, String)],
        fixed_argv: &'a [String],
        max_descendants: u32,
        memory_bytes: Option<u64>,
        profile: &'a str,
        program_path: &'a str,
        stderr_bytes: u64,
        stdout_bytes: u64,
        wall_timeout_ms: u64,
    }
    let empty: Vec<(String, String)> = Vec::new();
    let limits = profile_limits(profile);
    let env_allowlist = if profile == TESTD_PRODUCTIVE_PROFILE
        || profile == TESTD_LIST_PROFILE
        || profile == TESTD_SCOPED_PROFILE
    {
        TESTD_PRODUCTIVE_PROFILE_ENVIRONMENT
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>()
    } else {
        empty
    };
    let canonical = Canonical {
        cpu_time_ms: limits.1,
        env_allowlist: &env_allowlist,
        fixed_argv: argv,
        max_descendants: limits.5,
        memory_bytes: limits.2,
        profile,
        program_path: if profile == TESTD_ADMITTED_PROFILE {
            TESTD_PROFILE_PROGRAM
        } else {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM
        },
        stderr_bytes: limits.4,
        stdout_bytes: limits.3,
        wall_timeout_ms: limits.0,
    };
    eliot_contracts::canonical_json_bytes(&canonical)
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| TestdError::GrantDigestSerialization)
}

/// Canonical digest over the full binding including the installed
/// artifact digest. Binds one Drive registration to its exact installed
/// bytes; a substituted executable fails the comparison.
pub fn testd_binding_digest(binding: &TestdExecutableBinding) -> Result<String, TestdError> {
    binding.validate()?;
    eliot_contracts::canonical_json_bytes(binding)
        .map(|bytes| eliot_contracts::sha256_hex(&bytes))
        .map_err(|_| TestdError::GrantDigestSerialization)
}

/// Proves a presented binding digest names exactly this binding.
/// A tampered binding (substituted digest, argv, program, environment,
/// or caps) fails with `InvalidBinding` and executes nothing.
pub fn validate_testd_binding_digest(
    binding: &TestdExecutableBinding,
    expected: &str,
) -> Result<(), TestdError> {
    if testd_binding_digest(binding)? != expected {
        return Err(TestdError::InvalidBinding);
    }
    Ok(())
}

/// Builds the closed resource limits for one validated binding.
pub fn testd_profile_resource_limits(
    binding: &TestdExecutableBinding,
) -> Result<ResourceLimits, TestdError> {
    binding.validate()?;
    ResourceLimits::new(
        binding.wall_timeout_ms,
        binding.cpu_time_ms,
        binding.memory_bytes,
        binding.stdout_bytes,
        binding.stderr_bytes,
        binding.max_descendants,
    )
    .map_err(|error| TestdError::Contract(error.to_string()))
}

/// Builds the closed environment projection for one validated binding:
/// no inherited values and only the exact registered name/value bindings.
pub fn testd_profile_environment(
    binding: &TestdExecutableBinding,
) -> Result<EnvironmentProjection, TestdError> {
    binding.validate()?;
    EnvironmentProjection::new(
        binding
            .env_allowlist
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .map_err(|error| TestdError::Contract(error.to_string()))
}

pub(crate) fn is_binding_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Exact-match marker rendered before scoped filters.
pub const TESTD_SLOT_EXACT: &str = "--exact";
/// Separator between nextest options and exact test filters.
pub const TESTD_SLOT_SEPARATOR: &str = "--";

/// Validated slot values for one slotted nextest profile.
///
/// Values originate from the frozen discovery/selection material: package
/// and binary name admitted Cargo target slots, filters name exact
/// discovered test identities, and retries carry the declared per-test
/// policy. Nothing here is caller free text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TestdNextestSlots {
    /// Optional Cargo package slot (`--package`).
    pub package: Option<String>,
    /// Optional binary target slot (`--bin`).
    pub binary: Option<String>,
    /// Declared per-test retry count (`--retries`), scoped runs only.
    pub retries: Option<u32>,
    /// Exact discovered test identities, scoped runs only.
    pub filters: Vec<String>,
}

/// Fixed argv prefix for one slotted profile, or `None` for the
/// fixed-argv probe and productive profiles.
fn testd_slotted_prefix(profile: &str) -> Option<&'static [&'static str]> {
    if profile == TESTD_LIST_PROFILE {
        Some(TESTD_LIST_PROFILE_ARGV)
    } else if profile == TESTD_SCOPED_PROFILE {
        Some(TESTD_PRODUCTIVE_PROFILE_ARGV)
    } else {
        None
    }
}

/// Parses one validated slot suffix for a slotted profile.
///
/// The grammar is strict order with no unknown token:
///
/// ```text
/// list:   [--package NAME] [--bin NAME]
/// scoped: [--package NAME] [--bin NAME] [--retries N] [--exact -- FILTER...]
/// ```
///
/// A missing value, a duplicate or out-of-order flag, an unknown token, a
/// non-canonical retry spelling, or a scoped-only flag on the list profile
/// fails closed. Fixed-argv profiles are refused here; they never parse
/// caller arguments.
pub fn parse_testd_slot_suffix(
    profile: &str,
    suffix: &[String],
) -> Result<TestdNextestSlots, TestdError> {
    if !is_slotted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "the admitted profile takes fixed argv; caller arguments are refused",
        });
    }
    let scoped = profile == TESTD_SCOPED_PROFILE;
    let mut slots = TestdNextestSlots::default();
    let mut index = 0;
    for flag in [TESTD_SLOT_PACKAGE, TESTD_SLOT_BINARY] {
        if suffix.get(index).is_some_and(|token| token == flag) {
            let name = suffix.get(index + 1).ok_or(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "slot flag is missing its value",
            })?;
            validate_slot_name(name)?;
            if flag == TESTD_SLOT_PACKAGE {
                slots.package = Some(name.clone());
            } else {
                slots.binary = Some(name.clone());
            }
            index += 2;
        }
    }
    if scoped
        && suffix
            .get(index)
            .is_some_and(|token| token == TESTD_SLOT_RETRIES)
    {
        let token = suffix.get(index + 1).ok_or(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "slot flag is missing its value",
        })?;
        let retries: u32 = token.parse().map_err(|_| TestdError::Invalid {
            field: "invocation.arguments",
            reason: "slot retry count is not a canonical number",
        })?;
        if retries.to_string() != *token {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "slot retry count is not a canonical number",
            });
        }
        slots.retries = Some(retries);
        index += 2;
    }
    if scoped
        && suffix
            .get(index)
            .is_some_and(|token| token == TESTD_SLOT_EXACT)
    {
        if suffix
            .get(index + 1)
            .is_none_or(|token| token != TESTD_SLOT_SEPARATOR)
        {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "slot filters require the exact separator",
            });
        }
        let filters = &suffix[index + 2..];
        if filters.is_empty() {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "slot filter set is empty",
            });
        }
        for filter in filters {
            validate_slot_filter(filter)?;
        }
        slots.filters = filters.to_vec();
        index = suffix.len();
    }
    if index != suffix.len() {
        return Err(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "slot suffix carries an unknown, duplicate, or out-of-order token",
        });
    }
    Ok(slots)
}

/// Renders the complete sealed argv for one slotted profile: the fixed
/// prefix plus the canonical slot rendering.
///
/// Every slot is revalidated here, so the renderer never trusts
/// pre-validated input. The rendering equals the nextest owner's
/// `NextestCommand::list` / `run_scoped` output for the same slots.
pub fn render_testd_slotted_argv(
    profile: &str,
    slots: &TestdNextestSlots,
) -> Result<Vec<String>, TestdError> {
    let prefix = testd_slotted_prefix(profile).ok_or(TestdError::Invalid {
        field: "profile",
        reason: "only the slotted list and scoped profiles take slot arguments",
    })?;
    let scoped = profile == TESTD_SCOPED_PROFILE;
    if let Some(package) = &slots.package {
        validate_slot_name(package)?;
    }
    if let Some(binary) = &slots.binary {
        validate_slot_name(binary)?;
    }
    if !scoped && (slots.retries.is_some() || !slots.filters.is_empty()) {
        return Err(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "retries and filters are scoped-run slots only",
        });
    }
    for filter in &slots.filters {
        validate_slot_filter(filter)?;
    }
    let mut argv: Vec<String> = prefix.iter().map(ToString::to_string).collect();
    if let Some(package) = &slots.package {
        argv.push(TESTD_SLOT_PACKAGE.to_owned());
        argv.push(package.clone());
    }
    if let Some(binary) = &slots.binary {
        argv.push(TESTD_SLOT_BINARY.to_owned());
        argv.push(binary.clone());
    }
    if scoped {
        if let Some(retries) = slots.retries {
            argv.push(TESTD_SLOT_RETRIES.to_owned());
            argv.push(retries.to_string());
        }
        if !slots.filters.is_empty() {
            argv.push(TESTD_SLOT_EXACT.to_owned());
            argv.push(TESTD_SLOT_SEPARATOR.to_owned());
            argv.extend(slots.filters.iter().cloned());
        }
    }
    Ok(argv)
}

/// Encodes validated list slot arguments in canonical order.
pub fn encode_testd_list_slots(
    package: Option<&str>,
    binary: Option<&str>,
) -> Result<Vec<String>, TestdError> {
    let mut suffix = Vec::new();
    if let Some(package) = package {
        validate_slot_name(package)?;
        suffix.push(TESTD_SLOT_PACKAGE.to_owned());
        suffix.push(package.to_owned());
    }
    if let Some(binary) = binary {
        validate_slot_name(binary)?;
        suffix.push(TESTD_SLOT_BINARY.to_owned());
        suffix.push(binary.to_owned());
    }
    Ok(suffix)
}

/// Encodes validated scoped slot arguments in canonical order.
pub fn encode_testd_scoped_slots(
    package: Option<&str>,
    binary: Option<&str>,
    retries: Option<u32>,
    filters: &[String],
) -> Result<Vec<String>, TestdError> {
    let slots = TestdNextestSlots {
        package: package.map(str::to_owned),
        binary: binary.map(str::to_owned),
        retries,
        filters: filters.to_vec(),
    };
    let argv = render_testd_slotted_argv(TESTD_SCOPED_PROFILE, &slots)?;
    Ok(argv[TESTD_PRODUCTIVE_PROFILE_ARGV.len()..].to_vec())
}

/// Builds the typed invocation for one slotted discovery submission.
///
/// The template supplies request identity, instrument, target, scope, and
/// clock; this constructor binds the TEST kind, the list profile, and the
/// validated slot suffix. The result submits through the ordinary
/// [`TestdStore::submit`] path.
pub fn testd_list_invocation(
    template: &InstrumentInvocation,
    package: Option<&str>,
    binary: Option<&str>,
) -> Result<InstrumentInvocation, TestdError> {
    template
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let arguments = encode_testd_list_slots(package, binary)?;
    let mut invocation = template.clone();
    invocation.kind = InstrumentKind::Test;
    invocation.profile = TESTD_LIST_PROFILE.to_owned();
    invocation.arguments = arguments;
    invocation
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    Ok(invocation)
}

/// Builds the typed invocation for one slotted scoped-run submission.
///
/// The template supplies request identity, instrument, target, scope, and
/// clock; this constructor binds the TEST kind, the scoped profile, and
/// the validated slot suffix. The result submits through the ordinary
/// [`TestdStore::submit`] path.
pub fn testd_scoped_invocation(
    template: &InstrumentInvocation,
    package: Option<&str>,
    binary: Option<&str>,
    retries: Option<u32>,
    filters: &[String],
) -> Result<InstrumentInvocation, TestdError> {
    template
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let arguments = encode_testd_scoped_slots(package, binary, retries, filters)?;
    let mut invocation = template.clone();
    invocation.kind = InstrumentKind::Test;
    invocation.profile = TESTD_SCOPED_PROFILE.to_owned();
    invocation.arguments = arguments;
    invocation
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    Ok(invocation)
}

/// Validates one Cargo package/binary slot name.
///
/// Admitted names use Cargo's common ASCII package/target characters and
/// cannot start with `-`. Mirrors the nextest owner's slot validation.
fn validate_slot_name(value: &str) -> Result<(), TestdError> {
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+'))
    {
        return Err(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "slot name is not an admitted Cargo target name",
        });
    }
    validate_text(value, "invocation.arguments")
}

/// Validates one exact test filter. Filters are passed as individual argv
/// values after `--`; controls are rejected and no shell command is built.
fn validate_slot_filter(value: &str) -> Result<(), TestdError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(TestdError::Invalid {
            field: "invocation.arguments",
            reason: "slot filter is not an exact discovered test identity",
        });
    }
    Ok(())
}

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_jobs_v1");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_events_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_meta_v1");
/// Authenticated frame identities retained beside durable productive jobs.
/// Additive owner table: existing stores migrate idempotently without
/// rewriting job payloads.
const ADMITTED_IDENTITIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("testd_admitted_identities_v1");
/// Durable capability-scoped TestD→Kernel call intents. Store effect outcomes
/// remain owned by the Kernel issuer; this table records only the consumer's
/// one-use token binding and bounded status projection.
const BLOB_PROCESS_STREAM_CALLS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("testd_blob_process_stream_calls_v1");

/// Persistent daemon failures.
#[derive(Debug, Error)]
pub enum TestdError {
    /// The supplied identity or policy value is invalid.
    #[error("invalid {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    /// A job was submitted again with a different immutable payload.
    #[error("job {0} already exists with a different payload")]
    JobConflict(String),
    /// The requested state change is not valid for the current state.
    #[error("job {job_id} cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        job_id: String,
        from: JobState,
        to: JobState,
    },
    /// The lease is absent, expired, or belongs to another worker.
    #[error("lease rejected for job {0}")]
    LeaseRejected(String),
    /// The durable database could not complete an operation.
    #[error("database error: {0}")]
    Database(String),
    /// A persisted record was not decodable.
    #[error("corrupt persisted record: {0}")]
    Corrupt(String),
    /// A contract supplied by an instrument or process adapter is invalid.
    #[error("contract validation failed: {0}")]
    Contract(String),
    /// The execution-contour grant tuple could not be serialized exactly.
    #[error("execution contour grant digest serialization failed")]
    GrantDigestSerialization,
    /// The durable plane only admits test profiles.
    #[error("testd accepts only TEST instrument invocations")]
    WrongInstrumentKind,
    /// The instrument request and process admission were not bound together.
    #[error("instrument and process admissions are not bound")]
    InvalidBinding,
    /// A declared exclusive resource or serial group is held by another
    /// running job, so this claim would overlap. Fail-closed: the job is
    /// refused, never started concurrently.
    #[error("declared resource conflict: {0}")]
    ResourceConflict(String),
}

fn database<E: std::fmt::Display>(error: E) -> TestdError {
    TestdError::Database(error.to_string())
}

/// Default job class for a job persisted before job classes were declared.
/// A verification job is the productive TestD profile, so the default must not
/// silently demote an older verification job to a background lane.
fn default_job_class() -> JobClass {
    JobClass::Verification
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), TestdError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(TestdError::Invalid {
            field,
            reason: "must be non-blank and control-free",
        });
    }
    Ok(())
}

/// Durable lifecycle of a scheduled test.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    RetryWait,
    Succeeded,
    Failed,
    Cancelled,
    Quarantined,
}

impl JobState {
    /// Whether no worker may claim this job again.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Quarantined
        )
    }
}

/// The serializable portion of a one-shot process admission.
///
/// `ProcessRequest` intentionally cannot be cloned or deserialized: its permit
/// is a consuming capability.  Testd persists this identity projection and
/// receives a freshly-issued request from Kernel for each physical attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAdmission {
    /// Kernel process-job identity bound to the consuming permit.
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: EpochId,
    pub invocation_digest: String,
}

impl ProcessAdmission {
    fn from_request(request: &ProcessRequest) -> Self {
        Self {
            job_id: request.job_id().as_str().to_owned(),
            operation_id: request.operation_id().as_str().to_owned(),
            process_tree_id: request.process_tree_id().as_str().to_owned(),
            generation: request.generation().get(),
            authority_epoch: request.fence().authority_epoch().clone(),
            invocation_digest: request.invocation_digest().to_owned(),
        }
    }
}

/// Evidence returned by the Kernel/Governor admission provider.
///
/// The consuming [`ProcessRequest`] is already authenticated by Kernel. The
/// contour and grant identity remain inert provider evidence until this crate
/// privately seals them into [`ProcessAdmissionPermit`].
#[derive(Debug)]
pub struct KernelProcessAdmissionEvidence {
    pub process: ProcessRequest,
    pub contour_root: String,
    pub grant_id: String,
}

/// Public neutral seam for the external Kernel/Governor admission owner.
///
/// Implementations return the already-issued one-shot process request and
/// issuer-selected contour evidence. They never construct a Testd grant or
/// permit; [`issue_process_admission`] performs that private sealing step.
pub trait KernelProcessAdmissionProvider: Send + Sync {
    fn admit(
        &self,
        request: &KernelProcessAdmissionRequest,
    ) -> Result<KernelProcessAdmissionEvidence, TestdError>;
}

/// Seals one provider response into a consuming, non-serializable permit.
pub fn issue_process_admission(
    provider: &dyn KernelProcessAdmissionProvider,
    request: &KernelProcessAdmissionRequest,
) -> Result<ProcessAdmissionPermit, TestdError> {
    request
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let evidence = provider.admit(request)?;
    evidence
        .process
        .validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    if evidence.process.job_id().as_str() != request.job_id
        || evidence.process.operation_id().as_str()
            != request.invocation.request.request_id.as_str()
        || evidence.process.working_directory() != request.source_root
        || evidence
            .process
            .environment()
            .non_secret()
            .get("CARGO_TARGET_DIR")
            != Some(&request.target_root)
        || evidence
            .process
            .environment()
            .non_secret()
            .get("CARGO_HOME")
            != Some(&request.cache_root)
        || !evidence
            .process
            .fence()
            .authority_epoch()
            .is_same_authority(&request.invocation.request.state_fence.authority_epoch)
        || evidence.process.generation().get()
            != request
                .invocation
                .request
                .state_fence
                .resource_generation
                .value()
    {
        return Err(TestdError::InvalidBinding);
    }
    let grant = ExecutionContourGrant::issue(
        evidence.contour_root,
        request.job_id.clone(),
        request.invocation.request.request_id.as_str().to_owned(),
        &evidence.process,
        evidence.grant_id,
    )?;
    ProcessAdmissionPermit::issued(evidence.process, grant)
}

/// Governor/Kernel-issued external execution contour grant.
///
/// Fields are private and the grant is neither deserializable nor cloneable.
/// Only the injected issuer boundary can produce the consuming permit that
/// carries this grant with its one-shot [`ProcessRequest`].
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContourGrant {
    contour_root: String,
    job_id: String,
    invocation_id: String,
    operation_id: String,
    process_tree_id: String,
    authority_epoch: EpochId,
    resource_generation: u64,
    grant_id: String,
    grant_digest: String,
}

impl ExecutionContourGrant {
    /// Constructs a grant inside the trusted issuer boundary.
    ///
    /// The N4 Kernel/Governor adapter is the only caller. Keeping this seam
    /// crate-private prevents a deserialized or ordinary caller-owned value
    /// from minting execution authority.
    #[allow(dead_code)]
    pub(crate) fn issue(
        contour_root: impl Into<String>,
        job_id: impl Into<String>,
        invocation_id: impl Into<String>,
        process: &ProcessRequest,
        grant_id: impl Into<String>,
    ) -> Result<Self, TestdError> {
        let grant = Self {
            contour_root: contour_root.into(),
            job_id: job_id.into(),
            invocation_id: invocation_id.into(),
            operation_id: process.operation_id().as_str().to_owned(),
            process_tree_id: process.process_tree_id().as_str().to_owned(),
            authority_epoch: process.fence().authority_epoch().clone(),
            resource_generation: process.generation().get(),
            grant_id: grant_id.into(),
            grant_digest: String::new(),
        };
        grant.with_digest()
    }

    #[allow(dead_code)]
    fn with_digest(mut self) -> Result<Self, TestdError> {
        for (field, value) in [
            ("contour_root", self.contour_root.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
            ("grant_id", self.grant_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        self.grant_digest = contour_grant_digest(&self)?;
        Ok(self)
    }

    /// Returns the issuer-selected contour root; it grants no authority alone.
    pub fn contour_root(&self) -> &str {
        &self.contour_root
    }

    pub fn validate_for_process(
        &self,
        job_id: &str,
        invocation_id: &str,
        process: &ProcessRequest,
    ) -> Result<(), TestdError> {
        self.validate_integrity()?;
        if self.job_id != job_id
            || self.invocation_id != invocation_id
            || self.operation_id != process.operation_id().as_str()
            || self.process_tree_id != process.process_tree_id().as_str()
            || !self
                .authority_epoch
                .is_same_authority(process.fence().authority_epoch())
            || self.resource_generation != process.generation().get()
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("contour_root", self.contour_root.as_str()),
            ("job_id", self.job_id.as_str()),
            ("invocation_id", self.invocation_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("process_tree_id", self.process_tree_id.as_str()),
            ("grant_id", self.grant_id.as_str()),
        ] {
            validate_text(value, field)?;
        }
        if self.grant_digest != contour_grant_digest(self)? {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// One-shot Kernel process permit plus its immutable external-contour grant.
///
/// This type intentionally has no `Clone`, `Serialize`, or `Deserialize`
/// implementation. The issuer is the sole provenance boundary.
#[derive(Debug)]
pub struct ProcessAdmissionPermit {
    request: ProcessRequest,
    grant: ExecutionContourGrant,
}

impl ProcessAdmissionPermit {
    /// Seals the consuming request with the issuer's already-bound grant.
    ///
    /// This remains crate-private with the grant constructor so only the
    /// injected authority adapter can establish permit provenance.
    #[allow(dead_code)]
    pub(crate) fn issued(
        request: ProcessRequest,
        grant: ExecutionContourGrant,
    ) -> Result<Self, TestdError> {
        grant.validate_for_process(request.job_id().as_str(), &grant.invocation_id, &request)?;
        Ok(Self { request, grant })
    }

    /// Borrows the consuming request for pre-consumption validation only.
    pub fn request(&self) -> &ProcessRequest {
        &self.request
    }

    /// Borrows the issuer grant without exposing mutable construction.
    pub fn grant(&self) -> &ExecutionContourGrant {
        &self.grant
    }

    pub fn into_parts(self) -> (ProcessRequest, ExecutionContourGrant) {
        (self.request, self.grant)
    }
}

fn contour_grant_digest(grant: &ExecutionContourGrant) -> Result<String, TestdError> {
    let bytes = serde_json::to_vec(&(
        &grant.contour_root,
        &grant.job_id,
        &grant.invocation_id,
        &grant.operation_id,
        &grant.process_tree_id,
        &grant.authority_epoch,
        grant.resource_generation,
        &grant.grant_id,
    ))
    .map_err(|_| TestdError::GrantDigestSerialization)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Canonical roots bound to one isolated execution job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetRoots {
    /// Kernel/Governor-issued external execution contour.
    pub allowed_contour_root: String,
    /// Source/worktree root used as the process working directory.
    pub source_root: String,
    /// Dedicated external Cargo target/build root.
    pub target_root: String,
    /// Cache root; D0 requires this to be the same canonical root as target.
    pub cache_root: String,
}

impl TargetRoots {
    /// Creates and validates a path-identity projection.
    pub fn new(
        allowed_contour_root: impl Into<String>,
        source_root: impl Into<String>,
        target_root: impl Into<String>,
        cache_root: impl Into<String>,
    ) -> Result<Self, TestdError> {
        let roots = Self {
            allowed_contour_root: allowed_contour_root.into(),
            source_root: source_root.into(),
            target_root: target_root.into(),
            cache_root: cache_root.into(),
        };
        roots.validate()?;
        Ok(roots)
    }

    /// Revalidates immutable path identity before a later execution stage.
    pub fn validate(&self) -> Result<(), TestdError> {
        let contour = validate_root_identity(&self.allowed_contour_root, "allowed_contour_root")?;
        let source = validate_root_identity(&self.source_root, "source_root")?;
        let target = validate_root_identity(&self.target_root, "target_root")?;
        let cache = validate_root_identity(&self.cache_root, "cache_root")?;
        if cache != target {
            return Err(TestdError::Invalid {
                field: "cache_root",
                reason: "must equal the canonical target_root in the active profile",
            });
        }
        if paths_overlap(&contour, &source) {
            return Err(TestdError::Invalid {
                field: "allowed_contour_root",
                reason: "external execution contour must not contain or be contained by source_root",
            });
        }
        if !is_strict_descendant(&target, &contour) {
            return Err(TestdError::Invalid {
                field: "target_root",
                reason: "must be a strict descendant of the allowed external execution contour",
            });
        }
        if paths_overlap(&source, &target) {
            return Err(TestdError::Invalid {
                field: "target_root",
                reason: "external target root must not contain or be contained by source_root",
            });
        }
        Ok(())
    }
}

/// A durable test job plus the process identity it must be re-issued for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestJob {
    /// Caller-owned idempotency key.
    pub job_id: String,
    /// Project-local FIFO ordering key.
    pub project_id: String,
    /// Monotonic sequence assigned by the durable store.
    pub project_sequence: u64,
    /// Instrument contract to execute.
    pub invocation: InstrumentInvocation,
    /// Exact runner-admitted full-profile stage identity, when the caller
    /// entered through the stage dispatch path. Older jobs retain `None` and
    /// cannot be upgraded from legacy profile labels alone.
    #[serde(default)]
    pub stage_request: Option<InstrumentStageRequest>,
    /// Exact owner-observed installed tool identities retained for worker-side
    /// currentness re-observation. Productive submissions require this value.
    #[serde(default)]
    pub provider_tool_observation: Option<TestdToolObservation>,
    /// Secret-safe child environment projection admitted with the process.
    /// Productive submissions retain it so replay currentness can be rebuilt
    /// after restart without consulting ambient environment state.
    #[serde(default)]
    pub provider_environment_projection: Option<EnvironmentProjection>,
    /// Kernel-issued opaque grant and bounded one-use operation tokens. The
    /// TestD daemon carries these references but cannot derive authority from
    /// them.
    #[serde(default)]
    pub blob_process_stream_grant: Option<TestdBlobProcessStreamGrant>,
    /// Identity projection of the consuming process contract.
    pub process: ProcessAdmission,
    /// Canonical roots retained for later execution/reconciliation checks.
    pub target_roots: TargetRoots,
    /// Owner-issued workspace/checkout/class binding the roots were verified
    /// against (issue #1806). `None` preserves the pre-binding authority for
    /// rows admitted without a layout; it never selects a fallback root.
    #[serde(default)]
    pub target_layout: Option<TargetLayoutBinding>,
    /// Governed work-execution envelope allocated at submission (issue
    /// #1897): worktree, fingerprint, mode, namespace inputs, claims, and
    /// leases. `None` preserves the pre-lane authority for rows admitted
    /// without a lane; it never selects fallback identity.
    #[serde(default)]
    pub work_envelope: Option<GovernedWorkEnvelope>,
    /// Fixture namespace allocated for this work item at admission (issue
    /// #1897, W4), derived by the retained envelope from the whole lane
    /// tuple — work item, build mode, and normalized fingerprint — and never
    /// from the worktree, the project id, the job id, or a counter. `None`
    /// preserves the pre-lane authority for rows admitted without a lane; it
    /// never selects a fallback namespace.
    #[serde(default)]
    pub fixture_namespace: Option<String>,
    /// Scheduling priority; larger values run first among ready heads.
    pub priority: i32,
    /// Declared job class. The class, not the raw `priority` integer, is the
    /// I2.22 admission order; a background class is never ordered ahead of
    /// Kernel, Watchdog, Control Reserve, verification, or interactive work.
    #[serde(default = "default_job_class")]
    pub job_class: JobClass,
    /// Declared resource weight, exclusive resources, and serial group. An
    /// older job without the field keeps the default parallel declaration.
    #[serde(default)]
    pub resource_profile: TestResourceProfile,
    /// Leases allocated to this job while it runs, and the scheduling decision
    /// that produced them. Retained in the job so the work item execution
    /// record carries the decision and its leases after the worker returns.
    #[serde(default)]
    pub scheduling: Option<SchedulingDecision>,
    /// Durable lifecycle state.
    pub state: JobState,
    /// Number of physical execution attempts.
    pub attempts: u32,
    /// Earliest time at which the job can be claimed.
    pub not_before_ms: u64,
    /// Worker lease, if the job is running.
    pub lease: Option<Lease>,
    /// Last execution projection, retained across restarts.
    pub execution: Option<ExecutionStatus>,
    /// Verifier output, when a verifier has completed.
    pub verification: Option<VerificationRun>,
    /// Exact receipt identity retained with a completed attempt.
    pub receipt: Option<ReceiptBinding>,
    /// Full validated receipt retained with the durable attempt.  The
    /// binding above is the compact scheduling projection; this record is
    /// the only source from which a canonical verifier fact may recover raw
    /// artifact lineage after the worker has returned.
    #[serde(default)]
    pub verification_receipt: Option<VerificationReceipt>,
    /// Exact request identity and canonical verifier plan captured before a
    /// productive verifier is dispatched. The TestD owner stores the bytes;
    /// the daemon rehydrates and compares the Governor-owned plan at publish.
    #[serde(default)]
    pub verifier_dispatch: Option<TestdVerifierDispatchBinding>,
    /// Actual repository identity observed immediately before productive
    /// worker claim. The terminal receipt must retain this exact baseline.
    #[serde(default)]
    pub source_observation_before: Option<TestdSourceObservation>,
    /// Durable handoff to the daemon's canonical verifier-fact publisher.
    /// A pending marker is never a completion receipt.
    #[serde(default)]
    pub terminal_publication: Option<TestdTerminalPublication>,
    /// Last durable mutation time.
    pub updated_at_ms: u64,
    /// Immutable digest of the submitted contracts and scheduling fields.
    pub payload_digest: String,
}

/// Opaque stream capability and ordered single-use call references retained
/// against the durable productive job that received them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdBlobProcessStreamGrant {
    pub capability_ref: String,
    pub binding_sha256: String,
    pub process_binding_sha256: String,
    pub fence_sha256: String,
    pub policy_sha256: String,
    pub source_set_sha256: String,
    pub currentness_sha256: String,
    pub revoked_at_ms: Option<u64>,
    pub tokens: Vec<TestdBlobProcessStreamTokenRef>,
}

impl TestdBlobProcessStreamGrant {
    pub fn validate(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("blob_stream.capability_ref", self.capability_ref.as_str()),
            ("blob_stream.binding_sha256", self.binding_sha256.as_str()),
            (
                "blob_stream.process_binding_sha256",
                self.process_binding_sha256.as_str(),
            ),
            ("blob_stream.fence_sha256", self.fence_sha256.as_str()),
            ("blob_stream.policy_sha256", self.policy_sha256.as_str()),
            ("blob_stream.source_set_sha256", self.source_set_sha256.as_str()),
            ("blob_stream.currentness_sha256", self.currentness_sha256.as_str()),
        ] {
            validate_text(value, field)?;
        }
        for (field, value) in [
            ("blob_stream.binding_sha256", self.binding_sha256.as_str()),
            (
                "blob_stream.process_binding_sha256",
                self.process_binding_sha256.as_str(),
            ),
            ("blob_stream.fence_sha256", self.fence_sha256.as_str()),
            ("blob_stream.policy_sha256", self.policy_sha256.as_str()),
            ("blob_stream.source_set_sha256", self.source_set_sha256.as_str()),
            ("blob_stream.currentness_sha256", self.currentness_sha256.as_str()),
        ] {
            if !is_binding_digest(value) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        if self.tokens.is_empty() || self.tokens.len() > 8_336 {
            return Err(TestdError::Invalid {
                field: "blob_stream.tokens",
                reason: "grant must contain a bounded non-empty token sequence",
            });
        }
        if self.revoked_at_ms == Some(0) {
            return Err(TestdError::Invalid {
                field: "blob_stream.revoked_at_ms",
                reason: "revocation clock must be non-zero",
            });
        }
        for (index, token) in self.tokens.iter().enumerate() {
            validate_text(&token.reference, "blob_stream.token.reference")?;
            if token.ordinal as usize != index + 1 {
                return Err(TestdError::Invalid {
                    field: "blob_stream.tokens",
                    reason: "token ordinals must be contiguous from one",
                });
            }
            if self.tokens[..index]
                .iter()
                .any(|previous| previous.reference == token.reference)
            {
                return Err(TestdError::Invalid {
                    field: "blob_stream.tokens",
                    reason: "token references must be unique within a grant",
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdBlobProcessStreamTokenRef {
    pub reference: String,
    pub ordinal: u32,
}

/// Compact Kernel-return projection retained by TestD. It intentionally has
/// no field for stream chunk bytes or RequestIdentity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TestdBlobProcessStreamCallOutcome {
    Completed {
        response_sha256: String,
        response_ref: Option<String>,
    },
    NotStarted,
    Unknown,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TestdBlobProcessStreamCallState {
    Reserved,
    Dispatched,
    Completed(TestdBlobProcessStreamCallOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdBlobProcessStreamCallRecord {
    pub job_id: String,
    pub capability_ref: String,
    pub token_ref: String,
    pub ordinal: u32,
    pub operation_sha256: String,
    pub state: TestdBlobProcessStreamCallState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestdBlobProcessStreamReserve {
    Reserved,
    Replay(TestdBlobProcessStreamCallOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestdBlobProcessStreamResolution {
    NotReady,
    Unknown,
    Completed(TestdBlobProcessStreamCallOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TestdBlobProcessStreamGrantResolution {
    NotFound,
    Revoked,
    Active(TestdBlobProcessStreamGrant),
}

/// Immutable owner binding persisted before a productive verifier starts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdVerifierDispatchBinding {
    pub request_identity: RequestIdentity,
    pub operation_id: String,
    pub canonical_plan_json: String,
    pub canonical_plan_sha256: String,
}

/// Closed Git subcommand set admitted for one source observation.
///
/// The set is closed: [`TestdSourceObservation::capture`] seals exactly
/// these argument vectors, and the port receives only a value of this
/// type. No caller text, no shell string, and no arbitrary executable
/// path can reach the physical process contour through this port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceObservationGitCommand {
    /// `git rev-parse --show-toplevel`
    ShowTopLevel,
    /// `git rev-parse --abbrev-ref HEAD`
    AbbreviatedBranch,
    /// `git rev-parse --verify HEAD^{commit}`
    VerifiedCommit,
    /// `git status --porcelain=v2 -z --untracked-files=all`
    PorcelainV2Status,
    /// `git diff --binary --no-ext-diff HEAD --`
    BinaryWorktreeDiff,
    /// `git ls-files --others --exclude-standard -z`
    UntrackedListing,
}

impl SourceObservationGitCommand {
    /// Returns the exact sealed argv for this closed subcommand.
    #[must_use]
    pub const fn argv(self) -> &'static [&'static str] {
        match self {
            Self::ShowTopLevel => &["rev-parse", "--show-toplevel"],
            Self::AbbreviatedBranch => &["rev-parse", "--abbrev-ref", "HEAD"],
            Self::VerifiedCommit => &["rev-parse", "--verify", "HEAD^{commit}"],
            Self::PorcelainV2Status => &["status", "--porcelain=v2", "-z", "--untracked-files=all"],
            Self::BinaryWorktreeDiff => &["diff", "--binary", "--no-ext-diff", "HEAD", "--"],
            Self::UntrackedListing => &["ls-files", "--others", "--exclude-standard", "-z"],
        }
    }
}

/// Physical Git execution port for one source observation.
///
/// `eliot-testd-core` owns durable scheduling state and never owns
/// physical process mechanics: the governing `ProcessExecutor`/Job
/// Object contour (#100) launches every child. This crate contributes
/// only the closed subcommand vocabulary and the digest contract; the
/// composition root owns the bound implementation that resolves the
/// installed `git` executable, seals a `ProcessIntent` plus dispatch
/// permit, and reads the executor's bounded captured streams.
///
/// The port carries no authority of its own. A successful return proves
/// only that one admitted Git invocation exited successfully with
/// complete, bounded, untruncated stdout.
pub trait SourceObservationGitPort: Send + Sync {
    /// Runs one closed Git subcommand in `repository_root` and returns its
    /// exact complete stdout.
    ///
    /// # Errors
    /// Returns an error when the governed contour refuses the launch,
    /// the child does not exit successfully, or the bounded capture is
    /// incomplete or truncated. No partial observation is ever returned
    /// as success.
    fn run_git(
        &self,
        repository_root: &Path,
        command: SourceObservationGitCommand,
    ) -> Result<Vec<u8>, TestdError>;
}

/// Immutable observation of the source repository used by one verifier run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdSourceObservation {
    pub repository_root: String,
    pub branch: String,
    pub commit: String,
    pub dirty_state_sha256: String,
}

impl TestdSourceObservation {
    /// Reads the live Git repository identity and a content-bound working-tree
    /// digest through the governed process contour supplied by `git`.
    ///
    /// This crate never launches a child itself: every Git invocation is
    /// dispatched through `git`, whose production implementation is the
    /// composition root's `ProcessExecutor`. Any unavailable, oversized,
    /// truncated, or non-success observation fails closed.
    pub fn capture(
        repository_root: impl AsRef<Path>,
        git: &dyn SourceObservationGitPort,
    ) -> Result<Self, TestdError> {
        const MAX_GIT_OUTPUT: usize = 64 * 1024 * 1024;
        const MAX_OBSERVED_SOURCE_FILE_BYTES: usize = 64 * 1024 * 1024;
        let repository_root =
            std::fs::canonicalize(repository_root).map_err(|_| TestdError::Invalid {
                field: "source_observation.repository_root",
                reason: "source root cannot be canonicalized",
            })?;
        if !repository_root.is_dir() {
            return Err(TestdError::Invalid {
                field: "source_observation.repository_root",
                reason: "source root is not a directory",
            });
        }
        let run_git = |command: SourceObservationGitCommand| -> Result<Vec<u8>, TestdError> {
            let stdout = git.run_git(&repository_root, command)?;
            if stdout.len() > MAX_GIT_OUTPUT {
                return Err(TestdError::Invalid {
                    field: "source_observation.git",
                    reason: "Git source observation failed or exceeded its bound",
                });
            }
            Ok(stdout)
        };
        let decode_text = |bytes: Vec<u8>, field| -> Result<String, TestdError> {
            String::from_utf8(bytes)
                .map(|value| value.trim().to_owned())
                .map_err(|_| TestdError::Invalid {
                    field,
                    reason: "Git returned non-UTF-8 source identity",
                })
        };
        let top_level = decode_text(
            run_git(SourceObservationGitCommand::ShowTopLevel)?,
            "source_observation.repository_root",
        )?;
        let observed_root = std::fs::canonicalize(top_level).map_err(|_| TestdError::Invalid {
            field: "source_observation.repository_root",
            reason: "Git repository root cannot be canonicalized",
        })?;
        if observed_root != repository_root {
            return Err(TestdError::Invalid {
                field: "source_observation.repository_root",
                reason: "admitted source root is not the Git repository root",
            });
        }
        let branch = decode_text(
            run_git(SourceObservationGitCommand::AbbreviatedBranch)?,
            "source_observation.branch",
        )?;
        let branch = if branch == "HEAD" {
            "detached".to_owned()
        } else {
            branch
        };
        let commit = decode_text(
            run_git(SourceObservationGitCommand::VerifiedCommit)?,
            "source_observation.commit",
        )?;
        let status = run_git(SourceObservationGitCommand::PorcelainV2Status)?;
        let diff = run_git(SourceObservationGitCommand::BinaryWorktreeDiff)?;
        let untracked = run_git(SourceObservationGitCommand::UntrackedListing)?;
        let mut untracked_paths = untracked
            .split(|byte| *byte == 0)
            .filter(|path| !path.is_empty())
            .map(|path| {
                String::from_utf8(path.to_vec()).map_err(|_| TestdError::Invalid {
                    field: "source_observation.untracked_path",
                    reason: "Git returned a non-UTF-8 untracked path",
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        untracked_paths.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"eliot-testd-source-dirty-state-v1\0");
        hash_source_part(&mut hasher, &status);
        hash_source_part(&mut hasher, &diff);
        for relative in untracked_paths {
            let relative_path = Path::new(&relative);
            if relative_path.is_absolute()
                || relative_path.components().any(|component| {
                    matches!(
                        component,
                        Component::ParentDir | Component::RootDir | Component::Prefix(_)
                    )
                })
            {
                return Err(TestdError::Invalid {
                    field: "source_observation.untracked_path",
                    reason: "Git returned an untracked path outside the source root",
                });
            }
            let path = repository_root.join(relative_path);
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| TestdError::Invalid {
                field: "source_observation.untracked_path",
                reason: "untracked source path cannot be observed",
            })?;
            hasher.update((relative.len() as u64).to_be_bytes());
            hasher.update(relative.as_bytes());
            if is_reparse_point(&metadata) {
                let target = std::fs::read_link(&path).map_err(|_| TestdError::Invalid {
                    field: "source_observation.untracked_path",
                    reason: "untracked link target cannot be observed",
                })?;
                hasher.update(b"link\0");
                hash_source_part(&mut hasher, target.to_string_lossy().as_bytes());
            } else {
                let bytes = std::fs::read(&path).map_err(|_| TestdError::Invalid {
                    field: "source_observation.untracked_path",
                    reason: "untracked file cannot be read for source observation",
                })?;
                if bytes.len() > MAX_OBSERVED_SOURCE_FILE_BYTES {
                    return Err(TestdError::Invalid {
                        field: "source_observation.untracked_path",
                        reason: "untracked file exceeds the source-observation bound",
                    });
                }
                hasher.update(b"file\0");
                hash_source_part(&mut hasher, &bytes);
            }
        }
        let observation = Self {
            repository_root: repository_root.to_string_lossy().into_owned(),
            branch,
            commit,
            dirty_state_sha256: format!("{:x}", hasher.finalize()),
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), TestdError> {
        let commit_valid = matches!(self.commit.len(), 40 | 64)
            && self
                .commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !Path::new(&self.repository_root).is_absolute()
            || self.branch.trim().is_empty()
            || self.branch.chars().any(char::is_control)
            || !commit_valid
            || !is_binding_digest(&self.dirty_state_sha256)
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }
}

/// Before/after source identity around one physical verifier execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdSourceObservationRange {
    pub before: TestdSourceObservation,
    pub after: TestdSourceObservation,
}

impl TestdSourceObservationRange {
    pub fn validate(&self) -> Result<(), TestdError> {
        self.before.validate()?;
        self.after.validate()?;
        if self.before.repository_root != self.after.repository_root {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    #[must_use]
    pub fn unchanged(&self) -> bool {
        self.before == self.after
    }
}

fn hash_source_part(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

impl TestdVerifierDispatchBinding {
    /// Checks request, operation and plan identity against the durable job.
    /// Governor must still re-read the live task and plan before publishing.
    pub fn validate_for_job(&self, job: &TestJob) -> Result<(), TestdError> {
        self.request_identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        let metadata = &self.request_identity.request.metadata;
        let Some(task_id) = metadata.task_id.as_ref() else {
            return Err(TestdError::InvalidBinding);
        };
        let task_revision = self
            .request_identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value())
            .ok_or(TestdError::InvalidBinding)?;
        if self.operation_id.trim().is_empty() || self.operation_id.chars().any(char::is_control) {
            return Err(TestdError::InvalidBinding);
        }
        if metadata != &job.invocation.request
            || self.request_identity.request.state_fence != job.invocation.request.state_fence
            || self.operation_id != job.process.operation_id.as_str()
            || task_revision == 0
            || job.process.generation == 0
            || !job
                .process
                .authority_epoch
                .is_same_authority(&job.invocation.request.state_fence.authority_epoch)
        {
            return Err(TestdError::InvalidBinding);
        }
        let plan_value: serde_json::Value = serde_json::from_str(&self.canonical_plan_json)
            .map_err(|_| TestdError::InvalidBinding)?;
        let canonical =
            canonical_json_bytes(&plan_value).map_err(|_| TestdError::InvalidBinding)?;
        let canonical_text =
            String::from_utf8(canonical.clone()).map_err(|_| TestdError::InvalidBinding)?;
        if canonical_text != self.canonical_plan_json
            || sha256_hex(&canonical) != self.canonical_plan_sha256
            || plan_value
                .get("task_id")
                .and_then(serde_json::Value::as_str)
                != Some(task_id.as_str())
        {
            return Err(TestdError::InvalidBinding);
        }
        let verifier = plan_value
            .get("verifier")
            .and_then(serde_json::Value::as_object)
            .ok_or(TestdError::InvalidBinding)?;
        let invocation =
            serde_json::to_value(&job.invocation).map_err(|_| TestdError::InvalidBinding)?;
        for field in [
            "instrument",
            "kind",
            "profile",
            "target",
            "arguments",
            "declared_scope",
            "input_artifacts",
        ] {
            if verifier.get(field) != invocation.get(field) {
                return Err(TestdError::InvalidBinding);
            }
        }
        let evaluator = verifier
            .get("evaluator")
            .and_then(serde_json::Value::as_str)
            .ok_or(TestdError::InvalidBinding)?;
        let required_test_ids = verifier
            .get("required_test_ids")
            .and_then(serde_json::Value::as_array)
            .filter(|ids| !ids.is_empty())
            .ok_or(TestdError::InvalidBinding)?;
        let mut unique_test_ids = BTreeSet::new();
        for id in required_test_ids {
            let id = id.as_str().ok_or(TestdError::InvalidBinding)?;
            validate_text(id, "verifier_dispatch.required_test_id")?;
            if !unique_test_ids.insert(id) {
                return Err(TestdError::InvalidBinding);
            }
        }
        let planned = verifier
            .get("planned")
            .and_then(serde_json::Value::as_object)
            .ok_or(TestdError::InvalidBinding)?;
        let planned_id = planned
            .get("verifier_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(TestdError::InvalidBinding)?;
        let planned_scope = planned
            .get("scope")
            .and_then(serde_json::Value::as_str)
            .ok_or(TestdError::InvalidBinding)?;
        let declared_scope = verifier
            .get("declared_scope")
            .and_then(serde_json::Value::as_str)
            .ok_or(TestdError::InvalidBinding)?;
        let config_hash = planned
            .get("verifier_config_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or(TestdError::InvalidBinding)?;
        if planned_id != evaluator
            || planned_scope != declared_scope
            || !is_binding_digest(config_hash)
            || plan_value
                .get("work_scope_id")
                .and_then(serde_json::Value::as_str)
                .is_none()
        {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    /// Returns the exact non-empty required test IDs from the validated
    /// canonical verifier plan retained with this job.
    ///
    /// Runner replay must evaluate only the identities selected by the
    /// original plan; it must never infer required IDs from process output.
    pub fn required_test_ids_for_job(&self, job: &TestJob) -> Result<Vec<String>, TestdError> {
        self.validate_for_job(job)?;
        let plan_value: serde_json::Value = serde_json::from_str(&self.canonical_plan_json)
            .map_err(|_| TestdError::InvalidBinding)?;
        let ids = plan_value
            .get("verifier")
            .and_then(serde_json::Value::as_object)
            .and_then(|verifier| verifier.get("required_test_ids"))
            .and_then(serde_json::Value::as_array)
            .filter(|ids| !ids.is_empty())
            .ok_or(TestdError::InvalidBinding)?;
        ids.iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_owned)
                    .ok_or(TestdError::InvalidBinding)
            })
            .collect()
    }
}

/// Authenticated terminal notification for the daemon completion poller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestdTerminalCompletionNotice {
    pub job_id: String,
    pub receipt_sha256: String,
}

/// Persisted completion handoff. The receipt body is stored only after the
/// Governor returns a committed canonical WriteReceipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdTerminalPublication {
    pub receipt_sha256: String,
    #[serde(default)]
    pub committed_receipt_json: Option<String>,
}

/// Kernel-front-door payload for creating one productive verifier job.
///
/// The authenticated `RequestIdentity` is deliberately carried by the
/// enclosing Kernel frame, not by this payload. The Kernel owner persists
/// that frame identity beside the durable job before exposing it as a
/// pending dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdVerifierJobSubmission {
    pub job_id: String,
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    /// Exact runner-admitted profile/provider stage persisted with the job.
    /// Missing values decode only for legacy rows and fail productive submit.
    #[serde(default)]
    pub stage_request: Option<InstrumentStageRequest>,
    /// Owner-observed tool bytes and selected toolchain used to derive the
    /// provider freshness record; this is not inferred by the worker.
    pub provider_tool_observation: TestdToolObservation,
    /// Exact secret-safe process environment projection validated by the
    /// Kernel before admission and retained for worker re-observation.
    pub provider_environment_projection: EnvironmentProjection,
    pub target_roots: TargetRoots,
    /// Owner-issued layout binding the roots resolve from, when the
    /// submitting owner derived them from a workspace/checkout/class layout.
    #[serde(default)]
    pub target_layout: Option<TargetLayoutBinding>,
    /// Lane identity the work item is allocated in (issue #1897). The store
    /// allocates the governed envelope from this identity plus the declared
    /// resource claims in `metadata` and persists it on the job; `None`
    /// preserves the pre-lane authority for submissions whose lane producer
    /// does not exist yet.
    #[serde(default)]
    pub lane: Option<LaneIdentity>,
    pub priority: i32,
    /// Declared class and resource requirements for this verification job.
    /// A submission that omits it is a verification job with the default
    /// parallel declaration, never a background lane.
    #[serde(default)]
    pub metadata: JobSubmissionMetadata,
}

/// Authenticated Kernel owner-submit operation for one productive verifier.
/// The transport identity is carried by the enclosing Kernel frame; this
/// payload contains only the Governor-resolved project/source binding, the
/// typed invocation, and owner-observed tool material.
pub const TESTD_OWNER_SUBMIT_OPERATION: &str = "eliot.kernel.testd-owner-submit";
/// Current TestD owner operation wire revision.
pub const TESTD_OWNER_WIRE_VERSION: u16 = 1;
/// Submit-specific wire revision. Other TestD owner routes remain at v1.
pub const TESTD_OWNER_SUBMIT_WIRE_VERSION: u16 = 2;

/// Governor-resolved input to the Kernel-owned productive TestD owner.
/// `source_root` is the TaskContract WorkScope result; `project_id` is an
/// opaque project identity and is never interpreted as a filesystem path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdOwnerJobSubmission {
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    pub source_root: String,
    /// Exact runner-admitted stage identity. Productive owner submissions
    /// require a process stage; this carries no executable or authority.
    #[serde(default)]
    pub stage_request: Option<InstrumentStageRequest>,
}

impl TestdOwnerJobSubmission {
    pub fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.project_id, "project_id")?;
        validate_text(&self.source_root, "source_root")?;
        self.invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let stage = self.stage_request.as_ref().ok_or(TestdError::Invalid {
            field: "stage_request",
            reason: "productive owner submission requires the runner-admitted stage",
        })?;
        stage.validate()?;
        if self.invocation.kind != InstrumentKind::Test
            || self.invocation.profile != TESTD_PRODUCTIVE_PROFILE
            || !self.invocation.arguments.is_empty()
            || stage.invocation != self.invocation
            || stage.execution != StageExecutionKind::Process
            || stage.adapter != TESTD_PRODUCTIVE_ADAPTER
        {
            return Err(TestdError::Invalid {
                field: "stage_request",
                reason: "productive submission requires the registered Nextest process stage and no caller arguments",
            });
        }
        Ok(())
    }
}

/// Owner-observed installed tool identities and exact process environment
/// needed to reconstruct the registered productive ProcessIntent. The
/// Kernel rereads every executable and validates every environment binding
/// before it issues a process request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdProcessToolIntent {
    pub observation: TestdToolObservation,
}

/// Typed request for the authenticated Kernel owner-submit operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdOwnerSubmitRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub submission: TestdOwnerJobSubmission,
    pub process_tool: TestdProcessToolIntent,
    pub request_digest: String,
}

impl TestdOwnerSubmitRequest {
    /// Computes the request digest over all caller-presented inert terms.
    pub fn with_computed_digest(mut self) -> Result<Self, TestdError> {
        self.request_digest = self.compute_request_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Validates the closed operation, typed submission, tool observation,
    /// and canonical request digest. Filesystem facts are re-read by Kernel
    /// immediately before permit issuance.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.wire_id != TESTD_OWNER_SUBMIT_OPERATION
            || self.wire_version != TESTD_OWNER_SUBMIT_WIRE_VERSION
        {
            return Err(TestdError::Invalid {
                field: "owner_submit.wire",
                reason: "unsupported TestD owner-submit wire",
            });
        }
        self.submission.validate()?;
        self.process_tool.observation.validate()?;
        validate_text(&self.request_digest, "owner_submit.request_digest")?;
        if self.request_digest != self.compute_request_digest()? {
            return Err(TestdError::InvalidBinding);
        }
        Ok(())
    }

    fn compute_request_digest(&self) -> Result<String, TestdError> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            wire_id: &'a str,
            wire_version: u16,
            submission: &'a TestdOwnerJobSubmission,
            process_tool: &'a TestdProcessToolIntent,
        }
        let bytes = eliot_contracts::canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            submission: &self.submission,
            process_tool: &self.process_tool,
        })
        .map_err(|_| TestdError::GrantDigestSerialization)?;
        Ok(eliot_contracts::sha256_hex(&bytes))
    }
}

/// Typed directive for a productive TestD owner-submit refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestdOwnerSubmitDirective {
    /// A task-scoped effect cannot launch without an admitted task selection.
    TaskSelectionRequired,
}

/// Versioned, request-bound Kernel owner result for a productive submission.
///
/// The `outcome` tag makes a refusal a domain result rather than a transport
/// failure. Successful v2 submissions retain the exact durable admission
/// facts; denied submissions carry the original request digest and operation
/// identity so the caller can correlate the directive without retrying or
/// guessing whether a child was launched.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum TestdOwnerSubmitResponse {
    /// The productive job was durably admitted.
    Admitted {
        wire_id: String,
        wire_version: u16,
        request_digest: String,
        job_id: String,
        operation_id: String,
        authority_epoch: EpochId,
        generation: u64,
        payload_digest: String,
    },
    /// Admission stopped before any filesystem, store, or process effect.
    Denied {
        wire_id: String,
        wire_version: u16,
        request_digest: String,
        operation_id: String,
        directive: TestdOwnerSubmitDirective,
    },
}

impl TestdOwnerSubmitResponse {
    /// Checks the explicit submit-v2 envelope before it crosses the wire.
    pub fn validate(&self) -> Result<(), TestdError> {
        let (wire_id, wire_version, request_digest, operation_id) = match self {
            Self::Admitted {
                wire_id,
                wire_version,
                request_digest,
                operation_id,
                job_id,
                generation,
                payload_digest,
                ..
            } => {
                validate_text(job_id, "owner_submit.response.job_id")?;
                if *generation == 0 || !is_binding_digest(payload_digest) {
                    return Err(TestdError::InvalidBinding);
                }
                (wire_id, *wire_version, request_digest, operation_id)
            }
            Self::Denied {
                wire_id,
                wire_version,
                request_digest,
                operation_id,
                ..
            } => (wire_id, *wire_version, request_digest, operation_id),
        };
        if wire_id != TESTD_OWNER_SUBMIT_OPERATION
            || wire_version != TESTD_OWNER_SUBMIT_WIRE_VERSION
            || !is_binding_digest(request_digest)
        {
            return Err(TestdError::InvalidBinding);
        }
        validate_text(operation_id, "owner_submit.response.operation_id")
    }
}

/// Declared class and resource requirements carried into one submitted job.
///
/// This is the test/job metadata I2.22 asks to extend: the job's resource
/// weight, its exclusive-resource requirements, and its runtime-lease
/// requirements. It is bound at submission so the durable job record carries
/// the declaration the scheduler and the nextest lane plan both read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSubmissionMetadata {
    pub job_class: JobClass,
    pub resource_profile: TestResourceProfile,
}

impl Default for JobSubmissionMetadata {
    /// An undeclared job is a verification job: a productive TestD submission
    /// must never default into a background lane.
    fn default() -> Self {
        Self::verification()
    }
}

impl JobSubmissionMetadata {
    /// A verification job with the default parallel declaration.
    ///
    /// This is the declaration for a job that touches no shared mutable runtime
    /// resource. It is deliberately NOT the declaration of a job that runs a
    /// test suite: I2.22 requires a test group that touches mutable fixture
    /// state to declare that state, and a parallel declaration here is how an
    /// empty lease set reaches a productive run. Such a route declares its real
    /// claims through [`JobSubmissionMetadata::declared`] instead.
    #[must_use]
    pub const fn verification() -> Self {
        Self {
            job_class: JobClass::Verification,
            resource_profile: TestResourceProfile {
                weight: ResourceWeight::Light,
                exclusive_resources: Vec::new(),
                serial_group: String::new(),
            },
        }
    }

    /// A job of `job_class` with an explicit resource profile.
    #[must_use]
    pub const fn declared(job_class: JobClass, resource_profile: TestResourceProfile) -> Self {
        Self {
            job_class,
            resource_profile,
        }
    }

    /// The priority the declared class claims with.
    #[must_use]
    pub const fn priority(&self) -> i32 {
        self.job_class.priority()
    }

    /// Validates the declared profile and refuses a background class that
    /// claims to outrank a protected foreground class.
    pub fn validate(&self) -> Result<(), TestdError> {
        self.resource_profile
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))
    }
}

impl TestdVerifierJobSubmission {
    pub fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.job_id, "job_id")?;
        validate_text(&self.project_id, "project_id")?;
        self.invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if self.invocation.kind != InstrumentKind::Test
            || self.invocation.profile != TESTD_PRODUCTIVE_PROFILE
            || !self.invocation.arguments.is_empty()
        {
            return Err(TestdError::Invalid {
                field: "invocation",
                reason: "productive submission requires the registered TestD profile and no caller arguments",
            });
        }
        let stage = self.stage_request.as_ref().ok_or(TestdError::Invalid {
            field: "stage_request",
            reason: "productive submission requires the runner-admitted stage",
        })?;
        stage.validate()?;
        self.provider_tool_observation.validate()?;
        EnvironmentProjection::new(
            self.provider_environment_projection.non_secret().clone(),
            self.provider_environment_projection.secret_refs().to_vec(),
            self.provider_environment_projection.inheritance(),
        )
        .map_err(|error| TestdError::Contract(error.to_string()))?;
        if stage.provider_freshness.is_none() {
            return Err(TestdError::Invalid {
                field: "stage_request.provider_freshness",
                reason: "productive submission requires owner-issued provider currentness",
            });
        }
        if stage.provider_catalog_lifecycle.is_none() {
            return Err(TestdError::Invalid {
                field: "stage_request.provider_catalog_lifecycle",
                reason: "productive submission requires an accepted catalog lifecycle projection",
            });
        }
        if stage.invocation != self.invocation
            || stage.execution != StageExecutionKind::Process
            || stage.adapter != TESTD_PRODUCTIVE_ADAPTER
        {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(layout) = self.target_layout.as_ref() {
            layout.validate()?;
        }
        self.target_roots.validate()?;
        self.metadata.validate()
    }
}

/// A queued productive job joined to the exact authenticated identity saved
/// by its Kernel owner. This is the only pending-dispatch projection exposed
/// to the daemon planner.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdPendingVerifierDispatch {
    pub job: TestJob,
    pub request_identity: RequestIdentity,
}

/// Complete durable owner input for publishing one productive verifier fact.
/// The daemon receives this projection through the authenticated Kernel
/// owner route and never opens the TestD database itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdTerminalCompletionEvidence {
    pub job: TestJob,
    pub request_identity: RequestIdentity,
}

/// Contract spelling used by the test-execution-plane boundary.
pub type TestdJob = TestJob;
/// A worker fence is the durable lease for one physical attempt.
pub type Fence = Lease;

/// Fencing lease for one physical attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    /// Worker identity.
    pub owner: String,
    /// Random fence token.
    pub token: String,
    /// Monotonic attempt epoch.
    pub epoch: u64,
    /// Absolute expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Exact identity tuple carried by a verifier receipt at finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptBinding {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: EpochId,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
}

/// Physical stream from which a raw process artifact was captured.
///
/// The stream identity is part of the TestD-owned receipt so a verifier can
/// join stdout chunks before parsing and exclude stderr from the nextest
/// event dialect. `Unknown` is retained for legacy/unresolved handles and is
/// deliberately non-certifying.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawArtifactStream {
    Stdout,
    Stderr,
    #[default]
    Unknown,
}

/// A raw process artifact captured before any normalization.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawArtifact {
    pub handle: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub length: u64,
    pub sha256: String,
    pub truncated: bool,
    /// Monotonic sequence allocated by the TestD capture owner. Handle text
    /// is not a stream-order authority (`...-10` must not precede `...-2`).
    #[serde(default)]
    pub capture_sequence: u64,
    /// Owning process stream; unknown legacy handles cannot certify parsing.
    #[serde(default)]
    pub stream: RawArtifactStream,
    /// Clock captured by TestD at the stream-retention boundary.
    #[serde(default)]
    pub captured_at: ClockReading,
    /// Retained lane identity this artifact was emitted under (issue #1897).
    /// `None` while a stream is captured, because capture has no job; the
    /// artifact-admission seam stamps it from the retained envelope, and
    /// `VerificationReceipt::validate` refuses an enveloped job whose emitted
    /// artifact records do not all carry the retained candidate and contract
    /// revision. Presence alone is never accepted — the content is compared
    /// against the envelope's own `candidate_identity()`.
    #[serde(default)]
    pub lane_identity: Option<CandidateIdentity>,
}

impl RawArtifact {
    /// Captures immutable bytes and computes a length-domain-separated digest.
    pub fn from_bytes(
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
    ) -> Result<Self, TestdError> {
        let length = bytes.len() as u64;
        let sha256 = sha256_artifact(length, &bytes);
        let artifact = Self {
            handle: handle.into(),
            content_type: content_type.into(),
            bytes,
            length,
            sha256,
            truncated,
            capture_sequence: 0,
            stream: RawArtifactStream::Unknown,
            captured_at: ClockReading::default(),
            // Capture has no job, so no retained lane identity exists yet. The
            // artifact-admission seam binds it before the record is emitted.
            lane_identity: None,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    /// Captures bytes with the stream and retention clock observed by the
    /// TestD owner. The clock is never borrowed from request admission.
    pub fn from_observation(
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
        stream: RawArtifactStream,
        captured_at: ClockReading,
    ) -> Result<Self, TestdError> {
        let mut artifact = Self::from_bytes(handle, content_type, bytes, truncated)?;
        artifact.stream = stream;
        artifact.captured_at = captured_at;
        artifact.validate()?;
        Ok(artifact)
    }

    /// Revalidates exact bytes, canonical length, and digest correspondence.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.handle.trim().is_empty()
            || self.content_type.trim().is_empty()
            || self.handle.chars().any(char::is_control)
            || self.content_type.chars().any(char::is_control)
        {
            return Err(TestdError::Invalid {
                field: "raw_artifact",
                reason: "handle and content_type must be non-blank and control-free",
            });
        }
        if self.length != self.bytes.len() as u64
            || sha256_artifact(self.length, &self.bytes) != self.sha256
        {
            return Err(TestdError::InvalidBinding);
        }
        self.captured_at
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        Ok(())
    }
}

/// Observation-only normalized evidence bound to raw process handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedEvidence {
    pub kind: String,
    pub summary: String,
    pub raw_handles: Vec<String>,
    pub execution: ExecutionStatus,
}

/// Owner-observed identity of the productive verifier toolchain.
///
/// These paths and digests are captured from the admitted process environment
/// after the resolver has asked rustup for the selected toolchain executables.
/// A plan/evaluator version is not a substitute for this observation, and a
/// rustup shim digest is not accepted as the selected cargo/rustc identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdToolObservation {
    pub nextest_path: String,
    pub nextest_sha256: String,
    pub cargo_path: String,
    pub cargo_sha256: String,
    pub rustc_path: String,
    pub rustc_sha256: String,
    pub selected_toolchain: String,
}

impl TestdToolObservation {
    /// Validates the owner-observed executable identity without consulting a
    /// caller or ambient locator.
    pub fn validate(&self) -> Result<(), TestdError> {
        for (field, value) in [
            ("nextest_path", self.nextest_path.as_str()),
            ("cargo_path", self.cargo_path.as_str()),
            ("rustc_path", self.rustc_path.as_str()),
        ] {
            validate_text(value, field)?;
            if !Path::new(value).is_absolute()
                || Path::new(value)
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
            {
                return Err(TestdError::Invalid {
                    field,
                    reason: "owner-observed tool identity must use absolute traversal-free paths",
                });
            }
        }
        validate_text(&self.selected_toolchain, "selected_toolchain")?;
        for (field, value) in [
            ("nextest_sha256", self.nextest_sha256.as_str()),
            ("cargo_sha256", self.cargo_sha256.as_str()),
            ("rustc_sha256", self.rustc_sha256.as_str()),
        ] {
            if !is_binding_digest(value) {
                return Err(TestdError::Invalid {
                    field,
                    reason: "owner-observed tool identity requires a lowercase SHA-256",
                });
            }
        }
        Ok(())
    }

    /// Stable diagnostic identity derived only from the observed nextest
    /// executable, never from the evaluator contract version.
    pub fn nextest_identity(&self) -> String {
        format!("path={};sha256={}", self.nextest_path, self.nextest_sha256)
    }
}

impl TestdProcessToolIntent {
    /// Revalidates the tool observation and closed child environment against
    /// the retained governed envelope, then returns the exact non-inheriting
    /// process environment projection.
    ///
    /// Every lane-scoped binding this projection emits — the Cargo target root,
    /// the Cargo cache root, and both fixture bindings — is read off the one
    /// retained envelope rather than supplied by the caller, so a caller cannot
    /// compose a child environment whose fixture namespace disagrees with the
    /// envelope the store persists and admits. The two Cargo roots are still the
    /// same canonical directory (`cache_root == target_root`), which the checks
    /// below keep proving.
    pub fn validate_for_roots(
        &self,
        envelope: &GovernedWorkEnvelope,
    ) -> Result<eliot_process::EnvironmentProjection, TestdError> {
        self.observation.validate()?;
        let nextest = validate_canonical_tool_file(&self.observation.nextest_path)?;
        if nextest
            .file_stem()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !name.eq_ignore_ascii_case(TESTD_PRODUCTIVE_PROFILE_PROGRAM))
        {
            return Err(TestdError::Invalid {
                field: "process_tool.nextest_path",
                reason: "productive executable does not match the registered cargo-nextest profile",
            });
        }
        let cargo = validate_canonical_tool_file(&self.observation.cargo_path)?;
        let rustc = validate_canonical_tool_file(&self.observation.rustc_path)?;
        for (path, expected) in [
            (&nextest, self.observation.nextest_sha256.as_str()),
            (&cargo, self.observation.cargo_sha256.as_str()),
            (&rustc, self.observation.rustc_sha256.as_str()),
        ] {
            let bytes = std::fs::read(path).map_err(|_| TestdError::Invalid {
                field: "process_tool.executable",
                reason: "owner-observed tool cannot be reread before admission",
            })?;
            if eliot_contracts::sha256_hex(&bytes) != expected {
                return Err(TestdError::Invalid {
                    field: "process_tool.executable",
                    reason: "owner-observed tool bytes changed before admission",
                });
            }
        }

        // Issue #1897 (AUD2): the governed roots are read off the retained
        // envelope rather than accepted from the caller, so the child can never
        // be composed against a target root or fixture root the store did not
        // admit for this work item.
        let governed_root = envelope
            .derive_target_root()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let governed_root = governed_root.to_string_lossy().into_owned();
        let cargo_home = validate_canonical_tool_directory(&governed_root)?;
        let target = validate_canonical_tool_directory(&governed_root)?;
        if cargo_home != target {
            return Err(TestdError::Invalid {
                field: "process_tool.target_root",
                reason: "productive target and cache roots must be the same canonical directory",
            });
        }
        let cargo_bin = cargo.parent().ok_or(TestdError::InvalidBinding)?;
        let toolchain_root = cargo_bin.parent().ok_or(TestdError::InvalidBinding)?;
        let toolchain_catalog = toolchain_root.parent().ok_or(TestdError::InvalidBinding)?;
        let rustup_home = toolchain_catalog
            .parent()
            .ok_or(TestdError::InvalidBinding)?;
        if cargo_bin.file_name().and_then(|name| name.to_str()) != Some("bin")
            || toolchain_root.file_name().and_then(|name| name.to_str())
                != Some(self.observation.selected_toolchain.as_str())
            || toolchain_catalog.file_name().and_then(|name| name.to_str()) != Some("toolchains")
            || rustc.parent() != Some(cargo_bin)
        {
            return Err(TestdError::Invalid {
                field: "process_tool.toolchain",
                reason: "cargo and rustc do not belong to the selected Rustup toolchain",
            });
        }
        let rustup_home = validate_canonical_tool_directory(
            rustup_home.to_str().ok_or(TestdError::InvalidBinding)?,
        )?;
        let expected_dirs: BTreeSet<PathBuf> = [&nextest, &cargo, &rustc]
            .into_iter()
            .filter_map(|path| path.parent().map(Path::to_path_buf))
            .collect();
        let path_value = std::env::join_paths(&expected_dirs).map_err(|_| TestdError::Invalid {
            field: "process_tool.PATH",
            reason: "observed tool directories cannot be composed into PATH",
        })?;
        let path_value = path_value.to_string_lossy().into_owned();
        let mut values = BTreeMap::from([
            (
                "NEXTEST_EXPERIMENTAL_LIBTEST_JSON".to_owned(),
                "1".to_owned(),
            ),
            (
                "ELIOT_TESTD_NEXTEST_SHA256".to_owned(),
                self.observation.nextest_sha256.clone(),
            ),
            ("CARGO".to_owned(), self.observation.cargo_path.clone()),
            ("RUSTC".to_owned(), self.observation.rustc_path.clone()),
            (
                "ELIOT_TESTD_CARGO_SHA256".to_owned(),
                self.observation.cargo_sha256.clone(),
            ),
            (
                "ELIOT_TESTD_RUSTC_SHA256".to_owned(),
                self.observation.rustc_sha256.clone(),
            ),
            ("CARGO_HOME".to_owned(), governed_root.clone()),
            (
                "RUSTUP_HOME".to_owned(),
                rustup_home.to_string_lossy().into_owned(),
            ),
            (
                "ELIOT_TESTD_TOOLCHAIN".to_owned(),
                self.observation.selected_toolchain.clone(),
            ),
            ("PATH".to_owned(), path_value),
            ("CARGO_TARGET_DIR".to_owned(), governed_root.clone()),
        ]);
        // Issue #1897 (W4/AUD2): the fixture namespace and the physical root it
        // resolves to travel into the child. Without them the child resolves an
        // ambient fixture location shared with every concurrent run, and the
        // namespace the store persisted would stay inert. Both values come from
        // the retained envelope, and the root is proven to be the canonical
        // existing directory the same envelope derives, so the child cannot be
        // pointed at a fixture tree that was never admitted or created.
        let fixture_root = envelope
            .fixture_root()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let canonical_fixture_root =
            validate_canonical_tool_directory(&fixture_root.to_string_lossy())?
                .to_string_lossy()
                .into_owned();
        let fixture_environment = envelope
            .fixture_environment()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let derived_fixture_root = fixture_environment
            .iter()
            .find(|(name, _)| name == FIXTURE_ROOT_ENV)
            .map(|(_, value)| value.as_str());
        if derived_fixture_root != Some(canonical_fixture_root.as_str()) {
            return Err(TestdError::Invalid {
                field: "process_tool.fixture_root",
                reason: "the envelope fixture root is not the canonical fixture directory",
            });
        }
        for (name, value) in fixture_environment {
            values.insert(name, value);
        }

        eliot_process::EnvironmentProjection::new(
            values,
            Vec::new(),
            eliot_process::EnvironmentInheritance::None,
        )
        .map_err(|error| TestdError::Contract(error.to_string()))
    }
}

fn validate_canonical_tool_file(path: &str) -> Result<PathBuf, TestdError> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field: "process_tool.path",
            reason: "tool path must be absolute and traversal-free",
        });
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| TestdError::Invalid {
        field: "process_tool.path",
        reason: "tool path cannot be canonicalized",
    })?;
    if canonical != path || !canonical.is_file() {
        return Err(TestdError::Invalid {
            field: "process_tool.path",
            reason: "tool path must name an existing canonical file",
        });
    }
    Ok(canonical)
}

fn validate_canonical_tool_directory(path: &str) -> Result<PathBuf, TestdError> {
    let path = Path::new(path);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field: "process_tool.directory",
            reason: "tool directory must be absolute and traversal-free",
        });
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| TestdError::Invalid {
        field: "process_tool.directory",
        reason: "tool directory cannot be canonicalized",
    })?;
    if canonical != path || !canonical.is_dir() {
        return Err(TestdError::Invalid {
            field: "process_tool.directory",
            reason: "tool directory must be an existing canonical directory",
        });
    }
    Ok(canonical)
}

/// Candidate verification receipt accepted by the canonical finish boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReceipt {
    pub job_id: String,
    pub operation_id: String,
    pub process_tree_id: String,
    pub generation: u64,
    pub authority_epoch: EpochId,
    pub invocation_id: String,
    pub invocation_digest: String,
    pub allowed_contour_root: String,
    pub source_root: String,
    pub target_root: String,
    pub cache_root: String,
    pub execution: ExecutionStatus,
    /// TestD-owner observation when the admitted process was resumed.
    #[serde(default)]
    pub started_at: ClockReading,
    /// TestD-owner observation after terminal inspection and stream closure.
    #[serde(default)]
    pub finished_at: ClockReading,
    /// Productive profile tool identity observed by the TestD owner. Probe
    /// and refused/unknown paths may omit it; a productive succeeded attempt
    /// cannot be accepted without it.
    #[serde(default)]
    pub tool_observation: Option<TestdToolObservation>,
    /// Actual repository identity immediately before and after the physical
    /// verifier execution. A mismatch remains visible and cannot certify.
    #[serde(default)]
    pub source_observation: Option<TestdSourceObservationRange>,
    pub raw_artifacts: Vec<RawArtifact>,
    pub normalized: Vec<NormalizedEvidence>,
    /// Owner-neutral typed stream bundles admitted from the emitted
    /// `ProcessEvidence` records (issue #456, Wave A). Empty for legacy-only
    /// receipts; populated additively without changing legacy handle lineage.
    #[serde(default)]
    pub typed_evidence: Vec<TestdProcessEvidenceBundle>,
    /// Lane identity the emitting work item was allocated in (issue #1897):
    /// build fingerprint digest, candidate, and contract revision. `None`
    /// preserves the pre-lane authority for receipts of jobs admitted
    /// without a lane; it never stands in for an allocated identity.
    #[serde(default)]
    pub lane_identity: Option<CandidateIdentity>,
}

/// Evaluates the admitted TestD profile after the process observation has
/// been durably captured. The current closed profile is a bounded cargo tool
/// probe, so a clean process exit proves only execution of that probe; it
/// does not prove the requested task. The evaluator therefore records an
/// explicit `UNKNOWN` semantic outcome with the exact invocation, scope,
/// fence, and captured raw artifacts. A future profile adds its own
/// evaluator here and may return `PASS` only from profile-specific evidence.
pub fn evaluate_testd_verification(
    job: &TestJob,
    receipt: &VerificationReceipt,
    _finished_at_ms: u64,
) -> Result<VerificationRun, TestdError> {
    receipt.validate(job)?;
    let run_id = RequestId::new(format!(
        "{}:verification",
        job.invocation.request.request_id.as_str()
    ))
    .map_err(|error| TestdError::Contract(error.to_string()))?;
    let verifier = ContractId::new(job.invocation.profile.clone())
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    let raw_evidence = receipt
        .raw_artifacts
        .iter()
        .map(|artifact| {
            ArtifactId::new(artifact.handle.clone())
                .map_err(|error| TestdError::Contract(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let run = VerificationRun {
        run_id,
        verifier,
        invocation_id: job.invocation.request.request_id.clone(),
        property: format!(
            "admitted {} profile execution has profile-specific verifier evidence",
            job.invocation.profile
        ),
        scope: job.invocation.declared_scope.clone(),
        execution: receipt.execution,
        outcome: match receipt.execution {
            ExecutionStatus::Cancelled => eliot_instrument_api::VerificationOutcome::Cancelled,
            ExecutionStatus::Blocked => eliot_instrument_api::VerificationOutcome::Blocked,
            ExecutionStatus::Accepted
            | ExecutionStatus::Running
            | ExecutionStatus::Succeeded
            | ExecutionStatus::Failed
            | ExecutionStatus::Partial
            | ExecutionStatus::Unknown => eliot_instrument_api::VerificationOutcome::Unknown,
        },
        freshness: eliot_instrument_api::EvidenceFreshness::Unknown,
        coverage: eliot_instrument_api::EvidenceCoverage::Unknown,
        // The TestD receipt currently owns raw process evidence only. The
        // profile evaluator must supply normalized semantic evidence before
        // this run can certify completion.
        evidence: Vec::new(),
        raw_evidence,
        state_fence: job.invocation.request.state_fence.clone(),
        started_at: receipt.started_at,
        finished_at: Some(receipt.finished_at),
    };
    run.validate()
        .map_err(|error| TestdError::Contract(error.to_string()))?;
    Ok(run)
}

impl VerificationReceipt {
    /// Returns the exact durable identity tuple after validation.
    pub fn binding(&self) -> ReceiptBinding {
        ReceiptBinding {
            job_id: self.job_id.clone(),
            operation_id: self.operation_id.clone(),
            process_tree_id: self.process_tree_id.clone(),
            generation: self.generation,
            authority_epoch: self.authority_epoch.clone(),
            invocation_id: self.invocation_id.clone(),
            invocation_digest: self.invocation_digest.clone(),
            allowed_contour_root: self.allowed_contour_root.clone(),
            source_root: self.source_root.clone(),
            target_root: self.target_root.clone(),
            cache_root: self.cache_root.clone(),
        }
    }

    /// Validates identity and exact raw-handle lineage before publication.
    pub fn validate(&self, job: &TestJob) -> Result<(), TestdError> {
        job.target_roots.validate()?;
        verify_job_lane(
            &job.target_roots,
            job.target_layout.as_ref(),
            job.work_envelope.as_ref(),
            job.fixture_namespace.as_deref(),
        )?;
        let binding = self.binding();
        validate_receipt_binding(job, &binding)?;
        // Issue #1897 (W5): the emitted result carries the exact lane
        // identity of the work item that produced it. An enveloped job
        // without an identity, a forged identity without a lane, and an
        // identity that disagrees with the lane all refuse; bare presence
        // is never enough, the content is compared.
        match (job.work_envelope.as_ref(), self.lane_identity.as_ref()) {
            (Some(envelope), Some(identity)) => {
                let expected = envelope
                    .candidate_identity()
                    .map_err(|_| TestdError::InvalidBinding)?;
                if identity != &expected {
                    return Err(TestdError::InvalidBinding);
                }
                // Issue #1897 (W5, audit Exit): every emitted ARTIFACT record
                // carries the same retained candidate and contract revision as
                // the result, compared by content. An artifact that names
                // another lane, or names none, refuses: an artifact produced
                // under one candidate cannot be published under another one's
                // verdict.
                for artifact in &self.raw_artifacts {
                    if artifact.lane_identity.as_ref() != Some(&expected) {
                        return Err(TestdError::InvalidBinding);
                    }
                }
            }
            (Some(_), None) | (None, Some(_)) => return Err(TestdError::InvalidBinding),
            (None, None) => {}
        }
        self.started_at
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        self.finished_at
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if let Some(observation) = &self.tool_observation {
            observation.validate()?;
        } else if job.invocation.profile == TESTD_PRODUCTIVE_PROFILE
            && matches!(self.execution, ExecutionStatus::Succeeded)
        {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(source) = &self.source_observation {
            source.validate()?;
            if source.before.repository_root != job.target_roots.source_root
                || source.after.repository_root != job.target_roots.source_root
                || (job.invocation.profile == TESTD_PRODUCTIVE_PROFILE
                    && job.source_observation_before.as_ref() != Some(&source.before))
            {
                return Err(TestdError::InvalidBinding);
            }
        } else if job.invocation.profile == TESTD_PRODUCTIVE_PROFILE
            && matches!(self.execution, ExecutionStatus::Succeeded)
        {
            return Err(TestdError::InvalidBinding);
        }
        if let (Some(start), Some(finish)) = (
            self.started_at.known_time_ms,
            self.finished_at.known_time_ms,
        ) && finish < start
        {
            return Err(TestdError::InvalidBinding);
        }
        let mut artifacts = BTreeMap::new();
        for artifact in &self.raw_artifacts {
            artifact.validate()?;
            if artifact.capture_sequence == 0 {
                return Err(TestdError::InvalidBinding);
            }
            if artifacts
                .insert(artifact.handle.clone(), artifact)
                .is_some()
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        let mut referenced = BTreeSet::new();
        for evidence in &self.normalized {
            for handle in &evidence.raw_handles {
                if !referenced.insert(handle.clone()) || !artifacts.contains_key(handle) {
                    return Err(TestdError::InvalidBinding);
                }
            }
        }
        if artifacts.len() != referenced.len() {
            return Err(TestdError::InvalidBinding);
        }
        // Typed bundles revalidate structurally and against this job's
        // process identity (issue #456, Wave B): a bundle from another
        // operation, tree, generation, or authority epoch cannot ride on this
        // receipt. An empty bundle list keeps legacy receipts validating
        // exactly as before.
        for bundle in &self.typed_evidence {
            bundle
                .validate()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
            validate_typed_bundle_binding(job, bundle)?;
        }
        Ok(())
    }
}

/// A bounded evidence sink for one testd operation.
///
/// A collector built with [`EvidenceCollector::for_operation`] admits only
/// evidence from that exact attempt: foreign records are refused at the sink
/// boundary, and bytes can never be recorded under a legacy reference already
/// cited by an admitted record. The default collector keeps the legacy
/// unbound behavior for refusal paths that never start a process.
#[derive(Clone, Default)]
pub struct EvidenceCollector {
    records: Arc<Mutex<Vec<eliot_process::ProcessEvidence>>>,
    raw_artifacts: Arc<Mutex<BTreeMap<String, RawArtifact>>>,
    next_capture_sequence: Arc<AtomicU64>,
    tool_observation: Arc<Mutex<Option<TestdToolObservation>>>,
    typed: Arc<Mutex<Vec<TestdProcessEvidenceBundle>>>,
    expected_operation: Option<OperationId>,
}

impl EvidenceCollector {
    /// Builds a collector bound to one exact attempt operation (issue #456,
    /// Wave B). The production worker constructs this internally from the
    /// presented attempt before the consuming start; the start path refuses
    /// any collector bound to another operation or bound to none.
    #[must_use]
    pub fn for_operation(operation_id: OperationId) -> Self {
        Self {
            expected_operation: Some(operation_id),
            ..Self::default()
        }
    }

    /// Reports whether this collector serves exactly the given attempt.
    ///
    /// Only a collector bound to this operation qualifies for the production
    /// start path; an unbound collector never does.
    #[must_use]
    pub fn accepts_operation(&self, operation_id: &OperationId) -> bool {
        self.expected_operation.as_ref() == Some(operation_id)
    }

    /// Rebuilds a bound collector from persisted bundles after a daemon
    /// restart (issue #456, Wave D).
    ///
    /// Every bundle must revalidate structurally and belong to this same
    /// operation identity; history from a superseded attempt is refused
    /// rather than merged, so a restarted attempt can only ever reconcile
    /// its own evidence. Resolution itself still runs through the injected
    /// readback port by the bundle's original identity.
    pub fn reconstruct_persisted(
        operation_id: OperationId,
        bundles: &[TestdProcessEvidenceBundle],
    ) -> Result<Self, TestdError> {
        for bundle in bundles {
            bundle
                .validate()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
            if bundle.binding.operation_id() != &operation_id {
                return Err(TestdError::InvalidBinding);
            }
        }
        let collector = Self::for_operation(operation_id);
        collector
            .typed
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?
            .extend(bundles.iter().cloned());
        Ok(collector)
    }

    /// Returns a stable snapshot for receipt composition.
    pub fn snapshot(&self) -> Vec<eliot_process::ProcessEvidence> {
        self.records
            .lock()
            .map_or_else(|_| Vec::new(), |items| items.clone())
    }

    /// Returns a stable snapshot of admitted typed stream bundles.
    pub fn typed_bundles(&self) -> Vec<TestdProcessEvidenceBundle> {
        self.typed
            .lock()
            .map_or_else(|_| Vec::new(), |items| items.clone())
    }

    /// Commits replay observations only onto the exact post-readback stream
    /// snapshot supplied to the parser/evaluator.
    ///
    /// The snapshot includes process identity, stream identity, source digest,
    /// readback receipt, and fence. A concurrent re-resolution therefore
    /// refuses the stale result instead of allowing it to certify new bytes.
    pub fn apply_stream_replay(
        &self,
        expected: &TestdStreamEvidenceBinding,
        parsing: &TestdParsingObservation,
        evaluation: Option<&TestdEvaluationObservation>,
    ) -> Result<(), TestdError> {
        let mut bundles = self
            .typed
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        let matches = bundles
            .iter()
            .enumerate()
            .filter(|(_, bundle)| {
                if bundle.binding != expected.binding {
                    return false;
                }
                match expected.stream {
                    eliot_process::ProcessStreamKind::Stdout => {
                        bundle.stdout.binding.as_ref() == Some(expected)
                    }
                    eliot_process::ProcessStreamKind::Stderr => {
                        bundle.stderr.binding.as_ref() == Some(expected)
                    }
                }
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(TestdError::InvalidBinding);
        }
        bundles[matches[0]]
            .apply_replay_observations(expected, parsing, evaluation)
            .map_err(|error| TestdError::Contract(error.to_string()))
    }

    /// Resolves every pending typed bundle through the injected immutable-
    /// source readback port.
    ///
    /// Each bundle yields one explicit per-stream outcome; refusal and
    /// failure outcomes update the retained dispositions in place and never
    /// expose bytes. Resolution never fails wholesale.
    pub fn resolve_typed_sources(
        &self,
        port: &dyn ProcessStreamSourceReadbackPort,
        context: &TestdReadbackContext,
    ) -> Result<Vec<Vec<TestdStreamResolution>>, TestdError> {
        let mut bundles = self
            .typed
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        Ok(bundles
            .iter_mut()
            .map(|bundle| bundle.resolve_pending(port, context))
            .collect())
    }

    /// Asynchronously resolves every persisted stream bundle without holding
    /// the collector lock across provider I/O. The resolved observations are
    /// committed back only if the bundle set is unchanged, so concurrent
    /// process evidence cannot be overwritten by a stale replay.
    pub async fn resolve_typed_sources_async(
        &self,
        port: &dyn AsyncProcessStreamSourceReadbackPort,
        context: &TestdReadbackContext,
    ) -> Result<Vec<Vec<TestdStreamResolution>>, TestdError> {
        let original = self.typed_bundles();
        let mut updated = original.clone();
        let mut outcomes = Vec::with_capacity(updated.len());
        for bundle in &mut updated {
            outcomes.push(bundle.resolve_pending_async(port, context).await);
        }
        let mut current = self
            .typed
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        if *current != original {
            return Err(TestdError::InvalidBinding);
        }
        *current = updated;
        Ok(outcomes)
    }

    /// Captures bytes before normalization; the digest is always over bytes.
    pub fn record_raw_artifact(
        &self,
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
    ) -> Result<(), TestdError> {
        let artifact = RawArtifact::from_bytes(handle, content_type, bytes, truncated)?;
        self.insert_raw_artifact(artifact)
    }

    /// Captures one stream artifact with the actual TestD retention clock and
    /// stream boundary observed by the worker.
    pub fn record_raw_artifact_at(
        &self,
        handle: impl Into<String>,
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        truncated: bool,
        stream: RawArtifactStream,
        captured_at: ClockReading,
    ) -> Result<(), TestdError> {
        let artifact = RawArtifact::from_observation(
            handle,
            content_type,
            bytes,
            truncated,
            stream,
            captured_at,
        )?;
        self.insert_raw_artifact(artifact)
    }

    /// Records the exact productive tool identity observed at the owner
    /// boundary before the consuming process starts.
    pub fn record_tool_observation(
        &self,
        observation: TestdToolObservation,
    ) -> Result<(), TestdError> {
        observation.validate()?;
        let mut current = self
            .tool_observation
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        if let Some(existing) = &*current {
            if existing != &observation {
                return Err(TestdError::InvalidBinding);
            }
        } else {
            *current = Some(observation);
        }
        Ok(())
    }

    /// Reports whether an admitted record already cites this handle as a
    /// quarantined legacy reference.
    fn cites_legacy_handle(&self, handle: &str) -> bool {
        self.records.lock().is_ok_and(|records| {
            records.iter().any(|record| {
                record.stdout_ref() == Some(handle) || record.stderr_ref() == Some(handle)
            })
        })
    }

    fn insert_raw_artifact(&self, artifact: RawArtifact) -> Result<(), TestdError> {
        let mut artifact = artifact;
        // Attempt-bound production evidence has no raw-byte write path: a
        // caller-selected handle/byte pair cannot be associated with this
        // process attempt, even if it happens to match a stream preview or a
        // quarantined legacy reference. Independently, no collector may
        // upgrade a cited legacy reference by attaching matching bytes.
        if self.expected_operation.is_some() || self.cites_legacy_handle(&artifact.handle) {
            return Err(TestdError::InvalidBinding);
        }
        let mut artifacts = self
            .raw_artifacts
            .lock()
            .map_err(|_| TestdError::Contract("evidence collector lock poisoned".to_owned()))?;
        if let Some(existing) = artifacts.get(&artifact.handle) {
            artifact.capture_sequence = existing.capture_sequence;
            if existing != &artifact {
                return Err(TestdError::InvalidBinding);
            }
        } else {
            artifact.capture_sequence = self
                .next_capture_sequence
                .fetch_add(1, AtomicOrdering::Relaxed)
                .saturating_add(1);
            artifacts.insert(artifact.handle.clone(), artifact);
        }
        Ok(())
    }

    /// Builds an observation-only receipt from captured process handles.
    pub fn verification_receipt(
        &self,
        job: &TestJob,
        execution: ExecutionStatus,
    ) -> VerificationReceipt {
        self.verification_receipt_at(
            job,
            execution,
            ClockReading::default(),
            ClockReading::default(),
        )
    }

    /// Builds a receipt with the clocks observed by the TestD owner at the
    /// actual resume and terminal capture boundaries.
    pub fn verification_receipt_at(
        &self,
        job: &TestJob,
        execution: ExecutionStatus,
        started_at: ClockReading,
        finished_at: ClockReading,
    ) -> VerificationReceipt {
        let records = self.snapshot();
        let raw = self
            .raw_artifacts
            .lock()
            .map_or_else(|_| BTreeMap::new(), |artifacts| artifacts.clone());
        // Issue #1897 (W5): the artifact-admission seam is the one place in the
        // capture path that holds the job, so it is where every emitted
        // `RawArtifact` record is bound to the retained lane identity. Capture
        // itself has no job and deliberately leaves the field absent; the
        // receipt never publishes an unbound artifact for an enveloped job,
        // because `VerificationReceipt::validate` compares each artifact's
        // identity with the retained envelope's own value.
        let lane_identity = job
            .work_envelope
            .as_ref()
            .and_then(|envelope| envelope.candidate_identity().ok());
        let mut raw_artifacts = Vec::new();
        let mut handles = BTreeSet::new();
        for record in &records {
            for handle in [record.stdout_ref(), record.stderr_ref()]
                .into_iter()
                .flatten()
            {
                if handles.insert(handle.to_owned())
                    && let Some(artifact) = raw.get(handle)
                {
                    let mut artifact = artifact.clone();
                    artifact.lane_identity.clone_from(&lane_identity);
                    raw_artifacts.push(artifact);
                }
            }
        }
        raw_artifacts.sort_by(|left, right| {
            left.capture_sequence
                .cmp(&right.capture_sequence)
                .then_with(|| left.handle.cmp(&right.handle))
        });
        let normalized = records
            .iter()
            .map(|record| NormalizedEvidence {
                kind: "process.observation".to_owned(),
                summary: format!("process lifecycle: {:?}", record.view().lifecycle()),
                raw_handles: [record.stdout_ref(), record.stderr_ref()]
                    .into_iter()
                    .flatten()
                    .map(str::to_owned)
                    .collect(),
                execution,
            })
            .collect();
        VerificationReceipt {
            job_id: job.job_id.clone(),
            operation_id: job.process.operation_id.clone(),
            process_tree_id: job.process.process_tree_id.clone(),
            generation: job.process.generation,
            authority_epoch: job.process.authority_epoch.clone(),
            invocation_id: job.invocation.request.request_id.as_str().to_owned(),
            invocation_digest: job.process.invocation_digest.clone(),
            allowed_contour_root: job.target_roots.allowed_contour_root.clone(),
            source_root: job.target_roots.source_root.clone(),
            target_root: job.target_roots.target_root.clone(),
            cache_root: job.target_roots.cache_root.clone(),
            execution,
            started_at,
            finished_at,
            tool_observation: self
                .tool_observation
                .lock()
                .map_or(None, |observation| observation.clone()),
            source_observation: None,
            raw_artifacts,
            normalized,
            typed_evidence: self.typed_bundles(),
            // Issue #1897 (W5): attach the retained lane identity to the
            // emitted result, from the same value every emitted artifact
            // record was bound to above. The envelope was validated when the
            // job row committed, so identity derivation fails only on a
            // corrupt row; that failure still refuses loudly at `finish`
            // instead of emitting an unattributed result for an enveloped job.
            lane_identity,
        }
    }
}

impl eliot_process::ProcessEvidenceSink for EvidenceCollector {
    fn record(
        &self,
        evidence: eliot_process::ProcessEvidence,
    ) -> Result<(), eliot_process::EvidenceSinkError> {
        // An operation-bound collector refuses foreign records before any
        // admission: evidence from another attempt can never enter this
        // attempt's records, typed bundles, or receipt.
        if let Some(expected) = &self.expected_operation
            && evidence.operation_id() != expected
        {
            return Err(eliot_process::EvidenceSinkError {
                message: "process evidence carries a foreign operation identity".to_owned(),
            });
        }
        // Typed admission runs on every arrival: the bundle consumes only the
        // typed stdout()/stderr() values with an explicit disposition per
        // requested stream. Incoherent evidence fails closed here instead of
        // entering the receipt; every validly constructed record admits.
        let bundle = TestdProcessEvidenceBundle::admit(&evidence).map_err(|error| {
            eliot_process::EvidenceSinkError {
                message: error.to_string(),
            }
        })?;
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "evidence collector lock poisoned".to_owned(),
            })
            .map(|mut records| records.push(evidence))?;
        self.typed
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "evidence collector lock poisoned".to_owned(),
            })
            .map(|mut typed| typed.push(bundle))
    }
}

/// Append-only explanation for every durable lifecycle mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobEvent {
    /// Job identity.
    pub job_id: String,
    /// Project sequence at the time of the event.
    pub project_sequence: u64,
    /// Event sequence within this job.
    pub sequence: u64,
    /// Previous state.
    pub from: Option<JobState>,
    /// New state.
    pub to: JobState,
    /// Worker or API actor causing the change.
    pub actor: String,
    /// Event timestamp.
    pub at_ms: u64,
    /// Optional machine-readable reason.
    pub reason: Option<String>,
}

/// A bounded retry policy. Delays are applied in order and then capped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    /// Retry delays in milliseconds.
    pub delays_ms: Vec<u64>,
    /// Maximum number of physical attempts.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            delays_ms: vec![100, 250, 500, 1_000, 2_000, 5_000, 10_000],
            max_attempts: 8,
        }
    }
}

fn corrupt(reason: &'static str) -> TestdError {
    TestdError::Corrupt(reason.to_owned())
}

fn validate_blob_call_binding(
    job_id: &str,
    capability_ref: &str,
    token_ref: &str,
    operation_sha256: &str,
) -> Result<(), TestdError> {
    validate_text(job_id, "blob_stream.job_id")?;
    validate_text(capability_ref, "blob_stream.capability_ref")?;
    validate_text(token_ref, "blob_stream.token_ref")?;
    if !is_binding_digest(operation_sha256) {
        return Err(TestdError::Invalid {
            field: "blob_stream.operation_sha256",
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

fn validate_blob_process_stream_outcome(
    outcome: &TestdBlobProcessStreamCallOutcome,
) -> Result<(), TestdError> {
    if let TestdBlobProcessStreamCallOutcome::Completed {
        response_sha256,
        response_ref,
    } = outcome
    {
        if !is_binding_digest(response_sha256) {
            return Err(TestdError::Invalid {
                field: "blob_stream.response_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        let Some(response_ref) = response_ref else {
            return Err(TestdError::Invalid {
                field: "blob_stream.response_ref",
                reason: "a completed owner response requires an exact retained response reference",
            });
        };
        validate_text(response_ref, "blob_stream.response_ref")?;
    }
    Ok(())
}

fn validate_blob_process_stream_call_record(
    record: &TestdBlobProcessStreamCallRecord,
    job_id: &str,
    capability_ref: &str,
    token_ref: &str,
    ordinal: u32,
    operation_sha256: &str,
) -> Result<(), TestdError> {
    if record.job_id != job_id
        || record.capability_ref != capability_ref
        || record.token_ref != token_ref
        || record.ordinal != ordinal
        || record.operation_sha256 != operation_sha256
    {
        return Err(TestdError::InvalidBinding);
    }
    if let TestdBlobProcessStreamCallState::Completed(outcome) = &record.state {
        validate_blob_process_stream_outcome(outcome)?;
    }
    Ok(())
}

fn blob_process_stream_call_key(
    job_id: &str,
    capability_ref: &str,
    token_ref: &str,
) -> Result<String, TestdError> {
    let canonical = eliot_contracts::canonical_json_bytes(&(job_id, capability_ref, token_ref))
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(blake3::hash(&canonical).to_hex().to_string())
}

fn decode_project_sequence(bytes: &[u8]) -> Result<u64, TestdError> {
    serde_json::from_slice(bytes).map_err(|_| corrupt("project sequence metadata is invalid"))
}

fn decode_event_sequence_suffix(suffix: &str) -> Result<u64, TestdError> {
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(corrupt("event sequence suffix is invalid"));
    }
    let sequence = suffix
        .parse::<u64>()
        .map_err(|_| corrupt("event sequence suffix is invalid"))?;
    if sequence == 0 {
        return Err(corrupt("event sequence suffix is invalid"));
    }
    Ok(sequence)
}

fn validate_sequence_inventory(
    inventory: &BTreeMap<String, BTreeSet<u64>>,
    metadata: &BTreeMap<String, u64>,
) -> Result<(), TestdError> {
    for (project_id, sequences) in inventory {
        let highest = sequences
            .last()
            .copied()
            .ok_or_else(|| corrupt("durable project sequence inventory is invalid"))?;
        if metadata.get(project_id) != Some(&highest) {
            return Err(corrupt(
                "durable project sequence metadata conflicts with inventory",
            ));
        }
    }
    for (project_id, sequence) in metadata {
        if !inventory.contains_key(project_id) && *sequence != 0 {
            return Err(corrupt(
                "durable project sequence metadata has no inventory",
            ));
        }
    }
    Ok(())
}

/// One durable test-daemon state owner.
pub struct TestdStore {
    database: Arc<Database>,
    retry: RetryPolicy,
}

impl TestdStore {
    /// Opens or creates the persistent state file and all schema tables.
    pub fn open(path: impl AsRef<Path>, retry: RetryPolicy) -> Result<Self, TestdError> {
        if retry.max_attempts == 0 || retry.delays_ms.is_empty() {
            return Err(TestdError::Invalid {
                field: "retry_policy",
                reason: "must have bounded attempts and delays",
            });
        }
        let path = path.as_ref();
        let existed = path.exists();
        let db = Database::create(path).map_err(database)?;
        if existed {
            let read = db.begin_read().map_err(database)?;
            let jobs = read
                .open_table(JOBS)
                .map_err(|_| corrupt("durable jobs table is missing"))?;
            let mut inventory: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
            let mut job_ids = Vec::new();
            for item in jobs.iter().map_err(database)? {
                let (key, value) = item.map_err(database)?;
                let job: TestJob = serde_json::from_slice(value.value())
                    .map_err(|_| corrupt("durable job record is invalid"))?;
                if job.job_id != key.value() {
                    return Err(corrupt("durable job key conflicts with record"));
                }
                if job.project_sequence == 0 {
                    return Err(corrupt("durable job has invalid project sequence"));
                }
                if !inventory
                    .entry(job.project_id.clone())
                    .or_default()
                    .insert(job.project_sequence)
                {
                    return Err(corrupt("durable project sequence is duplicated"));
                }
                job_ids.push(job.job_id);
            }
            drop(jobs);

            let meta = read
                .open_table(META)
                .map_err(|_| corrupt("durable metadata table is missing"))?;
            let mut metadata = BTreeMap::new();
            for item in meta.iter().map_err(database)? {
                let (key, value) = item.map_err(database)?;
                if let Some(project_id) = key.value().strip_prefix("project:")
                    && (project_id.trim().is_empty()
                        || project_id.chars().any(char::is_control)
                        || metadata
                            .insert(
                                project_id.to_owned(),
                                decode_project_sequence(value.value())?,
                            )
                            .is_some())
                {
                    return Err(corrupt("durable project sequence key is invalid"));
                }
            }
            drop(meta);
            validate_sequence_inventory(&inventory, &metadata)?;

            let events = read
                .open_table(EVENTS)
                .map_err(|_| corrupt("durable events table is missing"))?;
            for job_id in job_ids {
                let prefix = format!("{job_id}:");
                let mut sequences = BTreeSet::new();
                for item in events.iter().map_err(database)? {
                    let (key, _) = item.map_err(database)?;
                    if let Some(suffix) = key.value().strip_prefix(&prefix) {
                        let sequence = decode_event_sequence_suffix(suffix)?;
                        if !sequences.insert(sequence) {
                            return Err(corrupt("durable event sequence is ambiguous"));
                        }
                    }
                }
            }
        } else {
            let write = db.begin_write().map_err(database)?;
            drop(write.open_table(JOBS).map_err(database)?);
            drop(write.open_table(EVENTS).map_err(database)?);
            drop(write.open_table(META).map_err(database)?);
            write.commit().map_err(database)?;
        }
        // Additive owner table for authenticated task identity. Existing
        // stores migrate idempotently without rewriting job payloads.
        let write = db.begin_write().map_err(database)?;
        drop(write.open_table(ADMITTED_IDENTITIES).map_err(database)?);
        drop(write.open_table(BLOB_PROCESS_STREAM_CALLS).map_err(database)?);
        write.commit().map_err(database)?;
        Ok(Self {
            database: Arc::new(db),
            retry,
        })
    }

    /// Returns the durable record for a job.
    pub fn get(&self, job_id: &str) -> Result<Option<TestJob>, TestdError> {
        validate_text(job_id, "job_id")?;
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        table
            .get(job_id)
            .map_err(database)?
            .map_or(Ok(None), |value| {
                serde_json::from_slice(value.value())
                    .map(Some)
                    .map_err(|error| TestdError::Corrupt(error.to_string()))
            })
    }

    /// Persists the Kernel-issued stream capability and its ordered one-use
    /// token table on the original durable job. This method records opaque
    /// references only; the Kernel remains the sole issuer and validator.
    pub fn persist_blob_process_stream_grant(
        &self,
        job_id: &str,
        grant: TestdBlobProcessStreamGrant,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        grant.validate()?;
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| corrupt("job not found"))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let Some(stage_freshness) = job
            .stage_request
            .as_ref()
            .and_then(|stage| stage.provider_freshness.as_ref())
        else {
            return Err(TestdError::Invalid {
                field: "blob_stream.grant",
                reason: "stream capability requires a currentness-bound productive job",
            });
        };
        let Some(stage_lifecycle) = job
            .stage_request
            .as_ref()
            .and_then(|stage| stage.provider_catalog_lifecycle.as_ref())
        else {
            return Err(TestdError::Invalid {
                field: "blob_stream.grant",
                reason: "stream capability requires an accepted catalog lifecycle projection",
            });
        };
        stage_freshness.validate()?;
        stage_lifecycle.validate()?;
        let Some(tool_observation) = job.provider_tool_observation.as_ref() else {
            return Err(TestdError::Invalid {
                field: "blob_stream.grant",
                reason: "stream capability requires retained tool observation",
            });
        };
        let Some(environment) = job.provider_environment_projection.as_ref() else {
            return Err(TestdError::Invalid {
                field: "blob_stream.grant",
                reason: "stream capability requires retained process environment",
            });
        };
        let currentness_bytes = canonical_json_bytes(&(
            stage_freshness,
            stage_lifecycle,
            tool_observation,
            environment,
        ))
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        if sha256_hex(&currentness_bytes) != grant.currentness_sha256
            || job.invocation.profile != TESTD_PRODUCTIVE_PROFILE
        {
            return Err(TestdError::Invalid {
                field: "blob_stream.grant",
                reason: "stream capability requires a currentness-bound productive job",
            });
        }
        if let Some(existing) = &job.blob_process_stream_grant {
            if existing == &grant {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        job.blob_process_stream_grant = Some(grant);
        let encoded = serde_json::to_vec(&job)
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job_id, encoded.as_slice())
            .map_err(database)?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Resolves an exact opaque capability from the original job row. The
    /// caller is expected to be the authenticated Kernel issuer; this method
    /// does not interpret or mint any authority value.
    pub fn resolve_blob_process_stream_grant(
        &self,
        job_id: &str,
        capability_ref: &str,
    ) -> Result<TestdBlobProcessStreamGrantResolution, TestdError> {
        validate_text(job_id, "blob_stream.job_id")?;
        validate_text(capability_ref, "blob_stream.capability_ref")?;
        let Some(job) = self.get(job_id)? else {
            return Ok(TestdBlobProcessStreamGrantResolution::NotFound);
        };
        let Some(grant) = job.blob_process_stream_grant else {
            return Ok(TestdBlobProcessStreamGrantResolution::NotFound);
        };
        if grant.capability_ref != capability_ref {
            return Ok(TestdBlobProcessStreamGrantResolution::NotFound);
        }
        grant.validate()?;
        if grant.revoked_at_ms.is_some() {
            Ok(TestdBlobProcessStreamGrantResolution::Revoked)
        } else {
            Ok(TestdBlobProcessStreamGrantResolution::Active(grant))
        }
    }

    /// Permanently revokes the exact retained capability. Repeated revocation
    /// is idempotent; the first owner clock remains authoritative.
    pub fn revoke_blob_process_stream_grant(
        &self,
        job_id: &str,
        capability_ref: &str,
        now_ms: u64,
    ) -> Result<(), TestdError> {
        validate_text(job_id, "blob_stream.job_id")?;
        validate_text(capability_ref, "blob_stream.capability_ref")?;
        if now_ms == 0 {
            return Err(TestdError::Invalid {
                field: "blob_stream.revoked_at_ms",
                reason: "revocation clock must be non-zero",
            });
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or(TestdError::InvalidBinding)?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let grant = job
            .blob_process_stream_grant
            .as_mut()
            .filter(|grant| grant.capability_ref == capability_ref)
            .ok_or(TestdError::InvalidBinding)?;
        if grant.revoked_at_ms.is_none() {
            grant.revoked_at_ms = Some(now_ms);
            let encoded = serde_json::to_vec(&job)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            write
                .open_table(JOBS)
                .map_err(database)?
                .insert(job_id, encoded.as_slice())
                .map_err(database)?;
            write.commit().map_err(database)?;
        }
        Ok(())
    }

    /// Atomically reserves the next exact capability token before Kernel sends
    /// an operation to Blob. Replayed or uncertain reservations never authorize
    /// another Store dispatch.
    pub fn reserve_blob_process_stream_call(
        &self,
        job_id: &str,
        capability_ref: &str,
        token_ref: &str,
        ordinal: u32,
        operation_sha256: &str,
    ) -> Result<TestdBlobProcessStreamReserve, TestdError> {
        validate_blob_call_binding(job_id, capability_ref, token_ref, operation_sha256)?;
        let write = self.database.begin_write().map_err(database)?;
        let job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let Some(value) = table.get(job_id).map_err(database)? else {
                return Ok(TestdBlobProcessStreamReserve::Replay(
                    TestdBlobProcessStreamCallOutcome::Unavailable,
                ));
            };
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let Some(grant) = job.blob_process_stream_grant.as_ref() else {
            return Ok(TestdBlobProcessStreamReserve::Replay(
                TestdBlobProcessStreamCallOutcome::Unavailable,
            ));
        };
        grant.validate()?;
        if grant.revoked_at_ms.is_some() {
            return Ok(TestdBlobProcessStreamReserve::Replay(
                TestdBlobProcessStreamCallOutcome::Unavailable,
            ));
        }
        if grant.capability_ref != capability_ref
            || grant.tokens.get(ordinal as usize).is_none_or(|token| {
                token.ordinal != ordinal || token.reference != token_ref
            })
        {
            return Err(TestdError::InvalidBinding);
        }
        let key = blob_process_stream_call_key(job_id, capability_ref, token_ref)?;
        {
            let table = write
                .open_table(BLOB_PROCESS_STREAM_CALLS)
                .map_err(database)?;
            if let Some(value) = table.get(key.as_str()).map_err(database)? {
                let existing: TestdBlobProcessStreamCallRecord =
                    serde_json::from_slice(value.value())
                        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                if existing.job_id != job_id
                    || existing.capability_ref != capability_ref
                    || existing.token_ref != token_ref
                    || existing.ordinal != ordinal
                    || existing.operation_sha256 != operation_sha256
                {
                    return Err(TestdError::InvalidBinding);
                }
                return Ok(TestdBlobProcessStreamReserve::Replay(match existing.state {
                    TestdBlobProcessStreamCallState::Completed(outcome) => outcome,
                    TestdBlobProcessStreamCallState::Reserved
                    | TestdBlobProcessStreamCallState::Dispatched => {
                        TestdBlobProcessStreamCallOutcome::Unknown
                    }
                }));
            }
        }
        let mut highest = None;
        {
            let table = write
                .open_table(BLOB_PROCESS_STREAM_CALLS)
                .map_err(database)?;
            for item in table.iter().map_err(database)? {
                let (_, value) = item.map_err(database)?;
                let row: TestdBlobProcessStreamCallRecord =
                    serde_json::from_slice(value.value())
                        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                if row.job_id == job_id && row.capability_ref == capability_ref {
                    highest = Some(highest.map_or(row.ordinal, |value: u32| value.max(row.ordinal)));
                }
            }
        }
        if ordinal != highest.map_or(1, |value| value.saturating_add(1)) {
            return Err(TestdError::InvalidBinding);
        }
        let record = TestdBlobProcessStreamCallRecord {
            job_id: job_id.to_owned(),
            capability_ref: capability_ref.to_owned(),
            token_ref: token_ref.to_owned(),
            ordinal,
            operation_sha256: operation_sha256.to_owned(),
            state: TestdBlobProcessStreamCallState::Reserved,
        };
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        write
            .open_table(BLOB_PROCESS_STREAM_CALLS)
            .map_err(database)?
            .insert(key.as_str(), encoded.as_slice())
            .map_err(database)?;
        write.commit().map_err(database)?;
        Ok(TestdBlobProcessStreamReserve::Reserved)
    }

    /// Durably marks that Kernel is about to send the reserved logical call to
    /// Blob. A restart after this point must reconcile and cannot resend.
    pub fn mark_blob_process_stream_call_dispatched(
        &self,
        job_id: &str,
        capability_ref: &str,
        token_ref: &str,
        ordinal: u32,
        operation_sha256: &str,
    ) -> Result<(), TestdError> {
        self.update_blob_process_stream_call(
            job_id,
            capability_ref,
            token_ref,
            ordinal,
            operation_sha256,
            None,
        )
    }

    /// Retains a compact response reference/status after the Kernel exchange.
    /// Response bytes are never copied into the TestD owner ledger.
    pub fn complete_blob_process_stream_call(
        &self,
        job_id: &str,
        capability_ref: &str,
        token_ref: &str,
        ordinal: u32,
        operation_sha256: &str,
        outcome: TestdBlobProcessStreamCallOutcome,
    ) -> Result<(), TestdError> {
        validate_blob_process_stream_outcome(&outcome)?;
        self.update_blob_process_stream_call(
            job_id,
            capability_ref,
            token_ref,
            ordinal,
            operation_sha256,
            Some(outcome),
        )
    }

    /// Returns the durable state of an exact logical call. It does not send or
    /// allocate another token; a dispatched call without a retained result is
    /// explicitly Unknown.
    pub fn reconcile_blob_process_stream_call(
        &self,
        job_id: &str,
        capability_ref: &str,
        token_ref: &str,
        ordinal: u32,
        operation_sha256: &str,
    ) -> Result<TestdBlobProcessStreamResolution, TestdError> {
        validate_blob_call_binding(job_id, capability_ref, token_ref, operation_sha256)?;
        let read = self.database.begin_read().map_err(database)?;
        let table = read
            .open_table(BLOB_PROCESS_STREAM_CALLS)
            .map_err(database)?;
        let key = blob_process_stream_call_key(job_id, capability_ref, token_ref)?;
        let Some(value) = table.get(key.as_str()).map_err(database)? else {
            return Ok(TestdBlobProcessStreamResolution::NotReady);
        };
        let record: TestdBlobProcessStreamCallRecord =
            serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        validate_blob_process_stream_call_record(
            &record,
            job_id,
            capability_ref,
            token_ref,
            ordinal,
            operation_sha256,
        )?;
        Ok(match record.state {
            TestdBlobProcessStreamCallState::Reserved => {
                TestdBlobProcessStreamResolution::Completed(
                    TestdBlobProcessStreamCallOutcome::NotStarted,
                )
            }
            TestdBlobProcessStreamCallState::Dispatched => {
                TestdBlobProcessStreamResolution::Unknown
            }
            TestdBlobProcessStreamCallState::Completed(outcome) => {
                TestdBlobProcessStreamResolution::Completed(outcome)
            }
        })
    }

    fn update_blob_process_stream_call(
        &self,
        job_id: &str,
        capability_ref: &str,
        token_ref: &str,
        ordinal: u32,
        operation_sha256: &str,
        outcome: Option<TestdBlobProcessStreamCallOutcome>,
    ) -> Result<(), TestdError> {
        validate_blob_call_binding(job_id, capability_ref, token_ref, operation_sha256)?;
        let write = self.database.begin_write().map_err(database)?;
        let key = blob_process_stream_call_key(job_id, capability_ref, token_ref)?;
        let mut record = {
            let table = write
                .open_table(BLOB_PROCESS_STREAM_CALLS)
                .map_err(database)?;
            let value = table
                .get(key.as_str())
                .map_err(database)?
                .ok_or(TestdError::InvalidBinding)?;
            serde_json::from_slice::<TestdBlobProcessStreamCallRecord>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        validate_blob_process_stream_call_record(
            &record,
            job_id,
            capability_ref,
            token_ref,
            ordinal,
            operation_sha256,
        )?;
        match (record.state.clone(), outcome) {
            (TestdBlobProcessStreamCallState::Reserved, None) => {
                record.state = TestdBlobProcessStreamCallState::Dispatched;
            }
            (TestdBlobProcessStreamCallState::Dispatched, None) => return Ok(()),
            (TestdBlobProcessStreamCallState::Reserved, Some(outcome))
                if matches!(outcome, TestdBlobProcessStreamCallOutcome::NotStarted
                    | TestdBlobProcessStreamCallOutcome::Unavailable) =>
            {
                record.state = TestdBlobProcessStreamCallState::Completed(outcome);
            }
            (TestdBlobProcessStreamCallState::Dispatched, Some(outcome)) => {
                record.state = TestdBlobProcessStreamCallState::Completed(outcome);
            }
            (TestdBlobProcessStreamCallState::Completed(existing), Some(outcome))
                if existing == outcome => return Ok(()),
            // A protected reconciliation can resolve an earlier Unknown for
            // this exact logical call. Unknown is explicitly unresolved, so
            // replacing it with the retained owner outcome does not change
            // the request binding or authorize another Store dispatch.
            (TestdBlobProcessStreamCallState::Completed(
                TestdBlobProcessStreamCallOutcome::Unknown,
            ), Some(outcome)) => {
                record.state = TestdBlobProcessStreamCallState::Completed(outcome);
            }
            _ => return Err(TestdError::InvalidBinding),
        }
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        write
            .open_table(BLOB_PROCESS_STREAM_CALLS)
            .map_err(database)?
            .insert(key.as_str(), encoded.as_slice())
            .map_err(database)?;
        write.commit().map_err(database)?;
        Ok(())
    }

    /// Attaches the exact Governor request and current plan before a
    /// productive job can be claimed. Replays must supply byte-identical
    /// binding; a changed binding under the same durable job id conflicts.
    pub fn bind_verifier_dispatch(
        &self,
        job_id: &str,
        binding: TestdVerifierDispatchBinding,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        self.bind_verifier_dispatch_inner(job_id, binding, now, None)
    }

    fn bind_verifier_dispatch_inner(
        &self,
        job_id: &str,
        binding: TestdVerifierDispatchBinding,
        now: u64,
        expected_identity: Option<&RequestIdentity>,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if now == 0 {
            return Err(TestdError::Invalid {
                field: "verifier_dispatch",
                reason: "binding time must be non-zero",
            });
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if let Some(expected_identity) = expected_identity {
            let identities = write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
            let admitted = identities
                .get(job_id)
                .map_err(database)?
                .map(|value| serde_json::from_slice::<RequestIdentity>(value.value()))
                .transpose()
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if admitted.as_ref() != Some(expected_identity) {
                return Err(TestdError::InvalidBinding);
            }
            drop(identities);
        }
        binding.validate_for_job(&job)?;
        if job.invocation.profile != TESTD_PRODUCTIVE_PROFILE {
            return Err(TestdError::Invalid {
                field: "verifier_dispatch",
                reason: "canonical verifier binding is only valid for productive nextest jobs",
            });
        }
        if let Some(existing) = &job.verifier_dispatch {
            if existing == &binding {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        if job.state != JobState::Queued || job.attempts != 0 || job.lease.is_some() {
            return Err(TestdError::InvalidBinding);
        }
        job.verifier_dispatch = Some(binding);
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table.insert(job_id, encoded.as_slice()).map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(JobState::Queued),
            JobState::Queued,
            "verifier-dispatch-owner",
            now,
            Some("immutable canonical verifier plan bound before dispatch".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Persists the exact RequestIdentity taken from the authenticated
    /// Kernel frame before the daemon can bind a verifier plan or dispatch
    /// the productive job. Exact retries are idempotent; changed identity
    /// under the same durable job id conflicts.
    pub fn bind_admitted_request_identity(
        &self,
        job_id: &str,
        identity: RequestIdentity,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if now == 0 {
            return Err(TestdError::Invalid {
                field: "request_identity",
                reason: "identity time must be non-zero",
            });
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let metadata = &identity.request.metadata;
        let task_revision = identity
            .request
            .state_fence
            .task_revision
            .as_ref()
            .map(|revision| revision.value());
        if job.job_id != job_id
            || job.invocation.profile != TESTD_PRODUCTIVE_PROFILE
            || metadata.task_id.is_none()
            || task_revision.is_none_or(|revision| revision == 0)
            || metadata != &job.invocation.request
            || identity.request.state_fence != job.invocation.request.state_fence
            || job.process.operation_id != job.invocation.request.request_id.as_str()
            || !job
                .process
                .authority_epoch
                .is_same_authority(&identity.request.state_fence.authority_epoch)
            || job.process.generation != identity.request.state_fence.resource_generation.value()
            || job.state != JobState::Queued
            || job.attempts != 0
            || job.lease.is_some()
        {
            return Err(TestdError::InvalidBinding);
        }
        let admitted_identity = {
            let table = write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
            table
                .get(job_id)
                .map_err(database)?
                .map(|value| serde_json::from_slice::<RequestIdentity>(value.value()))
                .transpose()
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if let Some(existing) = admitted_identity {
            if existing == identity {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        if job.verifier_dispatch.is_some() {
            return Err(TestdError::InvalidBinding);
        }
        {
            let mut table = write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
            let encoded = serde_json::to_vec(&identity)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            table.insert(job_id, encoded.as_slice()).map_err(database)?;
        }
        job.updated_at_ms = now;
        {
            let mut table = write.open_table(JOBS).map_err(database)?;
            let encoded =
                serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
            table.insert(job_id, encoded.as_slice()).map_err(database)?;
        }
        append_event(
            &write,
            &job,
            Some(JobState::Queued),
            JobState::Queued,
            "authenticated-request-identity",
            now,
            Some("request identity retained from authenticated Kernel frame".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Requires the verifier binding to reuse the exact authenticated
    /// identity persisted at job admission. The legacy binding method stays
    /// available for non-production fixtures; the Kernel owner uses this
    /// stricter entry.
    pub fn bind_verifier_dispatch_for_admitted_identity(
        &self,
        job_id: &str,
        binding: TestdVerifierDispatchBinding,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        let identity = binding.request_identity.clone();
        self.bind_verifier_dispatch_inner(job_id, binding, now, Some(&identity))
    }

    /// Returns stable, bounded queued productive jobs that have an admitted
    /// RequestIdentity but still need their canonical verifier binding.
    pub fn pending_verifier_dispatches(
        &self,
        limit: usize,
    ) -> Result<Vec<TestdPendingVerifierDispatch>, TestdError> {
        if limit == 0 || limit > 64 {
            return Err(TestdError::Invalid {
                field: "verifier_dispatch.limit",
                reason: "must be between one and 64",
            });
        }
        let read = self.database.begin_read().map_err(database)?;
        let jobs = read.open_table(JOBS).map_err(database)?;
        let identities = read.open_table(ADMITTED_IDENTITIES).map_err(database)?;
        let mut pending = Vec::new();
        for item in jobs.iter().map_err(database)? {
            let (key, value) = item.map_err(database)?;
            let job: TestJob = serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            let job_id = key.value();
            if job.job_id != job_id {
                return Err(corrupt("durable job key conflicts with record"));
            }
            if job.invocation.profile != TESTD_PRODUCTIVE_PROFILE
                || job.state != JobState::Queued
                || job.attempts != 0
                || job.lease.is_some()
                || job.verifier_dispatch.is_some()
            {
                continue;
            }
            let Some(value) = identities.get(job_id).map_err(database)? else {
                continue;
            };
            let request_identity: RequestIdentity = serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            pending.push(TestdPendingVerifierDispatch {
                job,
                request_identity,
            });
        }
        pending.sort_by(|left, right| left.job.job_id.cmp(&right.job.job_id));
        pending.truncate(limit);
        Ok(pending)
    }

    /// Persists the real source identity before the first productive claim.
    /// An exact retry is idempotent; any changed source snapshot or post-claim
    /// rewrite is rejected.
    pub fn bind_source_observation_before_dispatch(
        &self,
        job_id: &str,
        observation: TestdSourceObservation,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        observation.validate()?;
        if now == 0 {
            return Err(TestdError::Invalid {
                field: "source_observation",
                reason: "observation time must be non-zero",
            });
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if job.invocation.profile != TESTD_PRODUCTIVE_PROFILE
            || job.verifier_dispatch.is_none()
            || job.state != JobState::Queued
            || job.attempts != 0
            || job.lease.is_some()
            || job.target_roots.source_root != observation.repository_root
        {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(existing) = &job.source_observation_before {
            if existing == &observation {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        job.source_observation_before = Some(observation);
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table.insert(job_id, encoded.as_slice()).map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(JobState::Queued),
            JobState::Queued,
            "verifier-source-observation",
            now,
            Some("actual branch, commit, and dirty state captured before dispatch".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Records one authenticated terminal notification. Only a terminal row
    /// with a full durable verification receipt and the exact active launch
    /// fence can enter the daemon publication queue.
    pub fn request_terminal_publication(
        &self,
        job_id: &str,
        receipt_sha256: &str,
        authority_epoch: &EpochId,
        generation: u64,
        operation_id: &str,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if !is_binding_digest(receipt_sha256) {
            return Err(TestdError::Invalid {
                field: "terminal_publication.receipt_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        validate_text(operation_id, "terminal_publication.operation_id")?;
        if generation == 0 || now == 0 {
            return Err(TestdError::InvalidBinding);
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let terminal = matches!(
            job.state,
            JobState::Succeeded | JobState::Failed | JobState::Cancelled
        );
        let Some(binding) = job.verifier_dispatch.as_ref() else {
            return Err(TestdError::InvalidBinding);
        };
        binding.validate_for_job(&job)?;
        let receipt = job
            .verification_receipt
            .as_ref()
            .ok_or(TestdError::InvalidBinding)?;
        if !terminal
            || job.lease.is_some()
            || job.process.generation != generation
            || !job
                .process
                .authority_epoch
                .is_same_authority(authority_epoch)
            || job.process.operation_id.as_str() != operation_id
            || verification_receipt_sha256(receipt)? != receipt_sha256
        {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(existing) = &job.terminal_publication {
            if existing.receipt_sha256 == receipt_sha256 {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        job.terminal_publication = Some(TestdTerminalPublication {
            receipt_sha256: receipt_sha256.to_owned(),
            committed_receipt_json: None,
        });
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table.insert(job_id, encoded.as_slice()).map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(job.state),
            job.state,
            "authenticated-testd-terminal",
            now,
            Some(format!("receipt-sha256={receipt_sha256}")),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Returns pending terminal notifications in stable job-id order for the
    /// daemon's reactive completion feed.
    pub fn pending_terminal_publications(
        &self,
        limit: usize,
    ) -> Result<Vec<TestdTerminalCompletionNotice>, TestdError> {
        if limit == 0 || limit > 256 {
            return Err(TestdError::Invalid {
                field: "terminal_publication.limit",
                reason: "must be between one and 256",
            });
        }
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        let mut pending = Vec::new();
        for item in table.iter().map_err(database)? {
            let (key, value) = item.map_err(database)?;
            let job: TestJob = serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if job.job_id != key.value() {
                return Err(corrupt("durable job key conflicts with record"));
            }
            if let Some(publication) = job.terminal_publication
                && publication.committed_receipt_json.is_none()
            {
                pending.push(TestdTerminalCompletionNotice {
                    job_id: job.job_id,
                    receipt_sha256: publication.receipt_sha256,
                });
            }
        }
        pending.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        pending.truncate(limit);
        Ok(pending)
    }

    /// Returns complete, identity-joined productive terminal evidence for
    /// the daemon's governed verifier-fact publisher. Every entry must still
    /// be pending its canonical WriteReceipt; worker exit alone is excluded.
    pub fn pending_terminal_completion_evidence(
        &self,
        limit: usize,
    ) -> Result<Vec<TestdTerminalCompletionEvidence>, TestdError> {
        if limit == 0 || limit > 64 {
            return Err(TestdError::Invalid {
                field: "terminal_publication.limit",
                reason: "must be between one and 64",
            });
        }
        let read = self.database.begin_read().map_err(database)?;
        let jobs = read.open_table(JOBS).map_err(database)?;
        let identities = read.open_table(ADMITTED_IDENTITIES).map_err(database)?;
        let mut pending = Vec::new();
        for item in jobs.iter().map_err(database)? {
            let (key, value) = item.map_err(database)?;
            let job: TestJob = serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if job.job_id != key.value() {
                return Err(corrupt("durable job key conflicts with record"));
            }
            let Some(publication) = job.terminal_publication.as_ref() else {
                continue;
            };
            if publication.committed_receipt_json.is_some()
                || !matches!(
                    job.state,
                    JobState::Succeeded | JobState::Failed | JobState::Cancelled
                )
                || job.lease.is_some()
            {
                continue;
            }
            let Some(binding) = job.verifier_dispatch.as_ref() else {
                continue;
            };
            binding.validate_for_job(&job)?;
            let Some(identity_value) = identities.get(job.job_id.as_str()).map_err(database)?
            else {
                continue;
            };
            let request_identity: RequestIdentity = serde_json::from_slice(identity_value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if request_identity != binding.request_identity
                || verification_receipt_sha256(
                    job.verification_receipt
                        .as_ref()
                        .ok_or(TestdError::InvalidBinding)?,
                )? != publication.receipt_sha256
            {
                return Err(TestdError::InvalidBinding);
            }
            pending.push(TestdTerminalCompletionEvidence {
                job,
                request_identity,
            });
        }
        pending.sort_by(|left, right| left.job.job_id.cmp(&right.job.job_id));
        pending.truncate(limit);
        Ok(pending)
    }

    /// Stores the exact serialized canonical WriteReceipt after the daemon
    /// publisher has returned from its committed owner boundary.
    pub fn record_terminal_publication_receipt(
        &self,
        job_id: &str,
        receipt_sha256: &str,
        committed_receipt_json: String,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if !is_binding_digest(receipt_sha256) {
            return Err(TestdError::Invalid {
                field: "terminal_publication.receipt_sha256",
                reason: "must be a lowercase SHA-256 digest",
            });
        }
        if now == 0 {
            return Err(TestdError::InvalidBinding);
        }
        let receipt_value: serde_json::Value = serde_json::from_str(&committed_receipt_json)
            .map_err(|_| TestdError::InvalidBinding)?;
        let canonical =
            canonical_json_bytes(&receipt_value).map_err(|_| TestdError::InvalidBinding)?;
        if String::from_utf8(canonical.clone()).map_err(|_| TestdError::InvalidBinding)?
            != committed_receipt_json
        {
            return Err(TestdError::InvalidBinding);
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let publication = job
            .terminal_publication
            .as_mut()
            .ok_or(TestdError::InvalidBinding)?;
        if publication.receipt_sha256 != receipt_sha256 {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(existing) = &publication.committed_receipt_json {
            if existing == &committed_receipt_json {
                return Ok(job);
            }
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        publication.committed_receipt_json = Some(committed_receipt_json);
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table.insert(job_id, encoded.as_slice()).map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(job.state),
            job.state,
            "governor-verifier-fact-receipt",
            now,
            Some(format!("write-receipt-sha256={}", sha256_hex(&canonical))),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Submits a job exactly once and assigns its project-local sequence.
    ///
    /// The job's declared class and resource profile come from
    /// [`JobSubmissionMetadata`], which binds the I2.22 class, weight,
    /// exclusive resources, and serial group. This route serves probe jobs;
    /// the priority integer is retained for wire compatibility but the class
    /// is what orders the job.
    #[allow(clippy::too_many_arguments)]
    pub fn submit(
        &self,
        job_id: impl Into<String>,
        project_id: impl Into<String>,
        invocation: InstrumentInvocation,
        permit: ProcessAdmissionPermit,
        target_roots: TargetRoots,
        priority: i32,
        at_ms: u64,
    ) -> Result<TestJob, TestdError> {
        self.submit_with_metadata(
            job_id.into(),
            project_id.into(),
            invocation,
            permit,
            target_roots,
            priority,
            JobSubmissionMetadata::verification(),
            at_ms,
        )
    }

    /// Submits one stage-bound job, persisting its complete profile/provider
    /// identity in the same transaction as the job row and payload digest.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_with_stage(
        &self,
        job_id: impl Into<String>,
        project_id: impl Into<String>,
        invocation: InstrumentInvocation,
        stage_request: InstrumentStageRequest,
        permit: ProcessAdmissionPermit,
        target_roots: TargetRoots,
        priority: i32,
        at_ms: u64,
    ) -> Result<TestJob, TestdError> {
        stage_request.validate()?;
        if stage_request.invocation != invocation {
            return Err(TestdError::InvalidBinding);
        }
        self.submit_inner(
            job_id.into(),
            project_id.into(),
            invocation,
            permit,
            target_roots,
            None,
            None,
            priority,
            JobSubmissionMetadata::verification(),
            at_ms,
            None,
            Some(stage_request),
            None,
            None,
        )
    }

    /// Submits a job carrying its declared class and resource profile.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_with_metadata(
        &self,
        job_id: impl Into<String>,
        project_id: impl Into<String>,
        invocation: InstrumentInvocation,
        permit: ProcessAdmissionPermit,
        target_roots: TargetRoots,
        priority: i32,
        metadata: JobSubmissionMetadata,
        at_ms: u64,
    ) -> Result<TestJob, TestdError> {
        self.submit_inner(
            job_id.into(),
            project_id.into(),
            invocation,
            permit,
            target_roots,
            None,
            None,
            priority,
            metadata,
            at_ms,
            None,
            None,
            None,
            None,
        )
    }

    /// Admits one job whose roots were resolved from an owner-issued
    /// workspace/checkout/class layout (issue #1806). The roots must verify
    /// against the binding before the row commits; a missing safe root is a
    /// typed refusal, never a fallback.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_with_layout(
        &self,
        job_id: impl Into<String>,
        project_id: impl Into<String>,
        invocation: InstrumentInvocation,
        permit: ProcessAdmissionPermit,
        target_roots: TargetRoots,
        target_layout: TargetLayoutBinding,
        priority: i32,
        metadata: JobSubmissionMetadata,
        at_ms: u64,
    ) -> Result<TestJob, TestdError> {
        self.submit_inner(
            job_id.into(),
            project_id.into(),
            invocation,
            permit,
            target_roots,
            Some(target_layout),
            None,
            priority,
            metadata,
            at_ms,
            None,
            None,
            None,
            None,
        )
    }

    /// Shared transaction for legacy submissions and authenticated productive
    /// submissions. When identity is present, the job row and its exact
    /// authenticated RequestIdentity become visible in the same redb commit.
    #[allow(clippy::too_many_arguments)]
    fn submit_inner(
        &self,
        job_id: String,
        project_id: String,
        invocation: InstrumentInvocation,
        permit: ProcessAdmissionPermit,
        target_roots: TargetRoots,
        target_layout: Option<TargetLayoutBinding>,
        lane: Option<LaneIdentity>,
        priority: i32,
        metadata: JobSubmissionMetadata,
        at_ms: u64,
        identity: Option<RequestIdentity>,
        stage_request: Option<InstrumentStageRequest>,
        provider_tool_observation: Option<TestdToolObservation>,
        provider_environment_projection: Option<EnvironmentProjection>,
    ) -> Result<TestJob, TestdError> {
        validate_text(&job_id, "job_id")?;
        validate_text(&project_id, "project_id")?;
        metadata.validate()?;
        let JobSubmissionMetadata {
            job_class,
            resource_profile,
        } = metadata;
        invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if let Some(stage) = &stage_request {
            stage.validate()?;
            if stage.invocation != invocation {
                return Err(TestdError::InvalidBinding);
            }
        }
        if provider_tool_observation.is_some() != provider_environment_projection.is_some() {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(observation) = &provider_tool_observation {
            observation.validate()?;
        }
        let (process, grant) = permit.into_parts();
        if let Some(environment) = &provider_environment_projection {
            if process.environment() != environment {
                return Err(TestdError::InvalidBinding);
            }
            EnvironmentProjection::new(
                environment.non_secret().clone(),
                environment.secret_refs().to_vec(),
                environment.inheritance(),
            )
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        }
        process
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        grant.validate_for_process(&job_id, invocation.request.request_id.as_str(), &process)?;
        if !matches!(invocation.kind, InstrumentKind::Test) {
            return Err(TestdError::WrongInstrumentKind);
        }
        // Closed-profile registration (issue #20): only registered
        // profiles register. The probe and productive profiles take no
        // caller arguments: fixed argv comes from the registry binding,
        // never from the invocation. The slotted list/scoped profiles
        // (issue #1802, step 4) validate their arguments through the slot
        // schema instead; the Drive seals exactly the rendered argv.
        if !is_admitted_testd_profile(&invocation.profile) {
            return Err(TestdError::Invalid {
                field: "invocation.profile",
                reason: "testd admits only registered probe or productive nextest profiles",
            });
        }
        if !invocation.arguments.is_empty() {
            if is_slotted_testd_profile(&invocation.profile) {
                parse_testd_slot_suffix(&invocation.profile, &invocation.arguments)?;
            } else {
                return Err(TestdError::Invalid {
                    field: "invocation.arguments",
                    reason: "the admitted profile takes fixed argv; caller arguments are refused",
                });
            }
        }
        if invocation.request.request_id.as_str() != process.operation_id().as_str() {
            return Err(TestdError::InvalidBinding);
        }
        if !invocation
            .request
            .state_fence
            .authority_epoch
            .is_same_authority(process.fence().authority_epoch())
            || invocation.request.state_fence.resource_generation.value()
                != process.generation().get()
        {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(identity) = &identity {
            identity
                .validate()
                .map_err(|_| TestdError::InvalidBinding)?;
            let task_revision = identity
                .request
                .state_fence
                .task_revision
                .as_ref()
                .map(|revision| revision.value());
            if invocation.profile != TESTD_PRODUCTIVE_PROFILE
                || identity.request.metadata.task_id.is_none()
                || task_revision.is_none_or(|revision| revision == 0)
                || identity.request.metadata != invocation.request
                || identity.request.state_fence != invocation.request.state_fence
                || job_id != process.job_id().as_str()
                || process.operation_id().as_str() != invocation.request.request_id.as_str()
                || !process
                    .fence()
                    .authority_epoch()
                    .is_same_authority(&identity.request.state_fence.authority_epoch)
                || process.generation().get()
                    != identity.request.state_fence.resource_generation.value()
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        // Issue #1897 (W1): allocate the governed work-execution envelope
        // for the productive submission path. The claims are the job's own
        // declared exclusive resources — the submission carries no second
        // claim set, so the tuple cannot disagree with the scheduler's
        // declaration — and the leases stay empty until `claim_next`
        // grants them.
        let work_envelope = lane
            .map(|identity| {
                GovernedWorkEnvelope::allocate(
                    identity,
                    resource_profile.exclusive_resources.clone(),
                    Vec::new(),
                )
            })
            .transpose()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        if let (Some(envelope), Some(layout)) = (work_envelope.as_ref(), target_layout.as_ref())
            && let Some(expected) = layout.build_fingerprint.as_deref()
        {
            // The layout binding names the exact fingerprint its bound
            // output must satisfy; an allocated lane that disagrees with
            // it is refused rather than persisted beside it.
            let digest = envelope
                .normalized_fingerprint()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
            if expected != digest {
                return Err(TestdError::InvalidBinding);
            }
        }
        // Issue #1897 (W4): allocate the fixture namespace for this work item
        // in the same admitting transaction that allocates and persists its
        // envelope, and take it from the whole lane tuple through the
        // envelope's own derivation. It is never taken from the worktree, the
        // project id, the job id, or a counter, and it is allocated once per
        // work item rather than derived on demand at each use, so a restart
        // consumes the retained value instead of a replacement one.
        let fixture_namespace = work_envelope
            .as_ref()
            .map(|envelope| {
                envelope
                    .fixture_namespace()
                    .map_err(|error| TestdError::Contract(error.to_string()))
            })
            .transpose()?;
        // Issue #1897 (W1/W3/AUD4): an allocated lane is the ONE target-root
        // authority for this job. `TargetRoots` (issue #1806) and
        // `TargetLayoutBinding` are a second, competing derivation, so for an
        // enveloped job the layout contributes the admitted build root and the
        // workspace/checkout identity only, and the envelope contributes the
        // whole governed root. `TargetRoots::validate` keeps its existing
        // `cache_root == target_root` equality and its strict-descendant
        // requirement — this adds no distinctness on either side, it refuses
        // the disagreement.
        let mut target_roots = target_roots;
        target_roots.allowed_contour_root = grant.contour_root.clone();
        target_roots.validate()?;
        verify_job_lane(
            &target_roots,
            target_layout.as_ref(),
            work_envelope.as_ref(),
            fixture_namespace.as_deref(),
        )?;
        let digest = payload_digest(
            &invocation,
            &process,
            &target_roots,
            priority,
            job_class,
            &resource_profile,
            work_envelope.as_ref(),
            fixture_namespace.as_deref(),
            stage_request.as_ref(),
            provider_tool_observation.as_ref(),
            provider_environment_projection.as_ref(),
        )?;
        let process = ProcessAdmission::from_request(&process);
        let write = self.database.begin_write().map_err(database)?;
        let existing = {
            let table = write.open_table(JOBS).map_err(database)?;
            table
                .get(job_id.as_str())
                .map_err(database)?
                .map(|value| serde_json::from_slice::<TestJob>(value.value()))
        };
        if let Some(existing) = existing {
            let mut existing = existing.map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if existing.payload_digest != digest {
                return Err(TestdError::JobConflict(job_id));
            }
            if existing.target_layout != target_layout {
                return Err(TestdError::JobConflict(job_id));
            }
            if let Some(identity) = identity {
                let retained = {
                    let table = write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
                    table
                        .get(job_id.as_str())
                        .map_err(database)?
                        .map(|value| serde_json::from_slice::<RequestIdentity>(value.value()))
                        .transpose()
                        .map_err(|error| TestdError::Corrupt(error.to_string()))?
                };
                match retained {
                    Some(retained) if retained == identity => return Ok(existing),
                    Some(_) => return Err(TestdError::JobConflict(job_id)),
                    None => {
                        if existing.state != JobState::Queued
                            || existing.attempts != 0
                            || existing.lease.is_some()
                            || existing.verifier_dispatch.is_some()
                        {
                            return Err(TestdError::InvalidBinding);
                        }
                        {
                            let mut table =
                                write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
                            let encoded = serde_json::to_vec(&identity)
                                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                            table
                                .insert(job_id.as_str(), encoded.as_slice())
                                .map_err(database)?;
                        }
                        existing.updated_at_ms = at_ms;
                        {
                            let encoded = serde_json::to_vec(&existing)
                                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                            let mut table = write.open_table(JOBS).map_err(database)?;
                            table
                                .insert(job_id.as_str(), encoded.as_slice())
                                .map_err(database)?;
                        }
                        append_event(
                            &write,
                            &existing,
                            Some(JobState::Queued),
                            JobState::Queued,
                            "authenticated-request-identity",
                            at_ms,
                            Some(
                                "request identity retained from authenticated Kernel frame"
                                    .to_owned(),
                            ),
                        )?;
                        write.commit().map_err(database)?;
                        return Ok(existing);
                    }
                }
            }
            return Ok(existing);
        }
        let sequence_key = format!("project:{project_id}");
        let sequence = {
            let mut meta = write.open_table(META).map_err(database)?;
            let previous = meta
                .get(sequence_key.as_str())
                .map_err(database)?
                .map_or(Ok(0), |value| decode_project_sequence(value.value()))?;
            let next = previous
                .checked_add(1)
                .ok_or_else(|| corrupt("project sequence exhausted"))?;
            let encoded = serde_json::to_vec(&next)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            meta.insert(sequence_key.as_str(), encoded.as_slice())
                .map_err(database)?;
            next
        };
        let job = TestJob {
            job_id: job_id.clone(),
            project_id,
            project_sequence: sequence,
            invocation,
            stage_request,
            provider_tool_observation,
            provider_environment_projection,
            blob_process_stream_grant: None,
            process,
            target_roots,
            target_layout,
            work_envelope,
            fixture_namespace,
            priority,
            job_class,
            resource_profile,
            scheduling: None,
            state: JobState::Queued,
            attempts: 0,
            not_before_ms: at_ms,
            lease: None,
            execution: None,
            verification: None,
            receipt: None,
            verification_receipt: None,
            verifier_dispatch: None,
            source_observation_before: None,
            terminal_publication: None,
            updated_at_ms: at_ms,
            payload_digest: digest,
        };
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        let has_identity = identity.is_some();
        if let Some(identity) = identity {
            let encoded = serde_json::to_vec(&identity)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            let mut table = write.open_table(ADMITTED_IDENTITIES).map_err(database)?;
            table
                .insert(job_id.as_str(), encoded.as_slice())
                .map_err(database)?;
            drop(table);
        }
        append_event(&write, &job, None, JobState::Queued, "submit", at_ms, None)?;
        if has_identity {
            append_event(
                &write,
                &job,
                Some(JobState::Queued),
                JobState::Queued,
                "authenticated-request-identity",
                at_ms,
                Some("request identity retained from authenticated Kernel frame".to_owned()),
            )?;
        }
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Kernel-owner productive submission. The one-shot process permit is
    /// consumed into the durable job, then the authenticated frame identity
    /// is retained before the job can be returned to a dispatch poller.
    pub fn submit_productive_verifier(
        &self,
        submission: TestdVerifierJobSubmission,
        identity: RequestIdentity,
        permit: ProcessAdmissionPermit,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        submission.validate()?;
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        if now == 0
            || identity.request.metadata != submission.invocation.request
            || identity.request.state_fence != submission.invocation.request.state_fence
        {
            return Err(TestdError::InvalidBinding);
        }
        self.submit_inner(
            submission.job_id,
            submission.project_id,
            submission.invocation,
            permit,
            submission.target_roots,
            submission.target_layout,
            submission.lane,
            submission.priority,
            submission.metadata,
            now,
            Some(identity),
            submission.stage_request,
            Some(submission.provider_tool_observation),
            Some(submission.provider_environment_projection),
        )
    }

    /// Claims the oldest ready head of a project, with priority as a tie-breaker.
    pub fn claim_next(
        &self,
        owner: impl Into<String>,
        now: u64,
        lease_ms: u64,
    ) -> Result<Option<TestJob>, TestdError> {
        let owner = owner.into();
        validate_text(&owner, "owner")?;
        if lease_ms == 0 {
            return Err(TestdError::Invalid {
                field: "lease_ms",
                reason: "must be non-zero",
            });
        }
        // Opportunistic restart recovery: fence-expired running jobs reconcile
        // to Unknown/RetryWait on absent process evidence instead of blocking
        // their project head forever. A reconciled job never reruns silently;
        // it needs a fresh claim, lease, and permit binding.
        self.reconcile_expired_running_all(now)?;
        let running_weight = self.running_weight_units()?;
        let candidates = self.ready_heads(now)?;
        let Some(candidate) = candidates
            .into_iter()
            .filter(|candidate| {
                candidate.invocation.profile != TESTD_PRODUCTIVE_PROFILE
                    || candidate.verifier_dispatch.is_some()
            })
            .filter(|candidate| {
                // A background job may not consume the capacity reserved for
                // Kernel, Watchdog, Control Reserve, verification, and
                // interactive product work. Under constrained capacity a
                // background job waits rather than displacing a protected
                // class, so a queued verification job still starts first.
                !candidate.job_class.is_background() || running_weight < RESERVED_FOREGROUND_WEIGHT
            })
            .max_by(compare_ready)
        else {
            return Ok(None);
        };
        let mut job = candidate;
        let write = self.database.begin_write().map_err(database)?;
        let persisted = {
            let table = write.open_table(JOBS).map_err(database)?;
            let current = table
                .get(job.job_id.as_str())
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("claimed job disappeared".to_owned()))?;
            serde_json::from_slice::<TestJob>(current.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        job = persisted;
        job.target_roots.validate()?;
        if !matches!(job.state, JobState::Queued | JobState::RetryWait)
            || job.not_before_ms > now
            || job.lease.is_some()
        {
            return Ok(None);
        }
        let previous = job.state;
        // Allocate the runtime leases this job declared and record the
        // scheduling decision, so the work item execution record carries both
        // the decision and the distinct leases it received. The lease state is
        // rebuilt from the durable record inside the same write transaction,
        // so a competing claim committed first still wins and this claim is
        // refused rather than overlapping.
        let mut held = held_leases_in(&write, &job.job_id)?;
        let leases = held
            .allocate(&job.job_id, &job.resource_profile)
            .map_err(|error| TestdError::ResourceConflict(error.to_string()))?;
        job.scheduling = Some(
            scheduling_decision(job.job_class, &job.resource_profile, leases.clone())
                .map_err(|error| TestdError::ResourceConflict(error.to_string()))?,
        );
        // Issue #1897 (W1/W5/AUD3/AUD4): record the allocator's ACTUAL grant on
        // the allocated envelope, so the persisted work item keeps the leases it
        // was admitted with. `leases` is the live `ResourceLeaseAllocator`
        // outcome, not a reconstruction of matching field values: the allocator
        // refused above if any declared resource or serial group was already
        // held, and `with_granted_leases` additionally refuses a record whose
        // holder is not this job. The envelope is the only writer of that
        // record, so two jobs cannot claim one exclusive resource by presenting
        // identical lease DTOs. Because the allocator grants exactly the
        // declared claims, this is also where a mutating work item acquires its
        // runtime-environment lease: a lane that declared the fixture state it
        // touches is granted a lease naming that same state, and the persisted
        // envelope carries the grant. `GovernedWorkEnvelope::admit`, which the
        // claimed start path runs, refuses any tuple whose claims and leases do
        // not correspond.
        if let Some(envelope) = job.work_envelope.take() {
            job.work_envelope = Some(
                envelope
                    .with_granted_leases(
                        leases
                            .iter()
                            .map(|lease| RuntimeEnvironmentLease {
                                kind: lease.kind,
                                resource: lease.resource.clone(),
                                holder: lease.holder.clone(),
                            })
                            .collect(),
                    )
                    .map_err(|error| TestdError::ResourceConflict(error.to_string()))?,
            );
        }
        job.state = JobState::Running;
        job.attempts = job.attempts.saturating_add(1);
        job.execution = Some(ExecutionStatus::Running);
        job.lease = Some(Lease {
            owner: owner.clone(),
            token: Uuid::new_v4().to_string(),
            epoch: u64::from(job.attempts),
            expires_at_ms: now.saturating_add(lease_ms),
        });
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            JobState::Running,
            &owner,
            now,
            None,
        )?;
        write.commit().map_err(database)?;
        Ok(Some(job))
    }

    /// Binds one claimed job to a freshly-issued process permit (preflight).
    ///
    /// The durable record is reloaded by id and is the only authority; a
    /// caller-owned job is never accepted. The live lease, the stable
    /// operation/process-tree/generation/epoch/invocation/roots tuple, and
    /// the issuer grant binding must all match exactly, and the presented
    /// request must pass #100 dispatch validation. On success the consuming
    /// request is returned for the bins-side starter; this method performs no
    /// OS start itself. Any binding failure returns a typed [`TestdError`].
    pub fn bind_claimed_process_start(
        &self,
        job_id: &str,
        lease: &Lease,
        now: u64,
        permit: ProcessAdmissionPermit,
    ) -> Result<ProcessRequest, TestdError> {
        validate_text(job_id, "job_id")?;
        let job = self
            .get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
        job.target_roots.validate()?;
        verify_job_lane(
            &job.target_roots,
            job.target_layout.as_ref(),
            job.work_envelope.as_ref(),
            job.fixture_namespace.as_deref(),
        )?;
        // Issue #1897 (AUD4): run the COMPLETE admission gate on the retained
        // envelope before this attempt starts, not the shape-only requalify.
        // `requalify` proved the tuple is well-formed and that the retained
        // lease record is this job's own; it did not require the job to have
        // declared anything at all, so a persisted empty-claim/empty-lease
        // productive job passed it and executed. `admit` additionally refuses
        // an empty claim set, a claim with no held lease, and a held lease with
        // no claim behind it, so a worktree alone cannot reach a shared runtime
        // resource and a restart cannot execute a job that never declared what
        // it would touch. The row just read is the durable authority: nothing
        // here is re-derived from the current ambient environment.
        if let Some(envelope) = job.work_envelope.as_ref() {
            envelope.admit().map_err(|_| TestdError::InvalidBinding)?;
        }
        let request = permit.request();
        request
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let invocation_id = job.invocation.request.request_id.as_str();
        permit
            .grant()
            .validate_for_process(&job.job_id, invocation_id, request)?;
        let target_root = request
            .environment()
            .non_secret()
            .get("CARGO_TARGET_DIR")
            .ok_or(TestdError::InvalidBinding)?;
        let cache_root = request
            .environment()
            .non_secret()
            .get("CARGO_HOME")
            .ok_or(TestdError::InvalidBinding)?;
        // Issue #1897 (W3): the governed Cargo invocation must run under the
        // target root this work item was admitted with. The two values read
        // above are the invocation's own `CARGO_TARGET_DIR` and `CARGO_HOME`;
        // they are compared against the environment derived from the RETAINED
        // envelope, never against a tuple rebuilt from the current ambient
        // environment. An enveloped job therefore cannot execute in the
        // repository `target/`, in the user-global Cargo home, or in any root
        // other than the one its persisted envelope allocated. Both sides bind
        // the same directory, so this adds no distinctness: the existing
        // `cache_root == target_root` rule stays the single cache/target
        // relation, and the process environment resolver that emitted these
        // values (`TestdProcessToolIntent::validate_for_roots`) already refused
        // any other pairing.
        if let Some(envelope) = job.work_envelope.as_ref() {
            let governed = envelope
                .cargo_environment()
                .map_err(|_| TestdError::InvalidBinding)?;
            for (variable, expected) in [
                (CARGO_TARGET_DIR_ENV, target_root.as_str()),
                (CARGO_HOME_ENV, cache_root.as_str()),
            ] {
                let bound = governed
                    .iter()
                    .find(|(name, _)| name == variable)
                    .map(|(_, value)| value.as_str());
                if bound != Some(expected) {
                    return Err(TestdError::InvalidBinding);
                }
            }
            // Issue #1897 (AUD2): the fixture bindings the process request
            // carries are compared against the same RETAINED envelope, by
            // content and independently of the values this method was handed:
            // the namespace the job was admitted under, and the physical root
            // that namespace resolves to. A request naming another lane's
            // namespace, or a fixture root that is not this lane's, refuses
            // here before any process starts, so a restart cannot swap which
            // fixture tree the run touches.
            let non_secret = request.environment().non_secret();
            for (name, expected) in envelope
                .fixture_environment()
                .map_err(|_| TestdError::InvalidBinding)?
            {
                if non_secret.get(&name) != Some(&expected) {
                    return Err(TestdError::InvalidBinding);
                }
            }
        }
        let expected = ClaimBindingExpectation {
            operation_id: request.operation_id().as_str(),
            process_tree_id: request.process_tree_id().as_str(),
            generation: request.generation().get(),
            authority_epoch: request.fence().authority_epoch(),
            invocation_id,
            allowed_contour_root: permit.grant().contour_root(),
            source_root: request.working_directory(),
            target_root: target_root.as_str(),
            cache_root: cache_root.as_str(),
        };
        validate_claim_binding(&job, lease, now, &expected)?;
        Ok(permit.into_parts().0)
    }

    /// Renews one live worker fence without changing its owner, token, or
    /// attempt epoch.  The current row read, expiry check, and lease update
    /// share one write transaction so a reclaimed or cancelled attempt can
    /// never be renewed by a stale worker.
    pub fn renew_lease(
        &self,
        job_id: &str,
        lease: &Lease,
        now: u64,
        lease_ms: u64,
    ) -> Result<Lease, TestdError> {
        validate_text(job_id, "job_id")?;
        if lease_ms == 0 {
            return Err(TestdError::Invalid {
                field: "lease_ms",
                reason: "must be non-zero",
            });
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if !lease_matches(&job, lease, now) {
            return Err(TestdError::LeaseRejected(job_id.to_owned()));
        }
        let renewed = Lease {
            owner: lease.owner.clone(),
            token: lease.token.clone(),
            epoch: lease.epoch,
            expires_at_ms: now.saturating_add(lease_ms),
        };
        job.lease = Some(renewed.clone());
        job.updated_at_ms = now;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(JobState::Running),
            JobState::Running,
            &lease.owner,
            now,
            Some("worker lease renewed".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(renewed)
    }

    /// Recovers one fence-expired running job to Unknown/RetryWait.
    ///
    /// Returns `Ok(None)` when the job needs no reconciliation (not running,
    /// or still under a live fence). Otherwise the attempt is durably closed
    /// as [`ExecutionStatus::Unknown`] with the lease cleared and bounded
    /// retry timing applied, so a later attempt requires a fresh claim and
    /// `bind_claimed_process_start`. The optional process lifecycle is the
    /// process-evidence check; terminal evidence still lands on `Unknown`
    /// because only `finish` with a validated receipt may resolve an attempt.
    pub fn reconcile_expired(
        &self,
        job_id: &str,
        now: u64,
        evidence: Option<eliot_process::ProcessLifecycle>,
    ) -> Result<Option<TestJob>, TestdError> {
        validate_text(job_id, "job_id")?;
        let job = self
            .get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
        let Some(decision) = reconcile_expired_running(&job, now, evidence) else {
            return Ok(None);
        };
        self.persist_expiry_reconciliation(job, now, decision)
            .map(Some)
    }

    /// Restart sweeper for fence-expired running jobs without live evidence.
    ///
    /// Reconciles every running job whose fence no longer holds at `now` to
    /// Unknown/RetryWait (or Failed once attempts are exhausted), so a daemon
    /// restart cannot leave a project head blocked behind an orphaned lease
    /// and can never silently rerun ambiguous work. Callers that hold live
    /// executor evidence reconcile those jobs explicitly via
    /// [`TestdStore::reconcile_expired`] instead.
    pub fn reconcile_expired_running_all(&self, now: u64) -> Result<Vec<TestJob>, TestdError> {
        let running = {
            let read = self.database.begin_read().map_err(database)?;
            let table = read.open_table(JOBS).map_err(database)?;
            let mut running = Vec::new();
            for item in table.iter().map_err(database)? {
                let (key, value) = item.map_err(database)?;
                let job: TestJob = serde_json::from_slice(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                // A cancelled attempt that still reports `Running` execution
                // (issue #1897) holds runtime leases its cancelled process may
                // still be using, so it is swept with the running rows.
                if matches!(job.state, JobState::Running)
                    || (job.state == JobState::Cancelled
                        && job.execution == Some(ExecutionStatus::Running))
                {
                    running.push(key.value().to_owned());
                }
            }
            running
        };
        let mut reconciled = Vec::new();
        for job_id in running {
            if let Some(job) = self.reconcile_expired(&job_id, now, None)? {
                reconciled.push(job);
            }
        }
        Ok(reconciled)
    }

    fn persist_expiry_reconciliation(
        &self,
        mut job: TestJob,
        now: u64,
        decision: ExpiredRunningReconciliation,
    ) -> Result<TestJob, TestdError> {
        let actor = job
            .lease
            .as_ref()
            .map_or("testd-reconciler", |lease| lease.owner.as_str())
            .to_owned();
        let previous = job.state;
        let cancelled_unresolved =
            job.state == JobState::Cancelled && job.execution == Some(ExecutionStatus::Running);
        job.execution = Some(decision.execution);
        job.lease = None;
        let terminal = if cancelled_unresolved {
            // A cancelled attempt stays cancelled: reconciliation here releases
            // its runtime leases, it does not resurrect the work (issue #1897).
            JobState::Cancelled
        } else if job.attempts < self.retry.max_attempts {
            JobState::RetryWait
        } else {
            JobState::Failed
        };
        job.state = terminal;
        job.not_before_ms = if terminal == JobState::RetryWait {
            now.saturating_add(
                self.retry.delays_ms
                    [(job.attempts.saturating_sub(1) as usize).min(self.retry.delays_ms.len() - 1)],
            )
        } else {
            now
        };
        job.updated_at_ms = now;
        let write = self.database.begin_write().map_err(database)?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            terminal,
            &actor,
            now,
            Some(decision.reason.to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Completes an attempt, or durably schedules a bounded retry.
    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &self,
        job_id: &str,
        lease: &Lease,
        execution: ExecutionStatus,
        verification: Option<VerificationRun>,
        receipt: &VerificationReceipt,
        now: u64,
        reason: Option<String>,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if let Some(run) = &verification {
            run.validate()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
        }
        // The current row and the final mutation share one redb write
        // transaction.  A read through `self.get` here would leave a race in
        // which cancel/reclaim commits between the lease check and the
        // unconditional insert below, allowing a stale worker to overwrite a
        // newer owner state.
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let table = write.open_table(JOBS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if !lease_matches(&job, lease, now) {
            // Fail closed: an expired or foreign fence never completes an
            // attempt. Recovery flows through `reconcile_expired`
            // (Unknown/RetryWait) followed by a fresh claim and
            // `bind_claimed_process_start`, never through this path.
            return Err(TestdError::LeaseRejected(job_id.to_owned()));
        }
        receipt.validate(&job)?;
        if receipt.execution != execution {
            return Err(TestdError::InvalidBinding);
        }
        let binding = receipt.binding();
        if let Some(run) = &verification
            && (run.invocation_id.as_str() != job.invocation.request.request_id.as_str()
                || run.state_fence != job.invocation.request.state_fence)
        {
            return Err(TestdError::InvalidBinding);
        }
        let previous = job.state;
        job.execution = Some(execution);
        job.verification = verification;
        job.receipt = Some(binding);
        job.verification_receipt = Some(receipt.clone());
        job.lease = None;
        let retryable = matches!(
            execution,
            ExecutionStatus::Unknown | ExecutionStatus::Failed
        );
        let terminal = if matches!(execution, ExecutionStatus::Succeeded) {
            // Local daemon projection only: a local Succeeded never becomes a
            // canonical Durable Job outcome. Canonical promotion happens
            // exclusively through the Governor path; this subtree has no
            // canonical-store authority.
            JobState::Succeeded
        } else if retryable && job.attempts < self.retry.max_attempts {
            JobState::RetryWait
        } else if matches!(execution, ExecutionStatus::Cancelled) {
            JobState::Cancelled
        } else {
            JobState::Failed
        };
        job.state = terminal;
        job.not_before_ms = if terminal == JobState::RetryWait {
            now.saturating_add(
                self.retry.delays_ms
                    [(job.attempts.saturating_sub(1) as usize).min(self.retry.delays_ms.len() - 1)],
            )
        } else {
            now
        };
        job.updated_at_ms = now;
        let mut table = write.open_table(JOBS).map_err(database)?;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            terminal,
            &lease.owner,
            now,
            reason,
        )?;
        write.commit().map_err(database)?;
        // Resolve the owner row after commit so the caller receives the
        // durable readback rather than a pre-commit projection.  A later
        // retry claim may legitimately advance a RetryWait row before this
        // read; returning that current row keeps callers from treating an
        // obsolete attempt image as current.
        self.get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("committed job disappeared".to_owned()))
    }

    /// Cancels a queued or currently leased job using its current fence.
    ///
    /// Cancelling a *running* attempt clears the worker fence but does not
    /// release its runtime-environment leases: the process may still be alive
    /// and its effect on a port, service, fixture, or database volume is not yet
    /// observed. The retained [`SchedulingDecision`](super::SchedulingDecision)
    /// therefore stays on the row, and the reconciler — not this call — resolves
    /// the attempt and frees the leases. A queued job holds no lease and is
    /// released immediately.
    pub fn cancel(
        &self,
        job_id: &str,
        lease: Option<&Lease>,
        actor: &str,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        let mut job = self
            .get(job_id)?
            .ok_or_else(|| TestdError::Corrupt("job not found".to_owned()))?;
        if job.state.is_terminal() {
            return Ok(job);
        }
        validate_cancellation_lease(&job, lease, actor, now)?;
        validate_text(actor, "actor")?;
        // Issue #1897 (AUD6): cancellation reads the same retained envelope as
        // admission and execution. It requalifies the tuple before the worker
        // fence is cleared, so a cancelled attempt can only stop work whose
        // retained lease record is its own. A record naming another holder is a
        // copied DTO and refuses here instead of releasing a resource the
        // requesting transport never actually held. Nothing is re-derived from
        // the current ambient environment.
        if let Some(envelope) = job.work_envelope.as_ref() {
            envelope
                .requalify()
                .map_err(|_| TestdError::InvalidBinding)?;
        }
        let previous = job.state;
        let was_running = previous == JobState::Running;
        job.state = JobState::Cancelled;
        job.lease = None;
        // Issue #1897 (W5): cancelling a *running* attempt records the
        // cancellation, not the outcome. The worker fence is cleared so the
        // cancelled worker loses write authority, but the process may still be
        // alive and its effect on a leased port, service, fixture, or database
        // volume is unobserved. The execution projection therefore stays
        // `Running` — the one value that means "attempt started, outcome
        // unproven" — so the lease holder set keeps holding and the reconciler
        // releases it. A queued job never started, so its outcome is the
        // cancellation itself.
        job.execution = Some(if was_running {
            ExecutionStatus::Running
        } else {
            ExecutionStatus::Cancelled
        });
        job.updated_at_ms = now;
        let write = self.database.begin_write().map_err(database)?;
        let mut table = write.open_table(JOBS).map_err(database)?;
        let encoded =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(job.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        append_event(
            &write,
            &job,
            Some(previous),
            JobState::Cancelled,
            actor,
            now,
            Some("cancelled".to_owned()),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Reads the immutable transition history for one job.
    pub fn events(&self, job_id: &str) -> Result<Vec<JobEvent>, TestdError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(EVENTS).map_err(database)?;
        let prefix = format!("{job_id}:");
        let mut events = Vec::new();
        for item in table.iter().map_err(database)? {
            let (key, value) = item.map_err(database)?;
            if key.value().starts_with(&prefix) {
                events.push(
                    serde_json::from_slice(value.value())
                        .map_err(|error| TestdError::Corrupt(error.to_string()))?,
                );
            }
        }
        events.sort_by_key(|event: &JobEvent| event.sequence);
        Ok(events)
    }

    fn ready_heads(&self, now: u64) -> Result<Vec<TestJob>, TestdError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        let mut jobs = Vec::new();
        for item in table.iter().map_err(database)? {
            let (_, value) = item.map_err(database)?;
            jobs.push(
                serde_json::from_slice::<TestJob>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?,
            );
        }
        drop(table);

        // Project-head blocking must see every durable state. Filtering to
        // queued/retry candidates first would erase a Running predecessor and
        // allow a later same-project sequence to start concurrently.
        let snapshot = jobs;
        let mut candidates = snapshot
            .iter()
            .filter(|job| {
                matches!(job.state, JobState::Queued | JobState::RetryWait)
                    && job.not_before_ms <= now
                    && job.lease.is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.retain(|job| {
            !project_head_blocked(
                &job.project_id,
                job.project_sequence,
                snapshot.iter().map(|other| {
                    (
                        other.project_id.as_str(),
                        other.project_sequence,
                        other.state,
                    )
                }),
            )
        });
        // I2.22: "A worktree does not isolate runtime resources." A ready job
        // whose exclusive resource or serial group is already held by a
        // running job is not a claim candidate, so two tests that claim the
        // same exclusive stateful resource never run concurrently. The
        // decision is re-evaluated against the durable record at claim time.
        let allocator = running_lease_allocator(&snapshot);
        candidates.retain(|job| allocator.is_available(&job.resource_profile));
        Ok(candidates)
    }

    /// Sum of the declared resource weight units across durably running jobs.
    /// This is the capacity a background claim would be measured against.
    fn running_weight_units(&self) -> Result<u32, TestdError> {
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(JOBS).map_err(database)?;
        let mut units = 0u32;
        for item in table.iter().map_err(database)? {
            let (_, value) = item.map_err(database)?;
            let job: TestJob = serde_json::from_slice(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if job.state == JobState::Running {
                units = units.saturating_add(job.resource_profile.weight.as_u32());
            }
        }
        drop(table);
        Ok(units)
    }
}

/// Capacity units held back from background claims so a Kernel, Watchdog,
/// Control Reserve, verification, or interactive job is never displaced by a
/// background indexing, coverage, mutation, or Dreamer job under constrained
/// capacity. The reservation is expressed in the same declared weight units as
/// the job declarations, so it is measured rather than assumed.
const RESERVED_FOREGROUND_WEIGHT: u32 = 3;

/// Builds the lease state held by every durably running job. Recomputed from
/// the record rather than cached, so a restart reconstructs the same leases.
///
/// A cancelled attempt whose execution is still `Running` holds its leases too:
/// its worker fence is gone but its process may still be alive, so releasing the
/// exclusive resource here would let a second job claim a port, service,
/// fixture, or database volume the cancelled process is still using (issue
/// #1897).
fn running_lease_allocator(jobs: &[TestJob]) -> ResourceLeaseAllocator {
    let mut allocator = ResourceLeaseAllocator::new();
    for job in jobs.iter().filter(|job| {
        job.state == JobState::Running
            || (job.state == JobState::Cancelled && job.execution == Some(ExecutionStatus::Running))
    }) {
        let leases = job
            .scheduling
            .as_ref()
            .map_or_else(Vec::new, |scheduling| scheduling.leases.clone());
        allocator.adopt_running(
            job.job_id.clone(),
            leases,
            job.resource_profile.serial_group.clone(),
        );
    }
    allocator
}

/// Builds the lease state held by the running jobs in an open write
/// transaction, excluding `job_id` which is the claim being evaluated. This
/// makes the exclusivity check and the job update one transaction, so a
/// competing claim that committed first is observed and refused.
fn held_leases_in(
    write: &redb::WriteTransaction,
    job_id: &str,
) -> Result<ResourceLeaseAllocator, TestdError> {
    let table = write.open_table(JOBS).map_err(database)?;
    let mut jobs = Vec::new();
    for item in table.iter().map_err(database)? {
        let (_, value) = item.map_err(database)?;
        let job: TestJob = serde_json::from_slice(value.value())
            .map_err(|error| TestdError::Corrupt(error.to_string()))?;
        if job.job_id != job_id {
            jobs.push(job);
        }
    }
    drop(table);
    Ok(running_lease_allocator(&jobs))
}

fn project_head_blocked<'a>(
    project_id: &str,
    project_sequence: u64,
    jobs: impl IntoIterator<Item = (&'a str, u64, JobState)>,
) -> bool {
    jobs.into_iter()
        .any(|(other_project, other_sequence, other_state)| {
            other_project == project_id
                && other_sequence < project_sequence
                && !other_state.is_terminal()
        })
}

/// The one lane-root check every lifecycle stage runs.
///
/// A job admitted without a lane keeps the pre-lane layout authority: the
/// owner-issued binding resolves its own root. A job that carries a retained
/// [`GovernedWorkEnvelope`] has exactly one root authority — the envelope's
/// governed root — so the layout is verified against the envelope rather than
/// deriving a second root from its build-class level. Both branches keep the
/// `cache_root == target_root` relation of
/// [`TargetRoots::validate`] untouched and add no distinctness.
///
/// It also binds the retained fixture namespace (issue #1897, W4) to the
/// retained envelope BY CONTENT: the namespace the row carries must equal what
/// its own envelope derives from the whole lane tuple, and a lane without a
/// namespace is a namespace without a derivation. Presence is never enough, a
/// mismatched namespace is never repaired, and no namespace is ever derived
/// from the worktree, the project id, the job id, or a counter.
///
/// # Errors
///
/// Returns the first [`TestdError`] the selected verification raises.
fn verify_job_lane(
    target_roots: &TargetRoots,
    layout: Option<&TargetLayoutBinding>,
    envelope: Option<&GovernedWorkEnvelope>,
    fixture_namespace: Option<&str>,
) -> Result<(), TestdError> {
    let lane = match (layout, envelope) {
        (Some(layout), Some(envelope)) => {
            verify_envelope_layout_binding(target_roots, layout, envelope).map(|_| ())
        }
        (Some(layout), None) => verify_layout_binding(target_roots, layout).map(|_| ()),
        // A lane without an owner-issued binding still has exactly one root:
        // the one its retained envelope derives. The strict-descendant and
        // `TargetRoots` gates above already bound it to the granted contour.
        (None, Some(envelope)) => {
            let governed = envelope
                .derive_target_root()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
            let canonical =
                validate_root_identity(&governed.to_string_lossy(), "work_envelope.governed_root")?;
            let target =
                validate_root_identity(&target_roots.target_root, "target_roots.target_root")?;
            if canonical != target {
                return Err(TestdError::InvalidBinding);
            }
            Ok(())
        }
        (None, None) => Ok(()),
    };
    lane?;
    // The namespace is a derived half of the required tuple, not a name the
    // row may choose: the envelope is its only source, so an enveloped job
    // whose retained namespace is absent or different was not admitted under
    // this lane and refuses, and a namespace retained without a lane has no
    // derivation to agree with and also refuses.
    match (envelope, fixture_namespace) {
        (Some(envelope), Some(retained)) => {
            let expected = envelope
                .fixture_namespace()
                .map_err(|error| TestdError::Contract(error.to_string()))?;
            if retained != expected.as_str() {
                return Err(TestdError::InvalidBinding);
            }
        }
        (Some(_), None) | (None, Some(_)) => return Err(TestdError::InvalidBinding),
        (None, None) => {}
    }
    Ok(())
}

// The admitted payload is the whole tuple this job row commits to, so every
// element is a separate parameter rather than a struct that could be built
// partially. That makes the arity exceed the lint default by one; the sibling
// composition entrypoint in this workspace carries the same attribute for the
// same reason.
#[allow(clippy::too_many_arguments)]
fn payload_digest(
    invocation: &InstrumentInvocation,
    process: &ProcessRequest,
    target_roots: &TargetRoots,
    priority: i32,
    job_class: JobClass,
    resource_profile: &TestResourceProfile,
    work_envelope: Option<&GovernedWorkEnvelope>,
    fixture_namespace: Option<&str>,
    stage_request: Option<&InstrumentStageRequest>,
    provider_tool_observation: Option<&TestdToolObservation>,
    provider_environment_projection: Option<&EnvironmentProjection>,
) -> Result<String, TestdError> {
    // Preserve existing legacy and nonproductive stage digest formats while
    // binding the new durable currentness inputs into productive submission.
    let bytes = if let (Some(stage_request), Some(tool_observation), Some(environment)) = (
        stage_request,
        provider_tool_observation,
        provider_environment_projection,
    ) {
        serde_json::to_vec(&(
            invocation,
            process,
            target_roots,
            priority,
            job_class,
            resource_profile,
            work_envelope,
            fixture_namespace,
            stage_request,
            tool_observation,
            environment,
        ))
    } else if let Some(stage_request) = stage_request {
        serde_json::to_vec(&(
            invocation,
            process,
            target_roots,
            priority,
            job_class,
            resource_profile,
            work_envelope,
            fixture_namespace,
            stage_request,
        ))
    } else {
        serde_json::to_vec(&(
            invocation,
            process,
            target_roots,
            priority,
            job_class,
            resource_profile,
            work_envelope,
            fixture_namespace,
        ))
    }
    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub(crate) fn validate_root_identity(
    value: &str,
    field: &'static str,
) -> Result<PathBuf, TestdError> {
    validate_text(value, field)?;
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(TestdError::Invalid {
            field,
            reason: "must be an absolute path",
        });
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(TestdError::Invalid {
            field,
            reason: "parent traversal is forbidden",
        });
    }
    reject_reparse_components(path, field)?;
    let canonical = std::fs::canonicalize(path).map_err(|_| TestdError::Invalid {
        field,
        reason: "must identify an existing canonical root",
    })?;
    if !canonical.is_absolute() {
        return Err(TestdError::Invalid {
            field,
            reason: "must resolve to an absolute root",
        });
    }
    let metadata = std::fs::symlink_metadata(&canonical).map_err(|_| TestdError::Invalid {
        field,
        reason: "root metadata is unavailable",
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(TestdError::Invalid {
            field,
            reason: "must be a non-reparse directory",
        });
    }
    reject_reparse_components(&canonical, field)?;
    Ok(canonical)
}

fn reject_reparse_components(path: &Path, field: &'static str) -> Result<(), TestdError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TestdError::Invalid {
                    field,
                    reason: "parent traversal is forbidden",
                });
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|_| TestdError::Invalid {
                        field,
                        reason: "root traversal contains an unavailable component",
                    })?;
                if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                    return Err(TestdError::Invalid {
                        field,
                        reason: "symlink or reparse traversal is forbidden",
                    });
                }
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn is_strict_descendant(path: &Path, parent: &Path) -> bool {
    if path == parent {
        return false;
    }
    #[cfg(windows)]
    {
        let path = path.to_string_lossy().replace('/', "\\");
        let parent = parent.to_string_lossy().replace('/', "\\");
        let path = path.trim_end_matches('\\').to_ascii_lowercase();
        let parent = parent.trim_end_matches('\\').to_ascii_lowercase();
        path.starts_with(&format!("{parent}\\"))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(parent)
    }
}

fn validate_receipt_binding(job: &TestJob, receipt: &ReceiptBinding) -> Result<(), TestdError> {
    job.target_roots.validate()?;
    let matches = receipt.job_id == job.job_id
        && receipt.operation_id == job.process.operation_id
        && receipt.process_tree_id == job.process.process_tree_id
        && receipt.generation == job.process.generation
        && receipt
            .authority_epoch
            .is_same_authority(&job.process.authority_epoch)
        && receipt_invocation_matches(receipt, job.invocation.request.request_id.as_str())
        && receipt.invocation_digest == job.process.invocation_digest
        && receipt.allowed_contour_root == job.target_roots.allowed_contour_root
        && receipt.source_root == job.target_roots.source_root
        && receipt.target_root == job.target_roots.target_root
        && receipt.cache_root == job.target_roots.cache_root;
    if matches {
        Ok(())
    } else {
        Err(TestdError::InvalidBinding)
    }
}

fn receipt_invocation_matches(receipt: &ReceiptBinding, invocation_id: &str) -> bool {
    receipt.invocation_id == invocation_id
}

/// Rejects a typed bundle admitted from another attempt's process identity.
///
/// The bundle binding must agree with the durable job's process projection on
/// operation, tree, generation (via the authenticated fence), and authority
/// epoch. The job id itself is intentionally not compared: the current
/// dispatch path re-proves operation/tree/generation/epoch end to end while
/// the intent job id arrives with the dispatch material, so comparing it here
/// would bind this check to an identity this path does not re-prove.
fn validate_typed_bundle_binding(
    job: &TestJob,
    bundle: &TestdProcessEvidenceBundle,
) -> Result<(), TestdError> {
    let binding = &bundle.binding;
    let matches = binding.operation_id().as_str() == job.process.operation_id.as_str()
        && binding.process_tree_id().as_str() == job.process.process_tree_id.as_str()
        && binding.state_fence().generation().get() == job.process.generation
        && binding
            .authority_epoch()
            .is_same_authority(&job.process.authority_epoch);
    if matches {
        Ok(())
    } else {
        Err(TestdError::InvalidBinding)
    }
}

fn lease_matches(job: &TestJob, lease: &Lease, now: u64) -> bool {
    running_lease_matches(job.state, job.lease.as_ref(), lease, now)
}

fn running_lease_matches(
    state: JobState,
    current: Option<&Lease>,
    supplied: &Lease,
    now: u64,
) -> bool {
    current.is_some_and(|current| {
        current == supplied && current.expires_at_ms > now && state == JobState::Running
    })
}

/// Validates the exact current running fence before a consuming request may
/// start.  This is intentionally pure so protocol/composition callers cannot
/// accidentally replace it with a local lease check.
pub fn validate_running_lease(job: &TestJob, lease: &Lease, now: u64) -> Result<(), TestdError> {
    if lease_matches(job, lease, now) {
        Ok(())
    } else {
        Err(TestdError::LeaseRejected(job.job_id.clone()))
    }
}

fn validate_cancellation_lease(
    job: &TestJob,
    lease: Option<&Lease>,
    actor: &str,
    now: u64,
) -> Result<(), TestdError> {
    if !cancellation_lease_matches(job.state, job.lease.as_ref(), lease, actor, now) {
        return Err(TestdError::LeaseRejected(job.job_id.clone()));
    }
    Ok(())
}

fn cancellation_lease_matches(
    state: JobState,
    current: Option<&Lease>,
    supplied: Option<&Lease>,
    actor: &str,
    now: u64,
) -> bool {
    match state {
        JobState::Running => supplied.is_some_and(|lease| {
            running_lease_matches(state, current, lease, now) && actor == lease.owner
        }),
        _ => supplied.is_none_or(|lease| running_lease_matches(state, current, lease, now)),
    }
}

/// Orders two ready heads for a claim.
///
/// I2.22: "Verification has priority over background indexing, coverage,
/// mutation, and Dreamer jobs" and "A background build cannot displace Kernel,
/// Watchdog, Control Reserve, or interactive product work." The declared job
/// class therefore orders the claim first, and the caller-supplied `priority`
/// integer is only a within-class tie-break, so a background job can never be
/// promoted above a protected class by choosing a large integer.
fn compare_ready(left: &TestJob, right: &TestJob) -> Ordering {
    left.job_class
        .priority()
        .cmp(&right.job_class.priority())
        .then_with(|| left.priority.cmp(&right.priority))
        .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
        .then_with(|| right.project_sequence.cmp(&left.project_sequence))
        .then_with(|| right.job_id.cmp(&left.job_id))
}

fn append_event(
    write: &redb::WriteTransaction,
    job: &TestJob,
    from: Option<JobState>,
    to: JobState,
    actor: &str,
    at_ms: u64,
    reason: Option<String>,
) -> Result<(), TestdError> {
    let prefix = format!("{}:", job.job_id);
    let sequence = {
        let table = write.open_table(EVENTS).map_err(database)?;
        let mut highest = 0_u64;
        let mut sequences = BTreeSet::new();
        for item in table.iter().map_err(database)? {
            let (key, _) = item.map_err(database)?;
            if let Some(value) = key.value().strip_prefix(&prefix) {
                let sequence = decode_event_sequence_suffix(value)?;
                if !sequences.insert(sequence) {
                    return Err(corrupt("durable event sequence is ambiguous"));
                }
                highest = highest.max(sequence);
            }
        }
        highest
            .checked_add(1)
            .ok_or_else(|| corrupt("event sequence exhausted"))?
    };
    let event = JobEvent {
        job_id: job.job_id.clone(),
        project_sequence: job.project_sequence,
        sequence,
        from,
        to,
        actor: actor.to_owned(),
        at_ms,
        reason,
    };
    let encoded =
        serde_json::to_vec(&event).map_err(|error| TestdError::Corrupt(error.to_string()))?;
    let key = format!("{}:{:020}", job.job_id, sequence);
    let mut table = write.open_table(EVENTS).map_err(database)?;
    table
        .insert(key.as_str(), encoded.as_slice())
        .map_err(database)?;
    Ok(())
}

/// Computes a lowercase SHA-256 digest over bytes only.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Hashes the canonical durable finish receipt used by the authenticated
/// TestD terminal notification.
pub fn verification_receipt_sha256(receipt: &VerificationReceipt) -> Result<String, TestdError> {
    let bytes =
        canonical_json_bytes(receipt).map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Computes a length-domain-separated SHA-256 digest for one raw artifact.
///
/// The fixed-width big-endian length prefix makes the encoded tuple
/// unambiguous and prevents a detached length field from being accepted.
pub fn sha256_artifact(length: u64, bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(length.to_be_bytes());
    digest.update(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.finalize() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use std::num::NonZeroU64;

    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage-A");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn lease() -> Lease {
        Lease {
            owner: "worker-a".to_owned(),
            token: "fence-a".to_owned(),
            epoch: 3,
            expires_at_ms: 200,
        }
    }

    fn contour_grant_fixture() -> ExecutionContourGrant {
        ExecutionContourGrant {
            contour_root: "C:\\approved-contour".to_owned(),
            job_id: "job".to_owned(),
            invocation_id: "invocation".to_owned(),
            operation_id: "operation".to_owned(),
            process_tree_id: "tree".to_owned(),
            authority_epoch: test_epoch(7),
            resource_generation: 3,
            grant_id: "grant-1".to_owned(),
            grant_digest: String::new(),
        }
    }

    #[test]
    fn running_cancel_without_exact_fence_is_rejected() {
        let current = lease();
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            None,
            "worker-a",
            100,
        ));
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            Some(&current),
            "other-worker",
            100,
        ));
        assert!(!cancellation_lease_matches(
            JobState::Running,
            Some(&current),
            Some(&current),
            "worker-a",
            200,
        ));
    }

    #[test]
    fn project_head_blocking_uses_every_durable_nonterminal_state() {
        assert!(project_head_blocked(
            "project-a",
            2,
            [("project-a", 1, JobState::Running)]
        ));
        assert!(!project_head_blocked(
            "project-a",
            2,
            [("project-a", 1, JobState::Succeeded)]
        ));
        assert!(!project_head_blocked(
            "project-a",
            2,
            [("project-b", 1, JobState::Running)]
        ));
        assert!(project_head_blocked(
            "project-a",
            2,
            [("project-a", 1, JobState::Queued)]
        ));
        assert!(project_head_blocked(
            "project-a",
            2,
            [("project-a", 1, JobState::RetryWait)]
        ));
        assert!(!project_head_blocked(
            "project-a",
            1,
            [("project-a", 2, JobState::Running)]
        ));
    }

    #[test]
    fn receipt_invocation_identity_cannot_be_substituted() {
        let receipt = ReceiptBinding {
            job_id: "job".to_owned(),
            operation_id: "operation".to_owned(),
            process_tree_id: "tree".to_owned(),
            generation: 1,
            authority_epoch: test_epoch(1),
            invocation_id: "invocation-a".to_owned(),
            invocation_digest: "digest".to_owned(),
            allowed_contour_root: "contour".to_owned(),
            source_root: "source".to_owned(),
            target_root: "target".to_owned(),
            cache_root: "target".to_owned(),
        };
        assert!(receipt_invocation_matches(&receipt, "invocation-a"));
        assert!(!receipt_invocation_matches(&receipt, "invocation-b"));
    }

    #[test]
    fn contour_grant_digest_is_stable_for_identical_input() {
        let first = contour_grant_digest(&contour_grant_fixture()).expect("serialize grant");
        let second = contour_grant_digest(&contour_grant_fixture()).expect("serialize grant");
        assert_eq!(first, second);
    }

    #[test]
    fn contour_grant_issue_and_integrity_validation_round_trip() {
        let grant = contour_grant_fixture()
            .with_digest()
            .expect("issue contour grant");
        assert!(grant.validate_integrity().is_ok());
    }

    #[test]
    fn forged_contour_cannot_widen_issuer_grant() {
        let mut grant = contour_grant_fixture()
            .with_digest()
            .expect("issue contour grant");
        grant.contour_root = "C:\\caller-widened-contour".to_owned();
        assert!(grant.validate_integrity().is_err());
    }

    #[test]
    fn durable_sequence_decoders_distinguish_absence_from_corruption() {
        assert_eq!(decode_project_sequence(b"0").expect("zero is explicit"), 0);
        assert_eq!(decode_project_sequence(b"42").expect("valid sequence"), 42);
        assert!(matches!(
            decode_project_sequence(b""),
            Err(TestdError::Corrupt(_))
        ));
        assert!(matches!(
            decode_project_sequence(br#"\"42\""#),
            Err(TestdError::Corrupt(_))
        ));
    }

    #[test]
    fn event_sequence_decoder_rejects_malformed_and_exhausted_suffixes() {
        assert_eq!(
            decode_event_sequence_suffix("00000000000000000001").expect("valid event key"),
            1
        );
        for suffix in [
            "",
            "not-a-number",
            "18446744073709551616",
            "00000000000000000000",
        ] {
            assert!(matches!(
                decode_event_sequence_suffix(suffix),
                Err(TestdError::Corrupt(_))
            ));
        }
    }

    #[test]
    fn project_sequence_inventory_requires_matching_durable_metadata() {
        let inventory = BTreeMap::from([("project-a".to_owned(), BTreeSet::from([1, 3]))]);
        assert!(
            validate_sequence_inventory(&inventory, &BTreeMap::from([("project-a".to_owned(), 3)]))
                .is_ok()
        );
        assert!(matches!(
            validate_sequence_inventory(&inventory, &BTreeMap::from([("project-a".to_owned(), 2)])),
            Err(TestdError::Corrupt(_))
        ));
        assert!(matches!(
            validate_sequence_inventory(
                &BTreeMap::new(),
                &BTreeMap::from([("project-a".to_owned(), 3)])
            ),
            Err(TestdError::Corrupt(_))
        ));
    }
}
