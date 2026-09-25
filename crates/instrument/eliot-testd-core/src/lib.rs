//! Durable scheduling and lifecycle state for the instrument test daemon.
//!
//! The daemon deliberately keeps execution outside this crate.  It owns the
//! admission record, project-local ordering, leases, retry timing, and the
//! immutable transition journal.  A process adapter may therefore restart at
//! any point and recover exactly which work is safe to run next.

#![forbid(unsafe_code)]

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, EpochId, RequestId, canonical_json_bytes,
};
pub use eliot_instrument_api::KernelProcessAdmissionRequest;
use eliot_instrument_api::{
    ExecutionStatus, InstrumentInvocation, InstrumentKind, VerificationRun,
};
use eliot_process::{
    EnvironmentInheritance, EnvironmentProjection, ProcessRequest, ResourceLimits,
};
use eliot_protocol::RequestIdentity;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

mod claim;
pub mod improvement;

pub use claim::{
    ClaimBindingExpectation, ExpiredRunningReconciliation, reconcile_expired_running,
    validate_claim_binding,
};
pub use improvement::{
    GOVERNOR_IMPROVEMENT_OWNER_OPERATION, IMPROVEMENT_EFFECT_CEILING,
    IMPROVEMENT_EXPERIMENT_PLAN_SCHEMA, IMPROVEMENT_EXPERIMENT_SCHEMA, IMPROVEMENT_KERNEL_OWNER,
    IMPROVEMENT_OWNER, IMPROVEMENT_PRODUCT_OWNER, IMPROVEMENT_TESTD_OWNER,
    IMPROVEMENT_VERIFIER_OWNER, ImprovementActivationEvidence, ImprovementActivationStatus,
    ImprovementCanaryIdentity, ImprovementDiscriminator, ImprovementExperimentBudget,
    ImprovementExperimentDisposition, ImprovementExperimentOutcome, ImprovementExperimentPlan,
    ImprovementExperimentRecord, ImprovementExperimentRequest, ImprovementExperimentState,
    ImprovementExperimentTarget, ImprovementExternalOwnerReceipt, ImprovementMetricDisposition,
    ImprovementOperationBinding, ImprovementOperationKind, ImprovementOperationSet,
    ImprovementOwnerAdmissionReceipt, ImprovementPriorAttempt, ImprovementPriorOutcome,
    ImprovementPrivacyClass, ImprovementProposal, ImprovementReconciliationEvidence,
    ImprovementRiskClass, ImprovementSourceBinding, IndependentExecutionEvidence,
    MechanismDeclaration, MechanismDeclarationReceipt, RollbackContract,
    is_improvement_no_progress,
};

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
//   refused at registration: there is no caller passthrough. A future
//   profile with typed slots arrives as a new registry entry with its own
//   slot validation, never by widening these.
// * `env_allowlist` is the exact non-secret environment for the child.
//   The productive libtest-json profile receives only the explicitly
//   registered feature gate below; no ambient environment is inherited.
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
        let expected_program = if self.profile == TESTD_PRODUCTIVE_PROFILE {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM
        } else {
            TESTD_PROFILE_PROGRAM
        };
        if self.program_path != expected_program {
            return Err(TestdError::Invalid {
                field: "program_path",
                reason: "testd admits only the closed relative cargo tool program",
            });
        }
        let expected_argv: Vec<String> = if self.profile == TESTD_ADMITTED_PROFILE {
            TESTD_PROFILE_ARGV.iter().map(ToString::to_string).collect()
        } else {
            TESTD_PRODUCTIVE_PROFILE_ARGV
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        if self.fixed_argv != expected_argv {
            return Err(TestdError::Invalid {
                field: "fixed_argv",
                reason: "the registered profile takes fixed argv; caller arguments are refused",
            });
        }
        let expected_environment: Vec<(String, String)> =
            if self.profile == TESTD_PRODUCTIVE_PROFILE {
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
    if profile == TESTD_PRODUCTIVE_PROFILE {
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
    matches!(profile, TESTD_ADMITTED_PROFILE | TESTD_PRODUCTIVE_PROFILE)
}

/// Resolves the closed binding for one admitted profile.
///
/// The artifact digest is the caller's recorded SHA-256 of the installed
/// tool file bytes (see [`resolve_testd_tool_digest`] on the bins side);
/// it is shape-checked here and bound into [`testd_binding_digest`].
/// An unregistered profile fails with `Invalid` and can never execute.
pub fn testd_profile_binding(
    profile: &str,
    package_artifact_digest: &str,
) -> Result<TestdExecutableBinding, TestdError> {
    if !is_admitted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "testd admits only registered probe or productive nextest profiles",
        });
    }
    let fixed_argv = if profile == TESTD_ADMITTED_PROFILE {
        TESTD_PROFILE_ARGV
    } else {
        TESTD_PRODUCTIVE_PROFILE_ARGV
    };
    let binding = TestdExecutableBinding {
        profile: profile.to_owned(),
        package_artifact_digest: package_artifact_digest.to_owned(),
        program_path: if profile == TESTD_PRODUCTIVE_PROFILE {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM.to_owned()
        } else {
            TESTD_PROFILE_PROGRAM.to_owned()
        },
        fixed_argv: fixed_argv.iter().map(ToString::to_string).collect(),
        env_allowlist: if profile == TESTD_PRODUCTIVE_PROFILE {
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
pub fn testd_definition_digest_for_profile(profile: &str) -> Result<String, TestdError> {
    if !is_admitted_testd_profile(profile) {
        return Err(TestdError::Invalid {
            field: "profile",
            reason: "testd admits only registered probe or productive nextest profiles",
        });
    }
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
    let fixed_argv = if profile == TESTD_ADMITTED_PROFILE {
        TESTD_PROFILE_ARGV
    } else {
        TESTD_PRODUCTIVE_PROFILE_ARGV
    };
    let argv: Vec<String> = fixed_argv.iter().map(ToString::to_string).collect();
    let limits = profile_limits(profile);
    let env_allowlist = if profile == TESTD_PRODUCTIVE_PROFILE {
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
        fixed_argv: &argv,
        max_descendants: limits.5,
        memory_bytes: limits.2,
        profile,
        program_path: if profile == TESTD_PRODUCTIVE_PROFILE {
            TESTD_PRODUCTIVE_PROFILE_PROGRAM
        } else {
            TESTD_PROFILE_PROGRAM
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

fn is_binding_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

const JOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_jobs_v1");
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_events_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_meta_v1");
/// Authenticated frame identities retained beside durable productive jobs.
/// Additive owner table: existing stores migrate idempotently without
/// rewriting job payloads.
const ADMITTED_IDENTITIES: TableDefinition<&str, &[u8]> =
    TableDefinition::new("testd_admitted_identities_v1");
/// Durable improvement proposal/replay/outcome sidecars keyed by TestD job.
const IMPROVEMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("testd_improvements_v1");

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
}

fn database<E: std::fmt::Display>(error: E) -> TestdError {
    TestdError::Database(error.to_string())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), TestdError> {
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
    /// Identity projection of the consuming process contract.
    pub process: ProcessAdmission,
    /// Canonical roots retained for later execution/reconciliation checks.
    pub target_roots: TargetRoots,
    /// Scheduling priority; larger values run first among ready heads.
    pub priority: i32,
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

/// Immutable owner binding persisted before a productive verifier starts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdVerifierDispatchBinding {
    pub request_identity: RequestIdentity,
    pub operation_id: String,
    pub canonical_plan_json: String,
    pub canonical_plan_sha256: String,
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
    /// digest. Any unavailable or oversized observation fails closed.
    pub fn capture(repository_root: impl AsRef<Path>) -> Result<Self, TestdError> {
        const MAX_GIT_OUTPUT: usize = 64 * 1024 * 1024;
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
        let run_git = |arguments: &[&str]| -> Result<Vec<u8>, TestdError> {
            let mut command = Command::new("git");
            command.current_dir(&repository_root);
            for variable in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_COMMON_DIR",
                "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_PREFIX",
                "GIT_CEILING_DIRECTORIES",
                "GIT_DISCOVERY_ACROSS_FILESYSTEM",
                "GIT_EXTERNAL_DIFF",
                "GIT_CONFIG",
                "GIT_CONFIG_COUNT",
                "GIT_CONFIG_PARAMETERS",
                "GIT_CONFIG_SYSTEM",
                "GIT_CONFIG_GLOBAL",
                "GIT_CONFIG_NOSYSTEM",
            ] {
                command.env_remove(variable);
            }
            let output = command
                .args(arguments)
                .output()
                .map_err(|_| TestdError::Invalid {
                    field: "source_observation.git",
                    reason: "Git could not be started for source observation",
                })?;
            if !output.status.success() || output.stdout.len() > MAX_GIT_OUTPUT {
                return Err(TestdError::Invalid {
                    field: "source_observation.git",
                    reason: "Git source observation failed or exceeded its bound",
                });
            }
            Ok(output.stdout)
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
            run_git(&["rev-parse", "--show-toplevel"])?,
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
            run_git(&["rev-parse", "--abbrev-ref", "HEAD"])?,
            "source_observation.branch",
        )?;
        let branch = if branch == "HEAD" {
            "detached".to_owned()
        } else {
            branch
        };
        let commit = decode_text(
            run_git(&["rev-parse", "--verify", "HEAD^{commit}"])?,
            "source_observation.commit",
        )?;
        let status = run_git(&["status", "--porcelain=v2", "-z", "--untracked-files=all"])?;
        let diff = run_git(&["diff", "--binary", "--no-ext-diff", "HEAD", "--"])?;
        let untracked = run_git(&["ls-files", "--others", "--exclude-standard", "-z"])?;
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
                if bytes.len() > MAX_GIT_OUTPUT {
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
    pub target_roots: TargetRoots,
    pub priority: i32,
}

/// Authenticated Kernel owner-submit operation for one productive verifier.
/// The transport identity is carried by the enclosing Kernel frame; this
/// payload contains only the Governor-resolved project/source binding, the
/// typed invocation, and owner-observed tool material.
pub const TESTD_OWNER_SUBMIT_OPERATION: &str = "eliot.kernel.testd-owner-submit";
/// Current TestD owner operation wire revision.
pub const TESTD_OWNER_WIRE_VERSION: u16 = 1;

/// Governor-resolved input to the Kernel-owned productive TestD owner.
/// `source_root` is the TaskContract WorkScope result; `project_id` is an
/// opaque project identity and is never interpreted as a filesystem path.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdOwnerJobSubmission {
    pub project_id: String,
    pub invocation: InstrumentInvocation,
    pub source_root: String,
    /// Optional actual `eliot-improvement` candidate/intake declaration. The
    /// TestD owner-submit wire rejects this field; only the authenticated
    /// Governor-maintenance wire can admit it, and that owner stamps all
    /// runtime bindings into the durable proposal before dispatch.
    #[serde(default)]
    pub improvement: Option<improvement::ImprovementExperimentRequest>,
}

impl TestdOwnerJobSubmission {
    pub fn validate(&self) -> Result<(), TestdError> {
        validate_text(&self.project_id, "project_id")?;
        validate_text(&self.source_root, "source_root")?;
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
        if let Some(request) = &self.improvement {
            request.validate()?;
            if request.project_id != self.project_id {
                return Err(TestdError::InvalidBinding);
            }
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
            || self.wire_version != TESTD_OWNER_WIRE_VERSION
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

/// Authenticated Governor-maintenance intake operation for an improvement
/// experiment.  This is deliberately distinct from the TestD owner-submit
/// wire: a daemon cannot use a TestD worker session (or a static owner label)
/// to create an improvement experiment.
pub const GOVERNOR_IMPROVEMENT_SUBMIT_OPERATION: &str = "eliot.kernel.governor-improvement-submit";

/// Typed request carried by the authenticated Governor-maintenance intake
/// route.  The enclosing frame identity remains the authority source.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorImprovementSubmitRequest {
    pub wire_id: String,
    pub wire_version: u16,
    pub submission: TestdOwnerJobSubmission,
    pub process_tool: TestdProcessToolIntent,
    pub request_digest: String,
}

impl GovernorImprovementSubmitRequest {
    /// Computes and validates the exact owner-wire digest.
    pub fn with_computed_digest(mut self) -> Result<Self, TestdError> {
        self.request_digest = self.compute_request_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Validates the closed wire and requires a real improvement declaration.
    pub fn validate(&self) -> Result<(), TestdError> {
        if self.wire_id != GOVERNOR_IMPROVEMENT_SUBMIT_OPERATION
            || self.wire_version != TESTD_OWNER_WIRE_VERSION
            || self.submission.improvement.is_none()
        {
            return Err(TestdError::Invalid {
                field: "governor_improvement_submit.wire",
                reason: "the Governor-maintenance improvement wire requires a declaration",
            });
        }
        self.submission.validate()?;
        self.process_tool.observation.validate()?;
        validate_text(
            &self.request_digest,
            "governor_improvement_submit.request_digest",
        )?;
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
        let bytes = canonical_json_bytes(&Canonical {
            wire_id: &self.wire_id,
            wire_version: self.wire_version,
            submission: &self.submission,
            process_tool: &self.process_tool,
        })
        .map_err(|_| TestdError::GrantDigestSerialization)?;
        Ok(sha256_hex(&bytes))
    }
}

/// Durable Kernel owner result for one idempotent productive submission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestdOwnerSubmitResponse {
    pub job_id: String,
    pub operation_id: String,
    pub authority_epoch: EpochId,
    pub generation: u64,
    pub payload_digest: String,
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
        self.target_roots.validate()
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
    /// Durable candidate declaration joined to this terminal row, when the
    /// productive job was admitted as an improvement experiment.
    #[serde(default)]
    pub improvement: Option<improvement::ImprovementExperimentRecord>,
    /// Prior material attempts read from the same durable TestD owner store.
    #[serde(default)]
    pub improvement_prior_attempts: Vec<improvement::ImprovementPriorAttempt>,
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
    /// the Kernel-selected target/cache roots, then returns the exact
    /// non-inheriting process environment projection.
    pub fn validate_for_roots(
        &self,
        target_root: &str,
        cache_root: &str,
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

        let cargo_home = validate_canonical_tool_directory(cache_root)?;
        let target = validate_canonical_tool_directory(target_root)?;
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
        let values = BTreeMap::from([
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
            ("CARGO_HOME".to_owned(), cache_root.to_owned()),
            (
                "RUSTUP_HOME".to_owned(),
                rustup_home.to_string_lossy().into_owned(),
            ),
            (
                "ELIOT_TESTD_TOOLCHAIN".to_owned(),
                self.observation.selected_toolchain.clone(),
            ),
            ("PATH".to_owned(), path_value),
            ("CARGO_TARGET_DIR".to_owned(), target_root.to_owned()),
        ]);

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
        execution_reality: eliot_instrument_api::ExecutionReality::Live,
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
        let binding = self.binding();
        validate_receipt_binding(job, &binding)?;
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
        Ok(())
    }
}

/// A bounded evidence sink for one testd operation.
#[derive(Clone, Default)]
pub struct EvidenceCollector {
    records: Arc<Mutex<Vec<eliot_process::ProcessEvidence>>>,
    raw_artifacts: Arc<Mutex<BTreeMap<String, RawArtifact>>>,
    next_capture_sequence: Arc<AtomicU64>,
    tool_observation: Arc<Mutex<Option<TestdToolObservation>>>,
}

impl EvidenceCollector {
    /// Returns a stable snapshot for receipt composition.
    pub fn snapshot(&self) -> Vec<eliot_process::ProcessEvidence> {
        self.records
            .lock()
            .map_or_else(|_| Vec::new(), |items| items.clone())
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

    fn insert_raw_artifact(&self, artifact: RawArtifact) -> Result<(), TestdError> {
        let mut artifact = artifact;
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
                    raw_artifacts.push(artifact.clone());
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
        }
    }
}

impl eliot_process::ProcessEvidenceSink for EvidenceCollector {
    fn record(
        &self,
        evidence: eliot_process::ProcessEvidence,
    ) -> Result<(), eliot_process::EvidenceSinkError> {
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "evidence collector lock poisoned".to_owned(),
            })
            .map(|mut records| records.push(evidence))
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
        drop(write.open_table(IMPROVEMENTS).map_err(database)?);
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

    /// Returns the durable improvement sidecar for one TestD job.
    pub fn improvement_record(
        &self,
        job_id: &str,
    ) -> Result<Option<improvement::ImprovementExperimentRecord>, TestdError> {
        validate_text(job_id, "job_id")?;
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(IMPROVEMENTS).map_err(database)?;
        table
            .get(job_id)
            .map_err(database)?
            .map_or(Ok(None), |value| {
                serde_json::from_slice(value.value())
                    .map(Some)
                    .map_err(|error| TestdError::Corrupt(error.to_string()))
            })
    }

    /// Persists the predeclared improvement sidecar before a productive job
    /// can be dispatched. Exact replay is idempotent; changed material under
    /// one job identity is a durable conflict.
    pub fn attach_improvement_predeclaration(
        &self,
        record: improvement::ImprovementExperimentRecord,
        now: u64,
    ) -> Result<improvement::ImprovementExperimentRecord, TestdError> {
        if now == 0 {
            return Err(TestdError::InvalidBinding);
        }
        record.validate()?;
        let write = self.database.begin_write().map_err(database)?;
        let job = {
            let jobs = write.open_table(JOBS).map_err(database)?;
            let value = jobs
                .get(record.job_id.as_str())
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("improvement job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if job.job_id != record.job_id
            || job.invocation.profile != TESTD_PRODUCTIVE_PROFILE
            || job.state != JobState::Queued
            || job.attempts != 0
            || job.lease.is_some()
            || job.verifier_dispatch.is_some()
        {
            return Err(TestdError::InvalidBinding);
        }
        let current_discriminator = record
            .proposal
            .request
            .new_discriminator
            .as_ref()
            .map(|value| value.discriminator_id.as_str());
        for item in write
            .open_table(IMPROVEMENTS)
            .map_err(database)?
            .iter()
            .map_err(database)?
        {
            let (_, value) = item.map_err(database)?;
            let prior =
                serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            let prior_discriminator = prior
                .proposal
                .request
                .new_discriminator
                .as_ref()
                .map(|value| value.discriminator_id.as_str());
            if prior.job_id != record.job_id
                && prior.requires_reconciliation()
                && prior.proposal.material_digest == record.proposal.material_digest
                && prior_discriminator == current_discriminator
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
        if let Some(existing) = table
            .get(record.job_id.as_str())
            .map_err(database)?
            .map(|value| {
                serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))
            })
            .transpose()?
        {
            if existing == record {
                return Ok(existing);
            }
            return Err(TestdError::JobConflict(record.job_id));
        }
        let encoded =
            serde_json::to_vec(&record).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        table
            .insert(record.job_id.as_str(), encoded.as_slice())
            .map_err(database)?;
        drop(table);
        write.commit().map_err(database)?;
        Ok(record)
    }

    /// Returns prior failed material attempts for the no-progress decision.
    pub fn improvement_prior_attempts(
        &self,
        proposal: &improvement::ImprovementProposal,
    ) -> Result<Vec<improvement::ImprovementPriorAttempt>, TestdError> {
        proposal.validate()?;
        let read = self.database.begin_read().map_err(database)?;
        let table = read.open_table(IMPROVEMENTS).map_err(database)?;
        let mut attempts = Vec::new();
        for item in table.iter().map_err(database)? {
            let (_, value) = item.map_err(database)?;
            let record: improvement::ImprovementExperimentRecord =
                serde_json::from_slice(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if record.proposal.request.project_id != proposal.request.project_id {
                continue;
            }
            let prior_outcome = if record.requires_reconciliation() {
                improvement::ImprovementPriorOutcome::Unknown
            } else if record.is_failed_attempt() {
                improvement::ImprovementPriorOutcome::Failed
            } else if record.outcome.is_some() {
                improvement::ImprovementPriorOutcome::Passed
            } else {
                improvement::ImprovementPriorOutcome::Pending
            };
            let job_id = record.job_id.clone();
            let material_digest = record.proposal.material_digest.clone();
            let discriminator = record.proposal.request.new_discriminator.as_ref();
            let discriminator_id = discriminator.map(|value| value.discriminator_id.clone());
            let canonical_evidence_id =
                discriminator.and_then(|value| value.canonical_evidence_id.clone());
            let canonical_evidence_sha256 =
                discriminator.and_then(|value| value.canonical_evidence_sha256.clone());
            attempts.push(improvement::ImprovementPriorAttempt {
                job_id,
                material_digest,
                discriminator_id,
                canonical_evidence_id,
                canonical_evidence_sha256,
                outcome: prior_outcome,
            });
        }
        attempts.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        Ok(attempts)
    }

    /// Reconciles a previously unknown terminal outcome with a newly
    /// executed, exact evidence identity. The original committed receipt and
    /// proposal are retained; only the sidecar outcome can move forward, and
    /// the transaction records the reconciliation event.
    pub fn reconcile_improvement_terminal(
        &self,
        job_id: &str,
        evidence: improvement::ImprovementReconciliationEvidence,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if now == 0 {
            return Err(TestdError::InvalidBinding);
        }
        let write = self.database.begin_write().map_err(database)?;
        let mut job = {
            let jobs = write.open_table(JOBS).map_err(database)?;
            let value = jobs
                .get(job_id)
                .map_err(database)?
                .ok_or_else(|| TestdError::Corrupt("improvement job not found".to_owned()))?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        if !matches!(
            job.state,
            JobState::Succeeded | JobState::Failed | JobState::Cancelled
        ) || job.lease.is_some()
            || job.verifier_dispatch.is_none()
        {
            return Err(TestdError::InvalidBinding);
        }
        let committed_receipt_json = job
            .terminal_publication
            .as_ref()
            .and_then(|publication| publication.committed_receipt_json.as_deref())
            .ok_or(TestdError::InvalidBinding)?;
        let committed_receipt: serde_json::Value =
            serde_json::from_str(committed_receipt_json).map_err(|_| TestdError::InvalidBinding)?;
        let committed_receipt_digest = sha256_hex(
            &canonical_json_bytes(&committed_receipt).map_err(|_| TestdError::InvalidBinding)?,
        );
        let mut record = {
            let table = write.open_table(IMPROVEMENTS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or(TestdError::InvalidBinding)?;
            serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let previous = record.outcome.as_ref().ok_or(TestdError::InvalidBinding)?;
        if evidence.committed_receipt_sha256 != committed_receipt_digest {
            return Err(TestdError::InvalidBinding);
        }
        let outcome = improvement::ImprovementExperimentOutcome::from_reconciliation_evidence(
            &record.proposal,
            previous,
            &evidence,
        )?;
        record.reconcile_unknown_outcome(&outcome)?;
        let encoded_record =
            serde_json::to_vec(&record).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        {
            let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
            table
                .insert(job_id, encoded_record.as_slice())
                .map_err(database)?;
        }
        job.updated_at_ms = now;
        let encoded_job =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        {
            let mut table = write.open_table(JOBS).map_err(database)?;
            table
                .insert(job_id, encoded_job.as_slice())
                .map_err(database)?;
        }
        append_event(
            &write,
            &job,
            Some(job.state),
            job.state,
            "improvement-unknown-reconciled",
            now,
            Some(format!(
                "disposition={:?}",
                record.outcome.as_ref().map(|value| value.disposition)
            )),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
    }

    /// Records the terminal-evaluator receipt and the exact independent
    /// improvement disposition in one owner transaction. The committed
    /// canonical receipt is retained only after Governor/daemon validation.
    pub fn acknowledge_improvement_terminal(
        &self,
        job_id: &str,
        receipt_sha256: &str,
        committed_receipt_json: String,
        outcome: improvement::ImprovementExperimentOutcome,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        validate_text(job_id, "job_id")?;
        if !is_binding_digest(receipt_sha256) || now == 0 {
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
            let jobs = write.open_table(JOBS).map_err(database)?;
            let value = jobs.get(job_id).map_err(database)?.ok_or_else(|| {
                TestdError::Corrupt("improvement terminal job not found".to_owned())
            })?;
            serde_json::from_slice::<TestJob>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        let publication = job
            .terminal_publication
            .as_mut()
            .ok_or(TestdError::InvalidBinding)?;
        if publication.receipt_sha256 != receipt_sha256
            || !matches!(
                job.state,
                JobState::Succeeded | JobState::Failed | JobState::Cancelled
            )
            || job.lease.is_some()
            || job.verifier_dispatch.is_none()
            || verification_receipt_sha256(
                job.verification_receipt
                    .as_ref()
                    .ok_or(TestdError::InvalidBinding)?,
            )? != receipt_sha256
            || outcome.committed_receipt_sha256 != receipt_sha256
        {
            return Err(TestdError::InvalidBinding);
        }
        let mut record = {
            let table = write.open_table(IMPROVEMENTS).map_err(database)?;
            let value = table
                .get(job_id)
                .map_err(database)?
                .ok_or(TestdError::InvalidBinding)?;
            serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                .map_err(|error| TestdError::Corrupt(error.to_string()))?
        };
        record.apply_outcome(&outcome)?;
        if let Some(existing) = &publication.committed_receipt_json
            && existing != &committed_receipt_json
        {
            return Err(TestdError::JobConflict(job_id.to_owned()));
        }
        publication.committed_receipt_json = Some(committed_receipt_json);
        record.validate()?;
        let encoded_record =
            serde_json::to_vec(&record).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        {
            let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
            table
                .insert(job_id, encoded_record.as_slice())
                .map_err(database)?;
        }
        job.updated_at_ms = now;
        let encoded_job =
            serde_json::to_vec(&job).map_err(|error| TestdError::Corrupt(error.to_string()))?;
        {
            let mut table = write.open_table(JOBS).map_err(database)?;
            table
                .insert(job_id, encoded_job.as_slice())
                .map_err(database)?;
        }
        append_event(
            &write,
            &job,
            Some(job.state),
            job.state,
            "improvement-terminal-outcome",
            now,
            Some(format!(
                "disposition={:?}",
                record.outcome.as_ref().map(|value| value.disposition)
            )),
        )?;
        write.commit().map_err(database)?;
        Ok(job)
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
            if existing != &observation {
                return Err(TestdError::JobConflict(job_id.to_owned()));
            }
            let has_improvement = write
                .open_table(IMPROVEMENTS)
                .map_err(database)?
                .get(job_id)
                .map_err(database)?
                .is_some();
            if !has_improvement {
                return Ok(job);
            }
        }
        job.source_observation_before = Some(observation.clone());
        job.updated_at_ms = now;
        if let Some(value) = write
            .open_table(IMPROVEMENTS)
            .map_err(database)?
            .get(job_id)
            .map_err(database)?
        {
            let mut record =
                serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if let Some(existing) = &record.source_observation {
                if existing != &observation {
                    return Err(TestdError::JobConflict(job_id.to_owned()));
                }
            } else {
                record.source_observation = Some(observation);
                record.validate()?;
                let encoded = serde_json::to_vec(&record)
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
                table.insert(job_id, encoded.as_slice()).map_err(database)?;
            }
        }
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
        if let Some(value) = write
            .open_table(IMPROVEMENTS)
            .map_err(database)?
            .get(job_id)
            .map_err(database)?
        {
            let record =
                serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            if record.source_observation.is_none()
                || !matches!(
                    record.state,
                    improvement::ImprovementExperimentState::Predeclared
                )
            {
                return Err(TestdError::InvalidBinding);
            }
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
        if let Some(value) = write
            .open_table(IMPROVEMENTS)
            .map_err(database)?
            .get(job_id)
            .map_err(database)?
        {
            let mut record =
                serde_json::from_slice::<improvement::ImprovementExperimentRecord>(value.value())
                    .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            record.mark_terminal_evidence_pending()?;
            let encoded = serde_json::to_vec(&record)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
            table.insert(job_id, encoded.as_slice()).map_err(database)?;
        }
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
        let improvements = read.open_table(IMPROVEMENTS).map_err(database)?;
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
            let improvement = improvements
                .get(job.job_id.as_str())
                .map_err(database)?
                .map(|value| {
                    serde_json::from_slice::<improvement::ImprovementExperimentRecord>(
                        value.value(),
                    )
                    .map_err(|error| TestdError::Corrupt(error.to_string()))
                })
                .transpose()?;
            if let Some(record) = &improvement {
                record.validate()?;
                if record.proposal.experiment_id != job.job_id
                    || record.proposal.request.project_id != job.project_id
                {
                    return Err(TestdError::InvalidBinding);
                }
            }
            pending.push(TestdTerminalCompletionEvidence {
                job,
                request_identity,
                improvement,
                improvement_prior_attempts: Vec::new(),
            });
        }
        drop(improvements);
        drop(identities);
        drop(jobs);
        drop(read);
        for entry in &mut pending {
            if let Some(record) = &entry.improvement {
                entry.improvement_prior_attempts =
                    self.improvement_prior_attempts(&record.proposal)?;
            }
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
        let has_improvement = write
            .open_table(IMPROVEMENTS)
            .map_err(database)?
            .get(job_id)
            .map_err(database)?
            .is_some();
        if has_improvement {
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
        self.submit_inner(
            job_id.into(),
            project_id.into(),
            invocation,
            permit,
            target_roots,
            priority,
            at_ms,
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
        priority: i32,
        at_ms: u64,
        identity: Option<RequestIdentity>,
        improvement: Option<improvement::ImprovementExperimentRecord>,
    ) -> Result<TestJob, TestdError> {
        validate_text(&job_id, "job_id")?;
        validate_text(&project_id, "project_id")?;
        if improvement.is_some() && identity.is_none() {
            return Err(TestdError::InvalidBinding);
        }
        if let Some(record) = &improvement {
            record.validate()?;
            if record.job_id != job_id
                || record.proposal.experiment_id != job_id
                || record.proposal.request.project_id != project_id
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        invocation
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        let (process, grant) = permit.into_parts();
        process
            .validate()
            .map_err(|error| TestdError::Contract(error.to_string()))?;
        grant.validate_for_process(&job_id, invocation.request.request_id.as_str(), &process)?;
        if !matches!(invocation.kind, InstrumentKind::Test) {
            return Err(TestdError::WrongInstrumentKind);
        }
        // Closed-profile registration (issue #20): only registered probe or
        // productive nextest profiles register, and both take no caller
        // arguments. Fixed argv comes from the registry binding, never from
        // the invocation.
        if !is_admitted_testd_profile(&invocation.profile) {
            return Err(TestdError::Invalid {
                field: "invocation.profile",
                reason: "testd admits only registered probe or productive nextest profiles",
            });
        }
        if !invocation.arguments.is_empty() {
            return Err(TestdError::Invalid {
                field: "invocation.arguments",
                reason: "the admitted profile takes fixed argv; caller arguments are refused",
            });
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
        let mut target_roots = target_roots;
        target_roots.allowed_contour_root = grant.contour_root.clone();
        target_roots.validate()?;
        let digest = payload_digest(&invocation, &process, &target_roots, priority)?;
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
            let retained_improvement = {
                let table = write.open_table(IMPROVEMENTS).map_err(database)?;
                table
                    .get(job_id.as_str())
                    .map_err(database)?
                    .map(|value| {
                        serde_json::from_slice::<improvement::ImprovementExperimentRecord>(
                            value.value(),
                        )
                        .map_err(|error| TestdError::Corrupt(error.to_string()))
                    })
                    .transpose()?
            };
            match (&improvement, retained_improvement) {
                (Some(_), None) | (None, Some(_)) => {
                    return Err(TestdError::JobConflict(job_id));
                }
                (Some(expected), Some(retained)) if expected != &retained => {
                    return Err(TestdError::JobConflict(job_id));
                }
                _ => {}
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
        if let Some(record) = &improvement {
            let current_discriminator = record
                .proposal
                .request
                .new_discriminator
                .as_ref()
                .map(|value| value.discriminator_id.as_str());
            let table = write.open_table(IMPROVEMENTS).map_err(database)?;
            for item in table.iter().map_err(database)? {
                let (_, value) = item.map_err(database)?;
                let prior = serde_json::from_slice::<improvement::ImprovementExperimentRecord>(
                    value.value(),
                )
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
                let prior_discriminator = prior
                    .proposal
                    .request
                    .new_discriminator
                    .as_ref()
                    .map(|value| value.discriminator_id.as_str());
                if prior.job_id != record.job_id
                    && prior.requires_reconciliation()
                    && prior.proposal.material_digest == record.proposal.material_digest
                    && prior_discriminator == current_discriminator
                {
                    return Err(TestdError::InvalidBinding);
                }
            }
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
            process,
            target_roots,
            priority,
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
        if let Some(record) = improvement {
            let encoded = serde_json::to_vec(&record)
                .map_err(|error| TestdError::Corrupt(error.to_string()))?;
            let mut table = write.open_table(IMPROVEMENTS).map_err(database)?;
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
            submission.priority,
            now,
            Some(identity),
            None,
        )
    }

    /// Kernel-owner productive submission with an immutable improvement
    /// declaration committed in the same redb transaction as the job and
    /// authenticated identity. This is the only owner entry that can create
    /// an improvement experiment; ordinary verifier jobs remain unchanged.
    pub fn submit_productive_verifier_with_improvement(
        &self,
        submission: TestdVerifierJobSubmission,
        identity: RequestIdentity,
        permit: ProcessAdmissionPermit,
        improvement: improvement::ImprovementExperimentRecord,
        now: u64,
    ) -> Result<TestJob, TestdError> {
        submission.validate()?;
        identity
            .validate()
            .map_err(|_| TestdError::InvalidBinding)?;
        improvement.validate()?;
        if now == 0
            || identity.request.metadata != submission.invocation.request
            || identity.request.state_fence != submission.invocation.request.state_fence
            || improvement.job_id != submission.job_id
            || improvement.proposal.experiment_id != submission.job_id
            || improvement.proposal.request.project_id != submission.project_id
        {
            return Err(TestdError::InvalidBinding);
        }
        self.submit_inner(
            submission.job_id,
            submission.project_id,
            submission.invocation,
            permit,
            submission.target_roots,
            submission.priority,
            now,
            Some(identity),
            Some(improvement),
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
        let candidates = self.ready_heads(now)?;
        for candidate in &candidates {
            if let Some(record) = self.improvement_record(&candidate.job_id)?
                && (!matches!(
                    record.state,
                    improvement::ImprovementExperimentState::Predeclared
                ) || record.source_observation.is_none())
            {
                return Err(TestdError::InvalidBinding);
            }
        }
        let Some(candidate) = candidates
            .into_iter()
            .filter(|candidate| {
                candidate.invocation.profile != TESTD_PRODUCTIVE_PROFILE
                    || candidate.verifier_dispatch.is_some()
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
                if matches!(job.state, JobState::Running) {
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
        job.execution = Some(decision.execution);
        job.lease = None;
        let terminal = if job.attempts < self.retry.max_attempts {
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
        let previous = job.state;
        job.state = JobState::Cancelled;
        job.lease = None;
        job.execution = Some(ExecutionStatus::Cancelled);
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
        Ok(candidates)
    }
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

fn payload_digest(
    invocation: &InstrumentInvocation,
    process: &ProcessRequest,
    target_roots: &TargetRoots,
    priority: i32,
) -> Result<String, TestdError> {
    let bytes = serde_json::to_vec(&(invocation, process, target_roots, priority))
        .map_err(|error| TestdError::Corrupt(error.to_string()))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn validate_root_identity(value: &str, field: &'static str) -> Result<PathBuf, TestdError> {
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

fn is_strict_descendant(path: &Path, parent: &Path) -> bool {
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

fn compare_ready(left: &TestJob, right: &TestJob) -> Ordering {
    left.priority
        .cmp(&right.priority)
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
