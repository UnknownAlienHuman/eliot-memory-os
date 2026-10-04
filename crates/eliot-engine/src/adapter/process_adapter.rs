//! Deterministic process/CLI adapter — `I10.17`, issue #1819.
//!
//! # What this child owns
//!
//! The **governed caller** half of the `I10.17` execution rules: executable and
//! argv admission, the explicit cwd and environment allowlist, the resource
//! profile, bounded raw-output capture with Blob Store spill, and the
//! exit/protocol receipt.
//!
//! # What this child deliberately does NOT own
//!
//! Physical process lifecycle, Job Object / resource-profile binding, generation
//! routing and fencing. Issue #1819 Work step 1 assigns those to the Kernel, and
//! the repository process boundary (`clippy.toml` / `I10.8.2`) forbids a direct
//! `std::process::Command` / `tokio::process::Command` launch anywhere outside the
//! sole `ProcessExecutor` owner (`crates/instrument/eliot-process-executor`).
//!
//! So this adapter never spawns. It seals exact launch material as an
//! `eliot_process::ProcessIntent` — the canonical owner of separate executable and
//! argv, `EnvironmentProjection`, `ResourceLimits` and the sealed effect digest —
//! and hands it to an injected [`ProcessDispatchPort`], which is the Kernel-owned
//! `ProcessExecutor` boundary. Everything this adapter records is derived from the
//! sealed intent plus the executor's real outcome; nothing is asserted about a
//! process that did not run.
//!
//! # Why there is no command string anywhere in this file
//!
//! `I10.17` line 81: "construct executable and argv separately; never interpolate a
//! shell command by default". [`ProcessAdapterRequest`] therefore has an
//! `executable` member and a `Vec<String>` `argv` member and no third way to name
//! a program. There is no string that could be handed to a shell, so a path
//! containing `; & $ ( ) '` is data, not syntax.
//!
//! # Status taxonomy (issue #1819 Work W8)
//!
//! `I10.17` line 93 makes transport failure, semantic `no results`, stale index and
//! unsupported capability distinct, and keeps only transport/integrity failures in
//! circuit accounting. This adapter maps only a **launch** failure — the executor
//! could not start the sealed intent at all — to
//! [`AdapterResultStatus::TransportFailure`]. Everything else the child can report
//! is a completed protocol exchange:
//!
//! | observed | status | counts toward the circuit? |
//! |---|---|---|
//! | exit `0` | `Succeeded` | no (resets) |
//! | exit `<non-zero>` | `Failed` | no |
//! | executable not in the manifest allowlist | `UnsupportedCapability` | no |
//! | cwd outside the admitted roots | `Rejected` | no |
//! | malformed `input` | `Rejected` | no |
//! | deadline / cancellation | `Timeout` | no |
//! | executor could not launch | `TransportFailure` | yes |
//!
//! A non-zero exit is deliberately **not** a transport failure: the exchange
//! completed and the child answered with an exit code, so counting it against the
//! breaker would let a failing-but-healthy command take a whole route offline.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use eliot_process::{
    ContractError, EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId,
    OperationId, ProcessIntent, ProcessTreeId, ResourceLimits, SessionId,
};
use eliot_store::BlobStore;
use eliot_types::{
    AdapterCapability, AdapterClass, AdapterError, AdapterHealth, AdapterLimits, AdapterRequest,
    AdapterResult, AdapterResultStatus, AdapterState, BlobRef, CapabilityManifest,
    ProcessExecutionPolicy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::EngineError;
use crate::runtime_supervision::{AdapterExecutionContext, CancellationToken};

use super::{
    Adapter, BoxAdapterFuture, adapter_rejected, healthy, manifest, observation_for_request,
    rejected_result,
};

/// Default `adapter_id` for the deterministic process adapter.
pub const PROCESS_ADAPTER_ID: &str = "process.deterministic";

/// Upper bound on how many argv entries one request may carry.
///
/// `eliot-process` enforces its own `MAX_ARGUMENTS`; this is the adapter-side
/// mirror so an oversized request is refused before a `ProcessIntent` is sealed.
const MAX_ADAPTER_ARGV: usize = 256;

/// Upper bound on how many raw output bytes are kept inline before the remainder
/// spills to Blob Store.
const MAX_INLINE_RAW_OUTPUT_BYTES: usize = 4_096;

/// Stable `job_id` used for the logical Job identity.
const ADAPTER_JOB_ID: &str = "adapter:process.deterministic";

/// Stable `session_id` used for the host session identity.
const ADAPTER_SESSION_ID: &str = "adapter:host";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Exact admission material for one registered deterministic process adapter.
///
/// Every field here is *admission*, never a default: a value that is not declared
/// here cannot be used at runtime. In particular there is no field for a shell, a
/// command line, or an inherited environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessAdapterConfig {
    /// Stable adapter identity.
    pub adapter_id: String,
    /// Human-readable name recorded in the manifest and health projection.
    pub name: String,
    /// Adapter contract version. Recorded verbatim in the receipt.
    pub version: String,
    /// The only executable this adapter may launch.
    ///
    /// `None` means the adapter is registered but unarmed: it reports
    /// [`AdapterState::Unavailable`] and refuses every request. That is the safe
    /// default, because an adapter that can launch nothing cannot accidentally
    /// launch something.
    pub executable: Option<String>,
    /// Admitted working-directory roots. A request may name a working directory
    /// only under one of these, or may name none and use the configured default.
    pub working_directory_roots: Vec<String>,
    /// The working directory used when a request names none.
    pub default_working_directory: String,
    /// Non-secret environment values passed to the child. These are the *entire*
    /// child environment: the executor is required to clear first and apply only
    /// this map. Names are the only thing the receipt publishes.
    pub environment_allowlist: BTreeMap<String, String>,
    /// Resource profile ceilings bound to the sealed intent.
    pub resource_limits: ResourceLimits,
    /// Adapter scheduling limits (queue, concurrency, breaker, inline output).
    pub limits: AdapterLimits,
}

impl ProcessAdapterConfig {
    /// Builds a configuration whose only executable is `executable`.
    ///
    /// The executable's content digest is deliberately *not* a config field. It is
    /// derived from the file at dispatch time and sealed into the intent, which is
    /// the honest `I10.17` "exact version" for a process: an executable has no
    /// semantic version field, so its identity is its bytes. A binary swapped
    /// after registration therefore cannot run under a manifest that describes
    /// different bytes — the sealed digest names what actually launched.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter_id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        executable: Option<String>,
        working_directory_roots: Vec<String>,
        default_working_directory: impl Into<String>,
        environment_allowlist: BTreeMap<String, String>,
        resource_limits: ResourceLimits,
    ) -> Result<Self, EngineError> {
        let limits = AdapterLimits {
            timeout_ms: 30_000,
            max_payload_bytes: 16_384,
            max_output_bytes: 65_536,
            max_concurrent_requests: 2,
            circuit_breaker_failures: 3,
        };
        Self::with_limits(
            adapter_id,
            name,
            version,
            executable,
            working_directory_roots,
            default_working_directory,
            environment_allowlist,
            resource_limits,
            limits,
        )
    }

    /// Builds a configuration with explicit adapter scheduling limits.
    #[allow(clippy::too_many_arguments)]
    pub fn with_limits(
        adapter_id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        executable: Option<String>,
        working_directory_roots: Vec<String>,
        default_working_directory: impl Into<String>,
        environment_allowlist: BTreeMap<String, String>,
        resource_limits: ResourceLimits,
        limits: AdapterLimits,
    ) -> Result<Self, EngineError> {
        let adapter_id = adapter_id.into();
        let name = name.into();
        let default_working_directory = default_working_directory.into();
        if adapter_id.trim().is_empty() || name.trim().is_empty() {
            return Err(adapter_rejected(
                "process adapter identity and name are required",
            ));
        }
        if default_working_directory.trim().is_empty() {
            return Err(adapter_rejected(
                "process adapter requires an explicit working directory",
            ));
        }
        if limits.max_concurrent_requests == 0 {
            return Err(adapter_rejected(
                "process adapter max_concurrent_requests must be positive",
            ));
        }
        // The configured default must itself be admitted, otherwise the adapter
        // would hold a root it refuses to use and no request could ever run.
        if !under_any_root(
            Path::new(&default_working_directory),
            &working_directory_roots,
        ) {
            return Err(adapter_rejected(
                "process adapter default working directory is outside its admitted roots",
            ));
        }
        // `EnvironmentProjection` is the secret-safe owner of the child
        // environment. Constructing it here — at registration, not at execute
        // time — means a secret-shaped value is rejected long before any child
        // could observe it.
        let projection = environment_projection(&environment_allowlist)?;
        if projection.inheritance() != EnvironmentInheritance::None {
            return Err(adapter_rejected(
                "process adapter environment inheritance must be None",
            ));
        }
        Ok(Self {
            adapter_id,
            name,
            version: version.into(),
            executable,
            working_directory_roots,
            default_working_directory,
            environment_allowlist,
            resource_limits,
            limits,
        })
    }
}

/// Returns true when `candidate` is `root` itself or lies under it.
///
/// Purely lexical on purpose: a `canonicalize` would require the path to exist
/// before admission, and it would follow a symlink across the boundary this check
/// exists to hold. Existence is checked separately, after admission, by the
/// health probe and by the dispatch port that actually launches.
fn under_any_root(candidate: &Path, roots: &[String]) -> bool {
    roots.iter().any(|root| {
        let root = Path::new(root);
        candidate == root || candidate.starts_with(root)
    })
}

fn environment_projection(
    allowlist: &BTreeMap<String, String>,
) -> Result<EnvironmentProjection, EngineError> {
    EnvironmentProjection::new(allowlist.clone(), Vec::new(), EnvironmentInheritance::None)
        .map_err(|error| contract_rejected(&error))
}

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// The adapter's exact input contract.
///
/// Deliberately three members, none of which can express a command line: an
/// executable, a list of arguments, and a working directory. There is no
/// `command`, `cmdline`, `shell` or `script` member, so the "never interpolate a
/// shell command by default" rule of `I10.17` line 81 is structural rather than a
/// convention a future caller could forget.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessAdapterRequest {
    /// The executable to launch. Admitted only when it equals the configured
    /// executable. `None` means the configured one.
    #[serde(default)]
    pub executable: Option<String>,
    /// Arguments, each a separate argv entry.
    #[serde(default)]
    pub argv: Vec<String>,
    /// Working directory. Admitted only under a configured root.
    #[serde(default)]
    pub working_directory: Option<String>,
}

// ---------------------------------------------------------------------------
// Dispatch port — the Kernel-owned physical boundary
// ---------------------------------------------------------------------------

/// One sealed launch handed to the Kernel process owner.
///
/// `eliot_process::ProcessIntent` carries the sealed effect digest, so the port
/// takes it by value and hands back an outcome that names exactly what the
/// physical layer observed.
///
/// `Clone` without `Debug`: `CancellationToken` is a shared cancellation/reap
/// handle, not evidence, and this value is a dispatch envelope rather than a
/// receipt, so it gets no diagnostic rendering.
#[derive(Clone)]
pub struct ProcessDispatchRequest {
    /// The sealed, validated launch material. Executable, argv, working directory
    /// and environment are separate members by construction.
    pub intent: ProcessIntent,
    /// Ceiling on inline raw output before the adapter spills the remainder to
    /// Blob Store.
    pub max_raw_output_bytes: usize,
    /// Absolute deadline inherited from [`AdapterExecutionContext`].
    pub deadline: Instant,
    /// Cancellation inherited from [`AdapterExecutionContext`].
    pub cancellation: CancellationToken,
}

/// What the physical layer observed.
#[derive(Clone, Debug)]
pub struct ProcessDispatchOutcome {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// The child's exit code. `None` when the child was killed and never reported
    /// one.
    pub exit_code: Option<i32>,
    /// True when the owned process tree was killed on deadline or cancellation.
    pub killed: bool,
}

/// Why a dispatch produced no outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessDispatchError {
    /// The sealed intent could not be launched at all. This is the only variant
    /// that is a transport failure and therefore the only one that counts toward
    /// the circuit breaker.
    Launch(String),
    /// The deadline expired before the child reported an outcome.
    Deadline(String),
    /// Cancellation was observed before the child reported an outcome.
    Cancelled(String),
    /// The physical owner rejected the request itself.
    Refused(String),
}

impl ProcessDispatchError {
    /// Returns the stable error code recorded on the adapter result.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Launch(_) => "transport_failure",
            Self::Deadline(_) => "timeout",
            Self::Cancelled(_) => "cancelled",
            Self::Refused(_) => "dispatch_refused",
        }
    }

    /// Returns the adapter result status this dispatch failure translates to.
    ///
    /// The mapping is the W8 half of issue #1819: only `Launch` is a transport
    /// failure, so only `Launch` may reach circuit accounting.
    pub const fn status(&self) -> AdapterResultStatus {
        match self {
            Self::Launch(_) => AdapterResultStatus::TransportFailure,
            Self::Deadline(_) | Self::Cancelled(_) => AdapterResultStatus::Timeout,
            Self::Refused(_) => AdapterResultStatus::Rejected,
        }
    }

    /// Returns the recorded message.
    pub fn message(&self) -> &str {
        match self {
            Self::Launch(message)
            | Self::Deadline(message)
            | Self::Cancelled(message)
            | Self::Refused(message) => message,
        }
    }
}

impl fmt::Display for ProcessDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

/// The Kernel-owned physical process boundary.
///
/// Production binds this to the sole `ProcessExecutor` implementation
/// (`crates/instrument/eliot-process-executor`), which owns Job Object binding,
/// generation routing and process-tree kill. It is a trait object here because
/// this adapter must not become a second process-lifecycle owner: it decides what
/// may be launched and records what came back, and nothing else.
/// Boxed dispatch future.
///
/// Deliberately NOT [`BoxAdapterFuture`]: that alias collapses a future's own
/// error into [`EngineError`], which would erase the `Launch` / `Deadline` /
/// `Cancelled` / `Refused` distinction that [`ProcessDispatchError::status`] maps
/// onto the issue #1819 W8 outcome taxonomy. Losing it here would turn every
/// dispatch failure into one undifferentiated error at exactly the point the
/// circuit-breaker decision is made.
pub type BoxProcessDispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProcessDispatchOutcome, ProcessDispatchError>> + Send + 'a>>;

/// Returns a boxed future rather than an `async fn` so the port stays object safe
/// and `Arc<dyn ProcessDispatchPort>` is expressible, matching how [`Adapter`]
/// itself is wired.
pub trait ProcessDispatchPort: Send + Sync {
    /// Launches one sealed intent and reports exactly what the physical layer
    /// observed.
    fn dispatch(&self, request: ProcessDispatchRequest) -> BoxProcessDispatchFuture<'_>;
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// The recorded proof of one deterministic process invocation.
///
/// Every member is either copied from the sealed intent (identity the adapter
/// admitted) or observed from the executor (what actually happened). Nothing here
/// is reconstructed after the fact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionReceipt {
    /// The launched executable, separate from `argv`.
    pub executable: String,
    /// The arguments, in order, each a separate argv entry. Never joined.
    pub argv: Vec<String>,
    /// The explicit working directory the child ran in.
    pub working_directory: String,
    /// Names — never values — of the admitted environment allowlist.
    pub environment: Vec<String>,
    /// Adapter contract version recorded at registration.
    pub adapter_version: String,
    /// Content digest of the launched executable: the exact "version" of a
    /// process image.
    pub executable_sha256: String,
    /// Sealed effect digest over executable, argv, cwd, environment, resource
    /// profile and generation: the exact input hash of this invocation.
    pub input_hash: String,
    /// The generation this invocation was fenced to.
    pub generation: u64,
    /// The bound resource profile.
    pub resource_profile: ResourceLimits,
    /// Wall-clock duration measured by the adapter around the dispatch.
    pub duration_ms: u64,
    /// Inline stdout, at most `MAX_INLINE_RAW_OUTPUT_BYTES`.
    pub stdout: String,
    /// Inline stderr, at most `MAX_INLINE_RAW_OUTPUT_BYTES`.
    pub stderr: String,
    /// Total stdout bytes observed, before truncation.
    pub stdout_bytes: usize,
    /// Total stderr bytes observed, before truncation.
    pub stderr_bytes: usize,
    /// True when either stream overflowed and `raw_output_blob` carries the rest.
    pub truncated: bool,
    /// Blob Store handle for the overflow bytes.
    pub raw_output_blob: Option<BlobRef>,
    /// The child's exit code.
    pub exit_code: Option<i32>,
    /// Protocol verdict: `ok`, `non_zero_exit`, or `killed`.
    pub protocol_status: String,
    /// True when the owned process tree was killed on deadline or cancellation.
    pub killed: bool,
    /// Always false: this adapter holds no canonical write authority. It is
    /// recorded rather than implied so the acceptance proof asserts it from the
    /// receipt instead of from the type system.
    pub wrote_canonical_state: bool,
}

// ---------------------------------------------------------------------------
// Adapter
// ---------------------------------------------------------------------------

/// Everything admission proved, ready to be sealed into a [`ProcessIntent`].
///
/// Returned only by [`ProcessAdapter::admit`], so holding one is proof that every
/// admission rule already passed.
struct AdmittedLaunch {
    executable: String,
    executable_sha256: String,
    argv: Vec<String>,
    working_directory: String,
    environment: EnvironmentProjection,
}

/// A registered deterministic process adapter.
///
/// It is `AdapterClass::LocalService`: a governed local process route with its own
/// independent queue, concurrency, circuit and output limits — not a warm
/// supervised external process (`ExternalCandidate`) and not a test double
/// (`InternalTest`).
pub struct ProcessAdapter {
    manifest: CapabilityManifest,
    config: ProcessAdapterConfig,
    dispatch: Arc<dyn ProcessDispatchPort>,
    blob_store: Arc<BlobStore>,
}

impl ProcessAdapter {
    /// Registers the adapter against a Kernel-owned dispatch port.
    ///
    /// `blob_store` is required rather than optional because `I10.17` line 84 makes
    /// bounded output spill to Blob Store a property of every process/CLI adapter,
    /// not a capability a caller may decline.
    pub fn new(
        config: ProcessAdapterConfig,
        dispatch: Arc<dyn ProcessDispatchPort>,
        blob_store: Arc<BlobStore>,
    ) -> Self {
        let capabilities = vec![
            AdapterCapability::HealthCheck,
            AdapterCapability::ExecuteTest,
            AdapterCapability::EmitArtifactHandle,
        ];
        let mut declared = manifest(
            &config.adapter_id,
            &config.name,
            AdapterClass::LocalService,
            capabilities,
            config.limits.clone(),
        );
        declared.version.clone_from(&config.version);
        declared.description = format!(
            "Deterministic local process adapter ({}): sealed executable/argv, explicit cwd and \
             environment allowlist, bounded Blob Store output, exit/protocol receipt",
            declared.adapter_id
        );
        declared.process_policy = ProcessExecutionPolicy {
            process_spawn_allowed: config.executable.is_some(),
            allowed_executables: config.executable.iter().cloned().collect(),
            inherit_environment: false,
            network_allowed: false,
        };
        Self {
            manifest: declared,
            config,
            dispatch,
            blob_store,
        }
    }

    /// Returns the configuration this adapter was registered with.
    pub const fn config(&self) -> &ProcessAdapterConfig {
        &self.config
    }

    /// Readiness is exactly "the one admitted executable resolves on this host".
    ///
    /// Readiness never launches the process: a health probe must not consume the
    /// adapter's own concurrency budget or produce a receipt nobody asked for.
    fn probe_readiness(&self) -> Result<(), String> {
        let executable = self
            .config
            .executable
            .as_deref()
            .ok_or_else(|| "no executable is admitted for this process adapter".to_owned())?;
        let path = Path::new(executable);
        if !path.is_absolute() {
            return Err(format!(
                "admitted executable must be an absolute path so PATH can never select it: \
                 {executable}"
            ));
        }
        if !path.is_file() {
            return Err(format!("admitted executable is not a file: {executable}"));
        }
        if !Path::new(&self.config.default_working_directory).is_dir() {
            return Err(format!(
                "configured working directory is not a directory: {}",
                self.config.default_working_directory
            ));
        }
        Ok(())
    }

    /// Resolves the working directory a request asked for, or the configured one.
    fn admit_working_directory(&self, requested: Option<&str>) -> Result<String, &'static str> {
        let candidate = requested.unwrap_or(&self.config.default_working_directory);
        if !under_any_root(Path::new(candidate), &self.config.working_directory_roots) {
            return Err("requested working directory is outside the admitted roots");
        }
        Ok(candidate.to_owned())
    }

    /// Content digest of the executable at dispatch time.
    ///
    /// An unreadable admitted executable is a **transport** failure, not an
    /// internal adapter error: the route exists and is healthy, the bytes it would
    /// launch are simply not obtainable, which is exactly the condition
    /// `I10.17` line 93 sends to circuit accounting. Returning a generic
    /// `EngineError` here instead would silently drop it into the supervisor's
    /// catch-all `Failed` bucket and the breaker would never see it.
    fn executable_digest(executable: &Path) -> Result<String, String> {
        std::fs::read(executable)
            .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
            .map_err(|error| {
                format!("read admitted executable for identity digest failed: {error}")
            })
    }

    /// The manifest-declared process policy, as admitted.
    pub const fn process_policy(&self) -> &ProcessExecutionPolicy {
        &self.manifest.process_policy
    }
}

impl Adapter for ProcessAdapter {
    fn id(&self) -> &str {
        &self.manifest.adapter_id
    }

    fn manifest(&self) -> &CapabilityManifest {
        &self.manifest
    }

    fn health(&self) -> BoxAdapterFuture<'_, AdapterHealth> {
        Box::pin(async move {
            let checked_at = OffsetDateTime::now_utc();
            match self.probe_readiness() {
                Ok(()) => Ok(healthy(
                    &self.manifest,
                    "process adapter executable resolved",
                )),
                Err(message) => Ok(AdapterHealth {
                    adapter_id: self.manifest.adapter_id.clone(),
                    name: self.manifest.name.clone(),
                    state: AdapterState::Unavailable,
                    healthy: false,
                    message,
                    consecutive_failures: 0,
                    circuit_open: false,
                    checked_at,
                }),
            }
        })
    }

    fn execute(
        &self,
        request: AdapterRequest,
        context: AdapterExecutionContext,
    ) -> BoxAdapterFuture<'_, AdapterResult> {
        Box::pin(async move { self.execute_deterministic(request, context).await })
    }

    fn shutdown(&self) -> BoxAdapterFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

impl ProcessAdapter {
    #[allow(
        clippy::too_many_lines,
        reason = "one ordered admission-then-dispatch-then-receipt transaction"
    )]
    async fn execute_deterministic(
        &self,
        request: AdapterRequest,
        context: AdapterExecutionContext,
    ) -> Result<AdapterResult, EngineError> {
        // Admission first: nothing below this point may launch a process until
        // every admission rule has passed.
        let admission = match self.admit(&request) {
            Ok(admission) => admission,
            Err(refusal) => return Ok(refusal),
        };
        let AdmittedLaunch {
            executable,
            executable_sha256,
            argv,
            working_directory,
            environment,
        } = admission;
        // `Generation::new` rejects zero, and a zero generation would mean the
        // caller fenced this invocation to "no generation at all". The supervisor
        // already substitutes 1 for an absent generation, so a zero here is an
        // explicit claim and is refused by `seal_intent` rather than repaired.
        let generation = context.generation;
        let intent = Self::seal_intent(
            &request,
            &executable,
            &executable_sha256,
            argv,
            working_directory,
            environment,
            self.config.resource_limits,
            generation,
        )?;
        // Sealed before dispatch and never re-derived: this is the exact input hash
        // of the invocation, and it must describe what was launched.
        let input_hash = intent.effect_digest().to_owned();

        let started = Instant::now();
        let outcome = match self
            .dispatch
            .dispatch(ProcessDispatchRequest {
                intent: intent.clone(),
                max_raw_output_bytes: MAX_INLINE_RAW_OUTPUT_BYTES,
                deadline: context.deadline,
                cancellation: context.cancellation.clone(),
            })
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                return Ok(rejected_result(
                    &request,
                    error.status(),
                    error.code(),
                    error.message(),
                ));
            }
        };
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let (stdout, stdout_blob, stdout_truncated) = self.capture_bounded(&outcome.stdout)?;
        let (stderr, stderr_blob, stderr_truncated) = self.capture_bounded(&outcome.stderr)?;
        let receipt = ProcessExecutionReceipt {
            executable: intent.executable().to_owned(),
            argv: intent.argv().to_vec(),
            working_directory: intent.working_directory().to_owned(),
            environment: self.config.environment_allowlist.keys().cloned().collect(),
            adapter_version: self.manifest.version.clone(),
            executable_sha256: intent.executable_sha256().to_owned(),
            input_hash,
            generation,
            resource_profile: *intent.resource_limits(),
            duration_ms,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            stdout_bytes: outcome.stdout.len(),
            stderr_bytes: outcome.stderr.len(),
            truncated: stdout_truncated || stderr_truncated,
            raw_output_blob: stdout_blob.or(stderr_blob),
            exit_code: outcome.exit_code,
            protocol_status: protocol_status(&outcome).to_owned(),
            killed: outcome.killed,
            wrote_canonical_state: false,
        };
        Ok(receipt_result(&request, &receipt, &outcome))
    }

    /// Decides everything that must be true before any process may exist.
    ///
    /// One pass over the argv bound, the executable allowlist, the working-directory
    /// roots and the environment allowlist. Every refusal carries the W8 status that
    /// keeps it out of circuit accounting: an unsupported capability or a rejected
    /// request is not a transport failure and must never reach the breaker.
    #[allow(
        clippy::result_large_err,
        reason = "the refusal is a finished AdapterResult carrying its own receipt-shaped output and observation, not an error to be inspected; boxing it would only move the same bytes and lose the typed status at the call site"
    )]
    fn admit(&self, request: &AdapterRequest) -> Result<AdmittedLaunch, AdapterResult> {
        let parsed: ProcessAdapterRequest =
            serde_json::from_value(request.input.clone()).map_err(|error| {
                rejected_result(
                    request,
                    AdapterResultStatus::Rejected,
                    "malformed_process_request",
                    &format!("process adapter input is not a ProcessAdapterRequest: {error}"),
                )
            })?;
        if parsed.argv.len() > MAX_ADAPTER_ARGV {
            return Err(rejected_result(
                request,
                AdapterResultStatus::Rejected,
                "argv_too_long",
                "process adapter argv exceeds its bound",
            ));
        }
        if parsed
            .executable
            .as_deref()
            .is_some_and(|executable| self.config.executable.as_deref() != Some(executable))
        {
            // Unsupported capability, not a rejection: the route exists and is
            // healthy, it simply does not offer this executable. `I10.17` line 93
            // keeps that distinct from transport failure, and the breaker must
            // never see it.
            return Err(rejected_result(
                request,
                AdapterResultStatus::UnsupportedCapability,
                "executable_not_admitted",
                "requested executable is not in this adapter's admitted allowlist",
            ));
        }
        let Some(executable) = self.config.executable.clone() else {
            return Err(rejected_result(
                request,
                AdapterResultStatus::UnsupportedCapability,
                "no_executable_admitted",
                "this process adapter has no admitted executable",
            ));
        };
        let working_directory = self
            .admit_working_directory(parsed.working_directory.as_deref())
            .map_err(|message| {
                rejected_result(
                    request,
                    AdapterResultStatus::Rejected,
                    "working_directory_not_admitted",
                    message,
                )
            })?;
        let environment =
            environment_projection(&self.config.environment_allowlist).map_err(|error| {
                rejected_result(
                    request,
                    ProcessDispatchError::Launch(String::new()).status(),
                    ProcessDispatchError::Launch(String::new()).code(),
                    &error.to_string(),
                )
            })?;
        let executable_sha256 =
            Self::executable_digest(Path::new(&executable)).map_err(|message| {
                rejected_result(
                    request,
                    ProcessDispatchError::Launch(String::new()).status(),
                    ProcessDispatchError::Launch(String::new()).code(),
                    &message,
                )
            })?;
        Ok(AdmittedLaunch {
            executable,
            executable_sha256,
            argv: parsed.argv,
            working_directory,
            environment,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_intent(
        request: &AdapterRequest,
        executable: &str,
        executable_sha256: &str,
        argv: Vec<String>,
        working_directory: String,
        environment: EnvironmentProjection,
        resource_limits: ResourceLimits,
        generation: u64,
    ) -> Result<ProcessIntent, EngineError> {
        let operation_id = OperationId::new(request.request_id.clone())
            .map_err(|error| contract_rejected(&error))?;
        let tree_id = format!("tree:{}", request.request_id);
        let process_tree_id =
            ProcessTreeId::new(tree_id).map_err(|error| contract_rejected(&error))?;
        let job_id = JobId::new(ADAPTER_JOB_ID).map_err(|error| contract_rejected(&error))?;
        let image = format!("image:{executable_sha256}");
        let image_id = ImageId::new(image).map_err(|error| contract_rejected(&error))?;
        let session_id =
            SessionId::new(ADAPTER_SESSION_ID).map_err(|error| contract_rejected(&error))?;
        let generation = Generation::new(generation).map_err(|error| contract_rejected(&error))?;
        ProcessIntent::new(
            operation_id,
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            executable,
            executable_sha256,
            argv,
            working_directory,
            environment,
            resource_limits,
        )
        .map_err(|error| contract_rejected(&error))
    }

    /// Keeps at most `MAX_INLINE_RAW_OUTPUT_BYTES` inline and spills the rest.
    ///
    /// `I10.17` line 84 asks for bounded output with overflow streamed to Blob
    /// Store. Spilling the overflow — rather than the whole capture — keeps the
    /// common case readable while still guaranteeing the receipt can name the
    /// complete raw bytes.
    fn capture_bounded(&self, raw: &[u8]) -> Result<(Vec<u8>, Option<BlobRef>, bool), EngineError> {
        if raw.len() <= MAX_INLINE_RAW_OUTPUT_BYTES {
            return Ok((raw.to_vec(), None, false));
        }
        let overflow = &raw[MAX_INLINE_RAW_OUTPUT_BYTES..];
        let blob = self.blob_store.put_bytes(overflow)?;
        Ok((
            raw[..MAX_INLINE_RAW_OUTPUT_BYTES].to_vec(),
            Some(blob),
            true,
        ))
    }
}

/// The protocol verdict for a completed dispatch.
fn protocol_status(outcome: &ProcessDispatchOutcome) -> &'static str {
    if outcome.killed {
        "killed"
    } else if outcome.exit_code == Some(0) {
        "ok"
    } else {
        "non_zero_exit"
    }
}

/// Builds the adapter result for a completed exchange.
///
/// A completed exchange with a non-zero exit is `Failed`, and `Failed` is not a
/// transport failure, so `AdapterSupervisor::update_circuit` ignores it. That is the
/// W8 requirement: a command that ran and failed does not open the route.
fn receipt_result(
    request: &AdapterRequest,
    receipt: &ProcessExecutionReceipt,
    outcome: &ProcessDispatchOutcome,
) -> AdapterResult {
    let verdict = protocol_status(outcome);
    let exit_code = outcome.exit_code;
    let killed = outcome.killed;
    let status = match verdict {
        "ok" => AdapterResultStatus::Succeeded,
        _ => AdapterResultStatus::Failed,
    };
    let output = json!({ "process": receipt });
    let error = (verdict != "ok").then(|| AdapterError {
        code: if killed {
            "process_killed".to_owned()
        } else {
            "non_zero_exit".to_owned()
        },
        message: format!(
            "process adapter exchange completed with protocol status {verdict} and exit code \
             {exit_code:?}"
        ),
        retryable: false,
    });
    let mut result = AdapterResult {
        result_id: super::uuid_like("adapter-result"),
        request_id: request.request_id.clone(),
        adapter_id: request.adapter_id.clone(),
        status,
        output,
        output_blob: None,
        observations: Vec::new(),
        error,
        duration_ms: 0,
        trace_id: request.context.trace_id.clone(),
        created_at: OffsetDateTime::now_utc(),
    };
    let observation = observation_for_request(request, &result);
    result.observations.push(observation);
    result
}

fn contract_rejected(error: &ContractError) -> EngineError {
    adapter_rejected(format!("process contract rejected: {error}"))
}

/// Renders the recorded process receipt as a one-line summary, for diagnostics
/// that must not echo captured process output.
pub fn process_receipt_summary(output: &Value) -> Option<String> {
    let receipt = output.get("process")?;
    let executable = receipt
        .get("executable")
        .and_then(Value::as_str)
        .unwrap_or("");
    let argv = receipt
        .get("argv")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let verdict = receipt
        .get("protocol_status")
        .and_then(Value::as_str)
        .unwrap_or("");
    Some(format!("{executable} argv={argv} protocol={verdict}"))
}
