//! Production entry point that resolves one admitted verification route and
//! issues its shared `VerificationProfileReceipt` (issue #1914 W2 + W4).
//!
//! I18.21 requires that "CI builds the ELIOT verifier/runner bootstrap and then
//! calls the same versioned profiles used locally", that "local profile
//! revision == CI profile revision", that "executable/tool identities are
//! pinned or recorded", that "external binaries require digest/provenance
//! receipt", and that there is "no CI-only hidden verifier command list". This
//! binary is the one owner both sides execute, so the alias that names the
//! route, the admitted revision, the profile and stage digests, the receipt
//! schema, and the fail-closed identity/provenance checks are all decided by
//! the same code on either side of the network boundary.
//!
//! "local profile revision == CI profile revision" is decided by that same code
//! rather than asserted in prose. Given `--compare-against <receipt.json>`, this
//! entry deserialises the counterpart `VerificationProfileReceipt` and hands
//! both receipts to the one owner [`verify_profile_parity`], which refuses a
//! changed profile revision, a divergent schema/definition/stage-graph digest, a
//! missing declared environment dependency, a divergent tool identity, and a CI
//! verifier command the local receipt never declared. A refused comparison is
//! this entry's fail-closed nonzero exit, never a warning or a run that
//! proceeds anyway. The comparison is not implicit: a run that supplies no
//! `--compare-against` performs none, because the counterpart artifact is the
//! caller's exactly as `--receipt-out` is.
//!
//! Everything the receipt records is machine-observed or registry-admitted:
//!
//! - the route is named by a closed [`PROFILE_ALIASES`] entry and resolved
//!   through the shared [`InstrumentRegistry`]; it is never a command, a path,
//!   or a stage list, so no caller can invoke a stage the resolver did not
//!   admit;
//! - the pinned executable identity of every external stage is the SHA-256 of
//!   the real tool bytes on this machine, observed here, admitted as a
//!   [`SupplyChainReceipt`] against the admitted spec digest, and re-checked by
//!   `require_provenance` against the identity the launch itself recorded. A
//!   tool whose bytes cannot be read, or whose observed bytes differ from the
//!   admitted receipt, fails closed instead of yielding a receipt with a
//!   defaulted identity;
//! - an admitted spec names a toolchain MEMBER — every builtin declares the bare
//!   name `cargo` — and that name is resolved through the selected toolchain
//!   root by the one [`resolve_tool`] owner, never through a bare `PATH` lookup.
//!   A `PATH` lookup returns the rustup PROXY (`~/.cargo/bin/cargo`, canonically
//!   `rustup.exe`) on a normal install, which is a different FILE from the one
//!   the profile declares, so the identity pinned here, the identity sealed into
//!   the process intent, and the file actually launched would disagree. There is
//!   no `PATH` fallback and no "resolve to whatever exists": a workspace with no
//!   resolvable toolchain is refused rather than receipted against some ambient
//!   binary;
//! - every stage really starts as a real child through the sole
//!   [`WindowsProcessExecutor`] under a Kernel-issued dispatch permit, so the
//!   per-stage evidence the receipt carries came from a process this entry
//!   executed rather than from a value it was handed. The `--version` read that
//!   pins each tool's identity is launched the same way, under its own one-shot
//!   permit, so this entry has no launch of any kind outside that single
//!   executor. Each such child is observed to a terminal lifecycle before its
//!   evidence is read, because the executor's `reconcile` is terminal-only: see
//!   [`await_terminal_view`]. That stage launch is gated by
//!   `StageOrchestrator::launch_plan_live`, which refuses to launch a plan
//!   compiled against a replaced registry generation and admits each stage
//!   through `AdmittedStage::admit_live` against the live [`InstrumentRegistry`]
//!   this run assembled from the observed supply-chain receipts, so a spec,
//!   parser, receipt, or route revoked since compilation fails closed before
//!   any child exists;
//! - the receipt itself is issued by the shared
//!   [`build_verification_profile_receipt`] through
//!   [`resolve_verification_route`], which refuses a missing executable
//!   identity, a missing or mismatched supply-chain receipt, and an undeclared
//!   stage before any receipt exists.
//!
//! This entry never decides a verdict of its own: the receipt's normalized
//! outcome is the aggregate the admitted stages produced, a non-PASS outcome is
//! written to the receipt and reflected in the exit code, and nothing is
//! rounded up to PASS.
//!
//! Usage (I18.21:14 — the caller builds this binary as the one minimal
//! bootstrap build, then calls it with the same alias locally and in CI):
//!
//! ```text
//! eliot-profile-resolver --alias package-verification --source-root <abs> \
//!     --target-root <abs> --cache-root <abs> [--declared-environment NAME]... \
//!     [--receipt-out <path>] [--compare-against <counterpart-receipt.json>]
//! ```
//!
//! `--compare-against` is the caller's counterpart receipt — the artifact the
//! other side of the network boundary produced with the same alias. It is
//! compared by the shared [`verify_profile_parity`] owner, so the revision
//! equality is a computed verdict and a divergence refuses the run.
//!
//! Value discipline: `--alias` is matched exactly against the closed table
//! rather than normalized; the three roots must be existing absolute,
//! traversal-free, pairwise distinct paths or `TargetLayout` refuses them; the
//! environment class is the admitted `isolated-process` class both routes
//! declare, attested over the concrete material this process actually used; the
//! authority epoch, the per-stage nonce, and the clock are observed or derived
//! per process; and the pinned tool digests are read from the real executables,
//! never supplied as text.

#![forbid(unsafe_code)]
// The canonical receipt on stdout and its fail-closed refusal on stderr are
// this entry point's operator-facing contract, the same reason
// `eliot-verifier-selfchange` carries it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eliot_contracts::{
    ClockReading, ContractId, EpochContractError, EpochId, EpochLineageId, ProductId, RequestId,
    RequestMetadata, ResourceGeneration, SourceId, StateFence, sha256_hex,
};
use eliot_instrument_api::{InstrumentContractError, InstrumentInvocation};
use eliot_instrument_runner::{
    ADMITTED_SCOPE_CLASS, AdmittedProfile, DeclaredEnvironmentDependency, ISOLATED_PROCESS_CLASS,
    InstrumentRegistry, InstrumentRequestPort, InstrumentRunner, InstrumentSpec, ParityVerdict,
    PlannedStage, ProfileAggregate, ProfileCompiler, RunnerError, StageEnvironment, StageEvidence,
    StageLauncher, StageOrchestrator, SupplyChainReceipt, TargetLayout, VerificationProfileReceipt,
    VerificationRouteRequest, WorkScope, admitted_profile_for_alias, parity_summary,
    profile::{PROFILE_ALIASES, TOOLCHAIN_PATH_ENV, builtin_specs},
    resolve_verification_route, verify_profile_parity,
};
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError,
    ExitDisposition, FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId,
    PermitIssuance, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError,
    ProcessExecutionView, ProcessExecutor, ProcessIntent, ProcessRequest, ProcessStartReceipt,
    ProcessTreeId, ResourceLimits, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{
    DispatchValidationPort, ExecutableObservation, WindowsProcessExecutor,
    environment_projection_digest,
};

const EXIT_PASS: i32 = 0;
const EXIT_REFUSED: i32 = 1;
const VALIDATION_REVISION: u64 = 1;
const VERIFICATION_REGISTRY_GENERATION: u64 = 1;
const EPOCH_LINEAGE: &str = "eliot-verification-profile-resolver";
const ADMITTED_PRODUCT: &str = "eliot";
const STAGE_STDOUT_BYTES: u64 = 4 * 1024 * 1024;
const STAGE_WALL_TIMEOUT_MS: u64 = 3_600_000;
const STAGE_MAX_DESCENDANTS: u32 = 256;
const MAX_TOOL_VERSION_BYTES: usize = 4096;
const VERSION_WALL_TIMEOUT_MS: u64 = 60_000;
const VERSION_STDOUT_BYTES: u64 = 64 * 1024;
const VERSION_MAX_DESCENDANTS: u32 = 8;
const VERSION_OBSERVE_TIMEOUT: Duration = Duration::from_millis(VERSION_WALL_TIMEOUT_MS);
const VERSION_OBSERVE_POLL: Duration = Duration::from_millis(25);

struct Request {
    alias: String,
    source_root: PathBuf,
    target_root: PathBuf,
    cache_root: PathBuf,
    declared_environments: Vec<String>,
    receipt_out: Option<PathBuf>,
    compare_against: Option<PathBuf>,
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Contract(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(detail) | Self::Contract(detail) => {
                write!(f, "profile resolution refused: {detail}")
            }
        }
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Contract(format!("receipt is not serializable: {error}"))
    }
}

impl From<eliot_contracts::ContractError> for CliError {
    fn from(error: eliot_contracts::ContractError) -> Self {
        Self::Contract(format!("contract identity refused: {error}"))
    }
}

impl From<EpochContractError> for CliError {
    fn from(error: EpochContractError) -> Self {
        Self::Contract(format!("epoch identity refused: {error}"))
    }
}

impl From<eliot_process::ContractError> for CliError {
    fn from(error: eliot_process::ContractError) -> Self {
        Self::Contract(format!("process contract refused: {error}"))
    }
}

impl From<ProcessExecutionError> for CliError {
    fn from(error: ProcessExecutionError) -> Self {
        Self::Contract(format!("process boundary refused: {error}"))
    }
}

impl From<InstrumentContractError> for CliError {
    fn from(error: InstrumentContractError) -> Self {
        Self::Contract(format!("instrument admission refused: {error}"))
    }
}

impl From<RunnerError> for CliError {
    fn from(error: RunnerError) -> Self {
        Self::Contract(format!("instrument launch refused: {error}"))
    }
}

impl From<eliot_instrument_runner::RegistryError> for CliError {
    fn from(error: eliot_instrument_runner::RegistryError) -> Self {
        Self::Contract(format!("executable identity refused: {error}"))
    }
}

impl From<eliot_instrument_runner::ProfileError> for CliError {
    fn from(error: eliot_instrument_runner::ProfileError) -> Self {
        Self::Contract(format!("profile admission refused: {error}"))
    }
}

impl From<eliot_instrument_runner::VerificationProfileError> for CliError {
    fn from(error: eliot_instrument_runner::VerificationProfileError) -> Self {
        Self::Contract(format!("verification receipt refused: {error}"))
    }
}

impl From<eliot_instrument_runner::DevFastError> for CliError {
    fn from(error: eliot_instrument_runner::DevFastError) -> Self {
        Self::Contract(format!("profile route refused: {error}"))
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self::Contract(format!("receipt could not be written: {error}"))
    }
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let request = match read_request() {
        Ok(request) => request,
        Err(error) => {
            eprintln!("{error}");
            return EXIT_REFUSED;
        }
    };
    let receipt = match resolve_route(&request) {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!("{error}");
            return EXIT_REFUSED;
        }
    };
    if let Err(error) = require_receipt_parity(&request, &receipt) {
        eprintln!("{error}");
        return EXIT_REFUSED;
    }
    match serde_json::to_string_pretty(&receipt) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!(
                "{}",
                CliError::Contract(format!("receipt is not serializable: {error}"))
            );
            return EXIT_REFUSED;
        }
    }
    if receipt.outcome.is_pass() {
        EXIT_PASS
    } else {
        EXIT_REFUSED
    }
}

fn require_receipt_parity(
    request: &Request,
    receipt: &VerificationProfileReceipt,
) -> Result<(), CliError> {
    let Some(path) = request.compare_against.as_deref() else {
        return Ok(());
    };
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::Contract(format!(
            "counterpart receipt {} is unreadable: {error}",
            path.display()
        ))
    })?;
    let counterpart: VerificationProfileReceipt =
        serde_json::from_slice(&bytes).map_err(|error| {
            CliError::Contract(format!(
                "counterpart receipt {} is not a VerificationProfileReceipt: {error}",
                path.display()
            ))
        })?;
    let verdict = verify_profile_parity(receipt, &counterpart)?;
    println!("{}", parity_summary(&verdict));
    match verdict {
        ParityVerdict::Pass { .. } => Ok(()),
        ParityVerdict::NonPass { reason } => Err(CliError::Contract(format!(
            "local/CI profile parity refused against '{}': {reason}",
            path.display()
        ))),
    }
}

fn resolve_route(request: &Request) -> Result<VerificationProfileReceipt, CliError> {
    let layout = TargetLayout::new(
        admitted_root(&request.source_root)?,
        admitted_root(&request.target_root)?,
        admitted_root(&request.cache_root)?,
    )?;
    let specs = builtin_specs()?;
    let receipts = observed_supply_chain(&specs, &layout.source_root)?;
    let registry = InstrumentRegistry::with_verification_route_profiles(
        VERIFICATION_REGISTRY_GENERATION,
        receipts.clone(),
    )?;
    let route = admitted_profile_for_alias(&request.alias, &registry)?.clone();
    let compiler = ProfileCompiler::new(&registry);
    let admitted = compiler.compile_exact(&route.name, route.revision)?;
    let epoch = process_epoch()?;
    let clock = observation_clock(now_unix_ms());
    let scope = WorkScope::new(
        ADMITTED_SCOPE_CLASS.to_owned(),
        StateFence::new(
            epoch.clone(),
            ResourceGeneration::new(VERIFICATION_REGISTRY_GENERATION)?,
        ),
    )?;
    let environment = StageEnvironment::attest(
        ISOLATED_PROCESS_CLASS.to_owned(),
        &format!(
            "{}\0{}\0{}\0{}\0{}",
            ADMITTED_SCOPE_CLASS,
            ISOLATED_PROCESS_CLASS,
            layout.source_root,
            request.alias,
            admitted.profile_digest
        ),
    )?;
    let dependencies = request
        .declared_environments
        .iter()
        .map(|name| {
            Ok(DeclaredEnvironmentDependency::new(
                name.clone(),
                ISOLATED_PROCESS_CLASS.to_owned(),
                &environment,
            )?)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    compiler.resolve_full(
        &admitted.name,
        admitted.revision,
        layout.clone(),
        scope.clone(),
        environment.clone(),
    )?;
    let cell = Arc::new(DispatchCell::activate()?);
    let port = StagePort::seal_all(&cell, &epoch, &layout, &admitted)?;
    let runner = InstrumentRunner::new(Arc::new(StageExecutor::with(&cell)));
    let launcher = StageRoute {
        epoch,
        clock,
        layout: layout.clone(),
        port,
    };
    let plan = StageOrchestrator::plan(&admitted);
    let runs = block_on(StageOrchestrator::launch_plan_live(
        &runner, &registry, &plan, &launcher,
    ));
    let aggregate = ProfileAggregate::assemble(&plan, runs);
    require_launched_stage(&admitted, &aggregate)?;
    let receipt = resolve_verification_route(
        VERIFICATION_REGISTRY_GENERATION,
        VerificationRouteRequest {
            receipts,
            route: request.alias.clone(),
            layout,
            scope,
            environment,
        },
        &aggregate,
        &dependencies,
    )?;
    if let Some(path) = &request.receipt_out {
        std::fs::write(path, serde_json::to_vec_pretty(&receipt)?)?;
    }
    Ok(receipt)
}

fn require_launched_stage(
    admitted: &AdmittedProfile,
    aggregate: &ProfileAggregate,
) -> Result<(), CliError> {
    let launched = aggregate
        .runs
        .iter()
        .filter(|run| run.executable_digest.is_some())
        .count();
    if launched == 0 {
        let refusals = stage_refusals(aggregate);
        return Err(CliError::Contract(format!(
            "route '{}' revision {} launched no admitted stage; no tool identity was observed; {}",
            admitted.name, admitted.revision, refusals
        )));
    }
    Ok(())
}

fn stage_refusals(aggregate: &ProfileAggregate) -> String {
    if aggregate.runs.is_empty() {
        return "no admitted stage produced a run record at all".to_owned();
    }
    let mut reported = Vec::with_capacity(aggregate.runs.len());
    for run in &aggregate.runs {
        let stage_id = run.stage.stage_id.as_str();
        let reason = match &run.evidence {
            StageEvidence::Missing { reason } | StageEvidence::Omitted { reason } => {
                format!("{reason} (evidence missing, execution {:?})", run.execution)
            }
            StageEvidence::Retained { .. } => {
                format!("launched (execution {:?})", run.execution)
            }
        };
        reported.push(format!("stage '{stage_id}' {reason}"));
    }
    format!("per-stage refusals: [{}]", reported.join("; "))
}

fn observed_supply_chain(
    specs: &[InstrumentSpec],
    source_root: &str,
) -> Result<Vec<SupplyChainReceipt>, CliError> {
    specs
        .iter()
        .map(|spec| {
            let executable = resolve_tool(&spec.executable, source_root)?;
            Ok(SupplyChainReceipt::new(
                ContractId::new(spec.kind.as_str())?,
                spec.executable.clone(),
                file_digest(&executable)?,
                None,
                spec.digest(),
                VERIFICATION_REGISTRY_GENERATION,
            )?)
        })
        .collect()
}

fn admitted_root(path: &Path) -> Result<String, CliError> {
    if !path.is_absolute() {
        return Err(CliError::Contract(format!(
            "admitted root {} is not absolute",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        CliError::Contract(format!(
            "admitted root {} is unavailable: {error}",
            path.display()
        ))
    })?;
    Ok(canonical.to_string_lossy().into_owned())
}

fn resolve_tool(name: &str, source_root: &str) -> Result<PathBuf, CliError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() || candidate.components().count() > 1 {
        return Err(CliError::Contract(format!(
            "admitted executable '{name}' must be a bare tool name resolved through the selected toolchain"
        )));
    }
    let root = selected_toolchain_root(source_root)?;
    for suffix in executable_suffixes() {
        let candidate = root.join(format!("{name}{suffix}"));
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate).map_err(|error| {
                CliError::Contract(format!(
                    "admitted executable {} is unavailable: {error}",
                    candidate.display()
                ))
            });
        }
    }
    Err(CliError::Contract(format!(
        "admitted executable '{name}' is not a member of the selected toolchain {}; an unpinned tool cannot be receipted",
        root.display()
    )))
}

fn selected_toolchain_root(source_root: &str) -> Result<PathBuf, CliError> {
    let rustup_home = rustup_home()?;
    let source_root = current_source_root(source_root)?;
    let settings = read_bounded_metadata(
        &Path::new(&rustup_home).join("settings.toml"),
        "rustup settings",
    )?;
    let host = toml_string_value(&settings, "default_host_triple");
    let requested = read_toolchain_override(Path::new(&source_root))?
        .or_else(|| toml_string_value(&settings, "default_toolchain"))
        .ok_or_else(|| {
            CliError::Contract(format!(
                "no toolchain is selected: {source_root} pins none and {rustup_home} names no default"
            ))
        })?;
    let toolchains = Path::new(&rustup_home).join("toolchains");
    let mut candidates = std::fs::read_dir(&toolchains)
        .map_err(|error| {
            CliError::Contract(format!(
                "toolchain root {} is unavailable: {error}",
                toolchains.display()
            ))
        })?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .map(|_| entry.file_name().to_string_lossy().into_owned())
        })
        .filter(|name| name == &requested || name.starts_with(&format!("{requested}-")))
        .collect::<Vec<_>>();
    candidates.sort();
    if let Some(host) = host.as_deref() {
        let host_candidates = candidates
            .iter()
            .filter(|name| name.ends_with(host))
            .cloned()
            .collect::<Vec<_>>();
        if !host_candidates.is_empty() {
            candidates = host_candidates;
        }
    }
    let [selected] = candidates.as_slice() else {
        return Err(CliError::Contract(format!(
            "toolchain '{requested}' is not installed under {}; an unpinned toolchain cannot be receipted",
            toolchains.display()
        )));
    };
    Ok(toolchains.join(selected).join("bin"))
}

fn rustup_home() -> Result<String, CliError> {
    let candidate = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(|home| PathBuf::from(home).join(".rustup"))
        })
        .ok_or_else(|| {
            CliError::Contract("toolchain root is unknown: RUSTUP_HOME is unset".to_owned())
        })?;
    if !candidate.is_absolute() || !candidate.is_dir() {
        return Err(CliError::Contract(format!(
            "toolchain root {} is not an existing absolute directory",
            candidate.display()
        )));
    }
    Ok(std::fs::canonicalize(&candidate)
        .map_err(|error| {
            CliError::Contract(format!(
                "toolchain root {} cannot be canonicalized: {error}",
                candidate.display()
            ))
        })?
        .to_string_lossy()
        .into_owned())
}

fn current_source_root(source_root: &str) -> Result<String, CliError> {
    let root = PathBuf::from(source_root);
    if !root.is_absolute() || !root.is_dir() {
        return Err(CliError::Contract(format!(
            "admitted source root {} is not an existing absolute directory",
            root.display()
        )));
    }
    Ok(std::fs::canonicalize(&root)
        .map_err(|error| {
            CliError::Contract(format!(
                "admitted source root {} cannot be canonicalized: {error}",
                root.display()
            ))
        })?
        .to_string_lossy()
        .into_owned())
}

fn read_toolchain_override(source_root: &Path) -> Result<Option<String>, CliError> {
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        let path = source_root.join(name);
        match path.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                return Err(CliError::Contract(format!(
                    "rust-toolchain override {} cannot be inspected: {error}",
                    path.display()
                )));
            }
        }
        let text = read_bounded_metadata(&path, "rust-toolchain override")?;
        let value = if name.ends_with(".toml") {
            eliot_bootstrap::normative::parse_rust_toolchain_channel(&text).map_err(|error| {
                CliError::Contract(format!(
                    "rust-toolchain override {} is invalid: {error}",
                    path.display()
                ))
            })?
        } else {
            text.lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    CliError::Contract(format!(
                        "rust-toolchain override {} has no selected channel",
                        path.display()
                    ))
                })?
        };
        let value = value.trim();
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(CliError::Contract(format!(
                "rust-toolchain override {} has no valid selected channel",
                path.display()
            )));
        }
        return Ok(Some(value.to_owned()));
    }
    Ok(None)
}

fn read_bounded_metadata(path: &Path, what: &str) -> Result<String, CliError> {
    const MAX_METADATA_BYTES: usize = 64 * 1024;
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::Contract(format!("{what} {} is unreadable: {error}", path.display()))
    })?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(CliError::Contract(format!(
            "{what} {} exceeds the bounded read size",
            path.display()
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| CliError::Contract(format!("{what} {} is not UTF-8", path.display())))
}

fn toml_string_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        let value = value.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn executable_suffixes() -> Vec<String> {
    let suffixes = std::env::var("PATHEXT")
        .map(|pathext| {
            pathext
                .split(';')
                .filter(|suffix| !suffix.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if suffixes.is_empty() {
        return vec![String::new()];
    }
    suffixes
}

fn file_digest(path: &Path) -> Result<String, CliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::Contract(format!(
            "executable {} is unreadable: {error}",
            path.display()
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

fn await_terminal_view(
    executor: &WindowsProcessExecutor,
    operation: &OperationId,
    executable: &Path,
) -> Result<ProcessExecutionView, CliError> {
    let started = Instant::now();
    loop {
        let view = block_on(executor.inspect(operation.clone()))?;
        if view.lifecycle().is_terminal() {
            return Ok(view);
        }
        if started.elapsed() >= VERSION_OBSERVE_TIMEOUT {
            return Err(CliError::Contract(format!(
                "tool {} was still {:?} after {}ms of governed observation; its version is unknown rather than unobserved",
                executable.display(),
                view.lifecycle(),
                VERSION_OBSERVE_TIMEOUT.as_millis()
            )));
        }
        std::thread::sleep(VERSION_OBSERVE_POLL);
    }
}

fn observed_tool_version(executable: &Path, epoch: &EpochId) -> Result<String, CliError> {
    let cell = Arc::new(DispatchCell::activate()?);
    let executor = StageExecutor::with(&cell);
    let request = seal_version_request(&cell, epoch, executable)?;
    let receipt = block_on(executor.start(
        request,
        Arc::new(RetainedEvidenceSink::default()) as Arc<dyn ProcessEvidenceSink>,
    ))?;
    let view = await_terminal_view(executor.executor(), receipt.operation_id(), executable)?;
    let exit = view.exit().ok_or_else(|| {
        CliError::Contract(format!(
            "tool {} reported no exit observation while reading its version",
            executable.display()
        ))
    })?;
    if exit.disposition() != ExitDisposition::Completed {
        return Err(CliError::Contract(format!(
            "tool {} ended {exit:?} while reporting its version",
            executable.display()
        )));
    }
    let evidence = block_on(executor.reconcile(receipt.operation_id().clone()))?;
    let stdout = evidence.stdout().ok_or_else(|| {
        CliError::Contract(format!(
            "tool {} retained no version output",
            executable.display()
        ))
    })?;
    if !stdout.preview().omitted_ranges().is_empty() {
        return Err(CliError::Contract(format!(
            "tool {} wrote more than the {VERSION_STDOUT_BYTES} byte version bound; its version line was truncated",
            executable.display()
        )));
    }
    let reported = String::from_utf8_lossy(stdout.preview().bytes());
    let version = reported
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| {
            CliError::Contract(format!(
                "tool {} printed no version line",
                executable.display()
            ))
        })?;
    if version.len() > MAX_TOOL_VERSION_BYTES {
        return Err(CliError::Contract(format!(
            "tool {} reported a {} byte version line, over the {MAX_TOOL_VERSION_BYTES} byte bound",
            executable.display(),
            version.len()
        )));
    }
    Ok(version.to_owned())
}

fn seal_version_request(
    cell: &DispatchCell,
    epoch: &EpochId,
    executable: &Path,
) -> Result<ProcessRequest, CliError> {
    let projection = isolated_projection()?;
    let argv = vec!["--version".to_owned()];
    let operation = format!(
        "verification-profile-version-{}",
        &sha256_hex(format!("{}\0{}", executable.display(), argv.join("\u{1}")).as_bytes())[..24]
    );
    let intent = ProcessIntent::new(
        OperationId::new(operation.clone())?,
        ProcessTreeId::new(format!("{operation}-tree"))?,
        JobId::new(format!("{operation}-job"))?,
        ImageId::new(format!("{operation}-image"))?,
        SessionId::new(format!("{EPOCH_LINEAGE}-{operation}"))?,
        Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
        executable.to_string_lossy().into_owned(),
        file_digest(executable)?,
        argv.clone(),
        executable
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_string_lossy()
            .into_owned(),
        projection,
        ResourceLimits::new(
            VERSION_WALL_TIMEOUT_MS,
            None,
            None,
            VERSION_STDOUT_BYTES,
            VERSION_STDOUT_BYTES,
            VERSION_MAX_DESCENDANTS,
        )?,
    )?;
    let fence = FencingToken::new(
        epoch.clone(),
        Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
        format!("{operation}-fence"),
    )?;
    let heads = BTreeMap::from([(
        "verification-profile-version".to_owned(),
        sha256_hex(format!("{operation}\0{}", argv.join("\u{1}")).as_bytes()),
    )]);
    let issued_at = now_unix_ms().max(1);
    cell.issue(
        &intent,
        fence,
        heads,
        issued_at,
        issued_at.saturating_add(VERSION_WALL_TIMEOUT_MS),
        ActionLeaseRef::new(format!("{operation}-lease"))?,
        format!("{operation}-nonce"),
    )
}

fn read_request() -> Result<Request, CliError> {
    let mut args = std::env::args().skip(1);
    let mut alias = None;
    let mut source_root = None;
    let mut target_root = None;
    let mut cache_root = None;
    let mut declared_environments = Vec::new();
    let mut receipt_out = None;
    let mut compare_against = None;
    while let Some(option) = args.next() {
        let mut value = |option: &str| {
            args.next()
                .ok_or_else(|| CliError::Usage(format!("{option} requires a value")))
        };
        match option.as_str() {
            "--alias" => alias = Some(value("--alias")?),
            "--source-root" => source_root = Some(PathBuf::from(value("--source-root")?)),
            "--target-root" => target_root = Some(PathBuf::from(value("--target-root")?)),
            "--cache-root" => cache_root = Some(PathBuf::from(value("--cache-root")?)),
            "--declared-environment" => {
                declared_environments.push(value("--declared-environment")?);
            }
            "--receipt-out" => receipt_out = Some(PathBuf::from(value("--receipt-out")?)),
            "--compare-against" => {
                compare_against = Some(PathBuf::from(value("--compare-against")?));
            }
            other => return Err(CliError::Usage(format!("unknown option '{other}'"))),
        }
    }
    let alias = alias.ok_or_else(|| {
        CliError::Usage(format!(
            "--alias is required; it must name one of {}",
            aliases()
        ))
    })?;
    Ok(Request {
        alias,
        source_root: source_root
            .ok_or_else(|| CliError::Usage("--source-root is required".to_owned()))?,
        target_root: target_root
            .ok_or_else(|| CliError::Usage("--target-root is required".to_owned()))?,
        cache_root: cache_root
            .ok_or_else(|| CliError::Usage("--cache-root is required".to_owned()))?,
        declared_environments,
        receipt_out,
        compare_against,
    })
}

fn aliases() -> String {
    PROFILE_ALIASES
        .iter()
        .map(|entry| entry.alias)
        .collect::<Vec<_>>()
        .join(", ")
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => return output,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn process_epoch() -> Result<EpochId, CliError> {
    let mut material = fresh_key_bytes();
    material[..8].copy_from_slice(&u64::from(std::process::id()).to_le_bytes());
    material[8..16].copy_from_slice(&system_nanos().to_le_bytes());
    let mut lineage = String::with_capacity(36);
    for (index, byte) in material.iter().take(16).enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            lineage.push('-');
        }
        write!(lineage, "{byte:02x}")
            .map_err(|_| CliError::Contract("epoch lineage is not formattable".to_owned()))?;
    }
    let lineage = EpochLineageId::new(lineage)?;
    let sequence = NonZeroU64::new(1)
        .ok_or_else(|| CliError::Contract("epoch sequence is not one".to_owned()))?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn system_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

fn observation_clock(now: u64) -> ClockReading {
    let ceiling = i64::MAX;
    let now = i64::try_from(now.min(ceiling.cast_unsigned())).unwrap_or(i64::MAX);
    ClockReading {
        valid_time_ms: Some(now),
        known_time_ms: Some(now),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn fresh_key_bytes() -> [u8; 32] {
    static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let probe = 0u64;
    let stack = u64::try_from(std::ptr::addr_of!(probe).addr()).unwrap_or(0);
    let pid = u64::from(std::process::id());
    let count = MIXER.fetch_add(1, Ordering::Relaxed);
    let mut state = system_nanos()
        ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9)
        ^ stack.rotate_left(17)
        ^ count.wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    if out.iter().all(|byte| *byte == 0) {
        out[31] = 1;
    }
    out
}

struct DispatchCell {
    authority: Mutex<DispatchPermitAuthority>,
    contexts: Mutex<BTreeMap<String, DispatchValidationContext>>,
}

impl DispatchCell {
    fn activate() -> Result<Self, CliError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id =
            DispatchAuthorityId::new(format!("profile-resolver-dispatch-{pid}-{nanos}"))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            contexts: Mutex::new(BTreeMap::new()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        intent: &ProcessIntent,
        fence: FencingToken,
        heads: BTreeMap<String, String>,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        lease: ActionLeaseRef,
        nonce: String,
    ) -> Result<ProcessRequest, CliError> {
        let pinned_heads = heads.clone();
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads,
            issued_at_unix_ms,
            expires_at_unix_ms,
            nonce,
        )?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| CliError::Contract("dispatch authority lock poisoned".to_owned()))?
            .issue(intent, issuance)?;
        let context_epoch = fence.authority_epoch().clone();
        let context = DispatchValidationContext::new(
            observation_clock(issued_at_unix_ms),
            fence,
            context_epoch,
            pinned_heads,
            VALIDATION_REVISION,
        )?;
        self.contexts
            .lock()
            .map_err(|_| CliError::Contract("validation context lock poisoned".to_owned()))?
            .insert(intent.operation_id().as_str().to_owned(), context);
        Ok(ProcessRequest::new(intent.clone(), permit)?)
    }

    fn context(
        &self,
        request: &ProcessRequest,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        self.contexts
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("validation context poisoned".to_owned())
            })?
            .get(request.operation_id().as_str())
            .cloned()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(format!(
                    "validation context absent for operation '{}'",
                    request.operation_id().as_str()
                ))
            })
    }
}

impl DispatchValidationPort for DispatchCell {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let context = self.context(&request)?;
        self.authority
            .lock()
            .map_err(|_| ProcessExecutionError::Unavailable("authority lock poisoned".to_owned()))?
            .validate_and_consume(request, observed, &context)
            .map_err(ProcessExecutionError::from)
    }
}

struct StageExecutor {
    executor: WindowsProcessExecutor,
}

impl StageExecutor {
    fn with(cell: &Arc<DispatchCell>) -> Self {
        Self {
            executor: WindowsProcessExecutor::new(
                Arc::clone(cell) as Arc<dyn DispatchValidationPort>
            ),
        }
    }

    fn executor(&self) -> &WindowsProcessExecutor {
        &self.executor
    }
}

impl ProcessExecutor for StageExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        self.executor().start(request, sink).await
    }

    async fn inspect(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessExecutionView, ProcessExecutionError> {
        self.executor().inspect(operation_id).await
    }

    async fn cancel(
        &self,
        operation_id: OperationId,
    ) -> Result<CancellationReceipt, ProcessExecutionError> {
        self.executor().cancel(operation_id).await
    }

    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.executor().reconcile(operation_id).await
    }
}

struct StageRoute {
    epoch: EpochId,
    clock: ClockReading,
    layout: TargetLayout,
    port: StagePort,
}

struct StagePort {
    sealed: std::sync::Mutex<BTreeMap<String, ProcessRequest>>,
    sink: Arc<RetainedEvidenceSink>,
}

impl StagePort {
    fn seal_all(
        cell: &DispatchCell,
        epoch: &EpochId,
        layout: &TargetLayout,
        admitted: &AdmittedProfile,
    ) -> Result<Self, CliError> {
        let plan = StageOrchestrator::plan(admitted);
        let mut sealed = BTreeMap::new();
        for planned in &plan.stages {
            let stage_id = planned.route.stage().stage_id.as_str();
            let argv = stage_argv(planned);
            let operation = operation_identity(stage_id, &argv);
            let request = seal_stage_request(
                cell,
                epoch,
                layout,
                stage_id,
                &planned.stage.executable,
                &argv,
            )?;
            sealed.insert(operation, request);
        }
        Ok(Self {
            sealed: std::sync::Mutex::new(sealed),
            sink: Arc::new(RetainedEvidenceSink::default()),
        })
    }
}

fn stage_argv(stage: &PlannedStage) -> Vec<String> {
    stage.stage.verification_command.clone()
}

fn seal_stage_request(
    cell: &DispatchCell,
    epoch: &EpochId,
    layout: &TargetLayout,
    stage_id: &str,
    executable_name: &str,
    argv: &[String],
) -> Result<ProcessRequest, CliError> {
    let executable = resolve_tool(executable_name, &layout.source_root)?;
    let projection = isolated_projection()?;
    let observed = ExecutableObservation::observe_at_path(
        &executable,
        argv.to_vec(),
        environment_projection_digest(&projection),
        Some(observed_tool_version(&executable, epoch)?),
    )
    .map_err(|error| CliError::Contract(format!("executable observation refused: {error}")))?;
    if !observed.is_complete() {
        return Err(CliError::Contract(format!(
            "executable {} observation is incomplete",
            executable.display()
        )));
    }
    let operation = operation_identity(stage_id, argv);
    let intent = ProcessIntent::new(
        OperationId::new(operation.clone())?,
        ProcessTreeId::new(format!("{operation}-tree"))?,
        JobId::new(format!("{operation}-job"))?,
        ImageId::new(format!("{operation}-image"))?,
        SessionId::new(format!("{EPOCH_LINEAGE}-{operation}"))?,
        Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
        executable.to_string_lossy().into_owned(),
        observed.content_digest.clone(),
        argv.to_vec(),
        layout.source_root.clone(),
        projection,
        ResourceLimits::new(
            STAGE_WALL_TIMEOUT_MS,
            None,
            None,
            STAGE_STDOUT_BYTES,
            STAGE_STDOUT_BYTES,
            STAGE_MAX_DESCENDANTS,
        )?,
    )?;
    let fence = FencingToken::new(
        epoch.clone(),
        Generation::new(VERIFICATION_REGISTRY_GENERATION)?,
        format!("{operation}-fence"),
    )?;
    let heads = BTreeMap::from([(
        "verification-profile".to_owned(),
        sha256_hex(format!("{stage_id}\0{operation}").as_bytes()),
    )]);
    let issued_at = now_unix_ms().max(1);
    cell.issue(
        &intent,
        fence,
        heads,
        issued_at,
        issued_at.saturating_add(STAGE_WALL_TIMEOUT_MS),
        ActionLeaseRef::new(format!("{operation}-lease"))?,
        format!("{operation}-nonce"),
    )
}

fn isolated_projection() -> Result<EnvironmentProjection, CliError> {
    let path = std::env::var(TOOLCHAIN_PATH_ENV).map_err(|error| {
        CliError::Contract(format!(
            "explicitly permitted toolchain environment is unavailable: {TOOLCHAIN_PATH_ENV} is unset ({error})"
        ))
    })?;
    Ok(EnvironmentProjection::new(
        BTreeMap::from([(TOOLCHAIN_PATH_ENV.to_owned(), path)]),
        Vec::new(),
        EnvironmentInheritance::None,
    )?)
}

impl InstrumentRequestPort for StagePort {
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError> {
        self.sealed
            .lock()
            .map_err(|_| RunnerError::Binding("sealed stage map poisoned".to_owned()))?
            .remove(invocation.request.request_id.as_str())
            .ok_or_else(|| {
                RunnerError::Binding(format!(
                    "no sealed request for invocation '{}'",
                    invocation.request.request_id.as_str()
                ))
            })
    }
}

impl StageLauncher for StageRoute {
    fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError> {
        let stage_id = stage.route.stage().stage_id.as_str();
        let target = format!(
            "worktree:{}",
            &sha256_hex(self.layout.source_root.as_bytes())[..16]
        );
        let request_id = operation_identity(stage_id, &stage_argv(stage));
        let invocation = InstrumentInvocation {
            request: RequestMetadata {
                request_id: RequestId::new(request_id).map_err(|error| {
                    RunnerError::Binding(format!("stage '{stage_id}' request refused: {error}"))
                })?,
                session_id: None,
                task_id: None,
                product_id: ProductId::new(ADMITTED_PRODUCT).map_err(|error| {
                    RunnerError::Binding(format!("stage '{stage_id}' product refused: {error}"))
                })?,
                source_id: SourceId::new(self.layout.source_root.clone()).map_err(|error| {
                    RunnerError::Binding(format!("stage '{stage_id}' source refused: {error}"))
                })?,
                state_fence: StateFence::new(
                    self.epoch.clone(),
                    ResourceGeneration::new(VERIFICATION_REGISTRY_GENERATION).map_err(|error| {
                        RunnerError::Binding(format!("stage '{stage_id}' fence refused: {error}"))
                    })?,
                ),
                clock: self.clock,
            },
            instrument: stage.stage.spec.clone(),
            kind: stage.stage.kind,
            profile: stage.route.stage().profile.clone(),
            target,
            arguments: Vec::new(),
            input_artifacts: Vec::new(),
            declared_scope: ADMITTED_SCOPE_CLASS.to_owned(),
            requested_at: self.clock,
        };
        invocation.validate().map_err(|error| {
            RunnerError::Binding(format!("stage '{stage_id}' invocation refused: {error}"))
        })?;
        Ok(invocation)
    }

    fn port(&self, _stage: &PlannedStage) -> &dyn InstrumentRequestPort {
        &self.port
    }

    fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
        Arc::clone(&self.port.sink) as Arc<dyn ProcessEvidenceSink>
    }
}

fn operation_identity(stage_id: &str, argv: &[String]) -> String {
    let material = format!("{stage_id}\0{}", argv.join("\u{1}"));
    format!(
        "verification-profile-stage-{}",
        &sha256_hex(material.as_bytes())[..24]
    )
}

#[derive(Default)]
struct RetainedEvidenceSink {
    records: Mutex<Vec<Vec<u8>>>,
}

impl ProcessEvidenceSink for RetainedEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let bytes = serde_json::to_vec(&evidence).map_err(|error| EvidenceSinkError {
            message: format!("retained evidence is not serializable: {error}"),
        })?;
        self.records
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "retained evidence sink lock poisoned".to_owned(),
            })?
            .push(bytes);
        Ok(())
    }
}

#[cfg(test)]
#[path = "eliot-profile-resolver/provider_registry_physical.rs"]
mod provider_registry_physical;
