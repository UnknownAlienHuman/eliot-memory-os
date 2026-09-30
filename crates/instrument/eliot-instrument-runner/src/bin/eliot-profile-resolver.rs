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
    PlannedStage, ProfileAggregate, ProfileCompiler, RunnerError, StageEnvironment, StageLauncher,
    StageOrchestrator, SupplyChainReceipt, TargetLayout, VerificationProfileReceipt,
    VerificationRouteRequest, WorkScope, admitted_profile_for_alias, parity_summary,
    profile::{PROFILE_ALIASES, builtin_specs},
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

/// Exit code for a resolved, receipt-issued route whose aggregate outcome is PASS.
///
/// The `0` / `1` split is the same operator contract `eliot-testd` and
/// `eliot-verifier-selfchange` use, so a caller can treat a nonzero exit as a
/// fail-closed refusal without reading the receipt to learn why.
const EXIT_PASS: i32 = 0;
/// Exit code for any fail-closed refusal, including a non-PASS aggregate.
const EXIT_REFUSED: i32 = 1;

/// Validation revision pinned into every stored dispatch validation context.
///
/// The one-shot context shape the `eliot-verifier-selfchange` bootstrap stores;
/// no other revision is ever admitted here.
const VALIDATION_REVISION: u64 = 1;

/// Registry generation the shared verification registry is admitted at.
///
/// The route profiles ship at revision 1, and a supply-chain receipt is validated
/// against the admitted spec digest at exactly the generation the registry is
/// assembled with, so one fixed generation keeps an attested receipt and its
/// registry bound together on either side of a parity comparison.
const VERIFICATION_REGISTRY_GENERATION: u64 = 1;

/// Authority epoch lineage of this one-shot resolution process.
///
/// P-07 fences every permit of this run under the epoch it is activated with.
/// The lineage names this process instance rather than a durable authority: the
/// run holds one ephemeral authority and revokes nothing.
const EPOCH_LINEAGE: &str = "eliot-verification-profile-resolver";

/// Product identity every stage invocation of this run belongs to.
const ADMITTED_PRODUCT: &str = "eliot";

/// Ceiling on retained stdout bytes for one admitted stage child.
///
/// Bounded structurally: `ResourceLimits::new` refuses a zero ceiling, so a
/// stage's evidence is bounded rather than unbounded, and the executor retains
/// at most this much per stream.
const STAGE_STDOUT_BYTES: u64 = 4 * 1024 * 1024;

/// Wall bound for one admitted stage child, in milliseconds.
const STAGE_WALL_TIMEOUT_MS: u64 = 3_600_000;

/// Ceiling on descendant processes for one admitted stage child.
const STAGE_MAX_DESCENDANTS: u32 = 256;

/// Ceiling on the retained bytes of one observed tool version line.
///
/// Bounded so a tool that answers `--version` with an unbounded stream cannot
/// turn the version read into unbounded retention. It is far above any real
/// tool's version line, so an ordinary version is recorded in full and only a
/// runaway read is refused.
const MAX_TOOL_VERSION_BYTES: usize = 4096;

/// Wall bound for the permit-bound `--version` observation child, in milliseconds.
///
/// A version read is a short bounded probe, not a stage: this is deliberately
/// far below [`STAGE_WALL_TIMEOUT_MS`] so a tool that hangs instead of answering
/// its version is refused here rather than holding a stage-sized launch open.
const VERSION_WALL_TIMEOUT_MS: u64 = 60_000;

/// Per-stream capture ceiling for the permit-bound `--version` observation child.
///
/// Set above [`MAX_TOOL_VERSION_BYTES`] so an ordinary version is captured whole
/// and still bounds what a runaway tool can write. Because the retained prefix
/// preview omits any suffix past this ceiling, `observed_tool_version` refuses a
/// read that hit it instead of reporting a truncated line as the version.
const VERSION_STDOUT_BYTES: u64 = 64 * 1024;

/// Ceiling on descendant processes for the permit-bound `--version` child.
///
/// A version read answers with a single line from the tool itself, so a wider
/// descendant tree than [`STAGE_MAX_DESCENDANTS`] is not a normal observation.
const VERSION_MAX_DESCENDANTS: u32 = 8;

/// Bound on waiting for the permit-bound `--version` child to settle.
///
/// Set equal to [`VERSION_WALL_TIMEOUT_MS`], the wall bound that child was
/// sealed with, because that deadline is what makes the wait finite: the
/// executor's own operation-bound deadline watcher terminates the version child
/// at it, so the view reaches a terminal lifecycle at or before this bound and
/// this constant invents no timing policy of its own. A child still not settled
/// at the bound is refused, never reported.
const VERSION_OBSERVE_TIMEOUT: Duration = Duration::from_millis(VERSION_WALL_TIMEOUT_MS);

/// Cadence for observing the permit-bound `--version` child's lifecycle.
///
/// Reused rather than introduced: the same 25ms bound is the executor's own
/// terminal-wait poll, and the same cadence the two existing production callers
/// of a real child already poll [`ProcessExecutor::inspect`] at — the
/// `RECONCILE_OBSERVE_POLL` of `wasm_p03_adapter.rs` and `BOUND_RUN_POLL` of
/// `eliot-git-bridge`.
const VERSION_OBSERVE_POLL: Duration = Duration::from_millis(25);

/// The exact invocation this binary reads.
struct Request {
    /// Closed profile alias naming the route to resolve.
    alias: String,
    /// Admitted source root; the stage working directory.
    source_root: PathBuf,
    /// Admitted external build target root.
    target_root: PathBuf,
    /// Admitted cache root.
    cache_root: PathBuf,
    /// Declared environment dependency names this run declares.
    declared_environments: Vec<String>,
    /// Caller-chosen receipt path, when the caller wants the receipt on disk.
    receipt_out: Option<PathBuf>,
    /// Caller-chosen counterpart receipt this run compares against, when the
    /// caller has one.
    compare_against: Option<PathBuf>,
}

/// Fail-closed refusals of the verification-route resolution entry.
#[derive(Debug)]
enum CliError {
    /// The invocation text is missing a required field or names an unknown one.
    Usage(String),
    /// A typed contract refused the composition, the resolution, or the receipt.
    Contract(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // One sentence for both variants on purpose: a caller reading stderr
        // learns the run was REFUSED, and the `detail` after the colon says
        // whether that was a malformed invocation or a typed contract refusal.
        // The variant is still distinct to `From`/matching callers, which is
        // where the two need to be told apart.
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
    // The comparison is part of this run's outcome, not a side report: when the
    // caller supplied a counterpart receipt, the shared parity owner decides
    // whether this run may proceed, and a refusal exits here.
    //
    // Ordering note, stated because it is load-bearing for the caller: this run's
    // OWN receipt has already been persisted by `resolve_route` (it writes
    // `--receipt-out` before returning), and it is retained on refusal on
    // purpose — the receipt is this run's admission evidence and records what was
    // actually observed, so destroying it would discard evidence of the very run
    // whose parity was refused. A parity refusal therefore still leaves a receipt
    // on disk alongside a nonzero exit, which is why `verify.ps1` discriminates
    // the two refusals on this entry's `PARITY_PASS`/`PARITY_NON_PASS` verdict
    // line rather than on the exit code or the receipt's existence.
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
    // A non-PASS normalized outcome stays a non-PASS exit: this entry reports
    // the run's real outcome and never rounds it up to a success.
    if receipt.outcome.is_pass() {
        EXIT_PASS
    } else {
        EXIT_REFUSED
    }
}

/// Requires this run's receipt and the caller's counterpart receipt to agree.
///
/// The comparison itself belongs to [`verify_profile_parity`]; this only reads
/// the counterpart artifact the caller named and routes its verdict. A run with
/// no `--compare-against` compares nothing — the counterpart receipt is the
/// caller's exactly as the receipt path is — and a caller that wants I18.21's
/// "local profile revision == CI profile revision" checked must therefore name
/// it. Deserialization is the only thing this adds: a receipt read off disk
/// bypassed every check in the issuance builder, and [`verify_profile_parity`]
/// already runs `VerificationProfileReceipt::validate()` on both sides, so
/// there is deliberately no second validation layer here.
///
/// # Errors
///
/// Returns a [`CliError::Contract`] refusal when the counterpart receipt cannot
/// be read, is not a `VerificationProfileReceipt`, is internally inconsistent,
/// or diverges from this run's receipt. Every one of those is a refusal that
/// becomes [`EXIT_REFUSED`] in [`run`], never a warning and never a run that
/// proceeds as if parity had held.
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

/// Resolves one aliased route end to end and issues its shared receipt.
fn resolve_route(request: &Request) -> Result<VerificationProfileReceipt, CliError> {
    let layout = TargetLayout::new(
        admitted_root(&request.source_root)?,
        admitted_root(&request.target_root)?,
        admitted_root(&request.cache_root)?,
    )?;
    // The registry is assembled here from the builtin verification routes plus
    // the supply-chain receipts this process observed, rather than supplied by
    // the caller, because the registry is what decides which revision an alias
    // admits and a caller-assembled registry could admit a different revision
    // than the one CI resolves. It is built through the SAME shared owner
    // `InstrumentRegistry::with_verification_route_profiles` that
    // `resolve_verification_route` builds for the receipt below, so the
    // admission this process performs on every stage and the admission the
    // receipt builder performs are the same definitions at the same generation
    // — the plan this process compiles therefore carries exactly the
    // registry generation and digest `launch_plan_live` checks before it
    // admits anything.
    let specs = builtin_specs()?;
    let receipts = observed_supply_chain(&specs)?;
    let registry = InstrumentRegistry::with_verification_route_profiles(
        VERIFICATION_REGISTRY_GENERATION,
        receipts.clone(),
    )?;

    // `admitted_profile_for_alias` is the same closed-table lookup
    // `resolve_verification_route` performs. It runs first so an alias the table
    // does not admit fails closed before any tool is launched, rather than
    // after a whole run of the wrong stage set.
    let route = admitted_profile_for_alias(&request.alias, &registry)?.clone();
    let compiler = ProfileCompiler::new(&registry);
    let admitted = compiler.compile_exact(&route.name, route.revision)?;

    let epoch = process_epoch()?;
    let clock = observation_clock(now_unix_ms());
    // The workscope fence carries the same epoch and the same registry
    // generation every stage launch is sealed under, so one run has exactly one
    // admitted generation: a receipt whose scope fence and whose stage fences
    // disagreed would name two generations for one run.
    let scope = WorkScope::new(
        ADMITTED_SCOPE_CLASS.to_owned(),
        StateFence::new(
            epoch.clone(),
            ResourceGeneration::new(VERIFICATION_REGISTRY_GENERATION)?,
        ),
    )?;
    // The attested environment material is the concrete fact this process
    // actually holds: the admitted worktree class, the environment class, the
    // admitted source root, the resolved alias, and the admitted profile
    // digest. It is recorded into the digest rather than sniffed from ambient
    // CI variables, so a CI-only difference is a difference in this material and
    // shows up as a different environment digest on both sides of a parity
    // comparison instead of as an invisible one.
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

    // Resolve the exact admitted revision against the same bindings the receipt
    // is built from, before a single stage launches, so a refused binding is a
    // refusal rather than a run whose receipt is later refused.
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
    // The live registry is REQUIRED here, not optional. `launch_plan_live`
    // first checks that this plan was compiled against exactly this registry's
    // generation and digest — and records every stage as an explicit missing
    // proof if it was not, so a plan from a replaced generation can never
    // launch under revoked admission. It then admits every stage through
    // `AdmittedStage::admit_live`, which runs `refuse_if_revoked` against that
    // live registry before sealing the grant, so a spec, parser, supply-chain
    // receipt, or route replaced since this run's compilation fails closed here
    // and the stage becomes a visible missing run rather than a child process.
    // The registry-free `run_profile_stages` walks the same plan but passes
    // `None` for the live registry, so it never performs either the
    // generation/digest binding or the per-stage revocation check. Passing that
    // registry in — the real one this run built from the observed supply-chain
    // receipts, at the same generation the receipt builder uses — is what makes
    // this resolver's stage admission a live admission rather than a walk over a
    // stale compiled one.
    let plan = StageOrchestrator::plan(&admitted);
    let runs = block_on(StageOrchestrator::launch_plan_live(
        &runner, &registry, &plan, &launcher,
    ));
    let aggregate = ProfileAggregate::assemble(&plan, runs);
    require_launched_stage(&admitted, &aggregate)?;

    // The same observed receipts travel into the receipt builder. It assembles
    // its own registry from them, so `require_provenance` compares each run's
    // recorded executable identity against the receipt that pins the real bytes
    // of the tool this process launched. A receipt that did not travel here
    // would leave every external stage with no admitted provenance, and the
    // builder would refuse the receipt — which is the fail-closed behaviour
    // I18.21:8 requires when the provenance data is absent.
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

/// Requires at least one admitted stage to have really launched.
///
/// A run in which no stage produced a run record would hand the receipt builder
/// an aggregate whose every stage is missing, and the only honest outcome of
/// that is a refusal: a receipt cannot record a tool identity for a tool that
/// never ran, so this entry fails closed instead of printing one. This is a
/// reachability guard on the receipt, not a verdict — the aggregate's own
/// normalized outcome still decides PASS.
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
        return Err(CliError::Contract(format!(
            "route '{}' revision {} launched no admitted stage; no tool identity was observed",
            admitted.name, admitted.revision
        )));
    }
    Ok(())
}

/// Pins every admitted external stage executable from the real bytes here.
///
/// I18.21 requires "executable/tool identities are pinned or recorded" and
/// "external binaries require digest/provenance receipt". The digest below is the
/// SHA-256 this process computed over the executable file the route will run, at
/// the admitted spec digest, for the admitted generation. That receipt is what
/// `require_provenance` compares the launch-recorded identity against, so a
/// swapped tool fails closed instead of being receipted under a declared
/// identity. An executable this process cannot read, or one that is not on
/// `PATH` at all, is refused here rather than admitted with no digest.
///
/// One receipt is pinned per admitted spec, keyed by the spec's own kind
/// identity — which is the key `SupplyChainTable` admits and `compile_exact`
/// looks a stage's receipt up by — so the receipt set can never collide on two
/// specs that happen to name the same executable.
fn observed_supply_chain(specs: &[InstrumentSpec]) -> Result<Vec<SupplyChainReceipt>, CliError> {
    specs
        .iter()
        .map(|spec| {
            let executable = resolve_tool(&spec.executable)?;
            Ok(SupplyChainReceipt::new(
                ContractId::new(spec.kind.as_str())?,
                spec.executable.clone(),
                file_digest(&executable)?,
                // No version is attested on this path, so none is claimed; a spec
                // that pinned a version still gates inside admission.
                None,
                spec.digest(),
                VERIFICATION_REGISTRY_GENERATION,
            )?)
        })
        .collect()
}

/// Requires one admitted root to be an existing, traversal-free absolute path.
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

/// Resolves one admitted executable name to its real path on this machine.
///
/// An admitted spec names a tool, not a path (`cargo`, `rustc`), so the bytes
/// are located through `PATH` and then canonicalized: the identity that gets
/// pinned and the identity that gets executed are the same resolved file. On
/// Windows a tool name without its extension resolves through the same
/// `PATHEXT` suffixes the shell uses, because the admitted name carries no
/// extension and the file on disk does.
fn resolve_tool(name: &str) -> Result<PathBuf, CliError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() || candidate.components().count() > 1 {
        return Err(CliError::Contract(format!(
            "admitted executable '{name}' must be a bare tool name resolved through PATH"
        )));
    }
    let path = std::env::var_os("PATH").ok_or_else(|| {
        CliError::Contract(format!(
            "admitted executable '{name}' cannot be located: PATH is unset"
        ))
    })?;
    let suffixes = executable_suffixes();
    for directory in std::env::split_paths(&path) {
        for suffix in &suffixes {
            let candidate = directory.join(format!("{name}{suffix}"));
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate).map_err(|error| {
                    CliError::Contract(format!(
                        "admitted executable {} is unavailable: {error}",
                        candidate.display()
                    ))
                });
            }
        }
    }
    Err(CliError::Contract(format!(
        "admitted executable '{name}' is not on PATH; an unpinned tool cannot be receipted"
    )))
}

/// The filename suffixes one bare tool name may resolve to on this host.
///
/// On a non-Windows host the name must already be complete, so only the empty
/// suffix is admitted; on Windows the shell's own `PATHEXT` list is used when
/// the host publishes it, so the file this entry pins and executes is the file
/// the tool invocation would run. `PATHEXT` is a semicolon-separated list of
/// bare suffixes rather than a path list, so it is split on `;` directly.
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

/// The SHA-256 over the exact bytes of one file on this machine.
fn file_digest(path: &Path) -> Result<String, CliError> {
    let bytes = std::fs::read(path).map_err(|error| {
        CliError::Contract(format!(
            "executable {} is unreadable: {error}",
            path.display()
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

/// The `--version` child through this ONE executor, bounded-poll until it settles.
///
/// `ProcessExecutor::reconcile` is TERMINAL-ONLY: `reconcile_inner` calls
/// `join_streams` unconditionally (`eliot-process-executor/src/lib.rs`), which
/// cancels the still-running capture thread's IO and can therefore quarantine
/// this operation. `start` returns at child-CREATE, so the version child is
/// still driving when the very next call lands — calling `reconcile` there is
/// destructive, not merely early. So this wait observes the child the way the
/// two existing production callers of a real child already do: bounded-poll the
/// NON-DESTRUCTIVE `inspect` view of THIS operation on the executor that
/// recorded the `start`, then perform the single terminal `reconcile`. Nothing
/// here launches, cancels, re-permits, or retries anything, and the existing
/// operation registry is the only state involved.
///
/// The bound is [`VERSION_OBSERVE_TIMEOUT`] and the cadence is
/// [`VERSION_OBSERVE_POLL`]; both are justified on their constants. This returns
/// only a TERMINAL view — the refusal is its own return type, so no caller can
/// read an exit observation off a child that has not finished.
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

/// Observes one tool's reported version by really running that tool.
///
/// `ExecutableObservation::is_complete` refuses an identity that carries no
/// tool version, so the version is a required datum here rather than an
/// optional decoration: I18.21 requires that "executable/tool identities are
/// pinned or recorded", and a version nobody read is neither. The text is
/// whatever the tool itself printed on its own `--version` invocation, bounded
/// to the first non-empty line and to [`MAX_TOOL_VERSION_BYTES`]; a tool that
/// does not exit normally, prints nothing, or overruns that bound is refused
/// rather than receipted under a synthesized value, because a wrong version is a
/// pinned identity that does not describe the bytes it is bound to.
///
/// The `--version` child is a real launch and crosses the same physical
/// process boundary every other launch in this entry does: it is sealed with
/// its own one-shot P-07 dispatch permit by [`seal_version_request`] and started
/// through the sole [`WindowsProcessExecutor`], so I10.8.2's single-executor
/// rule holds for the version read exactly as it does for an admitted stage.
/// Reading the tool's version is observation, not a verdict: this runs before
/// any stage and derives nothing about the route's outcome, so it stays separate
/// from the admitted stage launch in [`seal_stage_request`]. What the governed
/// path adds is that the text it returns is the stdout this process's own
/// executor really captured under a Kernel-validated permit, not bytes an
/// ungoverned child wrote.
fn observed_tool_version(executable: &Path, epoch: &EpochId) -> Result<String, CliError> {
    // The read gets its own `DispatchCell` because a P-07 dispatch permit is
    // one-shot: the `--version` child is a distinct launch from the stage that
    // follows it, so it can never consume the stage's permit or its stored
    // validation context. It is still the same authority composition, the same
    // epoch, and the same generation, so this run has exactly one epoch.
    let cell = Arc::new(DispatchCell::activate()?);
    // ONE executor for the whole lifecycle of this read. Its registry is an
    // instance field, so the `inspect` below must cross the same instance the
    // `start` registered on; a second executor would read an empty registry and
    // refuse `NotFound`, which says nothing about the operation.
    let executor = StageExecutor::with(&cell);
    let request = seal_version_request(&cell, epoch, executable)?;
    let receipt = block_on(executor.start(
        request,
        Arc::new(RetainedEvidenceSink::default()) as Arc<dyn ProcessEvidenceSink>,
    ))?;
    // Settle first, then read the exit, then reconcile: the exit observation is
    // only meaningful once the tree is closed, and the reconcile is the single
    // terminal call the poll above was waiting to make safe.
    let view = await_terminal_view(executor.executor(), receipt.operation_id(), executable)?;
    // `ExitDisposition::Completed` is the executor's own observed terminal
    // classification, so this is the governed equivalent of the old
    // `output.status.success()` test: a signalled, resource-limited, cancelled,
    // or unclassifiable tree is refused here exactly as a nonzero exit was.
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
    // The version text is the stdout this executor really captured for that
    // exact permit-bound operation, read back out of the reconciled evidence's
    // bounded prefix preview. The preview is the transport-level prefix, so a
    // version line longer than the retained bound is still refused below rather
    // than silently truncated into a shorter "version".
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

/// Seals the one-shot permit-bound request for the `--version` observation read.
///
/// This is deliberately the same P-07 composition [`seal_stage_request`] uses —
/// the same [`ProcessIntent`] fields, the same isolated [`isolated_projection`],
/// the same fenced epoch and registry generation, and the same
/// [`DispatchCell::issue`] one-shot issuance — so the read is a governed launch
/// of the same kind the stage is, and the I10.8.2 single-executor rule covers it
/// without exception. It differs only in what is being launched: the tool's own
/// `--version` argv against the pinned executable, observed in the directory
/// [`resolve_tool`] resolved it in, so a stage's working directory cannot change
/// which bytes answer.
fn seal_version_request(
    cell: &DispatchCell,
    epoch: &EpochId,
    executable: &Path,
) -> Result<ProcessRequest, CliError> {
    let projection = isolated_projection(&[])?;
    let argv = vec!["--version".to_owned()];
    // The operation identity is derived from the same real tool bytes the stage
    // launch pins, so the read and the stage it precedes are bound to one
    // concrete executable rather than to a name that could resolve elsewhere.
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
        // The tool's own resolved parent, not the admitted source root: this
        // observes the tool where `resolve_tool` pinned it.
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

/// Reads the exact invocation text this binary accepts.
///
/// Every field is required and none is defaulted: a missing root, a missing
/// alias, or an unknown option is a refusal rather than a substituted value.
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

/// The closed alias names, for the usage refusal only.
fn aliases() -> String {
    PROFILE_ALIASES
        .iter()
        .map(|entry| entry.alias)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Drives one already-resolved future on the calling thread.
///
/// The stage launches are synchronous under the sole Windows executor, so this
/// binary needs no async runtime; the driver pumps the one future it owns and
/// never sleeps, retries, or performs I/O of its own.
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

/// The canonical one-shot authority epoch of this resolution process.
///
/// `EpochLineageId` is a closed contract: `new` accepts exactly a 36-character
/// canonical lowercase hyphenated UUID and refuses anything else, so the lineage
/// is DERIVED into that shape rather than assembled from readable text. A
/// `"{name}-{pid}-{nanos}"` string is a readable label, not a lineage, and is
/// refused on every run — so the identity is minted in the spelling the contract
/// actually validates instead of one that reads nicely and never works.
///
/// `EPOCH_LINEAGE` names what this process is, and `SessionId` below carries it
/// where a human-readable product identity belongs; the epoch itself is a
/// derived UUID because that is the only shape its owner accepts.
///
/// Uniqueness is what the one-shot fence needs: the epoch never leaves this
/// process and the run revokes nothing, so per-process key bytes plus the
/// process id and clock reading are sufficient and no durability is implied.
fn process_epoch() -> Result<EpochId, CliError> {
    let mut material = fresh_key_bytes();
    // Fold this process's own identity into the material so two resolutions
    // that happened to draw the same bytes are still distinct. Each source is
    // zero-extended into its own 8-byte lane, so the copy lengths match the
    // destination exactly rather than panicking at runtime.
    material[..8].copy_from_slice(&u64::from(std::process::id()).to_le_bytes());
    material[8..16].copy_from_slice(&system_nanos().to_le_bytes());
    let mut lineage = String::with_capacity(36);
    for (index, byte) in material.iter().take(16).enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            lineage.push('-');
        }
        // `write!` into the same String rather than appending a `format!` result:
        // one formatting call, no intermediate allocation, and no way for the
        // formatted hex to differ from what was pushed.
        write!(lineage, "{byte:02x}")
            .map_err(|_| CliError::Contract("epoch lineage is not formattable".to_owned()))?;
    }
    let lineage = EpochLineageId::new(lineage)?;
    let sequence = NonZeroU64::new(1)
        .ok_or_else(|| CliError::Contract("epoch sequence is not one".to_owned()))?;
    Ok(EpochId::new(lineage, sequence)?)
}

/// Machine clock reading in Unix milliseconds, observed now.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Derives a process-unique nanosecond reading.
fn system_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Builds one clock observation from an observed millisecond reading.
///
/// The `ClockReading` field is a signed millisecond count, so a reading beyond
/// `i64::MAX` cannot be represented and is clamped to the maximum rather than
/// wrapping into a negative instant. `cast_unsigned` states the intended
/// conversion: the ceiling is a positive constant, so the sign is not lost here.
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

/// Generates fresh per-process key bytes without adding a randomness dependency.
///
/// Per-process uniqueness, not unpredictability, is what the one-shot replay
/// fence needs: the key never leaves this process, is never persisted, and binds
/// only permits this authority instance issued.
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

/// The single dispatch-authority cell every stage of one run seals under.
///
/// The cell issues one permit per admitted stage and stores the validation
/// context those permits are consumed against. Every stage of a run shares the
/// same authority epoch and generation, so the one stored context validates
/// every permit the cell issued, while the per-stage one-shot nonce keeps each
/// permit independently single-use.
struct DispatchCell {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl DispatchCell {
    /// Activates one ephemeral authority around fresh in-memory key material.
    fn activate() -> Result<Self, CliError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id =
            DispatchAuthorityId::new(format!("profile-resolver-dispatch-{pid}-{nanos}"))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one admitted stage.
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
        // The heads are cloned out BEFORE the issuance consumes them, and the
        // validation context is built from that clone. This is the same value
        // the permit was issued with, not a second source: the authority builds
        // the permit from this exact `PermitIssuance` and re-proves the two
        // against each other at consume time. `DispatchPermit` exposes no reader
        // for its heads (that is deliberate — it is dispatch authority material),
        // so the run context is pinned from the issuance the authority consumed.
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
        // The stored context pins the exact material the permit was issued
        // with — the same fence, its own authority epoch, and the same revision
        // heads — so consume-time validation compares the permit against this
        // snapshot rather than against ambient state.
        let context_epoch = fence.authority_epoch().clone();
        let context = DispatchValidationContext::new(
            observation_clock(issued_at_unix_ms),
            fence,
            context_epoch,
            pinned_heads,
            VALIDATION_REVISION,
        )?;
        *self
            .context
            .lock()
            .map_err(|_| CliError::Contract("validation context lock poisoned".to_owned()))? =
            Some(context);
        Ok(ProcessRequest::new(intent.clone(), permit)?)
    }

    /// The stored validation context the executor consumes every permit against.
    fn context(&self) -> Result<DispatchValidationContext, ProcessExecutionError> {
        self.context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("validation context poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("validation context absent".to_owned())
            })
    }
}

impl DispatchValidationPort for DispatchCell {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let context = self.context()?;
        self.authority
            .lock()
            .map_err(|_| ProcessExecutionError::Unavailable("authority lock poisoned".to_owned()))?
            .validate_and_consume(request, observed, &context)
            .map_err(ProcessExecutionError::from)
    }
}

/// The physical process boundary every admitted stage of this run crosses.
///
/// Each stage really starts a child through the sole [`WindowsProcessExecutor`]
/// under this run's own dispatch cell, so the identity the receipt records for
/// that stage is the identity of bytes this process actually executed.
///
/// The permit-bound `--version` read uses this same owner over its own cell, so
/// every child this entry starts — the version probes and the stages alike —
/// crosses the one executor composition below.
struct StageExecutor {
    /// The ONE physical executor every lifecycle call of this owner crosses.
    ///
    /// `WindowsProcessExecutor` owns the operation registry as an instance
    /// field, so the registry that records a `start` must be the same instance
    /// a later `inspect`, `cancel` or `reconcile` reads. Constructing one per
    /// call discards the registration with the temporary, and the follow-up
    /// call is then refused as `NotFound` against an empty registry — which is
    /// a true statement about the wrong executor, not about the operation.
    ///
    /// The cell reaches this owner through this one field: the executor holds
    /// the `Arc<dyn DispatchValidationPort>` built from it, so the port the
    /// executor validates against and the cell this owner's caller sealed its
    /// one-shot permits under are the same value.
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

    /// The P-07 authority composition every lifecycle call crosses.
    ///
    /// Borrowed by [`await_terminal_view`] so the version probe's bounded
    /// inspect-poll observes THIS executor's registry — the one the `start`
    /// registered on — rather than a second executor that never saw the child.
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

/// The [`StageLauncher`] that turns one admitted profile plan into launches.
///
/// Nothing here restates a command list. The executable, the argv, the working
/// directory, the instrument contract, and the stage kind all come from the
/// admitted plan the shared resolver produced, so a stage this launcher runs is
/// exactly a stage the shared resolver admitted and no other.
struct StageRoute {
    /// Authority epoch every permit of this run is sealed under.
    epoch: EpochId,
    /// Observed admission instant carried by every stage invocation.
    clock: ClockReading,
    /// Admitted layout the stage working directory comes from.
    layout: TargetLayout,
    /// Admitted stage launch provisions the orchestrator binds each stage
    /// through: the per-stage permit source, the evidence sink, and the exact
    /// sealed request already issued for the stage being launched.
    ///
    /// The sealed request is stored per stage rather than derived inside
    /// `bind` because a dispatch permit is one-shot and the orchestrator asks
    /// for the port before it knows which stage it is binding. [`StageRoute`]
    /// seals one request per planned stage up front, in admitted plan order, so
    /// the port hands each stage the request that was sealed for it and refuses
    /// a bind for any other stage.
    port: StagePort,
}

/// The per-stage launch provisions the orchestrator binds one stage through.
///
/// The sealed requests are keyed by the exact durable stage identity the
/// orchestrator walks, so a bind for a stage this run never sealed fails closed
/// instead of producing a request for whatever stage happens to come next.
struct StagePort {
    /// One sealed, permit-bound request per admitted stage identity.
    ///
    /// Behind a mutex because `bind` takes `&self` (the port is shared) and
    /// because removing the slot is what enforces one seal per stage.
    sealed: std::sync::Mutex<BTreeMap<String, ProcessRequest>>,
    /// Evidence sink every stage launch retains through.
    sink: Arc<RetainedEvidenceSink>,
}

impl StagePort {
    /// Seals one permit-bound request for every stage of the admitted plan.
    ///
    /// Sealing is a per-stage operation because the P-07 dispatch permit is
    /// one-shot: one permit can never launch two children. Each stage's request
    /// is bound to its own one-shot nonce and its own sealed intent, and the
    /// shared run context validates all of them because they carry the same
    /// authority epoch and generation.
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
                &planned.stage.allowed_environment,
            )?;
            sealed.insert(operation, request);
        }
        Ok(Self {
            sealed: std::sync::Mutex::new(sealed),
            sink: Arc::new(RetainedEvidenceSink::default()),
        })
    }
}

/// The exact process argv one admitted stage runs.
///
/// It is built from the admitted spec's own argument template and nothing else,
/// so the argv is profile text read from the admitted registry, not a command
/// list restated here. Every builtin verification spec declares the real
/// argument template its owning adapter runs in production, so a stage runs
/// `cargo metadata --locked --no-deps --format-version 1`,
/// `rustc --print=sysroot --error-format=json`, the nextest
/// `run --message-format libtest-json-plus …` invocation, or
/// `cargo fmt --all -- --check`, rather than its executable with no arguments
/// at all.
///
/// No template is empty, `--help`, or `--version`, and none ever may be: a tool
/// that prints its banner or version has performed no verification, and its
/// own output would then be the only thing in the receipt standing in for the
/// work the stage was declared to do. The builtin templates this route runs are
/// non-empty by construction, so no stage of either admitted route reaches
/// `require_launched_stage` with nothing to execute.
fn stage_argv(stage: &PlannedStage) -> Vec<String> {
    stage.stage.argument_template.clone()
}

/// Seals the one permit-bound process request for one admitted stage.
///
/// The executable is the one the admitted spec names, resolved to the real file
/// on this machine, and the digest bound into the sealed intent is the SHA-256
/// the executor computed over that file's bytes — the same observation
/// `ExecutableObservation::observe_from_intent` re-derives at launch. The request
/// is therefore the one the admitted stage runs, and a tool swapped between
/// sealing and launch fails the executor's own observation check.
///
/// The tool version is observed by really running the tool's own version flag
/// through [`observed_tool_version`] and keeping the first line that launch
/// printed. A complete identity requires a non-empty version (`is_complete`
/// refuses an observation without one), and no version is invented from the file
/// name: a tool that cannot report one is refused here rather than receipted with
/// a placeholder. That read is itself a governed launch under its own one-shot
/// permit, so both children this function causes to exist — the `--version` probe
/// and the stage itself — cross the single [`WindowsProcessExecutor`] boundary.
fn seal_stage_request(
    cell: &DispatchCell,
    epoch: &EpochId,
    layout: &TargetLayout,
    stage_id: &str,
    executable_name: &str,
    argv: &[String],
    allowed_environment: &[String],
) -> Result<ProcessRequest, CliError> {
    let executable = resolve_tool(executable_name)?;
    let projection = isolated_projection(allowed_environment)?;
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

/// The isolated environment projection one admitted stage child runs under.
///
/// The projection carries exactly the variables the admitted spec permits,
/// resolved from this process's own environment and never inherited wholesale,
/// under `EnvironmentInheritance::None`. The admitted builtin environment is
/// the empty set (`BUILTIN_ALLOWED_ENVIRONMENT`), which is the same isolated
/// class every builtin spec declares together with its isolated credential and
/// network policies: the child receives no ambient variable and no inherited
/// secret, and the digest of that projection is what the executor binds as the
/// stage's environment identity.
///
/// "Allowed" is therefore the spec owner's [`InstrumentSpec::allowed_environment`]
/// list, not a judgement about what a tool might tolerate and not the ambient
/// environment. A verification tool that needs a variable is admitted by a spec
/// revision that names it, and only then does this function copy that one value
/// across; a variable nobody admitted can never reach the child.
fn isolated_projection(
    allowed: &[String],
) -> Result<EnvironmentProjection, CliError> {
    let mut variables = BTreeMap::new();
    for name in allowed {
        let value = std::env::var(name).map_err(|_| {
            CliError::Contract(format!(
                "stage environment admits '{name}' but this process does not define it"
            ))
        })?;
        variables.insert(name.clone(), value);
    }
    Ok(EnvironmentProjection::new(
        variables,
        Vec::new(),
        EnvironmentInheritance::None,
    )?)
}

impl InstrumentRequestPort for StagePort {
    /// Hands the stage the exact request this run sealed for it.
    ///
    /// The lookup key is the invocation's own request id, which is derived from
    /// the admitted stage identity and the admitted argv, so a bind names the
    /// stage it is for rather than consuming requests in plan order: a bind for
    /// a stage this run never sealed finds nothing and is refused.
    ///
    /// The sealed slot is TAKEN, not copied. `ProcessRequest` deliberately does
    /// not implement `Clone`: it holds the one-shot P-07 dispatch permit, so a
    /// second bind for the same stage must fail here rather than hand the same
    /// permit to a second child. Consuming the slot is what makes a
    /// one-seal-per-stage run structural instead of a convention the caller has
    /// to remember.
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
        let request_id = operation_identity(stage_id, &stage.stage.argument_template);
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
            // Instrument-level arguments are never argv: the process argv comes
            // from the admitted argument template in `seal`, so a stage cannot
            // smuggle a command through this field.
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
        // Every stage binds through the one port this run sealed against. The
        // port keys its sealed requests by the admitted operation identity, so
        // handing the same port to every stage cannot make one stage's permit
        // launch another stage's child: the request each stage receives is the
        // one sealed for that stage's own admitted identity.
        &self.port
    }

    fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
        // One sink for the whole run, so every stage's retained records land in
        // the same evidence store rather than in a per-stage buffer that would
        // be dropped as soon as the stage returned.
        Arc::clone(&self.port.sink) as Arc<dyn ProcessEvidenceSink>
    }
}

/// The stable operation identity bound to one admitted stage and its argv.
///
/// Both the sealed request's operation id and the stage invocation's request id
/// derive from it, which is what lets the request port hand each stage the exact
/// request sealed for it. It names the admitted stage and the admitted argv, so
/// two stages of the same profile never collide and a changed argument template
/// changes the identity.
fn operation_identity(stage_id: &str, argv: &[String]) -> String {
    let material = format!("{stage_id}\0{}", argv.join("\u{1}"));
    format!(
        "verification-profile-stage-{}",
        &sha256_hex(material.as_bytes())[..24]
    )
}

/// Process-owned sink that retains every record the process owner publishes.
///
/// The sink holds the executor's own evidence records for the whole run: a
/// record the process owner published is evidence of what the stage actually
/// did, and dropping it would mean the run retained evidence it then discarded.
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
