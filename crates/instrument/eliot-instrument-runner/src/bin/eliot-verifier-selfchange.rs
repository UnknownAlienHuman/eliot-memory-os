//! Production entry point for an I18.31 verification-surface self-change.
//!
//! A changed verifier cannot be the sole authority proving its own
//! correctness, so this binary is the one place where a verification-surface
//! generation actually crosses the asymmetric bootstrap. It reads the recorded
//! bootstrap evidence for the changed surface, drives the real
//! [`SelfChangeBootstrap`] through its five phases, dispatches the surface's
//! I18.31 special case through [`eliot_verifier::SpecialCase::verify`], and
//! only after the machine mints the real [`GenerationReceipt`] does it admit
//! the instrument launch through
//! [`InstrumentRunner::launch_verified_with_bootstrap`] (runner surface) or
//! report the cutover receipt (every other surface).
//!
//! Every phase is backed by a real process on this machine: the last-known-good
//! pass, the candidate shadow pass, and the bounded canary all cross the sole
//! [`WindowsProcessExecutor`], and the post-cutover launch crosses it exactly
//! once through the bootstrapped runner. No phase is asserted, no digest is
//! fabricated, and the receipt cannot be hand-built
//! ([`GenerationReceipt`] fields are private). A surface whose special-case
//! evidence does not verify fails closed before any launch, and the protocol
//! binds only the admitted surface, so an unrelated module is never dragged
//! through a full release cycle.
//!
//! Value discipline: nothing compositional is hardcoded. The recorded bundle
//! carries the authority epoch, dispatch generation, permit expiry, session,
//! normative pair, the unchanged external discriminator, the candidate
//! generation's own discriminator, child limits, and launch identities; the
//! machine clock, executable bytes, process observations, and per-process
//! authority material are observed; everything else is derived from those two.
//! The per-process dispatch authority id, wall clock readings, and fresh key
//! bytes follow the `eliot-testd` composition-root pattern; the permit window
//! follows its issue/consume shape with the bundle standing in for the grant.

#![forbid(unsafe_code)]
// The cutover report on stdout and its fail-closed refusal on stderr are this
// entry point's operator-facing contract, the same reason `bins/eliot` and
// `bins/eliot-testd` carry it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence, sha256_hex,
};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_instrument_runner::{
    InstrumentRequestPort, InstrumentRunner, ProviderRegistry, ResolvedExecutableIdentity,
    RunnerError,
    registry::{InvalidationSet, RegistryFreshness},
};
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, ExitDisposition, ExitStatus,
    FencingToken, Generation, ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessRequest, ProcessStreamEvidence, ProcessTreeId,
    ResourceLimits, SessionId, StreamEvaluationStatus, StreamEvidenceGap, StreamParsingStatus,
    StreamPersistenceStatus, StreamTransportStatus, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{
    DispatchValidationPort, ExecutableObservation, WindowsProcessExecutor,
    environment_projection_digest,
    outer_guardian::{
        GuardianEvidence, GuardianTreeState, OuterGuardianScenario, verify_outer_guardian,
    },
};
use eliot_verifier::{
    AxisVerdicts, CanaryRecord, ComparisonAxis, EvidenceDigest, GenerationReceipt,
    OracleResolution, OuterGuardianRecord, SelfChangeBootstrap, SelfChangeError, SelfChangeSurface,
    ShadowComparisonRecord, SpecialCase, SpecialCaseEvidence, VerificationDecision,
    verdict_with_bootstrap,
};

/// Exit code for a completed cutover plus its bootstrapped launch or report.
///
/// Follows the `eliot-testd` operator contract: `0` completed, `1` refused, `4`
/// reconcile-required.
const EXIT_CUTOVER: i32 = 0;
/// Exit code for any failed-closed gate before or during cutover.
const EXIT_REFUSED: i32 = 1;
/// Exit code for a committed launch whose terminal state needs reconciliation.
const EXIT_RECONCILE_REQUIRED: i32 = 4;

/// Validation revision pinned into every stored dispatch validation context.
///
/// The one-shot context this run stores pins revision 1, exactly like the
/// `eliot-testd` dispatch authority; no other revision is ever admitted here.
const VALIDATION_REVISION: u64 = 1;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let mut args = std::env::args().skip(1);
    let Some(bundle) = args.next().map(PathBuf::from) else {
        eprintln!("usage: eliot-verifier-selfchange <bootstrap-evidence.json>");
        return EXIT_REFUSED;
    };
    match drive_self_change(&bundle) {
        Ok(report) => {
            println!("{report}");
            EXIT_CUTOVER
        }
        Err(CliError::ReconcileRequired) => EXIT_RECONCILE_REQUIRED,
        Err(error) => {
            eprintln!("{error}");
            EXIT_REFUSED
        }
    }
}

/// The recorded evidence one verification-surface self-change run reads.
///
/// Every composition value arrives here: nothing below is defaulted, and every
/// path is absolute. Machine-observed values (clock, executable bytes, process
/// outcomes, per-process authority material) are never recorded; they are
/// observed at run time and bound against this record.
struct BootstrapEvidence {
    /// The changed verification/control surface, and nothing else (I18.31 W5).
    surface: SelfChangeSurface,
    /// The retired generation.
    old_generation: u64,
    /// The candidate generation, which must advance past the old one.
    candidate_generation: u64,
    /// The canonical authority epoch every permit of this run is sealed under.
    authority_epoch: EpochId,
    /// The P-07 fence generation sealing the harness discriminator children.
    dispatch_generation: Generation,
    /// Unix millisecond at which this run's dispatch permits expire. The issue
    /// instant is observed from the machine clock; the contour refuses a
    /// window that does not cover the run.
    permit_expires_at_unix_ms: u64,
    /// Durable execution session identity for this self-change run.
    session: String,
    /// Normative-pair digest the admitted registry is assembled against.
    normative_pair: String,
    /// Bounded resource envelope admitted for every child of this run.
    limits: ChildLimits,
    /// Evidence for the admitted surface's special case, when it requires one.
    special_case: Option<SpecialCaseEvidence>,
    /// The outer Host/OS guardian scenario this entry re-verifies from the
    /// machine before a `ProcessExecutor` self-change is admitted. The typed
    /// `ExecutorOuterGuardian` arm below requires it, so an executor-surface
    /// change can never reach cutover without a real scenario run.
    outer_guardian_scenario: Option<GuardianScenarioRecord>,
    /// The unchanged external discriminator, run for real on this machine by
    /// the last-known-good pass and the canary.
    discriminator: DiscriminatorCommand,
    /// The candidate generation's own discriminator executable, run for real
    /// on this machine by the shadow pass alone. It is what makes the
    /// comparison a changed implementation against the last-known-good one
    /// instead of one implementation compared with itself.
    candidate_discriminator: DiscriminatorCommand,
    /// The instrument launch admitted only under the freshly minted receipt.
    launch: LaunchCommand,
    /// The finish-gate run whose verdict the same receipt must also cover.
    finish: Option<FinishGate>,
}

/// Bounded resource envelope admitted for one self-change run's children.
///
/// Recorded by the operator, enforced by the [`ResourceLimits`] contour: a
/// zero wall timeout or stream ceiling fails closed at seal time.
struct ChildLimits {
    /// Wall bound for one admitted discriminator or launch child.
    wall_timeout_ms: u64,
    /// Retained stdout ceiling for one admitted child.
    stdout_bytes: u64,
    /// Retained stderr ceiling for one admitted child.
    stderr_bytes: u64,
    /// Descendant ceiling for one admitted child.
    max_descendants: u32,
}

/// The outer Host/OS guardian scenario a `ProcessExecutor` self-change runs.
///
/// This is the recorded scenario the machine-side
/// [`verify_outer_guardian`] re-checks from this process: it re-hashes the exact
/// presented evidence bytes and requires the scenario worktree to be absent or
/// emptied. Only the resulting observed tree state is handed to the typed
/// `OuterGuardianRecord`, so the verifier-side re-check below never trusts a
/// cleanup claim this run did not observe itself.
struct GuardianScenarioRecord {
    /// The scenario worktree root the guardian inspects for cleanup.
    worktree_root: PathBuf,
    /// The exact scenario evidence bytes the guardian re-hashes.
    evidence: String,
    /// The expected evidence digest the recomputed value must equal.
    expected_evidence: EvidenceDigest,
}

/// One real child process the bootstrap genuinely runs on this machine.
#[derive(Clone, Debug)]
struct DiscriminatorCommand {
    /// Absolute path to the executable. Its bytes are hashed from the machine
    /// and sealed into both the observation and the process request.
    executable: PathBuf,
    /// Exact process argv, bound argv to argv on the request and observation.
    argv: Vec<String>,
    /// Absolute working directory for the child.
    working_directory: PathBuf,
}

/// The instrument launch admitted only after a successful cutover.
#[derive(Clone, Debug)]
struct LaunchCommand {
    /// Registered instrument contract the admitted invocation carries.
    instrument: String,
    /// Product identity the admitted invocation belongs to.
    product: String,
    /// Source identity of the candidate under test.
    source: String,
    /// Registry profile text carried on the admitted invocation.
    profile: String,
    /// Invocation arguments; instrument-level filters, never argv.
    arguments: Vec<String>,
    /// Declared candidate scope of the admitted invocation.
    declared_scope: String,
    /// The candidate/worktree identity the launch binds to.
    target: String,
    /// The instrument kind the admitted invocation carries.
    kind: InstrumentKind,
    /// Absolute path to the launched executable, hashed from the machine.
    executable: PathBuf,
    /// Exact process argv for the admitted launch.
    argv: Vec<String>,
    /// Absolute working directory for the admitted launch.
    working_directory: PathBuf,
}

/// The finish-gate run whose verdict the same receipt must also cover.
#[derive(Debug)]
struct FinishGate {
    /// The planned verification run decided under the receipt.
    plan: eliot_verifier::VerifierPlan,
    /// The executed verification run decided under the receipt.
    run: eliot_verifier::VerificationRun,
}

/// Fail-closed refusals of the self-change cutover entry.
#[derive(Debug)]
enum CliError {
    /// The evidence bundle could not be read or is not a valid record.
    Bundle(String),
    /// A typed contract refused the composition or the bootstrap itself.
    Contract(String),
    /// The launch reached no terminal state inside its admitted deadline.
    ReconcileRequired,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bundle(detail) => write!(f, "bootstrap evidence refused: {detail}"),
            Self::Contract(detail) => write!(f, "self-change cutover refused: {detail}"),
            Self::ReconcileRequired => {
                write!(
                    f,
                    "cutover launch requires reconciliation on the process owner"
                )
            }
        }
    }
}

impl From<SelfChangeError> for CliError {
    fn from(error: SelfChangeError) -> Self {
        Self::Contract(error.to_string())
    }
}

impl From<RunnerError> for CliError {
    fn from(error: RunnerError) -> Self {
        Self::Contract(format!("instrument launch refused: {error}"))
    }
}

impl From<ProcessExecutionError> for CliError {
    fn from(error: ProcessExecutionError) -> Self {
        Self::Contract(format!("process boundary refused: {error}"))
    }
}

impl From<eliot_process::ContractError> for CliError {
    fn from(error: eliot_process::ContractError) -> Self {
        Self::Contract(format!("process contract refused: {error}"))
    }
}

impl From<eliot_instrument_runner::RegistryError> for CliError {
    fn from(error: eliot_instrument_runner::RegistryError) -> Self {
        Self::Contract(format!("provider registry refused: {error}"))
    }
}

impl From<eliot_contracts::EpochContractError> for CliError {
    fn from(error: eliot_contracts::EpochContractError) -> Self {
        Self::Contract(format!("epoch identity refused: {error}"))
    }
}

impl From<eliot_contracts::ContractError> for CliError {
    fn from(error: eliot_contracts::ContractError) -> Self {
        Self::Contract(format!("contract identity refused: {error}"))
    }
}

impl From<eliot_instrument_api::InstrumentContractError> for CliError {
    fn from(error: eliot_instrument_api::InstrumentContractError) -> Self {
        Self::Contract(format!("instrument admission refused: {error}"))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(error: serde_json::Error) -> Self {
        Self::Contract(format!("recorded evidence is not canonical: {error}"))
    }
}

/// Drives the whole asymmetric bootstrap for one verification-surface change.
fn drive_self_change(bundle: &Path) -> Result<String, CliError> {
    let evidence: BootstrapEvidence = read_bundle(bundle)?;
    let admission = HarnessAdmission {
        epoch: &evidence.authority_epoch,
        dispatch_generation: evidence.dispatch_generation,
        permit_expires_at_unix_ms: evidence.permit_expires_at_unix_ms,
        session: evidence.session.as_str(),
        limits: &evidence.limits,
    };

    // Phases 1 and 2 are produced by real runs on this machine, never by a
    // recorded claim: the unchanged external discriminator runs over the
    // identical command first as the last-known-good pass, then the recorded
    // candidate generation's own discriminator runs as the shadow pass over
    // the same raw tool evidence. The two sides are two different
    // implementations, so the five-axis comparison is exactly the raw capture,
    // normalized meaning, selection, omissions, and outcome checks I18.31
    // requires before a cutover, and a candidate that normalizes differently
    // from the last-known-good one diverges for real. The passes are NOT
    // required to produce equal whole-run digests: each pass activates its own
    // one-shot dispatch authority, so the run's own evidence digest
    // legitimately differs between them, and that per-activation permit
    // identity is deliberately excluded from the compared axes (see
    // `compare_axes`).
    let (last_known_good, last_known_good_pass) =
        run_discriminator(&evidence.discriminator, &admission)?;
    let (shadow, shadow_pass) = run_discriminator(&evidence.candidate_discriminator, &admission)?;
    let verdicts = compare_axes(&last_known_good_pass, &shadow_pass);

    let mut bootstrap = SelfChangeBootstrap::admit(
        evidence.surface,
        evidence.old_generation,
        evidence.candidate_generation,
    )?;
    bootstrap.record_last_known_good(last_known_good.clone())?;
    bootstrap.record_shadow(shadow)?;

    // The I18.31 special case is dispatched through the typed dispatcher, so a
    // `ProcessExecutor` change really runs the outer Host/OS guardian scenario
    // and every other case really runs its own mechanic. The typed
    // `SpecialCaseEvidence` shape makes a fabricated variant unrepresentable.
    if let Some((case, digest)) = dispatch_special_case(&evidence)? {
        bootstrap.record_special_case(case, digest)?;
    }

    // The comparison carries the axes actually computed from the two live
    // observations, never an assumed clean verdict. `record_comparison` then
    // refuses closed through [`SelfChangeError::ComparisonDiverged`], naming
    // exactly the diverging axes, before the phase can advance; the
    // last-known-good run's own evidence digest is what the record binds.
    let comparison = ShadowComparisonRecord::new(
        evidence.surface,
        evidence.old_generation,
        evidence.candidate_generation,
        verdicts,
        last_known_good,
    )?;
    bootstrap.record_comparison(comparison)?;

    // The canary runs the same real discriminator again under the candidate
    // generation. Bounded is structural: `CanaryRecord::new` refuses a count
    // outside `1..=MAX_CANARY_TASKS`, the recorded count is the number of
    // canary runs this process actually performed, and the retired generation
    // stays admitted because this run revokes nothing, which is what keeps
    // rollback capable.
    let mut canary_tasks: u32 = 0;
    let (canary_evidence, _canary_pass) = run_discriminator(&evidence.discriminator, &admission)?;
    canary_tasks += 1;
    let canary = CanaryRecord::new(
        evidence.surface,
        evidence.old_generation,
        evidence.candidate_generation,
        canary_tasks,
        true,
        canary_evidence,
    )?;
    bootstrap.record_canary(canary)?;

    // Cutover refuses through the oracle rule: a refusal is a real
    // candidate-rejection event by the old generation, and its reason travels
    // in the refusal instead of a bare phase error.
    let receipt = bootstrap.cutover_or_reject().map_err(|resolved| {
        let reason = match &resolved.resolution {
            OracleResolution::RejectedByOldGeneration { reason } => reason.clone(),
            OracleResolution::Escalated { to } => format!("escalated to {to:?}"),
        };
        CliError::Contract(format!("old generation refused the cutover: {reason}"))
    })?;
    finish_under_receipt(&evidence, &receipt)?;
    match evidence.surface {
        // The runner surface owns the strict launch entry, so its cutover
        // ends in the one bootstrapped launch. Every other surface ends in
        // the minted receipt itself: the receipt is the handoff its future
        // strict entries consume, and launching an unrelated surface through
        // the runner gate would violate changed-surface-only scoping.
        SelfChangeSurface::InstrumentRunner => launch_under_receipt(&evidence, &receipt),
        _ => Ok(cutover_report(&receipt)),
    }
}

/// The material one really-observed discriminator pass contributes to the
/// five-axis comparison.
///
/// Every field here is what the live run observed on this machine: the
/// executable bytes and environment projection, the reconciled process
/// evidence with the terminal exit observation and the per-stream capture and
/// meaning it carries, and the evidence records the process owner actually
/// published. Nothing is derived, defaulted, or carried over from the bundle.
struct DiscriminatorPass {
    /// Machine-derived executable and environment identity of the child.
    observed: ChildObservation,
    /// The reconciled evidence the executor published for this run.
    evidence: ProcessEvidence,
    /// Terminal exit observation the executor published, absent when the
    /// executor published no exit observation. It is held whole rather than
    /// reduced to its disposition class, so the axes below can read the
    /// observed exit code and signal off it. Only the stable subset of the
    /// value is compared; its observation instant is genuine per-pass noise and
    /// is never read.
    exit: Option<ExitStatus>,
    /// Retained evidence record digests, in the order the sink received them.
    retained: Vec<String>,
}

/// Compares the last-known-good pass against the candidate's shadow pass.
///
/// The two sides are two different implementations, not two runs of one: the
/// shadow pass runs `&evidence.candidate_discriminator` while the
/// last-known-good pass runs `&evidence.discriminator`, both through the same
/// `run_child` observation path. A candidate whose own parser or evidence
/// normalization differs therefore produces a real difference here, and that
/// difference reaches
/// [`SelfChangeBootstrap::record_comparison`], which refuses it through
/// [`SelfChangeError::ComparisonDiverged`] before any receipt can be minted.
/// I18-31's candidate-runner/module side is realized by loading the recorded
/// candidate executable; this function then decides, per axis, whether it
/// behaves like the last-known-good generation over the same raw evidence.
///
/// I18.31 requires the comparison to check raw capture, normalized meaning,
/// selection, omissions and outcome; it never requires the two passes to mint
/// equal whole-run digests. So each axis is decided from the value the live
/// runs actually observed, in [`ComparisonAxis::ALL`] order:
///
/// - [`ComparisonAxis::RawCapture`] from `pass.evidence`'s per-stream
///   `ProcessStreamEvidence::observed_sha256` and `observed_bytes`, in
///   `ProcessStreamKind` order: the machine hash and length of the bytes the
///   tool actually wrote to each stream. This is the raw capture itself. The
///   executable `content_digest` it replaces hashed the program image, which
///   both passes necessarily shared, so it could never diverge and proved
///   nothing about the run; it remains in the per-run evidence digest, where
///   the sealed request binds it.
/// - [`ComparisonAxis::NormalizedMeaning`] from the same streams'
///   `ProcessStreamEvidence::parsing` and `::evaluation`: the meaning the
///   captured bytes were actually attributed, per stream, by the parser and
///   evaluator that classified them. This is the honest normalized meaning in
///   hand. `pass.observed.environment_digest` is NOT it: the caller of
///   `observe_at_path` supplies that value, and this driver supplies it from a
///   hardcoded empty
///   `EnvironmentProjection::new(BTreeMap::new(), Vec::new(),
///   EnvironmentInheritance::None)`, so it is the same constant for every
///   invocation that has ever existed and carries no comparison signal at all.
/// - [`ComparisonAxis::Selection`] from `pass.observed.argv` plus the
///   deterministic `operation_identity` the run sealed: the selection axis is
///   the operation the pass chose to run, so a pass that selects a different
///   command, or a different executable for it, diverges here.
/// - [`ComparisonAxis::Omissions`] from the exact streams each pass actually
///   published, every `ProcessStreamEvidence::gaps` entry it declared, the
///   `StreamTransportStatus` and `StreamPersistenceStatus` it recorded per
///   stream, and how many evidence records the sink retained. The gaps are the
///   omissions the executor itself recorded (unavailable capture, failed
///   transport or persistence, cancelled before EOF, an unknown outcome), so
///   this compares how completely each pass captured the same raw evidence:
///   a pass that retained a different number of records, or the same records
///   over a different completeness shape, genuinely retained something the
///   other pass did not.
/// - [`ComparisonAxis::Outcome`] from the stable part of the terminal
///   `ExitStatus` — its `disposition`, its `code`, and its `signal` — plus the
///   captured bytes and record count the pass produced, which is the outcome
///   this pass actually reached. A pass that turns exit code 0 into exit code
///   1, or completion into a signal, diverges here.
///
/// Deliberately excluded from every axis, and excluded because each is
/// genuine per-activation or per-instant noise rather than evidence about the
/// surface under change: the per-pass dispatch `permit_digest` and the other
/// per-`DispatchCell` permit fields behind it — `authority_id`, the keyed
/// `authentication_tag`, and `issued_at_unix_ms`, plus the copies of all of
/// them inside each retained evidence record; every observation instant, so
/// `ExitStatus::observed_at_unix_ms` and the view's recorded clock readings;
/// and, above, the content of each retained evidence record itself, which is
/// excluded for exactly that reason. That record content is why the retained
/// volume and the declared omission shape are compared instead of record
/// digests: each record embeds its own per-pass permit identity, so its digest
/// differs between two passes by construction even when both observed exactly
/// the same thing. What IS compared is the part of the same observation that
/// is stable across the two passes: the per-stream captured-bytes digest and
/// length, the transport and persistence statuses, the declared gaps, the exit
/// code and signal, and the retained record count. All of it stays inside each
/// run's own bound evidence digest as well.
///
/// The candidate side is loaded, not assumed: the shadow pass runs the
/// recorded `candidate_discriminator`, so a clean verdict here is a statement
/// about the candidate generation's own observed behaviour over the same raw
/// fixture/tool evidence, compared against the last-known-good generation's.
/// A bundle that names no candidate executable is refused by
/// [`read_bundle`], so the comparison can never silently fall back to
/// comparing the last-known-good generation with itself.
///
/// No axis is fabricated: an axis is recorded as diverging only on a real
/// difference between two observed values, and an empty list means every axis
/// in [`ComparisonAxis::ALL`] was compared and matched.
fn compare_axes(last_known_good: &DiscriminatorPass, shadow: &DiscriminatorPass) -> AxisVerdicts {
    let mut axes = Vec::new();
    for axis in ComparisonAxis::ALL {
        let matched = match axis {
            ComparisonAxis::RawCapture => {
                pass_raw_capture(last_known_good) == pass_raw_capture(shadow)
            }
            ComparisonAxis::NormalizedMeaning => {
                pass_normalized_meaning(last_known_good) == pass_normalized_meaning(shadow)
            }
            ComparisonAxis::Selection => pass_selection(last_known_good) == pass_selection(shadow),
            ComparisonAxis::Omissions => pass_omissions(last_known_good) == pass_omissions(shadow),
            ComparisonAxis::Outcome => pass_outcome(last_known_good) == pass_outcome(shadow),
        };
        if !matched {
            axes.push(axis);
        }
    }
    AxisVerdicts::with_divergence(axes)
}

/// The machine hash and length of the bytes one pass actually captured on each
/// published stream, in `ProcessStreamKind` order.
///
/// The vector is positional rather than counted, so a pass that stopped
/// publishing a stream, or published one the other pass never captured,
/// cannot compare equal to it. The digest and the length are the capture
/// itself: the same command producing different bytes on a stream — extra
/// output, truncated output, reordered output, output only one pass managed to
/// keep — is a real, stable difference in what was captured, so it diverges.
fn pass_raw_capture(pass: &DiscriminatorPass) -> Vec<(String, u64)> {
    streams(pass)
        .map(|stream| (stream.observed_sha256().to_owned(), stream.observed_bytes()))
        .collect()
}

/// The meaning one pass attributed to the bytes it captured on each published
/// stream, in `ProcessStreamKind` order.
///
/// Parsing and evaluation are the normalized layer over the raw capture: the
/// two statuses say how the captured bytes were classified downstream. They are
/// compared per stream, so a pass whose bytes were parsed into a different
/// meaning, or evaluated to a different verdict, diverges. An absent stream
/// compares unequal to a present one, which is exactly the intended signal
/// rather than a missing value.
fn pass_normalized_meaning(
    pass: &DiscriminatorPass,
) -> Vec<(StreamParsingStatus, StreamEvaluationStatus)> {
    streams(pass)
        .map(|stream| (stream.parsing(), stream.evaluation()))
        .collect()
}

/// The observed selection of one pass: the exact argv it ran and the
/// deterministic operation identity that argv and executable select.
///
/// This is the same identity the sealed request binds, derived the same way, so
/// a pass that selected a different command — or a different executable for it
/// — genuinely differs in what it chose to run.
fn pass_selection(pass: &DiscriminatorPass) -> (Vec<String>, String) {
    (
        pass.observed.argv.clone(),
        operation_identity(&pass.observed.executable_path, &pass.observed.argv),
    )
}

/// The omissions of one pass: exactly which streams it published, the exact
/// gaps, transport, and persistence statuses it declared on each, and how many
/// evidence records it retained.
///
/// The gaps are the omissions the executor itself recorded on the streams it
/// published (unavailable capture, failed transport or persistence, cancelled
/// before EOF, an unknown outcome), so comparing them compares how completely
/// each pass captured the same raw evidence. Gaps and statuses are compared as
/// the sets the executor recorded them as — a gap set is unordered, so
/// comparing it as a set cannot manufacture a difference from ordering — while
/// the stream order itself stays positional, so dropping a stream still
/// diverges. Nothing here is a completeness claim of this driver's own: a pass
/// that captured a different volume, retained a different number of records, or
/// reported a different omission shape, genuinely observed something the other
/// pass did not.
fn pass_omissions(
    pass: &DiscriminatorPass,
) -> (
    Vec<BTreeSet<StreamEvidenceGap>>,
    Vec<(StreamTransportStatus, StreamPersistenceStatus)>,
    usize,
) {
    let declared: Vec<BTreeSet<StreamEvidenceGap>> = streams(pass)
        .map(|stream| stream.gaps().iter().copied().collect())
        .collect();
    let transport: Vec<(StreamTransportStatus, StreamPersistenceStatus)> = streams(pass)
        .map(|stream| (stream.transport(), stream.persistence()))
        .collect();
    (declared, transport, pass.retained.len())
}

/// The observed outcome of one pass: the stable part of its terminal
/// [`ExitStatus`] and the evidence volume that outcome arrived with.
///
/// The disposition class alone is too coarse for this axis — the most obvious
/// outcome divergence there is a run that keeps its `Completed` class and still
/// changes its exit code — so the observed exit code and signal are decoded and
/// compared too. `observed_at_unix_ms` is the one field deliberately left out:
/// it is a per-pass wall-clock reading that differs by construction. A pass
/// that published no exit observation at all is represented as `None`, so it
/// still diverges from a pass that published a negative result instead.
fn pass_outcome(pass: &DiscriminatorPass) -> PassOutcome {
    PassOutcome {
        exit: pass.exit.as_ref().map(exit_outcome),
        captured: pass_raw_capture(pass),
        retained: pass.retained.len(),
    }
}

/// The terminal exit fact of one pass that is stable across the two runs.
///
/// The exit code and signal come off the executor's own wire value: see
/// [`exit_outcome`]. `observed_at_unix_ms` is deliberately not a member, because
/// it is an instant rather than an outcome and no two passes agree on it.
#[derive(Debug, Eq, PartialEq)]
struct PassOutcome {
    /// Terminal disposition, observed exit code, and observed signal; `None`
    /// when the pass published no exit status at all; and the decode failure
    /// as text when it published one this driver cannot read. No two different
    /// runs can share that failure, so an unreadable status is a divergence
    /// and never a defaulted outcome two runs could match on.
    exit: Option<Result<ExitOutcome, String>>,
    /// Machine hash and length of the bytes the pass captured.
    captured: Vec<(String, u64)>,
    /// How many evidence records the pass's sink retained.
    retained: usize,
}

/// The terminal exit fact read off one published [`ExitStatus`].
///
/// `ExitStatus` publishes its disposition through a getter but keeps `code` and
/// `signal` private, and this crate may not change that type, so the wire value
/// the type already serialises is decoded here to read the two payload fields
/// that make the outcome axis more than a disposition class. The decode
/// requires both keys to be present on that object, and an absent or malformed
/// one is an `Err`, which the outcome axis scores as a divergence: a status
/// this driver cannot read is never a defaulted `(None, None)` that two
/// different runs could share. No field is renamed, re-derived, or otherwise
/// invented on the way through, and `observed_at_unix_ms` is read past and
/// discarded rather than compared.
fn exit_outcome(status: &ExitStatus) -> Result<ExitOutcome, String> {
    let object: BTreeMap<String, serde_json::Value> =
        serde_json::from_value(serde_json::to_value(status).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let payload = |key: &str| -> Result<Option<i32>, String> {
        Ok(match object.get(key) {
            None | Some(serde_json::Value::Null) => None,
            Some(raw) => Some(
                serde_json::from_value::<i32>(raw.clone()).map_err(|error| error.to_string())?,
            ),
        })
    };
    Ok(ExitOutcome {
        disposition: status.disposition(),
        code: payload("code")?,
        signal: payload("signal")?,
    })
}

/// The comparable part of one [`ExitStatus`]: disposition, code, and signal.
///
/// The observation instant is absent by construction, so it cannot be compared
/// even by accident.
#[derive(Debug, Eq, PartialEq)]
struct ExitOutcome {
    /// Physical exit class the executor observed.
    disposition: ExitDisposition,
    /// Observed exit code, when the process produced one.
    code: Option<i32>,
    /// Observed termination signal, when one ended the process.
    signal: Option<i32>,
}

/// The streams one pass actually published, in `ProcessStreamKind` order.
///
/// Returns only the streams the evidence really carries, so the caller
/// compares over the streams that exist rather than over a placeholder for a
/// missing one. A pass that published a different set of streams therefore
/// yields a different vector length and genuinely diverges.
fn streams(pass: &DiscriminatorPass) -> impl Iterator<Item = &ProcessStreamEvidence> {
    [pass.evidence.stdout(), pass.evidence.stderr()]
        .into_iter()
        .flatten()
}

/// Dispatches the surface's I18.31 special case through the typed mechanic.
///
/// A surface that requires a special case but presents none fails closed, and
/// a surface that requires none but presents one fails closed too: the typed
/// evidence variant can only be admitted for the case that guards it.
fn dispatch_special_case(
    evidence: &BootstrapEvidence,
) -> Result<Option<(SpecialCase, EvidenceDigest)>, CliError> {
    match (
        evidence.surface.special_case(),
        evidence.special_case.clone(),
    ) {
        (Some(case), Some(record)) => {
            // The `ProcessExecutor` arm additionally re-runs the machine-side
            // outer guardian scenario here, so the cleanup fact the typed
            // `OuterGuardianRecord` carries is one this process observed from
            // the machine rather than a claim read back from the bundle.
            let record = match (case, &record) {
                (
                    SpecialCase::ExecutorOuterGuardian,
                    SpecialCaseEvidence::ExecutorOuterGuardian(record),
                ) => observe_outer_guardian(evidence, record)?,
                (_, record) => record.clone(),
            };
            case.verify(&record)?;
            Ok(Some((case, evidence_digest(&record)?)))
        }
        (Some(case), None) => Err(CliError::Contract(format!(
            "surface {} requires the {} special case",
            evidence.surface.as_str(),
            case.as_str()
        ))),
        (None, Some(record)) => Err(CliError::Contract(format!(
            "surface {} carries no special case, observed {}",
            evidence.surface.as_str(),
            record.case().as_str()
        ))),
        (None, None) => Ok(None),
    }
}

/// Re-runs the outer Host/OS guardian scenario from this machine.
///
/// The scenario is really verified here: the exact recorded evidence bytes are
/// re-hashed and the scenario worktree must be absent or emptied. The observed
/// tree state then replaces whatever the bundle claimed, so a worktree that
/// still holds residue fails closed before any bootstrap phase advances.
fn observe_outer_guardian(
    evidence: &BootstrapEvidence,
    record: &OuterGuardianRecord,
) -> Result<SpecialCaseEvidence, CliError> {
    let Some(scenario) = &evidence.outer_guardian_scenario else {
        return Err(CliError::Contract(
            "the executor outer-guardian special case requires a guardian scenario".to_owned(),
        ));
    };
    let bytes = scenario.evidence.as_bytes().to_vec();
    if bytes != record.evidence_bytes {
        return Err(CliError::Contract(
            "recorded guardian evidence bytes differ from the scenario".to_owned(),
        ));
    }
    let observed: GuardianEvidence = verify_outer_guardian(
        &OuterGuardianScenario::new(
            scenario.worktree_root.clone(),
            bytes,
            scenario.expected_evidence.as_str(),
        )
        .map_err(|error| CliError::Contract(format!("outer guardian scenario refused: {error}")))?,
    )
    .map_err(|error| CliError::Contract(format!("outer guardian refused: {error}")))?;
    Ok(SpecialCaseEvidence::ExecutorOuterGuardian(
        OuterGuardianRecord {
            evidence_bytes: record.evidence_bytes.clone(),
            expected_evidence: record.expected_evidence.clone(),
            tree_cleaned: matches!(
                observed.tree_state,
                GuardianTreeState::Absent | GuardianTreeState::Emptied
            ),
        },
    ))
}

/// Reads and shape-validates the recorded evidence bundle.
///
/// The bundle is read field by field from its JSON value, so a missing,
/// mistyped, or unknown field fails closed with the exact offending key instead
/// of silently binding a default.
fn read_bundle(bundle: &Path) -> Result<BootstrapEvidence, CliError> {
    let bytes = std::fs::read(bundle).map_err(|error| CliError::Bundle(error.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| CliError::Bundle(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("bundle is not a JSON object".to_owned()))?;
    let evidence = BootstrapEvidence {
        surface: field(object, "surface")?,
        old_generation: field(object, "old_generation")?,
        candidate_generation: field(object, "candidate_generation")?,
        authority_epoch: authority_epoch(required(object, "authority_epoch")?)?,
        dispatch_generation: Generation::new(integer(object, "dispatch_generation")?)?,
        permit_expires_at_unix_ms: integer(object, "permit_expires_at_unix_ms")?,
        session: text(object, "session")?,
        normative_pair: text(object, "normative_pair")?,
        limits: child_limits(required(object, "limits")?)?,
        special_case: optional_field(object, "special_case")?,
        outer_guardian_scenario: match optional_field::<serde_json::Value>(
            object,
            "outer_guardian_scenario",
        )? {
            Some(scenario) => Some(guardian_scenario(&scenario)?),
            None => None,
        },
        discriminator: discriminator(object, "discriminator")?,
        candidate_discriminator: discriminator(object, "candidate_discriminator")?,
        launch: launch(required(object, "launch")?)?,
        finish: match optional_field::<serde_json::Value>(object, "finish")? {
            Some(finish) => {
                let Some(plan) = finish.get("plan") else {
                    return Err(CliError::Bundle("'finish.plan' is missing".to_owned()));
                };
                let Some(run) = finish.get("run") else {
                    return Err(CliError::Bundle("'finish.run' is missing".to_owned()));
                };
                Some(FinishGate {
                    plan: serde_json::from_value(plan.clone())?,
                    run: serde_json::from_value(run.clone())?,
                })
            }
            None => None,
        },
    };
    Ok(evidence)
}

/// Requires one bundle field to be present.
fn required<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Value, CliError> {
    object
        .get(key)
        .ok_or_else(|| CliError::Bundle(format!("bundle field '{key}' is missing")))
}

/// Requires one bundle field and decodes it into `T`.
fn field<T: serde::de::DeserializeOwned>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<T, CliError> {
    serde_json::from_value(required(object, key)?.clone()).map_err(CliError::from)
}

/// Decodes one optional bundle field, rejecting a present-but-invalid value.
fn optional_field<T: serde::de::DeserializeOwned>(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Option<T>, CliError> {
    match object.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => Ok(Some(
            serde_json::from_value(value.clone()).map_err(CliError::from)?,
        )),
    }
}

/// Decodes the recorded canonical authority epoch of this run.
fn authority_epoch(value: &serde_json::Value) -> Result<EpochId, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'authority_epoch' is not an object".to_owned()))?;
    let lineage = EpochLineageId::new(text(object, "lineage")?)?;
    let sequence = integer(object, "sequence")?;
    let sequence = NonZeroU64::new(sequence).ok_or_else(|| {
        CliError::Bundle("'authority_epoch.sequence' must be non-zero".to_owned())
    })?;
    Ok(EpochId::new(lineage, sequence)?)
}

/// Decodes the recorded bounded child resource envelope of this run.
fn child_limits(value: &serde_json::Value) -> Result<ChildLimits, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'limits' is not an object".to_owned()))?;
    let max_descendants = integer(object, "max_descendants")?;
    let max_descendants = u32::try_from(max_descendants)
        .map_err(|_| CliError::Bundle("'limits.max_descendants' does not fit a u32".to_owned()))?;
    Ok(ChildLimits {
        wall_timeout_ms: integer(object, "wall_timeout_ms")?,
        stdout_bytes: integer(object, "stdout_bytes")?,
        stderr_bytes: integer(object, "stderr_bytes")?,
        max_descendants,
    })
}

/// Decodes the recorded outer-guardian scenario.
fn guardian_scenario(value: &serde_json::Value) -> Result<GuardianScenarioRecord, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'outer_guardian_scenario' is not an object".to_owned()))?;
    Ok(GuardianScenarioRecord {
        worktree_root: absolute_path(object, "outer_guardian_scenario", "worktree_root")?,
        evidence: text(object, "evidence")?,
        expected_evidence: field(object, "expected_evidence")?,
    })
}

/// Decodes one recorded discriminator command.
///
/// The recorded field is required and never defaulted: a bundle that names no
/// candidate executable has no candidate to shadow-run, so the shadow pass
/// cannot be produced at all and the run fails closed here.
fn discriminator(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<DiscriminatorCommand, CliError> {
    let value = required(object, key)?;
    let command = value
        .as_object()
        .ok_or_else(|| CliError::Bundle(format!("'{key}' is not an object")))?;
    Ok(DiscriminatorCommand {
        executable: absolute_path(command, key, "executable")?,
        argv: string_list(command, "argv")?,
        working_directory: absolute_path(command, key, "working_directory")?,
    })
}

/// Decodes the recorded post-cutover launch command.
fn launch(value: &serde_json::Value) -> Result<LaunchCommand, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'launch' is not an object".to_owned()))?;
    Ok(LaunchCommand {
        instrument: text(object, "instrument")?,
        product: text(object, "product")?,
        source: text(object, "source")?,
        profile: text(object, "profile")?,
        arguments: string_list(object, "arguments")?,
        declared_scope: text(object, "declared_scope")?,
        target: text(object, "target")?,
        kind: field(object, "kind")?,
        executable: absolute_path(object, "launch", "executable")?,
        argv: string_list(object, "argv")?,
        working_directory: absolute_path(object, "launch", "working_directory")?,
    })
}

/// Reads one required non-blank text field.
fn text(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, CliError> {
    let value = required(object, key)?
        .as_str()
        .ok_or_else(|| CliError::Bundle(format!("'{key}' is not a string")))?;
    if value.trim().is_empty() {
        return Err(CliError::Bundle(format!("'{key}' is blank")));
    }
    Ok(value.to_owned())
}

/// Reads one required unsigned integer field.
fn integer(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, CliError> {
    required(object, key)?
        .as_u64()
        .ok_or_else(|| CliError::Bundle(format!("'{key}' is not a u64")))
}

/// Reads one required absolute path field.
fn absolute_path(
    object: &serde_json::Map<String, serde_json::Value>,
    context: &str,
    key: &str,
) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(text(object, key)?);
    if !path.is_absolute() {
        return Err(CliError::Bundle(format!(
            "'{context}.{key}' must be an absolute path"
        )));
    }
    Ok(path)
}

/// Reads one required list-of-strings field.
fn string_list(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<String>, CliError> {
    let value = required(object, key)?
        .as_array()
        .ok_or_else(|| CliError::Bundle(format!("'{key}' is not a list")))?;
    value
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| CliError::Bundle(format!("'{key}' holds a non-string item")))
        })
        .collect()
}

/// Recomputes the bound digest of one recorded special-case evidence body.
///
/// The digest binds the exact bytes the typed mechanic verified, so the minted
/// receipt names the same admitted record the mechanic accepted.
fn evidence_digest(record: &SpecialCaseEvidence) -> Result<EvidenceDigest, CliError> {
    let bytes = serde_json::to_vec(record)?;
    Ok(EvidenceDigest::new(sha256_hex(&bytes))?)
}

/// Recorded admission material shared by every child this run seals.
///
/// The bundle owns every value; the machine clock supplies only the issue
/// instant and the per-child observations.
struct HarnessAdmission<'a> {
    /// Canonical authority epoch every permit of this run is sealed under.
    epoch: &'a EpochId,
    /// P-07 fence generation sealing one child intent.
    dispatch_generation: Generation,
    /// Unix millisecond at which this run's dispatch permits expire.
    permit_expires_at_unix_ms: u64,
    /// Durable execution session identity for this self-change run.
    session: &'a str,
    /// Bounded resource envelope admitted for every child of this run.
    limits: &'a ChildLimits,
}

/// Machine clock reading in Unix milliseconds, observed now.
///
/// Mirrors the `eliot-testd` worker clock: a missing or unrepresentable
/// reading fails closed downstream at the freshness contour, never here.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Builds one clock observation from an observed millisecond reading.
///
/// Mirrors the `eliot-testd` worker observation: wall and known time carry
/// the observed instant, and the unobserved transaction sequence and monotonic
/// readings stay canonically absent instead of carrying a placeholder.
fn observation_clock(now: u64) -> ClockReading {
    let ceiling = u64::try_from(i64::MAX).unwrap_or(u64::MAX);
    let now = i64::try_from(now.min(ceiling)).unwrap_or(i64::MAX);
    ClockReading {
        valid_time_ms: Some(now),
        known_time_ms: Some(now),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

/// Derives the process-invocation component of the authority id from the
/// wall clock. Uniqueness (not secrecy) is load-bearing here: the id only
/// names the instance.
fn system_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Generates fresh per-process key bytes from process-unique std sources
/// mixed through splitmix64, without adding a randomness dependency.
///
/// Mirrors the `eliot-testd` dispatch authority: the load-bearing property is
/// per-process uniqueness, not unpredictability. The key never leaves this
/// process, is never persisted, and only binds permits issued by this same
/// authority instance. The replay fence is per-instance regardless, and the
/// process exits after one shot.
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

/// Runs the unchanged external discriminator over the real machine and returns
/// the digest of the retained evidence it produced plus the observed material
/// the five-axis comparison is computed from.
///
/// The pass really launches the admitted child through the sole
/// `WindowsProcessExecutor`, really observes it to a terminal lifecycle, and
/// really reconciles the retained evidence; the returned digest binds exactly
/// that retained evidence plus the sealed operation identity, while
/// [`DiscriminatorPass`] carries the observed axes of the same live run.
fn run_discriminator(
    command: &DiscriminatorCommand,
    admission: &HarnessAdmission,
) -> Result<(EvidenceDigest, DiscriminatorPass), CliError> {
    let child = run_child(command, admission)?;
    let digest = EvidenceDigest::new(child.retained_sha256.clone())?;
    Ok((
        digest,
        DiscriminatorPass {
            observed: child.observation,
            exit: child.exit_status,
            retained: child.retained_records,
            evidence: child.evidence,
        },
    ))
}

/// The machine-derived identity of one really-observed child process.
struct ChildObservation {
    /// Canonical executable path observed on this machine.
    executable_path: String,
    /// Machine-derived content digest of the executable bytes.
    content_digest: String,
    /// Machine-derived environment projection identity.
    environment_digest: String,
    /// Observed tool version for the launched image.
    tool_version: Option<String>,
    /// Exact process argv the request and the observation both carry.
    argv: Vec<String>,
}

/// The machine-derived identity of one really-launched child process plus
/// the digest binding its retained terminal evidence.
struct Child {
    /// Machine-derived executable identity observed before launch.
    observation: ChildObservation,
    /// Digest binding the retained terminal evidence of the run.
    retained_sha256: String,
    /// The reconciled evidence the executor published for the run.
    evidence: ProcessEvidence,
    /// Terminal exit status the executor observed for the child. Its
    /// disposition is the material the run's own evidence digest binds, and
    /// the whole value is what the five-axis comparison reads.
    exit_status: Option<ExitStatus>,
    /// Terminal exit disposition the executor observed for the child, kept
    /// beside the full status so the evidence-digest material below is the
    /// same bytes it was before the status was retained whole.
    exit_disposition: Option<ExitDisposition>,
    /// The retained evidence record digests, in publication order.
    retained_records: Vec<String>,
}

/// Observes one recorded child executable from the machine without launching it.
///
/// The executable bytes are hashed from the machine and the environment
/// identity comes from the canonical projection digest, so the observation is
/// evidence and never a synthesised success. The launch path uses this
/// directly so the launch binary executes exactly once, through the
/// bootstrapped runner, instead of once for observation plus once for real.
fn observe_child_command(executable: &Path, argv: &[String]) -> Result<ChildObservation, CliError> {
    let projection =
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?;
    let observation = ExecutableObservation::observe_at_path(
        executable,
        argv.to_vec(),
        environment_projection_digest(&projection),
        Some(tool_version(executable)),
    )
    .map_err(|error| CliError::Contract(format!("executable observation refused: {error}")))?;
    if !observation.is_complete() {
        return Err(CliError::Contract(
            "executable observation is incomplete".to_owned(),
        ));
    }
    Ok(ChildObservation {
        executable_path: observation.canonical_path,
        content_digest: observation.content_digest,
        environment_digest: observation.environment_digest,
        tool_version: observation.tool_version,
        argv: argv.to_vec(),
    })
}

/// Runs one admitted child to a terminal state and returns its retained proof.
///
/// Every composition piece is real: the executable bytes are hashed from the
/// machine, the permit is issued by an activated `DispatchPermitAuthority`, and
/// the launch really goes through [`WindowsProcessExecutor`], so the returned
/// digest is evidence and never a synthesised success.
fn run_child(
    command: &DiscriminatorCommand,
    admission: &HarnessAdmission,
) -> Result<Child, CliError> {
    let executable = resolve_executable(&command.executable)?;
    let observed = observe_child_command(executable.as_path(), command.argv.as_slice())?;
    let operation = operation_identity(&observed.executable_path, &observed.argv);
    let issued_at_unix_ms = now_unix_ms().max(1);
    let inputs = ChildInputs {
        operation: operation.as_str(),
        executable: executable.as_path(),
        argv: command.argv.as_slice(),
        working_directory: command.working_directory.as_path(),
        content_digest: observed.content_digest.as_str(),
        generation: admission.dispatch_generation,
        session: admission.session,
        limits: admission.limits,
    };
    let cell = DispatchCell::activate()?;
    let request = seal_child_request(
        &cell,
        admission.epoch,
        &inputs,
        issued_at_unix_ms,
        admission.permit_expires_at_unix_ms,
    )?;
    let executor = WindowsProcessExecutor::new(Arc::new(cell) as Arc<dyn DispatchValidationPort>);
    let sink = Arc::new(RetainedEvidenceSink::default());
    let receipt =
        block_on(executor.start(request, Arc::clone(&sink) as Arc<dyn ProcessEvidenceSink>))?;
    let view = block_on(executor.inspect(receipt.operation_id().clone()))?;
    if !view.lifecycle().is_terminal() {
        return Err(CliError::ReconcileRequired);
    }
    let evidence = block_on(executor.reconcile(receipt.operation_id().clone()))?;

    // The digest binds the observed outcome, not an assertion about it: the
    // executor's own terminal exit disposition plus the retained evidence it
    // published, so a diverging pass over the same command changes the digest.
    // The permit digest joins only this run's own bound evidence, never the
    // five-axis comparison: it is minted from a fresh per-`DispatchCell` key
    // and authority id, so it differs between the two passes by construction
    // rather than by any difference in what the runs observed.
    let mut child = Child {
        observation: observed,
        retained_sha256: String::new(),
        exit_status: view.exit().cloned(),
        exit_disposition: view.exit().map(ExitStatus::disposition),
        retained_records: sink.retained(),
        evidence,
    };
    let mut material = format!(
        "self-change-retained\0{}\0{}\0{:?}\0{}\0{}",
        child.observation.content_digest,
        child.observation.environment_digest,
        child.exit_disposition,
        child.evidence.operation_id().as_str(),
        receipt.permit_digest(),
    );
    for record in &child.retained_records {
        material.push('\0');
        material.push_str(record);
    }
    child.retained_sha256 = sha256_hex(material.as_bytes());
    Ok(child)
}

/// Exact launch material for one child the dispatch cell seals.
struct ChildInputs<'a> {
    /// Stable operation identity bound to this child.
    operation: &'a str,
    /// Canonical machine path of the executable.
    executable: &'a Path,
    /// Exact process argv the request and the observation both carry.
    argv: &'a [String],
    /// Absolute working directory for the child.
    working_directory: &'a Path,
    /// Machine-derived content digest of the executable bytes.
    content_digest: &'a str,
    /// P-07 fence generation sealing this child intent.
    generation: Generation,
    /// Durable execution session identity for this self-change run.
    session: &'a str,
    /// Bounded resource envelope admitted for this child.
    limits: &'a ChildLimits,
}

/// Seals one Kernel-issued process request for a real child launch.
///
/// The intent carries the machine-observed executable digest, the recorded
/// session, limits, and fence generation; the dispatch cell issues the permit
/// and stores the matching validation context, so the one-shot replay fence
/// is real for the launch below.
fn seal_child_request(
    cell: &DispatchCell,
    epoch: &EpochId,
    inputs: &ChildInputs,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<ProcessRequest, CliError> {
    let intent = ProcessIntent::new(
        OperationId::new(inputs.operation)?,
        ProcessTreeId::new(format!("{}-tree", inputs.operation))?,
        JobId::new(format!("{}-job", inputs.operation))?,
        ImageId::new(format!("{}-image", inputs.operation))?,
        SessionId::new(inputs.session)?,
        inputs.generation,
        inputs.executable.to_string_lossy().into_owned(),
        inputs.content_digest.to_owned(),
        inputs.argv.to_vec(),
        inputs.working_directory.to_string_lossy().into_owned(),
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?,
        ResourceLimits::new(
            inputs.limits.wall_timeout_ms,
            None,
            None,
            inputs.limits.stdout_bytes,
            inputs.limits.stderr_bytes,
            inputs.limits.max_descendants,
        )?,
    )?;
    let fence = FencingToken::new(
        epoch.clone(),
        inputs.generation,
        format!("{}-fence", inputs.operation),
    )?;
    let heads = BTreeMap::from([(
        "self-change".to_owned(),
        sha256_hex(inputs.operation.as_bytes()),
    )]);
    let lease = ActionLeaseRef::new(format!("{}-lease", inputs.operation))?;
    let nonce = format!("{}-nonce", inputs.operation);
    cell.issue(
        &intent,
        fence,
        heads,
        issued_at_unix_ms,
        expires_at_unix_ms,
        lease,
        nonce,
    )
}

/// The single dispatch-authority cell for one sealed child request.
///
/// Mirrors the `eliot-testd` dispatch authority: the cell issues the permit
/// and stores the validation context built from the same fence, revision
/// heads, epoch, and observed clock, so consume-time validation compares the
/// permit against the exact material it was issued with.
struct DispatchCell {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl DispatchCell {
    /// Activates one ephemeral authority around fresh in-memory key material.
    ///
    /// The authority id names this process invocation after the
    /// testd/doctor/dreamer `<component>-dispatch-{pid}-{nanos}` convention;
    /// the key never leaves this process.
    fn activate() -> Result<Self, CliError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id =
            DispatchAuthorityId::new(format!("verifier-selfchange-dispatch-{pid}-{nanos}"))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one admitted child.
    ///
    /// Mirrors the broker/testd issue shape: the fence, revision heads, and
    /// epoch travel from the caller, issuance runs from the observed issue
    /// instant to the recorded expiry, and the stored validation context pins
    /// the same material plus revision 1. Freshness (`issued_at < expires_at`,
    /// and later `now < expires_at` at consume time) is enforced by the
    /// contour types, never assumed.
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
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            issued_at_unix_ms,
            expires_at_unix_ms,
            nonce,
        )?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| CliError::Contract("self-change authority lock poisoned".to_owned()))?
            .issue(intent, issuance)?;
        // The stored context pins the exact material the permit was issued
        // with: the same fence, the fence's own authority epoch, and the same
        // revision heads. Consume-time validation compares the permit against
        // this snapshot, so any drift fails closed there.
        let epoch = fence.authority_epoch().clone();
        let context = DispatchValidationContext::new(
            observation_clock(issued_at_unix_ms),
            fence,
            epoch,
            heads,
            VALIDATION_REVISION,
        )?;
        *self
            .context
            .lock()
            .map_err(|_| CliError::Contract("self-change context lock poisoned".to_owned()))? =
            Some(context);
        Ok(ProcessRequest::new(intent.clone(), permit)?)
    }
}

impl DispatchValidationPort for DispatchCell {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let context = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("validation context poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("validation context absent".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| ProcessExecutionError::Unavailable("authority lock poisoned".to_owned()))?
            .validate_and_consume(request, observed, &context)
            .map_err(ProcessExecutionError::from)
    }
}

/// One-shot request port over an already-sealed Kernel process request.
///
/// The sealed request is owned here because [`ProcessRequest`] is deliberately
/// not cloneable: a single dispatch permit can never be minted twice, so the
/// port hands the one request it holds to the runner exactly once and every
/// later bind of the same port fails closed.
struct LaunchPort {
    request: Mutex<Option<ProcessRequest>>,
}

impl LaunchPort {
    /// Holds the single request bound to one admitted post-cutover launch.
    fn sealed(request: ProcessRequest) -> Self {
        Self {
            request: Mutex::new(Some(request)),
        }
    }
}

impl InstrumentRequestPort for LaunchPort {
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError> {
        let mut sealed = self
            .request
            .lock()
            .map_err(|_| RunnerError::Binding("sealed request cell poisoned".to_owned()))?;
        let request = sealed.as_ref().ok_or(RunnerError::ReceiptMismatch)?;
        if request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        if request.generation().get() != invocation.request.state_fence.resource_generation.value()
        {
            return Err(RunnerError::Binding(
                "sealed request generation differs from the admitted fence".to_owned(),
            ));
        }
        if request.fence().authority_epoch() != &invocation.request.state_fence.authority_epoch {
            return Err(RunnerError::Binding(
                "sealed request authority epoch differs from the admitted fence".to_owned(),
            ));
        }
        // The one-shot permit transfers exactly once, matching the
        // kernel-owned request port: a second bind of the same admission can
        // never launch a second child under one permit.
        sealed.take().ok_or(RunnerError::ReceiptMismatch)
    }
}

/// Evidence sink that retains every record the process owner publishes.
#[derive(Default)]
struct RetainedEvidenceSink {
    records: Mutex<Vec<Vec<u8>>>,
}

impl RetainedEvidenceSink {
    /// The retained record digests, in publication order.
    fn retained(&self) -> Vec<String> {
        self.records
            .lock()
            .map(|records| records.iter().map(|bytes| sha256_hex(bytes)).collect())
            .unwrap_or_default()
    }
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

/// The single physical process boundary the post-cutover launch crosses.
///
/// The launch reuses the same composition as the discriminator passes, so the
/// verified launch really starts a child instead of fabricating a receipt. The
/// cell is shared with the launch port, so the one-shot permit the port hands
/// over is consumed against the exact validation context it was issued with.
struct LaunchExecutor {
    authority: Arc<DispatchCell>,
}

impl LaunchExecutor {
    /// Wraps the dispatch cell the post-cutover launch consumes through.
    fn with(authority: Arc<DispatchCell>) -> Self {
        Self { authority }
    }

    /// The P-07 authority composition every lifecycle call of this launch
    /// crosses. The same activated cell issues and consumes, so the one-shot
    /// replay fence is real for the admitted launch.
    fn executor(&self) -> WindowsProcessExecutor {
        WindowsProcessExecutor::new(Arc::clone(&self.authority) as Arc<dyn DispatchValidationPort>)
    }
}

impl ProcessExecutor for LaunchExecutor {
    async fn start(
        &self,
        request: ProcessRequest,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<eliot_process::ProcessStartReceipt, ProcessExecutionError> {
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
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.executor().cancel(operation_id).await
    }

    async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        self.executor().reconcile(operation_id).await
    }
}

/// Launches the admitted instrument under the freshly minted receipt.
///
/// This is the only launch of a self-change generation, and it goes through
/// [`InstrumentRunner::launch_verified_with_bootstrap`], so the receipt must
/// genuinely cover the runner surface before the verified launch runs. The
/// launch binary is observed without executing, then executed exactly once
/// through the bootstrapped runner.
fn launch_under_receipt(
    evidence: &BootstrapEvidence,
    receipt: &GenerationReceipt,
) -> Result<String, CliError> {
    if !receipt.covers(SelfChangeSurface::InstrumentRunner) {
        return Err(CliError::Contract(format!(
            "receipt covers {}, not the instrument runner surface",
            receipt.surface().as_str()
        )));
    }
    let command = DiscriminatorCommand {
        executable: evidence.launch.executable.clone(),
        argv: evidence.launch.argv.clone(),
        working_directory: evidence.launch.working_directory.clone(),
    };
    let executable = resolve_executable(&command.executable)?;
    let observed = observe_child_command(executable.as_path(), command.argv.as_slice())?;
    let generation = Generation::new(receipt.new_generation())?;
    let fingerprints = fingerprint_set(
        &observed,
        evidence.launch.instrument.as_str(),
        evidence.normative_pair.as_str(),
    );
    let registry = ProviderRegistry::ready(
        receipt.new_generation(),
        evidence.normative_pair.clone(),
        &fingerprints,
    )?;
    let clock = observation_clock(now_unix_ms());
    let invocation = launch_invocation(
        &evidence.launch,
        &observed,
        receipt.new_generation(),
        evidence.authority_epoch.clone(),
        clock,
    )?;
    let freshness = RegistryFreshness {
        generation: receipt.new_generation(),
        normative_pair_digest: evidence.normative_pair.as_str(),
        fingerprints: &fingerprints,
    };
    let entry = registry.resolve_current(&invocation, &freshness)?;
    // The port request is sealed through the same cell the launch executor
    // consumes through, under the receipt's new generation: the one-shot
    // permit hands over exactly once and validates against the exact context
    // it was issued with.
    let cell = Arc::new(DispatchCell::activate()?);
    let inputs = ChildInputs {
        operation: invocation.request.request_id.as_str(),
        executable: executable.as_path(),
        argv: command.argv.as_slice(),
        working_directory: command.working_directory.as_path(),
        content_digest: observed.content_digest.as_str(),
        generation,
        session: evidence.session.as_str(),
        limits: &evidence.limits,
    };
    let request = seal_child_request(
        &cell,
        &evidence.authority_epoch,
        &inputs,
        now_unix_ms().max(1),
        evidence.permit_expires_at_unix_ms,
    )?;
    let port = LaunchPort::sealed(request);
    let resolved = ResolvedExecutableIdentity::new(
        evidence.launch.instrument.as_str(),
        observed.executable_path.clone(),
        observed.content_digest.clone(),
        observed.tool_version.clone(),
        observed.environment_digest.clone(),
        observed.argv.clone(),
    )?;
    let runner = InstrumentRunner::new(Arc::new(LaunchExecutor::with(cell)));
    let start = block_on(runner.launch_verified_with_bootstrap(
        invocation,
        &port,
        entry,
        Some(&resolved),
        Arc::new(RetainedEvidenceSink::default()) as Arc<dyn ProcessEvidenceSink>,
        receipt,
    ))?;
    Ok(format!(
        "{} operation={} executable_digest={}",
        cutover_report(receipt),
        start.process.operation_id().as_str(),
        start.executable.map_or_else(
            || "none".to_owned(),
            |observation| observation.content_digest.clone()
        ),
    ))
}

/// Reports one completed cutover: the covering receipt, never a launch claim.
fn cutover_report(receipt: &GenerationReceipt) -> String {
    format!(
        "cutover surface={} old_generation={} new_generation={} comparison={} canary={} special_case={}",
        receipt.surface().as_str(),
        receipt.old_generation(),
        receipt.new_generation(),
        receipt.comparison().as_str(),
        receipt.canary().as_str(),
        receipt
            .special_case()
            .map_or_else(|| "none".to_owned(), |(case, _)| case.as_str().to_owned()),
    )
}

/// Decides the finish-gate run under the same cutover receipt.
///
/// While the finish surface itself ships a generation, the decision runs
/// through the strict [`verdict_with_bootstrap`] entry instead of the plain
/// one, so the same receipt covers both the runner launch and the finish
/// verdict, and a blocking verdict refuses the cutover.
fn finish_under_receipt(
    evidence: &BootstrapEvidence,
    receipt: &GenerationReceipt,
) -> Result<(), CliError> {
    let Some(finish) = &evidence.finish else {
        return Ok(());
    };
    if !receipt.covers(SelfChangeSurface::FinishService) {
        return Err(CliError::Contract(format!(
            "recorded finish gate requires a {} receipt, observed {}",
            SelfChangeSurface::FinishService.as_str(),
            receipt.surface().as_str()
        )));
    }
    let verdict = verdict_with_bootstrap(
        &finish.plan,
        &finish.run,
        finish.run.finished_at.unwrap_or(finish.run.started_at),
        receipt,
    )?;
    if verdict.decision == VerificationDecision::Block {
        return Err(CliError::Contract(
            "bootstrapped finish gate blocks the cutover".to_owned(),
        ));
    }
    Ok(())
}

/// Caller-attested registry fingerprints for one observed child.
///
/// The registry never reads files at runtime, so these slots are attested from
/// the machine observation the launch itself pinned plus the recorded
/// instrument and normative-pair identities.
fn fingerprint_set(
    observed: &ChildObservation,
    instrument: &str,
    normative_pair: &str,
) -> InvalidationSet {
    InvalidationSet {
        source: observed.content_digest.clone(),
        lock: observed.environment_digest.clone(),
        toolchain: observed.tool_version.clone().unwrap_or_default(),
        env: observed.environment_digest.clone(),
        exe: observed.content_digest.clone(),
        profile: sha256_hex(instrument.as_bytes()),
        parser: sha256_hex(normative_pair.as_bytes()),
    }
}

/// The invocation admitted for the post-cutover launch.
///
/// Identities arrive with the recorded bundle; the fence carries the recorded
/// authority epoch plus the receipt generation, and the clock carries the
/// observed admission instant.
fn launch_invocation(
    launch: &LaunchCommand,
    observed: &ChildObservation,
    generation: u64,
    epoch: EpochId,
    clock: ClockReading,
) -> Result<InstrumentInvocation, CliError> {
    let request_id = format!(
        "self-change-launch-{}",
        &sha256_hex(observed.argv.join("\u{1}").as_bytes())[..24]
    );
    let invocation = InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new(request_id)?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new(launch.product.clone())?,
            source_id: SourceId::new(launch.source.clone())?,
            state_fence: StateFence::new(epoch, ResourceGeneration::new(generation)?),
            clock,
        },
        instrument: ContractId::new(launch.instrument.clone())?,
        kind: launch.kind,
        profile: launch.profile.clone(),
        target: launch.target.clone(),
        arguments: launch.arguments.clone(),
        input_artifacts: Vec::new(),
        declared_scope: launch.declared_scope.clone(),
        requested_at: clock,
    };
    invocation.validate()?;
    Ok(invocation)
}

/// Resolves one recorded executable to its canonical machine path.
fn resolve_executable(path: &Path) -> Result<PathBuf, CliError> {
    if !path.is_absolute() {
        return Err(CliError::Contract(format!(
            "executable {} must be an absolute path",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|error| {
        CliError::Contract(format!(
            "executable {} is unavailable: {error}",
            path.display()
        ))
    })
}

/// The stable operation identity bound to one observed executable and argv.
///
/// Both the sealed request and the selection axis of the five-axis comparison
/// derive their identity here, so a pass that selected a different command — or
/// a different executable for it — is the same difference the sealed permit
/// names. The machine-resolved path is what the child actually runs, so this is
/// the observed value rather than the recorded one.
fn operation_identity(executable: &str, argv: &[String]) -> String {
    let material = format!("{executable}\0{}", argv.join("\u{1}"));
    format!(
        "self-change-discriminator-{}",
        &sha256_hex(material.as_bytes())[..24]
    )
}

/// The observed tool version, derived from the executable's own file name.
fn tool_version(executable: &Path) -> String {
    let name = executable.file_name().map_or_else(
        || "unknown".to_owned(),
        |value| value.to_string_lossy().into_owned(),
    );
    format!("i18-31-selfchange-{}", &sha256_hex(name.as_bytes())[..16])
}

/// Drives one already-resolved future on the calling thread.
///
/// The child launch is synchronous under the sole Windows executor — `start`,
/// `inspect`, and `reconcile` complete without awaiting — so this binary
/// needs no async runtime; the driver only pumps the one future it owns
/// and never sleeps, retries, or performs I/O of its own.
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
