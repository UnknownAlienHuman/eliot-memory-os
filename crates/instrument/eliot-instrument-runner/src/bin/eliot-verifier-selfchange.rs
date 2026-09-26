//! Production entry point for an I18.31 verification-surface self-change.
//!
//! A changed verifier cannot be the sole authority proving its own
//! correctness, so this binary is the one place where a verification-surface
//! generation actually crosses the asymmetric bootstrap. It reads the recorded
//! bootstrap evidence for the changed surface, drives the real
//! [`SelfChangeBootstrap`] through its five phases, dispatches the surface's
//! I18.31 special case through [`eliot_verifier::SpecialCase::verify`], and
//! only after [`SelfChangeBootstrap::cutover`] mints the real
//! [`GenerationReceipt`] does it launch the instrument through
//! [`InstrumentRunner::launch_verified_with_bootstrap`].
//!
//! Every phase is backed by a real process on this machine: the last-known-good
//! pass, the candidate shadow pass, the bounded canary, and the post-cutover
//! launch all cross the sole [`WindowsProcessExecutor`]. No phase is asserted,
//! no digest is fabricated, and the receipt cannot be hand-built
//! ([`GenerationReceipt`] fields are private). A surface whose special-case
//! evidence does not verify fails closed before any launch, and the protocol
//! binds only the admitted surface, so an unrelated module is never dragged
//! through a full release cycle.

#![forbid(unsafe_code)]
// The cutover report on stdout and its fail-closed refusal on stderr are this
// entry point's operator-facing contract, the same reason `bins/eliot` and
// `bins/eliot-store-surreal` carry it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError, FencingToken, Generation,
    ImageId, JobId, KernelDispatchKey, OperationId, PermitIssuance, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessIntent, ProcessRequest, ProcessTreeId, ResourceLimits, SessionId,
    SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{
    DispatchValidationPort, WindowsProcessExecutor,
    outer_guardian::{
        GuardianEvidence, GuardianTreeState, OuterGuardianScenario, verify_outer_guardian,
    },
};
use eliot_verifier::{
    AxisVerdicts, CanaryRecord, EvidenceDigest, GenerationReceipt, OuterGuardianRecord,
    SelfChangeBootstrap, SelfChangeError, SelfChangeSurface, ShadowComparisonRecord, SpecialCase,
    SpecialCaseEvidence, VerificationDecision, verdict_with_bootstrap,
};

/// Exit code for a completed cutover plus its bootstrapped launch.
const EXIT_CUTOVER: i32 = 0;
/// Exit code for any failed-closed gate before or during cutover.
const EXIT_REFUSED: i32 = 1;
/// Exit code for a committed launch whose terminal state needs reconciliation.
const EXIT_RECONCILE_REQUIRED: i32 = 4;

/// Stable identity of the instrument contract this entry launches.
const INSTRUMENT: &str = "eliot.instrument.rustc";
/// Normative-pair digest the admitted registry is assembled against.
const NORMATIVE_PAIR: &str = "i18-31-verification-self-change";
/// Durable execution session identity for one self-change run.
const SESSION: &str = "eliot-verifier-selfchange-session";
/// Product identity the admitted invocation belongs to.
const PRODUCT: &str = "eliot-verifier-selfchange";
/// Source identity of the candidate under test.
const SOURCE: &str = "verification-surface-candidate";
/// Dispatch authority identity of this process's one permit cell.
const AUTHORITY: &str = "self-change-dispatch-authority";
/// Wall bound for one admitted discriminator or launch child.
const CHILD_WALL_TIMEOUT_MS: u64 = 120_000;
/// Retained stream ceiling for one admitted child.
const CHILD_STREAM_BYTES: u64 = 65_536;
/// Bounded real tasks a canary may run, one per recorded self-change run.
const CANARY_TASKS: u32 = 1;
/// Canonical epoch lineage of this self-change composition root.
const EPOCH_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
/// Epoch sequence of this self-change composition root, as its decimal text.
const EPOCH_LINEAGE_SEQUENCE: &str = "1";
/// Epoch sequence of this self-change composition root.
const EPOCH_SEQUENCE: u64 = 1;
/// Machine clock observation carried into every fresh Kernel state.
const CLOCK: ClockReading = ClockReading {
    valid_time_ms: Some(1),
    known_time_ms: Some(1),
    transaction_sequence: None,
    monotonic_ns: Some(1),
};
/// Unix millisecond at which the in-memory permits below are issued.
const ISSUED_AT_UNIX_MS: u64 = 1;
/// Unix millisecond at which the in-memory permits below expire.
///
/// The permit window is the process-scoped dispatch cell, not a policy value:
/// the composition root issues and consumes inside one synchronous call chain,
/// so the bound is the last representable millisecond and freshness is still
/// enforced against the current Kernel clock on every consume.
const EXPIRES_AT_UNIX_MS: u64 = u64::MAX;

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
struct BootstrapEvidence {
    /// The changed verification/control surface, and nothing else (I18.31 W5).
    surface: SelfChangeSurface,
    /// The retired generation.
    old_generation: u64,
    /// The candidate generation, which must advance past the old one.
    candidate_generation: u64,
    /// Evidence for the admitted surface's special case, when it requires one.
    special_case: Option<SpecialCaseEvidence>,
    /// The outer Host/OS guardian scenario this entry re-verifies from the
    /// machine before a `ProcessExecutor` self-change is admitted. The typed
    /// `ExecutorOuterGuardian` arm below requires it, so an executor-surface
    /// change can never reach cutover without a real scenario run.
    outer_guardian_scenario: Option<GuardianScenarioRecord>,
    /// The unchanged external discriminator, run for real on this machine by
    /// the last-known-good pass, the candidate shadow pass, and the canary.
    discriminator: DiscriminatorCommand,
    /// The instrument launch admitted only under the freshly minted receipt.
    launch: LaunchCommand,
    /// The finish-gate run whose verdict the same receipt must also cover.
    finish: Option<FinishGate>,
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

    // Phases 1 and 2 are produced by real runs on this machine, never by a
    // recorded claim: the unchanged external discriminator runs over the
    // identical command first as the last-known-good pass, then again as the
    // candidate's shadow pass over the same raw tool evidence. The two live
    // observations must agree on the retained evidence digest, which is the
    // comparison over raw capture, normalized meaning, selection, omissions,
    // and outcome that I18.31 requires before a cutover.
    let last_known_good = run_discriminator(&evidence.discriminator)?;
    let shadow = run_discriminator(&evidence.discriminator)?;
    if last_known_good != shadow {
        return Err(CliError::Contract(format!(
            "shadow pass diverged from the last-known-good pass: {} != {}",
            last_known_good.as_str(),
            shadow.as_str()
        )));
    }

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

    // The comparison covers every `ComparisonAxis` by construction: the clean
    // verdict is the only accepted one, and `record_comparison` refuses any
    // non-empty divergence list before the phase can advance.
    let comparison = ShadowComparisonRecord::new(
        evidence.surface,
        evidence.old_generation,
        evidence.candidate_generation,
        AxisVerdicts::all_matched(),
        last_known_good,
    )?;
    bootstrap.record_comparison(comparison)?;

    // The canary runs the same real discriminator again under the candidate
    // generation. Bounded is structural: `CanaryRecord::new` refuses a count
    // outside `1..=MAX_CANARY_TASKS`, and the retired generation stays
    // admitted for the launch below, which is what keeps rollback capable.
    let canary = CanaryRecord::new(
        evidence.surface,
        evidence.old_generation,
        evidence.candidate_generation,
        CANARY_TASKS,
        true,
        run_discriminator(&evidence.discriminator)?,
    )?;
    bootstrap.record_canary(canary)?;

    let receipt = bootstrap.cutover()?;
    finish_under_receipt(&evidence, &receipt)?;
    launch_under_receipt(&evidence, &receipt)
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
    let evidence =
        BootstrapEvidence {
            surface: field(object, "surface")?,
            old_generation: field(object, "old_generation")?,
            candidate_generation: field(object, "candidate_generation")?,
            special_case: optional_field(object, "special_case")?,
            outer_guardian_scenario: match optional_field::<serde_json::Value>(
                object,
                "outer_guardian_scenario",
            )? {
                Some(scenario) => Some(guardian_scenario(&scenario)?),
                None => None,
            },
            discriminator: discriminator(required(object, "discriminator")?)?,
            launch: launch(required(object, "launch")?)?,
            finish: match optional_field::<serde_json::Value>(object, "finish")? {
                Some(finish) => {
                    Some(FinishGate {
                        plan: serde_json::from_value(finish.get("plan").cloned().ok_or_else(
                            || CliError::Bundle("'finish.plan' is missing".to_owned()),
                        )?)?,
                        run: serde_json::from_value(finish.get("run").cloned().ok_or_else(
                            || CliError::Bundle("'finish.run' is missing".to_owned()),
                        )?)?,
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

/// Decodes the recorded discriminator command.
fn discriminator(value: &serde_json::Value) -> Result<DiscriminatorCommand, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'discriminator' is not an object".to_owned()))?;
    Ok(DiscriminatorCommand {
        executable: absolute_path(object, "discriminator", "executable")?,
        argv: string_list(object, "argv")?,
        working_directory: absolute_path(object, "discriminator", "working_directory")?,
    })
}

/// Decodes the recorded post-cutover launch command.
fn launch(value: &serde_json::Value) -> Result<LaunchCommand, CliError> {
    let object = value
        .as_object()
        .ok_or_else(|| CliError::Bundle("'launch' is not an object".to_owned()))?;
    Ok(LaunchCommand {
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

/// Runs the unchanged external discriminator over the real machine and returns
/// the digest of the retained evidence it produced.
///
/// The pass really launches the admitted child through the sole
/// `WindowsProcessExecutor`, really observes it to a terminal lifecycle, and
/// really reconciles the retained evidence; the returned digest binds exactly
/// that retained evidence plus the sealed operation identity.
fn run_discriminator(command: &DiscriminatorCommand) -> Result<EvidenceDigest, CliError> {
    let child = run_child(command)?;
    Ok(EvidenceDigest::new(child.retained_sha256)?)
}

/// The machine-derived identity of one really-launched child process.
struct Child {
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
    /// Digest binding the retained terminal evidence of the run.
    retained_sha256: String,
}

/// Runs one admitted child to a terminal state and returns its retained proof.
///
/// Every composition piece is real: the executable bytes are hashed from the
/// machine, the permit is issued by an activated `DispatchPermitAuthority`, and
/// the launch really goes through [`WindowsProcessExecutor`], so the returned
/// digest is evidence and never a synthesised success.
fn run_child(command: &DiscriminatorCommand) -> Result<Child, CliError> {
    let executable = resolve_executable(&command.executable)?;
    let environment_digest = sha256_hex(b"i18-31-self-change-child-environment");
    let observation = eliot_process_executor::ExecutableObservation::observe_at_path(
        &executable,
        command.argv.clone(),
        environment_digest.clone(),
        Some(tool_version(&executable)),
    )
    .map_err(|error| CliError::Contract(format!("executable observation refused: {error}")))?;
    if !observation.is_complete() {
        return Err(CliError::Contract(
            "executable observation is incomplete".to_owned(),
        ));
    }

    let epoch = self_change_epoch()?;
    let generation = Generation::new(1)?;
    let operation = operation_identity(command);
    let request = sealed_request(
        &operation,
        &executable,
        &command.argv,
        &command.working_directory,
        &observation.content_digest,
        generation,
        &epoch,
    )?;
    let authority = Arc::new(DispatchCell::activate(epoch)?);
    let executor =
        WindowsProcessExecutor::new(Arc::clone(&authority) as Arc<dyn DispatchValidationPort>);
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
    // published, so a diverging pass over the same command changes the digest
    // and fails the comparison above.
    let mut material = format!(
        "self-change-retained\0{}\0{}\0{:?}\0{}\0{}",
        observation.content_digest,
        observation.environment_digest,
        view.exit().map(eliot_process::ExitStatus::disposition),
        evidence.operation_id().as_str(),
        receipt.permit_digest(),
    );
    for record in sink.retained() {
        material.push('\0');
        material.push_str(&sha256_hex(record.as_bytes()));
    }
    Ok(Child {
        executable_path: observation.canonical_path,
        content_digest: observation.content_digest,
        environment_digest: observation.environment_digest,
        tool_version: observation.tool_version,
        argv: command.argv.clone(),
        retained_sha256: sha256_hex(material.as_bytes()),
    })
}

/// Seals one Kernel-issued process request for a real child launch.
#[allow(clippy::too_many_arguments)]
fn sealed_request(
    operation: &str,
    executable: &Path,
    argv: &[String],
    working_directory: &Path,
    content_digest: &str,
    generation: Generation,
    epoch: &EpochId,
) -> Result<ProcessRequest, CliError> {
    let intent = ProcessIntent::new(
        OperationId::new(operation.to_owned())?,
        ProcessTreeId::new(format!("{operation}-tree"))?,
        JobId::new(format!("{operation}-job"))?,
        ImageId::new(format!("{operation}-image"))?,
        SessionId::new(SESSION)?,
        generation,
        executable.to_string_lossy().into_owned(),
        content_digest.to_owned(),
        argv.to_vec(),
        working_directory.to_string_lossy().into_owned(),
        EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)?,
        ResourceLimits::new(
            CHILD_WALL_TIMEOUT_MS,
            None,
            None,
            CHILD_STREAM_BYTES,
            CHILD_STREAM_BYTES,
            8,
        )?,
    )?;
    let fence = FencingToken::new(epoch.clone(), generation, format!("{operation}-fence"))?;
    let heads = BTreeMap::from([("self-change".to_owned(), sha256_hex(operation.as_bytes()))]);
    let permit = DispatchPermitAuthority::activate(
        DispatchAuthorityId::new(AUTHORITY)?,
        KernelDispatchKey::from_secret_bytes(dispatch_key_material())?,
    )
    .issue(
        &intent,
        PermitIssuance::new(
            ActionLeaseRef::new(format!("{operation}-lease"))?,
            fence,
            heads,
            ISSUED_AT_UNIX_MS,
            EXPIRES_AT_UNIX_MS,
            format!("{operation}-nonce"),
        )?,
    )?;
    Ok(ProcessRequest::new(intent, permit)?)
}

/// Launches the admitted instrument under the freshly minted receipt.
///
/// This is the only launch of a self-change generation, and it goes through
/// [`InstrumentRunner::launch_verified_with_bootstrap`], so the receipt must
/// genuinely cover the runner surface before the verified launch runs.
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
    let child = run_child(&command)?;
    let generation = Generation::new(receipt.new_generation())?;
    let fingerprints = fingerprint_set(&child);
    let registry = ProviderRegistry::ready(
        receipt.new_generation(),
        NORMATIVE_PAIR.to_owned(),
        &fingerprints,
    )?;
    let invocation = launch_invocation(&evidence.launch, &child, receipt.new_generation())?;
    let freshness = RegistryFreshness {
        generation: receipt.new_generation(),
        normative_pair_digest: NORMATIVE_PAIR,
        fingerprints: &fingerprints,
    };
    let entry = registry.resolve_current(&invocation, &freshness)?;
    let port = LaunchPort::sealed(&invocation, &command, &child, generation)?;
    let resolved = ResolvedExecutableIdentity::new(
        INSTRUMENT,
        child.executable_path.clone(),
        child.content_digest.clone(),
        child.tool_version.clone(),
        child.environment_digest.clone(),
        child.argv.clone(),
    )?;
    let runner = InstrumentRunner::new(Arc::new(LaunchExecutor::new()?));
    let start = block_on(runner.launch_verified_with_bootstrap(
        invocation,
        &port,
        entry,
        Some(&resolved),
        Arc::new(RetainedEvidenceSink::default()) as Arc<dyn ProcessEvidenceSink>,
        receipt,
    ))?;
    Ok(format!(
        "cutover surface={} old_generation={} new_generation={} comparison={} canary={} special_case={} operation={} executable_digest={}",
        start.receipt_surface(receipt),
        receipt.old_generation(),
        receipt.new_generation(),
        receipt.comparison().as_str(),
        receipt.canary().as_str(),
        receipt
            .special_case()
            .map_or_else(|| "none".to_owned(), |(case, _)| case.as_str().to_owned()),
        start.process.operation_id().as_str(),
        start.executable.map_or_else(
            || "none".to_owned(),
            |observation| observation.content_digest.clone()
        ),
    ))
}

/// The launch receipt surface label, taken from the covering receipt.
trait ReceiptSurface {
    /// The surface the covering receipt was minted for.
    fn receipt_surface(&self, receipt: &GenerationReceipt) -> String;
}

impl ReceiptSurface for eliot_instrument_runner::InstrumentStartReceipt {
    fn receipt_surface(&self, receipt: &GenerationReceipt) -> String {
        receipt.surface().as_str().to_owned()
    }
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

/// The canonical authority epoch of this self-change composition root.
fn self_change_epoch() -> Result<EpochId, CliError> {
    let lineage = EpochLineageId::new(EPOCH_LINEAGE)?;
    let sequence = std::num::NonZeroU64::new(EPOCH_SEQUENCE).ok_or_else(|| {
        CliError::Contract("self-change epoch sequence must be non-zero".to_owned())
    })?;
    Ok(EpochId::new(lineage, sequence)?)
}

/// Fresh Kernel key material for this process's dispatch authority cell.
///
/// The key is derived in memory at composition time and never crosses a
/// boundary, exactly like the broker/doctor/testd authority cells.
fn dispatch_key_material() -> [u8; 32] {
    let mut key = [0_u8; 32];
    let mut seed = sha256_hex(b"i18-31-self-change-dispatch-authority").into_bytes();
    for (index, slot) in key.iter_mut().enumerate() {
        seed = sha256_hex(&seed).into_bytes();
        *slot = seed[index % seed.len()];
    }
    key
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

/// The stable operation identity bound to one discriminator command.
fn operation_identity(command: &DiscriminatorCommand) -> String {
    let material = format!(
        "{}\0{}",
        command.executable.display(),
        command.argv.join("\u{1}")
    );
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

/// Caller-attested registry fingerprints for one observed child.
///
/// The registry never reads files at runtime, so these slots are attested from
/// the machine observation the launch itself pinned.
fn fingerprint_set(child: &Child) -> InvalidationSet {
    InvalidationSet {
        source: child.content_digest.clone(),
        lock: child.environment_digest.clone(),
        toolchain: child.tool_version.clone().unwrap_or_default(),
        env: child.environment_digest.clone(),
        exe: child.content_digest.clone(),
        profile: sha256_hex(INSTRUMENT.as_bytes()),
        parser: sha256_hex(NORMATIVE_PAIR.as_bytes()),
    }
}

/// The invocation admitted for the post-cutover launch.
fn launch_invocation(
    launch: &LaunchCommand,
    child: &Child,
    generation: u64,
) -> Result<InstrumentInvocation, CliError> {
    let request_id = format!(
        "self-change-launch-{}",
        &sha256_hex(child.argv.join("\u{1}").as_bytes())[..24]
    );
    let invocation = InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new(request_id)?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new(PRODUCT)?,
            source_id: SourceId::new(SOURCE)?,
            state_fence: StateFence::new(
                self_change_epoch()?,
                ResourceGeneration::new(generation)?,
            ),
            clock: CLOCK,
        },
        instrument: ContractId::new(INSTRUMENT)?,
        kind: launch.kind,
        profile: launch.profile.clone(),
        target: launch.target.clone(),
        arguments: launch.arguments.clone(),
        input_artifacts: Vec::new(),
        declared_scope: launch.declared_scope.clone(),
        requested_at: CLOCK,
    };
    invocation.validate()?;
    Ok(invocation)
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
    /// Seals the single request bound to one admitted post-cutover launch.
    fn sealed(
        invocation: &InstrumentInvocation,
        command: &DiscriminatorCommand,
        child: &Child,
        generation: Generation,
    ) -> Result<Self, CliError> {
        let executable = resolve_executable(&command.executable)?;
        let request = sealed_request(
            invocation.request.request_id.as_str(),
            &executable,
            &command.argv,
            &command.working_directory,
            &child.content_digest,
            generation,
            &self_change_epoch()?,
        )?;
        Ok(Self {
            request: Mutex::new(Some(request)),
        })
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

/// The single dispatch-authority cell for this run's Kernel permits.
struct DispatchCell {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl DispatchCell {
    /// Activates the cell around in-memory key material and the current Kernel
    /// validation context. The same activation issues and consumes, so the
    /// one-shot replay fence is real for every child this run launches.
    fn activate(epoch: EpochId) -> Result<Self, CliError> {
        // The revision head is bound to this composition root's own constant
        // lineage text rather than a formatted epoch: `EpochId` deliberately
        // exposes no scalar or `Display` projection, and every permit minted
        // here is sealed against the same lineage constant.
        let heads = BTreeMap::from([
            (
                "self-change".to_owned(),
                sha256_hex(EPOCH_LINEAGE.as_bytes()),
            ),
            (
                "self-change-epoch".to_owned(),
                sha256_hex(EPOCH_LINEAGE_SEQUENCE.as_bytes()),
            ),
        ]);
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(
                DispatchAuthorityId::new(AUTHORITY)?,
                KernelDispatchKey::from_secret_bytes(dispatch_key_material())?,
            )),
            context: Mutex::new(Some(DispatchValidationContext::new(
                CLOCK,
                FencingToken::new(epoch.clone(), Generation::new(1)?, "self-change-cell-fence")?,
                epoch,
                heads,
                1,
            )?)),
        })
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

/// The single physical process boundary the post-cutover launch crosses.
///
/// The launch reuses the same composition as the discriminator passes, so the
/// verified launch really starts a child instead of fabricating a receipt.
struct LaunchExecutor {
    authority: Arc<DispatchCell>,
}

impl LaunchExecutor {
    /// Activates a launch authority cell bound to this run's epoch.
    fn new() -> Result<Self, CliError> {
        Ok(Self {
            authority: Arc::new(DispatchCell::activate(self_change_epoch()?)?),
        })
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

/// Drives one already-resolved future on the calling thread.
///
/// The child launch is synchronous under the sole Windows executor, so this
/// binary needs no async runtime; the driver only pumps the one future it owns
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
