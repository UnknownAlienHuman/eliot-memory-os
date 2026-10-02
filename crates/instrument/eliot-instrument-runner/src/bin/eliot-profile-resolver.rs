//! Resolves an existing authenticated bootstrap selection through the current
//! canonical instrument registry, obtains a fresh Kernel stage grant, and runs
//! the selected stage through the shared InstrumentRunner gate. The selection
//! is inert input: Kernel owner state, the original registration receipt, and
//! current WorkScope bindings decide whether execution is admitted.
//!
//! Usage: `eliot-profile-resolver --bootstrap-evidence <evidence.json>` with
//! optional receipt/parity arguments. No command, identity, epoch, executable
//! version, or process permit is created by this binary.

#![forbid(unsafe_code)]
// The canonical receipt on stdout and its fail-closed refusal on stderr are
// this entry point's operator-facing contract, the same reason
// `eliot-verifier-selfchange` carries it.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use eliot_contracts::EpochContractError;
use eliot_instrument_api::registry::{
    EnvironmentInheritanceBinding, EnvironmentProjectionBinding, EnvironmentSecretReference,
    ExternalExecutableObservation, ProcessExecutionProjection, ResolvedExecutionBinding,
    validate_external_stage,
};
use eliot_instrument_api::{InstrumentContractError, InstrumentInvocation};
use eliot_instrument_runner::{
    AdmittedProfile, CanonicalRegistryProofPort, DeclaredEnvironmentDependency, InstrumentRegistry,
    InstrumentRegistryReadClient, InstrumentRequestPort, InstrumentRunner,
    KernelInstrumentStageRuntimeObserver, ParityVerdict, PlannedStage, ProfileAggregate,
    ProfileCompiler, RegistryLaunchSelection, RunnerError, StageEnvironment, StageEvidence,
    StageLauncher, StageOrchestrator, TargetLayout, VerificationProfileReceipt,
    VerificationRouteRequest, parity_summary, registry_launch_selection, registry_state_request,
    resolve_verification_route, verify_profile_parity,
};
use eliot_ipc::KernelClient;
use eliot_kernel_service::{
    INSTRUMENT_STAGE_GRANT_OPERATION, InstrumentStageGrantRequest, InstrumentStageGrantResponse,
    KernelChildDispatchAuthority,
};
use eliot_process::{
    CancellationReceipt, EnvironmentInheritance, EnvironmentProjection, EvidenceSinkError,
    OperationId, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessRequest, ProcessStartReceipt,
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

/// The exact invocation this binary reads.
struct Request {
    /// Existing bootstrap carrier containing the authenticated current stage selection.
    selection: RegistryLaunchSelection,
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

/// Resolves one bootstrap-selected, owner-admitted route and issues its shared receipt.
fn resolve_route(request: &Request) -> Result<VerificationProfileReceipt, CliError> {
    let selection = &request.selection;
    let kernel = KernelClient::load()
        .map_err(|error| CliError::Contract(format!("Kernel front door unavailable: {error}")))?;
    let client = Arc::new(
        InstrumentRegistryReadClient::new(
            kernel,
            selection.request_identity.clone(),
            selection.scope_id.clone(),
        )
        .map_err(|error| {
            CliError::Contract(format!("canonical registry client refused: {error}"))
        })?,
    );
    let read_request = registry_state_request(
        &selection.scope_id,
        &selection.request_identity.request.state_fence,
    );
    let proof = block_on(CanonicalRegistryProofPort::retain_original(
        Arc::clone(&client),
        read_request,
    ))
    .map_err(|error| CliError::Contract(format!("original registry proof refused: {error}")))?;
    let (_, _, current) = block_on(proof.current_owner_readback())
        .map_err(|error| CliError::Contract(format!("current registry read refused: {error}")))?;
    let encoded_snapshot = current
        .payload
        .get("snapshot_json")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CliError::Contract("current registry row omitted its snapshot".to_owned())
        })?;
    let registry = InstrumentRegistry::recover(encoded_snapshot)?;
    let snapshot: eliot_instrument_api::registry::InstrumentRegistrySnapshot<serde_json::Value> =
        serde_json::from_str(encoded_snapshot).map_err(|error| {
            CliError::Contract(format!("current registry snapshot is invalid: {error}"))
        })?;
    let alias = PROFILE_ALIASES
        .iter()
        .find(|entry| {
            entry.profile == selection.pin.profile
                && entry.revision == selection.pin.profile_revision
        })
        .ok_or_else(|| {
            CliError::Contract(
                "selected profile revision has no verification receipt route".to_owned(),
            )
        })?;
    let admitted = ProfileCompiler::new(&registry)
        .compile_exact(&selection.pin.profile, selection.pin.profile_revision)?;
    let profile = registry.admitted(&selection.pin.profile, selection.pin.profile_revision)?;
    let environment = StageEnvironment::attest_projection(
        profile.classes.environment.clone(),
        selection.intent.environment().clone(),
    )?;
    let layout = TargetLayout::new(
        selection.layout.source_root.clone(),
        selection.layout.target_root.clone(),
        selection.layout.cache_root.clone(),
    )?;
    let resolved = ProfileCompiler::new(&registry).resolve_full(
        &selection.pin.profile,
        selection.pin.profile_revision,
        layout.clone(),
        selection.work_scope.clone(),
        environment.clone(),
    )?;
    let plan = StageOrchestrator::plan_resolved(&admitted, &resolved)?;
    if plan.stages.len() != 1 || plan.stages[0].route.stage().stage_id != selection.pin.stage_id {
        return Err(CliError::Contract(
            "a single bootstrap ProcessIntent can resolve only a profile plan containing exactly its selected stage".to_owned(),
        ));
    }
    let planned = plan
        .stages
        .iter()
        .find(|stage| {
            stage.stage.profile == selection.pin.profile
                && stage.stage.profile_revision == selection.pin.profile_revision
                && stage.stage.stage_id == selection.pin.stage_id
        })
        .ok_or_else(|| {
            CliError::Contract(
                "bootstrap selection does not match a current profile stage".to_owned(),
            )
        })?;
    let resolution = planned.resolution.as_ref().ok_or_else(|| {
        CliError::Contract("selected external stage omitted its resolved owner binding".to_owned())
    })?;
    if selection.intent.working_directory() != resolution.layout.source_root
        || selection.work_scope.declared_scope != resolution.scope.declared_scope
    {
        return Err(CliError::Contract(
            "bootstrap process intent differs from the retained profile resolution".to_owned(),
        ));
    }
    let invocation = InstrumentInvocation {
        request: selection.request_identity.request.metadata.clone(),
        instrument: planned.stage.spec.clone(),
        kind: planned.stage.kind,
        profile: planned.stage.profile.clone(),
        target: resolution.layout.source_root.clone(),
        arguments: planned.stage.argument_template.clone(),
        input_artifacts: Vec::new(),
        declared_scope: resolution.scope.declared_scope.clone(),
        requested_at: selection.request_identity.request.metadata.clock,
    };
    invocation.validate()?;
    let observed =
        ExecutableObservation::observe_from_intent(&selection.intent, None).map_err(|error| {
            CliError::Contract(format!("external executable observation refused: {error}"))
        })?;
    let observed_file_identity = observed.file_identity.ok_or_else(|| {
        CliError::Contract(
            "external executable observation has no owner-observed file identity".to_owned(),
        )
    })?;
    let mut identity = ResolvedExecutableIdentity::new(
        invocation.instrument.as_str(),
        observed.canonical_path,
        observed.content_digest,
        None,
        environment_projection_digest(selection.intent.environment()),
        selection.intent.argv().to_vec(),
    )?;
    identity.file_identity = Some(observed_file_identity);
    identity.tool_version =
        StageOrchestrator::recorded_tool_version(&registry, &planned.stage, &identity)?;
    let admission_intent = selection
        .intent
        .clone()
        .with_executable_file_identity(observed_file_identity)?;
    let expected_admission = validate_external_stage(
        &snapshot,
        &selection.pin,
        &invocation,
        &ExternalExecutableObservation {
            canonical_path: identity.canonical_path.clone(),
            executable_file_name: identity.executable_file_name(),
            content_digest: identity.content_digest.clone(),
            file_identity: observed_file_identity,
            tool_version: identity.tool_version.clone(),
        },
        selection.intent.argv(),
        &ResolvedExecutionBinding {
            source_root: resolution.layout.source_root.clone(),
            environment_class: resolution.environment.class.clone(),
            environment_digest: resolution.environment.digest.clone(),
            environment_projection: environment_projection_binding(
                &resolution.environment.projection.clone().ok_or_else(|| {
                    CliError::Contract("resolved environment projection is absent".to_owned())
                })?,
            ),
            declared_scope: resolution.scope.declared_scope.clone(),
            authority_epoch: resolution.scope.fence.authority_epoch.clone(),
            resource_generation: resolution.scope.fence.resource_generation.value(),
        },
        &process_projection(selection, &admission_intent)?,
    )
    .map_err(|error| {
        CliError::Contract(format!(
            "canonical external-stage admission refused: {error}"
        ))
    })?;
    let intent =
        admission_intent.with_instrument_admission_digest(expected_admission.digest.clone())?;
    let grant_request = InstrumentStageGrantRequest {
        scope_id: selection.scope_id.clone(),
        pin: selection.pin.clone(),
        invocation: invocation.clone(),
        resolution: ResolvedExecutionBinding {
            source_root: resolution.layout.source_root.clone(),
            environment_class: resolution.environment.class.clone(),
            environment_digest: resolution.environment.digest.clone(),
            environment_projection: environment_projection_binding(
                &resolution.environment.projection.clone().ok_or_else(|| {
                    CliError::Contract("resolved environment projection is absent".to_owned())
                })?,
            ),
            declared_scope: resolution.scope.declared_scope.clone(),
            authority_epoch: resolution.scope.fence.authority_epoch.clone(),
            resource_generation: resolution.scope.fence.resource_generation.value(),
        },
        intent,
    };
    grant_request
        .validate_admission_binding(&expected_admission)
        .map_err(|error| {
            CliError::Contract(format!(
                "local Kernel stage request binding refused: {error}"
            ))
        })?;
    let grant_value = serde_json::to_value(&grant_request)?;
    let authenticated = block_on(client.transact_json_authenticated_async(
        INSTRUMENT_STAGE_GRANT_OPERATION,
        grant_value,
        selection.request_identity.clone(),
    ))
    .map_err(|error| CliError::Contract(format!("Kernel stage grant refused: {error}")))?;
    let response: InstrumentStageGrantResponse =
        serde_json::from_value(authenticated.payload().clone())?;
    if authenticated.operation() != INSTRUMENT_STAGE_GRANT_OPERATION
        || authenticated.request_identity() != &selection.request_identity
        || response.admission != expected_admission
    {
        return Err(CliError::Contract(
            "authenticated Kernel stage grant differs from the exact canonical admission"
                .to_owned(),
        ));
    }
    let observation_client = KernelClient::load().map_err(|error| {
        CliError::Contract(format!(
            "Kernel instrument-stage runtime observer unavailable: {error}"
        ))
    })?;
    let runtime_observer = Arc::new(KernelInstrumentStageRuntimeObserver::new(
        observation_client,
    ));
    let authority = Arc::new(KernelChildDispatchAuthority::new_with_observation_port(
        runtime_observer,
    )?);
    let process_request = authority.issue_authenticated(
        &grant_request,
        &selection.request_identity,
        authenticated,
        now_unix_ms().max(1),
    )?;
    let process_operation_id = process_request.operation_id().clone();
    let process_request_digest = process_request.invocation_digest().to_owned();
    let port = StagePort::for_selection(&invocation, process_request);
    let launcher = StageRoute {
        invocation,
        selected_stage_id: selection.pin.stage_id.clone(),
        selected_profile_revision: selection.pin.profile_revision,
        port,
    };
    let executor = Arc::new(StageExecutor::with_kernel_authority(Arc::clone(&authority)));
    let runner = InstrumentRunner::new(Arc::clone(&executor));
    let runs = block_on(StageOrchestrator::launch_plan_live(
        &runner, &registry, &plan, &launcher, &proof,
    ));
    let aggregate = ProfileAggregate::assemble(&plan, runs);
    require_launched_stage(&admitted, &aggregate)?;
    let terminal_evidence = executor
        .executor()
        .wait_for_terminal_evidence(process_operation_id.clone())
        .map_err(|error| {
            CliError::Contract(format!(
                "instrument stage terminal supervision refused: {error}"
            ))
        })?;
    if terminal_evidence.view().operation_id() != &process_operation_id
        || terminal_evidence.view().request_digest() != process_request_digest.as_str()
        || !eliot_instrument_runner::process_evidence_reports_terminal_or_transport_failure(
            &terminal_evidence,
        )
    {
        return Err(CliError::Contract(
            "instrument stage terminal evidence differs from the original process request"
                .to_owned(),
        ));
    }
    authority
        .report_terminal(&terminal_evidence)
        .map_err(|error| {
            CliError::Contract(format!(
                "authenticated instrument stage terminal report refused: {error}"
            ))
        })?;
    let scope = selection.work_scope.clone();
    let dependencies = request
        .declared_environments
        .iter()
        .map(|name| {
            Ok(DeclaredEnvironmentDependency::new(
                name.clone(),
                profile.classes.environment.clone(),
                &environment,
            )?)
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let receipt = resolve_verification_route(
        registry.generation(),
        VerificationRouteRequest {
            receipts: snapshot.receipts.clone(),
            route: alias.alias.to_owned(),
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

fn process_projection(
    selection: &RegistryLaunchSelection,
    intent: &ProcessIntent,
) -> Result<ProcessExecutionProjection, CliError> {
    let executable_file_identity = intent.executable_file_identity().copied().ok_or_else(|| {
        CliError::Contract(
            "process projection has no owner-observed executable file identity".to_owned(),
        )
    })?;
    let limits = intent.resource_limits();
    Ok(ProcessExecutionProjection {
        working_directory: intent.working_directory().to_owned(),
        environment_digest: environment_projection_digest(intent.environment()),
        environment_projection: environment_projection_binding(intent.environment()),
        executable_file_identity,
        authority_epoch: selection
            .request_identity
            .request
            .state_fence
            .authority_epoch
            .clone(),
        resource_generation: intent.generation().get(),
        wall_timeout_ms: limits.wall_timeout_ms(),
        stdout_bytes: limits.stdout_bytes(),
        stderr_bytes: limits.stderr_bytes(),
    })
}

fn environment_projection_binding(
    projection: &EnvironmentProjection,
) -> EnvironmentProjectionBinding {
    EnvironmentProjectionBinding {
        non_secret: projection.non_secret().clone(),
        secret_refs: projection
            .secret_refs()
            .iter()
            .map(|reference| EnvironmentSecretReference {
                provider: reference.provider().to_owned(),
                key: reference.key().to_owned(),
            })
            .collect(),
        inheritance: match projection.inheritance() {
            EnvironmentInheritance::None => EnvironmentInheritanceBinding::None,
            EnvironmentInheritance::Allowlisted => EnvironmentInheritanceBinding::Allowlisted,
        },
    }
}

/// Requires at least one admitted stage to have really launched.
///
/// A run in which no stage produced a run record would hand the receipt builder
/// an aggregate whose every stage is missing, and the only honest outcome of
/// that is a refusal: a receipt cannot record a tool identity for a tool that
/// never ran, so this entry fails closed instead of printing one. This is a
/// reachability guard on the receipt, not a verdict — the aggregate's own
/// normalized outcome still decides PASS.
///
/// The guard is NOT the diagnostic. Before it reduces the outcome to "launched
/// no admitted stage", it reports what each stage's own run record already
/// carries: every run whose evidence is `Missing` or `Omitted` is a refusal this
/// run observed, and its exact reason text travels out with the refusal. A
/// reader is therefore told WHICH stage refused and WHY, rather than only that
/// the route launched nothing. The zero-launch verdict is unchanged and no
/// refusal is dropped to reach it: a run that launched at least one stage still
/// reports no per-stage reasons here, because this is a zero-launch guard and
/// not a general stage report.
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

/// Renders each refused stage's existing run record as one reported reason.
///
/// This reads the aggregate the orchestrator already assembled; it computes
/// nothing new and launches nothing. Every run is rendered, whether it launched
/// a tool or not, so a stage that failed with a non-empty executable identity
/// still contributes its execution axis and outcome to the report. A run with a
/// concrete missing/omitted reason reports that exact reason; a launched run
/// reports the outcome it actually reached, so the report never claims a stage
/// refused when it in fact ran.
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
            StageEvidence::Transformed {
                source_artifact,
                result_digest,
                ..
            } => format!(
                "pure transform succeeded from retained artifact '{}' with result {}",
                source_artifact.as_str(),
                result_digest
            ),
        };
        reported.push(format!("stage '{stage_id}' {reason}"));
    }
    format!("per-stage refusals: [{}]", reported.join("; "))
}

/// Reads the exact invocation text this binary accepts.
///
/// Every field is required and none is defaulted: a missing root, a missing
/// alias, or an unknown option is a refusal rather than a substituted value.
fn read_request() -> Result<Request, CliError> {
    let mut args = std::env::args().skip(1);
    let mut bootstrap_evidence = None;
    let mut declared_environments = Vec::new();
    let mut receipt_out = None;
    let mut compare_against = None;
    while let Some(option) = args.next() {
        let mut value = |option: &str| {
            args.next()
                .ok_or_else(|| CliError::Usage(format!("{option} requires a value")))
        };
        match option.as_str() {
            "--bootstrap-evidence" => {
                bootstrap_evidence = Some(PathBuf::from(value("--bootstrap-evidence")?))
            }
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
    let evidence_path = bootstrap_evidence.ok_or_else(|| {
        CliError::Usage("--bootstrap-evidence is required; it must contain the existing launch.registry_selection carrier".to_owned())
    })?;
    let evidence_bytes = std::fs::read(&evidence_path).map_err(|error| {
        CliError::Contract(format!(
            "bootstrap evidence {} could not be read: {error}",
            evidence_path.display()
        ))
    })?;
    let evidence: serde_json::Value = serde_json::from_slice(&evidence_bytes)
        .map_err(|error| CliError::Contract(format!("bootstrap evidence is invalid: {error}")))?;
    let selection_value = evidence
        .pointer("/launch/registry_selection")
        .ok_or_else(|| {
            CliError::Contract("bootstrap evidence omitted launch.registry_selection".to_owned())
        })?;
    let selection = registry_launch_selection(selection_value).map_err(|error| {
        CliError::Contract(format!("bootstrap stage selection refused: {error}"))
    })?;
    Ok(Request {
        selection,
        declared_environments,
        receipt_out,
        compare_against,
    })
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

/// Machine clock reading in Unix milliseconds, observed now.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

struct StageExecutor {
    /// One executor retains the operation registry across the full lifecycle.
    executor: WindowsProcessExecutor,
}

impl StageExecutor {
    fn with_kernel_authority(authority: Arc<KernelChildDispatchAuthority>) -> Self {
        Self {
            executor: WindowsProcessExecutor::new(authority as Arc<dyn DispatchValidationPort>),
        }
    }

    /// Lifecycle operations stay on the same executor that started the child.
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
        #[cfg(all(test, windows))]
        start_observer::record(request.operation_id().as_str());
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
    /// Exact invocation sealed by the authenticated Kernel grant.
    invocation: InstrumentInvocation,
    /// One stage identity selected by the existing bootstrap carrier.
    selected_stage_id: String,
    /// Exact profile revision selected by the existing bootstrap carrier.
    selected_profile_revision: u64,
    /// Request port holding the exact one-shot request returned by Kernel.
    port: StagePort,
}

/// The per-stage launch provisions the orchestrator binds one stage through.
///
/// The sealed requests are keyed by the exact durable stage identity the
/// orchestrator walks, so a bind for a stage this run never sealed fails closed
/// instead of producing a request for whatever stage happens to come next.
struct StagePort {
    /// One-shot Kernel request indexed by its original operation identity.
    sealed: std::sync::Mutex<BTreeMap<String, ProcessRequest>>,
    /// Evidence sink every stage launch retains through.
    sink: Arc<RetainedEvidenceSink>,
}

impl StagePort {
    fn for_selection(invocation: &InstrumentInvocation, request: ProcessRequest) -> Self {
        Self {
            sealed: std::sync::Mutex::new(BTreeMap::from([(
                invocation.request.request_id.as_str().to_owned(),
                request,
            )])),
            sink: Arc::new(RetainedEvidenceSink::default()),
        }
    }
}

impl InstrumentRequestPort for StagePort {
    /// Consumes the exact Kernel-issued request once.
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
        if stage_id != self.selected_stage_id
            || stage.route.stage().profile != self.invocation.profile
            || stage.stage.spec != self.invocation.instrument
            || stage.route.stage().profile_revision != self.selected_profile_revision
        {
            return Err(RunnerError::Binding(format!(
                "bootstrap carries no Kernel request for profile stage '{stage_id}'"
            )));
        }
        Ok(self.invocation.clone())
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

#[cfg(all(test, windows))]
mod start_observer {
    use std::collections::BTreeMap;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static SERIAL: Mutex<()> = Mutex::new(());
    static STARTS: OnceLock<Mutex<BTreeMap<String, usize>>> = OnceLock::new();

    fn starts() -> &'static Mutex<BTreeMap<String, usize>> {
        STARTS.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    pub(super) fn serialize() -> MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn clear(operation_id: &str) {
        let _ = starts()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(operation_id);
    }

    pub(super) fn record(operation_id: &str) {
        let mut starts = starts()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *starts.entry(operation_id.to_owned()).or_default() += 1;
    }

    pub(super) fn count(operation_id: &str) -> usize {
        starts()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(operation_id)
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(all(test, windows))]
mod live_acceptance_tests {
    use super::{
        CliError, InstrumentRegistry, InstrumentRegistryReadClient, KernelClient, ProfileCompiler,
        RegistryLaunchSelection, Request, RunnerError, VerificationProfileReceipt, block_on,
        environment_projection_digest, registry_launch_selection, registry_state_request,
        resolve_route, start_observer,
    };
    use eliot_instrument_runner::CanonicalRegistryProofPort;
    use eliot_process::ProcessIntent;
    use std::sync::Arc;

    const ACCEPTANCE_FIXTURE_ENV: &str = "ELIOT_PROFILE_RESOLVER_LIVE_ACCEPTANCE_FIXTURE";
    const ARGUMENT_REFUSAL_FIXTURE_ENV: &str =
        "ELIOT_PROFILE_RESOLVER_LIVE_ARGUMENT_REFUSAL_FIXTURE";
    const EXECUTABLE_REFUSAL_FIXTURE_ENV: &str =
        "ELIOT_PROFILE_RESOLVER_LIVE_EXECUTABLE_REFUSAL_FIXTURE";

    /// Requires three original owner-issued current-stage bootstrap fixtures:
    /// one positive and distinct-operation argument/executable refutations.
    /// Each file is the production JSON carrier whose selection is at
    /// `/launch/registry_selection` and has exactly `request_identity`,
    /// `scope_id`, `pin`, `layout`, `work_scope`, and `intent`. All selections
    /// must name the same current canonical profile/stage/fence; each operation
    /// identity is owner-issued and distinct. The files are selected by
    /// `ELIOT_PROFILE_RESOLVER_LIVE_ACCEPTANCE_FIXTURE`,
    /// `ELIOT_PROFILE_RESOLVER_LIVE_ARGUMENT_REFUSAL_FIXTURE`, and
    /// `ELIOT_PROFILE_RESOLVER_LIVE_EXECUTABLE_REFUSAL_FIXTURE`. This test uses
    /// the same `registry_launch_selection` parser as `read_request`, which
    /// consumes the operator's `--bootstrap-evidence` selection; each call to
    /// `resolve_route` authenticates the current canonical registry read and
    /// stage-grant exchange against the original Governor registration before
    /// reaching the real `WindowsProcessExecutor`.
    /// Missing or malformed evidence is an error, never a skipped assertion
    /// or passing return.
    #[test]
    #[ignore = "requires OR-provisioned live Kernel registry, WorkScope, and admitted external-stage fixtures"]
    fn live_registered_stage_acceptance_and_field_refusals() -> Result<(), String> {
        let _serialized = start_observer::serialize();
        let accepted = request_from_original_fixture(ACCEPTANCE_FIXTURE_ENV)?;
        let mut changed_arguments = request_from_original_fixture(ARGUMENT_REFUSAL_FIXTURE_ENV)?;
        let mut changed_executable = request_from_original_fixture(EXECUTABLE_REFUSAL_FIXTURE_ENV)?;
        let original_argument_selection = changed_arguments.selection.clone();

        assert_same_original_stage(
            &accepted.selection,
            &changed_arguments.selection,
            &changed_executable.selection,
        );
        let accepted_operation = operation_id(&accepted.selection);
        let arguments_operation = operation_id(&changed_arguments.selection);
        let executable_operation = operation_id(&changed_executable.selection);
        assert_ne!(accepted_operation, arguments_operation);
        assert_ne!(accepted_operation, executable_operation);
        assert_ne!(arguments_operation, executable_operation);

        let canonical = current_registry(&accepted.selection)?;
        let admitted = ProfileCompiler::new(&canonical)
            .compile_exact(
                &accepted.selection.pin.profile,
                accepted.selection.pin.profile_revision,
            )
            .map_err(|error| error.to_string())?;
        let admitted_stage = admitted
            .stages
            .iter()
            .find(|stage| stage.stage_id == accepted.selection.pin.stage_id)
            .ok_or("owner-pinned stage is missing from the current admitted profile")?;
        assert!(admitted_stage.external);
        assert!(!admitted_stage.parser.as_str().is_empty());
        assert!(admitted_stage.parser_generation > 0);
        let supply_receipt = admitted_stage
            .supply_receipt
            .as_ref()
            .ok_or("owner-pinned stage omitted its supply-chain receipt")?;
        assert_eq!(supply_receipt.generation, canonical.generation());
        assert_eq!(
            accepted.selection.intent.working_directory(),
            accepted.selection.layout.source_root.as_str()
        );

        start_observer::clear(&accepted_operation);
        let receipt = resolve_route(&accepted).map_err(|error| error.to_string())?;
        assert_eq!(start_observer::count(&accepted_operation), 1);
        assert_admission_receipt_matches(
            &receipt,
            &accepted.selection,
            &canonical,
            &admitted,
            admitted_stage,
            supply_receipt,
        )?;

        let unregistered_kind_operation = arguments_operation.clone();
        start_observer::clear(&unregistered_kind_operation);
        let mut unregistered_kind_evidence = fixture_evidence(ARGUMENT_REFUSAL_FIXTURE_ENV)?;
        // The launch carrier has no caller-selected kind field: the live
        // registry derives that identity from its pinned profile stage. Reject
        // an attempted extra `kind_id` at the closed parser boundary instead
        // of adding a synthetic field to the production carrier.
        let selected_pin = unregistered_kind_evidence
            .pointer_mut("/launch/registry_selection/pin")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("argument-refusal fixture pin is not an object")?;
        assert!(
            selected_pin
                .insert(
                    "kind_id".to_owned(),
                    serde_json::Value::String("unregistered-kind".to_owned()),
                )
                .is_none()
        );
        let selected = unregistered_kind_evidence
            .pointer("/launch/registry_selection")
            .ok_or("argument-refusal fixture omitted its launch selection")?;
        match registry_launch_selection(selected) {
            Err(RunnerError::Binding(detail))
                if detail.contains("pin") && detail.contains("kind_id") => {}
            Err(error) => {
                return Err(format!(
                    "closed-schema kind-field refusal had the wrong reason: {error}"
                ));
            }
            Ok(_) => return Err("unsupported kind field was accepted".to_owned()),
        }
        assert_eq!(start_observer::count(&unregistered_kind_operation), 0);

        changed_arguments.selection.intent = changed_intent(
            &original_argument_selection,
            original_argument_selection.intent.executable().to_owned(),
            {
                let mut argv = original_argument_selection.intent.argv().to_vec();
                argv.push("--unadmitted-argument".to_owned());
                argv
            },
        )?;
        start_observer::clear(&arguments_operation);
        match resolve_route(&changed_arguments) {
            Err(CliError::Contract(detail))
                if detail.contains(
                    "canonical external-stage admission refused: arguments or executable argv differ from the canonical fixed template",
                ) => {}
            Err(error) => {
                return Err(format!(
                    "changed-argument request failed for the wrong reason: {error}"
                ));
            }
            Ok(_) => return Err("changed arguments were admitted".to_owned()),
        }
        assert_eq!(start_observer::count(&arguments_operation), 0);

        changed_arguments.selection.intent = changed_intent(
            &original_argument_selection,
            original_argument_selection.intent.executable().to_owned(),
            {
                let mut argv = original_argument_selection.intent.argv().to_vec();
                argv.push("&& whoami".to_owned());
                argv
            },
        )?;
        start_observer::clear(&arguments_operation);
        match resolve_route(&changed_arguments) {
            Err(CliError::Contract(detail))
                if detail.contains(
                    "canonical external-stage admission refused: arguments or executable argv differ from the canonical fixed template",
                ) => {}
            Err(error) => {
                return Err(format!(
                    "raw-shell request failed for the wrong reason: {error}"
                ));
            }
            Ok(_) => return Err("raw-shell argument was admitted".to_owned()),
        }
        assert_eq!(start_observer::count(&arguments_operation), 0);

        let changed_path = format!(
            "{}.unadmitted",
            changed_executable.selection.intent.executable()
        );
        changed_executable.selection.intent = changed_intent(
            &changed_executable.selection,
            changed_path,
            changed_executable.selection.intent.argv().to_vec(),
        )?;
        start_observer::clear(&executable_operation);
        match resolve_route(&changed_executable) {
            Err(CliError::Contract(detail))
                if detail.starts_with("external executable observation refused:") => {}
            Err(error) => {
                return Err(format!(
                    "changed-executable request failed for the wrong reason: {error}"
                ));
            }
            Ok(_) => return Err("changed executable identity was admitted".to_owned()),
        }
        assert_eq!(start_observer::count(&executable_operation), 0);

        Ok(())
    }

    fn fixture_evidence(env_name: &str) -> Result<serde_json::Value, String> {
        let path = std::env::var_os(env_name)
            .ok_or_else(|| format!("required live fixture variable {env_name} is absent"))?;
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }

    fn request_from_original_fixture(env_name: &str) -> Result<Request, String> {
        let evidence = fixture_evidence(env_name)?;
        let selection = evidence
            .pointer("/launch/registry_selection")
            .ok_or("bootstrap fixture omits /launch/registry_selection")?;
        let selection = registry_launch_selection(selection).map_err(|error| error.to_string())?;
        Ok(Request {
            selection,
            declared_environments: Vec::new(),
            receipt_out: None,
            compare_against: None,
        })
    }

    fn current_registry(selection: &RegistryLaunchSelection) -> Result<InstrumentRegistry, String> {
        let kernel = KernelClient::load().map_err(|error| error.to_string())?;
        let client = Arc::new(
            InstrumentRegistryReadClient::new(
                kernel,
                selection.request_identity.clone(),
                selection.scope_id.clone(),
            )
            .map_err(|error| error.to_string())?,
        );
        let read_request = registry_state_request(
            &selection.scope_id,
            &selection.request_identity.request.state_fence,
        );
        let proof = block_on(CanonicalRegistryProofPort::retain_original(
            Arc::clone(&client),
            read_request,
        ))
        .map_err(|error| error.to_string())?;
        let (_, _, current) =
            block_on(proof.current_owner_readback()).map_err(|error| error.to_string())?;
        let encoded_snapshot = current
            .payload
            .get("snapshot_json")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "current canonical owner read has no registry snapshot".to_owned())?;
        InstrumentRegistry::recover(encoded_snapshot).map_err(|error| error.to_string())
    }

    fn changed_intent(
        selection: &RegistryLaunchSelection,
        executable: String,
        argv: Vec<String>,
    ) -> Result<ProcessIntent, String> {
        let original = &selection.intent;
        ProcessIntent::new(
            original.operation_id().clone(),
            original.process_tree_id().clone(),
            original.job_id().clone(),
            original.image_id().clone(),
            original.session_id().clone(),
            original.generation(),
            executable,
            original.executable_sha256().to_owned(),
            argv,
            original.working_directory().to_owned(),
            original.environment().clone(),
            original.resource_limits().clone(),
        )
        .map_err(|error| error.to_string())
    }

    fn operation_id(selection: &RegistryLaunchSelection) -> String {
        selection.intent.operation_id().as_str().to_owned()
    }

    fn assert_same_original_stage(
        accepted: &RegistryLaunchSelection,
        changed_arguments: &RegistryLaunchSelection,
        changed_executable: &RegistryLaunchSelection,
    ) {
        for candidate in [changed_arguments, changed_executable] {
            assert_eq!(candidate.scope_id, accepted.scope_id);
            assert_eq!(candidate.pin, accepted.pin);
            assert_eq!(candidate.layout, accepted.layout);
            assert_eq!(candidate.work_scope, accepted.work_scope);
            assert_eq!(candidate.intent.executable(), accepted.intent.executable());
            assert_eq!(
                candidate.intent.executable_sha256(),
                accepted.intent.executable_sha256()
            );
            assert_eq!(candidate.intent.argv(), accepted.intent.argv());
            assert_eq!(
                candidate.intent.working_directory(),
                accepted.intent.working_directory()
            );
            assert_eq!(
                candidate.intent.environment(),
                accepted.intent.environment()
            );
            assert_eq!(
                candidate.intent.resource_limits(),
                accepted.intent.resource_limits()
            );
        }
    }

    fn assert_admission_receipt_matches(
        receipt: &VerificationProfileReceipt,
        selection: &RegistryLaunchSelection,
        registry: &InstrumentRegistry,
        admitted: &eliot_instrument_runner::AdmittedProfile,
        stage: &eliot_instrument_runner::AdmittedStage,
        supply_receipt: &eliot_instrument_api::registry::SupplyChainReceipt,
    ) -> Result<(), String> {
        assert_eq!(
            receipt.outcome,
            eliot_instrument_runner::AggregateOutcome::Unknown,
            "a live launch without retained parser evidence remains Unknown"
        );
        assert_eq!(receipt.profile.as_str(), selection.pin.profile.as_str());
        assert_eq!(receipt.profile_revision, selection.pin.profile_revision);
        assert_eq!(receipt.profile_revision, admitted.revision);
        assert_eq!(
            receipt.profile_digest.as_str(),
            admitted.profile_digest.as_str()
        );
        assert_eq!(receipt.dag_digest.as_str(), admitted.dag_digest.as_str());
        assert_eq!(registry.generation(), selection.pin.registry_generation);
        assert_eq!(receipt.runs.len(), 1);
        let run = receipt
            .runs
            .first()
            .ok_or_else(|| "accepted route has no stage receipt".to_owned())?;
        assert_eq!(run.stage_id, selection.pin.stage_id);
        assert_eq!(run.execution, "Accepted");
        assert!(matches!(
            &run.evidence,
            eliot_instrument_runner::StageEvidenceRecord::Omitted { reason }
                if reason == "launched; terminal observation is owned by the supervising lane"
        ));
        assert!(run.executable_digest.is_some());
        assert!(run.grant_digest.is_some());
        let tool = receipt
            .tool_identities
            .iter()
            .find(|tool| tool.stage_id == selection.pin.stage_id)
            .ok_or_else(|| "accepted receipt omitted the selected tool identity".to_owned())?;
        assert_eq!(tool.instrument.as_str(), stage.spec.as_str());
        assert_eq!(tool.executable.as_str(), selection.intent.executable());
        assert_eq!(tool.executable_digest, run.executable_digest);
        assert_eq!(tool.grant_digest, run.grant_digest);
        let provenance = tool.provenance.as_ref().ok_or_else(|| {
            "accepted receipt omitted the original supply-chain provenance".to_owned()
        })?;
        assert_eq!(provenance.spec_digest, stage.spec_digest);
        assert_eq!(
            provenance.content_digest.as_str(),
            selection.intent.executable_sha256()
        );
        assert_eq!(provenance.generation, registry.generation());
        assert_eq!(provenance.content_digest, supply_receipt.content_digest);
        assert_eq!(provenance.tool_version, supply_receipt.tool_version);

        let admission = run
            .admission_grant
            .as_ref()
            .ok_or_else(|| "accepted run omitted the original admission grant".to_owned())?;
        assert_eq!(admission.digest(), admission.grant_digest);
        assert_eq!(
            run.grant_digest.as_deref(),
            Some(admission.grant_digest.as_str())
        );
        assert_eq!(admission.kind_id.as_str(), stage.spec.as_str());
        assert_eq!(admission.kind, stage.kind);
        assert_eq!(admission.profile.as_str(), selection.pin.profile.as_str());
        assert_eq!(admission.profile_revision, selection.pin.profile_revision);
        assert_eq!(admission.spec_digest.as_str(), stage.spec_digest.as_str());
        assert_eq!(
            admission.executable.as_str(),
            supply_receipt.executable.as_str()
        );
        assert_eq!(
            admission.content_digest.as_str(),
            supply_receipt.content_digest.as_str()
        );
        assert_eq!(admission.executable_version, stage.executable_version);
        assert_eq!(admission.executable_path, tool.executable);
        assert_eq!(admission.supply_digest, supply_receipt.digest());
        assert_eq!(admission.arguments.as_slice(), selection.intent.argv());
        assert_eq!(admission.arguments.as_slice(), stage.verification_command);
        assert_eq!(
            admission.environment_class.as_str(),
            stage.environment_class.as_str()
        );
        assert_eq!(
            admission.source_root.as_deref(),
            Some(selection.layout.source_root.as_str())
        );
        assert_eq!(
            admission.declared_scope.as_deref(),
            Some(selection.work_scope.declared_scope.as_str())
        );
        let expected_environment_digest =
            environment_projection_digest(selection.intent.environment());
        assert_eq!(
            admission.environment_digest.as_deref(),
            Some(expected_environment_digest.as_str())
        );
        assert_eq!(
            admission.resource_generation,
            Some(selection.work_scope.fence.resource_generation.value())
        );
        assert_eq!(
            admission.authority_epoch.as_ref(),
            Some(&selection.work_scope.fence.authority_epoch)
        );
        assert_eq!(admission.parser, stage.parser);
        assert_eq!(admission.parser_generation, stage.parser_generation);
        assert_eq!(admission.timeout_ms, stage.timeout_ms);
        assert_eq!(admission.max_output_bytes, stage.max_output_bytes);
        let credential_policy = stage
            .credential_policy
            .as_ref()
            .ok_or_else(|| "admitted stage omitted its credential policy".to_owned())?;
        assert_eq!(
            admission.credential_policy.as_str(),
            credential_policy.as_str()
        );
        let network_policy = stage
            .network_policy
            .as_ref()
            .ok_or_else(|| "admitted stage omitted its network policy".to_owned())?;
        assert_eq!(admission.network_policy.as_str(), network_policy.as_str());
        let max_concurrency = stage
            .max_concurrency
            .ok_or_else(|| "admitted stage omitted its concurrency ceiling".to_owned())?;
        assert_eq!(admission.max_concurrency, max_concurrency);
        assert_eq!(supply_receipt.generation, selection.pin.registry_generation);
        Ok(())
    }
}
#[cfg(all(test, windows))]
#[path = "eliot-profile-resolver/provider_registry_physical.rs"]
mod provider_registry_physical;
