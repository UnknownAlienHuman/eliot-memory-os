//! The single bounded execution boundary for governed instruments.
//!
//! This crate owns orchestration, not physical effects.  A composition root
//! supplies an admitted [`InstrumentRequestPort`] and the production
//! [`eliot_process::ProcessExecutor`].  The runner validates every hand-off,
//! preserves request identity and generation, and never converts process
//! failure into semantic verification evidence.

#![forbid(unsafe_code)]

use std::sync::Arc;

use eliot_instrument_api::{ExecutionStatus, InstrumentInvocation};
use eliot_process::{
    CancellationReceipt, ExitDisposition, ExitStatus, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

pub mod cache_lane;
pub mod process_owner;
pub mod profile;
pub mod profile_run;
pub mod registry;
pub mod testd_port;

pub use cache_lane::{CacheLane, CacheLaneAttestations, CacheLaneError, LaneOutcome};
pub use process_owner::{
    KernelAdmissionError, KernelAdmittedProcess, KernelInstrumentAdmission,
    KernelInstrumentRequestPort,
};
pub use profile::{
    AdmittedProfile, AdmittedStage, BUILTIN_PROFILE_REVISION, BUILTIN_SPEC_VERSION,
    COMPILER_PROFILE, CompiledProfile, InstrumentProfile, InstrumentProfileResolver,
    InstrumentRegistry, InstrumentSpec, ProfileCompiler, ProfileError, ProfileScopeClasses,
    ResolvedProfile, ResolvedStage, StageDag, StageDecl, StageEnvironment, TEST_PROFILE,
    TargetLayout, WorkScope,
};
pub use profile_run::{
    AggregateStatus, InstrumentRun, MappedStageLauncher, PlannedStage, ProfileAggregate,
    ProfileRunError, StageEvidence, StageIdentity, StageLauncher, StageOrchestrator, StagePlan,
    TestExecutionPlaneRoute, TestdPlaneAdmission,
};
pub use registry::{
    ExecutableIdentityCause, ProviderRegistry, RegistryEntry, RegistryError,
    ResolvedExecutableIdentity,
};
pub use testd_port::{
    OmissionReason, RawEvidence, TestdAdmission, TestdAdmissionPort, TestdPortError,
};

/// Stable identity of the shared instrument runner contract.
pub const CONTRACT_NAME: &str = "eliot.instrument.runner";
/// Wire revision of the runner contract.
pub const CONTRACT_VERSION: (u16, u16, u16) = (1, 0, 0);

/// Supplies the already-authorized, immutable process request for an invocation.
///
/// The implementation belongs to the runtime composition root.  It must obtain
/// executable identity, limits, generation, environment projection, and fence
/// from the owning authority; the runner never derives or replaces them.
pub trait InstrumentRequestPort: Send + Sync {
    /// Binds one admitted invocation to exactly one P-03 process request.
    ///
    /// # Errors
    /// Returns a runner error when the request cannot be issued or does not
    /// preserve the invocation identity.
    fn bind(&self, invocation: &InstrumentInvocation) -> Result<ProcessRequest, RunnerError>;
}

/// Failures raised by admission, identity checks, or process execution.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// The provider-neutral invocation failed structural validation.
    #[error("invalid instrument invocation: {0}")]
    InvalidInvocation(String),
    /// The request port rejected the binding.
    #[error("instrument request binding failed: {0}")]
    Binding(String),
    /// The process implementation rejected the operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// The process request was not correlated to the instrument request.
    #[error("instrument and process operation identities do not match")]
    IdentityMismatch,
    /// A returned receipt did not preserve the immutable process request.
    #[error("process receipt does not preserve the bound request")]
    ReceiptMismatch,
    /// A result was requested for a different operation than the binding.
    #[error("process observation does not preserve the bound request")]
    ObservationMismatch,
    /// A result carries no complete machine-derived executable identity.
    #[error("instrument result lacks a complete executable identity: {0}")]
    UnresolvedExecutable(String),
    /// A machine-derived identity does not match the registry binding.
    #[error("instrument executable identity mismatch: {0}")]
    ExecutableMismatch(String),
    /// Authoritative PASS requires retained raw output.
    #[error("authoritative PASS requires retained raw output")]
    RawOutputMissing,
    /// The result entry binding does not match the recorded invocation.
    #[error("instrument result does not match its registry entry: {0}")]
    EntryMismatch(String),
    /// Execution did not succeed, so no authoritative PASS exists.
    #[error("instrument execution is not successful: {0}")]
    NotAuthoritative(String),
    /// The self-change bootstrap receipt does not cover the runner surface.
    #[error("bootstrap receipt covers '{0}', not the instrument runner surface")]
    BootstrapRejected(String),
}

/// The immutable invocation/request pair used for every runner operation.
#[derive(Debug)]
pub struct InstrumentBinding {
    /// Provider-neutral instrument invocation.
    pub invocation: InstrumentInvocation,
    /// Exact sealed process request delegated to P-03.
    process_request: Option<ProcessRequest>,
    operation_id: OperationId,
    request_digest: String,
    generation: u64,
    /// Machine-derived observation pinned by
    /// [`InstrumentBinding::verify_executable`], sealed into the launch
    /// receipt by [`InstrumentRunner::launch`].
    verified_executable: Option<ResolvedExecutableIdentity>,
}

impl InstrumentBinding {
    /// Validates and binds an invocation through the owning request port.
    ///
    /// # Errors
    /// Returns an error when invocation validation, request binding, request
    /// validation, or identity correlation fails.
    pub fn bind(
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
    ) -> Result<Self, RunnerError> {
        invocation
            .validate()
            .map_err(|error| RunnerError::InvalidInvocation(error.to_string()))?;
        let process_request = port.bind(&invocation)?;
        process_request
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        Ok(Self {
            invocation,
            operation_id: process_request.operation_id().clone(),
            request_digest: process_request.invocation_digest().to_owned(),
            generation: process_request.generation().get(),
            process_request: Some(process_request),
            verified_executable: None,
        })
    }

    /// Creates a binding from a request already checked by the composition root.
    ///
    /// # Errors
    /// Returns an error when the invocation or process request is invalid, or
    /// when their identities do not match.
    pub fn from_request(
        invocation: InstrumentInvocation,
        process_request: ProcessRequest,
    ) -> Result<Self, RunnerError> {
        invocation
            .validate()
            .map_err(|error| RunnerError::InvalidInvocation(error.to_string()))?;
        process_request
            .validate()
            .map_err(|error| RunnerError::Binding(error.to_string()))?;
        if process_request.operation_id().as_str() != invocation.request.request_id.as_str() {
            return Err(RunnerError::IdentityMismatch);
        }
        Ok(Self {
            invocation,
            operation_id: process_request.operation_id().clone(),
            request_digest: process_request.invocation_digest().to_owned(),
            generation: process_request.generation().get(),
            process_request: Some(process_request),
            verified_executable: None,
        })
    }

    /// Returns the operation identity without exposing the consuming request.
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Pins a machine-derived executable observation to this binding under
    /// `entry` before launch.
    ///
    /// The entry must claim the binding invocation, the observation must be
    /// complete and name the registry-bound executable, the observed content
    /// digest must equal the sealed intent digest, and the observed argv must
    /// equal the sealed process-request argv (argv to argv: the admitted
    /// invocation arguments are instrument-level filters, never argv). A
    /// missing, incomplete, or mismatched identity fails closed so the later
    /// result can never take authoritative PASS. On success the observation
    /// is retained and sealed into the launch receipt by
    /// [`InstrumentRunner::launch`], so a later executable replacement
    /// cannot be silently rebound to this launch.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::EntryMismatch`], [`RunnerError::UnresolvedExecutable`],
    /// [`RunnerError::ExecutableMismatch`], or [`RunnerError::ReceiptMismatch`]
    /// when the binding is already consumed and the sealed request is gone.
    pub fn verify_executable(
        &mut self,
        entry: &RegistryEntry,
        resolved: Option<&ResolvedExecutableIdentity>,
    ) -> Result<(), RunnerError> {
        check_governed_binding(entry, &self.invocation, resolved)?;
        if let Some(observation) = resolved {
            let Some(request) = self.process_request.as_ref() else {
                return Err(RunnerError::ReceiptMismatch);
            };
            if !observation.binds_argv(request.argv()) {
                return Err(RunnerError::ExecutableMismatch(
                    "observed argv does not match the sealed process request".to_owned(),
                ));
            }
            if observation.content_digest != request.executable_sha256() {
                return Err(RunnerError::ExecutableMismatch(
                    "observed content digest does not match the sealed process intent".to_owned(),
                ));
            }
        }
        self.verified_executable = resolved.cloned();
        Ok(())
    }
}

/// Checks the entry/invocation/observation triple shared by pre-launch
/// binding verification and authoritative-PASS verdicts.
///
/// The entry must claim the invocation instrument and kind, and the
/// observation must satisfy
/// [`RegistryEntry::check_resolved_executable`]. Argv is *not* compared here:
/// pre-launch verification compares against the live sealed request argv,
/// while verdicts compare against the argv sealed into the result at launch.
fn check_governed_binding(
    entry: &RegistryEntry,
    invocation: &InstrumentInvocation,
    resolved: Option<&ResolvedExecutableIdentity>,
) -> Result<(), RunnerError> {
    if entry.instrument.as_str() != invocation.instrument.as_str() {
        return Err(RunnerError::EntryMismatch(
            "registry entry claims a different instrument".to_owned(),
        ));
    }
    if !entry.supports(invocation.kind) {
        return Err(RunnerError::EntryMismatch(
            "registry entry does not support the invocation kind".to_owned(),
        ));
    }
    entry
        .check_resolved_executable(resolved)
        .map_err(|error| match error {
            RegistryError::UnresolvedExecutable { reason, .. } => {
                RunnerError::UnresolvedExecutable(reason.to_string())
            }
            RegistryError::ExecutableMismatch {
                expected, observed, ..
            } => RunnerError::ExecutableMismatch(format!(
                "expected '{expected}', observed '{observed}'"
            )),
            other => RunnerError::EntryMismatch(other.to_string()),
        })
}

/// Receipt returned after the physical executor accepts an instrument.
///
/// The launch seals the executable observation pinned by
/// [`InstrumentBinding::verify_executable`] together with the exact argv
/// from the consumed request. A receipt launched without verification
/// carries no observation; a governed result built from it through
/// [`GovernedInstrumentResult::from_launch`] can then never take
/// authoritative PASS for a process entry.
#[derive(Debug)]
pub struct InstrumentStartReceipt {
    /// Original provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// P-03 acceptance receipt.
    pub process: ProcessStartReceipt,
    /// Executable observation pinned before launch, if verified.
    pub executable: Option<ResolvedExecutableIdentity>,
    /// Exact process argv sealed from the request at launch.
    pub argv: Vec<String>,
}

/// Current process observation correlated to its instrument invocation.
#[derive(Clone, Debug)]
pub struct InstrumentObservation {
    /// Original provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// Current process view.
    pub view: ProcessExecutionView,
    /// Execution axis only; no semantic verifier result is inferred.
    pub execution: ExecutionStatus,
}

/// Governed profile result bound to its exact executable identity.
///
/// Every field is admission-sealed or machine-derived: the invocation
/// (candidate/profile/worktree identity plus instrument-level arguments), the
/// registry-selected adapter and generation, the resolved executable
/// observation, the process argv sealed at launch, the raw output handle, and
/// the execution axis. The authoritative verdict comes only from
/// [`GovernedInstrumentResult::require_authoritative_pass`]: a changed or
/// missing identity, diverged argv, unretained raw output, or non-success
/// execution refuses PASS instead of degrading into one. A replaced
/// executable yields a different
/// [`ResolvedExecutableIdentity::identity_digest`], so comparing stored
/// identities exposes the swap instead of silently rebinding the earlier
/// result.
///
/// Decoder-only entries never launch a process and legitimately carry no
/// observation: for them, `executable` is `None` and the verdict still
/// applies to the retained decode output. Every process entry requires a
/// complete observation.
#[derive(Clone, Debug)]
pub struct GovernedInstrumentResult {
    /// Original provider-neutral invocation.
    pub invocation: InstrumentInvocation,
    /// Adapter identity selected by the registry.
    pub adapter: String,
    /// Registry generation the selection was validated against.
    pub registry_generation: u64,
    /// Machine-derived executable observation, if one was resolved.
    pub executable: Option<ResolvedExecutableIdentity>,
    /// Exact process argv sealed at launch; the observation must match it.
    pub argv: Vec<String>,
    /// Raw output handle retained before any reduction.
    pub raw: RawEvidence,
    /// Execution axis only; no semantic verifier result is inferred.
    pub execution: ExecutionStatus,
}

impl GovernedInstrumentResult {
    /// Records one governed result from a launch-sealed receipt.
    ///
    /// The invocation, executable observation, and argv come from the
    /// receipt sealed at launch, never from fresh caller values, so the
    /// authoritative verdict in
    /// [`GovernedInstrumentResult::require_authoritative_pass`] binds to
    /// the exact identity pinned before launch. A replaced executable
    /// yields a different
    /// [`ResolvedExecutableIdentity::identity_digest`], and a receipt
    /// launched without verification carries no observation, which keeps
    /// the result non-authoritative for every process entry.
    pub fn from_launch(
        receipt: &InstrumentStartReceipt,
        adapter: String,
        registry_generation: u64,
        raw: RawEvidence,
        execution: ExecutionStatus,
    ) -> Self {
        Self {
            invocation: receipt.invocation.clone(),
            adapter,
            registry_generation,
            executable: receipt.executable.clone(),
            argv: receipt.argv.clone(),
            raw,
            execution,
        }
    }

    /// Records one governed result without deciding any verdict.
    ///
    /// Callers that launched through [`InstrumentRunner::launch`] hold a
    /// sealed [`InstrumentStartReceipt`] and must prefer
    /// [`GovernedInstrumentResult::from_launch`] so the verdict binds to
    /// the launch-pinned identity instead of fresh caller values.
    pub fn new(
        invocation: InstrumentInvocation,
        adapter: String,
        registry_generation: u64,
        executable: Option<ResolvedExecutableIdentity>,
        argv: Vec<String>,
        raw: RawEvidence,
        execution: ExecutionStatus,
    ) -> Self {
        Self {
            invocation,
            adapter,
            registry_generation,
            executable,
            argv,
            raw,
            execution,
        }
    }

    /// Candidate/worktree identity from the admitted invocation target.
    pub fn worktree_identity(&self) -> &str {
        &self.invocation.target
    }

    /// Declared candidate scope from the admitted invocation.
    pub fn candidate_scope(&self) -> &str {
        &self.invocation.declared_scope
    }

    /// Whether this result may take authoritative PASS under `entry`.
    pub fn is_authoritative_pass(&self, entry: &RegistryEntry) -> bool {
        self.require_authoritative_pass(entry).is_ok()
    }

    /// Refuses every non-authoritative PASS with its exact typed cause.
    ///
    /// PASS requires all of: the entry claims this invocation instrument and
    /// kind, a complete machine-derived executable observation naming the
    /// registry-bound executable (decoder-only entries legitimately carry
    /// none and never launch), observed argv equal to the argv sealed at
    /// launch, a retained raw output handle, and successful execution.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::EntryMismatch`],
    /// [`RunnerError::UnresolvedExecutable`],
    /// [`RunnerError::ExecutableMismatch`], [`RunnerError::RawOutputMissing`],
    /// or [`RunnerError::NotAuthoritative`] for the first failing requirement.
    pub fn require_authoritative_pass(&self, entry: &RegistryEntry) -> Result<(), RunnerError> {
        check_governed_binding(entry, &self.invocation, self.executable.as_ref())?;
        if self
            .executable
            .as_ref()
            .is_some_and(|observation| !observation.binds_argv(&self.argv))
        {
            return Err(RunnerError::ExecutableMismatch(
                "observed argv does not match the argv sealed at launch".to_owned(),
            ));
        }
        if !matches!(self.raw, RawEvidence::Retained { .. }) {
            return Err(RunnerError::RawOutputMissing);
        }
        if self.execution != ExecutionStatus::Succeeded {
            return Err(RunnerError::NotAuthoritative(format!(
                "execution is {:?}, not Succeeded",
                self.execution
            )));
        }
        Ok(())
    }
}

/// The bounded facade over the injected physical process executor.
pub struct InstrumentRunner<E> {
    executor: Arc<E>,
}

impl<E> InstrumentRunner<E> {
    /// Creates a runner around the active production process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self { executor }
    }
}

impl<E: ProcessExecutor + 'static> InstrumentRunner<E> {
    /// Binds an invocation and launches it through P-03.
    ///
    /// # Errors
    /// Returns an error when binding or process launch fails, or when the
    /// returned receipt does not preserve the binding identity.
    pub async fn launch_bound(
        &self,
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let mut binding = InstrumentBinding::bind(invocation, port)?;
        self.launch(&mut binding, sink).await
    }

    /// Binds an invocation, pins its executable identity, and launches it.
    ///
    /// The machine-derived `resolved` observation is checked against `entry`,
    /// the sealed intent digest, and the sealed request argv *before* the
    /// process starts, so a swapped executable fails closed here instead of
    /// producing evidence that could later take authoritative PASS. The
    /// pinned observation and sealed argv travel in the returned receipt for
    /// [`GovernedInstrumentResult::from_launch`]. Composition roots that need
    /// authoritative evidence must use this path; [`InstrumentRunner::launch`]
    /// performs no identity check.
    ///
    /// # Errors
    ///
    /// Returns an error when binding, identity pinning, or process launch
    /// fails, or when the returned receipt does not preserve the binding
    /// identity.
    pub async fn launch_verified(
        &self,
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
        entry: &RegistryEntry,
        resolved: Option<&ResolvedExecutableIdentity>,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let mut binding = InstrumentBinding::bind(invocation, port)?;
        binding.verify_executable(entry, resolved)?;
        self.launch(&mut binding, sink).await
    }

    /// Binds, verifies, and launches only under a runner-surface cutover receipt.
    ///
    /// This is the strict [`InstrumentRunner::launch_verified`] path for use
    /// while the runner surface itself ships a new generation through the
    /// I18.31 bootstrap: the generation receipt must cover
    /// [`eliot_verifier::SelfChangeSurface::InstrumentRunner`], then the
    /// real verified launch runs. Unrelated launches keep using
    /// [`InstrumentRunner::launch_verified`] directly; the protocol binds
    /// only the changed surface.
    ///
    /// Residual: composition roots switch to this entry when they ship a
    /// new runner-surface generation (no caller migrates yet), and binding
    /// the receipt generation to a runner build identity awaits a runner
    /// build-identity owner.
    ///
    /// # Errors
    ///
    /// Returns [`RunnerError::BootstrapRejected`] when the receipt covers a
    /// different surface, or the underlying launch error otherwise.
    pub async fn launch_verified_with_bootstrap(
        &self,
        invocation: InstrumentInvocation,
        port: &dyn InstrumentRequestPort,
        entry: &RegistryEntry,
        resolved: Option<&ResolvedExecutableIdentity>,
        sink: Arc<dyn ProcessEvidenceSink>,
        receipt: &eliot_verifier::GenerationReceipt,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        if !receipt.covers(eliot_verifier::SelfChangeSurface::InstrumentRunner) {
            return Err(RunnerError::BootstrapRejected(
                receipt.surface().as_str().to_owned(),
            ));
        }
        self.launch_verified(invocation, port, entry, resolved, sink)
            .await
    }

    /// Launches the exact immutable binding through P-03.
    ///
    /// # Errors
    /// Returns an error when the binding is already consumed, process launch
    /// fails, or the returned receipt does not preserve its identity.
    pub async fn launch(
        &self,
        binding: &mut InstrumentBinding,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let process_request = binding
            .process_request
            .take()
            .ok_or(RunnerError::ReceiptMismatch)?;
        let argv = process_request.argv().to_vec();
        let executable = binding.verified_executable.clone();
        let process = self.executor.start(process_request, sink).await?;
        if process.operation_id() != &binding.operation_id
            || process.request_digest() != binding.request_digest
            || process.accepted_generation().get() != binding.generation
        {
            return Err(RunnerError::ReceiptMismatch);
        }
        Ok(InstrumentStartReceipt {
            invocation: binding.invocation.clone(),
            process,
            executable,
            argv,
        })
    }

    /// Inspects an operation and preserves the binding identity.
    ///
    /// # Errors
    /// Returns an error when process inspection fails or the observed operation
    /// does not match the binding.
    pub async fn inspect(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<InstrumentObservation, RunnerError> {
        let view = self.executor.inspect(binding.operation_id.clone()).await?;
        if view.operation_id() != &binding.operation_id
            || view.request_digest() != binding.request_digest
            || view.fence().generation().get() != binding.generation
        {
            return Err(RunnerError::ObservationMismatch);
        }
        Ok(InstrumentObservation {
            invocation: binding.invocation.clone(),
            execution: execution_status(&view),
            view,
        })
    }

    /// Cancels an operation through the process contract's current fence.
    ///
    /// # Errors
    /// Returns an error when the process executor rejects cancellation.
    pub async fn cancel(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<CancellationReceipt, RunnerError> {
        Ok(self.executor.cancel(binding.operation_id.clone()).await?)
    }

    /// Reconciles an unknown operation and returns retained process evidence.
    ///
    /// # Errors
    /// Returns an error when reconciliation fails or the returned evidence does
    /// not preserve the binding identity.
    pub async fn reconcile(
        &self,
        binding: &InstrumentBinding,
    ) -> Result<ProcessEvidence, RunnerError> {
        let evidence = self
            .executor
            .reconcile(binding.operation_id.clone())
            .await?;
        if evidence.operation_id() != &binding.operation_id
            || evidence.request_digest() != binding.request_digest
        {
            return Err(RunnerError::ObservationMismatch);
        }
        Ok(evidence)
    }
}

/// Converts an executor-side machine observation into the registry-bound
/// identity form.
///
/// Both records carry the same five machine-derived fields (canonical path,
/// content digest, tool version, environment digest, exact argv); the
/// executor resolves them from the machine at launch while the registry
/// checks them before launch and at verdict time. Validation is re-applied
/// under the claiming `instrument` so a bridged observation can never carry
/// an empty instrument label.
impl From<eliot_process_executor::ExecutableObservation> for ResolvedExecutableIdentity {
    fn from(observation: eliot_process_executor::ExecutableObservation) -> Self {
        Self {
            canonical_path: observation.canonical_path,
            content_digest: observation.content_digest,
            tool_version: observation.tool_version,
            environment_digest: observation.environment_digest,
            arguments: observation.arguments,
        }
    }
}

/// Bridges an executor-side observation into a checked registry identity.
///
/// Unlike the infallible [`From`] bridge (which moves already-shaped fields),
/// this re-validates every field under the claiming `instrument` and fails
/// closed on any malformed value.
///
/// # Errors
///
/// Returns [`RegistryError::UnresolvedExecutable`] when any field is
/// malformed.
pub fn bridge_executor_observation(
    instrument: &str,
    observation: eliot_process_executor::ExecutableObservation,
) -> Result<ResolvedExecutableIdentity, RegistryError> {
    ResolvedExecutableIdentity::new(
        instrument,
        observation.canonical_path,
        observation.content_digest,
        observation.tool_version,
        observation.environment_digest,
        observation.arguments,
    )
}

/// Compatibility name for composition roots using the bounded terminology.
pub type BoundedInstrumentRunner<E> = InstrumentRunner<E>;
/// Compatibility name for callers that refer to the runner as an adapter.
pub type InstrumentAdapter<E> = InstrumentRunner<E>;

fn execution_status(view: &ProcessExecutionView) -> ExecutionStatus {
    use eliot_process::{ExitDisposition, ProcessLifecycle};
    match view.lifecycle() {
        ProcessLifecycle::Created | ProcessLifecycle::Starting => ExecutionStatus::Accepted,
        ProcessLifecycle::Running | ProcessLifecycle::Cancelling => ExecutionStatus::Running,
        ProcessLifecycle::UnknownOutcome | ProcessLifecycle::Quarantined => {
            ExecutionStatus::Unknown
        }
        ProcessLifecycle::Reconciled => ExecutionStatus::Partial,
        ProcessLifecycle::Exited => match view.exit() {
            Some(exit) if successful_exit(exit) => ExecutionStatus::Succeeded,
            Some(exit) if matches!(exit.disposition(), ExitDisposition::Cancelled) => {
                ExecutionStatus::Cancelled
            }
            Some(exit) if matches!(exit.disposition(), ExitDisposition::Unknown) => {
                ExecutionStatus::Unknown
            }
            None => ExecutionStatus::Unknown,
            _ => ExecutionStatus::Failed,
        },
        ProcessLifecycle::Failed => ExecutionStatus::Failed,
    }
}

fn successful_exit(exit: &ExitStatus) -> bool {
    if !matches!(exit.disposition(), ExitDisposition::Completed) {
        return false;
    }
    serde_json::to_value(exit)
        .ok()
        .and_then(|value| value.get("code").and_then(serde_json::Value::as_i64))
        .is_some_and(|code| code == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId,
        RequestMetadata, SourceId, StateFence,
    };
    use eliot_instrument_api::InstrumentKind;
    use eliot_instrument_rustc::RUSTC_INSTRUMENT;
    use std::num::NonZeroU64;

    use crate::registry::InvalidationSet;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn unreachable_value<T>(result: Result<T, impl std::fmt::Debug>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => unreachable!(),
        }
    }

    fn test_invocation(arguments: Vec<String>) -> InstrumentInvocation {
        let lineage = unreachable_value(EpochLineageId::new(TEST_LINEAGE_A));
        let epoch = unreachable_value(EpochId::new(
            lineage,
            NonZeroU64::new(1).unwrap_or_else(|| unreachable!()),
        ));
        let clock = ClockReading {
            valid_time_ms: Some(10),
            known_time_ms: Some(11),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        };
        InstrumentInvocation {
            request: RequestMetadata {
                request_id: unreachable_value(RequestId::new("instrument-request-1")),
                session_id: None,
                task_id: None,
                product_id: unreachable_value(ProductId::new("product-1")),
                source_id: unreachable_value(SourceId::new("source-1")),
                state_fence: StateFence::new(epoch, eliot_contracts::ResourceGeneration::genesis()),
                clock,
            },
            instrument: unreachable_value(ContractId::new(RUSTC_INSTRUMENT)),
            kind: InstrumentKind::Build,
            profile: "dev-fast".to_owned(),
            target: "worktree:a04".to_owned(),
            arguments,
            input_artifacts: Vec::new(),
            declared_scope: "workspace".to_owned(),
            requested_at: clock,
        }
    }

    fn test_entry() -> RegistryEntry {
        let fingerprints = InvalidationSet {
            source: "source".to_owned(),
            lock: "lock".to_owned(),
            toolchain: "toolchain".to_owned(),
            env: "env".to_owned(),
            exe: "exe".to_owned(),
            profile: "profile".to_owned(),
            parser: "parser".to_owned(),
        };
        let registry = unreachable_value(ProviderRegistry::ready(
            7,
            "normative".to_owned(),
            &fingerprints,
        ));
        let invocation = test_invocation(vec!["--crate-name".to_owned(), "foo".to_owned()]);
        match registry.resolve(&invocation) {
            Ok(entry) => entry.clone(),
            Err(_) => unreachable!(),
        }
    }

    fn test_observation(arguments: Vec<String>) -> ResolvedExecutableIdentity {
        unreachable_value(ResolvedExecutableIdentity::new(
            RUSTC_INSTRUMENT,
            "/usr/bin/rustc".to_owned(),
            "a".repeat(64),
            Some("rustc 1.89.0".to_owned()),
            "b".repeat(64),
            arguments,
        ))
    }

    fn retained_raw() -> RawEvidence {
        RawEvidence::Retained {
            artifact: unreachable_value(ArtifactId::new("raw-artifact-1")),
            byte_len: 128,
        }
    }

    #[test]
    fn nonzero_completed_exit_is_failed() -> Result<(), eliot_process::ContractError> {
        let exit = ExitStatus::new(ExitDisposition::Completed, Some(7), None, 1)?;
        assert!(!successful_exit(&exit));
        Ok(())
    }

    #[test]
    fn zero_completed_exit_succeeds() -> Result<(), eliot_process::ContractError> {
        let exit = ExitStatus::new(ExitDisposition::Completed, Some(0), None, 1)?;
        assert!(successful_exit(&exit));
        Ok(())
    }

    #[test]
    fn result_without_executable_identity_cannot_pass() {
        let entry = test_entry();
        let invocation = test_invocation(vec!["--crate-name".to_owned(), "foo".to_owned()]);
        let result = GovernedInstrumentResult::new(
            invocation,
            entry.adapter.clone(),
            entry.generation,
            None,
            Vec::new(),
            retained_raw(),
            ExecutionStatus::Succeeded,
        );
        assert!(!result.is_authoritative_pass(&entry));
        assert!(matches!(
            result.require_authoritative_pass(&entry),
            Err(RunnerError::UnresolvedExecutable(_))
        ));
    }

    #[test]
    fn unretained_raw_output_cannot_pass() {
        let entry = test_entry();
        let arguments = vec!["--crate-name".to_owned(), "foo".to_owned()];
        let result = GovernedInstrumentResult::new(
            test_invocation(arguments.clone()),
            entry.adapter.clone(),
            entry.generation,
            Some(test_observation(arguments.clone())),
            arguments,
            RawEvidence::Omitted {
                reason: OmissionReason::Omitted {
                    reason: "policy withheld output".to_owned(),
                },
            },
            ExecutionStatus::Succeeded,
        );
        assert!(matches!(
            result.require_authoritative_pass(&entry),
            Err(RunnerError::RawOutputMissing)
        ));
    }

    #[test]
    fn authoritative_pass_requires_matching_identity_and_retained_output() {
        let entry = test_entry();
        let arguments = vec!["--crate-name".to_owned(), "foo".to_owned()];
        let observation = test_observation(arguments.clone());
        let result = GovernedInstrumentResult::new(
            test_invocation(arguments.clone()),
            entry.adapter.clone(),
            entry.generation,
            Some(observation.clone()),
            arguments.clone(),
            retained_raw(),
            ExecutionStatus::Succeeded,
        );
        assert_eq!(result.worktree_identity(), "worktree:a04");
        assert_eq!(result.candidate_scope(), "workspace");
        assert!(result.require_authoritative_pass(&entry).is_ok());

        let mut replaced = observation;
        replaced.content_digest = "c".repeat(64);
        let swapped = GovernedInstrumentResult::new(
            test_invocation(arguments.clone()),
            entry.adapter.clone(),
            entry.generation,
            Some(replaced),
            arguments,
            retained_raw(),
            ExecutionStatus::Succeeded,
        );
        assert_ne!(
            result
                .executable
                .as_ref()
                .map(ResolvedExecutableIdentity::identity_digest),
            swapped
                .executable
                .as_ref()
                .map(ResolvedExecutableIdentity::identity_digest)
        );

        let diverged = GovernedInstrumentResult::new(
            test_invocation(vec!["--different".to_owned()]),
            entry.adapter.clone(),
            entry.generation,
            swapped.executable.clone(),
            vec!["--sealed-at-launch".to_owned()],
            retained_raw(),
            ExecutionStatus::Succeeded,
        );
        assert!(matches!(
            diverged.require_authoritative_pass(&entry),
            Err(RunnerError::ExecutableMismatch(_))
        ));
    }

    #[test]
    fn executor_observation_bridges_into_registry_identity() {
        use std::path::PathBuf;

        struct TempFile {
            path: PathBuf,
        }

        impl Drop for TempFile {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.path);
            }
        }

        let path = std::env::temp_dir().join(format!(
            "eliot-runner-bridge-{}-{}.bin",
            std::process::id(),
            "observation"
        ));
        std::fs::write(&path, b"bridge-bytes").unwrap_or_else(|_| unreachable!());
        let guard = TempFile { path: path.clone() };
        let arguments = vec!["--crate-name".to_owned(), "foo".to_owned()];
        let observed = eliot_process_executor::ExecutableObservation::observe_at_path(
            &guard.path,
            arguments.clone(),
            "b".repeat(64),
            Some("rustc 1.89.0".to_owned()),
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(observed.is_complete());
        let bridged = bridge_executor_observation(RUSTC_INSTRUMENT, observed.clone());
        match bridged {
            Ok(identity) => assert!(identity.binds_argv(&arguments)),
            Err(_) => unreachable!(),
        }
        let converted: ResolvedExecutableIdentity = observed.into();
        assert!(converted.binds_argv(&arguments));
    }
}
