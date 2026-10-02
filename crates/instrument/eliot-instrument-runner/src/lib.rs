//! The single bounded execution boundary for governed instruments.
//!
//! This crate owns orchestration, not physical effects.  A composition root
//! supplies an admitted [`InstrumentRequestPort`] and the production
//! [`eliot_process::ProcessExecutor`].  The runner validates every hand-off,
//! preserves request identity and generation, and never converts process
//! failure into semantic verification evidence.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use eliot_instrument_api::{ExecutionStatus, InstrumentAdmissionGrant, InstrumentInvocation};
use eliot_process::{
    CancellationReceipt, ExitDisposition, ExitStatus, OperationId, ProcessEvidence,
    ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView, ProcessExecutor,
    ProcessRequest, ProcessStartReceipt,
};
use thiserror::Error;

pub mod admission_submission;
pub mod build_projection;
pub mod cache_lane;
pub mod capsule_binding;
mod dev_fast;
pub mod kernel_registry_read_client;
pub mod package_disposition;
pub mod process_owner;
pub mod profile;
pub mod profile_run;
pub mod provider_denominator;
pub mod registry;
pub mod registry_owner_readback;
pub mod testd_port;
pub mod testd_profile_dispatch;
pub mod testd_registry;
pub mod verification_profile;

pub use admission_submission::{
    AdmissionSubmission, AdmissionSubmissionReadback, PureTransformSubmission,
    prepare_admission_submission, prepare_pure_transform_submission,
};
pub use build_projection::{
    AffectedEdge, BuildCacheDecision, BuildCancellation, BuildClaimOrder, BuildCleanupPass,
    BuildProjectionError, CargoOrigin, CargoScopeRefusal, ClaimedBuild, CleanupCandidate,
    CleanupDecision, DeclaredWorkItem, FlightResolution, HeldLease, LiveClaim, PreemptionClass,
    ProducerClaim, ProducerCompletion, ProducerOutcome, ProjectedBuild, QuarantinedArtifact,
    TargetClass, TargetRootBuildCoordinator, restrict_agent_argv,
};
pub use cache_lane::{CacheLane, CacheLaneAttestations, CacheLaneError, LaneOutcome};
pub use capsule_binding::{
    BoundCapsulePlan, CapsuleBindingError, CapsuleRunObservation, assemble_evidence, bind_capsule,
    ceiling_admits_edge_claim, ceiling_admits_product_claim, nextest_test_filters,
};
pub use dev_fast::{
    DEV_FAST_FIRST_PACKAGE, DEV_FAST_PROFILE, DEV_FAST_PROFILE_REVISION, DEV_FAST_SLICE_PARTIAL,
    DEV_FAST_STAGE_CLIPPY, DEV_FAST_STAGE_LIST, DEV_FAST_STAGE_RUN, DEV_FAST_STAGE_RUSTFMT,
    DevFastBudgets, DevFastCandidate, DevFastDispatch, DevFastError, DevFastFailurePolicy,
    DevFastPreflight, DevFastStageOutcome, DevFastTargetIdentity, DevFastToolRevisions,
    VERIFICATION_PROFILE_RUN_VERSION, VerificationProfileRun, VerificationRouteRequest,
    check_zero_execution, confirm_dev_fast_finish, dev_fast_caller_plan, dev_fast_disposition,
    dev_fast_execute, dev_fast_registry, dev_fast_replay, dev_fast_stage_dispatch,
    dev_fast_unresolved_runs, finalize_dev_fast_stage, normalize_dev_fast_stage_bytes,
    require_dev_fast_parity, resolve_verification_route, run_dev_fast_profile,
};
pub use eliot_build_test_graph::{
    BUILD_ROOT_DIRECTORY, BuildMode, CARGO_HOME_ENV, CARGO_TARGET_DIR_ENV, CandidateIdentity,
    GovernedWorkEnvelope, LaneIdentity, RuntimeEnvironmentLease, WorkEnvelopeError,
};
pub use eliot_ipc::{KernelClient, KernelClientConfig, KernelClientError, RequestIdentity};

/// Returns whether process evidence describes a terminal lifecycle or an
/// unknown outcome attributable to a real stdout/stderr transport read failure.
/// The Kernel still independently verifies physical Job closure before it
/// releases an instrument slot.
#[must_use]
pub fn process_evidence_reports_terminal_or_transport_failure(evidence: &ProcessEvidence) -> bool {
    let lifecycle = evidence.view().lifecycle();
    lifecycle.is_terminal()
        || (lifecycle == eliot_process::ProcessLifecycle::UnknownOutcome
            && (evidence.stdout().is_some_and(|stream| {
                stream.transport() == eliot_process::StreamTransportStatus::ReadFailed
            }) || evidence.stderr().is_some_and(|stream| {
                stream.transport() == eliot_process::StreamTransportStatus::ReadFailed
            })))
}

/// Authenticated Kernel observation client used by the real wrapper runtimes.
///
/// This adapter preserves the original request identity retained by the
/// dispatch authority and verifies the authenticated response selector,
/// identity, and exact operation/admission/dispatch pins before returning it
/// to P-04.
#[cfg(windows)]
pub struct KernelInstrumentStageRuntimeObserver {
    client: Mutex<KernelClient>,
}

#[cfg(windows)]
impl KernelInstrumentStageRuntimeObserver {
    /// Creates a runtime observer over the protected authenticated Kernel
    /// client used by the wrapper composition.
    pub fn new(client: KernelClient) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

    fn validate_runtime_key(
        dispatch_grant_digest: Option<&str>,
        attempt_seq: Option<u32>,
        job_id: Option<&str>,
    ) -> Result<(), ProcessExecutionError> {
        let generic_stage =
            dispatch_grant_digest.is_some() && attempt_seq.is_none() && job_id.is_none();
        let testd_attempt =
            dispatch_grant_digest.is_none() && attempt_seq.is_some() && job_id.is_some();
        if generic_stage || testd_attempt {
            Ok(())
        } else {
            Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::InvalidValue {
                    field: "instrument_stage_runtime.owner_key",
                    reason: "generic dispatch and durable TestD attempt pins cannot be mixed",
                },
            ))
        }
    }

    fn exchange(
        &self,
        selector: &str,
        identity: &RequestIdentity,
        payload: serde_json::Value,
    ) -> Result<eliot_ipc::kernel_client::AuthenticatedKernelResponse, ProcessExecutionError> {
        let mut client = self.client.lock().map_err(|_| {
            ProcessExecutionError::Unavailable(
                "Kernel instrument-stage observer lock poisoned".to_owned(),
            )
        })?;
        client.set_request_identity(identity.clone());
        let response = client
            .transact_json_authenticated(selector, payload)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        if response.operation() != selector || response.request_identity() != identity {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DigestMismatch {
                    field: "instrument_stage_runtime.authenticated_response",
                    expected: format!(
                        "{selector}:{}",
                        identity.request.metadata.request_id.as_str()
                    ),
                    observed: format!(
                        "{}:{}",
                        response.operation(),
                        response
                            .request_identity()
                            .request
                            .metadata
                            .request_id
                            .as_str()
                    ),
                },
            ));
        }
        Ok(response)
    }
}

#[cfg(windows)]
impl eliot_kernel_service::InstrumentStageRuntimeObservationPort
    for KernelInstrumentStageRuntimeObserver
{
    fn before_resume(
        &self,
        identity: &RequestIdentity,
        request: eliot_kernel_service::InstrumentStageStartedRequest,
    ) -> Result<eliot_ipc::kernel_client::AuthenticatedKernelResponse, ProcessExecutionError> {
        use eliot_kernel_service::{
            INSTRUMENT_STAGE_STARTED_OPERATION, InstrumentStageStartedResponse,
        };

        Self::validate_runtime_key(
            request.dispatch_grant_digest.as_deref(),
            request.attempt_seq,
            request.job_id.as_deref(),
        )?;

        let payload = serde_json::to_value(&request).map_err(|error| {
            ProcessExecutionError::Unavailable(format!(
                "encode authenticated instrument-stage start observation: {error}"
            ))
        })?;
        let response = self.exchange(INSTRUMENT_STAGE_STARTED_OPERATION, identity, payload)?;
        let echoed: InstrumentStageStartedResponse =
            serde_json::from_value(response.payload().clone()).map_err(|error| {
                ProcessExecutionError::Unavailable(format!(
                    "decode authenticated instrument-stage start response: {error}"
                ))
            })?;
        if echoed.operation_id != request.operation_id
            || echoed.admission_digest != request.admission_digest
            || echoed.dispatch_grant_digest != request.dispatch_grant_digest
            || echoed.attempt_seq != request.attempt_seq
            || echoed.job_id != request.job_id
            || echoed.process_request_digest != request.process_request_digest
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DigestMismatch {
                    field: "instrument_stage_runtime.started_pins",
                    expected: format!(
                        "{}:{}:{:?}:{:?}:{:?}:{}",
                        request.operation_id.as_str(),
                        request.admission_digest,
                        request.dispatch_grant_digest,
                        request.attempt_seq,
                        request.job_id,
                        request.process_request_digest
                    ),
                    observed: format!(
                        "{}:{}:{:?}:{:?}:{:?}:{}",
                        echoed.operation_id.as_str(),
                        echoed.admission_digest,
                        echoed.dispatch_grant_digest,
                        echoed.attempt_seq,
                        echoed.job_id,
                        echoed.process_request_digest
                    ),
                },
            ));
        }
        Ok(response)
    }

    fn terminal(
        &self,
        identity: &RequestIdentity,
        request: eliot_kernel_service::InstrumentStageTerminalRequest,
    ) -> Result<eliot_ipc::kernel_client::AuthenticatedKernelResponse, ProcessExecutionError> {
        use eliot_kernel_service::{
            INSTRUMENT_STAGE_TERMINAL_OPERATION, InstrumentStageTerminalResponse,
        };

        Self::validate_runtime_key(
            request.dispatch_grant_digest.as_deref(),
            request.attempt_seq,
            request.job_id.as_deref(),
        )?;

        let payload = serde_json::to_value(&request).map_err(|error| {
            ProcessExecutionError::Unavailable(format!(
                "encode authenticated instrument-stage terminal observation: {error}"
            ))
        })?;
        let response = self.exchange(INSTRUMENT_STAGE_TERMINAL_OPERATION, identity, payload)?;
        let echoed: InstrumentStageTerminalResponse =
            serde_json::from_value(response.payload().clone()).map_err(|error| {
                ProcessExecutionError::Unavailable(format!(
                    "decode authenticated instrument-stage terminal response: {error}"
                ))
            })?;
        if request.evidence.view().operation_id() != &request.operation_id
            || request.evidence.view().request_digest() != request.process_request_digest.as_str()
            || echoed.operation_id != request.operation_id
            || echoed.admission_digest != request.admission_digest
            || echoed.dispatch_grant_digest != request.dispatch_grant_digest
            || echoed.attempt_seq != request.attempt_seq
            || echoed.job_id != request.job_id
            || echoed.process_request_digest != request.process_request_digest
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DigestMismatch {
                    field: "instrument_stage_runtime.terminal_pins",
                    expected: format!(
                        "{}:{}:{:?}:{:?}:{:?}:{}",
                        request.operation_id.as_str(),
                        request.admission_digest,
                        request.dispatch_grant_digest,
                        request.attempt_seq,
                        request.job_id,
                        request.process_request_digest
                    ),
                    observed: format!(
                        "{}:{}:{:?}:{:?}:{:?}:{}",
                        echoed.operation_id.as_str(),
                        echoed.admission_digest,
                        echoed.dispatch_grant_digest,
                        echoed.attempt_seq,
                        echoed.job_id,
                        request.evidence.view().request_digest()
                    ),
                },
            ));
        }
        Ok(response)
    }
}
pub use eliot_test_selection::{FrozenSelection, TestSelectionReceipt};
pub use kernel_registry_read_client::{
    INSTRUMENT_REGISTRY_READ_OPERATION, InstrumentRegistryReadClient,
    InstrumentRegistryReadRequest, registration_receipt_request, registry_state_request,
};
pub use package_disposition::{
    CAPABILITY_OWNER_UNIVERSE, CONSUMER_CRATE_UNIVERSE, DISPOSITION_REVIEWED_ON, DispositionError,
    DispositionField, ExecutionContour, INSTRUMENT_PACKAGE_FAMILY, PACKAGE_DISPOSITIONS,
    PROOF_CEILING_UNIVERSE, PackageDispositionRecord, PackageRoute, STATE_OWNER_UNIVERSE,
    TESTD_DISPATCH_UNIVERSE, TESTD_PROFILE_UNIVERSE, verify_disposition_coverage,
};
pub use process_owner::{
    KernelAdmissionError, KernelAdmittedProcess, KernelInstrumentAdmission,
    KernelInstrumentRequestPort, UnprovisionedKernelAdmission,
};
pub use profile::{
    ADMITTED_SCOPE_CLASS, ADMITTED_WORKTREE_CLASS, AdmissionError, AdmittedProfile, AdmittedStage,
    BUILTIN_PROFILE_REVISION, BUILTIN_SPEC_VERSION, BUNDLE_VERIFICATION_ALIAS,
    BUNDLE_VERIFICATION_ROUTE, COMPILER_PROFILE, CompiledProfile, EnvironmentPolicy,
    ISOLATED_PROCESS_CLASS, InstrumentClass, InstrumentKindId, InstrumentProfile,
    InstrumentProfileResolver, InstrumentRegistry, InstrumentRegistrySnapshot, InstrumentSpec,
    InstrumentSpecParams, PACKAGE_VERIFICATION_ALIAS, PACKAGE_VERIFICATION_ROUTE, PROFILE_ALIASES,
    ProfileAlias, ProfileCompiler, ProfileError, ProfileScopeClasses, PureTransformHandler,
    PureTransformSpec, REGISTRY_SNAPSHOT_SCHEMA, REGISTRY_SNAPSHOT_SCHEMA_VERSION, ResolvedProfile,
    ResolvedStage, ResourceLimits, StageDag, StageDecl, StageEnvironment, StageExecution,
    TEST_PROFILE, TOOLCHAIN_PATH_ENV, TargetLayout, WorkScope, admitted_profile_for_alias,
    bundle_verification_profile, compiler_profile, package_verification_profile, scip_profile,
    test_profile,
};
pub use profile_run::{
    AdmissionSubmissionOwnerReadback, AdmissionSubmissionProofPort, AdmittedStageGrant,
    AggregateStatus, InstrumentRun, MappedStageLauncher, PlannedStage, ProfileAggregate,
    ProfileRunError, ProviderDispatch, PureTransformAdmission, PureTransformInput,
    RegistryLaunchSelection, RetainedExitOutcome, RetainedToolIdentity, StageEvidence,
    StageIdentity, StageLauncher, StageOrchestrator, StagePlan, StageTargetLayout,
    TestExecutionPlaneRoute, TestdPlaneAdmission, UnprovisionedAdmissionProofPort,
    compose_provider_dispatch, registry_launch_selection,
};
pub use provider_denominator::{
    ADVERTISED_INSTRUMENTS, AvailabilityInputs, ConformanceCase, ConformanceCorpus,
    ConformanceError, DENOMINATOR_CONTRACT, DENOMINATOR_CONTRACT_VERSION, ProviderAvailability,
    ProviderDenominator, ProviderDenominatorError, ProviderDenominatorRow, ProviderDisposition,
    ProviderFixtureSet, ProviderSupport, UNMAPPED_IN_PROCESS_INSTRUMENTS, declared_instruments,
    disposition_for_parts, host_platform,
};
pub use registry::{
    ATTESTED_IDENTITY_SLOTS, ExecutableIdentityCause, IdentitySlot, PROFILE_IDENTITY_SLOTS,
    ProfileIdentities, ProfileIdentityParams, ProviderRegistry, REQUIRED_IDENTITY_SLOTS,
    RegistryEntry, RegistryError, ResolvedExecutableIdentity, SupplyChainReceipt, SupplyChainTable,
};
pub use registry_owner_readback::CanonicalRegistryProofPort;
pub use testd_port::{
    OmissionReason, RawEvidence, TestdAdmission, TestdAdmissionPort, TestdPortError,
};
pub use testd_profile_dispatch::{
    TESTD_DISPATCH_BINDINGS, TestdDispatchBinding, TestdDispatchError,
    compose_testd_profile_dispatch, dispatched_testd_profiles,
    instrument_contract_for_testd_profile, verify_testd_dispatch,
};
pub use testd_registry::{
    READY_PROVIDER_REGISTRY_GENERATION, TESTD_PROVIDER_REGISTRY_CONTENT_TYPE,
    TestdProviderRegistryMetadata, TestdProviderRegistryObservations,
    TestdProviderRegistrySnapshot, bind_testd_provider_registry_snapshot,
    build_testd_provider_registry, compose_testd_provider_dispatch,
    decode_testd_provider_registry_snapshot, encode_testd_provider_registry_snapshot,
    validate_testd_provider_factory,
};
pub use verification_profile::{
    AggregateOutcome, DeclaredEnvironmentDependency, ExternalToolProvenance, PROFILE_PROOF_CEILING,
    ParityVerdict, ProfileRunEvidence, RECEIPT_SCHEMA, RECEIPT_SCHEMA_VERSION, ReceiptBindings,
    ReceiptSchemaIdentity, StageEvidenceRecord, ToolIdentityRecord, VERIFICATION_OPERATION_KIND,
    VERIFICATION_PROFILE_VERIFIER, VERIFICATION_PROFILE_VERIFIER_REVISION,
    VerificationProfileError, VerificationProfileReceipt, build_verification_profile_receipt,
    check_declared_environment_dependencies, issue_receipt_envelope, parity_summary,
    require_provenance, verify_profile_parity,
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
    /// The shared canonical registry checker refused this external stage.
    #[error(transparent)]
    RegistryAdmission(#[from] eliot_instrument_api::registry::RegistryAdmissionError),
    /// The process implementation rejected the operation.
    #[error(transparent)]
    Process(#[from] ProcessExecutionError),
    /// The exact instrument kind already has its declared number of live processes.
    #[error("instrument kind '{kind}' reached its admitted concurrency limit ({limit})")]
    AdmissionConcurrency { kind: String, limit: u32 },
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
    /// Exact original pre-start admission grant, when the launch used the
    /// shared profile gate.
    pub admission_grant: Option<InstrumentAdmissionGrant>,
    /// Executable observation pinned before launch, if verified.
    pub executable: Option<ResolvedExecutableIdentity>,
    /// Exact process argv sealed from the request at launch.
    pub argv: Vec<String>,
    /// Working directory sealed from the request at launch.
    pub working_directory: String,
    /// `CARGO_TARGET_DIR` sealed from the request environment at launch,
    /// when the admitted request carries one.
    pub target_root_observed: Option<String>,
    /// `CARGO_HOME` sealed from the request environment at launch, when
    /// the admitted request carries one.
    pub cache_root_observed: Option<String>,
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

/// A governed result with the lane identity that produced it attached.
#[derive(Clone, Debug)]
pub struct EnvelopedInstrumentResult {
    /// The runner's governed result: invocation, executable identity, argv,
    /// raw output, and execution axis.
    pub result: GovernedInstrumentResult,
    /// Which candidate, fingerprint, and contract revision produced it.
    pub identity: CandidateIdentity,
}

impl EnvelopedInstrumentResult {
    /// Attaches a work item's lane identity to one emitted governed result.
    ///
    /// The identity is read from the one [`GovernedWorkEnvelope`] the work
    /// item was allocated in, so the attached candidate and contract revision
    /// can never disagree with the lane. The envelope type lives in
    /// `eliot-build-test-graph` so the test daemon reads the same identity
    /// onto its verification receipt; this constructor is the runner-side
    /// counterpart of that attachment.
    ///
    /// # Errors
    ///
    /// Returns [`WorkEnvelopeError::InvalidFingerprint`] when the fingerprint
    /// is not a valid fingerprint.
    pub fn attach(
        envelope: &GovernedWorkEnvelope,
        result: GovernedInstrumentResult,
    ) -> Result<Self, WorkEnvelopeError> {
        Ok(Self {
            result,
            identity: envelope.candidate_identity()?,
        })
    }
}

/// The bounded facade over the injected physical process executor.
pub struct InstrumentRunner<E> {
    executor: Arc<E>,
    admission_state: Arc<InstrumentAdmissionState>,
}

/// Shared live-process accounting for clones of one runner owner.
///
/// Each slot is retained from admitted start until terminal inspection or
/// successful reconciliation. Sharing this value is required when one
/// executor owner is exposed through multiple Runner handles.
#[derive(Debug, Default)]
pub struct InstrumentAdmissionState {
    inner: Mutex<InstrumentAdmissionStateInner>,
}

#[derive(Debug, Default)]
struct InstrumentAdmissionStateInner {
    active: BTreeMap<String, ActiveInstrumentOperation>,
}

#[derive(Debug)]
struct ActiveInstrumentOperation {
    kind: String,
}

impl InstrumentAdmissionState {
    fn reserve(
        &self,
        operation: &OperationId,
        grant: &InstrumentAdmissionGrant,
    ) -> Result<(), RunnerError> {
        let operation = operation.as_str().to_owned();
        let kind = format!("{}@{}", grant.kind_id, grant.kind_version);
        let mut inner = self.inner.lock().map_err(|_| {
            RunnerError::Binding("instrument admission state is unavailable".to_owned())
        })?;
        if inner.active.contains_key(&operation) {
            return Err(RunnerError::ReceiptMismatch);
        }
        let count = inner
            .active
            .values()
            .filter(|active| active.kind == kind)
            .count();
        if count >= grant.max_concurrency as usize {
            return Err(RunnerError::AdmissionConcurrency {
                kind: grant.kind_id.clone(),
                limit: grant.max_concurrency,
            });
        }
        inner
            .active
            .insert(operation, ActiveInstrumentOperation { kind });
        Ok(())
    }

    fn release(&self, operation: &OperationId) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.active.remove(operation.as_str());
        }
    }

    fn release_after_pre_resume_refusal(
        &self,
        operation: &OperationId,
        error: &RunnerError,
    ) -> bool {
        if matches!(
            error,
            RunnerError::Process(ProcessExecutionError::Contract(_))
        ) {
            self.release(operation);
            true
        } else {
            false
        }
    }
}

impl<E> Clone for InstrumentRunner<E> {
    fn clone(&self) -> Self {
        Self {
            executor: Arc::clone(&self.executor),
            admission_state: Arc::clone(&self.admission_state),
        }
    }
}

impl<E> InstrumentRunner<E> {
    /// Creates a runner around the active production process executor.
    #[must_use]
    pub fn new(executor: Arc<E>) -> Self {
        Self {
            executor,
            admission_state: Arc::new(InstrumentAdmissionState::default()),
        }
    }

    /// Creates a runner using owner-shared per-kind live-process accounting.
    #[must_use]
    pub fn new_with_admission_state(
        executor: Arc<E>,
        admission_state: Arc<InstrumentAdmissionState>,
    ) -> Self {
        Self {
            executor,
            admission_state,
        }
    }

    /// Returns the admission state that sibling runner handles must share.
    #[must_use]
    pub fn admission_state(&self) -> Arc<InstrumentAdmissionState> {
        Arc::clone(&self.admission_state)
    }
}

impl<E: ProcessExecutor + 'static> InstrumentRunner<E> {
    /// Binds an invocation and launches it through P-03.
    ///
    /// # Errors
    /// Returns an error when binding or process launch fails, or when the
    /// returned receipt does not preserve the binding identity.
    pub(crate) async fn launch_bound(
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
    pub(crate) async fn launch_verified(
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
    pub(crate) async fn launch_verified_with_bootstrap(
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
    pub(crate) async fn launch(
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
        let working_directory = process_request.working_directory().to_owned();
        let target_root_observed = process_request
            .environment()
            .non_secret()
            .get("CARGO_TARGET_DIR")
            .cloned();
        let cache_root_observed = process_request
            .environment()
            .non_secret()
            .get("CARGO_HOME")
            .cloned();
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
            admission_grant: None,
            executable,
            argv,
            working_directory,
            target_root_observed,
            cache_root_observed,
        })
    }

    /// Launches the exact immutable binding only under a sealed admission grant.
    ///
    /// The grant must seal itself and must bind the sealed request's exact
    /// arguments and executable digest: a grant minted for another object, or
    /// a request that drifted after admission, fails closed here instead of
    /// reaching the executor. Observation and revocation stay with the
    /// admission boundary; this is the at-dispatch revalidation of the same
    /// object at use.
    ///
    /// # Errors
    /// Returns [`RunnerError::ReceiptMismatch`] when the grant does not seal
    /// itself, the binding is already consumed, or the sealed request drifts
    /// from the grant, and the underlying launch error otherwise.
    pub(crate) async fn launch_admitted(
        &self,
        binding: &mut InstrumentBinding,
        admitted: &profile_run::AdmittedStageGrant,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Result<InstrumentStartReceipt, RunnerError> {
        let grant = &admitted.grant;
        if grant.digest() != grant.grant_digest {
            return Err(RunnerError::ReceiptMismatch);
        }
        if profile_run::admitted_binding_seal(binding)? != admitted.binding_seal {
            return Err(RunnerError::ReceiptMismatch);
        }
        let Some(request) = binding.process_request.as_ref() else {
            return Err(RunnerError::ReceiptMismatch);
        };
        if request.argv() != grant.arguments.as_slice() {
            return Err(RunnerError::ReceiptMismatch);
        }
        if request.executable_sha256() != grant.content_digest.as_str() {
            return Err(RunnerError::ReceiptMismatch);
        }
        if grant.source_root.as_deref() != Some(request.working_directory())
            || grant.declared_scope.as_deref() != Some(binding.invocation.declared_scope.as_str())
            || grant.environment_digest.as_deref()
                != Some(
                    eliot_process_executor::environment_projection_digest(request.environment())
                        .as_str(),
                )
            || grant.authority_epoch.as_ref() != Some(request.fence().authority_epoch())
            || grant.resource_generation != Some(request.fence().generation().get())
        {
            return Err(RunnerError::ReceiptMismatch);
        }
        if request.intent().instrument_admission_digest() != Some(grant.digest().as_str()) {
            return Err(RunnerError::ReceiptMismatch);
        }
        if request.intent().executable_file_identity() != grant.executable_file_identity.as_ref()
            || grant.executable_file_identity.is_none()
        {
            return Err(RunnerError::ReceiptMismatch);
        }
        self.admission_state.reserve(&binding.operation_id, grant)?;
        match self.launch(binding, sink).await {
            Ok(mut receipt) => {
                receipt.admission_grant = Some(grant.clone());
                Ok(receipt)
            }
            Err(error) => {
                self.admission_state
                    .release_after_pre_resume_refusal(&binding.operation_id, &error);
                Err(error)
            }
        }
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
        let view = match self.executor.inspect(binding.operation_id.clone()).await {
            Ok(view) => view,
            Err(error) => {
                return Err(RunnerError::from(error));
            }
        };
        if view.operation_id() != &binding.operation_id
            || view.request_digest() != binding.request_digest
            || view.fence().generation().get() != binding.generation
        {
            return Err(RunnerError::ObservationMismatch);
        }
        if view.lifecycle().is_terminal() {
            self.admission_state.release(&binding.operation_id);
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
        let evidence = match self.executor.reconcile(binding.operation_id.clone()).await {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(RunnerError::from(error));
            }
        };
        if evidence.operation_id() != &binding.operation_id
            || evidence.request_digest() != binding.request_digest
        {
            return Err(RunnerError::ObservationMismatch);
        }
        self.admission_state.release(&binding.operation_id);
        Ok(evidence)
    }
}

/// Converts an executor-side machine observation into the registry-bound
/// identity form.
///
/// Both records carry the same machine-derived fields (canonical path, exact
/// file-object identity, content digest, tool version, environment digest,
/// exact argv); the
/// executor resolves them from the machine at launch while the registry
/// checks them before launch and at verdict time. Validation is re-applied
/// under the claiming `instrument` so a bridged observation can never carry
/// an empty instrument label.
impl From<eliot_process_executor::ExecutableObservation> for ResolvedExecutableIdentity {
    fn from(observation: eliot_process_executor::ExecutableObservation) -> Self {
        Self {
            canonical_path: observation.canonical_path,
            file_identity: observation.file_identity,
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
    let file_identity = observation.file_identity;
    let mut resolved = ResolvedExecutableIdentity::new(
        instrument,
        observation.canonical_path,
        observation.content_digest,
        observation.tool_version,
        observation.environment_digest,
        observation.arguments,
    )?;
    resolved.file_identity = file_identity;
    Ok(resolved)
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
        ArtifactId, ClockReading, ContractId, ContractVersion, EpochId, EpochLineageId, ProductId,
        RequestId, RequestMetadata, SourceId, StateFence,
    };
    use eliot_instrument_api::InstrumentKind;
    use eliot_instrument_rustc::RUSTC_INSTRUMENT;
    use std::num::NonZeroU64;

    use crate::registry::InvalidationSet;

    #[test]
    fn per_kind_concurrency_is_independent_and_released_only_for_the_terminal_operation() {
        fn grant(kind: &str, max_concurrency: u32) -> InstrumentAdmissionGrant {
            let identity = ContractId::new(kind.to_owned()).expect("kind identity");
            InstrumentAdmissionGrant {
                kind_id: kind.to_owned(),
                kind_version: ContractVersion::new(1, 0, 0),
                kind: InstrumentKind::Test,
                profile: "profile:test".to_owned(),
                profile_revision: 1,
                spec_digest: "a".repeat(64),
                executable: "test-runner.exe".to_owned(),
                executable_version: None,
                content_digest: "b".repeat(64),
                executable_path: "C:\\tools\\test-runner.exe".to_owned(),
                executable_file_identity: None,
                supply_digest: "c".repeat(64),
                arguments: vec!["test".to_owned()],
                environment_class: "isolated-process".to_owned(),
                scope_class: "admitted-scope".to_owned(),
                source_root: Some("C:\\work".to_owned()),
                declared_scope: Some("workspace".to_owned()),
                environment_digest: Some("d".repeat(64)),
                authority_epoch: None,
                resource_generation: Some(1),
                credential_policy: identity.clone(),
                network_policy: identity.clone(),
                timeout_ms: None,
                max_output_bytes: None,
                parser: identity,
                parser_generation: 1,
                max_concurrency,
                grant_digest: String::new(),
            }
        }

        let state = InstrumentAdmissionState::default();
        let first = OperationId::new("operation:first").expect("operation");
        let same_kind = OperationId::new("operation:same-kind").expect("operation");
        let other_kind = OperationId::new("operation:other-kind").expect("operation");
        let pre_resume_refused =
            OperationId::new("operation:pre-resume-refused").expect("operation");
        let unknown_outcome = OperationId::new("operation:unknown-outcome").expect("operation");
        let kind_a = grant("eliot.instrument.testd.alpha", 1);
        let kind_b = grant("eliot.instrument.testd.beta", 1);

        assert!(state.reserve(&first, &kind_a).is_ok());
        assert!(matches!(
            state.reserve(&same_kind, &kind_a),
            Err(RunnerError::AdmissionConcurrency { kind, limit: 1 })
                if kind == kind_a.kind_id
        ));
        assert!(state.reserve(&other_kind, &kind_b).is_ok());
        state.release(&first);
        assert!(state.reserve(&same_kind, &kind_a).is_ok());

        assert!(state.reserve(&pre_resume_refused, &kind_b).is_ok());
        let contract_refusal = RunnerError::Process(ProcessExecutionError::Contract(
            eliot_contracts::ContractError::InvalidValue {
                field: "pre_resume_test",
                reason: "validation refused before resume",
            },
        ));
        assert!(state.release_after_pre_resume_refusal(&pre_resume_refused, &contract_refusal));
        assert!(state.reserve(&pre_resume_refused, &kind_b).is_ok());

        state.release(&other_kind);
        assert!(state.reserve(&unknown_outcome, &kind_b).is_ok());
        let uncertain_start = RunnerError::Process(ProcessExecutionError::UnknownOutcome);
        assert!(!state.release_after_pre_resume_refusal(&unknown_outcome, &uncertain_start));
        assert!(matches!(
            state.reserve(
                &OperationId::new("operation:still-full").expect("operation"),
                &kind_b
            ),
            Err(RunnerError::AdmissionConcurrency { limit: 1, .. })
        ));
    }

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
