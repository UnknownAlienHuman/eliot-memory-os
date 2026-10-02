//! Kernel-owned one-shot dispatch authority for authenticated child grants.

use std::collections::BTreeMap;
use std::path::Path;
#[cfg(windows)]
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::sha256_hex;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, ContractError, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, FencingToken, Generation, KernelDispatchGrant, KernelDispatchKey,
    PermitIssuance, ProcessEvidence, ProcessExecutionError, ProcessIntent, ProcessRequest,
};

#[cfg(windows)]
fn observed_image_matches_admitted(observed_image: &str, admitted_executable: &str) -> bool {
    let Ok(canonical_observed) = std::fs::canonicalize(observed_image) else {
        return false;
    };
    eliot_platform_windows::windows_paths_equal(&canonical_observed, Path::new(admitted_executable))
}

#[cfg(windows)]
use eliot_process::{SuspendedLaunchEvidence, SuspendedProcessIdentity, ValidatedDispatch};

#[cfg(windows)]
use crate::{
    INSTRUMENT_STAGE_STARTED_OPERATION, INSTRUMENT_STAGE_TERMINAL_OPERATION,
    InstrumentStageRuntimeObservationPort, InstrumentStageStartedRequest,
    InstrumentStageStartedResponse, InstrumentStageTerminalRequest,
    InstrumentStageTerminalResponse,
};

#[cfg(windows)]
#[derive(Clone)]
enum InstrumentDispatchLifecycle {
    Generic,
    Testd { job_id: String, attempt_seq: u32 },
}

#[cfg(windows)]
impl InstrumentDispatchLifecycle {
    fn attempt_identity(&self) -> (Option<String>, Option<u32>) {
        match self {
            Self::Generic => (None, None),
            Self::Testd {
                job_id,
                attempt_seq,
            } => (Some(job_id.clone()), Some(*attempt_seq)),
        }
    }
}

#[cfg(windows)]
#[derive(Clone)]
struct InstrumentDispatchBinding {
    identity: eliot_ipc::RequestIdentity,
    operation_id: eliot_process::OperationId,
    admission_digest: String,
    /// The exact Kernel-issued grant digest remains private authority state.
    dispatch_grant_digest: String,
    intent_effect_digest: String,
    process_request_digest: String,
    lifecycle: InstrumentDispatchLifecycle,
}

#[cfg(windows)]
impl InstrumentDispatchBinding {
    fn lifecycle_dispatch_grant_digest(&self) -> Option<String> {
        Some(self.dispatch_grant_digest.clone())
    }

    fn lifecycle_attempt_identity(&self) -> (Option<String>, Option<u32>) {
        self.lifecycle.attempt_identity()
    }
}

/// P-07 authority that validates an original Kernel grant and issues its
/// in-process one-shot request for the P-04 executor.
pub struct KernelChildDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
    #[cfg(windows)]
    observation_port: Option<Arc<dyn InstrumentStageRuntimeObservationPort>>,
    #[cfg(windows)]
    instrument_binding: Mutex<Option<InstrumentDispatchBinding>>,
}

impl KernelChildDispatchAuthority {
    /// Activates one process-local Kernel dispatch authority.
    pub fn new() -> Result<Self, ProcessExecutionError> {
        let authority_id = DispatchAuthorityId::new(format!(
            "kernel-child-dispatch-{}-{}",
            std::process::id(),
            system_nanos()
        ))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
            #[cfg(windows)]
            observation_port: None,
            #[cfg(windows)]
            instrument_binding: Mutex::new(None),
        })
    }

    /// Activates the P-07 authority with the required authenticated P-04
    /// lifecycle observer for new external instrument grants.
    #[cfg(windows)]
    pub fn new_with_observation_port(
        observation_port: Arc<dyn InstrumentStageRuntimeObservationPort>,
    ) -> Result<Self, ProcessExecutionError> {
        let mut authority = Self::new()?;
        authority.observation_port = Some(observation_port);
        Ok(authority)
    }

    /// Consumes a dispatch grant only from the exact authenticated Kernel
    /// response that admitted this process intent. A caller-created JSON
    /// grant is not an authenticated response and cannot enter this path.
    pub fn issue_authenticated(
        &self,
        request: &crate::InstrumentStageGrantRequest,
        original_identity: &eliot_ipc::RequestIdentity,
        response: eliot_ipc::kernel_client::AuthenticatedKernelResponse,
        now_ms: u64,
    ) -> Result<ProcessRequest, ProcessExecutionError> {
        use crate::{INSTRUMENT_STAGE_GRANT_OPERATION, InstrumentStageGrantResponse};

        let intent = &request.intent;
        original_identity.validate().map_err(|_| {
            ProcessExecutionError::Contract(ContractError::DigestMismatch {
                field: "authenticated_kernel_response.request_identity",
                expected: intent.operation_id().as_str().to_owned(),
                observed: response
                    .request_identity()
                    .request
                    .metadata
                    .request_id
                    .as_str()
                    .to_owned(),
            })
        })?;
        intent.validate()?;
        request.invocation.validate().map_err(|_| {
            ProcessExecutionError::Contract(ContractError::DigestMismatch {
                field: "authenticated_kernel_response.instrument_invocation",
                expected: original_identity
                    .request
                    .metadata
                    .request_id
                    .as_str()
                    .to_owned(),
                observed: request.invocation.request.request_id.as_str().to_owned(),
            })
        })?;
        if response.operation() != INSTRUMENT_STAGE_GRANT_OPERATION
            || response.request_identity() != original_identity
            || request.invocation.request != original_identity.request.metadata
            || request.invocation.request.state_fence != original_identity.request.state_fence
            || original_identity.request.metadata.request_id.as_str()
                != intent.operation_id().as_str()
            || original_identity
                .request
                .state_fence
                .resource_generation
                .value()
                != intent.generation().get()
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "authenticated_kernel_response.binding",
                    expected: format!(
                        "{}:{}:{}",
                        INSTRUMENT_STAGE_GRANT_OPERATION,
                        original_identity.request.metadata.request_id,
                        intent.generation().get()
                    ),
                    observed: format!(
                        "{}:{}:{}",
                        response.operation(),
                        response.request_identity().request.metadata.request_id,
                        response
                            .request_identity()
                            .request
                            .state_fence
                            .resource_generation
                            .value()
                    ),
                },
            ));
        }
        let grant_response: InstrumentStageGrantResponse =
            serde_json::from_value(response.payload().clone()).map_err(|error| {
                ProcessExecutionError::Unavailable(format!(
                    "decode authenticated Kernel stage grant: {error}"
                ))
            })?;
        let expected_file_identity =
            intent
                .executable_file_identity()
                .ok_or(ContractError::InvalidValue {
                    field: "instrument_dispatch.executable_file_identity",
                    reason: "new external-stage grants require the original observed file object",
                })?;
        if grant_response.admission.executable_file_identity.as_ref()
            != Some(expected_file_identity)
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "instrument_admission.executable_file_identity",
                    expected: format!("{expected_file_identity:?}"),
                    observed: format!("{:?}", grant_response.admission.executable_file_identity),
                },
            ));
        }
        request
            .validate_admission_binding(&grant_response.admission)
            .map_err(ProcessExecutionError::from)?;
        if grant_response.dispatch_grant.authority_epoch
            != original_identity.request.state_fence.authority_epoch
            || grant_response.dispatch_grant.fence_generation
                != original_identity
                    .request
                    .state_fence
                    .resource_generation
                    .value()
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::FenceMismatch,
            ));
        }
        #[cfg(windows)]
        let is_instrument = intent.instrument_admission_digest().is_some();
        #[cfg(not(windows))]
        let is_instrument = intent.instrument_admission_digest().is_some();
        #[cfg(windows)]
        if is_instrument && self.observation_port.is_none() {
            return Err(ProcessExecutionError::Unavailable(
                "new instrument grants require the authenticated Kernel lifecycle observer"
                    .to_owned(),
            ));
        }
        #[cfg(not(windows))]
        if is_instrument {
            return Err(ProcessExecutionError::Unavailable(
                "new instrument grants require the Windows Kernel lifecycle observer".to_owned(),
            ));
        }
        let process_request = self.issue(intent, &grant_response.dispatch_grant, now_ms)?;
        #[cfg(windows)]
        if is_instrument {
            let binding = InstrumentDispatchBinding {
                identity: original_identity.clone(),
                operation_id: process_request.operation_id().clone(),
                admission_digest: grant_response.admission.grant_digest,
                dispatch_grant_digest: grant_response.dispatch_grant.grant_digest,
                intent_effect_digest: intent.effect_digest().to_owned(),
                process_request_digest: process_request.invocation_digest().to_owned(),
                lifecycle: InstrumentDispatchLifecycle::Generic,
            };
            let mut stored = self.instrument_binding.lock().map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "instrument dispatch binding lock poisoned".to_owned(),
                )
            })?;
            if stored.is_some() {
                return Err(ProcessExecutionError::Unavailable(
                    "Kernel child dispatch authority already owns an instrument request".to_owned(),
                ));
            }
            *stored = Some(binding);
        }
        Ok(process_request)
    }

    /// Consumes one sealed Kernel TestD attempt response and issues the
    /// original Kernel grant for the exact durable TestD attempt. The caller
    /// supplies the independent owner-retained job intent/admission and the
    /// authenticated current identity; no JSON grant can enter this path.
    #[cfg(windows)]
    pub fn issue_testd_authenticated(
        &self,
        original_identity: &eliot_ipc::RequestIdentity,
        original_intent: &ProcessIntent,
        original_admission: &eliot_instrument_api::InstrumentAdmissionGrant,
        job_id: &str,
        attempt_seq: u32,
        response: eliot_ipc::kernel_client::AuthenticatedKernelResponse,
        now_ms: u64,
    ) -> Result<ProcessRequest, ProcessExecutionError> {
        use crate::{TESTD_ADMISSION_WIRE_ID, TestdAdmissionResponse};

        original_identity.validate().map_err(|_| {
            ProcessExecutionError::Contract(ContractError::DigestMismatch {
                field: "testd_dispatch.request_identity",
                expected: original_intent.operation_id().as_str().to_owned(),
                observed: response
                    .request_identity()
                    .request
                    .metadata
                    .request_id
                    .as_str()
                    .to_owned(),
            })
        })?;
        original_intent.validate()?;
        if self.observation_port.is_none() {
            return Err(ProcessExecutionError::Unavailable(
                "TestD instrument grants require the authenticated Kernel lifecycle observer"
                    .to_owned(),
            ));
        }
        if original_intent.instrument_admission_digest()
            != Some(original_admission.grant_digest.as_str())
            || original_admission.digest() != original_admission.grant_digest
            || response.operation() != TESTD_ADMISSION_WIRE_ID
            || response.request_identity() != original_identity
            || original_identity
                .request
                .state_fence
                .resource_generation
                .value()
                != original_intent.generation().get()
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "testd_dispatch.authenticated_binding",
                    expected: format!(
                        "{}:{}:{}:{}",
                        TESTD_ADMISSION_WIRE_ID,
                        original_identity.request.metadata.request_id,
                        job_id,
                        attempt_seq
                    ),
                    observed: format!(
                        "{}:{}:{}:{}",
                        response.operation(),
                        response.request_identity().request.metadata.request_id,
                        original_intent.operation_id(),
                        original_intent.generation().get()
                    ),
                },
            ));
        }

        let decoded: TestdAdmissionResponse = serde_json::from_value(response.payload().clone())
            .map_err(|error| {
                ProcessExecutionError::Unavailable(format!(
                    "decode authenticated TestD attempt grant: {error}"
                ))
            })?;
        decoded.validate().map_err(|error| {
            ProcessExecutionError::Unavailable(format!(
                "validate authenticated TestD attempt grant: {error}"
            ))
        })?;
        let TestdAdmissionResponse::Admitted(admission) = decoded else {
            return Err(ProcessExecutionError::Unavailable(
                "Kernel did not admit the TestD process attempt".to_owned(),
            ));
        };
        let attempt = admission.process_attempt_grant.as_ref().ok_or_else(|| {
            ProcessExecutionError::Unavailable(
                "Kernel TestD admission omitted its original process-attempt grant".to_owned(),
            )
        })?;
        attempt.validate().map_err(|error| {
            ProcessExecutionError::Unavailable(format!(
                "validate Kernel TestD process-attempt grant: {error}"
            ))
        })?;
        let original_operation_id = original_intent.operation_id().as_str();
        if admission.job_id != job_id
            || admission.operation_id != original_operation_id
            || attempt.request_identity != *original_identity
            || attempt.job_id != job_id
            || attempt.attempt_seq != attempt_seq
            || attempt.operation_id != original_operation_id
            || attempt.process_intent.effect_digest() != original_intent.effect_digest()
            || attempt.process_intent.instrument_admission_digest()
                != original_intent.instrument_admission_digest()
            || attempt.instrument_admission.grant_digest != original_admission.grant_digest
            || attempt.instrument_admission.digest() != original_admission.digest()
            || attempt.dispatch_grant.authority_epoch
                != original_identity.request.state_fence.authority_epoch
            || attempt.dispatch_grant.fence_generation
                != original_identity
                    .request
                    .state_fence
                    .resource_generation
                    .value()
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "testd_dispatch.original_attempt_binding",
                    expected: format!(
                        "{}:{}:{}:{}:{}",
                        job_id,
                        attempt_seq,
                        original_operation_id,
                        original_intent.effect_digest(),
                        original_admission.grant_digest
                    ),
                    observed: format!(
                        "{}:{}:{}:{}:{}",
                        admission.job_id,
                        attempt.attempt_seq,
                        attempt.operation_id,
                        attempt.process_intent.effect_digest(),
                        attempt.instrument_admission.grant_digest
                    ),
                },
            ));
        }

        let mut stored = self.instrument_binding.lock().map_err(|_| {
            ProcessExecutionError::Unavailable(
                "instrument dispatch binding lock poisoned".to_owned(),
            )
        })?;
        if stored.is_some() {
            return Err(ProcessExecutionError::Unavailable(
                "Kernel child dispatch authority already owns an instrument request".to_owned(),
            ));
        }
        attempt.process_intent.validate()?;
        let process_request =
            self.issue(&attempt.process_intent, &attempt.dispatch_grant, now_ms)?;
        let binding = InstrumentDispatchBinding {
            identity: original_identity.clone(),
            operation_id: process_request.operation_id().clone(),
            admission_digest: original_admission.grant_digest.clone(),
            dispatch_grant_digest: attempt.dispatch_grant.grant_digest.clone(),
            intent_effect_digest: attempt.process_intent.effect_digest().to_owned(),
            process_request_digest: process_request.invocation_digest().to_owned(),
            lifecycle: InstrumentDispatchLifecycle::Testd {
                job_id: job_id.to_owned(),
                attempt_seq,
            },
        };
        *stored = Some(binding);
        Ok(process_request)
    }

    /// Reports the actual terminal evidence produced by P-04 reconciliation
    /// after the process owner has validated its typed streams.
    #[cfg(windows)]
    pub fn report_terminal(
        &self,
        evidence: &ProcessEvidence,
    ) -> Result<InstrumentStageTerminalResponse, ProcessExecutionError> {
        evidence.validate()?;
        let binding = self
            .instrument_binding
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "instrument dispatch binding lock poisoned".to_owned(),
                )
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(
                    "missing original Kernel instrument dispatch binding".to_owned(),
                )
            })?;
        let view = evidence.view();
        if evidence.operation_id() != &binding.operation_id
            || evidence.request_digest() != binding.process_request_digest
            || view.operation_id() != &binding.operation_id
            || (!view.lifecycle().is_terminal()
                && !(view.lifecycle() == eliot_process::ProcessLifecycle::UnknownOutcome
                    && (evidence.stdout().is_some_and(|stream| {
                        stream.transport() == eliot_process::StreamTransportStatus::ReadFailed
                    }) || evidence.stderr().is_some_and(|stream| {
                        stream.transport() == eliot_process::StreamTransportStatus::ReadFailed
                    }))))
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "instrument_terminal.process_evidence",
                    expected: format!(
                        "{}:{}:{}",
                        binding.operation_id, binding.process_request_digest, "terminal"
                    ),
                    observed: format!(
                        "{}:{}:{:?}",
                        evidence.operation_id(),
                        evidence.request_digest(),
                        view.lifecycle()
                    ),
                },
            ));
        }
        let port = self.observation_port.as_ref().ok_or_else(|| {
            ProcessExecutionError::Unavailable(
                "missing authenticated Kernel instrument lifecycle observer".to_owned(),
            )
        })?;
        let (job_id, attempt_seq) = binding.lifecycle_attempt_identity();
        let response = port.terminal(
            &binding.identity,
            InstrumentStageTerminalRequest {
                operation_id: binding.operation_id.clone(),
                admission_digest: binding.admission_digest.clone(),
                dispatch_grant_digest: binding.lifecycle_dispatch_grant_digest(),
                process_request_digest: binding.process_request_digest.clone(),
                job_id,
                attempt_seq,
                evidence: evidence.clone(),
            },
        )?;
        validate_authenticated_terminal_response(&binding, response)
    }

    #[cfg(windows)]
    fn validate_and_consume_instrument_launch(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
        launch: SuspendedLaunchEvidence,
        recoverable_job_binding: eliot_platform_windows::RecoverableJobBinding,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        request.validate()?;
        let binding = self
            .instrument_binding
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "instrument dispatch binding lock poisoned".to_owned(),
                )
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(
                    "missing original Kernel instrument dispatch binding".to_owned(),
                )
            })?;
        let expected_file_identity =
            request
                .intent()
                .executable_file_identity()
                .ok_or(ContractError::InvalidValue {
                    field: "instrument_dispatch.executable_file_identity",
                    reason: "new external-stage grants require the original observed file object",
                })?;
        let physical = observed.physical();
        let root = recoverable_job_binding.root();
        if request.operation_id() != &binding.operation_id
            || request.invocation_digest() != binding.process_request_digest
            || request.intent().effect_digest() != binding.intent_effect_digest
            || request.intent().instrument_admission_digest()
                != Some(binding.admission_digest.as_str())
            || observed.executable_sha256() != request.intent().executable_sha256()
            || launch.requested_executable() != request.intent().executable()
            || launch.executable_volume_serial_number()
                != expected_file_identity.volume_serial_number
            || launch.executable_file_index() != expected_file_identity.file_index
            || root.process().process_id != physical.process_id()
            || root.process().start_time_100ns != physical.start_time_100ns()
            || root.process().image_path != physical.image_path()
            || !observed_image_matches_admitted(
                &root.process().image_path,
                request.intent().executable(),
            )
            || root.executable_file_identity() != *expected_file_identity
        {
            return Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch {
                    field: "instrument_dispatch.suspended_binding",
                    expected: format!(
                        "{}:{}:{}:{}:{}",
                        binding.operation_id,
                        binding.process_request_digest,
                        request.intent().executable(),
                        expected_file_identity.volume_serial_number,
                        expected_file_identity.file_index
                    ),
                    observed: format!(
                        "{}:{}:{}:{}:{}",
                        request.operation_id(),
                        request.invocation_digest(),
                        root.process().image_path,
                        root.executable_file_identity().volume_serial_number,
                        root.executable_file_identity().file_index
                    ),
                },
            ));
        }

        let port = self.observation_port.as_ref().ok_or_else(|| {
            ProcessExecutionError::Unavailable(
                "missing authenticated Kernel instrument lifecycle observer".to_owned(),
            )
        })?;
        let (job_id, attempt_seq) = binding.lifecycle_attempt_identity();
        let response = port.before_resume(
            &binding.identity,
            InstrumentStageStartedRequest {
                operation_id: binding.operation_id.clone(),
                admission_digest: binding.admission_digest.clone(),
                dispatch_grant_digest: binding.lifecycle_dispatch_grant_digest(),
                process_request_digest: request.invocation_digest().to_owned(),
                job_id,
                attempt_seq,
                suspended_identity: observed.clone(),
                launch,
                recoverable_job_binding,
            },
        )?;
        validate_authenticated_started_response(&binding, response)?;
        self.consume_dispatch(request, observed)
    }

    fn consume_dispatch(
        &self,
        request: ProcessRequest,
        observed: eliot_process::SuspendedProcessIdentity,
    ) -> Result<eliot_process::ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(
                    "missing Kernel dispatch validation context".to_owned(),
                )
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }

    /// Validates a grant's own digest domain and issues one process request.
    /// This low-level operation is private so production callers must first
    /// consume the authenticated Kernel response above.
    fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &KernelDispatchGrant,
        now_ms: u64,
    ) -> Result<ProcessRequest, ProcessExecutionError> {
        intent.validate()?;
        validate_original_grant(intent, grant, now_ms)?;

        let generation = Generation::new(grant.fence_generation)?;
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
            generation,
            grant.fence_nonce.clone(),
        )?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone())?;
        let heads = BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_ms.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("dispatch authority lock poisoned".to_owned())
            })?
            .issue(intent, issuance)?;

        let observed_ms = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(observed_ms),
                known_time_ms: Some(observed_ms),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch.clone(),
            heads,
            1,
        )?;
        *self.context.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("dispatch context lock poisoned".to_owned())
        })? = Some(context);
        Ok(ProcessRequest::new(intent.clone(), permit)?)
    }
}

impl eliot_process::DispatchValidationPort for KernelChildDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: eliot_process::SuspendedProcessIdentity,
    ) -> Result<eliot_process::ValidatedDispatch, ProcessExecutionError> {
        if request.intent().instrument_admission_digest().is_some() {
            return Err(ProcessExecutionError::Unavailable(
                "new instrument requests require the suspended-child lifecycle observation"
                    .to_owned(),
            ));
        }
        self.consume_dispatch(request, observed)
    }

    #[cfg(windows)]
    fn validate_and_consume_instrument(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
        launch: SuspendedLaunchEvidence,
        recoverable_job_binding: eliot_platform_windows::RecoverableJobBinding,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        if request.intent().instrument_admission_digest().is_none() {
            return Err(ProcessExecutionError::Contract(
                ContractError::InvalidValue {
                    field: "instrument_dispatch.admission_digest",
                    reason: "instrument lifecycle validation requires an original admission",
                },
            ));
        }
        self.validate_and_consume_instrument_launch(
            request,
            observed,
            launch,
            recoverable_job_binding,
        )
    }
}

#[cfg(windows)]
fn validate_authenticated_started_response(
    binding: &InstrumentDispatchBinding,
    response: eliot_ipc::kernel_client::AuthenticatedKernelResponse,
) -> Result<InstrumentStageStartedResponse, ProcessExecutionError> {
    if response.operation() != INSTRUMENT_STAGE_STARTED_OPERATION
        || response.request_identity() != &binding.identity
    {
        return Err(ProcessExecutionError::Contract(
            ContractError::DigestMismatch {
                field: "instrument_stage.started_response.binding",
                expected: format!(
                    "{}:{}",
                    INSTRUMENT_STAGE_STARTED_OPERATION,
                    binding.identity.request.metadata.request_id
                ),
                observed: format!(
                    "{}:{}",
                    response.operation(),
                    response.request_identity().request.metadata.request_id
                ),
            },
        ));
    }
    let echo: InstrumentStageStartedResponse = serde_json::from_value(response.payload().clone())
        .map_err(|error| {
        ProcessExecutionError::Unavailable(format!(
            "decode authenticated Kernel started observation: {error}"
        ))
    })?;
    let (job_id, attempt_seq) = binding.lifecycle_attempt_identity();
    if echo.operation_id != binding.operation_id
        || echo.admission_digest != binding.admission_digest
        || echo.dispatch_grant_digest != binding.lifecycle_dispatch_grant_digest()
        || echo.process_request_digest != binding.process_request_digest
        || echo.job_id != job_id
        || echo.attempt_seq != attempt_seq
    {
        return Err(ProcessExecutionError::Contract(
            ContractError::DigestMismatch {
                field: "instrument_stage.started_response.echo",
                expected: format!(
                    "{}:{}:{}:{}:{:?}:{:?}",
                    binding.operation_id,
                    binding.admission_digest,
                    binding.lifecycle_dispatch_grant_digest(),
                    binding.process_request_digest,
                    job_id,
                    attempt_seq
                ),
                observed: format!(
                    "{}:{}:{}:{}:{:?}:{:?}",
                    echo.operation_id,
                    echo.admission_digest,
                    echo.dispatch_grant_digest,
                    echo.process_request_digest,
                    echo.job_id,
                    echo.attempt_seq
                ),
            },
        ));
    }
    Ok(echo)
}

#[cfg(windows)]
fn validate_authenticated_terminal_response(
    binding: &InstrumentDispatchBinding,
    response: eliot_ipc::kernel_client::AuthenticatedKernelResponse,
) -> Result<InstrumentStageTerminalResponse, ProcessExecutionError> {
    if response.operation() != INSTRUMENT_STAGE_TERMINAL_OPERATION
        || response.request_identity() != &binding.identity
    {
        return Err(ProcessExecutionError::Contract(
            ContractError::DigestMismatch {
                field: "instrument_stage.terminal_response.binding",
                expected: format!(
                    "{}:{}",
                    INSTRUMENT_STAGE_TERMINAL_OPERATION,
                    binding.identity.request.metadata.request_id
                ),
                observed: format!(
                    "{}:{}",
                    response.operation(),
                    response.request_identity().request.metadata.request_id
                ),
            },
        ));
    }
    let echo: InstrumentStageTerminalResponse = serde_json::from_value(response.payload().clone())
        .map_err(|error| {
            ProcessExecutionError::Unavailable(format!(
                "decode authenticated Kernel terminal observation: {error}"
            ))
        })?;
    let (job_id, attempt_seq) = binding.lifecycle_attempt_identity();
    if echo.operation_id != binding.operation_id
        || echo.admission_digest != binding.admission_digest
        || echo.dispatch_grant_digest != binding.lifecycle_dispatch_grant_digest()
        || echo.process_request_digest != binding.process_request_digest
        || echo.job_id != job_id
        || echo.attempt_seq != attempt_seq
    {
        return Err(ProcessExecutionError::Contract(
            ContractError::DigestMismatch {
                field: "instrument_stage.terminal_response.echo",
                expected: format!(
                    "{}:{}:{}:{}:{:?}:{:?}",
                    binding.operation_id,
                    binding.admission_digest,
                    binding.lifecycle_dispatch_grant_digest(),
                    binding.process_request_digest,
                    job_id,
                    attempt_seq
                ),
                observed: format!(
                    "{}:{}:{}:{}:{:?}:{:?}",
                    echo.operation_id,
                    echo.admission_digest,
                    echo.dispatch_grant_digest,
                    echo.process_request_digest,
                    echo.job_id,
                    echo.attempt_seq
                ),
            },
        ));
    }
    Ok(echo)
}

fn validate_original_grant(
    intent: &ProcessIntent,
    grant: &KernelDispatchGrant,
    now_ms: u64,
) -> Result<(), ContractError> {
    if grant.fence_generation == 0 || grant.fence_generation != intent.generation().get() {
        return Err(ContractError::FenceMismatch);
    }
    if grant.expires_at <= now_ms || now_ms == 0 {
        return Err(ContractError::InvalidValue {
            field: "dispatch_grant_freshness",
            reason: "grant must be unexpired at a non-zero observation time",
        });
    }
    if grant
        .testd_owner_store_path
        .as_ref()
        .is_some_and(|path| path.trim().is_empty() || !Path::new(path).is_absolute())
    {
        return Err(ContractError::InvalidValue {
            field: "testd_owner_store_path",
            reason: "must be a non-blank absolute path",
        });
    }

    let epoch_json = serde_json::to_string(&grant.authority_epoch)
        .map_err(|error| ContractError::Serialization(error.to_string()))?;
    let mut material = String::with_capacity(256);
    material.push_str(intent.effect_digest());
    material.push('|');
    material.push_str(&epoch_json);
    material.push('|');
    material.push_str(&grant.fence_generation.to_string());
    material.push('|');
    material.push_str(&grant.fence_nonce);
    material.push('|');
    material.push_str(&grant.idempotency_key);
    material.push('|');
    material.push_str(&grant.expires_at.to_string());
    if let Some(path) = grant.testd_owner_store_path.as_deref() {
        material.push_str("|testd-owner-store|");
        material.push_str(path);
    }
    let expected = sha256_hex(material.as_bytes());
    if grant.grant_digest != expected {
        return Err(ContractError::DigestMismatch {
            field: "kernel_dispatch_grant.grant_digest",
            expected,
            observed: grant.grant_digest.clone(),
        });
    }
    Ok(())
}

/// Generates an instance label. Uniqueness names the authority; key bytes
/// stay local to this process and never cross the Kernel boundary.
fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Reuses the existing TestD process-local dispatch authority key derivation.
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
    let stack = std::ptr::addr_of!(probe) as usize as u64;
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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_process::{
        EnvironmentInheritance, EnvironmentProjection, ImageId, JobId, OperationId, ProcessTreeId,
        ResourceLimits, SessionId,
    };
    use std::num::NonZeroU64;

    fn intent() -> ProcessIntent {
        ProcessIntent::new(
            OperationId::new("operation-1").unwrap(),
            ProcessTreeId::new("tree-1").unwrap(),
            JobId::new("job-1").unwrap(),
            ImageId::new("image-1").unwrap(),
            SessionId::new("session-1").unwrap(),
            Generation::new(7).unwrap(),
            "C:\\tools\\worker.exe",
            "a".repeat(64),
            vec!["--one-shot".to_owned()],
            "C:\\work",
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .unwrap(),
            ResourceLimits::new(60_000, None, None, 1024, 1024, 0).unwrap(),
        )
        .unwrap()
    }

    fn grant(intent: &ProcessIntent) -> KernelDispatchGrant {
        let authority_epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            NonZeroU64::new(3).unwrap(),
        )
        .unwrap();
        let fence_nonce = "testd-fence-original".to_owned();
        let idempotency_key = "testd-lease-original".to_owned();
        let expires_at = 20_000;
        let mut material = format!(
            "{}|{}|7|{}|{}|{}",
            intent.effect_digest(),
            serde_json::to_string(&authority_epoch).unwrap(),
            fence_nonce,
            idempotency_key,
            expires_at
        );
        material.push_str("|testd-owner-store|C:\\data\\testd.db");
        KernelDispatchGrant {
            grant_digest: sha256_hex(material.as_bytes()),
            authority_epoch,
            fence_generation: 7,
            fence_nonce,
            idempotency_key,
            expires_at,
            testd_owner_store_path: Some("C:\\data\\testd.db".to_owned()),
        }
    }

    #[cfg(windows)]
    #[test]
    fn observed_image_accepts_canonical_path_prefix_and_refuses_replacement_path() {
        let observed = Path::new(&std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let admitted = std::fs::canonicalize(&observed).unwrap();
        let admitted = admitted.to_string_lossy().into_owned();

        assert!(observed_image_matches_admitted(
            &observed.to_string_lossy(),
            &admitted
        ));
        assert!(!observed_image_matches_admitted(
            &observed.to_string_lossy(),
            &format!("{admitted}.replacement")
        ));
    }

    #[test]
    fn original_grant_issues_a_bound_one_shot_request() {
        let intent = intent();
        let grant = grant(&intent);
        let authority = KernelChildDispatchAuthority::new().unwrap();

        let request = authority.issue(&intent, &grant, 10_000).unwrap();

        assert_eq!(request.intent(), &intent);
        assert!(!request.permit_digest().is_empty());
    }

    #[test]
    fn changed_original_grant_binding_is_refused() {
        let intent = intent();
        let mut grant = grant(&intent);
        grant.fence_nonce.push_str("-substituted");
        let authority = KernelChildDispatchAuthority::new().unwrap();

        assert!(matches!(
            authority.issue(&intent, &grant, 10_000),
            Err(ProcessExecutionError::Contract(
                ContractError::DigestMismatch { .. }
            ))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn lifecycle_discriminator_rejects_partial_testd_attempt_identity() {
        let generic = InstrumentDispatchLifecycle::Generic;
        assert_eq!(generic.attempt_identity(), (None, None));

        let testd = InstrumentDispatchLifecycle::Testd {
            job_id: "job-1".to_owned(),
            attempt_seq: 1,
        };
        assert_eq!(
            testd.attempt_identity(),
            (Some("job-1".to_owned()), Some(1))
        );
        assert_ne!(testd.attempt_identity(), (Some("job-1".to_owned()), None));
        assert_ne!(testd.attempt_identity(), (None, Some(1)));
        assert_ne!(testd.attempt_identity(), (None, None));
    }
}
