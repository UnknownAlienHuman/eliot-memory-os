use std::collections::BTreeMap;
use std::fmt;

use eliot_process::{CancellationStatus, ProcessLifecycle, ProcessRequest};
use eliot_runtime_contracts::{LeaseState, ModuleGenerationState};
use eliot_security_contracts::{
    EffectCeiling as SourceEffectCeiling, EpistemicUse, FreshnessStatus, InstructionTaint,
    IntegrityStatus, QuarantineState,
};

use crate::{
    AuthorityResolution, DerivedExecutionEvidence, EngineInvocation, EngineReport,
    EngineTermination, GovernorResolution, InvocationDisposition, InvocationRequest,
    InvocationResult, PortError, ProcessBinding, ProcessLaunchEnvelope, PromotionQuery,
    PromotionVerification, RuntimeError, RuntimePorts, Sha256Digest, SourceVerification,
    canonical_digest, validate_text,
};

const MAX_CACHED_INVOCATIONS: usize = 256;

#[derive(Clone)]
struct SealedAdmission {
    governor: GovernorResolution,
    authority: AuthorityResolution,
    source: SourceVerification,
    promotion: PromotionVerification,
}

#[derive(Clone)]
struct CachedInvocation {
    request: InvocationRequest,
    admission: Option<SealedAdmission>,
    launch_envelope: Option<ProcessLaunchEnvelope>,
    process_binding: Option<ProcessBinding>,
    engine_invocation: Option<EngineInvocation>,
    terminal_report: Option<EngineReport>,
    reconciliation_attempt: ReconciliationAttempt,
    result: InvocationResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconciliationAttempt {
    NotAttempted,
    Consumed,
}

/// Idempotent A-12 facade. It owns only its request/result replay cache.
pub struct WasmRuntime {
    ports: Option<RuntimePorts>,
    cache: BTreeMap<crate::InvocationId, CachedInvocation>,
}

impl fmt::Debug for WasmRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WasmRuntime")
            .field("ports_bound", &self.ports.is_some())
            .field("cached_invocations", &self.cache.len())
            .finish()
    }
}

impl WasmRuntime {
    /// Creates a facade. Missing ports preserve the exact typed `PLAN_GAP`.
    pub fn new(ports: Option<RuntimePorts>) -> Self {
        Self {
            ports,
            cache: BTreeMap::new(),
        }
    }

    /// Resolves external authority, starts through P-03, invokes, and caches.
    pub fn execute(&mut self, request: InvocationRequest) -> InvocationResult {
        if let Err(error) = request.validate() {
            return plain_result(&request, InvocationDisposition::Rejected, error);
        }
        if let Some(cached) = self.cache.get(&request.invocation_id) {
            if cached.request.request_digest() == request.request_digest() {
                return cached.result.clone();
            }
            return plain_result(
                &request,
                InvocationDisposition::Rejected,
                RuntimeError::ReplayConflict,
            );
        }
        if self.cache.len() >= MAX_CACHED_INVOCATIONS {
            return plain_result(
                &request,
                InvocationDisposition::Rejected,
                RuntimeError::ReplayCapacityExceeded,
            );
        }
        if request.cancellation_requested {
            return self.cache_plain(
                request,
                InvocationDisposition::Rejected,
                RuntimeError::Cancelled,
            );
        }
        let cached = execute_uncached(self.ports.as_mut(), request);
        let result = cached.result.clone();
        self.cache_insert(cached.request.invocation_id.clone(), cached);
        result
    }

    /// Cancels only an unknown in-flight result and preserves terminal replay.
    pub fn cancel(
        &mut self,
        invocation_id: &crate::InvocationId,
        request_digest: &Sha256Digest,
    ) -> Result<InvocationResult, RuntimeError> {
        let cached = self
            .cache
            .get(invocation_id)
            .cloned()
            .ok_or(RuntimeError::UnknownOutcome)?;
        if cached.request.request_digest() != request_digest {
            return Err(RuntimeError::ReplayConflict);
        }
        if !matches!(
            cached.result.receipt.disposition,
            InvocationDisposition::Unknown
        ) {
            return Err(RuntimeError::TerminalCancellationConflict);
        }
        let process_binding = cached
            .process_binding
            .as_ref()
            .ok_or(RuntimeError::UnknownOutcome)?;
        let envelope = cached
            .launch_envelope
            .as_ref()
            .ok_or(RuntimeError::UnknownOutcome)?;
        let Some(ports) = self.ports.as_mut() else {
            return Err(RuntimeError::PlanGap);
        };
        let Ok(receipt) = ports.process.cancel(process_binding) else {
            let result = plain_result(
                &cached.request,
                InvocationDisposition::Unknown,
                RuntimeError::UnknownOutcome,
            );
            return self.replace_cached_result(invocation_id, result);
        };
        let verified = ports
            .process_receipt_verifier
            .verify_cancellation(process_binding, &receipt, envelope)
            .is_ok();
        let descendants_complete = receipt
            .descendants()
            .is_some_and(|descendants| descendants.complete() && descendants.tree_terminated());
        let complete = verified
            && matches!(receipt.status(), CancellationStatus::Completed)
            && receipt.no_effect_proven()
            && descendants_complete;
        let result = if complete {
            plain_result(
                &cached.request,
                InvocationDisposition::Rejected,
                RuntimeError::Cancelled,
            )
        } else {
            plain_result(
                &cached.request,
                InvocationDisposition::Unknown,
                if verified {
                    RuntimeError::UnknownOutcome
                } else {
                    RuntimeError::InvalidProcessReceipt
                },
            )
        };
        self.replace_cached_result(invocation_id, result)
    }

    /// Requires independently verified P-03 evidence before engine reconciliation.
    pub fn reconcile(
        &mut self,
        invocation_id: &crate::InvocationId,
        request_digest: &Sha256Digest,
    ) -> Result<InvocationResult, RuntimeError> {
        let cached = self
            .cache
            .get(invocation_id)
            .cloned()
            .ok_or(RuntimeError::UnknownOutcome)?;
        if cached.request.request_digest() != request_digest {
            return Err(RuntimeError::ReplayConflict);
        }
        if !matches!(
            cached.result.receipt.disposition,
            InvocationDisposition::Unknown
        ) {
            return Ok(cached.result);
        }
        if matches!(
            cached.reconciliation_attempt,
            ReconciliationAttempt::Consumed
        ) {
            return Ok(cached.result);
        }
        let admission = cached.admission.as_ref().ok_or(RuntimeError::PlanGap)?;
        let envelope = cached
            .launch_envelope
            .as_ref()
            .ok_or(RuntimeError::PlanGap)?;
        let invocation = cached
            .engine_invocation
            .as_ref()
            .ok_or(RuntimeError::UnknownOutcome)?;
        let Some(ports) = self.ports.as_mut() else {
            return Err(RuntimeError::PlanGap);
        };
        let process_evidence = ports
            .process
            .reconcile(&invocation.process_binding)
            .map_err(|_| RuntimeError::UnknownOutcome)?;
        ports
            .process_receipt_verifier
            .verify_reconciliation(&invocation.process_binding, &process_evidence, envelope)
            .map_err(|_| RuntimeError::InvalidProcessReceipt)?;
        if !process_evidence.view().lifecycle().is_terminal() {
            return Ok(cached.result);
        }
        let Ok(report) = ports.engine.reconcile(invocation) else {
            let result = plain_result(
                &cached.request,
                InvocationDisposition::Unknown,
                RuntimeError::UnknownOutcome,
            );
            let Some(cached) = self.cache.get_mut(invocation_id) else {
                return Err(RuntimeError::UnknownOutcome);
            };
            cached.reconciliation_attempt = ReconciliationAttempt::Consumed;
            cached.result = result.clone();
            return Ok(result);
        };
        let result = classify_engine_report(
            ports,
            &cached.request,
            admission,
            invocation,
            report.clone(),
            true,
        );
        let Some(cached) = self.cache.get_mut(invocation_id) else {
            return Err(RuntimeError::UnknownOutcome);
        };
        cached.terminal_report = Some(report);
        cached.reconciliation_attempt = ReconciliationAttempt::Consumed;
        cached.result = result.clone();
        Ok(result)
    }

    fn replace_cached_result(
        &mut self,
        invocation_id: &crate::InvocationId,
        result: InvocationResult,
    ) -> Result<InvocationResult, RuntimeError> {
        let Some(cached) = self.cache.get_mut(invocation_id) else {
            return Err(RuntimeError::UnknownOutcome);
        };
        cached.result = result.clone();
        Ok(result)
    }

    fn cache_insert(&mut self, invocation_id: crate::InvocationId, cached: CachedInvocation) {
        if self.cache.len() >= MAX_CACHED_INVOCATIONS && !self.cache.contains_key(&invocation_id) {
            return;
        }
        self.cache.insert(invocation_id, cached);
    }

    fn cache_plain(
        &mut self,
        request: InvocationRequest,
        disposition: InvocationDisposition,
        error: RuntimeError,
    ) -> InvocationResult {
        let result = plain_result(&request, disposition, error);
        self.cache_insert(
            request.invocation_id.clone(),
            CachedInvocation {
                request,
                admission: None,
                launch_envelope: None,
                process_binding: None,
                engine_invocation: None,
                terminal_report: None,
                reconciliation_attempt: ReconciliationAttempt::NotAttempted,
                result: result.clone(),
            },
        );
        result
    }
}

#[allow(clippy::too_many_lines)]
fn execute_uncached(
    ports: Option<&mut RuntimePorts>,
    request: InvocationRequest,
) -> CachedInvocation {
    let Some(ports) = ports else {
        return cached_plain(
            request,
            InvocationDisposition::Unavailable,
            RuntimeError::PlanGap,
        );
    };
    let admission = match resolve_admission(ports, &request) {
        Ok(admission) => admission,
        Err((disposition, error)) => return cached_plain(request, disposition, error),
    };
    if ports.engine.binding() != &admission.governor.manifest.engine
        || ports.engine.binding().validate().is_err()
    {
        return cached_with_admission(
            request,
            admission,
            InvocationDisposition::Unavailable,
            RuntimeError::EngineBindingMismatch,
        );
    }
    let envelope = launch_envelope(&request, &admission);
    let process_request = match ports.process.prepare(&envelope) {
        Ok(process_request) => process_request,
        Err(error) => {
            let (disposition, runtime_error) = map_pre_effect_port_error(error);
            return cached_with_admission(request, admission, disposition, runtime_error);
        }
    };
    if validate_process_binding(&process_request, &envelope).is_err() {
        return cached_with_admission(
            request,
            admission,
            InvocationDisposition::Rejected,
            RuntimeError::InvalidProcessBinding,
        );
    }
    let process_binding = ProcessBinding::from_request(&process_request);
    let start_receipt = match ports.process.start(process_request) {
        Ok(receipt) => receipt,
        Err(PortError::Denied) => {
            return cached_with_admission(
                request,
                admission,
                InvocationDisposition::Rejected,
                RuntimeError::AuthorityDenied,
            );
        }
        Err(PortError::Unavailable | PortError::UnknownOutcome) => {
            return cached_with_process_unknown(
                request,
                admission,
                envelope,
                process_binding,
                RuntimeError::UnknownOutcome,
            );
        }
    };
    if !basic_start_receipt_matches(&process_binding, &start_receipt)
        || ports
            .process_receipt_verifier
            .verify_start(&process_binding, &start_receipt, &envelope)
            .is_err()
    {
        return cached_with_process_unknown(
            request,
            admission,
            envelope,
            process_binding,
            RuntimeError::InvalidProcessReceipt,
        );
    }
    let invocation = engine_invocation(&request, &admission, process_binding, start_receipt);
    let Ok(report) = ports.engine.invoke(&invocation) else {
        return cached_with_engine_unknown(
            request,
            admission,
            envelope,
            invocation,
            RuntimeError::UnknownOutcome,
        );
    };
    let terminal_report = Some(report.clone());
    let p03_verified = if matches!(report.termination, EngineTermination::Completed) {
        verify_p03_reap(ports, &invocation, &envelope)
    } else {
        false
    };
    let result = classify_engine_report(
        ports,
        &request,
        &admission,
        &invocation,
        report,
        p03_verified,
    );
    CachedInvocation {
        request,
        admission: Some(admission),
        launch_envelope: Some(envelope),
        process_binding: Some(invocation.process_binding.clone()),
        engine_invocation: Some(invocation),
        terminal_report,
        reconciliation_attempt: ReconciliationAttempt::NotAttempted,
        result,
    }
}

fn resolve_admission(
    ports: &mut RuntimePorts,
    request: &InvocationRequest,
) -> Result<SealedAdmission, (InvocationDisposition, RuntimeError)> {
    let governor = ports
        .governor
        .resolve(request)
        .map_err(map_resolution_port_error)?;
    let authority = ports
        .authority
        .resolve(request)
        .map_err(map_resolution_port_error)?;
    let source = ports
        .source_verifier
        .verify(request)
        .map_err(map_resolution_port_error)?;
    validate_resolutions(request, &governor, &authority, &source)
        .map_err(|error| (InvocationDisposition::Rejected, error))?;
    let query = PromotionQuery {
        request_digest: request.request_digest().clone(),
        component_id: request.component_id.clone(),
        generation: governor.generation.clone(),
        contour: request.requested_contour,
        artifact_digest: governor.manifest.artifact_digest.clone(),
        interface_digest: governor.manifest.interface_digest.clone(),
        state_contract_digest: governor.manifest.state_contract_digest.clone(),
    };
    let promotion = ports
        .promotion_verifier
        .verify(&query)
        .map_err(map_promotion_port_error)?;
    validate_promotion(request.requested_contour, &promotion)
        .map_err(|error| (InvocationDisposition::Rejected, error))?;
    Ok(SealedAdmission {
        governor,
        authority,
        source,
        promotion,
    })
}

fn validate_resolutions(
    request: &InvocationRequest,
    governor: &GovernorResolution,
    authority: &AuthorityResolution,
    source: &SourceVerification,
) -> Result<(), RuntimeError> {
    governor.manifest.validate()?;
    governor.generation.validate()?;
    governor.lease.validate()?;
    governor
        .limits
        .validate(&governor.manifest.artifact_digest)?;
    authority.work_scope.validate()?;
    source.assurance.validate()?;
    if request.input.len() as u64 > governor.limits.max_input_bytes {
        return Err(RuntimeError::InputLimitExceeded);
    }
    if request.component_id != governor.manifest.component_id
        || governor.generation.module_id.as_str() != request.component_id.as_str()
        || governor.generation.artifact_id.as_str() != governor.manifest.artifact_digest.as_str()
    {
        return Err(RuntimeError::GenerationBindingMismatch);
    }
    if !matches!(
        governor.generation.state,
        ModuleGenerationState::Ready | ModuleGenerationState::Active
    ) || (matches!(request.requested_contour, crate::ExecutionContour::Active)
        && !matches!(governor.generation.state, ModuleGenerationState::Active))
    {
        return Err(RuntimeError::GenerationNotReady);
    }
    let scope = authority.work_scope.work_scope.to_string();
    validate_text(&scope, "work_scope")?;
    if authority.work_unit != request.work_unit
        || scope != request.work_scope_ref.as_str()
        || authority.work_scope.attempt_ref.as_deref() != Some(request.work_unit.as_str())
        || authority.work_scope.module_or_route_ref.as_deref()
            != Some(request.component_id.as_str())
        || governor.lease.scope_ref != scope
    {
        return Err(RuntimeError::AuthorityBindingMismatch);
    }
    if !matches!(governor.lease.state, LeaseState::Active) {
        return Err(RuntimeError::LeaseNotActive);
    }
    if governor.lease.authority_epoch != governor.lease.state_fence.authority_epoch
        || governor.lease.state_fence != governor.generation.state_fence
        || source.assurance.state_fence != governor.generation.state_fence
    {
        return Err(RuntimeError::StaleFence);
    }
    if !matches!(source.assurance.integrity, IntegrityStatus::Verified)
        || !matches!(source.assurance.freshness, FreshnessStatus::Current)
        || !matches!(
            source.assurance.instruction_taint,
            InstructionTaint::Cleared | InstructionTaint::DataOnly
        )
        || !matches!(
            source.assurance.quarantine,
            QuarantineState::None | QuarantineState::Released
        )
        || !source
            .assurance
            .allowed_epistemic_use
            .contains(&EpistemicUse::VerificationInput)
        || !source
            .assurance
            .allowed_effects
            .contains(&SourceEffectCeiling::NoExternalEffect)
        || source.assurance.required_verifier.as_deref()
            != Some(governor.manifest.required_verifier.as_str())
        || !governor
            .manifest
            .admitted_privacy_classes
            .contains(&source.assurance.privacy_class)
    {
        return Err(RuntimeError::SourceNotAdmitted);
    }
    Ok(())
}

fn validate_promotion(
    contour: crate::ExecutionContour,
    promotion: &PromotionVerification,
) -> Result<(), RuntimeError> {
    let admitted = match contour {
        crate::ExecutionContour::Conformance => true,
        crate::ExecutionContour::Shadow => promotion.shadow.is_verified(),
        crate::ExecutionContour::Canary => {
            promotion.shadow.is_verified()
                && promotion.canary.is_verified()
                && promotion.rollback.is_verified()
        }
        crate::ExecutionContour::Active => {
            promotion.shadow.is_verified()
                && promotion.canary.is_verified()
                && promotion.rollback.is_verified()
                && promotion.cutover.is_verified()
        }
    };
    if admitted {
        Ok(())
    } else {
        Err(RuntimeError::PromotionDenied)
    }
}

fn launch_envelope(
    request: &InvocationRequest,
    admission: &SealedAdmission,
) -> ProcessLaunchEnvelope {
    ProcessLaunchEnvelope {
        invocation_id: request.invocation_id.clone(),
        request_digest: request.request_digest().clone(),
        owner: admission.authority.owner.clone(),
        work_unit: admission.authority.work_unit.clone(),
        work_scope: admission.authority.work_scope.clone(),
        manifest: admission.governor.manifest.clone(),
        generation: admission.governor.generation.clone(),
        lease: admission.governor.lease.clone(),
        authority_revision: admission.governor.authority_revision,
        lifecycle_revision: admission.governor.lifecycle_revision,
        limits: admission.governor.limits.clone(),
    }
}

fn validate_process_binding(
    process: &ProcessRequest,
    envelope: &ProcessLaunchEnvelope,
) -> Result<(), RuntimeError> {
    process.validate()?;
    validate_text(process.operation_id().as_str(), "process.operation_id")?;
    validate_text(
        process.process_tree_id().as_str(),
        "process.process_tree_id",
    )?;
    if process.operation_id().as_str() != envelope.invocation_id.as_str()
        || process.process_tree_id().as_str() != envelope.work_scope.work_scope.to_string()
        || process.generation().get() != envelope.generation.generation.value()
        || process.fence().authority_epoch() != envelope.lease.state_fence.authority_epoch.value()
        || process.fence().generation().get() != envelope.generation.generation.value()
    {
        return Err(RuntimeError::InvalidProcessBinding);
    }
    let limits = process.resource_limits();
    if limits.wall_timeout_ms() != envelope.limits.wall_deadline_ms
        || limits.memory_bytes() != Some(envelope.limits.max_memory_bytes)
        || limits.stdout_bytes() != envelope.limits.max_output_bytes
    {
        return Err(RuntimeError::InvalidProcessBinding);
    }
    Ok(())
}

fn basic_start_receipt_matches(
    process: &ProcessBinding,
    receipt: &eliot_process::ProcessStartReceipt,
) -> bool {
    receipt.operation_id() == process.operation_id()
        && receipt.request_digest() == process.request_digest()
        && receipt.accepted_generation() == process.generation()
        && receipt.binding().state_fence().matches(process.fence())
        && matches!(
            receipt.lifecycle(),
            ProcessLifecycle::Starting | ProcessLifecycle::Running
        )
}

fn engine_invocation(
    request: &InvocationRequest,
    admission: &SealedAdmission,
    process_binding: ProcessBinding,
    process_start_receipt: eliot_process::ProcessStartReceipt,
) -> EngineInvocation {
    EngineInvocation {
        invocation_id: request.invocation_id.clone(),
        request_digest: request.request_digest().clone(),
        component_id: request.component_id.clone(),
        contour: request.requested_contour,
        manifest: admission.governor.manifest.clone(),
        imports: admission.governor.manifest.imports.clone(),
        exports: admission.governor.manifest.exports.clone(),
        allowed_host_calls: admission.authority.allowed_host_calls.clone(),
        allowed_effect_proposals: admission.authority.allowed_effect_proposals.clone(),
        generation: admission.governor.generation.clone(),
        lease: admission.governor.lease.clone(),
        owner: admission.authority.owner.clone(),
        work_unit: admission.authority.work_unit.clone(),
        work_scope: admission.authority.work_scope.clone(),
        authority_revision: admission.governor.authority_revision,
        lifecycle_revision: admission.governor.lifecycle_revision,
        source_assurance: admission.source.assurance.clone(),
        source_verification_revision: admission.source.verification_revision,
        promotion_verification_revision: admission.promotion.verification_revision,
        conformance_corpus_digest: admission.promotion.corpus_digest.clone(),
        governor_resolution_receipt_digest: admission.governor.resolution_receipt_digest.clone(),
        authority_resolution_receipt_digest: admission.authority.resolution_receipt_digest.clone(),
        source_verification_receipt_digest: admission.source.verification_receipt_digest.clone(),
        promotion_verification_receipt_digest: admission
            .promotion
            .verification_receipt_digest
            .clone(),
        state_contract_digest: admission.governor.manifest.state_contract_digest.clone(),
        limits: admission.governor.limits.clone(),
        input: request.input.clone(),
        deterministic_seed: request.deterministic_seed,
        process_binding,
        process_start_receipt,
    }
}

fn classify_engine_report(
    ports: &mut RuntimePorts,
    request: &InvocationRequest,
    admission: &SealedAdmission,
    invocation: &EngineInvocation,
    report: EngineReport,
    p03_verified: bool,
) -> InvocationResult {
    if !report_contract_valid(invocation, &report) {
        return InvocationResult::classified(
            request,
            InvocationDisposition::Unknown,
            Some(RuntimeError::EngineContractViolation),
            None,
            Vec::new(),
            None,
            Some(admission.governor.manifest.engine.clone()),
            Some(report.usage),
        );
    }
    let derived = match derive_execution(&report) {
        Ok(derived) => derived,
        Err(error) => {
            return InvocationResult::classified(
                request,
                InvocationDisposition::Unknown,
                Some(error),
                None,
                Vec::new(),
                None,
                Some(admission.governor.manifest.engine.clone()),
                Some(report.usage),
            );
        }
    };
    if let Err(error) = ports
        .promotion_verifier
        .verify_execution(invocation, &report, &derived)
    {
        let (disposition, runtime_error) = match error {
            PortError::Denied => (
                InvocationDisposition::Rejected,
                RuntimeError::PromotionDenied,
            ),
            PortError::Unavailable => (InvocationDisposition::Unknown, RuntimeError::PlanGap),
            PortError::UnknownOutcome => {
                (InvocationDisposition::Unknown, RuntimeError::UnknownOutcome)
            }
        };
        return InvocationResult::classified(
            request,
            disposition,
            Some(runtime_error),
            None,
            Vec::new(),
            None,
            Some(admission.governor.manifest.engine.clone()),
            Some(report.usage),
        );
    }
    if matches!(report.termination, EngineTermination::Completed)
        && (derived.result_digest != admission.promotion.expected_result_digest
            || derived.effect_digest != admission.promotion.expected_effect_digest
            || derived.state_delta_digest != admission.promotion.expected_state_delta_digest)
    {
        return InvocationResult::classified(
            request,
            InvocationDisposition::Rejected,
            Some(RuntimeError::DifferentialMismatch),
            None,
            Vec::new(),
            None,
            Some(admission.governor.manifest.engine.clone()),
            Some(report.usage),
        );
    }
    let usage = report.usage.clone();
    let (disposition, error, output, effects, state_delta) =
        classify_termination(report, p03_verified);
    InvocationResult::classified(
        request,
        disposition,
        error,
        output,
        effects,
        state_delta,
        Some(admission.governor.manifest.engine.clone()),
        Some(usage),
    )
}

fn report_contract_valid(invocation: &EngineInvocation, report: &EngineReport) -> bool {
    let limits = &invocation.limits;
    report.request_digest == invocation.request_digest
        && report.usage.output_bytes == report.output.len() as u64
        && report.usage.attempted_output_bytes >= report.usage.output_bytes
        && (report.usage.attempted_output_bytes <= limits.max_output_bytes
            || matches!(report.termination, EngineTermination::OutputLimit))
        && report.usage.host_calls <= limits.max_host_calls
        && report.usage.fuel_consumed <= limits.max_fuel
        && report
            .usage
            .peak_memory_bytes
            .is_none_or(|value| value <= limits.max_memory_bytes)
        && report
            .usage
            .table_elements
            .is_none_or(|value| value <= limits.max_table_elements)
        && (report.usage.instances <= limits.max_instances
            || matches!(report.termination, EngineTermination::InstanceLimit))
        && report
            .usage
            .stack_bytes
            .is_none_or(|value| value <= limits.max_stack_bytes)
        && (report.usage.stack_bytes.is_some()
            || report.usage.enforced_stack_limit_bytes == Some(limits.max_stack_bytes))
        && (report.usage.elapsed_ms <= limits.wall_deadline_ms
            || matches!(
                report.termination,
                EngineTermination::Deadline | EngineTermination::EpochDeadline
            ))
        && report
            .usage
            .epoch_ticks
            .is_none_or(|value| value <= limits.epoch.deadline_ticks)
        && report.usage.artifact_reads <= limits.artifact_access.max_reads
        && report.usage.artifact_bytes <= limits.artifact_access.max_bytes
        && u32::try_from(report.host_calls.len()).ok() == Some(report.usage.host_calls)
        && u32::try_from(report.usage.accessed_artifact_digests.len()).ok()
            == Some(report.usage.artifact_reads)
        && report.host_calls.iter().all(|call| {
            invocation.imports.contains(call) && invocation.allowed_host_calls.contains(call)
        })
        && report.proposed_effects.iter().all(|effect| {
            invocation
                .allowed_effect_proposals
                .contains(&effect.effect_kind)
        })
        && report
            .usage
            .accessed_artifact_digests
            .iter()
            .all(|digest| limits.artifact_access.allowed_digests.contains(digest))
        && (!matches!(invocation.contour, crate::ExecutionContour::Shadow)
            || report.proposed_effects.is_empty())
        && (!matches!(report.termination, EngineTermination::Completed)
            || (report.usage.peak_memory_bytes.is_some()
                && report.usage.table_elements.is_some()
                && (report.usage.stack_bytes.is_some()
                    || report.usage.enforced_stack_limit_bytes == Some(limits.max_stack_bytes))
                && report.usage.epoch_ticks.is_some()))
}

fn derive_execution(report: &EngineReport) -> Result<DerivedExecutionEvidence, RuntimeError> {
    Ok(DerivedExecutionEvidence {
        result_digest: Sha256Digest::of_bytes(&report.output),
        effect_digest: canonical_digest(&report.proposed_effects)?,
        state_delta_digest: Sha256Digest::of_bytes(&report.observed_state_delta),
    })
}

type TerminationClassification = (
    InvocationDisposition,
    Option<RuntimeError>,
    Option<Vec<u8>>,
    Vec<crate::EffectProposal>,
    Option<Vec<u8>>,
);

fn classify_termination(report: EngineReport, p03_verified: bool) -> TerminationClassification {
    let unknown = || {
        (
            InvocationDisposition::Unknown,
            Some(RuntimeError::UnknownOutcome),
            None,
            Vec::new(),
            None,
        )
    };
    if (matches!(report.termination, EngineTermination::Completed) && !p03_verified)
        || !report.post_commit_known
    {
        return unknown();
    }
    match report.termination {
        EngineTermination::Completed => (
            InvocationDisposition::Succeeded,
            None,
            Some(report.output),
            report.proposed_effects,
            Some(report.observed_state_delta),
        ),
        EngineTermination::Trap(class) => rejected(RuntimeError::Trap(class)),
        EngineTermination::OutputLimit => rejected(RuntimeError::OutputLimit),
        EngineTermination::HostCallLimit => rejected(RuntimeError::HostCallLimit),
        EngineTermination::FuelExhausted => rejected(RuntimeError::FuelExhausted),
        EngineTermination::MemoryLimit => rejected(RuntimeError::MemoryLimit),
        EngineTermination::TableLimit => rejected(RuntimeError::TableLimit),
        EngineTermination::InstanceLimit => rejected(RuntimeError::InstanceLimit),
        EngineTermination::StackLimit => rejected(RuntimeError::StackLimit),
        EngineTermination::Deadline => rejected(RuntimeError::Deadline),
        EngineTermination::EpochDeadline => rejected(RuntimeError::EpochDeadline),
        EngineTermination::ArtifactAccessDenied => rejected(RuntimeError::ArtifactAccessDenied),
        EngineTermination::Cancelled => rejected(RuntimeError::Cancelled),
        EngineTermination::Partial | EngineTermination::PostCommitUnknown => unknown(),
    }
}

fn verify_p03_reap(
    ports: &mut RuntimePorts,
    invocation: &EngineInvocation,
    envelope: &ProcessLaunchEnvelope,
) -> bool {
    let Ok(evidence) = ports.process.reconcile(&invocation.process_binding) else {
        return false;
    };
    if ports
        .process_receipt_verifier
        .verify_reconciliation(&invocation.process_binding, &evidence, envelope)
        .is_err()
    {
        return false;
    }
    evidence.view().lifecycle().is_terminal()
}

fn rejected(error: RuntimeError) -> TerminationClassification {
    (
        InvocationDisposition::Rejected,
        Some(error),
        None,
        Vec::new(),
        None,
    )
}

fn plain_result(
    request: &InvocationRequest,
    disposition: InvocationDisposition,
    error: RuntimeError,
) -> InvocationResult {
    InvocationResult::classified(
        request,
        disposition,
        Some(error),
        None,
        Vec::new(),
        None,
        None,
        None,
    )
}

fn cached_plain(
    request: InvocationRequest,
    disposition: InvocationDisposition,
    error: RuntimeError,
) -> CachedInvocation {
    let result = plain_result(&request, disposition, error);
    CachedInvocation {
        request,
        admission: None,
        launch_envelope: None,
        process_binding: None,
        engine_invocation: None,
        terminal_report: None,
        reconciliation_attempt: ReconciliationAttempt::NotAttempted,
        result,
    }
}

fn cached_with_admission(
    request: InvocationRequest,
    admission: SealedAdmission,
    disposition: InvocationDisposition,
    error: RuntimeError,
) -> CachedInvocation {
    let result = plain_result(&request, disposition, error);
    CachedInvocation {
        request,
        admission: Some(admission),
        launch_envelope: None,
        process_binding: None,
        engine_invocation: None,
        terminal_report: None,
        reconciliation_attempt: ReconciliationAttempt::NotAttempted,
        result,
    }
}

fn cached_with_process_unknown(
    request: InvocationRequest,
    admission: SealedAdmission,
    launch_envelope: ProcessLaunchEnvelope,
    process_binding: ProcessBinding,
    error: RuntimeError,
) -> CachedInvocation {
    let result = plain_result(&request, InvocationDisposition::Unknown, error);
    CachedInvocation {
        request,
        admission: Some(admission),
        launch_envelope: Some(launch_envelope),
        process_binding: Some(process_binding),
        engine_invocation: None,
        terminal_report: None,
        reconciliation_attempt: ReconciliationAttempt::NotAttempted,
        result,
    }
}

fn cached_with_engine_unknown(
    request: InvocationRequest,
    admission: SealedAdmission,
    launch_envelope: ProcessLaunchEnvelope,
    engine_invocation: EngineInvocation,
    error: RuntimeError,
) -> CachedInvocation {
    let result = plain_result(&request, InvocationDisposition::Unknown, error);
    CachedInvocation {
        request,
        admission: Some(admission),
        launch_envelope: Some(launch_envelope),
        process_binding: Some(engine_invocation.process_binding.clone()),
        engine_invocation: Some(engine_invocation),
        terminal_report: None,
        reconciliation_attempt: ReconciliationAttempt::NotAttempted,
        result,
    }
}

fn map_resolution_port_error(error: PortError) -> (InvocationDisposition, RuntimeError) {
    match error {
        PortError::Denied => (
            InvocationDisposition::Rejected,
            RuntimeError::AuthorityDenied,
        ),
        PortError::Unavailable => (InvocationDisposition::Unavailable, RuntimeError::PlanGap),
        PortError::UnknownOutcome => (InvocationDisposition::Unknown, RuntimeError::UnknownOutcome),
    }
}

fn map_promotion_port_error(error: PortError) -> (InvocationDisposition, RuntimeError) {
    match error {
        PortError::Denied => (
            InvocationDisposition::Rejected,
            RuntimeError::PromotionDenied,
        ),
        PortError::Unavailable => (InvocationDisposition::Unavailable, RuntimeError::PlanGap),
        PortError::UnknownOutcome => (InvocationDisposition::Unknown, RuntimeError::UnknownOutcome),
    }
}

fn map_pre_effect_port_error(error: PortError) -> (InvocationDisposition, RuntimeError) {
    match error {
        PortError::Denied => (
            InvocationDisposition::Rejected,
            RuntimeError::AuthorityDenied,
        ),
        PortError::Unavailable => (InvocationDisposition::Unavailable, RuntimeError::PlanGap),
        PortError::UnknownOutcome => (InvocationDisposition::Unknown, RuntimeError::UnknownOutcome),
    }
}
