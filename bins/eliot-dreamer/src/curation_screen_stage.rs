//! Pre-model curation screen stage for admitted Dreamer jobs (issue #702, Slice 3).
//!
//! After dispatch admits a job class, the A-20 pre-model screen filters the
//! Curation target set through the #588 owner
//! ([`ScreenBinding::validate`](eliot_dreamer_contracts::ScreenBinding::validate))
//! exactly once, leaving only eligible targets. This module owns no screening
//! algorithm, performs no I/O, fetch, ranking, or model work, and invents no
//! state: the pure owner function decides, this composition only calls it once
//! and maps its typed refusal fail-closed.
//!
//! Stage order is dispatch, then the controller step, then the screen here,
//! then [`plan_admitted_bundle`](crate::bundle_stage::plan_admitted_bundle):
//! non-Curation classes pass through with zero screen work, a refused class
//! returns at dispatch with zero screen work, and a failed screen never
//! reaches the bundle stage.

use crate::controller::verify_admitted_binding;
use eliot_contracts::{ArtifactId, OperationId, RequestId, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::DreamJobAdmission;
use eliot_dreamer_contracts::{
    AdmittedCurationMaterial, ContractViolation, JobClass, ScreenBinding,
};
use eliot_dreamer_cycle::{
    CYCLE_SCHEMA_VERSION, CycleError, CyclePhase, CyclePlan, CyclePolicy, CycleSample,
    DreamerCycleState, ExpectedArtifact, PendingRequest, PhasePolicyRule, RequestKind,
    SampleLimits, plan_cycle, sample_cycle,
};
use eliot_memory_curation_contracts::{
    CurationScreenRequest, CurationScreenResult, SourceSnapshot,
};
use eliot_memory_curation_screen::{CurationScreenError, screen_memory_curation};
use eliot_receipts::{EffectClass, ProofCeiling, ReceiptKind};

use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// Minimal admitted screen inputs for one job.
///
/// Carries only the admitted job class. For Curation, the exact owner-issued
/// [`ScreenBinding`] arrives through the protected admitted material and is
/// validated once through [`screen_admitted_targets`]; this seam never derives
/// or defaults a binding from semantic handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenInputs {
    /// Admitted job class carried for dispatch context.
    pub job_class: JobClass,
}

/// Admitted screen outcome: pass-through for classes the screen does not
/// filter, or the owner-screened eligible target set for Curation.
#[allow(
    clippy::large_enum_variant,
    reason = "Screened must carry the validated owner binding alongside the eligible set; boxing would split the screened identity the downstream stages reuse verbatim"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenDecision {
    /// Non-Curation classes need no pre-model screen: zero screen work, and
    /// the bundle stage sees the admitted job unchanged.
    PassThrough(ScreenInputs),
    /// Curation targets that survived the owner screen, carried unmodified:
    /// no target is added, rewritten, or re-selected here. The validated
    /// binding is carried alongside so downstream stages (model, grounding)
    /// reuse the exact screened identity instead of rebuilding it.
    Screened {
        /// Inputs the eligible set was screened from.
        inputs: ScreenInputs,
        /// Validated owner binding the eligible set was screened under.
        binding: ScreenBinding,
        /// Eligible targets, exactly as the owner screen returned them.
        eligible_targets: Vec<String>,
    },
}

/// Resolves the owner-issued A-20 binding for one admitted job.
///
/// Curation never derives a binding from handles: the exact owner value must
/// arrive through the protected admission material. Non-Curation classes carry
/// no A-20 binding and therefore return `None` without screen work.
pub(crate) fn screen_binding_for(
    job: &DreamJobInput,
    owner_binding: Option<&ScreenBinding>,
) -> Result<Option<ScreenBinding>, DreamerError> {
    if job.job_class != JobClass::Curation {
        return Ok(None);
    }
    Ok(Some(owner_binding.cloned().ok_or(
        DreamerError::InvalidAdmission("admitted curation requires owner-resolved screen binding"),
    )?))
}

/// Resolves the A-20 screen decision for one admitted job.
///
/// Fails closed: any invalid/stale admission or identity mismatch refuses here
/// with zero owner-screen calls. Non-Curation classes pass through with no
/// screen work. Curation jobs require the exact owner binding carried by the
/// protected admitted material and run the real owner screen exactly once
/// through the production entry; no local binding is ever synthesized.
pub(crate) fn resolve_screen_inputs(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    owner_binding: Option<&ScreenBinding>,
) -> Result<ScreenDecision, DreamerError> {
    verify_admitted_binding(admission, job)?;
    let inputs = ScreenInputs {
        job_class: job.job_class,
    };
    let Some(binding) = screen_binding_for(job, owner_binding)? else {
        return Ok(ScreenDecision::PassThrough(inputs));
    };
    if binding.scope_id != admission.scope_id
        || !eliot_contracts::fences_match_exact(&binding.state_fence, &admission.state_fence)
    {
        return Err(DreamerError::InvalidAdmission(
            "owner screen binding scope or fence",
        ));
    }
    screen_admitted_targets(inputs, binding)
}

/// Screens the admitted Curation targets exactly once.
///
/// `screen_once` is `FnOnce`: the owner screen cannot run twice for one
/// admission through this seam. Production passes a closure over the real
/// [`ScreenBinding::validate`](eliot_dreamer_contracts::ScreenBinding::validate);
/// deterministic tests pass a counting wrapper around the real function to
/// prove the once-per-admission call shape. The surviving targets and the
/// validated binding are carried unmodified into
/// [`ScreenDecision::Screened`]: no target is dropped beyond what the owner
/// refused, thinned, or re-selected here.
pub(crate) fn screen_admitted_targets_with(
    inputs: ScreenInputs,
    binding: ScreenBinding,
    screen_once: impl FnOnce(ScreenBinding) -> Result<Vec<String>, ContractViolation>,
) -> Result<ScreenDecision, DreamerError> {
    let carried = binding.clone();
    screen_once(binding)
        .map(|eligible_targets| ScreenDecision::Screened {
            inputs,
            binding: carried,
            eligible_targets,
        })
        .map_err(|error| screen_denied(&error))
}

/// Production entry: the real A-20 owner screen, once per admission.
pub(crate) fn screen_admitted_targets(
    inputs: ScreenInputs,
    binding: ScreenBinding,
) -> Result<ScreenDecision, DreamerError> {
    screen_admitted_targets_with(inputs, binding, |candidate| {
        candidate.validate()?;
        Ok(candidate.screened_targets)
    })
}

/// Stable owner identity used by the native screen's inert cycle request.
const NATIVE_SCREEN_OWNER: &str = "eliot-memory-curation-screen";
/// Stable operation identity used by the native screen's inert cycle request.
const NATIVE_SCREEN_OPERATION: &str = "CURATION_SCREEN";

/// Owned native screen inputs and the explicit carrier omissions.
pub(crate) struct CurationSourceCarrier {
    pub(crate) admission: DreamJobAdmission,
    pub(crate) screen_binding: ScreenBinding,
    pub(crate) request: CurationScreenRequest,
    pub(crate) source: SourceSnapshot,
    pub(crate) evidence: Vec<eliot_memory_curation_contracts::ProtectionEvidence>,
    pub(crate) omissions: Vec<String>,
    pub(crate) source_manifest_digest: String,
}

impl CurationSourceCarrier {
    /// Clones the already owner-resolved source closure after revalidating its
    /// exact Kernel claim. The consumer creates no semantic class, source
    /// member, query, profile, evidence record, policy revision, or fence.
    pub(crate) fn from_admitted(
        material: &AdmittedCurationMaterial,
        claim: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Self, DreamerError> {
        material
            .validate_for_launch(
                &claim.job_id,
                &claim.attempt_id,
                &claim.request_id,
                &material.admission.operation_id,
                &claim.idempotency_key,
                &claim.scope_id,
                &claim.state_fence,
            )
            .map_err(|_| DreamerError::InvalidAdmission("owner-admitted Curation material"))?;
        if &material.job != job {
            return Err(DreamerError::InvalidAdmission(
                "semantic job differs from owner-admitted Curation material",
            ));
        }
        Ok(Self {
            admission: material.admission.clone(),
            screen_binding: material.screen_binding.clone(),
            request: material.request.clone(),
            source: material.source.clone(),
            evidence: material.protection_evidence.clone(),
            omissions: material.omissions.clone(),
            source_manifest_digest: material
                .source_manifest_digest()
                .map_err(|_| DreamerError::InvalidAdmission("Curation source manifest digest"))?,
        })
    }
}

/// Native screen result plus the frozen sample and one-cycle plan projections.
pub(crate) struct NativeCurationRoute {
    pub(crate) job_id: String,
    pub(crate) screen_binding: ScreenBinding,
    pub(crate) source_manifest_digest: String,
    pub(crate) screen: CurationScreenResult,
    pub(crate) sample: CycleSample,
    pub(crate) plan: CyclePlan,
    pub(crate) omissions: Vec<String>,
}

/// Runs the real native screen and the frozen cycle sample/plan projections.
pub(crate) fn run_native_screen_route(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    carrier: CurationSourceCarrier,
) -> Result<NativeCurationRoute, DreamerError> {
    carrier_screen_binding(&carrier, admission, job)?;
    let screen = screen_memory_curation(&carrier.request, &carrier.source, &carrier.evidence)
        .map_err(|error| native_screen_denied(&error))?;
    if screen.request != carrier.request || screen.source != carrier.source {
        return Err(DreamerError::InvalidAdmission(
            "native screen result owner binding",
        ));
    }
    let (sample, plan) = frozen_cycle_projection(admission, job, &screen, &carrier)?;
    let job_id = carrier.admission.canonical_id();
    Ok(NativeCurationRoute {
        job_id,
        screen_binding: carrier.screen_binding,
        source_manifest_digest: carrier.source_manifest_digest,
        screen,
        sample,
        plan,
        omissions: carrier.omissions,
    })
}

fn carrier_screen_binding(
    carrier: &CurationSourceCarrier,
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<(), DreamerError> {
    carrier
        .screen_binding
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("owner A-20 screen binding"))?;
    job.validate_against(&carrier.admission)
        .map_err(|_| DreamerError::InvalidAdmission("owner Curation job admission"))?;
    if carrier.request.binding.request_id.as_str() != admission.request_id
        || carrier.request.binding.operation_id.as_str() != carrier.admission.operation_id
        || carrier.admission.idempotency_key != admission.idempotency_key
        || carrier.admission.scope_id != admission.scope_id
        || carrier.screen_binding.request_id.as_str() != admission.request_id
        || carrier.screen_binding.scope_id != admission.scope_id
        || carrier.screen_binding.task_id != carrier.admission.task_id
        || !eliot_contracts::fences_match_exact(
            &carrier.admission.state_fence,
            &admission.state_fence,
        )
        || !eliot_contracts::fences_match_exact(
            &carrier.screen_binding.state_fence,
            &admission.state_fence,
        )
    {
        return Err(DreamerError::InvalidAdmission(
            "owner A-20 screen binding admission",
        ));
    }
    Ok(())
}

/// Builds one sealed, read-only cycle state over the admitted job and then
/// invokes the frozen `sample_cycle` and `plan_cycle` owners. No state is
/// persisted and no owner request is dispatched; the plan remains inert.
#[allow(
    clippy::too_many_lines,
    reason = "the frozen cycle state, policy, and digest bindings are kept in one auditable constructor"
)]
fn frozen_cycle_projection(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    screen: &CurationScreenResult,
    carrier: &CurationSourceCarrier,
) -> Result<(CycleSample, CyclePlan), DreamerError> {
    carrier_screen_binding(carrier, admission, job)?;
    let admitted = carrier.admission.clone();
    let bundle_digest = carrier.source_manifest_digest.clone();
    let budget_usage = crate::admitted_material::usage_of(&admitted.budget);
    let job_bytes = canonical_json_bytes(&admitted)
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle job digest"))?;
    let job_digest = sha256_hex(&job_bytes);
    let deadline_ms = admitted
        .deadline_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle deadline"))?;
    let policy_id = ArtifactId::new(admitted.policy_ref.clone())
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle policy id"))?;
    let cycle_id = ArtifactId::new(format!("dreamer-cycle:{}", admitted.canonical_id()))
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle id"))?;
    let request_id = RequestId::new(format!("{}:cycle-screen", admission.request_id))
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle request id"))?;
    let operation_id = OperationId::new(format!("{}:cycle-screen", admission.request_id))
        .map_err(|_| DreamerError::InvalidAdmission("frozen cycle operation id"))?;
    let payload_digest = screen.result_digest.as_str().to_owned();
    let source_product = screen.source.identity.product_id.clone();
    let source_id = screen.source.identity.source_id.clone();
    let task_id = admitted.task_id.clone();
    let scope_id = admitted.scope_id.clone();
    let state_fence = admitted.state_fence.clone();
    let policy_revision = state_fence
        .policy_revision
        .ok_or(DreamerError::InvalidAdmission(
            "frozen cycle policy revision",
        ))?;
    if policy_revision != screen.request.profile.policy_revision {
        return Err(DreamerError::InvalidAdmission(
            "frozen cycle policy revision",
        ));
    }
    let pending = PendingRequest {
        request_id: request_id.clone(),
        operation_id: operation_id.clone(),
        idempotency_key: admitted.idempotency_key.clone(),
        product_id: source_product.clone(),
        source_id: source_id.clone(),
        operation_kind: NATIVE_SCREEN_OPERATION.to_owned(),
        effect: EffectClass::Read,
        proof_ceiling: ProofCeiling::Observation,
        owner: NATIVE_SCREEN_OWNER.to_owned(),
        kind: RequestKind::CurationScreen,
        phase: CyclePhase::Screened,
        attempt_id: screen.request.binding.attempt_id.clone(),
        payload_digest: payload_digest.clone(),
        bundle_digest: bundle_digest.clone(),
        job_digest,
        task_id: task_id.clone(),
        scope_id: scope_id.clone(),
        state_fence: state_fence.clone(),
        predecessor_receipt_id: None,
        handler_request: None,
        expected_artifacts: vec![
            ExpectedArtifact {
                artifact_id: ArtifactId::new(format!("{}:screen-result", request_id.as_str()))
                    .map_err(|_| DreamerError::InvalidAdmission("screen result artifact"))?,
                sha256: payload_digest,
                role: ReceiptKind::Request,
                source_revision: Some(screen.source.identity.revision.to_string()),
            },
            ExpectedArtifact {
                artifact_id: ArtifactId::new(format!("{}:bundle", request_id.as_str()))
                    .map_err(|_| DreamerError::InvalidAdmission("bundle artifact"))?,
                sha256: bundle_digest.clone(),
                role: ReceiptKind::Artifact,
                source_revision: None,
            },
        ],
    };
    let mut policy = CyclePolicy {
        schema_version: CYCLE_SCHEMA_VERSION,
        policy_id: policy_id.clone(),
        policy_revision,
        state_fence: state_fence.clone(),
        max_pending: 1,
        max_outcomes: 1,
        max_requests: 1,
        max_transitions: 1,
        max_bytes: 1_048_576,
        deadline_ms,
        cancellation_requested: false,
        canonical_digest: String::new(),
        phase_rules: vec![PhasePolicyRule {
            phase: CyclePhase::Screened,
            owner: NATIVE_SCREEN_OWNER.to_owned(),
            product_id: source_product,
            source_id,
            operation_kind: NATIVE_SCREEN_OPERATION.to_owned(),
            effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        }],
    };
    policy.seal().map_err(|error| native_cycle_denied(&error))?;
    let mut state = DreamerCycleState {
        schema_version: CYCLE_SCHEMA_VERSION,
        cycle_id,
        job: admitted,
        bundle_digest,
        policy_id,
        policy_revision,
        policy_digest: policy.canonical_digest.clone(),
        phase: CyclePhase::BundleValidated,
        controller_revision: 0,
        predecessor_digest: None,
        pending: vec![pending],
        proposed_requests: Vec::new(),
        outcomes: Vec::new(),
        frontier: carrier.omissions.clone(),
        budget_usage,
        cancellation_requested: false,
        canonical_digest: String::new(),
    };
    state.seal().map_err(|error| native_cycle_denied(&error))?;
    state
        .validate()
        .map_err(|error| native_cycle_denied(&error))?;
    let sample = sample_cycle(&state, &policy, &SampleLimits { max_sampled: 1 })
        .map_err(|error| native_cycle_denied(&error))?;
    let plan = plan_cycle(&sample, &state, &policy, Some(0))
        .map_err(|error| native_cycle_denied(&error))?;
    Ok((sample, plan))
}

fn native_screen_denied(error: &CurationScreenError) -> DreamerError {
    match error {
        CurationScreenError::Cancelled => DreamerError::InvalidAdmission("native curation screen"),
        CurationScreenError::Contract(_) => {
            DreamerError::InvalidAdmission("native curation screen contract")
        }
    }
}

fn native_cycle_denied(error: &CycleError) -> DreamerError {
    match error {
        CycleError::BindingMismatch { field, .. } | CycleError::Bound { field, .. } => {
            DreamerError::InvalidAdmission(field)
        }
        CycleError::PhaseViolation(reason) | CycleError::IncompleteOutcome(reason) => {
            DreamerError::InvalidAdmission(reason)
        }
        CycleError::IdentityConflict { .. } => {
            DreamerError::InvalidAdmission("frozen cycle identity conflict")
        }
        CycleError::BudgetBlocked => DreamerError::InvalidAdmission("frozen cycle budget"),
        CycleError::Contract(_) | CycleError::Receipt(_) | CycleError::Encoding(_) => {
            DreamerError::InvalidAdmission("frozen cycle contract")
        }
    }
}

///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the screen
/// inputs were not. Dynamic payloads (handles, digests, reasons) are dropped
/// in favor of bounded static field names; nothing secret flows.
fn screen_denied(error: &ContractViolation) -> DreamerError {
    match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::CrossStage(field) => DreamerError::InvalidAdmission(field),
        ContractViolation::Budget { dimension, .. } => DreamerError::InvalidAdmission(dimension),
        ContractViolation::KindPayload(_) => {
            DreamerError::InvalidAdmission("kind/payload mismatch")
        }
        ContractViolation::Registry(_) => {
            DreamerError::InvalidAdmission("handler registry conflict")
        }
        ContractViolation::ScreenIneligible(_) => {
            DreamerError::InvalidAdmission("screen ineligible")
        }
        ContractViolation::Preservation(_) => {
            DreamerError::InvalidAdmission("preservation failure")
        }
        ContractViolation::ForbiddenCarry(_) => {
            DreamerError::InvalidAdmission("forbidden candidate carry")
        }
    }
}

#[cfg(test)]
mod slice_3_screen_tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_contracts::{
        EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, StateFence,
    };
    use eliot_dreamer_contracts::ScreenState;

    use crate::KERNEL_ADMISSION_REQUIRED;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage"),
            NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission_with_deadline(deadline_unix_ms: u64) -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-3".to_owned(),
            attempt_id: "attempt-slice-3".to_owned(),
            scope_id: "scope-slice-3".to_owned(),
            request_id: "request-slice-3".to_owned(),
            idempotency_key: "job-slice-3:attempt-slice-3".to_owned(),
            cancellation_id: "cancel-slice-3".to_owned(),
            deadline_unix_ms,
            state_fence: fence(),
        }
    }

    fn job_of_class(admission: &KernelJobAdmission, job_class: JobClass) -> DreamJobInput {
        DreamJobInput {
            job_id: admission.job_id.clone(),
            job_class,
            exact_question: "What does ELIOT know about this scope?".to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: admission.scope_id.clone(),
            task_id: None,
            state_fence: admission.state_fence.clone(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local_only".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".to_owned(),
            forbidden_effects: Vec::new(),
        }
    }

    fn job_with_handles(admission: &KernelJobAdmission, job_class: JobClass) -> DreamJobInput {
        let mut job = job_of_class(admission, job_class);
        job.evidence_handles = vec!["evidence-b".to_owned(), "evidence-a".to_owned()];
        job.memory_handles = vec!["evidence-a".to_owned(), "memory-a".to_owned()];
        job.architecture_handles = vec!["architecture-a".to_owned()];
        job
    }

    /// Stale Kernel input fails closed at resolution with zero screen calls:
    /// resolution precedes the screen, so there is no screen to count — the
    /// refusal itself is the proof, and it carries the request-rejected code,
    /// never the Kernel-admission code for a mere stale deadline.
    #[test]
    fn stale_admission_fails_closed_before_any_screen() {
        let admission = admission_with_deadline(1);
        let job = job_of_class(&admission, JobClass::Orientation);
        let refused = resolve_screen_inputs(&admission, &job, None);
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("Kernel deadline is stale"))
            ),
            "stale admission must fail closed, got {refused:?}"
        );
    }

    /// A caller-switched job identity fails closed at the binding check with
    /// the Kernel-admission code and zero screen calls.
    #[test]
    fn switched_job_identity_fails_closed_before_any_screen() {
        let admission = admission_with_deadline(u64::MAX);
        let mut job = job_of_class(&admission, JobClass::Orientation);
        job.job_id = "caller-switched-job".to_owned();
        let refused = resolve_screen_inputs(&admission, &job, None);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// Every non-Curation class passes through with zero screen work: the
    /// decision carries the admitted class unchanged and filters nothing.
    #[test]
    fn valid_non_curation_passes_through() {
        let admitted = [
            JobClass::Orientation,
            JobClass::Clarification,
            JobClass::ResearchSynthesis,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::Maintenance,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ];
        assert_eq!(admitted.len(), 8);
        let admission = admission_with_deadline(u64::MAX);
        for job_class in admitted {
            let job = job_of_class(&admission, job_class);
            let decision = resolve_screen_inputs(&admission, &job, None)
                .expect("non-Curation must pass through");
            assert_eq!(
                decision,
                ScreenDecision::PassThrough(ScreenInputs { job_class }),
                "class {job_class:?} must pass through unfiltered"
            );
        }
    }

    /// A Curation admission without the owner-issued A-20 binding refuses
    /// before any screen work. The consumer never derives a replacement from
    /// semantic handles or a local default.
    #[test]
    fn curation_without_owner_binding_refuses_before_screening() {
        let admission = admission_with_deadline(u64::MAX);
        let job = job_with_handles(&admission, JobClass::Curation);
        let refused = resolve_screen_inputs(&admission, &job, None);
        assert!(matches!(
            refused,
            Err(DreamerError::InvalidAdmission(
                "admitted curation requires owner-resolved screen binding"
            ))
        ));
    }

    /// Builds an owner screen binding whose result digest is corrupted. The
    /// shape is otherwise valid (eligible state, well-formed item digest,
    /// distinct identities), so the real owner validation must refuse it; the
    /// test proves it runs exactly once and the refusal maps fail-closed.
    fn digest_corrupted_binding() -> ScreenBinding {
        ScreenBinding {
            request_id: RequestId::new("req-slice-3").expect("request id"),
            receipt_id: ReceiptId::new("rcpt-slice-3").expect("receipt id"),
            screened_targets: vec!["target-slice-3".to_owned()],
            source_snapshot: "snapshot-slice-3".to_owned(),
            source_revision: "revision-slice-3".to_owned(),
            profile: "profile-slice-3".to_owned(),
            task_id: "task-slice-3".to_owned(),
            scope_id: "scope-slice-3".to_owned(),
            state_fence: fence(),
            state: ScreenState::Eligible,
            result_digest: "corrupted-digest".to_owned(),
            item_digest: "b".repeat(64),
        }
    }

    /// Builds a fully valid owner screen binding: eligible state, well-formed
    /// digests, and distinct request/receipt identities.
    fn valid_binding() -> ScreenBinding {
        ScreenBinding {
            result_digest: "a".repeat(64),
            ..digest_corrupted_binding()
        }
    }

    fn curation_inputs() -> ScreenInputs {
        ScreenInputs {
            job_class: JobClass::Curation,
        }
    }

    /// The real A-20 owner screen runs exactly once per admitted admission:
    /// one counting wrapper around the production validation over a
    /// digest-corrupted binding, one call, one typed fail-closed refusal with
    /// the request-rejected code.
    #[test]
    fn owner_screen_runs_exactly_once_per_admission() {
        let binding = digest_corrupted_binding();
        let calls = AtomicU64::new(0);
        let refused = screen_admitted_targets_with(curation_inputs(), binding, |candidate| {
            calls.fetch_add(1, Ordering::SeqCst);
            candidate.validate()?;
            Ok(candidate.screened_targets)
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner screen must run exactly once per admission"
        );
        let Err(error) = refused else {
            panic!("digest-corrupted screen inputs must refuse");
        };
        assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        assert!(
            !matches!(error, DreamerError::KernelAdmissionRequired(_)),
            "screen refusal must not borrow the Kernel-admission code"
        );
    }

    /// A valid owner screen carries its eligible set and its validated binding
    /// through unmodified: the production entry returns the screened targets
    /// exactly as validated, bound to the admitted inputs.
    #[test]
    fn valid_screen_preserves_eligible_targets() {
        let binding = valid_binding();
        let expected = binding.screened_targets.clone();
        assert!(
            !expected.is_empty(),
            "fixture must carry at least one eligible target"
        );
        let decision = screen_admitted_targets(curation_inputs(), binding.clone())
            .expect("valid screen must pass");
        assert_eq!(
            decision,
            ScreenDecision::Screened {
                inputs: curation_inputs(),
                binding,
                eligible_targets: expected,
            }
        );
    }

    /// Every owner screen refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("screened_targets"),
            ContractViolation::ImplicitDefault("screen_state"),
            ContractViolation::CrossStage("screened"),
            ContractViolation::UnknownVariant {
                field: "screen_state",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "screened_targets",
                min: 1,
                max: 1024,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "screened_targets",
                reason: "duplicate screened target".to_owned(),
            },
            ContractViolation::Malformed {
                field: "result_digest",
                reason: "expected 64 lowercase hex chars".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "screened_targets",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen binding is not eligible".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = screen_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "screen refusal {error:?} must not borrow the Kernel-admission code"
            );
        }
    }
}
