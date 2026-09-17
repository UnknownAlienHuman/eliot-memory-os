#![forbid(unsafe_code)]

#[cfg(test)]
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::StateFence;
use eliot_dreamer_contracts::ContractViolation;
use eliot_dreamer_contracts::ScreenBinding;
use eliot_dreamer_contracts::registry::{CurationHandlerRegistry, canonical_registry};
use eliot_protocol::dreamer_job::{DurableJobResponse, JobState as ProtocolJobState};
use serde::{Deserialize, Serialize};

use crate::dispatch_stage::CurationExecutionCarrier;
use crate::kernel_port::{ClaimTransport, KernelClaimTransport};

pub(crate) mod kernel_port;
mod admitted_material;
mod bundle_stage;
mod controller;
mod curation_screen_stage;
mod dispatch_stage;
mod error;
mod grounding_stage;
mod model_stage;
mod result_stage;
mod validation_stage;

#[cfg(test)]
mod pipeline_e2e;

pub use error::DreamerError;

pub const SERVICE_NAME: &str = "eliot-dreamer";
pub const PROTOCOL_VERSION: &str = "eliot.dreamer.v1";
pub const KERNEL_ADMISSION_REQUIRED: &str = "KERNEL_ADMISSION_REQUIRED";
const MAX_TEXT: usize = 16_384;
const MAX_ITEMS: usize = 256;

/// The canonical nine work classes of I9.3, owned by `eliot-dreamer-contracts`.
///
/// This crate previously declared its own copy whose `Architecture`,
/// `Orchestration` and `Configuration` variants were truncations of the
/// document's headings, and whose `rename_all` wire tokens therefore did not
/// match the taxonomy. The owner carries an explicit `#[serde(rename)]` per
/// variant, so the spelling is stated rather than derived.
pub use eliot_dreamer_contracts::JobClass;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamJobInput {
    pub job_id: String,
    pub job_class: JobClass,
    pub exact_question: String,
    pub requester: String,
    pub scope_id: String,
    pub task_id: Option<String>,
    pub state_fence: String,
    pub evidence_handles: Vec<String>,
    pub memory_handles: Vec<String>,
    pub architecture_handles: Vec<String>,
    pub implementation_handles: Vec<String>,
    pub conformance_handles: Vec<String>,
    pub conflicts_and_unknowns: Vec<String>,
    pub privacy_profile: String,
    pub allowed_tools: Vec<String>,
    pub allowed_model_routes: Vec<String>,
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub output_schema: String,
    pub forbidden_effects: Vec<String>,
}

/// Exact identity inherited from the Kernel for one Dreamer job attempt.
///
/// This is deliberately separate from [`DreamJobInput`]: semantic input is a
/// candidate bundle, while the Kernel owns the job/attempt idempotency and
/// fencing authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelJobAdmission {
    pub job_id: String,
    pub attempt_id: String,
    pub scope_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub cancellation_id: String,
    pub deadline_unix_ms: u64,
    pub state_fence: StateFence,
}

impl KernelJobAdmission {
    pub fn validate(&self) -> Result<(), DreamerError> {
        for (name, value) in [
            ("job_id", &self.job_id),
            ("attempt_id", &self.attempt_id),
            ("scope_id", &self.scope_id),
            ("request_id", &self.request_id),
            ("idempotency_key", &self.idempotency_key),
            ("cancellation_id", &self.cancellation_id),
        ] {
            validate_text(name, value)?;
        }
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DreamerError::InvalidAdmission("Kernel clock is unavailable"))?
            .as_millis();
        let now_unix_ms = u64::try_from(now_unix_ms)
            .map_err(|_| DreamerError::InvalidAdmission("Kernel clock exceeds wire range"))?;
        if self.deadline_unix_ms <= now_unix_ms {
            return Err(DreamerError::InvalidAdmission("Kernel deadline is stale"));
        }
        self.state_fence
            .validate()
            .map_err(|error| DreamerError::KernelAdmissionRequired(error.to_string()))
    }
}

/// The authenticated Kernel handshake snapshot bound to this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelHandshake {
    pub authority_epoch: u64,
    pub dreamer_claim_supported: bool,
}

/// Provider-neutral Kernel job contract used by the production composition.
/// Implementations own no semantic state; replay and terminal readback remain
/// Kernel-owned by idempotency key and exact job/attempt identity.
pub trait KernelJobPort {
    fn handshake(&mut self) -> Result<KernelHandshake, DreamerError>;
    fn submit(
        &mut self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<JobView, DreamerError>;
    fn cancel(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError>;
    fn status(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError>;
    fn reconcile(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError>;
}

/// Governor injection point for the Curation execution carrier.
///
/// Production carries no carrier: the ten live handler ports A-31 routes
/// through are Governor-injected and absent in-binary, so Curation refuses at
/// the carrier check without one. The Governor (or a test harness) supplies a
/// source via
/// [`AuthenticatedKernelJobPort::with_curation_source`], and `submit` resolves
/// the carrier from the A-20 screen binding before running the admitted
/// pipeline.
///
/// Object-safe by construction: no generic parameters and no lifetime on the
/// trait itself, so it is usable as `&dyn CurationCarrierSource`.
pub trait CurationCarrierSource {
    /// Resolves the execution carrier for one screened Curation admission.
    ///
    /// The returned carrier borrows the source (`'s`), so the caller must
    /// consume it before any `&mut` use of the port holding the source;
    /// `submit` complies by running the admitted pipeline to an owned
    /// [`DreamResult`] before observing the live view.
    fn resolve_carrier<'s>(
        &'s self,
        screen: &ScreenBinding,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<CurationExecutionCarrier<'s>, DreamerError>;
}

/// Authenticated production adapter over the installation-owned Kernel client.
///
/// The port owns the validated one-shot claim: connecting loads the
/// installation-owned client, probes the authenticated health handshake,
/// binds the live authority epoch it echoes, validates the staged dispatch
/// material presented next to this executable, derives the in-process
/// dispatch permit exactly once, and performs `LeaseExact` then `Start`
/// through the authenticated worker session. Any step failing closed refuses
/// with [`DreamerError::KernelAdmissionRequired`] without effect.
pub struct AuthenticatedKernelJobPort<'a> {
    material: kernel_port::ValidatedDreamerMaterial,
    admission: KernelJobAdmission,
    view: JobView,
    handshake: KernelHandshake,
    /// Boxed claim transport: the production [`KernelClaimTransport`] at
    /// `connect()`, an injected test double via `for_test`. Boxed behind the
    /// object-safe [`ClaimTransport`] seam so the generic `claim_once` /
    /// `status_once` call sites need no changes (the blanket `Box<T>` impl
    /// forwards).
    transport: Box<dyn ClaimTransport>,
    /// Optional Governor-injected Curation carrier source. `None` in
    /// production (live handler ports are absent in-binary, so Curation
    /// refuses at the carrier check); `Some` where the Governor wired one via
    /// [`AuthenticatedKernelJobPort::with_curation_source`].
    curation_source: Option<&'a dyn CurationCarrierSource>,
}

impl<'a> AuthenticatedKernelJobPort<'a> {
    pub fn connect() -> Result<Self, DreamerError> {
        let mut session = KernelClient::load().map_err(|error| kernel_admission_error(&error))?;
        let health = session
            .probe()
            .map_err(|error| kernel_admission_error(&error))?;
        if health.get("status").and_then(serde_json::Value::as_str) != Some("OPEN") {
            return Err(DreamerError::KernelAdmissionRequired(
                "Kernel health handshake was not OPEN and fenced".to_owned(),
            ));
        }
        let live_epoch = kernel_port::live_epoch_from_health(&health)
            .map_err(|error| port_denied(&error))?;
        let material = kernel_port::read_material(&live_epoch)
            .map_err(|error| port_denied(&error))?
            .ok_or_else(|| {
                DreamerError::KernelAdmissionRequired(
                    "no staged dreamer dispatch material was presented".to_owned(),
                )
            })?;
        let (executable, working_directory) = kernel_port::claim_executable_paths()
            .map_err(|error| port_denied(&error))?;
        // Derive-and-drop: the sealed request proves the grant binds through
        // the real contour constructors now. Dropping the ephemeral authority
        // admits no second issuance in this process; the staged file is
        // already consumed and claim authority stays Kernel-side.
        kernel_port::derive_permit(&material, &executable, &working_directory)
            .map_err(|error| port_denied(&error))?;
        let mut transport = KernelClaimTransport::new(session);
        let started =
            kernel_port::claim_once(&material, &mut transport).map_err(|error| port_denied(&error))?;
        let admission = claim_admission(&material);
        admission.validate()?;
        let handshake = KernelHandshake {
            authority_epoch: material.epoch.sequence.get(),
            dreamer_claim_supported: true,
        };
        let view = project_claimed_view(&started);
        Ok(Self {
            material,
            admission,
            view,
            handshake,
            transport: Box::new(transport),
            curation_source: None,
        })
    }

    /// Wires a Governor-injected Curation carrier source into the port.
    ///
    /// The Governor calls this after `connect()`; `submit` resolves the
    /// execution carrier from the A-20 screen binding through this source for
    /// Curation jobs only. Non-Curation jobs never consult it.
    #[must_use]
    pub fn with_curation_source(self, source: &'a dyn CurationCarrierSource) -> Self {
        Self {
            curation_source: Some(source),
            ..self
        }
    }

    /// Test-only constructor mirroring `connect()`'s tail with an injected
    /// transport and zero Kernel contact.
    ///
    /// Validates the presented admission, synthesizes the `Running` claimed
    /// view for its job identity, derives the claim admission from the
    /// material and validates it (proving the claim binding), and snapshots
    /// the handshake from the material epoch — performing no health probe, no
    /// permit derivation, and no `LeaseExact`/`Start` transact.
    #[cfg(test)]
    pub(crate) fn for_test(
        material: kernel_port::ValidatedDreamerMaterial,
        admission: KernelJobAdmission,
        transport: Box<dyn ClaimTransport>,
        curation_source: Option<&'a dyn CurationCarrierSource>,
    ) -> Result<Self, DreamerError> {
        admission.validate()?;
        let view = JobView {
            job_id: admission.job_id.clone(),
            state: JobState::Running,
            result: None,
        };
        let claimed = claim_admission(&material);
        claimed.validate()?;
        let handshake = KernelHandshake {
            authority_epoch: material.epoch.sequence.get(),
            dreamer_claim_supported: true,
        };
        Ok(Self {
            material,
            admission,
            view,
            handshake,
            transport,
            curation_source,
        })
    }

    /// Returns the Kernel-proved view of the claimed job.
    #[must_use]
    pub fn claimed_view(&self) -> &JobView {
        &self.view
    }

    /// Returns the Kernel-bound admission identity this claim proved.
    ///
    /// The caller drives the supervised loop through
    /// [`KernelSupervisedComposition`] with exactly this admission; any other
    /// identity refuses fail-closed at the port.
    #[must_use]
    pub fn claimed_admission(&self) -> &KernelJobAdmission {
        &self.admission
    }

    /// Refuses any admission that is not the claimed dreamer job.
    fn check_claimed(&self, admission: &KernelJobAdmission) -> Result<(), DreamerError> {
        admission.validate()?;
        if admission.job_id != self.material.job_id
            || admission.scope_id != self.material.scope_id
            || admission.state_fence != self.material.fence
            || admission.idempotency_key != self.admission.idempotency_key
        {
            return Err(DreamerError::KernelAdmissionRequired(
                "presented admission is not the claimed dreamer job".to_owned(),
            ));
        }
        Ok(())
    }

    /// Resolves the Governor-injected Curation execution carrier, if any.
    ///
    /// Copies the source reference out of `self` first (`Option<&dyn>` is
    /// `Copy`, ending the borrow), so the resolved carrier borrows the source
    /// rather than this port. `None` (production) flows to the carrier check
    /// inside the admitted pipeline, which refuses with the precise typed
    /// reason; `Some` delegates to the Governor source with the A-20 screen
    /// binding.
    ///
    /// The caller must consume the carrier before any `&mut` use of the port:
    /// `submit` runs the admitted pipeline to an owned [`DreamResult`] first
    /// and only then observes the live view.
    fn resolve_curation_carrier(
        &self,
        screen: &ScreenBinding,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<CurationExecutionCarrier<'_>>, DreamerError> {
        let source = self.curation_source;
        match source {
            None => Ok(None),
            Some(source) => source.resolve_carrier(screen, admission, job).map(Some),
        }
    }

    /// Observes the live Kernel-proved disposition of the claimed job.
    ///
    /// A refused or unbound reply fails closed; the port never serves a stale
    /// cached view as liveness.
    fn live_view(&mut self) -> Result<JobView, DreamerError> {
        let observed = kernel_port::status_once(&self.material, &mut self.transport)
            .map_err(|error| port_denied(&error))?;
        Ok(project_claimed_view(&observed))
    }

    /// Shared submit tail: observes the live Kernel-proved disposition, then
    /// attaches the computed result to it.
    ///
    /// The Kernel owns state authority, so the computed result attaches to the
    /// live view instead of inventing terminal state. The Slice-8 result stage
    /// projects the view and proves its JSONL encoding; the binary receipt
    /// edge (`main.rs`) emits the line on stdout.
    fn finish_with_result(&mut self, result: DreamResult) -> Result<JobView, DreamerError> {
        let view = self.live_view()?;
        let projected =
            result_stage::project_result_view(&view.job_id, view.state, Some(result));
        let line = result_stage::render_jsonl(&projected)?;
        debug_assert!(
            !line.is_empty(),
            "a decided view must render a non-empty receipt line"
        );
        Ok(projected)
    }
}

/// Binds the validated claim to the Kernel-owned admission identity.
///
/// The stable half reuses the Kernel-issued grant lineage (idempotency key
/// plus expiry as the freshness bound, so [`KernelJobAdmission::validate`]
/// re-proves liveness); the correlation half is derived from the grant
/// digest. Nothing is taken from argv, stdin, or environment.
fn claim_admission(material: &kernel_port::ValidatedDreamerMaterial) -> KernelJobAdmission {
    let short: String = material.grant.grant_digest.chars().take(16).collect();
    KernelJobAdmission {
        job_id: material.job_id.clone(),
        attempt_id: material.attempt_id.clone(),
        scope_id: material.scope_id.clone(),
        request_id: format!("dreamer-claim-{short}"),
        idempotency_key: material.grant.idempotency_key.clone(),
        cancellation_id: format!("dreamer-claim-{short}:cancel"),
        deadline_unix_ms: material.grant.expires_at,
        state_fence: material.fence.clone(),
    }
}

fn port_denied(error: &kernel_port::KernelPortError) -> DreamerError {
    DreamerError::KernelAdmissionRequired(error.to_string())
}

/// Slice-A fail-closed dispatcher over the closed [`JobClass`] taxonomy (I9.3).
///
/// Runs first in [`AuthenticatedKernelJobPort::submit`], before
/// `check_claimed`/`live_view`, so a class with no owning Slice-A handler is
/// refused with [`DreamerError::UnsupportedJobClass`] before any
/// Kernel-facing call. The gate takes only the semantic input and returns a
/// plain result: refusal performs zero transport and zero status calls by
/// construction (there is no port, transport, or admission channel to call).
///
/// Curation passes: its six handlers were admitted to the workspace (Wave S2,
/// #966) and A-31 is its sole fan-in, so the class flows to the screen and
/// dispatch stages instead of refusing here.
///
/// Exhaustive with no wildcard arm: extending the closed taxonomy breaks
/// compilation here until the new class is assigned an owning slice.
fn refuse_unsupported_job_class(job: &DreamJobInput) -> Result<(), DreamerError> {
    match job.job_class {
        JobClass::Clarification
        | JobClass::ArchitectureSelfQuery
        | JobClass::DevelopmentDiagnosis
        | JobClass::OrchestrationPlanning
        | JobClass::ConfigurationAssistance => {
            Err(DreamerError::UnsupportedJobClass(job.job_class))
        }
        JobClass::Orientation
        | JobClass::Curation
        | JobClass::ResearchSynthesis
        | JobClass::Maintenance => Ok(()),
    }
}

/// Slice-1 class dispatch outcome: exactly one arm per closed I9.3 class.
///
/// Arms are routing identities only, not a second refusal mapping: refusal
/// authority lives in [`refuse_unsupported_job_class`] plus the exhaustive
/// [`dispatch_class`] match. Exhaustive with no wildcard arm: extending the
/// closed taxonomy breaks compilation here and in
/// [`refuse_unsupported_job_class`] until the new class is assigned an
/// owning slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClassArm {
    OrientationAdmitted,
    CurationAdmitted,
    ClarificationRefused,
    ResearchSynthesisAdmitted,
    ArchitectureSelfQueryRefused,
    DevelopmentDiagnosisRefused,
    MaintenanceAdmitted,
    OrchestrationPlanningRefused,
    ConfigurationAssistanceRefused,
}

/// Routes one closed job class to its distinct Slice-1 arm (I9.3).
///
/// Pure: takes only the class and performs no leaf, transport, or
/// status work, so refused arms perform zero Kernel-facing calls by
/// construction. Nine distinct arms, exhaustive with no wildcard arm.
fn dispatch_class(class: JobClass) -> ClassArm {
    match class {
        JobClass::Orientation => ClassArm::OrientationAdmitted,
        JobClass::Curation => ClassArm::CurationAdmitted,
        JobClass::Clarification => ClassArm::ClarificationRefused,
        JobClass::ResearchSynthesis => ClassArm::ResearchSynthesisAdmitted,
        JobClass::ArchitectureSelfQuery => ClassArm::ArchitectureSelfQueryRefused,
        JobClass::DevelopmentDiagnosis => ClassArm::DevelopmentDiagnosisRefused,
        JobClass::Maintenance => ClassArm::MaintenanceAdmitted,
        JobClass::OrchestrationPlanning => ClassArm::OrchestrationPlanningRefused,
        JobClass::ConfigurationAssistance => ClassArm::ConfigurationAssistanceRefused,
    }
}

/// Slice-1 admission dispatch: Slice-A gate, then the distinct per-class arm,
/// then the owner-published canonical registry validation (Slice 1c, #702).
///
/// Runs first in [`AuthenticatedKernelJobPort::submit`], before
/// `check_claimed`/`live_view`, so refused classes fail closed with a typed
/// refusal before any leaf runs and before any Kernel-facing call. The
/// Slice-A gate is the sole refusal authority: refused classes return before
/// the arm is routed and before any registry work, so there is no second
/// refusal mapping to diverge and no registry cost on refusal.
///
/// Admitted classes validate the owner value only —
/// [`canonical_registry()`](canonical_registry) once, then its
/// [`validate_closure`](CurationHandlerRegistry::validate_closure), then its
/// [`digest`](CurationHandlerRegistry::digest) — with no local handler-ID
/// table, no separate kind-coverage pass, and no direct `handlers` iteration:
/// kind coverage is proved by the owner's closure check, not daemon-side.
/// Returns the routed arm with the stable registry digest; no handler is
/// invoked on any path.
fn dispatch_admission(job: &DreamJobInput) -> Result<(ClassArm, String), DreamerError> {
    dispatch_admission_with(job, canonical_registry)
}

/// Admission dispatch with an injectable canonical-registry provider.
///
/// Production passes
/// [`canonical_registry()`](canonical_registry); deterministic tests pass a
/// counting wrapper around it to prove the owner validation runs exactly once
/// per admitted admission and never on refusal.
fn dispatch_admission_with(
    job: &DreamJobInput,
    canonical: impl Fn() -> Result<CurationHandlerRegistry, ContractViolation>,
) -> Result<(ClassArm, String), DreamerError> {
    refuse_unsupported_job_class(job)?;
    let arm = dispatch_class(job.job_class);
    let not_closed =
        |violation: ContractViolation| DreamerError::RegistryNotClosed(violation.to_string());
    let registry = canonical().map_err(not_closed)?;
    registry.validate_closure().map_err(not_closed)?;
    let digest = registry.digest().map_err(not_closed)?;
    Ok((arm, digest))
}

/// Runs the admitted stage chain for one Kernel-bound job.
///
/// This is the exact chain [`AuthenticatedKernelJobPort::submit`] executes
/// past the bundle plan. Curation owns a separate pipeline: screen (A-20),
/// then the execution-carrier check, then A-31 — it never consumes the
/// generic grounded draft and never enters common A-05 validation (the A-05
/// owner itself directs Curation to its separate carrier). The carrier check
/// runs BEFORE any model/grounding work, so a Curation job with no
/// Governor-injected carrier refuses with the precise typed refusal instead
/// of burning generic stages only to fail at the port boundary. Every other
/// admitted class runs screen (pass-through), model, grounding, validation,
/// then native dispatch, each stage genuinely invoking its owner exactly
/// once; any refusal fails closed with zero further stage calls.
///
/// The carrier is `None` in production (live handler ports are
/// Governor-injected and absent in-binary); tests inject it to prove the
/// wired A-31 path. Extracted as a free function so the chain is
/// unit-provable without a live Kernel transport (`submit` adds only the
/// claim check before it and the live view after it).
fn run_admitted_pipeline(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    curation_carrier: Option<dispatch_stage::CurationExecutionCarrier<'_>>,
) -> Result<DreamResult, DreamerError> {
    let screen = curation_screen_stage::resolve_screen_inputs(admission, job)?;
    if job.job_class == JobClass::Curation {
        let binding = match screen {
            curation_screen_stage::ScreenDecision::Screened { binding, .. } => binding,
            curation_screen_stage::ScreenDecision::PassThrough(_) => {
                return Err(DreamerError::InvalidAdmission(
                    "admitted curation dispatch requires Governor-resolved screen binding",
                ));
            }
        };
        // Carrier check before any generic model/grounding work: without a
        // Governor-injected execution carrier there is nothing downstream to
        // run, so refuse here with the precise reason.
        let carrier = curation_carrier.ok_or(DreamerError::InvalidAdmission(
            dispatch_stage::CURATION_CARRIER_REFUSAL,
        ))?;
        return dispatch_stage::dispatch_curation(binding, carrier);
    }
    let model_inputs = model_stage::resolve_model_inputs(admission, job)?;
    let draft = model_stage::run_admitted_model(model_inputs)?;
    let grounding_request = grounding_stage::resolve_grounding_inputs(admission, job, draft)?;
    let grounded = grounding_stage::ground_admitted_draft(grounding_request)?;
    // Non-Curation classes pass the screen through with no binding to carry:
    // the resolve above already proved the pass-through.
    let screen_binding = None;
    let _validation = validation_stage::resolve_validation_inputs(admission, job)?;
    let validation_input =
        admitted_material::validation_input_for(admission, job, grounded, Some(0))?;
    let _validated = validation_stage::validate_admitted_draft(&validation_input)?;
    dispatch_stage::dispatch_admitted(admission, job, screen_binding, None, job.job_class)
}

impl KernelJobPort for AuthenticatedKernelJobPort<'_> {
    fn handshake(&mut self) -> Result<KernelHandshake, DreamerError> {
        Ok(self.handshake)
    }

    fn submit(
        &mut self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<JobView, DreamerError> {
        // Admitted pipeline in canonical order: Slice-A/1 dispatch runs
        // first, so refused classes fail closed before any Kernel-facing call.
        // Admitted jobs prove the Kernel-claimed binding next; that binding
        // holds for every class.
        //
        // Curation branches early, before the #806 controller step and the
        // A-04 bundle plan: Curation owns a separate carrier and never
        // consumes controller-cycle or bundle-plan outputs (fix3), so gating
        // it on Slice-2 Governor material would block it unconditionally. The
        // screen resolves first — proving screen-first ordering and supplying
        // the carrier-resolution input — then the Governor-injected carrier,
        // then the admitted stage chain (screen, carrier check, A-31), each
        // stage genuinely invoking its owner exactly once. Non-Curation jobs
        // keep controller, bundle plan, and the admitted stage chain
        // (model/grounding/validation/dispatch).
        //
        // Only then is the live Kernel-proved disposition observed via the
        // shared tail: the Kernel owns state authority, so the computed result
        // attaches to the live view instead of inventing terminal state. The
        // Slice-8 result stage projects the view and proves its JSONL
        // encoding; the binary receipt edge (`main.rs`) emits the line on
        // stdout.
        let (_arm, _digest) = dispatch_admission(job)?;
        self.check_claimed(admission)?;
        if job.job_class == JobClass::Curation {
            let screen = curation_screen_stage::resolve_screen_inputs(admission, job)?;
            let binding = match screen {
                curation_screen_stage::ScreenDecision::Screened { binding, .. } => binding,
                curation_screen_stage::ScreenDecision::PassThrough(_) => {
                    return Err(DreamerError::InvalidAdmission(
                        "admitted curation dispatch requires Governor-resolved screen binding",
                    ));
                }
            };
            let carrier = self.resolve_curation_carrier(&binding, admission, job)?;
            let result = run_admitted_pipeline(admission, job, carrier)?;
            return self.finish_with_result(result);
        }
        let (state, observed, policy, observation_time_ms) =
            controller::resolve_cycle_inputs(admission, job)?;
        let _step =
            controller::step_admitted_cycle(&state, &observed, &policy, observation_time_ms)?;
        let request = bundle_stage::resolve_bundle_request(admission, job)?;
        let _plan = bundle_stage::plan_admitted_bundle(request)?;
        let result = run_admitted_pipeline(admission, job, None)?;
        self.finish_with_result(result)
    }

    fn cancel(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        let _ = admission;
        Err(DreamerError::KernelAdmissionRequired(
            "worker role admits no cancel origination; cancellation is Kernel-owned and arrives as a proved disposition"
                .to_owned(),
        ))
    }

    fn status(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        self.check_claimed(admission)?;
        self.live_view()
    }

    fn reconcile(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        let _ = admission;
        Err(DreamerError::KernelAdmissionRequired(
            "mutation reconciliation originates Kernel-side; the claim port preserves the reconciling disposition via status"
                .to_owned(),
        ))
    }
}

fn kernel_admission_error(error: &KernelClientError) -> DreamerError {
    DreamerError::KernelAdmissionRequired(error.to_string())
}

impl DreamJobInput {
    pub fn validate(&self) -> Result<(), DreamerError> {
        for (name, value) in [
            ("job_id", &self.job_id),
            ("exact_question", &self.exact_question),
            ("requester", &self.requester),
            ("scope_id", &self.scope_id),
            ("state_fence", &self.state_fence),
            ("privacy_profile", &self.privacy_profile),
            ("output_schema", &self.output_schema),
        ] {
            validate_text(name, value)?;
        }
        for (name, values) in [
            ("evidence_handles", &self.evidence_handles),
            ("memory_handles", &self.memory_handles),
            ("architecture_handles", &self.architecture_handles),
            ("implementation_handles", &self.implementation_handles),
            ("conformance_handles", &self.conformance_handles),
            ("conflicts_and_unknowns", &self.conflicts_and_unknowns),
            ("allowed_tools", &self.allowed_tools),
            ("allowed_model_routes", &self.allowed_model_routes),
            ("forbidden_effects", &self.forbidden_effects),
        ] {
            if values.len() > MAX_ITEMS {
                return Err(DreamerError::LimitExceeded(name));
            }
            for value in values {
                validate_text(name, value)?;
            }
        }
        if self.budget_units == 0 || self.deadline_ms <= 0 {
            return Err(DreamerError::InvalidAdmission(
                "budget and deadline must be positive",
            ));
        }
        if self.allowed_model_routes.is_empty() {
            return Err(DreamerError::InvalidAdmission(
                "no model route was admitted",
            ));
        }
        Ok(())
    }
}

fn validate_text(name: &'static str, value: &str) -> Result<(), DreamerError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DreamerError::InvalidField(name));
    }
    if value.len() > MAX_TEXT {
        return Err(DreamerError::LimitExceeded(name));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Completed,
    Cancelled,
    Rejected,
    /// Terminal partial disposition proved by the Kernel ledger: exact, never
    /// promoted to success.
    Partial,
    /// Terminal failure disposition proved by the Kernel ledger: exact, never
    /// rendered as absence.
    Failed,
    /// Reconciling disposition: the Kernel reported `UnknownOutcome`. The
    /// outcome is unresolved and must never render as success or absence.
    Reconciling,
}

/// Projects one Kernel-proved claim-port observation onto the local lifecycle.
///
/// Total over the closed protocol lifecycle: in-progress states project to
/// the matching local progress state, every terminal state keeps its exact
/// identity, and `UnknownOutcome` projects to [`JobState::Reconciling`].
pub(crate) fn project_claimed_state(observed: ProtocolJobState) -> JobState {
    match observed {
        ProtocolJobState::NotStarted | ProtocolJobState::Queued => JobState::Queued,
        ProtocolJobState::Leased
        | ProtocolJobState::Running
        | ProtocolJobState::Checkpointed
        | ProtocolJobState::Verifying => JobState::Running,
        ProtocolJobState::Completed => JobState::Completed,
        ProtocolJobState::Partial => JobState::Partial,
        ProtocolJobState::Failed => JobState::Failed,
        ProtocolJobState::Cancelled => JobState::Cancelled,
        ProtocolJobState::UnknownOutcome => JobState::Reconciling,
    }
}

/// Projects the Kernel-proved disposition of one claim-port observation.
///
/// The view carries no candidate payload: candidate artifacts arrive through
/// the model channel, and the claim port never invents one. A `None` result
/// is honest absence of a proved payload, not a success claim.
pub(crate) fn project_claimed_view(observed: &DurableJobResponse) -> JobView {
    JobView {
        job_id: observed.job_id.as_str().to_owned(),
        state: project_claimed_state(observed.state),
        result: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamPacket {
    pub packet_id: String,
    pub job_id: String,
    pub question: String,
    pub scope_id: String,
    pub state_fence: String,
    pub source_coverage: SourceCoverage,
    pub synthesized_interpretations: Vec<Interpretation>,
    pub rival_models_and_dissent: Vec<String>,
    pub unknowns_and_gaps: Vec<String>,
    pub recommended_probes_or_next_actions: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceCoverage {
    pub evidence: Vec<String>,
    pub memory: Vec<String>,
    pub architecture: Vec<String>,
    pub implementation: Vec<String>,
    pub conformance: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Interpretation {
    pub statement: String,
    pub support_handles: Vec<String>,
    pub epistemic_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CurationCandidate {
    pub candidate_id: String,
    pub kind: String,
    pub source_handles: Vec<String>,
    pub proposed_transformation: String,
    pub uncertainty: String,
    pub rollback: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "DreamResult is a public serialized protocol surface; boxing would change its wire/API shape"
)]
pub enum DreamResult {
    Packet(DreamPacket),
    Curation {
        job_id: String,
        candidates: Vec<CurationCandidate>,
        provenance: Vec<String>,
    },
    Clarification {
        job_id: String,
        question: String,
        why_it_matters: String,
        safe_fallback: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JobView {
    pub job_id: String,
    pub state: JobState,
    pub result: Option<DreamResult>,
}

// `DreamerError` is singly owned by `error.rs` and re-exported above; the
// public path `eliot_dreamer::DreamerError` is unchanged.

/// Production Dreamer composition. It has no local job map: all admission,
/// cancellation, replay and terminal readback are delegated to Kernel.
pub struct KernelSupervisedComposition<P> {
    port: P,
    handshake: KernelHandshake,
}

impl<P: KernelJobPort> KernelSupervisedComposition<P> {
    pub fn connect(mut port: P) -> Result<Self, DreamerError> {
        let handshake = port.handshake()?;
        if handshake.authority_epoch == 0 {
            return Err(DreamerError::KernelAdmissionRequired(
                "Kernel handshake omitted the authority epoch".to_owned(),
            ));
        }
        if !handshake.dreamer_claim_supported {
            return Err(DreamerError::KernelAdmissionRequired(
                "Kernel health is OPEN but Dreamer job claim is unavailable".to_owned(),
            ));
        }
        Ok(Self { port, handshake })
    }

    pub fn submit(
        &mut self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<JobView, DreamerError> {
        job.validate()?;
        self.validate_fence(admission)?;
        if admission.job_id != job.job_id || admission.scope_id != job.scope_id {
            return Err(DreamerError::KernelAdmissionRequired(
                "job/attempt identity does not match the admitted semantic input".to_owned(),
            ));
        }
        self.port.submit(admission, job)
    }

    pub fn cancel(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        self.validate_fence(admission)?;
        self.port.cancel(admission)
    }

    pub fn status(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        self.validate_fence(admission)?;
        self.port.status(admission)
    }

    pub fn reconcile(&mut self, admission: &KernelJobAdmission) -> Result<JobView, DreamerError> {
        self.validate_fence(admission)?;
        self.port.reconcile(admission)
    }

    fn validate_fence(&self, admission: &KernelJobAdmission) -> Result<(), DreamerError> {
        admission.validate()?;
        if admission.state_fence.authority_epoch.sequence.get() != self.handshake.authority_epoch {
            return Err(DreamerError::KernelAdmissionRequired(
                "job state fence does not match the authenticated Kernel epoch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
struct StoredJob {
    input: DreamJobInput,
    state: JobState,
    result: Option<DreamResult>,
}

/// Composition root for the demand-start Dreamer process. It has no database,
/// provider credentials, process-launch capability, or canonical write path.
#[cfg(test)]
pub struct DreamerComposition {
    jobs: BTreeMap<String, StoredJob>,
    max_jobs: usize,
}

#[cfg(test)]
impl Default for DreamerComposition {
    fn default() -> Self {
        Self::new(128)
    }
}

#[cfg(test)]
impl DreamerComposition {
    #[must_use]
    pub fn new(max_jobs: usize) -> Self {
        Self {
            jobs: BTreeMap::new(),
            max_jobs: max_jobs.max(1),
        }
    }

    pub fn submit(&mut self, input: DreamJobInput) -> Result<JobView, DreamerError> {
        input.validate()?;
        if self.jobs.contains_key(&input.job_id) {
            return Err(DreamerError::DuplicateJob(input.job_id));
        }
        if self.jobs.len() >= self.max_jobs {
            return Err(DreamerError::InvalidAdmission(
                "bounded job capacity reached",
            ));
        }
        let job_id = input.job_id.clone();
        let mut job = StoredJob {
            input,
            state: JobState::Running,
            result: None,
        };
        let result = build_result(&job.input);
        job.result = Some(result);
        job.state = JobState::Completed;
        let view = view(&job_id, &job);
        self.jobs.insert(job_id, job);
        Ok(view)
    }

    pub fn cancel(&mut self, job_id: &str) -> Result<JobView, DreamerError> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| DreamerError::UnknownJob(job_id.into()))?;
        if matches!(
            job.state,
            JobState::Completed | JobState::Cancelled | JobState::Rejected
        ) {
            return Err(DreamerError::NotCancellable(job_id.into()));
        }
        job.state = JobState::Cancelled;
        job.result = None;
        Ok(view(job_id, job))
    }

    pub fn status(&self, job_id: &str) -> Result<JobView, DreamerError> {
        let job = self
            .jobs
            .get(job_id)
            .ok_or_else(|| DreamerError::UnknownJob(job_id.into()))?;
        Ok(view(job_id, job))
    }
}

#[cfg(test)]
fn view(job_id: &str, job: &StoredJob) -> JobView {
    JobView {
        job_id: job_id.into(),
        state: job.state,
        result: job.result.clone(),
    }
}

#[cfg(test)]
fn build_result(input: &DreamJobInput) -> DreamResult {
    if input.job_class == JobClass::Clarification {
        return DreamResult::Clarification {
            job_id: input.job_id.clone(),
            question: format!("Clarify the observation, scope, and outcome relevant to: {}", input.exact_question),
            why_it_matters: "A bounded interpretation cannot distinguish fact from interpretation without that distinction.".into(),
            safe_fallback: "Preserve the source as unresolved and return no canonical transformation.".into(),
        };
    }
    if input.job_class == JobClass::Curation {
        let handles = all_handles(input);
        return DreamResult::Curation {
            job_id: input.job_id.clone(),
            candidates: handles.iter().enumerate().map(|(index, handle)| CurationCandidate {
                candidate_id: format!("{}-candidate-{}", input.job_id, index + 1),
                kind: "review_required".into(),
                source_handles: vec![handle.clone()],
                proposed_transformation: "Inspect provenance and propose a reversible derived projection; do not alter the source.".into(),
                uncertainty: "No semantic promotion is possible from a handle-only bounded bundle.".into(),
                rollback: "Discard the candidate and reopen the source handle.".into(),
            }).collect(),
            provenance: handles,
        };
    }
    let handles = all_handles(input);
    let unknowns = if input.conflicts_and_unknowns.is_empty() {
        vec!["No explicit conflict set was supplied; absence is not evidence of resolution.".into()]
    } else {
        input.conflicts_and_unknowns.clone()
    };
    DreamResult::Packet(DreamPacket {
        packet_id: format!("{}-packet", input.job_id),
        job_id: input.job_id.clone(),
        question: input.exact_question.clone(),
        scope_id: input.scope_id.clone(),
        state_fence: input.state_fence.clone(),
        source_coverage: SourceCoverage { evidence: input.evidence_handles.clone(), memory: input.memory_handles.clone(), architecture: input.architecture_handles.clone(), implementation: input.implementation_handles.clone(), conformance: input.conformance_handles.clone() },
        synthesized_interpretations: vec![Interpretation { statement: "The supplied bounded references are available for governed interpretation; no fact was promoted by this service.".into(), support_handles: handles.clone(), epistemic_status: "candidate_only".into() }],
        rival_models_and_dissent: vec!["The bundle may omit relevant sources or contain correlated evidence; inspect independent references before acting.".into()],
        unknowns_and_gaps: unknowns,
        recommended_probes_or_next_actions: vec!["Ask the owning Governor or Human to admit the next reversible probe.".into()],
        invalidation_conditions: vec!["State-fence change, source revocation, or evidence disproving the candidate interpretation.".into()],
        provenance: handles,
    })
}

#[cfg(test)]
fn all_handles(input: &DreamJobInput) -> Vec<String> {
    input
        .evidence_handles
        .iter()
        .chain(&input.memory_handles)
        .chain(&input.architecture_handles)
        .chain(&input.implementation_handles)
        .chain(&input.conformance_handles)
        .cloned()
        .collect()
}

#[cfg(test)]
mod taxonomy_tests {
    use super::*;

    /// The nine classes this binary admits are the nine section headings of
    /// I9.3, in the owner's stated wire spelling. Before this crate took
    /// `JobClass` from `eliot-dreamer-contracts` it declared its own copy in
    /// which three of these tokens were truncated, so a job admitted here
    /// would not have matched the same class at the boundary.
    #[test]
    fn admitted_classes_are_the_canonical_nine_wire_tokens() {
        let taxonomy = [
            (JobClass::Orientation, "orientation"),
            (JobClass::Curation, "curation"),
            (JobClass::Clarification, "clarification"),
            (JobClass::ResearchSynthesis, "research_synthesis"),
            (JobClass::ArchitectureSelfQuery, "architecture_self_query"),
            (JobClass::DevelopmentDiagnosis, "development_diagnosis"),
            (JobClass::Maintenance, "maintenance"),
            (JobClass::OrchestrationPlanning, "orchestration_planning"),
            (JobClass::ConfigurationAssistance, "configuration_assistance"),
        ];
        for (class, token) in taxonomy {
            let encoded = serde_json::to_string(&class).expect("a closed class encodes");
            assert_eq!(encoded, format!("\"{token}\""), "wire token for {class:?}");
        }
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    /// The claim-port projection is total and exact: every closed protocol
    /// lifecycle state maps to its local identity, terminal states keep
    /// their exact disposition, and `UnknownOutcome` never renders as
    /// success or absence.
    #[test]
    fn protocol_state_projection_is_total_and_exact() {
        for (observed, expected) in [
            (ProtocolJobState::NotStarted, JobState::Queued),
            (ProtocolJobState::Queued, JobState::Queued),
            (ProtocolJobState::Leased, JobState::Running),
            (ProtocolJobState::Running, JobState::Running),
            (ProtocolJobState::Checkpointed, JobState::Running),
            (ProtocolJobState::Verifying, JobState::Running),
            (ProtocolJobState::Completed, JobState::Completed),
            (ProtocolJobState::Partial, JobState::Partial),
            (ProtocolJobState::Failed, JobState::Failed),
            (ProtocolJobState::Cancelled, JobState::Cancelled),
            (ProtocolJobState::UnknownOutcome, JobState::Reconciling),
        ] {
            assert_eq!(project_claimed_state(observed), expected);
        }
    }
}

#[cfg(test)]
mod slice_a_dispatch_tests {
    use super::*;

    /// Builds a well-formed semantic input for one class. The Slice-A gate
    /// reads only `job_class`, so validity of the remaining fields keeps the
    /// proof focused on dispatch rather than input validation.
    fn job_of_class(class: JobClass) -> DreamJobInput {
        DreamJobInput {
            job_id: "job-slice-a".into(),
            job_class: class,
            exact_question: "What does ELIOT know about this scope?".into(),
            requester: "test-harness".into(),
            scope_id: "scope-slice-a".into(),
            task_id: None,
            state_fence: "fence-slice-a".into(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local_only".into(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".into()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".into(),
            forbidden_effects: Vec::new(),
        }
    }

    /// Proves refusal for one class with the exact variant and payload.
    ///
    /// No-transport/no-status proof is structural: the gate under test takes
    /// only `&DreamJobInput` and returns a plain result, so there is no port,
    /// transport, or admission channel it could call; `submit` invokes it
    /// before `check_claimed`/`live_view`, which are the only Kernel-facing
    /// calls on that path.
    fn assert_refused(class: JobClass) {
        let job = job_of_class(class);
        let refused = refuse_unsupported_job_class(&job);
        assert!(
            matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
            "class {class:?} must refuse with UnsupportedJobClass({class:?})"
        );
    }

    #[test]
    fn clarification_refuses_without_kernel_contact() {
        assert_refused(JobClass::Clarification);
    }

    #[test]
    fn architecture_self_query_refuses_without_kernel_contact() {
        assert_refused(JobClass::ArchitectureSelfQuery);
    }

    #[test]
    fn development_diagnosis_refuses_without_kernel_contact() {
        assert_refused(JobClass::DevelopmentDiagnosis);
    }

    #[test]
    fn orchestration_planning_refuses_without_kernel_contact() {
        assert_refused(JobClass::OrchestrationPlanning);
    }

    #[test]
    fn configuration_assistance_refuses_without_kernel_contact() {
        assert_refused(JobClass::ConfigurationAssistance);
    }

    /// The four Slice-A admitted classes fall through to the existing path:
    /// the gate returns `Ok`, preserving the `check_claimed`/`live_view`
    /// behavior (including its `None`-result projection) unchanged. Curation
    /// passes since Wave S2 (#966): A-31 is its sole fan-in.
    #[test]
    fn admitted_classes_pass_the_slice_a_gate() {
        for class in [
            JobClass::Orientation,
            JobClass::Curation,
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
        ] {
            let job = job_of_class(class);
            assert!(
                refuse_unsupported_job_class(&job).is_ok(),
                "class {class:?} must pass the Slice-A gate"
            );
        }
    }

    /// The new variant renders its payload and maps to the request-rejected
    /// code, never to the Kernel-admission code.
    #[test]
    fn unsupported_variant_display_and_code_hold() {
        for class in [
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let error = DreamerError::UnsupportedJobClass(class);
            assert_eq!(
                format!("{error}"),
                format!("unsupported Dreamer job class: {class:?}")
            );
            assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
        }
    }
}

#[cfg(test)]
mod slice_1_dispatch_tests {
    use super::*;
    use eliot_dreamer_contracts::{
        BoundCurationCall, ContractViolation, NativeCurationHandler, ProducedCurationContent,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Builds a well-formed semantic input for one class. The Slice-1
    /// dispatch reads only `job_class`, so validity of the remaining fields
    /// keeps each proof focused on routing rather than input validation.
    fn job_of_class(class: JobClass) -> DreamJobInput {
        DreamJobInput {
            job_id: "job-slice-1".into(),
            job_class: class,
            exact_question: "What does ELIOT know about this scope?".into(),
            requester: "test-harness".into(),
            scope_id: "scope-slice-1".into(),
            task_id: None,
            state_fence: "fence-slice-1".into(),
            evidence_handles: Vec::new(),
            memory_handles: Vec::new(),
            architecture_handles: Vec::new(),
            implementation_handles: Vec::new(),
            conformance_handles: Vec::new(),
            conflicts_and_unknowns: Vec::new(),
            privacy_profile: "local_only".into(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".into()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".into(),
            forbidden_effects: Vec::new(),
        }
    }

    /// All nine closed classes route to distinct arms. No wildcard arm
    /// exists, so a tenth class would break compilation instead of
    /// misrouting. Admitted/refused partition is proved by
    /// `dispatch_admission` outcomes below, not by a second boolean mapping:
    /// the Slice-A gate plus this exhaustive match are the sole refusal
    /// authority.
    #[test]
    fn all_nine_classes_route_to_distinct_arms() {
        let routed = [
            (JobClass::Orientation, ClassArm::OrientationAdmitted),
            (JobClass::Curation, ClassArm::CurationAdmitted),
            (JobClass::Clarification, ClassArm::ClarificationRefused),
            (
                JobClass::ResearchSynthesis,
                ClassArm::ResearchSynthesisAdmitted,
            ),
            (
                JobClass::ArchitectureSelfQuery,
                ClassArm::ArchitectureSelfQueryRefused,
            ),
            (
                JobClass::DevelopmentDiagnosis,
                ClassArm::DevelopmentDiagnosisRefused,
            ),
            (JobClass::Maintenance, ClassArm::MaintenanceAdmitted),
            (
                JobClass::OrchestrationPlanning,
                ClassArm::OrchestrationPlanningRefused,
            ),
            (
                JobClass::ConfigurationAssistance,
                ClassArm::ConfigurationAssistanceRefused,
            ),
        ];
        assert_eq!(routed.len(), 9);
        for (class, expected) in routed {
            assert_eq!(dispatch_class(class), expected, "distinct arm for {class:?}");
        }
        let mut arms: Vec<ClassArm> = routed.iter().map(|(_, arm)| *arm).collect();
        arms.sort_by_key(|arm| *arm as u8);
        arms.dedup();
        assert_eq!(arms.len(), 9, "all nine arms must be distinct");
    }

    /// Each admitted class dispatches to its distinct admitted arm with the
    /// owner registry digest: the Slice 1c step validates the
    /// owner-published canonical registry and returns its stable digest
    /// alongside the arm.
    #[test]
    fn admitted_classes_dispatch_to_admitted_arms() {
        for class in [
            JobClass::Orientation,
            JobClass::Curation,
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
        ] {
            let (arm, digest) =
                dispatch_admission(&job_of_class(class)).expect("admitted class must dispatch");
            assert_eq!(dispatch_class(class), arm);
            assert!(!digest.is_empty(), "admitted arm must carry a registry digest");
        }
        let (first_arm, first_digest) = dispatch_admission(&job_of_class(JobClass::Orientation))
            .expect("admitted class must dispatch");
        let (second_arm, second_digest) = dispatch_admission(&job_of_class(JobClass::Orientation))
            .expect("admitted class must dispatch");
        assert_eq!(first_arm, second_arm, "dispatch must be deterministic");
        assert_eq!(
            first_digest, second_digest,
            "registry digest must be stable across admissions"
        );
    }

    /// The owner registry validation runs exactly once per admitted admission:
    /// one `canonical_registry()` provider call, then the owner's
    /// `validate_closure()` and `digest()` on that same value. The counting
    /// wrapper drives the production helper, so the count proves the call
    /// shape rather than a second implementation.
    #[test]
    fn admitted_arm_validates_owner_registry_exactly_once() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use eliot_dreamer_contracts::registry::canonical_registry;

        let calls = AtomicU64::new(0);
        let provider = || {
            calls.fetch_add(1, Ordering::SeqCst);
            canonical_registry()
        };
        let (arm, digest) = dispatch_admission_with(&job_of_class(JobClass::Orientation), provider)
            .expect("admitted class must dispatch");
        assert_eq!(arm, ClassArm::OrientationAdmitted);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "owner registry must be published exactly once per admission"
        );
        let owner_digest = canonical_registry()
            .expect("canonical registry composes")
            .digest()
            .expect("closed registry digests");
        assert_eq!(
            digest, owner_digest,
            "admission digest must be the owner digest, not a local value"
        );
    }

    /// Refused classes return at the Slice-A gate with no registry work: the
    /// provider is never called, so refusal costs no validation and performs
    /// zero Kernel-facing calls (the dispatch takes only `&DreamJobInput`,
    /// and `submit` runs it before `check_claimed`/`live_view`).
    #[test]
    fn refused_arms_do_no_registry_work() {
        use std::sync::atomic::{AtomicU64, Ordering};

        use eliot_dreamer_contracts::registry::canonical_registry;

        for class in [
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let calls = AtomicU64::new(0);
            let provider = || {
                calls.fetch_add(1, Ordering::SeqCst);
                canonical_registry()
            };
            let refused = dispatch_admission_with(&job_of_class(class), provider);
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?})"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "refused class {class:?} must do no registry work"
            );
        }
    }

    /// Each refused class fails closed at the Slice-A gate with the exact
    /// refusal before any leaf or Kernel-facing call: the dispatch
    /// takes only `&DreamJobInput` and returns a plain result, so there is no
    /// port, transport, or admission channel it could call, and `submit`
    /// invokes it before `check_claimed`/`live_view`, the only Kernel-facing
    /// calls. The refused arm identity is routed only for classes the gate
    /// already refused, so it carries no second refusal decision.
    #[test]
    fn refused_classes_fail_closed_before_kernel() {
        let refused_arms = [
            (JobClass::Clarification, ClassArm::ClarificationRefused),
            (
                JobClass::ArchitectureSelfQuery,
                ClassArm::ArchitectureSelfQueryRefused,
            ),
            (
                JobClass::DevelopmentDiagnosis,
                ClassArm::DevelopmentDiagnosisRefused,
            ),
            (
                JobClass::OrchestrationPlanning,
                ClassArm::OrchestrationPlanningRefused,
            ),
            (
                JobClass::ConfigurationAssistance,
                ClassArm::ConfigurationAssistanceRefused,
            ),
        ];
        for (class, expected) in refused_arms {
            assert_eq!(
                dispatch_class(class),
                expected,
                "class {class:?} must route its distinct refused arm"
            );
            let refused = dispatch_admission(&job_of_class(class));
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?})"
            );
        }
    }

    /// The Slice-1 typed refusals render their payloads and map to the
    /// request-rejected code, never to the Kernel-admission code.
    #[test]
    fn slice_1_refusal_display_and_code_hold() {
        let kind_error =
            DreamerError::UnsupportedCurationKind(eliot_dreamer_contracts::CurationKind::Repair);
        assert_eq!(
            format!("{kind_error}"),
            "unsupported Dreamer curation kind: Repair"
        );
        assert_eq!(kind_error.code(), "DREAMER_REQUEST_REJECTED");
        let registry_error =
            DreamerError::RegistryNotClosed("incomplete coverage".to_owned());
        assert_eq!(
            format!("{registry_error}"),
            "curation handler registry is not closed: incomplete coverage"
        );
        assert_eq!(registry_error.code(), "DREAMER_REQUEST_REJECTED");
    }

    /// Counting handler double in the contracts owner's blessed shape:
    /// implementors count real `handle` calls against an injected port. Slice
    /// 1 exposes no invocation surface, so driving the full admission dispatch
    /// for every class must leave every counter at
    /// zero. A later slice wiring a `handle` call into this path trips this
    /// guard.
    struct CountingLeaf {
        calls: AtomicU64,
    }

    impl NativeCurationHandler for CountingLeaf {
        fn handle(
            &self,
            _call: &BoundCurationCall,
        ) -> Result<ProducedCurationContent, ContractViolation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ContractViolation::Registry(
                "slice-1 counting double is never invoked".to_owned(),
            ))
        }
    }

    #[test]
    fn slice_1_dispatch_runs_no_handler() {
        let leaves: [CountingLeaf; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            .map(|_| CountingLeaf {
                calls: AtomicU64::new(0),
            });
        for class in [
            JobClass::Orientation,
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ResearchSynthesis,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::Maintenance,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let _ = dispatch_admission(&job_of_class(class));
        }
        for (index, leaf) in leaves.iter().enumerate() {
            assert_eq!(
                leaf.calls.load(Ordering::SeqCst),
                0,
                "leaf {index} must never be called by Slice-1 dispatch"
            );
        }
    }
}
