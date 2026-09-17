#![forbid(unsafe_code)]

#[cfg(test)]
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_cli::kernel_client::{KernelClient, KernelClientError};
use eliot_contracts::StateFence;
use eliot_protocol::dreamer_job::{DurableJobResponse, JobState as ProtocolJobState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) mod kernel_port;

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

/// Authenticated production adapter over the installation-owned Kernel client.
///
/// The port owns the validated one-shot claim: connecting loads the
/// installation-owned client, probes the authenticated health handshake,
/// binds the live authority epoch it echoes, validates the staged dispatch
/// material presented next to this executable, derives the in-process
/// dispatch permit exactly once, and performs `LeaseExact` then `Start`
/// through the authenticated worker session. Any step failing closed refuses
/// with [`DreamerError::KernelAdmissionRequired`] without effect.
pub struct AuthenticatedKernelJobPort {
    material: kernel_port::ValidatedDreamerMaterial,
    admission: KernelJobAdmission,
    view: JobView,
    handshake: KernelHandshake,
    transport: kernel_port::KernelClaimTransport,
}

impl AuthenticatedKernelJobPort {
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
        let mut transport = kernel_port::KernelClaimTransport::new(session);
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
            transport,
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

    /// Observes the live Kernel-proved disposition of the claimed job.
    ///
    /// A refused or unbound reply fails closed; the port never serves a stale
    /// cached view as liveness.
    fn live_view(&mut self) -> Result<JobView, DreamerError> {
        let observed = kernel_port::status_once(&self.material, &mut self.transport)
            .map_err(|error| port_denied(&error))?;
        Ok(project_claimed_view(&observed))
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
/// Exhaustive with no wildcard arm: extending the closed taxonomy breaks
/// compilation here until the new class is assigned an owning slice.
fn refuse_unsupported_job_class(job: &DreamJobInput) -> Result<(), DreamerError> {
    match job.job_class {
        JobClass::Curation => Err(DreamerError::UnsupportedJobClass(job.job_class)),
        JobClass::Clarification => Err(DreamerError::UnsupportedJobClass(job.job_class)),
        JobClass::ArchitectureSelfQuery => {
            Err(DreamerError::UnsupportedJobClass(job.job_class))
        }
        JobClass::DevelopmentDiagnosis => Err(DreamerError::UnsupportedJobClass(job.job_class)),
        JobClass::OrchestrationPlanning => {
            Err(DreamerError::UnsupportedJobClass(job.job_class))
        }
        JobClass::ConfigurationAssistance => {
            Err(DreamerError::UnsupportedJobClass(job.job_class))
        }
        JobClass::Orientation => Ok(()),
        JobClass::ResearchSynthesis => Ok(()),
        JobClass::Maintenance => Ok(()),
    }
}

impl KernelJobPort for AuthenticatedKernelJobPort {
    fn handshake(&mut self) -> Result<KernelHandshake, DreamerError> {
        Ok(self.handshake)
    }

    fn submit(
        &mut self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<JobView, DreamerError> {
        refuse_unsupported_job_class(job)?;
        self.check_claimed(admission)?;
        self.live_view()
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

#[derive(Debug, Error)]
pub enum DreamerError {
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("input limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("invalid admission: {0}")]
    InvalidAdmission(&'static str),
    #[error("job already exists: {0}")]
    DuplicateJob(String),
    #[error("unknown job: {0}")]
    UnknownJob(String),
    #[error("job is not cancellable: {0}")]
    NotCancellable(String),
    #[error("{KERNEL_ADMISSION_REQUIRED}: {0}")]
    KernelAdmissionRequired(String),
    #[error("unsupported Dreamer job class: {0:?}")]
    UnsupportedJobClass(JobClass),
}

impl DreamerError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KernelAdmissionRequired(_) => KERNEL_ADMISSION_REQUIRED,
            Self::UnsupportedJobClass(_) => "DREAMER_REQUEST_REJECTED",
            _ => "DREAMER_REQUEST_REJECTED",
        }
    }
}

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

/// T12-08 consumer-linkage prerequisite for issue #702.
///
/// Real production references to the five T8-A4-admitted leaves so package
/// resolution succeeds. Linkage only, not a working job path: no stage
/// modules, no job execution, and no reference to the still-excluded
/// `eliot-dreamer-orientation` leaf.
pub fn admitted_leaf_linkage() {
    let _ = eliot_dreamer_bundle::plan_bundle;
    let _ = eliot_dreamer_candidate_validation::validate_grounded_dream_draft_at;
    let _ = eliot_dreamer_claim_grounding::ground_draft;
    let _ = eliot_dreamer_rival_model::structure_rival_models;
    let _ = eliot_dreamer_probe_plan::ProbePlan::new;
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
    fn curation_refuses_without_kernel_contact() {
        assert_refused(JobClass::Curation);
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

    /// The three Slice-A admitted classes fall through to the existing path:
    /// the gate returns `Ok`, preserving the `check_claimed`/`live_view`
    /// behavior (including its `None`-result projection) unchanged.
    #[test]
    fn admitted_classes_pass_the_slice_a_gate() {
        for class in [
            JobClass::Orientation,
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
