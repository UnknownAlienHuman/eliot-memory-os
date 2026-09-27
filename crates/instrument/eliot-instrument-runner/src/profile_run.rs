//! Deterministic stage orchestration, durable run records, and aggregation.
//!
//! This module extends [`InstrumentRunner`](crate::InstrumentRunner) toward
//! deterministic stage-DAG orchestration for issue #1813 without changing any
//! existing launch, inspection, or verdict behavior. The
//! [`StageOrchestrator`] walks an admitted profile DAG in topological order,
//! launches each external stage through the existing runner primitives, and
//! assembles one [`InstrumentRun`] per stage plus a [`ProfileAggregate`] that
//! retains every success, partial-failure, missing-stage, and evidence-handle
//! state.
//!
//! The orchestrator never synthesizes commands (every launch binds through a
//! caller-supplied [`InstrumentRequestPort`](crate::InstrumentRequestPort)),
//! never declares tasks complete (the aggregate is an observation, not a
//! finish decision), and never conceals missing or failed stages (unobserved
//! stages become explicit [`StageEvidence::Missing`] runs).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;

use eliot_contracts::{ModuleRuntimeClass, sha256_hex};
use eliot_instrument_api::{
    ExecutionStatus, InstrumentAdmissionGrant, InstrumentInvocation, InstrumentKind,
};
use eliot_process::{ProcessEvidenceSink, ProcessExecutor};
use eliot_process_executor::ExecutableObservation;
use thiserror::Error;

use crate::profile::{AdmissionError, AdmittedProfile, AdmittedStage};
use crate::registry::{RegistryEntry, RegistryError};
use crate::testd_port::{TestdAdmission, TestdAdmissionPort, TestdPortError, testd_dispatchable};
use crate::{
    InstrumentBinding, InstrumentRequestPort, InstrumentRunner, RunnerError,
    bridge_executor_observation,
};

/// Failures raised while planning or recording profile runs.
///
/// Launch failures never surface here: they become explicit
/// [`StageEvidence::Missing`] runs so the aggregate stays total.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProfileRunError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Field that failed validation.
        field: &'static str,
    },
    /// A stage identity names revision zero, which is never admitted.
    #[error("stage '{stage}' names unversioned profile revision zero")]
    InvalidRevision {
        /// Offending stage identity.
        stage: String,
    },
}

/// Validates one required text value.
fn validate_text(value: &str, field: &'static str) -> Result<(), ProfileRunError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProfileRunError::InvalidText { field });
    }
    Ok(())
}

/// Durable stage identity (I10.8.13).
///
/// The `(profile, revision, stage)` triple is stable across restarts; the
/// executor operation reference binds at launch. Re-execution under the same
/// identity never hides the first failed or unknown attempt: each attempt is
/// a separate [`InstrumentRun`] under the same stable triple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageIdentity {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted profile revision.
    pub profile_revision: u64,
    /// Durable stage identity within the profile revision.
    pub stage_id: String,
    /// Executor operation reference, bound at launch.
    pub operation_id: Option<String>,
}

impl StageIdentity {
    /// Plans an identity for a declared stage before launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] when an identity is blank, or
    /// [`ProfileRunError::InvalidRevision`] when the revision is zero.
    pub fn planned(
        profile: String,
        profile_revision: u64,
        stage_id: String,
    ) -> Result<Self, ProfileRunError> {
        validate_text(&profile, "profile")?;
        validate_text(&stage_id, "stage_id")?;
        if profile_revision == 0 {
            return Err(ProfileRunError::InvalidRevision { stage: stage_id });
        }
        Ok(Self {
            profile,
            profile_revision,
            stage_id,
            operation_id: None,
        })
    }

    /// Binds the sealed executor operation reference after launch.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileRunError::InvalidText`] when the operation identity
    /// is blank or carries control characters.
    pub fn bound(mut self, operation_id: String) -> Result<Self, ProfileRunError> {
        validate_text(&operation_id, "operation_id")?;
        self.operation_id = Some(operation_id);
        Ok(self)
    }

    /// Deterministic identity over the stable triple plus bound operation.
    pub fn digest(&self) -> String {
        let operation = self.operation_id.as_deref().unwrap_or("");
        let material = format!(
            "{}\0{}\0{}\0{}",
            self.profile, self.profile_revision, self.stage_id, operation,
        );
        sha256_hex(material.as_bytes())
    }
}

/// Pins one external stage to the test execution plane (I10.8.15).
///
/// The route records which runtime class owns the stage and whether live
/// `testd` can dispatch its class today. Recording the route grants no
/// launch authority: physical execution still flows through the injected
/// [`ProcessExecutor`](eliot_process::ProcessExecutor) behind the owning
/// supervisor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestExecutionPlaneRoute {
    stage: StageIdentity,
    kind: InstrumentKind,
    external: bool,
}

impl TestExecutionPlaneRoute {
    /// Routes one planned stage through the test execution plane.
    pub fn route(stage: StageIdentity, kind: InstrumentKind, external: bool) -> Self {
        Self {
            stage,
            kind,
            external,
        }
    }

    /// Runtime class that owns external build/test stages.
    pub const fn plane() -> ModuleRuntimeClass {
        ModuleRuntimeClass::TestExecutionPlane
    }

    /// Durable stage identity carried by this route.
    pub fn stage(&self) -> &StageIdentity {
        &self.stage
    }

    /// Stage class carried by this route.
    pub const fn kind(&self) -> InstrumentKind {
        self.kind
    }

    /// Whether the stage dispatches through the plane (`false` marks an
    /// explicitly pure in-process transform).
    pub const fn external(&self) -> bool {
        self.external
    }

    /// Whether live `testd` can dispatch this stage class today.
    ///
    /// Only [`InstrumentKind::Test`] dispatches; every other class resolves
    /// through the registry but stays non-dispatchable via `testd`, reported
    /// here instead of failing the whole plan.
    pub fn dispatchable_via_testd(&self) -> bool {
        crate::testd_port::testd_dispatchable(self.kind)
    }
}

/// One planned stage: admitted declaration plus its plane route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedStage {
    /// Admitted declaration in topological position.
    pub stage: AdmittedStage,
    /// Plane route for the stage.
    pub route: TestExecutionPlaneRoute,
}

/// One deterministic stage plan expanded from an admitted profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagePlan {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Planned stages in deterministic topological order.
    pub stages: Vec<PlannedStage>,
}

/// Per-stage launch provisions supplied by the composition root.
///
/// The implementation belongs to the runtime composition root: it derives
/// each stage invocation from the admitted plan, returns the sealed process
/// request through its port, and supplies the governed evidence sink. The
/// orchestrator never invents invocations, requests, or sinks.
pub trait StageLauncher: Send + Sync {
    /// Derives the typed invocation for one planned stage.
    ///
    /// # Errors
    ///
    /// Returns a runner error when the stage invocation is unavailable; the
    /// orchestrator records the stage as missing instead of failing the plan.
    fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError>;

    /// Returns the admitted request port for one planned stage.
    fn port(&self, stage: &PlannedStage) -> &dyn InstrumentRequestPort;

    /// Returns the governed evidence sink for one planned stage.
    fn sink(&self, stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink>;
}

/// Raw evidence state carried by one [`InstrumentRun`].
///
/// Retention alone establishes no outcome; omission and absence are explicit
/// typed states that can never become a successful aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StageEvidence {
    /// Material output retained under an immutable artifact handle.
    Retained {
        /// Stable handle for the retained bytes.
        artifact: eliot_contracts::ArtifactId,
        /// Exact retained byte length.
        byte_len: u64,
    },
    /// Material output absent for an explicit, typed reason.
    Omitted {
        /// Why the output is absent.
        reason: String,
    },
    /// The stage never produced evidence: unavailable instrument, refused
    /// admission, failed launch, blocked dependency, or unobserved stage.
    Missing {
        /// Exact missing proof (I10.8.11).
        reason: String,
    },
}

impl StageEvidence {
    /// Whether the stage produced no evidence at all.
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing { .. })
    }
}

/// One durable run record per stage (I16.17).
///
/// The record binds the durable [`StageIdentity`], the owning plane, the
/// execution axis, the raw evidence handle, and the machine-derived
/// executable digest. It carries no semantic verdict and no completion claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstrumentRun {
    /// Durable stage identity; the operation binds at launch.
    pub stage: StageIdentity,
    /// Runtime class that owns the stage.
    pub plane: ModuleRuntimeClass,
    /// Whether live `testd` can dispatch the stage class.
    pub testd_dispatchable: bool,
    /// Execution axis only; no semantic result is inferred.
    pub execution: ExecutionStatus,
    /// Raw evidence state.
    pub evidence: StageEvidence,
    /// Machine-derived executable identity digest, when observed.
    pub executable_digest: Option<String>,
    /// Process grant digest sealed by pre-launch admission, when admitted.
    ///
    /// The digest binds the matched spec revision, profile revision, and
    /// parser generation (I10.8.3): a run that never passed admission
    /// carries no grant. It travels into the aggregate digest so a changed
    /// executable/argument combination can never reuse an earlier receipt.
    pub grant_digest: Option<String>,
}

impl InstrumentRun {
    /// Records a launched stage whose terminal observation is still owned by
    /// the supervising lane.
    ///
    /// A malformed sealed operation identity fails closed into an explicit
    /// missing proof instead of an unbound launched run.
    pub fn launched(
        route: &TestExecutionPlaneRoute,
        operation_id: String,
        grant: &InstrumentAdmissionGrant,
    ) -> Self {
        let Ok(stage) = route.stage().clone().bound(operation_id) else {
            return Self::missing(route, "sealed operation identity is malformed");
        };
        Self {
            stage,
            plane: TestExecutionPlaneRoute::plane(),
            testd_dispatchable: route.dispatchable_via_testd(),
            execution: ExecutionStatus::Accepted,
            evidence: StageEvidence::Omitted {
                reason: "launched; terminal observation is owned by the supervising lane"
                    .to_owned(),
            },
            executable_digest: None,
            grant_digest: Some(grant.grant_digest.clone()),
        }
    }

    /// Records an explicit missing proof for a stage that never ran.
    pub fn missing(route: &TestExecutionPlaneRoute, reason: impl Into<String>) -> Self {
        Self {
            stage: route.stage().clone(),
            plane: TestExecutionPlaneRoute::plane(),
            testd_dispatchable: route.dispatchable_via_testd(),
            execution: ExecutionStatus::Unknown,
            evidence: StageEvidence::Missing {
                reason: reason.into(),
            },
            executable_digest: None,
            grant_digest: None,
        }
    }

    /// Whether the run may count toward a successful aggregate.
    ///
    /// Success requires successful execution, retained raw evidence, and an
    /// observed executable identity. Anything else stays visible in the
    /// aggregate instead of collapsing into success.
    pub fn is_success(&self) -> bool {
        self.execution == ExecutionStatus::Succeeded
            && matches!(self.evidence, StageEvidence::Retained { .. })
            && self.executable_digest.is_some()
    }
}

/// Aggregate status over one profile run.
///
/// Missing or failed required stages dominate: they can never be represented
/// as [`AggregateStatus::Succeeded`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AggregateStatus {
    /// Every required stage succeeded and every optional stage succeeded.
    Succeeded,
    /// Every required stage succeeded; an optional stage did not.
    PartialFailure,
    /// A required stage failed, was cancelled, or was blocked.
    Failed,
    /// A required stage has no evidence: unavailable, refused, or unobserved.
    MissingRequired,
    /// A required stage has not reached a terminal successful state.
    Unknown,
}

/// Aggregate profile result retaining every per-stage state (I10.8.4).
///
/// Assembly is total over the declared plan: declared stages without an
/// observed run become explicit [`StageEvidence::Missing`] runs, so an
/// unavailable or failed required stage remains visible and the aggregate
/// can never represent it as successful.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileAggregate {
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Aggregate digest over definition plus ordered runs.
    pub aggregate_digest: String,
    /// Per-stage runs in plan order.
    pub runs: Vec<InstrumentRun>,
    /// Aggregate status; never successful over missing/failed required work.
    pub status: AggregateStatus,
}

impl ProfileAggregate {
    /// Assembles the aggregate over observed runs in plan order.
    ///
    /// Runs are matched to declared stages by the full durable stage
    /// identity (`profile`, `profile_revision`, `stage_id`): a run recorded
    /// for another profile or revision never satisfies this plan, even when
    /// the stage identities coincide. Extra runs for undeclared stages are
    /// ignored, and declared stages without a run become explicit missing
    /// proofs.
    pub fn assemble(plan: &StagePlan, runs: Vec<InstrumentRun>) -> Self {
        let mut observed = BTreeMap::new();
        for run in runs {
            observed
                .entry((
                    run.stage.profile.clone(),
                    run.stage.profile_revision,
                    run.stage.stage_id.clone(),
                ))
                .or_insert(run);
        }
        let mut ordered = Vec::with_capacity(plan.stages.len());
        for planned in &plan.stages {
            let key = (
                plan.profile.clone(),
                plan.revision,
                planned.route.stage().stage_id.clone(),
            );
            match observed.remove(&key) {
                Some(run) => ordered.push(run),
                None => ordered.push(InstrumentRun::missing(
                    &planned.route,
                    "stage has no observed run",
                )),
            }
        }
        let status = aggregate_status(plan, &ordered);
        let mut material = format!(
            "{}\0{}\0{}\0{}\0",
            plan.profile, plan.revision, plan.profile_digest, plan.dag_digest,
        );
        for run in &ordered {
            material.push_str(&run.stage.digest());
            material.push('\0');
            let _ = write!(material, "{:?}", run.execution);
            material.push('\0');
            match &run.evidence {
                StageEvidence::Retained { artifact, byte_len } => {
                    material.push_str(artifact.as_str());
                    material.push('\0');
                    material.push_str(&byte_len.to_string());
                }
                StageEvidence::Omitted { reason } | StageEvidence::Missing { reason } => {
                    material.push_str(reason);
                }
            }
            material.push('\0');
            material.push_str(run.executable_digest.as_deref().unwrap_or(""));
            material.push('\0');
            material.push_str(run.grant_digest.as_deref().unwrap_or(""));
            material.push('\0');
        }
        Self {
            profile: plan.profile.clone(),
            revision: plan.revision,
            profile_digest: plan.profile_digest.clone(),
            dag_digest: plan.dag_digest.clone(),
            aggregate_digest: sha256_hex(material.as_bytes()),
            runs: ordered,
            status,
        }
    }

    /// Whether the aggregate represents fully successful verification.
    pub const fn is_success(&self) -> bool {
        matches!(self.status, AggregateStatus::Succeeded)
    }
}

/// Computes the aggregate status with required-stage dominance.
///
/// A missing required stage dominates a failed one, which dominates an
/// unknown one; optional stages can only downgrade success to partial
/// failure, never the reverse.
fn aggregate_status(plan: &StagePlan, runs: &[InstrumentRun]) -> AggregateStatus {
    let mut required_failure: Option<AggregateStatus> = None;
    for (planned, run) in plan.stages.iter().zip(runs.iter()) {
        if !planned.stage.required || run.is_success() {
            continue;
        }
        let failure = if run.evidence.is_missing() {
            AggregateStatus::MissingRequired
        } else if matches!(
            run.execution,
            ExecutionStatus::Failed | ExecutionStatus::Cancelled | ExecutionStatus::Blocked
        ) {
            AggregateStatus::Failed
        } else {
            AggregateStatus::Unknown
        };
        let worse = match required_failure {
            None => true,
            Some(current) => status_rank(failure) > status_rank(current),
        };
        if worse {
            required_failure = Some(failure);
        }
    }
    if let Some(failure) = required_failure {
        return failure;
    }
    let optional_failure = plan
        .stages
        .iter()
        .zip(runs.iter())
        .any(|(planned, run)| !planned.stage.required && !run.is_success());
    if optional_failure {
        AggregateStatus::PartialFailure
    } else {
        AggregateStatus::Succeeded
    }
}

/// Dominance rank for required-stage failures.
const fn status_rank(status: AggregateStatus) -> u8 {
    match status {
        AggregateStatus::MissingRequired => 3,
        AggregateStatus::Failed => 2,
        AggregateStatus::Unknown => 1,
        AggregateStatus::PartialFailure | AggregateStatus::Succeeded => 0,
    }
}

/// Deterministic stage-DAG orchestration over the existing runner.
///
/// Planning expands the admitted DAG; launching walks it in topological
/// order through [`InstrumentRunner::launch`]. Dependent stages of a stage
/// that never launched are recorded as blocked missing proofs instead of
/// launching against absent prerequisites. Independent stages always launch:
/// one failure never discards an unrelated sibling.
pub struct StageOrchestrator;

impl StageOrchestrator {
    /// Expands an admitted profile into a deterministic stage plan.
    ///
    /// Identities reuse admission-validated values, so planning is total:
    /// the same admission always yields the same plan.
    pub fn plan(admitted: &AdmittedProfile) -> StagePlan {
        let stages = admitted
            .stages
            .iter()
            .map(|stage| {
                let identity = StageIdentity {
                    profile: admitted.name.clone(),
                    profile_revision: admitted.revision,
                    stage_id: stage.stage_id.clone(),
                    operation_id: None,
                };
                PlannedStage {
                    route: TestExecutionPlaneRoute::route(identity, stage.kind, stage.external),
                    stage: stage.clone(),
                }
            })
            .collect();
        StagePlan {
            profile: admitted.name.clone(),
            revision: admitted.revision,
            profile_digest: admitted.profile_digest.clone(),
            dag_digest: admitted.dag_digest.clone(),
            stages,
        }
    }

    /// Launches every planned stage in topological order.
    ///
    /// The walk is total: launch, admission, and invocation failures become
    /// explicit missing runs, and dependents of a stage that never launched
    /// become blocked missing proofs. Terminal observation and evidence
    /// retention stay with the supervising lane; this walk never holds an
    /// ordering slot while a tool runs.
    pub async fn launch_plan<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        plan: &StagePlan,
        launcher: &dyn StageLauncher,
    ) -> Vec<InstrumentRun> {
        let mut runs = Vec::with_capacity(plan.stages.len());
        let mut unlaunched: BTreeSet<String> = BTreeSet::new();
        for planned in &plan.stages {
            let route = &planned.route;
            let blocked_by = planned
                .stage
                .depends_on
                .iter()
                .find(|dependency| unlaunched.contains(*dependency));
            if let Some(dependency) = blocked_by {
                runs.push(InstrumentRun::missing(
                    route,
                    format!("blocked by unlaunched dependency '{dependency}'"),
                ));
                unlaunched.insert(route.stage().stage_id.clone());
                continue;
            }
            let run = Self::launch_one(runner, planned, launcher).await;
            if run.evidence.is_missing() {
                unlaunched.insert(route.stage().stage_id.clone());
            }
            runs.push(run);
        }
        runs
    }

    /// Binds and launches one stage through the existing runner primitives.
    ///
    /// The pre-launch closure runs in fixed order before any child process
    /// exists: the owning port binds the invocation shape into the sealed
    /// process request (adapter schema authority), the executable
    /// hash/file identity resolves from the machine against the
    /// intent-sealed digest, the shared admission gate checks the fixed
    /// argument template and executable identity into a sealed grant, and
    /// only then does the runner launch. A changed executable, an unknown
    /// identity, or an off-template argument combination becomes an
    /// explicit missing run here instead of a child process. The tool
    /// version stays unobserved (`None`): no version is attested on this
    /// path, so none is claimed, while a spec-pinned version still gates
    /// inside admission.
    async fn launch_one<E: ProcessExecutor + 'static>(
        runner: &InstrumentRunner<E>,
        planned: &PlannedStage,
        launcher: &dyn StageLauncher,
    ) -> InstrumentRun {
        let route = &planned.route;
        if !route.external() {
            return InstrumentRun::missing(
                route,
                "pure in-process stage bypasses the plane; no in-process lane is bound",
            );
        }
        let invocation = match launcher.invocation(planned) {
            Ok(invocation) => invocation,
            Err(error) => {
                return InstrumentRun::missing(
                    route,
                    format!("stage invocation unavailable: {error}"),
                );
            }
        };
        if invocation.instrument.as_str() != planned.stage.spec.as_str() {
            return InstrumentRun::missing(
                route,
                "stage admission refused: invocation instrument differs from admitted stage",
            );
        }
        if invocation.kind != planned.stage.kind {
            return InstrumentRun::missing(
                route,
                "stage admission refused: invocation kind differs from admitted stage",
            );
        }
        if invocation.profile.as_str() != route.stage().profile.as_str() {
            return InstrumentRun::missing(
                route,
                "stage admission refused: invocation profile differs from admitted stage",
            );
        }
        let process_request = match launcher.port(planned).bind(&invocation) {
            Ok(request) => request,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage admission refused: {error}"));
            }
        };
        let observed =
            match ExecutableObservation::observe_from_intent(process_request.intent(), None) {
                Ok(observation) => observation,
                Err(error) => {
                    return InstrumentRun::missing(
                        route,
                        format!(
                            "stage admission refused: {}",
                            AdmissionError::ExecutableMismatch {
                                detail: error.to_string(),
                            }
                        ),
                    );
                }
            };
        let identity = match bridge_executor_observation(invocation.instrument.as_str(), observed) {
            Ok(identity) => identity,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage admission refused: {error}"));
            }
        };
        let admission = planned
            .stage
            .admission_request(&invocation, Some(&identity));
        let grant =
            match planned
                .stage
                .admit(&admission, Some(&identity), route.stage().profile_revision)
            {
                Ok(grant) => grant,
                Err(error) => {
                    return InstrumentRun::missing(
                        route,
                        format!("stage admission refused: {error}"),
                    );
                }
            };
        let mut binding = match InstrumentBinding::from_request(invocation, process_request) {
            Ok(binding) => binding,
            Err(error) => {
                return InstrumentRun::missing(route, format!("stage admission refused: {error}"));
            }
        };
        match runner.launch(&mut binding, launcher.sink(planned)).await {
            Ok(receipt) => {
                let operation = receipt.process.operation_id().as_str().to_owned();
                InstrumentRun::launched(route, operation, &grant)
            }
            Err(error) => InstrumentRun::missing(route, format!("stage launch failed: {error}")),
        }
    }
}

impl<E: ProcessExecutor + 'static> InstrumentRunner<E> {
    /// Runs one admitted profile end to end: plan, launch, aggregate.
    ///
    /// This is deterministic orchestration only. Stage commands come solely
    /// from the admitted plan through the caller-supplied [`StageLauncher`];
    /// the returned [`ProfileAggregate`] observes success, partial failure,
    /// missing stages, and evidence handles without declaring any task
    /// complete.
    pub async fn run_profile_stages(
        &self,
        admitted: &AdmittedProfile,
        launcher: &dyn StageLauncher,
    ) -> ProfileAggregate {
        let plan = StageOrchestrator::plan(admitted);
        let runs = StageOrchestrator::launch_plan(self, &plan, launcher).await;
        ProfileAggregate::assemble(&plan, runs)
    }
}

/// Production [`StageLauncher`] serving composition-root-admitted invocations.
///
/// The composition root admits one typed [`InstrumentInvocation`] per planned
/// stage identity and hands the map to the orchestrator together with its
/// request port and evidence sink. Lookup is exact: a stage without an
/// admitted invocation fails into an explicit missing run through the
/// orchestrator's existing total-walk behavior, never into a synthesized
/// command or a silently skipped stage.
pub struct MappedStageLauncher<'p> {
    invocations: BTreeMap<String, InstrumentInvocation>,
    port: &'p dyn InstrumentRequestPort,
    sink: Arc<dyn ProcessEvidenceSink>,
}

impl<'p> MappedStageLauncher<'p> {
    /// Serves `invocations` through `port`, retaining evidence via `sink`.
    pub fn new(
        invocations: BTreeMap<String, InstrumentInvocation>,
        port: &'p dyn InstrumentRequestPort,
        sink: Arc<dyn ProcessEvidenceSink>,
    ) -> Self {
        Self {
            invocations,
            port,
            sink,
        }
    }
}

impl StageLauncher for MappedStageLauncher<'_> {
    fn invocation(&self, stage: &PlannedStage) -> Result<InstrumentInvocation, RunnerError> {
        let stage_id = stage.route.stage().stage_id.as_str();
        self.invocations.get(stage_id).cloned().ok_or_else(|| {
            RunnerError::Binding(format!("no admitted invocation for stage '{stage_id}'"))
        })
    }

    fn port(&self, _stage: &PlannedStage) -> &dyn InstrumentRequestPort {
        self.port
    }

    fn sink(&self, _stage: &PlannedStage) -> Arc<dyn ProcessEvidenceSink> {
        Arc::clone(&self.sink)
    }
}

/// Production [`TestdAdmissionPort`] behind the test execution plane (I10.8.15).
///
/// External build/test stages resolve through the provider registry first;
/// this admission records which of them live `eliot-testd` can dispatch
/// today. Only [`InstrumentKind::Test`] dispatches: every other class keeps
/// its registry resolution and is reported as the typed
/// [`TestdPortError::UnsupportedByTestd`] refusal instead of failing the plan.
pub struct TestdPlaneAdmission;

impl TestdPlaneAdmission {
    /// Admits one admitted `(instrument, kind)` pair behind the test execution
    /// plane without an invocation.
    ///
    /// This is the exact [`TestdAdmissionPort::admit`] decision over the
    /// admitted stage identity instead of a full provider-neutral invocation,
    /// so classification-only callers (the registry composition in
    /// [`compose_provider_dispatch`); issue #1813 W4: the governed describe
    /// path records per-stage testd admission without execution provisions)
    /// never fabricate invocation authority material such as a State Fence,
    /// session, or lease. The receipt still binds the registry-selected
    /// adapter and generation; only the invocation clone is absent, and no
    /// governed claim may rest on that absence.
    pub fn admit_parts(
        instrument: &eliot_contracts::ContractId,
        kind: InstrumentKind,
        entry: &RegistryEntry,
    ) -> Result<(String, u64), TestdPortError> {
        if entry.instrument.as_str() != instrument.as_str() {
            return Err(TestdPortError::Registry(RegistryError::Missing {
                instrument: instrument.as_str().to_owned(),
                kind,
            }));
        }
        if !entry.supports(kind) {
            return Err(TestdPortError::Registry(RegistryError::Unsupported {
                adapter: entry.adapter.clone(),
                kind,
            }));
        }
        if !testd_dispatchable(kind) {
            return Err(TestdPortError::UnsupportedByTestd { kind });
        }
        Ok((entry.adapter.clone(), entry.generation))
    }
}

impl TestdAdmissionPort for TestdPlaneAdmission {
    fn admit(
        &self,
        invocation: &InstrumentInvocation,
        entry: &RegistryEntry,
    ) -> Result<TestdAdmission, TestdPortError> {
        Self::admit_parts(&invocation.instrument, invocation.kind, entry)?;
        Ok(TestdAdmission::new(invocation.clone(), entry))
    }
}

/// The registry-composed dispatch decision for one admitted stage.
///
/// This is the single decision point where the current provider registry,
/// the host's observed platform, and Testd's dispatch capability meet. It
/// runs the whole pre-execution closure — exactly-one-entry resolution,
/// generation and fingerprint freshness, host support, then Testd
/// capability — and every rejection carries a typed
/// [`ProviderDisposition`](crate::ProviderDisposition) so the stage stays
/// counted in the declared denominator. A `Dispatch` decision is a
/// precondition only: it grants no process, no task acceptance, and no
/// Finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderDispatch {
    /// The provider resolved, is current, is supported on this host, and is
    /// dispatchable by Testd. The entry carries no process authority.
    Dispatch {
        /// The single current registry entry that owns the stage.
        entry: Box<RegistryEntry>,
    },
    /// The provider was refused. It remains in the declared denominator.
    Refused {
        /// The exact typed reason.
        disposition: crate::ProviderDisposition,
    },
}

impl ProviderDispatch {
    /// The owning entry, only on the dispatch path.
    #[must_use]
    pub fn entry(&self) -> Option<&RegistryEntry> {
        match self {
            Self::Dispatch { entry } => Some(entry),
            Self::Refused { .. } => None,
        }
    }

    /// The typed disposition for this stage.
    #[must_use]
    pub fn disposition(&self) -> crate::ProviderDisposition {
        match self {
            Self::Dispatch { .. } => crate::ProviderDisposition::Ready,
            Self::Refused { disposition } => disposition.clone(),
        }
    }

    /// Whether the stage may be dispatched.
    #[must_use]
    pub const fn is_dispatchable(&self) -> bool {
        matches!(self, Self::Dispatch { .. })
    }
}

/// Composes the current provider registry behind the Testd boundary.
///
/// Runs the whole pre-execution closure in order: exactly-one-entry
/// resolution, generation and fingerprint freshness, host support, then
/// admission of the resolved entry through
/// [`TestdPlaneAdmission::admit_parts`] behind the test execution plane.
/// The closure is total: no rejection is an `Err`, so a missing, duplicate,
/// ambiguous, stale, unsupported, or unmapped provider is reported as a
/// typed [`ProviderDispatch::Refused`] carrying its exact cause rather than
/// an error that could be dropped from a denominator. No process, build
/// root, task, budget, or Finish authority is created here; only Testd
/// dispatches.
///
/// Freshness inputs and the observed platform are supplied by the
/// composition root, which owns the machine observations. A dispatch
/// decision is a precondition only: the caller still has to run the
/// provider and the runner still has to bind a launch-sealed executable
/// identity before any result can take authoritative PASS.
#[must_use]
pub fn compose_provider_dispatch(
    registry: &crate::ProviderRegistry,
    instrument: &eliot_contracts::ContractId,
    kind: InstrumentKind,
    inputs: &crate::AvailabilityInputs<'_>,
) -> ProviderDispatch {
    let available = registry.availability_parts(instrument, kind, inputs);
    if !available.is_available() {
        return ProviderDispatch::Refused {
            disposition: available.disposition(),
        };
    }
    // `availability_parts` already ran the freshness-pinned resolution, so
    // the ready arm is exactly the single current entry it returned.
    let Some(entry) = available.entry() else {
        return ProviderDispatch::Refused {
            disposition: crate::ProviderDisposition::Unmapped,
        };
    };
    match TestdPlaneAdmission::admit_parts(instrument, kind, entry) {
        Ok(_) => ProviderDispatch::Dispatch {
            entry: Box::new(entry.clone()),
        },
        Err(TestdPortError::UnsupportedByTestd { kind }) => ProviderDispatch::Refused {
            disposition: crate::ProviderDisposition::Unsupported {
                adapter: instrument.as_str().to_owned(),
                kind,
            },
        },
        Err(TestdPortError::Registry(error)) => ProviderDispatch::Refused {
            disposition: crate::disposition_for_parts(instrument.as_str(), kind, &error),
        },
    }
}
