//! Governed instrument profile execution reporting (issue #1813).
//!
//! This edge serves the two verify entries that accept a profile name
//! (`verify run`/`verify plan` locally and `eliot_verify_plan` over MCP).
//! A governed name compiles through the single [`ProfileCompiler`], expands
//! to its deterministic [`StagePlan`](eliot_instrument_runner::StagePlan),
//! and assembles the total
//! [`ProfileAggregate`](eliot_instrument_runner::ProfileAggregate) over zero
//! observed runs: the verify entries carry no stage launcher provisions, so
//! every stage becomes an explicit missing proof instead of a launch. One
//! run record per stage plus the aggregate record persist to the configured
//! [`BlobStore`](eliot_store::BlobStore); the returned handles are
//! content-addressed, so both entries observe the identical bytes.
//!
//! No process is launched here and no task is declared complete: execution
//! provisions (executor, request port, evidence sink) and finish authority
//! belong to the Kernel/testd/Governor composition roots. A non-successful
//! aggregate fails closed through
//! [`GovernedProfileService::enforce_success`].

use eliot_instrument_runner::profile::{AdmittedProfile, InstrumentRegistry, ProfileCompiler};
use eliot_instrument_runner::profile_run::{
    InstrumentRun, ProfileAggregate, StageEvidence, StageOrchestrator, StagePlan,
};
use eliot_store::BlobStore;
use eliot_types::BlobRef;
use serde::Serialize;

use super::rejected;
use crate::EngineError;

/// Schema version carried by every [`GovernedProfileReport`].
pub const GOVERNED_PROFILE_REPORT_SCHEMA: &str = "eliot-governed-profile-report-v1";
/// Schema version of one persisted per-stage run record.
const GOVERNED_RUN_RECORD_SCHEMA: &str = "eliot-governed-run-record-v1";
/// Schema version of the persisted aggregate record.
const GOVERNED_AGGREGATE_RECORD_SCHEMA: &str = "eliot-governed-aggregate-record-v1";
/// Registry generation shared with the governed build and current lanes.
const BUILTIN_REGISTRY_GENERATION: u64 = 1;
/// Exact missing proof recorded when no stage could launch.
const NO_LAUNCH_PROVISIONS: &str = "no stage launcher provisions in this composition root: stages were planned but never launched, so every run is an explicit missing proof";

/// One planned stage with its durable run record and persist handle.
#[derive(Clone, Debug, Serialize)]
pub struct GovernedStageReport {
    /// Durable stage identity within the profile revision.
    pub stage_id: String,
    /// Bound spec kind identity.
    pub spec: String,
    /// Stage class.
    pub kind: String,
    /// Whether the aggregate fails without this stage.
    pub required: bool,
    /// Whether the stage dispatches through `TestExecutionPlane`.
    pub external: bool,
    /// Prerequisite stage identities.
    pub depends_on: Vec<String>,
    /// Runtime class that owns the stage.
    pub plane: String,
    /// Whether live `testd` can dispatch the stage class today.
    pub testd_dispatchable: bool,
    /// Execution axis only; never a semantic result.
    pub execution: String,
    /// Evidence state: `retained`, `omitted`, or `missing`.
    pub evidence_state: String,
    /// Retained handle or the explicit typed reason output is absent.
    pub evidence_detail: String,
    /// Machine-derived executable identity digest, when observed.
    pub executable_digest: Option<String>,
    /// Executor operation reference, bound at launch.
    pub operation_id: Option<String>,
    /// Canonical handle of the persisted run record, when a store was supplied.
    pub run_blob: Option<BlobRef>,
}

/// Governed execution report over one admitted profile revision.
#[derive(Clone, Debug, Serialize)]
pub struct GovernedProfileReport {
    /// Report schema version.
    pub schema_version: String,
    /// Admitted profile name.
    pub profile: String,
    /// Exact admitted revision.
    pub revision: u64,
    /// Profile definition digest.
    pub profile_digest: String,
    /// Stage DAG digest.
    pub dag_digest: String,
    /// Admitted invocation classes.
    pub kinds: Vec<String>,
    /// Registry generation the admission was validated against.
    pub registry_generation: u64,
    /// Per-stage reports in deterministic plan order.
    pub stages: Vec<GovernedStageReport>,
    /// Aggregate digest over definition plus ordered runs.
    pub aggregate_digest: String,
    /// Aggregate status; never successful over missing/failed required work.
    pub aggregate_status: String,
    /// Whether the aggregate represents fully successful verification.
    pub success: bool,
    /// Number of stages with an observed run.
    pub observed_runs: usize,
    /// Canonical handle of the persisted aggregate record, when supplied.
    pub aggregate_blob: Option<BlobRef>,
    /// Exact missing proof when stages never launched.
    pub missing_proof: String,
}

/// Governed profile execution behind the verify entries.
pub struct GovernedProfileService;

impl GovernedProfileService {
    /// Compiles one profile name through the single profile compiler.
    ///
    /// Returns the governed admission, or `None` when the name quarantines as
    /// legacy suite-profile text with no governed claim.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the builtin profile registry is unavailable.
    pub fn compile_governed(&self, name: &str) -> Result<Option<AdmittedProfile>, EngineError> {
        let registry = builtin_registry()?;
        let compiled = ProfileCompiler::new(&registry).compile(name);
        Ok(compiled.admitted().ok().cloned())
    }

    /// Describes one governed profile execution: compile, plan, aggregate,
    /// persist.
    ///
    /// The admission pins the exact revision and stage graph; the plan expands
    /// deterministically; the aggregate assembles over zero observed runs, so
    /// every stage without execution becomes an explicit missing proof. One
    /// run record per stage plus the aggregate record persist through
    /// `blob_store` when supplied, and the returned report carries the
    /// content-addressed handles. Identical input always yields identical
    /// persisted bytes on every entry point.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the builtin registry is unavailable, the
    /// name quarantines instead of governing, or blob persistence fails.
    pub fn describe_execution(
        &self,
        name: &str,
        blob_store: Option<&BlobStore>,
    ) -> Result<GovernedProfileReport, EngineError> {
        let registry = builtin_registry()?;
        let compiled = ProfileCompiler::new(&registry).compile(name);
        let admitted = compiled.admitted().map_err(|error| {
            rejected(
                "governed-profile",
                &format!("profile '{name}' is not governed: {error}"),
            )
        })?;
        let plan = StageOrchestrator::plan(admitted);
        let aggregate = ProfileAggregate::assemble(&plan, Vec::new());
        let mut stages = Vec::with_capacity(plan.stages.len());
        for (planned, run) in plan.stages.iter().zip(aggregate.runs.iter()) {
            stages.push(persist_stage_report(
                blob_store,
                &plan.profile,
                plan.revision,
                planned,
                run,
            )?);
        }
        let aggregate_blob = persist_aggregate_record(blob_store, &plan, &aggregate, &stages)?;
        let observed_runs = aggregate
            .runs
            .iter()
            .filter(|run| !run.evidence.is_missing())
            .count();
        Ok(GovernedProfileReport {
            schema_version: GOVERNED_PROFILE_REPORT_SCHEMA.to_owned(),
            profile: plan.profile.clone(),
            revision: plan.revision,
            profile_digest: plan.profile_digest.clone(),
            dag_digest: plan.dag_digest.clone(),
            kinds: admitted
                .kinds
                .iter()
                .map(|kind| format!("{kind:?}"))
                .collect(),
            registry_generation: registry.generation(),
            stages,
            aggregate_digest: aggregate.aggregate_digest.clone(),
            aggregate_status: format!("{:?}", aggregate.status),
            success: aggregate.is_success(),
            observed_runs,
            aggregate_blob,
            missing_proof: NO_LAUNCH_PROVISIONS.to_owned(),
        })
    }

    /// Refuses a non-successful governed aggregate as an error.
    ///
    /// Missing or failed required stages stay visible in the report instead of
    /// being representable as successful verification.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the aggregate did not reach full success.
    pub fn enforce_success(&self, report: &GovernedProfileReport) -> Result<(), EngineError> {
        if report.success {
            return Ok(());
        }
        Err(rejected(
            "governed-profile",
            &format!(
                "governed profile '{}' revision {} did not succeed: {}; {}",
                report.profile, report.revision, report.aggregate_status, report.missing_proof,
            ),
        ))
    }
}

/// Loads the builtin registry shared with the other compiler lanes.
fn builtin_registry() -> Result<InstrumentRegistry, EngineError> {
    InstrumentRegistry::with_builtin_profiles(BUILTIN_REGISTRY_GENERATION).map_err(|error| {
        rejected(
            "governed-profile",
            &format!("builtin profile registry is unavailable: {error}"),
        )
    })
}

/// Projects one evidence state to its report pair.
fn project_evidence(evidence: &StageEvidence) -> (&'static str, String) {
    match evidence {
        StageEvidence::Retained { artifact, byte_len } => {
            ("retained", format!("{}:{byte_len}", artifact.as_str()))
        }
        StageEvidence::Omitted { reason } => ("omitted", reason.clone()),
        StageEvidence::Missing { reason } => ("missing", reason.clone()),
    }
}

/// Persists one per-stage run record and projects its report.
fn persist_stage_report(
    blob_store: Option<&BlobStore>,
    profile: &str,
    revision: u64,
    planned: &eliot_instrument_runner::PlannedStage,
    run: &InstrumentRun,
) -> Result<GovernedStageReport, EngineError> {
    let (evidence_state, evidence_detail) = project_evidence(&run.evidence);
    let record = serde_json::json!({
        "schema_version": GOVERNED_RUN_RECORD_SCHEMA,
        "profile": profile,
        "revision": revision,
        "stage_id": run.stage.stage_id,
        "spec": planned.stage.spec.as_str(),
        "kind": format!("{:?}", planned.stage.kind),
        "required": planned.stage.required,
        "external": planned.stage.external,
        "depends_on": planned.stage.depends_on,
        "plane": format!("{:?}", run.plane),
        "testd_dispatchable": run.testd_dispatchable,
        "execution": format!("{:?}", run.execution),
        "evidence_state": evidence_state,
        "evidence_detail": evidence_detail,
        "executable_digest": run.executable_digest,
        "operation_id": run.stage.operation_id,
    });
    let run_blob = match blob_store {
        Some(store) => Some(store.put_bytes(&serde_json::to_vec(&record)?)?),
        None => None,
    };
    Ok(GovernedStageReport {
        stage_id: run.stage.stage_id.clone(),
        spec: planned.stage.spec.as_str().to_owned(),
        kind: format!("{:?}", planned.stage.kind),
        required: planned.stage.required,
        external: planned.stage.external,
        depends_on: planned.stage.depends_on.clone(),
        plane: format!("{:?}", run.plane),
        testd_dispatchable: run.testd_dispatchable,
        execution: format!("{:?}", run.execution),
        evidence_state: evidence_state.to_owned(),
        evidence_detail,
        executable_digest: run.executable_digest.clone(),
        operation_id: run.stage.operation_id.clone(),
        run_blob,
    })
}

/// Persists the aggregate record over the per-stage handles.
fn persist_aggregate_record(
    blob_store: Option<&BlobStore>,
    plan: &StagePlan,
    aggregate: &ProfileAggregate,
    stages: &[GovernedStageReport],
) -> Result<Option<BlobRef>, EngineError> {
    let Some(store) = blob_store else {
        return Ok(None);
    };
    let stage_blobs = stages
        .iter()
        .map(|stage| {
            serde_json::json!({
                "stage_id": stage.stage_id,
                "evidence_state": stage.evidence_state,
                "run_blob": stage.run_blob,
            })
        })
        .collect::<Vec<_>>();
    let record = serde_json::json!({
        "schema_version": GOVERNED_AGGREGATE_RECORD_SCHEMA,
        "profile": plan.profile,
        "revision": plan.revision,
        "profile_digest": plan.profile_digest,
        "dag_digest": plan.dag_digest,
        "aggregate_digest": aggregate.aggregate_digest,
        "aggregate_status": format!("{:?}", aggregate.status),
        "success": aggregate.is_success(),
        "observed_runs": aggregate.runs.iter().filter(|run| !run.evidence.is_missing()).count(),
        "missing_proof": NO_LAUNCH_PROVISIONS,
        "stage_blobs": stage_blobs,
    });
    Ok(Some(store.put_bytes(&serde_json::to_vec(&record)?)?))
}
