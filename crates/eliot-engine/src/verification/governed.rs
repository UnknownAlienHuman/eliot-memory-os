//! Governed instrument profile execution reporting (issue #1813).
//!
//! This edge serves the two verify entries that accept a profile name
//! (`verify run`/`verify plan` locally and `eliot_verify_plan` over MCP).
//! A governed name compiles through the single [`ProfileCompiler`], expands
//! to its deterministic [`StagePlan`](eliot_instrument_runner::StagePlan),
//! and assembles the total
//! [`ProfileAggregate`](eliot_instrument_runner::ProfileAggregate) over the
//! observed runs supplied by the executing composition root. The verify
//! entries carry no stage launcher provisions, so
//! [`GovernedProfileService::describe_execution`] assembles over zero
//! observed runs and every stage becomes an explicit missing proof instead
//! of a launch; [`GovernedProfileService::describe_execution_with_runs`]
//! assembles over caller-observed runs once the W4 execution lane produces
//! them. One run record per stage plus the aggregate record persist to the
//! configured [`BlobStore`](eliot_store::BlobStore); the returned handles are
//! content-addressed, so both entries observe the identical bytes.
//!
//! Every planned stage is also resolved through the ready provider registry
//! and admitted behind the test execution plane by admitted identity only
//! ([`ProviderRegistry::resolve_parts`](eliot_instrument_runner::registry::ProviderRegistry::resolve_parts)
//! plus [`TestdPlaneAdmission::admit_parts`](eliot_instrument_runner::TestdPlaneAdmission::admit_parts)):
//! classification without execution provisions, so no invocation authority
//! material is ever fabricated here.
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
use eliot_instrument_runner::registry::{InvalidationSet, ProviderRegistry};
use eliot_instrument_runner::{RegistryError, TestdPlaneAdmission, TestdPortError};
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
/// Exact proof recorded when observed runs were supplied: supplied stages
/// carry their recorded evidence, and stages without runs stay explicit
/// missing proofs.
const OBSERVED_RUNS_PRESENT: &str = "observed runs were supplied by the executing composition root; stages without a run remain explicit missing proofs";

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
    /// Registry-selected adapter identity, when the stage spec resolves.
    pub provider_adapter: Option<String>,
    /// Testd admission decision over the admitted stage identity:
    /// `admitted`, `refused:<typed reason>`, or `unresolved:<typed reason>`.
    /// Classification only; no stage launches on this decision.
    pub testd_admission: String,
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
        self.describe_execution_with_runs(name, Vec::new(), blob_store)
    }

    /// Describes one governed profile execution over caller-observed runs.
    ///
    /// This is the [`GovernedProfileService::describe_execution`] shape for
    /// the W4 execution lane (issue #1813 A1): observed
    /// [`InstrumentRun`](eliot_instrument_runner::InstrumentRun) records
    /// produced by the executing composition root assemble into the aggregate
    /// with their executable identity, bound operation, and raw evidence
    /// handle, so executable digests, governed stage receipts, and raw
    /// evidence handles become producible instead of structurally absent.
    /// Runs are matched to declared stages by the full durable stage
    /// identity; foreign runs never satisfy the plan, and declared stages
    /// without a run stay explicit missing proofs.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the builtin registry is unavailable, the
    /// name quarantines instead of governing, or blob persistence fails.
    pub fn describe_execution_with_runs(
        &self,
        name: &str,
        runs: Vec<InstrumentRun>,
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
        let aggregate = ProfileAggregate::assemble(&plan, runs);
        let providers = ProviderRegistry::ready(
            BUILTIN_REGISTRY_GENERATION,
            String::new(),
            &unattested_fingerprints(),
        )
        .map_err(|error| {
            rejected(
                "governed-profile",
                &format!("ready provider registry is unavailable: {error}"),
            )
        })?;
        let mut stages = Vec::with_capacity(plan.stages.len());
        for (planned, run) in plan.stages.iter().zip(aggregate.runs.iter()) {
            let admission = admit_stage(&providers, planned);
            stages.push(persist_stage_report(
                blob_store,
                &plan.profile,
                plan.revision,
                planned,
                run,
                &admission,
            )?);
        }
        let observed_runs = aggregate
            .runs
            .iter()
            .filter(|run| !run.evidence.is_missing())
            .count();
        let missing_proof = if observed_runs == 0 {
            NO_LAUNCH_PROVISIONS
        } else {
            OBSERVED_RUNS_PRESENT
        };
        let aggregate_blob =
            persist_aggregate_record(blob_store, &plan, &aggregate, &stages, missing_proof)?;
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
            missing_proof: missing_proof.to_owned(),
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

/// Per-stage provider resolution plus testd admission (classification only).
struct StageAdmission {
    /// Registry-selected adapter identity, when the stage spec resolves.
    adapter: Option<String>,
    /// Admission decision: `admitted`, `refused:<typed reason>`, or
    /// `unresolved:<typed reason>`.
    decision: String,
}

/// Admits one planned stage by admitted identity only (issue #1813 W4).
///
/// The stage spec and class resolve through the ready provider registry and
/// admit behind the test execution plane without any invocation authority
/// material: no State Fence, session, or lease is fabricated, and no stage
/// launches on this decision. Callers match on the typed variants, never on
/// message text.
fn admit_stage(
    providers: &ProviderRegistry,
    planned: &eliot_instrument_runner::PlannedStage,
) -> StageAdmission {
    match providers.resolve_parts(&planned.stage.spec, planned.stage.kind) {
        Ok(entry) => {
            let adapter = entry.adapter.clone();
            match TestdPlaneAdmission::admit_parts(&planned.stage.spec, planned.stage.kind, entry) {
                Ok(_) => StageAdmission {
                    adapter: Some(adapter),
                    decision: "admitted".to_owned(),
                },
                Err(error) => StageAdmission {
                    adapter: Some(adapter),
                    decision: format!("refused:{}", testd_port_error_name(&error)),
                },
            }
        }
        Err(error) => StageAdmission {
            adapter: None,
            decision: format!("unresolved:{}", registry_error_name(&error)),
        },
    }
}

/// Names one registry failure variant for the stage admission record.
fn registry_error_name(error: &RegistryError) -> &'static str {
    match error {
        RegistryError::Missing { .. } => "missing",
        RegistryError::Duplicate { .. } => "duplicate",
        RegistryError::Stale { .. } => "stale",
        RegistryError::Ambiguous { .. } => "ambiguous",
        RegistryError::Unsupported { .. } => "unsupported",
        RegistryError::Contract(_) => "contract",
        RegistryError::UnresolvedExecutable { .. } => "unresolved-executable",
        RegistryError::ExecutableMismatch { .. } => "executable-mismatch",
    }
}

/// Names one testd admission failure for the stage admission record.
fn testd_port_error_name(error: &TestdPortError) -> String {
    match error {
        TestdPortError::UnsupportedByTestd { .. } => "unsupported-by-testd".to_owned(),
        TestdPortError::Registry(error) => format!("registry-{}", registry_error_name(error)),
    }
}

/// Empty fingerprints for static provider resolution.
///
/// The describe path performs classification only via
/// [`ProviderRegistry::resolve_parts`](eliot_instrument_runner::registry::ProviderRegistry::resolve_parts),
/// which never consults fingerprints: empty slots attest nothing and make no
/// freshness claim. Launching callers must supply caller-attested
/// fingerprints with
/// [`ProviderRegistry::resolve_current`](eliot_instrument_runner::registry::ProviderRegistry::resolve_current)
/// instead.
fn unattested_fingerprints() -> InvalidationSet {
    InvalidationSet {
        source: String::new(),
        lock: String::new(),
        toolchain: String::new(),
        env: String::new(),
        exe: String::new(),
        profile: String::new(),
        parser: String::new(),
    }
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
    admission: &StageAdmission,
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
        "provider_adapter": admission.adapter,
        "testd_admission": admission.decision,
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
        provider_adapter: admission.adapter.clone(),
        testd_admission: admission.decision.clone(),
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
    missing_proof: &str,
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
                "testd_admission": stage.testd_admission,
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
        "missing_proof": missing_proof,
        "stage_blobs": stage_blobs,
    });
    Ok(Some(store.put_bytes(&serde_json::to_vec(&record)?)?))
}
