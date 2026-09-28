//! Governed instrument profile execution reporting (issue #1813).
//!
//! This edge serves the two verify entries that accept a profile name
//! (`verify run`/`verify plan` locally and `eliot_verify_plan` over MCP).
//! A governed name is RESOLVED first through the single
//! [`ProfileCompiler`]'s [`ProfileCompiler::resolve_admitted`], so the exact
//! admitted revision is bound to the caller-admitted target layout,
//! [`WorkScope`], and environment before anything is planned. The
//! [`ResolvedProfile`] is then expanded to its deterministic
//! [`StagePlan`](eliot_instrument_runner::StagePlan) and assembled into the
//! total [`ProfileAggregate`](eliot_instrument_runner::ProfileAggregate) over
//! the observed runs supplied by the executing composition root. The verify
//! entries carry no stage launcher provisions, so
//! [`GovernedProfileService::describe_execution`] assembles over zero
//! observed runs and every stage becomes an explicit missing proof instead
//! of a launch; [`GovernedProfileService::describe_execution_with_runs`]
//! assembles over caller-observed runs once the W4 execution lane produces
//! them. The resolution is not decoration: the resolved revision, stage DAG,
//! and resolution digest are the only source of the planned stages and the
//! persisted per-stage and aggregate records. One run record per stage plus
//! the aggregate record persist to the configured
//! [`BlobStore`](eliot_store::BlobStore); the returned handles are
//! content-addressed, so both entries observe the identical bytes.
//!
//! Every planned stage is also classified through the single composed
//! provider-dispatch closure
//! ([`compose_provider_dispatch`](eliot_instrument_runner::compose_provider_dispatch)):
//! exactly-one-entry resolution, generation and fingerprint freshness,
//! host support, then Testd admission behind the test execution plane, by
//! admitted identity only. Classification without execution provisions, so
//! no invocation authority material is ever fabricated here.
//!
//! No process is launched here and no task is declared complete: execution
//! provisions (executor, request port, evidence sink) and finish authority
//! belong to the Kernel/testd/Governor composition roots. A non-successful
//! aggregate fails closed through
//! [`GovernedProfileService::enforce_success`].

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_instrument_runner::profile::{
    AdmittedProfile, InstrumentRegistry, ProfileCompiler, ResolvedProfile, StageEnvironment,
    TargetLayout, WorkScope,
};
use eliot_instrument_runner::profile_run::{
    InstrumentRun, ProfileAggregate, StageEvidence, StageOrchestrator, StagePlan,
};
use eliot_instrument_runner::registry::{InvalidationSet, ProviderRegistry};
use eliot_instrument_runner::{
    AvailabilityInputs, ProviderDispatch, ProviderDisposition, compose_provider_dispatch,
    host_platform,
};
use eliot_store::BlobStore;
use eliot_types::BlobRef;
use serde::Serialize;
use std::num::NonZeroU64;

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
/// Authority epoch sequence this edge admits its own lineage at.
///
/// The contract genesis sequence (`EpochTransition::genesis` pins sequence one
/// as the first authority epoch of a lineage): the verify entries start an
/// authority lineage for the run instead of inheriting a Kernel epoch they were
/// never granted, and the sequence is never advanced.
const AUTHORITY_GENESIS_SEQUENCE: NonZeroU64 = NonZeroU64::MIN;

/// Admitted execution inputs a verify entry supplies for one resolution.
///
/// These are the composing root's own values: real roots on disk, its real
/// authority lineage, the declared scope it verifies, and the environment class
/// its instrument specs declare. This edge only turns them into the resolver's
/// typed [`TargetLayout`], [`WorkScope`], and [`StageEnvironment`]; it never
/// substitutes a root, a scope, or an environment of its own, and a malformed
/// or colliding value fails closed instead of being repaired.
///
/// The lineage names the authority that admits this run, so the same
/// composition root always resolves against the same fence. The epoch sequence
/// and resource generation are the contract genesis values: this edge starts an
/// authority lineage for the run rather than inheriting a Kernel epoch it was
/// never granted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileResolutionRequest {
    /// Admitted source root; the stage working directory.
    pub source_root: String,
    /// Admitted external build target root.
    pub target_root: String,
    /// Admitted cache root.
    pub cache_root: String,
    /// Authority lineage of the admitted state fence, as its UUID text.
    pub authority_lineage: String,
    /// Declared scope used for coverage and freshness.
    pub declared_scope: String,
    /// Environment class the instrument specs declare for their stages.
    pub environment_class: String,
}

impl ProfileResolutionRequest {
    /// Binds the admitted roots, authority lineage, scope, and environment.
    #[must_use]
    pub const fn new(
        source_root: String,
        target_root: String,
        cache_root: String,
        authority_lineage: String,
        declared_scope: String,
        environment_class: String,
    ) -> Self {
        Self {
            source_root,
            target_root,
            cache_root,
            authority_lineage,
            declared_scope,
            environment_class,
        }
    }

    /// Turns the admitted inputs into the resolver's typed bindings.
    ///
    /// The fence binds the caller's own lineage at the contract genesis epoch
    /// and generation, so the admitted authority is a real lineage identity
    /// rather than a synthesized constant, and the environment material attested
    /// to the resolver is the exact admitted class plus the three admitted
    /// roots, so the environment digest changes whenever the layout does.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the admitted lineage cannot form an
    /// authority epoch, or when the resolver's typed layout, scope, or
    /// environment construction refuses the values.
    pub fn bindings(&self) -> Result<ProfileResolutionBindings, EngineError> {
        let lineage = EpochLineageId::new(self.authority_lineage.clone()).map_err(|error| {
            rejected(
                "governed-profile",
                &format!("admitted authority lineage is not a lineage id: {error}"),
            )
        })?;
        let layout = TargetLayout::new(
            self.source_root.clone(),
            self.target_root.clone(),
            self.cache_root.clone(),
        )
        .map_err(|error| {
            rejected(
                "governed-profile",
                &format!("admitted target layout is refused: {error}"),
            )
        })?;
        let scope = WorkScope::new(
            self.declared_scope.clone(),
            StateFence::new(
                EpochId::new(lineage, AUTHORITY_GENESIS_SEQUENCE).map_err(|error| {
                    rejected(
                        "governed-profile",
                        &format!("admitted authority epoch is invalid: {error}"),
                    )
                })?,
                ResourceGeneration::genesis(),
            ),
        )
        .map_err(|error| {
            rejected(
                "governed-profile",
                &format!("admitted workscope is refused: {error}"),
            )
        })?;
        let environment = StageEnvironment::attest(
            self.environment_class.clone(),
            &format!(
                "{}\0{}\0{}",
                self.source_root, self.target_root, self.cache_root
            ),
        )
        .map_err(|error| {
            rejected(
                "governed-profile",
                &format!("admitted environment is refused: {error}"),
            )
        })?;
        Ok(ProfileResolutionBindings::new(layout, scope, environment))
    }
}

/// Caller-admitted execution bindings for one profile resolution.
///
/// The composing root owns these values: the resolver only validates that the
/// admitted roots are absolute, distinct, and that the `WorkScope` fence
/// validates, so it can never substitute a root, scope, or environment of its
/// own. Bundling them keeps the resolution step a single required argument, so
/// no governed entry can plan a profile without a resolved binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileResolutionBindings {
    /// Admitted source, target, and cache roots.
    pub layout: TargetLayout,
    /// Admitted declared scope plus its state fence.
    pub scope: WorkScope,
    /// Admitted environment class and attested material digest.
    pub environment: StageEnvironment,
}

impl ProfileResolutionBindings {
    /// Binds the three admitted execution values for one resolution.
    #[must_use]
    pub const fn new(
        layout: TargetLayout,
        scope: WorkScope,
        environment: StageEnvironment,
    ) -> Self {
        Self {
            layout,
            scope,
            environment,
        }
    }
}

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
    /// Refusals name the exact closure cause, including
    /// `refused:unsupported-platform` when this host cannot run the entry.
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
    /// Pre-launch admission grant digest, when recorded for the run.
    pub grant_digest: Option<String>,
    /// Executor operation reference, bound at launch.
    pub operation_id: Option<String>,
    /// Canonical handle of the persisted run record, when a store was supplied.
    pub run_blob: Option<BlobRef>,
}

/// The resolved execution binding carried by a governed run.
///
/// These are the values the resolver admitted before the stage DAG was
/// expanded; they travel with the report so a reader can tell which layout,
/// scope, and environment the persisted records were produced under.
#[derive(Clone, Debug, Serialize)]
pub struct ResolvedBindingReport {
    /// Admitted source root; the stage working directory.
    pub source_root: String,
    /// Admitted external build target root.
    pub target_root: String,
    /// Admitted cache root.
    pub cache_root: String,
    /// Deterministic identity over the three admitted roots.
    pub layout_digest: String,
    /// Declared scope used for coverage and freshness.
    pub declared_scope: String,
    /// Deterministic identity over scope and fence material.
    pub scope_digest: String,
    /// Authority epoch of the admitted state fence.
    pub authority_epoch: String,
    /// Resource generation of the admitted state fence.
    pub resource_generation: u64,
    /// Environment class the stages resolve under.
    pub environment_class: String,
    /// Attested environment material digest.
    pub environment_digest: String,
    /// Registry digest the resolution was validated against.
    pub registry_digest: String,
    /// Resolution digest over registry, definition, and bindings.
    pub resolution_digest: String,
}

/// Governed execution report over one resolved profile revision.
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
    /// Resolved execution binding the run was planned under.
    pub resolution: ResolvedBindingReport,
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

    /// Describes one governed profile execution: resolve, plan, aggregate,
    /// persist.
    ///
    /// The profile name is RESOLVED through
    /// [`ProfileCompiler::resolve_admitted`], so the exact admitted revision is
    /// bound to the caller-admitted layout, `WorkScope`, and environment before
    /// planning; a refused binding fails closed here. The plan is expanded from
    /// the resolved stage DAG, and the aggregate assembles over zero observed
    /// runs, so every stage without execution becomes an explicit missing
    /// proof. One run record per stage plus the aggregate record persist
    /// through `blob_store` when supplied, and the returned report carries the
    /// content-addressed handles together with the resolved binding. Identical
    /// input always yields identical persisted bytes on every entry point.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the builtin registry is unavailable, the
    /// name quarantines instead of governing, a resolution binding is refused,
    /// or blob persistence fails.
    pub fn describe_execution(
        &self,
        name: &str,
        bindings: &ProfileResolutionBindings,
        blob_store: Option<&BlobStore>,
    ) -> Result<GovernedProfileReport, EngineError> {
        self.describe_execution_with_runs(name, bindings, Vec::new(), blob_store)
    }

    /// Describes one governed profile execution over caller-observed runs.
    ///
    /// This is the [`GovernedProfileService::describe_execution`] shape for
    /// the W4 execution lane (issue #1813 A1): the name is resolved through
    /// [`ProfileCompiler::resolve_admitted`] against the caller-admitted
    /// bindings before planning, and observed
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
    /// name quarantines instead of governing, a resolution binding is refused,
    /// or blob persistence fails.
    pub fn describe_execution_with_runs(
        &self,
        name: &str,
        bindings: &ProfileResolutionBindings,
        runs: Vec<InstrumentRun>,
        blob_store: Option<&BlobStore>,
    ) -> Result<GovernedProfileReport, EngineError> {
        let registry = builtin_registry()?;
        let resolved = ProfileCompiler::new(&registry)
            .resolve_admitted(
                name,
                bindings.layout.clone(),
                bindings.scope.clone(),
                bindings.environment.clone(),
            )
            .map_err(|error| {
                rejected(
                    "governed-profile",
                    &format!("profile '{name}' could not be resolved: {error}"),
                )
            })?;
        let admitted = admitted_from_resolution(&resolved).map_err(|reason| {
            rejected(
                "governed-profile",
                &format!("resolved profile '{name}' did not compile: {reason}"),
            )
        })?;
        let plan = StageOrchestrator::plan(&admitted);
        require_resolved_stages(&resolved, &plan).map_err(|reason| {
            rejected(
                "governed-profile",
                &format!("resolved profile '{name}' did not plan: {reason}"),
            )
        })?;
        let aggregate = ProfileAggregate::assemble(&plan, runs);
        let fingerprints = unattested_fingerprints();
        let normative_pair_digest = String::new();
        let providers = ProviderRegistry::ready(
            BUILTIN_REGISTRY_GENERATION,
            normative_pair_digest.clone(),
            &fingerprints,
        )
        .map_err(|error| {
            rejected(
                "governed-profile",
                &format!("ready provider registry is unavailable: {error}"),
            )
        })?;
        let dispatch_inputs = AvailabilityInputs {
            generation: BUILTIN_REGISTRY_GENERATION,
            normative_pair_digest: &normative_pair_digest,
            fingerprints: &fingerprints,
            platform: host_platform(),
        };
        let mut stages = Vec::with_capacity(plan.stages.len());
        for (planned, run) in plan.stages.iter().zip(aggregate.runs.iter()) {
            let admission = admit_stage(&providers, planned, &dispatch_inputs);
            stages.push(persist_stage_report(
                blob_store, &resolved, &plan, planned, run, &admission,
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
        let aggregate_blob = persist_aggregate_record(
            blob_store,
            &resolved,
            &plan,
            &aggregate,
            &stages,
            missing_proof,
        )?;
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
            resolution: resolved_binding(&resolved),
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
                "governed profile '{}' revision {} resolved as {} but did not succeed: {}; {}",
                report.profile,
                report.revision,
                report.resolution.resolution_digest,
                report.aggregate_status,
                report.missing_proof,
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

/// Classifies one planned stage through the composed dispatch closure
/// (issue #1813 W4 describe path).
///
/// The stage spec and class run the single
/// [`compose_provider_dispatch`](eliot_instrument_runner::compose_provider_dispatch)
/// closure — exactly-one-entry resolution, generation and fingerprint
/// freshness, host support, then Testd admission — by admitted identity
/// only, without any invocation authority material: no State Fence,
/// session, or lease is fabricated, and no stage launches on this decision.
/// Every refusal keeps the stage inside the declared denominator under its
/// typed disposition. Callers match on the typed variants, never on message
/// text.
fn admit_stage(
    providers: &ProviderRegistry,
    planned: &eliot_instrument_runner::PlannedStage,
    inputs: &AvailabilityInputs<'_>,
) -> StageAdmission {
    match compose_provider_dispatch(providers, &planned.stage.spec, planned.stage.kind, inputs) {
        ProviderDispatch::Dispatch { entry } => StageAdmission {
            adapter: Some(entry.adapter.clone()),
            decision: "admitted".to_owned(),
        },
        ProviderDispatch::Refused { disposition } => {
            let (adapter, reason) = match disposition {
                // Unreachable through the closure: it never refuses as Ready.
                ProviderDisposition::Ready => (None, "admitted".to_owned()),
                ProviderDisposition::Unmapped => (None, "unresolved:missing".to_owned()),
                ProviderDisposition::Ambiguous { .. } => (None, "unresolved:ambiguous".to_owned()),
                ProviderDisposition::Stale { .. } => (None, "unresolved:stale".to_owned()),
                ProviderDisposition::Unsupported { .. } => {
                    (None, "unresolved:unsupported".to_owned())
                }
                ProviderDisposition::UnsupportedByTestd { adapter, .. } => {
                    (Some(adapter), "refused:unsupported-by-testd".to_owned())
                }
                ProviderDisposition::UnsupportedPlatform { .. } => {
                    (None, "refused:unsupported-platform".to_owned())
                }
                ProviderDisposition::Unavailable { .. } => {
                    (None, "unresolved:unavailable".to_owned())
                }
            };
            StageAdmission {
                adapter,
                decision: reason,
            }
        }
    }
}

/// Empty fingerprints for static provider classification.
///
/// The describe path classifies through the composed dispatch closure
/// against the ready registry it just constructed from these same inputs,
/// so the closure's freshness step passes self-consistently by
/// construction: empty slots attest no machine state and make no freshness
/// claim beyond the registry handle itself. Launching callers must supply
/// caller-attested fingerprints with
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

/// Recovers the compiled admission from one resolution.
///
/// The resolution is the governing input, so its name and exact revision are
/// recompiled through the single compiler and the definition digests are
/// compared: a resolution that does not describe the admitted definition is
/// refused instead of being planned.
fn admitted_from_resolution(resolved: &ResolvedProfile) -> Result<AdmittedProfile, String> {
    let registry = InstrumentRegistry::with_builtin_profiles(resolved.registry_generation)
        .map_err(|error| format!("builtin profile registry is unavailable: {error}"))?;
    let compiled = ProfileCompiler::new(&registry)
        .compile_exact(&resolved.name, resolved.revision)
        .map_err(|error| format!("exact revision is not admitted: {error}"))?;
    if compiled.profile_digest != resolved.profile_digest
        || compiled.dag_digest != resolved.dag_digest
    {
        return Err("the resolved definition digests differ from the admitted profile".to_owned());
    }
    Ok(compiled)
}

/// Refuses a plan that does not expand the resolved stage DAG exactly.
///
/// The resolver is the owner of the declared stage DAG, so the plan must carry
/// the same stage identities in the same topological order, and the persisted
/// run records may only ever be written for those stages.
fn require_resolved_stages(resolved: &ResolvedProfile, plan: &StagePlan) -> Result<(), String> {
    if plan.profile != resolved.name || plan.revision != resolved.revision {
        return Err("the plan does not carry the resolved profile identity".to_owned());
    }
    if plan.stages.len() != resolved.stages.len() {
        return Err("the plan does not expand every resolved stage".to_owned());
    }
    for (planned, stage) in plan.stages.iter().zip(resolved.stages.iter()) {
        if planned.stage.stage_id != stage.stage_id
            || planned.stage.spec != stage.spec
            || planned.stage.kind != stage.kind
            || planned.stage.required != stage.required
            || planned.stage.external != stage.external
            || planned.stage.depends_on != stage.depends_on
        {
            return Err(format!(
                "planned stage '{}' does not match the resolved stage '{}'",
                planned.stage.stage_id, stage.stage_id
            ));
        }
    }
    Ok(())
}

/// Projects the resolved execution binding into its report form.
fn resolved_binding(resolved: &ResolvedProfile) -> ResolvedBindingReport {
    ResolvedBindingReport {
        source_root: resolved.layout.source_root.clone(),
        target_root: resolved.layout.target_root.clone(),
        cache_root: resolved.layout.cache_root.clone(),
        layout_digest: resolved.layout.digest(),
        declared_scope: resolved.scope.declared_scope.clone(),
        scope_digest: resolved.scope.digest(),
        authority_epoch: format!("{:?}", resolved.scope.fence.authority_epoch),
        resource_generation: resolved.scope.fence.resource_generation.value(),
        environment_class: resolved.environment.class.clone(),
        environment_digest: resolved.environment.digest.clone(),
        registry_digest: resolved.registry_digest.clone(),
        resolution_digest: resolved.resolution_digest.clone(),
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
///
/// The record is bound to the resolution digest, so a record is never readable
/// as evidence of a run under different admitted roots, scope, or environment.
fn persist_stage_report(
    blob_store: Option<&BlobStore>,
    resolved: &ResolvedProfile,
    plan: &StagePlan,
    planned: &eliot_instrument_runner::PlannedStage,
    run: &InstrumentRun,
    admission: &StageAdmission,
) -> Result<GovernedStageReport, EngineError> {
    let (evidence_state, evidence_detail) = project_evidence(&run.evidence);
    let record = serde_json::json!({
        "schema_version": GOVERNED_RUN_RECORD_SCHEMA,
        "profile": plan.profile,
        "revision": plan.revision,
        "resolution_digest": resolved.resolution_digest,
        "source_root": resolved.layout.source_root,
        "target_root": resolved.layout.target_root,
        "cache_root": resolved.layout.cache_root,
        "declared_scope": resolved.scope.declared_scope,
        "authority_epoch": format!("{:?}", resolved.scope.fence.authority_epoch),
        "resource_generation": resolved.scope.fence.resource_generation.value(),
        "environment_class": resolved.environment.class,
        "environment_digest": resolved.environment.digest,
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
        "grant_digest": run.grant_digest,
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
        grant_digest: run.grant_digest.clone(),
        operation_id: run.stage.operation_id.clone(),
        run_blob,
    })
}

/// Persists the aggregate record over the per-stage handles.
fn persist_aggregate_record(
    blob_store: Option<&BlobStore>,
    resolved: &ResolvedProfile,
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
        "registry_digest": resolved.registry_digest,
        "resolution_digest": resolved.resolution_digest,
        "layout_digest": resolved.layout.digest(),
        "scope_digest": resolved.scope.digest(),
        "environment_digest": resolved.environment.digest,
        "aggregate_digest": aggregate.aggregate_digest,
        "aggregate_status": format!("{:?}", aggregate.status),
        "success": aggregate.is_success(),
        "observed_runs": aggregate.runs.iter().filter(|run| !run.evidence.is_missing()).count(),
        "missing_proof": missing_proof,
        "stage_blobs": stage_blobs,
    });
    Ok(Some(store.put_bytes(&serde_json::to_vec(&record)?)?))
}
