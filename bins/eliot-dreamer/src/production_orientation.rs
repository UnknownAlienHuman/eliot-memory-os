//! Runtime-owned production Orientation carrier and typed composer (issue #2901).
//!
//! Production Orientation composes only from one versioned
//! [`ProductionOrientationInputs`] carrier: the admitted job/bundle/candidate,
//! the mandatory CC-002 model-route request/outcome and CC-004 canonical
//! projection set, every mandatory stage-owner record, and the shared
//! operation/task/scope/fence identity with deadline/cancellation. Missing
//! prerequisites yield a typed blocked [`OrientationPulseResult`](crate::OrientationPulseResult),
//! never a packet.
//!
//! Production owner chain (frozen by this issue):
//!
//! | Responsibility | Actual runtime owner | Status |
//! |---|---|---|
//! | Construct/admit `ModelRouteRequest` | the owner supply channel ([`OrientationSupplySource`](crate::OrientationSupplySource)), which resolves it from admitted material | wired through [`resolve_production_inputs`] |
//! | Execute the admitted provider route, return `ModelRouteOutcome` | the same supply channel; provider text lives outside the dreamer binary | wired through [`resolve_production_inputs`] |
//! | Read/build the exact `CanonicalProjectionSet` from Governor/canonical owners | `eliot_governor::compose_canonical_projection_set`, supplied by the same channel | wired through [`resolve_production_inputs`] |
//! | Acquire each mandatory stage's owner input/receipt | the same supply channel, carrying each stage's owner-built record | wired through [`resolve_production_inputs`] |
//! | Invoke the pure composer | [`compose_production_result`] below (this module) | reachable: `dispatch_stage::dispatch_orientation` calls it on the resolved carrier |
//! | Publish the typed result | `dispatch_stage::dispatch_orientation` as `DreamResult::Orientation` | all three dispositions reachable |
//!
//! A missing adapter is implementation work, never substituted with local
//! data: the v1 hypothesis pair derived in dispatch cannot impersonate the
//! CC-002 outcome, empty projections are never synthesized, and no stage runs
//! from a caller-built lookalike. Smart stays pure: model calls, canonical
//! reads, retries, leases, policy/authority decisions, and persistence execute
//! in runtime/Governor adapters before composition; the composer receives
//! immutable admitted records and performs no external effects. Owner inputs
//! are acquired without holding any Dreamer composition mutex, and the
//! synchronous composer runs only on frozen records.
//!
//! Overall result rule: `Complete` requires every denominator member executed
//! under one coherent identity closure with both boundaries admitted and the
//! conflict output qualified; `Partial` carries the projected packet with the
//! conflict qualification outstanding (#2869/#2870); `Blocked` carries no
//! packet and names every missing, incoherent, or refused prerequisite. The
//! carrier-mandatory design admits no missing-stage partial: a complete
//! carrier either executes every stage or records the refusal as blocked.

use std::time::{SystemTime, UNIX_EPOCH};

use eliot_context_contracts::{CanonicalProjectionSet, ContextError, SerializedContextMeasurement};
use eliot_contracts::StateFence;
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::{
    DreamInputBundle, JobClass, ModelRouteDisposition, ModelRouteOutcome, ModelRouteRequest,
    ValidatedCandidate, bundle_digest_of,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, CurrentEpistemicPositionHandle, OrientationDisposition,
    OrientationError, OrientationPolicy,
    projection::{OrientationPacketCandidate, build_projection},
};
use eliot_dreamer_probe_plan::ProbePlanParams;
use eliot_epistemic::PositionRequest;

use crate::pulse::{
    CEILING_BLOCKED, CEILING_CANDIDATE_ONLY, CONFLICT_OUTPUT_QUALIFIED, CandidateStage,
    ClassificationStage, ConflictStage, CueActivationStage, MANDATORY_DENOMINATOR, PulseError,
    PulseStage, PulseStageId, RivalStage, UnderstandingStage, check_model_boundary,
    check_projection_boundary, fences_compatible, output_digest, run_candidate_stage,
    run_classification_stage, run_conflict_stage, run_cue_stage, run_epistemic_stage,
    run_grounding_stage, run_probe_stage, run_rival_stage, run_understanding_stage,
};
use crate::{
    DreamJobInput, KernelJobAdmission, ORIENTATION_PULSE_RESULT_SCHEMA_VERSION,
    OrientationAdmittedPrefix, OrientationBoundaryRecord, OrientationPulseResult,
    OrientationStageDisposition, OrientationStageRecord,
};

/// Exact schema version accepted by [`ProductionOrientationInputs`].
pub(crate) const PRODUCTION_ORIENTATION_INPUTS_SCHEMA_VERSION: u32 = 1;
/// Blocked reason when the CC-002 outcome is absent.
pub(crate) const CC002_MISSING: &str =
    "production orientation requires an admitted model-route outcome";
/// Blocked reason when the CC-004 projection set is absent.
pub(crate) const CC004_MISSING: &str = "production orientation requires a canonical projection set";
/// Blocked reason naming the absent Governor supply channel.
pub(crate) const ORIENTATION_SUPPLY_MISSING: &str = "governor orientation supply channel absent";
/// Blocked reason when the admitted outcome is malformed.
pub(crate) const MODEL_OUTCOME_MALFORMED: &str = "admitted model-route outcome is malformed";
/// Blocked reason when the admitted outcome is cancelled.
pub(crate) const MODEL_OUTCOME_CANCELLED: &str = "admitted model-route outcome is cancelled";
/// Blocked reason when the admitted outcome timed out.
pub(crate) const MODEL_OUTCOME_TIMEOUT: &str = "admitted model-route outcome timed out";
/// Partial qualification while the conflict proof gap is open.
pub(crate) const CONFLICT_UNQUALIFIED: &str = "conflict output unqualified until #2869/#2870";
/// Fallback commitment when canonical serialization fails.
const DIGEST_UNAVAILABLE: &str = "digest unavailable";
/// Missing-owner identity for the CC-002 runtime owner.
const OWNER_MODEL_ROUTE: &str = "model-route runtime owner";
/// Missing-owner identity for the CC-004 projection owner.
const OWNER_PROJECTIONS: &str = "governor canonical projection owner";

/// Immutable route-measurement function supplied with the understanding record.
///
/// A plain `fn` item keeps the carrier non-generic: the Governor channel
/// supplies the measurement with the admitted set, and the composer invokes it
/// at most once through the understanding owner entry.
type MeasureFn = fn(&[u8]) -> Result<SerializedContextMeasurement, ContextError>;

/// Versioned runtime-owned production carrier: everything one complete
/// Orientation pulse must consume, with no optional mandatory member.
///
/// Every reference borrows caller-owned admitted records; nothing is
/// JSON-round-tripped and no missing member is defaulted. The assembler
/// declares the shared operation/task/scope/fence identity explicitly, and
/// [`compose_production_result`] re-proves every member against it before any
/// stage runs. Budget travels on the admitted job; deadline and cancellation
/// travel as scalars observed before composition.
pub(crate) struct ProductionOrientationInputs<'a> {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Admitted Orientation job with frame, evidence, and denominator.
    pub admitted_job: &'a AdmittedOrientationJob,
    /// Bounded bundle the pulse binds.
    pub bundle: &'a DreamInputBundle,
    /// Receipt-bound v1 validated candidate.
    pub validated_candidate: &'a ValidatedCandidate,
    /// Sealed orientation policy.
    pub policy: &'a OrientationPolicy,
    /// CC-002 admitted model-route request (denominator, timeout, privacy).
    pub model_request: &'a ModelRouteRequest,
    /// CC-002 admitted model-route outcome (mandatory boundary).
    pub model_outcome: &'a ModelRouteOutcome,
    /// CC-004 canonical projection set (mandatory boundary).
    pub projections: &'a CanonicalProjectionSet,
    /// Governor-resolved epistemic-position handles for the packet.
    pub cep_handles: &'a [CurrentEpistemicPositionHandle],
    /// Classification stage inputs.
    pub classification: ClassificationStage<'a>,
    /// Cue-activation stage inputs.
    pub cue_activation: CueActivationStage<'a>,
    /// Epistemic resolution request over admitted records.
    pub epistemic: &'a PositionRequest,
    /// Understanding stage inputs with the route measurement.
    pub understanding: UnderstandingStage<'a, MeasureFn>,
    /// Claim-grounding request (cloned; the owner takes owned input).
    pub grounding: &'a GroundingRequest,
    /// Rival-structuring stage inputs.
    pub rivals: RivalStage<'a>,
    /// Conflict-analysis stage inputs.
    pub conflict: ConflictStage<'a>,
    /// Discriminative probe-plan parameters.
    pub probes: ProbePlanParams<'a>,
    /// Context-candidate stage inputs.
    pub candidates: CandidateStage<'a>,
    /// Declared shared operation identity.
    pub operation_id: String,
    /// Declared shared task identity.
    pub task_id: String,
    /// Declared shared scope identity.
    pub scope_id: String,
    /// Declared shared state fence.
    pub state_fence: StateFence,
    /// Wall-clock deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// True when cancellation was observed before composition.
    pub cancelled: bool,
}

/// Governor-resolved owner records for one admitted Orientation pulse.
///
/// The carrier's mandatory members are owner values, not derivations: the
/// CC-002 outcome carries provider text and observed usage that live outside
/// this binary, the CC-004 set is composed by
/// `eliot_governor::compose_canonical_projection_set`, and every stage input
/// is an owner-built record. This is the one shape that carries all of them
/// across the process boundary, mirroring the Curation
/// [`CurationExecutionCarrier`](crate::dispatch_stage::CurationExecutionCarrier)
/// exactly: an owned value the source hands out per admission, which the
/// composer then borrows for the life of one synchronous composition.
///
/// Identity is not carried here. `operation_id`, `task_id`, `scope_id`, and
/// `state_fence` are read from the admitted job, which
/// [`validate_identity_closure`] already proves equal to the bundle, the frame,
/// and the semantic job, so a second copy in the supply could only disagree.
pub(crate) struct OrientationSupply<'a> {
    /// CC-002 admitted model-route request (denominator, timeout, privacy).
    pub model_request: ModelRouteRequest,
    /// CC-002 admitted model-route outcome (mandatory boundary).
    pub model_outcome: ModelRouteOutcome,
    /// CC-004 canonical projection set (mandatory boundary).
    pub projections: CanonicalProjectionSet,
    /// Governor-resolved epistemic-position handles for the packet.
    pub cep_handles: Vec<CurrentEpistemicPositionHandle>,
    /// Classification stage inputs.
    pub classification: ClassificationStage<'a>,
    /// Cue-activation stage inputs.
    pub cue_activation: CueActivationStage<'a>,
    /// Epistemic resolution request over admitted records.
    pub epistemic: PositionRequest,
    /// Understanding stage inputs with the route measurement.
    pub understanding: UnderstandingStage<'a, MeasureFn>,
    /// Claim-grounding request (cloned; the owner takes owned input).
    pub grounding: GroundingRequest,
    /// Rival-structuring stage inputs.
    pub rivals: RivalStage<'a>,
    /// Conflict-analysis stage inputs.
    pub conflict: ConflictStage<'a>,
    /// Discriminative probe-plan parameters.
    pub probes: ProbePlanParams<'a>,
    /// Context-candidate stage inputs.
    pub candidates: CandidateStage<'a>,
    /// True when cancellation was observed by the owner before composition.
    pub cancelled: bool,
}

/// Resolves the production carrier from admitted dispatch artifacts plus the
/// owner supply.
///
/// The identity half (operation/task/scope/fence) is read from the admitted job
/// and the deadline from the Kernel admission, so it cannot drift from the
/// records it is re-proved against. Every other member is the owner value the
/// supply handed over verbatim: nothing here synthesizes an outcome, projects
/// an empty set, fills a usage receipt, or builds a lookalike stage record, so
/// a missing supply member is the typed blocked result rather than filler.
///
/// # Errors
///
/// Returns the typed blocked [`OrientationPulseResult`] naming the absent
/// boundaries and every stage owner when `supply` is [`None`].
pub(crate) fn resolve_production_inputs<'a>(
    admission: &'a KernelJobAdmission,
    admitted_job: &'a AdmittedOrientationJob,
    candidate: &'a ValidatedCandidate,
    bundle: &'a DreamInputBundle,
    policy: &'a OrientationPolicy,
    supply: Option<&'a OrientationSupply<'a>>,
) -> Result<ProductionOrientationInputs<'a>, Box<OrientationPulseResult>> {
    let Some(supply) = supply else {
        return Err(Box::new(missing_prerequisites_blocked(
            admission,
            admitted_job,
            candidate,
            bundle,
            policy,
        )));
    };
    let job = &admitted_job.job;
    Ok(ProductionOrientationInputs {
        schema_version: PRODUCTION_ORIENTATION_INPUTS_SCHEMA_VERSION,
        admitted_job,
        bundle,
        validated_candidate: candidate,
        policy,
        model_request: &supply.model_request,
        model_outcome: &supply.model_outcome,
        projections: &supply.projections,
        cep_handles: &supply.cep_handles,
        // Each stage input is copied out of the supply field by field: the
        // stage records are plain aggregates of references, so this borrows
        // the owner's records without moving or duplicating any of them.
        classification: ClassificationStage {
            input: supply.classification.input,
            context: supply.classification.context,
            policy: supply.classification.policy,
        },
        cue_activation: CueActivationStage {
            candidate: supply.cue_activation.candidate,
            request: supply.cue_activation.request,
            profile: supply.cue_activation.profile,
        },
        epistemic: &supply.epistemic,
        understanding: UnderstandingStage {
            admitted: supply.understanding.admitted,
            recipe: supply.understanding.recipe,
            quality: supply.understanding.quality.clone(),
            policy: supply.understanding.policy,
            measure: supply.understanding.measure,
        },
        grounding: &supply.grounding,
        rivals: RivalStage {
            bundle: supply.rivals.bundle,
            validated_draft: supply.rivals.validated_draft,
            current_position: supply.rivals.current_position,
            policy: supply.rivals.policy,
        },
        conflict: ConflictStage {
            item: supply.conflict.item,
            draft: supply.conflict.draft,
            grounded: supply.conflict.grounded,
            conflict_set: supply.conflict.conflict_set,
            supplements: supply.conflict.supplements,
            policy: supply.conflict.policy,
        },
        probes: ProbePlanParams {
            plan_id: supply.probes.plan_id.clone(),
            bundle: supply.probes.bundle,
            draft: supply.probes.draft,
            rivals: supply.probes.rivals,
            affordances: supply.probes.affordances,
            limits: supply.probes.limits,
            policy: supply.probes.policy,
        },
        candidates: CandidateStage {
            request: supply.candidates.request,
            recipe: supply.candidates.recipe,
            measurements: supply.candidates.measurements,
            attention_and_conflicts: supply.candidates.attention_and_conflicts,
            epistemic_position: supply.candidates.epistemic_position,
            cue_activation_result: supply.candidates.cue_activation_result,
            evidence: supply.candidates.evidence,
            policy: supply.candidates.policy,
        },
        operation_id: job.operation_id.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        state_fence: job.state_fence.clone(),
        deadline_unix_ms: admission.deadline_unix_ms,
        cancelled: supply.cancelled,
    })
}

/// Composes one typed production pulse from the versioned carrier.
///
/// Cancellation and deadline gate first (no owner work burns on a dead
/// pulse), then the identity closure, then the model-disposition gate, then
/// all nine stages with refusals collected into blocked records, and finally
/// the packet from the same joined closure. Cancellation, deadline expiry,
/// and packet-owner refusal surface as [`PulseError`]; missing, incoherent,
/// unusable, or refused prerequisites surface as a blocked result.
pub(crate) fn compose_production_result(
    inputs: ProductionOrientationInputs<'_>,
    semantic_job: &DreamJobInput,
) -> Result<OrientationPulseResult, PulseError> {
    if inputs.cancelled {
        return Err(PulseError::Cancelled);
    }
    check_carrier_deadline(inputs.deadline_unix_ms)?;
    if inputs.schema_version != PRODUCTION_ORIENTATION_INPUTS_SCHEMA_VERSION {
        return Err(PulseError::Boundary("production inputs version"));
    }
    let admitted = admitted_prefix(&inputs);
    if let Err(field) = validate_identity_closure(&inputs, semantic_job) {
        return Ok(closure_blocked(&inputs, &admitted, field));
    }
    if let Some(reason) = unusable_model_reason(inputs.model_outcome.disposition) {
        return Ok(unusable_model_blocked(&inputs, &admitted, reason));
    }
    let identity = BlockedIdentity::of(&inputs);
    let model_boundary = present_model_boundary(inputs.model_outcome);
    let projections_boundary = present_projections_boundary(inputs.projections);

    let mut records = Vec::with_capacity(MANDATORY_DENOMINATOR.members.len());
    let mut refused: Vec<String> = Vec::new();
    collect_ref_stages(&inputs, &mut records, &mut refused);
    collect_stage(
        &mut records,
        &mut refused,
        PulseStageId::Understanding,
        run_understanding_stage(Some(inputs.understanding)),
    );
    collect_stage(
        &mut records,
        &mut refused,
        PulseStageId::Probes,
        run_probe_stage(Some(inputs.probes)),
    );
    order_stage_records(&mut records);
    if !refused.is_empty() {
        return Ok(refused_stages_blocked(
            identity,
            admitted,
            model_boundary,
            projections_boundary,
            records,
            refused,
        ));
    }

    let packet = build_projection(
        inputs.admitted_job,
        inputs.validated_candidate,
        inputs.bundle,
        inputs.cep_handles,
        inputs.policy,
    )?;
    records.push(packet_stage_record(&packet)?);
    let dream_packet = crate::dispatch_stage::map_orientation_packet(&packet, semantic_job);
    let (disposition, omissions) = if CONFLICT_OUTPUT_QUALIFIED {
        (OrientationDisposition::Complete, Vec::new())
    } else {
        (
            OrientationDisposition::Partial,
            vec![CONFLICT_UNQUALIFIED.to_owned()],
        )
    };
    Ok(OrientationPulseResult {
        schema_version: ORIENTATION_PULSE_RESULT_SCHEMA_VERSION,
        disposition,
        proof_ceiling: CEILING_CANDIDATE_ONLY.to_owned(),
        job_id: identity.job_id,
        task_id: identity.task_id,
        scope_id: identity.scope_id,
        operation_id: identity.operation_id,
        state_fence: identity.fence,
        denominator: MANDATORY_DENOMINATOR.identity.to_owned(),
        stages: records,
        model_outcome: model_boundary,
        projections: projections_boundary,
        admitted,
        packet: Some(dream_packet),
        omissions,
        missing_owners: Vec::new(),
    })
}

/// Rejects a carrier whose deadline passed or whose clock is unavailable.
///
/// A broken clock cannot prove freshness, so it fails closed through the
/// revalidation gate rather than publishing a possibly stale result.
fn check_carrier_deadline(deadline_unix_ms: u64) -> Result<(), PulseError> {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PulseError::DeadlineExceeded)?
        .as_millis();
    let now_unix_ms = u64::try_from(now_unix_ms).map_err(|_| PulseError::DeadlineExceeded)?;
    if deadline_unix_ms <= now_unix_ms {
        return Err(PulseError::DeadlineExceeded);
    }
    Ok(())
}

/// Validates one coherent identity closure over the carrier.
///
/// Checks the admitted job/bundle/operation, task/`WorkScope`, complete
/// `StateFence`, `CC-002` request/outcome/privacy bindings, `CC-004` binding,
/// and every `CEP` handle against the declared shared identity, so
/// compatible-looking fields
/// from different snapshots cannot be stitched into one pulse. Returns the
/// static field that refused. The validated candidate and sealed policy were
/// bound to this exact admitted pair by the v1 owner call and policy seal in
/// dispatch, so they are committed, not re-proved, here; per-stage input
/// freshness and predecessor commitments are enforced by the owner entries
/// themselves, which validate their own inputs and refuse lookalikes.
fn validate_identity_closure(
    inputs: &ProductionOrientationInputs,
    semantic_job: &DreamJobInput,
) -> Result<(), &'static str> {
    if semantic_job.job_class != JobClass::Orientation {
        return Err("production job class");
    }
    if semantic_job.job_id != inputs.bundle.job_id {
        return Err("production job binding");
    }
    if semantic_job.scope_id != inputs.scope_id {
        return Err("production scope binding");
    }
    if !fences_compatible(&semantic_job.state_fence, &inputs.state_fence) {
        return Err("production fence");
    }
    let admitted = &inputs.admitted_job.job;
    if admitted.task_id != inputs.task_id {
        return Err("production task binding");
    }
    if admitted.scope_id != inputs.scope_id {
        return Err("production scope binding");
    }
    if admitted.operation_id != inputs.operation_id {
        return Err("production operation binding");
    }
    if !fences_compatible(&admitted.state_fence, &inputs.state_fence) {
        return Err("production fence");
    }
    let bundle = inputs.bundle;
    if bundle.task_id != inputs.task_id {
        return Err("production task binding");
    }
    if bundle.scope_id != inputs.scope_id {
        return Err("production scope binding");
    }
    if !fences_compatible(&bundle.state_fence, &inputs.state_fence) {
        return Err("production fence");
    }
    let frame = &inputs.admitted_job.frame;
    if frame.operation_id != inputs.operation_id {
        return Err("production operation binding");
    }
    if frame.task_id != inputs.task_id {
        return Err("production task binding");
    }
    if frame.scope_id != inputs.scope_id {
        return Err("production scope binding");
    }
    if !fences_compatible(&frame.state_fence, &inputs.state_fence) {
        return Err("production fence");
    }
    inputs
        .model_request
        .validate_binds_bundle(bundle)
        .map_err(|_| "model request binding")?;
    if inputs.model_request.privacy.as_str() != admitted.privacy_profile {
        return Err("model privacy binding");
    }
    check_model_boundary(inputs.model_outcome, bundle).map_err(|error| match error {
        PulseError::Boundary(field) => field,
        _ => "model outcome",
    })?;
    inputs
        .model_outcome
        .validate_binding(inputs.model_request)
        .map_err(|_| "model outcome binding")?;
    check_projection_boundary(inputs.projections, bundle).map_err(|error| match error {
        PulseError::Boundary(field) => field,
        _ => "canonical projections",
    })?;
    if inputs.projections.binding.task_id.as_str() != inputs.task_id {
        return Err("projection task binding");
    }
    if inputs.projections.binding.scope_id.as_str() != inputs.scope_id {
        return Err("projection scope binding");
    }
    if let Some(operation) = &inputs.projections.binding.operation_id
        && operation.as_str() != inputs.operation_id
    {
        return Err("projection operation binding");
    }
    if !fences_compatible(&inputs.projections.binding.state_fence, &inputs.state_fence) {
        return Err("projection fence");
    }
    for handle in inputs.cep_handles {
        handle
            .validate_for(&inputs.admitted_job.job)
            .map_err(|_| "cep handle binding")?;
    }
    Ok(())
}

/// Maps an unusable model disposition to its blocked reason, if any.
///
/// Only completed or partial outcomes carry a usable draft; malformed,
/// cancelled, and timeout outcomes block the pulse with their disposition
/// named.
fn unusable_model_reason(disposition: ModelRouteDisposition) -> Option<&'static str> {
    match disposition {
        ModelRouteDisposition::Completed | ModelRouteDisposition::Partial => None,
        ModelRouteDisposition::Malformed => Some(MODEL_OUTCOME_MALFORMED),
        ModelRouteDisposition::Cancelled => Some(MODEL_OUTCOME_CANCELLED),
        ModelRouteDisposition::Timeout => Some(MODEL_OUTCOME_TIMEOUT),
    }
}

/// Collects one stage outcome into the ledger, recording refusals as blocked.
fn collect_stage(
    records: &mut Vec<OrientationStageRecord>,
    refused: &mut Vec<String>,
    id: PulseStageId,
    outcome: Result<PulseStage, PulseError>,
) {
    if let Ok(stage) = outcome {
        records.push(stage_record(&stage));
    } else {
        records.push(blocked_stage_record(id, id.refusal_reason()));
        refused.push(id.refusal_reason().to_owned());
    }
}

/// Collects the stages borrowed from the carrier; the understanding and probe
/// stages move their inputs and are collected by the caller.
fn collect_ref_stages(
    inputs: &ProductionOrientationInputs,
    records: &mut Vec<OrientationStageRecord>,
    refused: &mut Vec<String>,
) {
    collect_stage(
        records,
        refused,
        PulseStageId::Classification,
        run_classification_stage(Some(&inputs.classification)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::CueActivation,
        run_cue_stage(Some(&inputs.cue_activation)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::EpistemicPosition,
        run_epistemic_stage(Some(inputs.epistemic)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::Grounding,
        run_grounding_stage(Some(inputs.grounding)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::Rivals,
        run_rival_stage(Some(&inputs.rivals)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::Conflict,
        run_conflict_stage(Some(&inputs.conflict)),
    );
    collect_stage(
        records,
        refused,
        PulseStageId::Candidates,
        run_candidate_stage(Some(inputs.projections), Some(&inputs.candidates)),
    );
}

/// Sorts ledger records into denominator order.
fn order_stage_records(records: &mut [OrientationStageRecord]) {
    records.sort_by_key(|record| stage_order(&record.stage));
}

/// Denominator position of one ledger record; unknown stages sort last.
fn stage_order(stage: &str) -> usize {
    PulseStageId::ORDER
        .iter()
        .position(|id| id.as_str() == stage)
        .unwrap_or(usize::MAX)
}

/// Builds the blocked result for refused stages: executed members keep their
/// commitments, refused members name their owner, and no packet projects.
fn refused_stages_blocked(
    identity: BlockedIdentity,
    admitted: OrientationAdmittedPrefix,
    model_outcome: OrientationBoundaryRecord,
    projections: OrientationBoundaryRecord,
    mut records: Vec<OrientationStageRecord>,
    refused: Vec<String>,
) -> OrientationPulseResult {
    records.push(blocked_stage_record(
        PulseStageId::Packet,
        PulseStageId::Packet.missing_reason(),
    ));
    blocked_result(BlockedParts {
        identity,
        admitted,
        model_outcome,
        projections,
        stages: records,
        omissions: refused,
        missing_owners: Vec::new(),
    })
}

/// Maps one internal stage outcome onto its public ledger record.
fn stage_record(stage: &PulseStage) -> OrientationStageRecord {
    let ceiling = match stage.disposition {
        OrientationStageDisposition::Executed => CEILING_CANDIDATE_ONLY,
        _ => CEILING_BLOCKED,
    };
    let recovery = match stage.disposition {
        OrientationStageDisposition::Executed => None,
        _ => Some(stage.id.recovery().to_owned()),
    };
    OrientationStageRecord {
        stage: stage.id.as_str().to_owned(),
        owner: stage.id.owner_entry().to_owned(),
        required: true,
        disposition: stage.disposition,
        expected_input: stage.id.expected_input().to_owned(),
        input_commitment: stage.input_commitment.clone(),
        output_commitment: stage.output_commitment.clone(),
        proof_ceiling: ceiling.to_owned(),
        reason: stage.reason.map(str::to_owned),
        recovery,
    }
}

/// Builds one blocked ledger record for a member that did not run.
fn blocked_stage_record(id: PulseStageId, reason: &'static str) -> OrientationStageRecord {
    stage_record(&PulseStage::blocked(id, reason))
}

/// Builds the packet ledger record for a projected packet.
fn packet_stage_record(
    packet: &OrientationPacketCandidate,
) -> Result<OrientationStageRecord, PulseError> {
    let commitment = output_digest(packet).ok_or(PulseError::Packet(
        OrientationError::Encoding("packet output"),
    ))?;
    Ok(OrientationStageRecord {
        stage: PulseStageId::Packet.as_str().to_owned(),
        owner: PulseStageId::Packet.owner_entry().to_owned(),
        required: true,
        disposition: OrientationStageDisposition::Executed,
        expected_input: PulseStageId::Packet.expected_input().to_owned(),
        input_commitment: Some(PulseStageId::Packet.expected_input().to_owned()),
        output_commitment: Some(commitment),
        proof_ceiling: CEILING_CANDIDATE_ONLY.to_owned(),
        reason: None,
        recovery: None,
    })
}

/// Commits the admitted-material prefix: v1 candidate, sealed policy, bundle.
fn admitted_prefix(inputs: &ProductionOrientationInputs) -> OrientationAdmittedPrefix {
    OrientationAdmittedPrefix {
        candidate_digest: output_digest(inputs.validated_candidate)
            .unwrap_or_else(|| DIGEST_UNAVAILABLE.to_owned()),
        policy_digest: output_digest(inputs.policy)
            .unwrap_or_else(|| DIGEST_UNAVAILABLE.to_owned()),
        bundle_digest: bundle_digest_of(inputs.bundle)
            .unwrap_or_else(|_| DIGEST_UNAVAILABLE.to_owned()),
    }
}

/// Builds the boundary record for a supplied model outcome.
fn present_model_boundary(outcome: &ModelRouteOutcome) -> OrientationBoundaryRecord {
    OrientationBoundaryRecord {
        boundary: "cc002_model_route".to_owned(),
        present: true,
        commitment: output_digest(outcome),
        disposition: Some(outcome.disposition.as_str().to_owned()),
        reason: None,
    }
}

/// Builds the boundary record for a supplied projection set.
fn present_projections_boundary(projections: &CanonicalProjectionSet) -> OrientationBoundaryRecord {
    OrientationBoundaryRecord {
        boundary: "cc004_canonical_projections".to_owned(),
        present: true,
        commitment: output_digest(projections),
        disposition: None,
        reason: None,
    }
}

/// Owned identity half shared by the blocked-result builders.
struct BlockedIdentity {
    job_id: String,
    task_id: String,
    scope_id: String,
    operation_id: String,
    fence: StateFence,
}

impl BlockedIdentity {
    fn of(inputs: &ProductionOrientationInputs) -> Self {
        Self {
            job_id: inputs.bundle.job_id.clone(),
            task_id: inputs.task_id.clone(),
            scope_id: inputs.scope_id.clone(),
            operation_id: inputs.operation_id.clone(),
            fence: inputs.state_fence.clone(),
        }
    }
}

/// Owned parts of one blocked result.
struct BlockedParts {
    identity: BlockedIdentity,
    admitted: OrientationAdmittedPrefix,
    model_outcome: OrientationBoundaryRecord,
    projections: OrientationBoundaryRecord,
    stages: Vec<OrientationStageRecord>,
    omissions: Vec<String>,
    missing_owners: Vec<String>,
}

/// Assembles one blocked result: full denominator, no packet.
fn blocked_result(parts: BlockedParts) -> OrientationPulseResult {
    debug_assert_eq!(parts.stages.len(), MANDATORY_DENOMINATOR.members.len());
    OrientationPulseResult {
        schema_version: ORIENTATION_PULSE_RESULT_SCHEMA_VERSION,
        disposition: OrientationDisposition::Blocked,
        proof_ceiling: CEILING_BLOCKED.to_owned(),
        job_id: parts.identity.job_id,
        task_id: parts.identity.task_id,
        scope_id: parts.identity.scope_id,
        operation_id: parts.identity.operation_id,
        state_fence: parts.identity.fence,
        denominator: MANDATORY_DENOMINATOR.identity.to_owned(),
        stages: parts.stages,
        model_outcome: parts.model_outcome,
        projections: parts.projections,
        admitted: parts.admitted,
        packet: None,
        omissions: parts.omissions,
        missing_owners: parts.missing_owners,
    }
}

/// Builds the blocked result for absent prerequisites: no boundary values,
/// no stage records, no packet.
fn missing_prerequisites_blocked(
    admission: &KernelJobAdmission,
    admitted_job: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    bundle: &DreamInputBundle,
    policy: &OrientationPolicy,
) -> OrientationPulseResult {
    let stages = PulseStageId::ORDER
        .iter()
        .map(|id| blocked_stage_record(*id, id.missing_reason()))
        .collect();
    let mut missing_owners = vec![OWNER_MODEL_ROUTE.to_owned(), OWNER_PROJECTIONS.to_owned()];
    missing_owners.extend(
        PulseStageId::ORDER
            .iter()
            .filter(|id| **id != PulseStageId::Packet)
            .map(|id| id.owner_entry().to_owned()),
    );
    blocked_result(BlockedParts {
        identity: BlockedIdentity {
            job_id: admission.job_id.clone(),
            task_id: admitted_job.job.task_id.clone(),
            scope_id: admitted_job.job.scope_id.clone(),
            operation_id: admitted_job.job.operation_id.clone(),
            fence: admission.state_fence.clone(),
        },
        admitted: OrientationAdmittedPrefix {
            candidate_digest: output_digest(candidate)
                .unwrap_or_else(|| DIGEST_UNAVAILABLE.to_owned()),
            policy_digest: output_digest(policy).unwrap_or_else(|| DIGEST_UNAVAILABLE.to_owned()),
            bundle_digest: bundle_digest_of(bundle)
                .unwrap_or_else(|_| DIGEST_UNAVAILABLE.to_owned()),
        },
        model_outcome: OrientationBoundaryRecord {
            boundary: "cc002_model_route".to_owned(),
            present: false,
            commitment: None,
            disposition: None,
            reason: Some(CC002_MISSING.to_owned()),
        },
        projections: OrientationBoundaryRecord {
            boundary: "cc004_canonical_projections".to_owned(),
            present: false,
            commitment: None,
            disposition: None,
            reason: Some(CC004_MISSING.to_owned()),
        },
        stages,
        omissions: vec![
            CC002_MISSING.to_owned(),
            CC004_MISSING.to_owned(),
            ORIENTATION_SUPPLY_MISSING.to_owned(),
        ],
        missing_owners,
    })
}

/// Builds the blocked result for a refused identity closure: the boundary
/// values exist but cannot be stitched into one pulse.
fn closure_blocked(
    inputs: &ProductionOrientationInputs,
    admitted: &OrientationAdmittedPrefix,
    field: &'static str,
) -> OrientationPulseResult {
    let stages = PulseStageId::ORDER
        .iter()
        .map(|id| blocked_stage_record(*id, field))
        .collect();
    blocked_result(BlockedParts {
        identity: BlockedIdentity::of(inputs),
        admitted: admitted.clone(),
        model_outcome: OrientationBoundaryRecord {
            boundary: "cc002_model_route".to_owned(),
            present: true,
            commitment: output_digest(inputs.model_outcome),
            disposition: Some(inputs.model_outcome.disposition.as_str().to_owned()),
            reason: Some(field.to_owned()),
        },
        projections: OrientationBoundaryRecord {
            boundary: "cc004_canonical_projections".to_owned(),
            present: true,
            commitment: output_digest(inputs.projections),
            disposition: None,
            reason: Some(field.to_owned()),
        },
        stages,
        omissions: vec![field.to_owned()],
        missing_owners: Vec::new(),
    })
}

/// Builds the blocked result for an unusable model disposition: the outcome
/// exists but carries no usable draft.
fn unusable_model_blocked(
    inputs: &ProductionOrientationInputs,
    admitted: &OrientationAdmittedPrefix,
    reason: &'static str,
) -> OrientationPulseResult {
    let stages = PulseStageId::ORDER
        .iter()
        .map(|id| blocked_stage_record(*id, reason))
        .collect();
    blocked_result(BlockedParts {
        identity: BlockedIdentity::of(inputs),
        admitted: admitted.clone(),
        model_outcome: OrientationBoundaryRecord {
            boundary: "cc002_model_route".to_owned(),
            present: true,
            commitment: output_digest(inputs.model_outcome),
            disposition: Some(inputs.model_outcome.disposition.as_str().to_owned()),
            reason: Some(reason.to_owned()),
        },
        projections: present_projections_boundary(inputs.projections),
        stages,
        omissions: vec![reason.to_owned()],
        missing_owners: Vec::new(),
    })
}
