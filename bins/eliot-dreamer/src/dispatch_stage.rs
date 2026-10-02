#![forbid(unsafe_code)]

//! Native owner dispatch for admitted Dreamer jobs (issue #702, Slice 7).
//!
//! After the Slice-A/1 admission dispatch admits a job class, this stage
//! resolves the exact native owner for one closed [`JobClass`] and invokes it
//! with no fallthrough: Curation names the A-31 curation fan-in
//! ([`route_validated_curation`](eliot_dreamer_curation::route_validated_curation)),
//! Orientation names the production Orientation composer
//! ([`dispatch_orientation`], which reaches
//! `eliot-dreamer-orientation` `build_projection` through the versioned
//! [`ProductionOrientationInputs`](crate::production_orientation::ProductionOrientationInputs)
//! carrier), and every
//! other class names its native owner. Exhaustive with no wildcard arm:
//! extending the closed taxonomy breaks compilation here until the new class
//! is assigned an owning slice.
//!
//! [`dispatch_admitted`] is the single Slice-7 owner entry: it takes the
//! Kernel admission, the semantic job, the A-20 screen binding (for
//! Curation), the Governor-injected Curation execution carrier (for Curation),
//! the closed class, and the structured A-05 validated candidate (for every
//! non-Curation admitted class, carried from the validation stage), and
//! returns the typed [`DreamResult`]. Typestate: Orientation,
//! `ResearchSynthesis`, and `Maintenance` cannot dispatch without the
//! validated receipt — raw unvalidated input is refused before any owner
//! work — and the native projector is reachable only through the validated
//! wrapper around `build_projection`, which itself takes only the
//! receipt-bound v1 aggregate.
//! There is no class-only stub seam: every arm either genuinely invokes its
//! owner or refuses naming the exact missing governed input. Orientation
//! derives the v1 hypothesis pair, validates it through the real v1 A-05
//! entry, then resolves the production carrier prerequisites and returns the
//! typed [`DreamResult::Orientation`] complete/partial/blocked result (issue
//! #2901): with no CC-002 outcome, CC-004 set, or stage-owner records
//! in-binary, production returns blocked, never a packet. Orientation has
//! exactly one composition path: the packet-only compatibility seam is
//! deleted, so no alternative route can produce a candidate packet outside
//! the versioned carrier. Curation genuinely resolves descriptors, validates
//! registry/policy/screen, and routes the injected batch through the real
//! A-31 fan-in; `ResearchSynthesis` and `Maintenance` fail closed naming
//! their missing Governor-resolved inputs; the remaining five classes refuse
//! with `UnsupportedJobClass` (they never reach here via `submit`; direct
//! calls refuse).
//!
//! Fail-closed: every refusal is [`DreamerError::InvalidAdmission`] (the
//! request-rejected code) or [`DreamerError::UnsupportedJobClass`], never the
//! Kernel-admission code: the admission itself was valid, the owner inputs
//! were not. Dynamic payloads (handles, digests, reasons) are dropped in favor
//! of bounded static field names; nothing secret flows. The Curation leaf
//! handler runs only behind a Governor-injected carrier: production carries
//! none (the ten live ports are Governor-injected and absent in-binary), so
//! production Curation refuses at the carrier check before any generic stage
//! work; tests inject the [`curation_test_support`] carrier to prove the wired
//! A-31 path end to end.

use std::time::Instant;

use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, DreamDraftValidationError, validate_grounded_dream_draft_at,
};
use eliot_dreamer_claim_grounding::GroundingRequest;
use eliot_dreamer_contracts::registry::{CurationHandlerRegistry, canonical_registry};
use eliot_dreamer_contracts::validation::structured::ValidatedGroundingCandidate;
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobAdmission, JobClass, ScreenBinding, ScreenState,
    SourceDisposition,
};
use eliot_dreamer_curation::{
    CurationCandidateSet, CurationMemberOutcome, CurationRoutingError, MAX_BATCH_ITEMS,
    NativeCurationPortSet, OwnerRevisionPin, RoutingDisposition, RoutingPolicy,
    ValidatedCurationBatch, route_validated_curation,
};
use eliot_dreamer_orientation::{
    AdmittedOrientationJob, LocalOrientationFrame, OrientationError, OrientationPolicy,
    projection::OrientationPacketCandidate,
};

use crate::admitted_material::{
    admission_of, bundle_of, orientation_frame_of, preservation_of, usage_of, v1_grounded_of,
    v1_model_of, validation_policy_of,
};
use crate::controller::verify_admitted_binding;
use crate::curation_pulse::compose_curation_pulse;
use crate::curation_screen_stage::{CurationProtection, CurationProtectionSet, ProtectionClass};
use crate::production_orientation::OrientationSupply;
use crate::{
    CurationCandidate, DreamJobInput, DreamPacket, DreamResult, DreamerError, Interpretation,
    KernelJobAdmission, SourceCoverage,
};

/// Terminal fail-closed reason when the A-31 fan-in cannot be invoked: the
/// closed registry resolved and the owner port-boundary validation ran for
/// real, but the ten live handler ports it requires are Governor-injected and
/// absent in-binary.
const CURATION_PORTS_REFUSAL: &str =
    "admitted dispatch requires Governor-injected live handler ports";
/// Fail-closed reason when the Curation arm is entered without the A-20 screen
/// binding the fan-in must be checked against.
const CURATION_SCREEN_REFUSAL: &str =
    "admitted curation dispatch requires Governor-resolved screen binding";
/// Fail-closed reason when the Curation arm is entered without the A-20 owner
/// protection assessment derived from that same screen binding. The receipt
/// must carry a protection finding for every routed member, so a route that
/// cannot name one refuses instead of emitting candidates whose protection
/// state is simply absent.
const CURATION_PROTECTION_REFUSAL: &str =
    "admitted curation dispatch requires the owner screen protection assessment";
/// Fail-closed reason when the Curation arm is entered without the
/// Governor-injected execution carrier: the validated batch and the ten live
/// handler ports arrive together from the Governor, so without them there is
/// no A-31 input to route and no generic stage work to burn first.
pub(crate) const CURATION_CARRIER_REFUSAL: &str =
    "admitted Curation requires Governor-injected execution carrier and handler ports";
/// Fail-closed reason when a routed set carries no accepted candidate: an
/// empty success would promote absence to a result, so the arm refuses
/// instead.
const CURATION_EMPTY_REFUSAL: &str = "curation produced no accepted candidates";
/// Routing policy identity shared by dispatch and the test harness: the sealed
/// input digest covers the policy, so both sides must use the identical value.
const CURATION_POLICY_ID: &str = "eliot-dreamer-dispatch";
/// Fail-closed reason for the `ResearchSynthesis` arm: the owner projection
/// needs a Governor-owned `ResearchPack` its synthesis vocabulary cannot be
/// built from here (see the arm documentation).
const RESEARCH_PACK_REFUSAL: &str =
    "ResearchSynthesis dispatch requires Governor-resolved research pack";
/// Fail-closed reason for the Maintenance arm: the owner plan needs
/// Governor-owned maintenance inputs its plan vocabulary cannot be built from
/// here (see the arm documentation).
const MAINTENANCE_INPUTS_REFUSAL: &str =
    "Maintenance dispatch requires Governor-resolved maintenance plan inputs";
/// Fail-closed reason when the Orientation bundle carries no non-excluded
/// material the projection frame could bind: the frame source designates
/// Governor-resolved bundle material and is never invented here.
const FRAME_SOURCE_REFUSAL: &str =
    "admitted orientation dispatch requires Governor-resolved frame source";
/// Fail-closed reason when a non-Curation arm is entered without the
/// structured A-05 validated candidate: the common pre-handler gate
/// ([`validate_admitted_draft`](crate::validation_stage::validate_admitted_draft))
/// must accept before any native handler runs, so dispatch without its
/// receipt refuses before any owner work.
pub(crate) const VALIDATION_RECEIPT_REFUSAL: &str =
    "admitted dispatch requires validated pre-handler candidate";

/// Governor-injected Curation execution carrier: the validated batch plus the
/// ten live handler ports A-31 routes it through.
///
/// Both halves arrive together from the Governor. Production carries none
/// (live ports are absent in-binary); tests inject the
/// [`curation_test_support`] carrier to prove the wired path.
pub struct CurationExecutionCarrier<'a> {
    /// Already-validated batch bound to the dispatched screen.
    pub batch: ValidatedCurationBatch,
    /// Exactly one live port per owner family, validated against the closed
    /// registry and the batch pins at dispatch time.
    pub ports: NativeCurationPortSet<'a>,
}

/// The per-job owner carriers one admitted dispatch may carry.
///
/// Curation and Orientation are the two admitted classes whose owner records
/// live outside this binary: Curation needs its validated batch plus one live
/// port per owner family, Orientation needs the Governor-resolved owner supply.
/// Each stays an independent optional so one class's absence never implies the
/// other's, and both are `None` in the worker role where no owner is attached.
pub(crate) struct OwnerCarriers<'a> {
    /// Curation owner records, present only for an admitted Curation job.
    pub curation: Option<CurationExecutionCarrier<'a>>,
    /// The screened binding a Curation job resolved, absent for every other class.
    pub screen: Option<ScreenBinding>,
    /// The protection assessment derived from that binding.
    pub curation_protection: Option<CurationProtectionSet>,
    /// Orientation owner records, present only for an admitted Orientation job.
    pub orientation: Option<&'a OrientationSupply<'a>>,
}

/// The two Orientation carrier records the admitted pipeline itself produces.
///
/// They are outputs of stages that run after the Governor supply channel is
/// resolved, so no channel can carry them: the grounding request comes from
/// `grounding_stage::resolve_grounding_inputs` and the structured A-05
/// validated grounding candidate from `validation_stage::validate_admitted_draft`.
/// This is the existing pipeline's own committed receipt, joined by reference —
/// never a copy, a default, or a lookalike rebuilt for the composer.
///
/// The v1 hypothesis pair is deliberately absent: it is derived and validated
/// inside `dispatch_orientation` itself, so that arm carries it directly rather
/// than through this struct.
pub(crate) struct PipelineOrientationRecords<'a> {
    /// Owner grounding request the claim-grounding stage ran under.
    pub grounding: &'a GroundingRequest,
    /// Structured A-05 validated candidate carrying the rival declarations.
    pub validated_draft: &'a ValidatedGroundingCandidate,
    /// The coherent v1 pair, present only once the v1 A-05 entry has accepted its
    /// aggregate. It cannot exist before this pipeline runs, which is why it is
    /// never asked of the Governor channel.
    pub v1: Option<V1GroundedPair<'a>>,
}
impl<'a> PipelineOrientationRecords<'a> {
    /// Builds the record from the facts this pipeline holds before the v1 entry.
    pub(crate) fn new(
        grounding: &'a GroundingRequest,
        validated_draft: &'a ValidatedGroundingCandidate,
    ) -> Self {
        Self {
            grounding,
            validated_draft,
            v1: None,
        }
    }

    /// Attaches the coherent v1 pair this arm derived and the v1 entry accepted.
    pub(crate) fn with_v1(
        self,
        grounded: &'a eliot_dreamer_contracts::GroundedDreamDraft,
        draft: &'a eliot_dreamer_contracts::ValidatedDreamDraft,
    ) -> Self {
        Self {
            v1: Some(V1GroundedPair { grounded, draft }),
            ..self
        }
    }
}

/// The coherent v1 pair this arm derived and the real v1 A-05 entry accepted.
///
/// Both halves are read back out of the accepted aggregate rather than
/// re-derived, so the conflict stage consumes exactly what validation approved.
/// They cannot travel the Governor channel: they do not exist until this
/// pipeline has run.
#[derive(Clone, Copy)]
pub(crate) struct V1GroundedPair<'a> {
    /// The grounded draft the v1 entry accepted.
    pub grounded: &'a eliot_dreamer_contracts::GroundedDreamDraft,
    /// The validated draft the v1 entry accepted.
    pub draft: &'a eliot_dreamer_contracts::ValidatedDreamDraft,
}

/// Maps a native owner refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the owner
/// inputs were not. Dynamic payloads (handles, digests, reasons) are dropped
/// in favor of bounded static field names; nothing secret flows.
fn dispatch_denied(error: &ContractViolation) -> DreamerError {
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

/// Dispatches one admitted job to its exact native owner.
///
/// Takes the Kernel admission, the semantic job, the A-20 screen binding
/// (`Some` for Curation, carried from the screen stage; `None` elsewhere),
/// the Governor-injected Curation execution carrier (`Some` only where the
/// Governor injected one; production passes `None`), the closed class, and
/// the structured A-05 validated candidate (`Some` for every non-Curation
/// admitted class, carried from the validation stage; `None` for Curation,
/// which owns its separate carrier, and for refused classes, which never
/// reach validation), and the two pipeline-produced records the Orientation
/// carrier joins (read only on the Orientation arm, and therefore optional for
/// exactly the same reason the validated candidate is — see the parameter
/// documentation below). Returns the owner-typed [`DreamResult`].
///
/// Fail-closed: the admission/job binding is verified first, then the class
/// parameter is bound against the semantic job, then the exhaustive nine-arm
/// match runs with no wildcard. Orientation proves the structured receipt
/// binding first ([`require_validated_binding`]), then derives the v1
/// hypothesis pair, validates it through the real v1 A-05 entry, resolves
/// the production carrier prerequisites, and returns the typed
/// [`DreamResult::Orientation`] complete/partial/blocked result (blocked
/// until the Governor supply channel lands); Curation checks the carrier first
/// (a missing carrier refuses before any screen or registry work, so no
/// generic stage burns on a job that cannot route), then the screen binding
/// together with the protection assessment derived from that binding, then the
/// real A-31 fan-in; `ResearchSynthesis` and `Maintenance` prove
/// the structured receipt binding first and then name their missing
/// Governor-resolved inputs; the five classes `submit` never admits refuse
/// with `UnsupportedJobClass`.
pub(crate) fn dispatch_admitted(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    carriers: OwnerCarriers<'_>,
    job_class: JobClass,
    validated: Option<&ValidatedGroundingCandidate>,
    // The two records the Orientation composer joins, or `None` for every
    // class whose Orientation pipeline never runs.
    //
    // Optional for the same structural reason as `validated`, and because of
    // one owner rule: the A-05 gate rejects `JobClass::Curation`
    // unconditionally
    // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
    // `validate_family` → `UnsupportedJobShape`, "Curation requires its
    // separate typed post-handler carrier"). A Curation job therefore never
    // produces a `ValidatedGroundingCandidate`, so this record is
    // **unconstructible** for it — there is nothing to hand over, not a value
    // that was merely left out. Requiring it would force a caller to
    // fabricate a receipt that the owner refuses to issue, which is why it is
    // `Option` here and why the Curation arm never reads it.
    //
    // The Curation arm deliberately does not inspect this value at all: it
    // never branches on `Some`/`None`, so `None` is not a new refusal there.
    // Only the Orientation arm consumes it.
    pipeline: Option<PipelineOrientationRecords<'_>>,
) -> Result<DreamResult, DreamerError> {
    verify_admitted_binding(admission, job)?;
    if job.job_class != job_class {
        return Err(DreamerError::InvalidAdmission("job class binding"));
    }
    match job_class {
        // Native owner: eliot-dreamer-curation (A-31 sole fan-in). The
        // carrier check runs before the screen check: without the
        // Governor-injected batch and ports there is nothing to route, so
        // the precise carrier refusal names the missing governed input
        // even when the screen is absent too.
        JobClass::Curation => {
            let Some(carrier) = carriers.curation else {
                return Err(DreamerError::InvalidAdmission(CURATION_CARRIER_REFUSAL));
            };
            let Some(binding) = carriers.screen else {
                return Err(DreamerError::InvalidAdmission(CURATION_SCREEN_REFUSAL));
            };
            let Some(protection) = carriers.curation_protection else {
                return Err(DreamerError::InvalidAdmission(CURATION_PROTECTION_REFUSAL));
            };
            dispatch_curation(binding, protection, carrier)
        }
        // Native owner: the production Orientation composer (typed
        // complete/partial/blocked result via the versioned carrier), gated
        // on the structured A-05 receipt: without the validated candidate
        // there is no proved pre-handler gate, so the arm refuses before any
        // v1 derivation or owner projection work.
        JobClass::Orientation => {
            let Some(candidate) = validated else {
                return Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL));
            };
            // The pipeline record carries the structured A-05 validated draft
            // this composer joins, so its absence is the SAME missing-receipt
            // condition the arm above already refuses. This reuses that typed
            // refusal rather than introducing a second reason code for one
            // condition. It is a fail-closed backstop, not a new outcome:
            // production and every Orientation case supply the record.
            let Some(records) = pipeline else {
                return Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL));
            };
            dispatch_orientation(admission, job, candidate, carriers.orientation, records)
        }
        // Native owner: eliot-dreamer-research-synthesis `synthesize`. The
        // owner takes its own `SynthesisRequest` vocabulary (a
        // Governor-owned `ResearchPack` with evidence grades, frozen
        // denominator, and source-independence bindings plus its own
        // grounded-draft shape): none of it is constructible from the
        // admitted binary material, and transcribing the validated
        // candidate into that vocabulary would be semantic recomputation
        // owned elsewhere. The structured receipt binding is still proved
        // first (validation runs before dispatch refusal, so a rejected
        // candidate never reaches even this refusal with handler work
        // burned); then fail closed naming the missing governed input; no
        // dependency is added for an unwired owner.
        JobClass::ResearchSynthesis => {
            let Some(candidate) = validated else {
                return Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL));
            };
            require_validated_binding(admission, job, candidate)?;
            Err(DreamerError::InvalidAdmission(RESEARCH_PACK_REFUSAL))
        }
        // Native owner: eliot-dreamer-maintenance-plan
        // `propose_maintenance_plan`. The owner takes its own Governor-owned
        // plan inputs (objectives, trigger evidence, bounds, and history
        // bindings): none of it is constructible from the admitted binary
        // material, and synthesizing it here would be self-issued
        // authority. The structured receipt binding is still proved first
        // (see the `ResearchSynthesis` arm); then fail closed naming the
        // missing governed input; no dependency is added for an unwired
        // owner.
        JobClass::Maintenance => {
            let Some(candidate) = validated else {
                return Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL));
            };
            require_validated_binding(admission, job, candidate)?;
            Err(DreamerError::InvalidAdmission(MAINTENANCE_INPUTS_REFUSAL))
        }
        // The five classes `submit` never admits: direct calls refuse here.
        JobClass::Clarification => Err(DreamerError::UnsupportedJobClass(JobClass::Clarification)),
        JobClass::ArchitectureSelfQuery => Err(DreamerError::UnsupportedJobClass(
            JobClass::ArchitectureSelfQuery,
        )),
        JobClass::DevelopmentDiagnosis => Err(DreamerError::UnsupportedJobClass(
            JobClass::DevelopmentDiagnosis,
        )),
        JobClass::OrchestrationPlanning => Err(DreamerError::UnsupportedJobClass(
            JobClass::OrchestrationPlanning,
        )),
        JobClass::ConfigurationAssistance => Err(DreamerError::UnsupportedJobClass(
            JobClass::ConfigurationAssistance,
        )),
    }
}

/// Proves the structured A-05 receipt binding for one admitted job before any
/// native handler runs.
///
/// Recomputes the intrinsic receipt binding
/// ([`ValidatedGroundingCandidate::validate_binding`]) and pins the
/// validated preimage to this admission: the grounded job canonical identity
/// must equal the admitted canonical identity, both scope bindings must equal
/// the admitted scope, and the validated fence must equal the semantic fence
/// (proved equal to the Kernel fence by the binding check). Any drift —
/// stale, duplicate, tampered, or foreign-job receipt — refuses fail-closed
/// with a bounded static field before any v1 derivation or handler work.
/// This is a binding re-proof, never a validator re-run: the owner
/// validation ran exactly once upstream, and this check consumes its receipt
/// without invoking it again.
pub(crate) fn require_validated_binding(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    validated: &ValidatedGroundingCandidate,
) -> Result<(), DreamerError> {
    validated
        .validate_binding()
        .map_err(|_| DreamerError::InvalidAdmission("validation receipt"))?;
    let admitted = admission_of(admission, job)?;
    let expected = admitted.canonical_id();
    if validated.input.grounded.input.job.canonical_id() != expected {
        return Err(DreamerError::InvalidAdmission("validation receipt binding"));
    }
    if validated.input.grounded.scope_id != admission.scope_id
        || validated.validated.scope_id != admission.scope_id
    {
        return Err(DreamerError::InvalidAdmission("validation receipt binding"));
    }
    if validated.validated.state_fence != job.state_fence {
        return Err(DreamerError::InvalidAdmission("validation receipt binding"));
    }
    Ok(())
}

/// Dispatches one admitted Orientation job through the production composer.
///
/// Takes the structured A-05 validated candidate alongside the admitted pair:
/// typestate makes raw dispatch impossible — without the receipt there is no
/// call. The structured receipt binding is proved first, then the v1
/// hypothesis pair validates through the real v1 A-05 entry exactly once,
/// then the production carrier prerequisites resolve into the typed
/// [`DreamResult::Orientation`] complete/partial/blocked result. A v1
/// semantic rejection maps to the static refusal and never reaches
/// composition, so rejection invokes zero handlers with no fallback dispatch.
///
/// `pipeline` carries the two records the admitted pipeline itself produced,
/// so the carrier joins that pipeline's own committed receipt instead of asking
/// the Governor channel for values the channel could never hold.
fn dispatch_orientation(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    validated: &ValidatedGroundingCandidate,
    orientation_supply: Option<&OrientationSupply<'_>>,
    pipeline: PipelineOrientationRecords<'_>,
) -> Result<DreamResult, DreamerError> {
    require_validated_binding(admission, job, validated)?;
    let admitted = admission_of(admission, job)?;
    // The same published slice the model and grounding stages received, so all
    // three derive ONE bundle for this job and the cross-stage rival binding
    // sees equal bundles.
    let bundle = bundle_of(
        admission,
        job,
        crate::admitted_material::published_positions(orientation_supply),
    )?;
    let frame_source = orientation_frame_source(&bundle)?;
    let route_started = Instant::now();
    let model = v1_model_of(admission, job)?;
    let route_wall_ms = u64::try_from(route_started.elapsed().as_millis())
        .map_err(|_| DreamerError::InvalidAdmission("model route wall observation"))?;
    let grounded = v1_grounded_of(&model)?;
    let usage = usage_of(&admitted.budget);
    let validation_policy = validation_policy_of(admitted.policy_ref.as_str())?;
    let preservation = preservation_of()?;
    let candidate = match validate_grounded_dream_draft_at(
        &admitted,
        &bundle,
        &model,
        &grounded,
        &validation_policy,
        &usage,
        &preservation,
        Some(0),
        false,
    ) {
        Ok(CandidateValidationOutcome::Accepted(candidate)) => *candidate,
        Ok(CandidateValidationOutcome::Rejected(_)) => {
            return Err(DreamerError::InvalidAdmission(
                "validation semantic rejection",
            ));
        }
        Err(error) => return Err(v1_denied(&error)),
    };
    // The CC-002 boundary: the admitted request over this exact bundle, and
    // the outcome of the one admitted call this runtime performed. Both are
    // proved against the bundle and the request through the real owner
    // validators, and the receipt reports measured bytes, the measured elapsed
    // wall time, and the exact provider-call count this runtime made — no
    // provider process is launched in-binary, so that count is zero rather than
    // an invented call.
    let model_request = crate::model_stage::model_route_request(admission, job, &bundle)?;
    let route_usage =
        crate::model_stage::ModelRouteUsage::measured(&bundle, &model, 0, route_wall_ms)?;
    let model_outcome =
        crate::model_stage::model_route_outcome(&model_request, &model, route_usage)?;
    let frame = orientation_frame_of(admission, &admitted, job, frame_source.as_str())?;
    let admitted_job = orientation_admitted_job(admitted, frame);
    let policy = orientation_dispatch_policy()?;
    match crate::production_orientation::resolve_production_inputs(
        &crate::production_orientation::AdmittedOrientationRefs {
            admission,
            admitted_job: &admitted_job,
            candidate: &candidate,
            bundle: &bundle,
            policy: &policy,
        },
        Some((&model_request, &model_outcome)),
        orientation_supply,
        // The coherent v1 pair this very arm derived and the real v1 A-05 entry
        // accepted above, read back out of the accepted aggregate, so the conflict
        // stage consumes exactly what validation approved.
        &pipeline.with_v1(&candidate.grounded, &candidate.validated),
    ) {
        Ok(inputs) => crate::production_orientation::compose_production_result(inputs, job)
            .map(DreamResult::Orientation)
            .map_err(|error| orientation_denied(&error.into_orientation_error())),
        // A missing prerequisite is an honest blocked disposition and is
        // published; a composer defect (a ledger that does not cover the
        // mandatory denominator) is a refusal and is not, so the two answers
        // stay distinguishable instead of collapsing into one.
        Err(crate::production_orientation::OrientationResolution::Blocked(blocked)) => {
            Ok(DreamResult::Orientation(*blocked))
        }
        Err(crate::production_orientation::OrientationResolution::Defect(error)) => {
            Err(orientation_denied(&error.into_orientation_error()))
        }
    }
}

/// Selects the deterministic frame-source handle from admitted bundle material.
///
/// The first non-excluded material in bundle order is the deterministic
/// candidate frame source until the Governor pins the frame source
/// explicitly. No handle is invented: a bundle with no bindable material
/// refuses. This selects the same first evidence handle the bundle plants
/// the frame digest on, so the frame built downstream is byte-identical to
/// the planted one.
fn orientation_frame_source(bundle: &DreamInputBundle) -> Result<String, DreamerError> {
    bundle
        .materials
        .iter()
        .find(|material| !matches!(material.disposition, SourceDisposition::Excluded))
        .map(|material| material.handle.clone())
        .ok_or(DreamerError::InvalidAdmission(FRAME_SOURCE_REFUSAL))
}

/// Builds the admitted Orientation job over one validated frame.
///
/// Governor-resolved evidence travels empty here (G5: locally built
/// envelopes would be self-issued authority), as does the coverage
/// denominator, which only the Governor can pin.
fn orientation_admitted_job(
    admitted: DreamJobAdmission,
    frame: LocalOrientationFrame,
) -> AdmittedOrientationJob {
    AdmittedOrientationJob {
        job: admitted,
        frame,
        admitted_evidence: Vec::new(),
        coverage_denominator: None,
    }
}

/// Builds the bounded sealed dispatch policy for Orientation projection.
///
/// Explicit identity and revision, a 1 MiB output envelope (inside the owner
/// 4 MiB ceiling), and the owner defaults for every other maximum. Sealing
/// freezes the policy digest the packet provenance binds.
fn orientation_dispatch_policy() -> Result<OrientationPolicy, DreamerError> {
    let mut policy = OrientationPolicy::new("eliot-dreamer-dispatch", 1, 1_048_576);
    policy.seal().map_err(|error| orientation_denied(&error))?;
    Ok(policy)
}

/// Maps a v1 A-05 validation refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected
/// code), never the Kernel-admission code: the admission itself was valid,
/// the hypothesis pair was not. Dynamic payloads are dropped in favor of the
/// bounded static field names the owner variants already carry.
fn v1_denied(error: &DreamDraftValidationError) -> DreamerError {
    match error {
        DreamDraftValidationError::Bound { field, .. }
        | DreamDraftValidationError::Encoding { field, .. }
        | DreamDraftValidationError::InvalidContract { field, .. } => {
            DreamerError::InvalidAdmission(field)
        }
    }
}

/// Projects one native orientation packet onto the crate packet result.
///
/// Identity bindings travel verbatim (packet/job/question/scope from the
/// owner packet; the state fence from the admitted semantic input, which now
/// carries the typed fence proved equal to the Kernel-admitted one by the
/// binding check). Source
/// coverage carries the five admitted handle families verbatim. Interpreted
/// statements travel with their source handles at the candidate-only ceiling:
/// nothing is promoted. ABSOLUTE G4 RULE: both owner residues,
/// `architecture_implications` and `model_routes_and_cost`, are appended to
/// `rival_models_and_dissent` after the rival texts, so neither marker can be
/// dropped or thinned by this mapping. Unknowns, inert probes (text only:
/// probes never execute), invalidation conditions, and projection-input
/// provenance (proof of inputs, never of truth) travel likewise.
///
/// The single packet mapping the production composer applies; the deleted
/// compatibility seam no longer has a second path to stay identical to.
pub(crate) fn map_orientation_packet(
    packet: &OrientationPacketCandidate,
    job: &DreamJobInput,
) -> DreamPacket {
    let mut rival_models_and_dissent: Vec<String> = packet
        .rival_models_and_dissent
        .iter()
        .map(|residue| residue.text.clone())
        .collect();
    rival_models_and_dissent.push(packet.architecture_implications.text.clone());
    rival_models_and_dissent.push(packet.model_routes_and_cost.text.clone());
    let mut provenance = vec![
        packet.provenance.operation_id.clone(),
        packet.provenance.idempotency_key.clone(),
        packet.provenance.task_id.clone(),
        packet.provenance.scope_id.clone(),
        packet.provenance.manifest_digest.clone(),
        packet.provenance.validation_input_digest.clone(),
        packet.provenance.validation_output_digest.clone(),
        packet.provenance.policy_digest.clone(),
    ];
    provenance.extend(packet.provenance.source_handles.iter().cloned());
    DreamPacket {
        packet_id: packet.packet_id.clone(),
        job_id: packet.job_id.clone(),
        question: packet.question.clone(),
        scope_id: packet.scope_id.clone(),
        state_fence: job.state_fence.clone(),
        source_coverage: SourceCoverage {
            evidence: job.evidence_handles.clone(),
            memory: job.memory_handles.clone(),
            architecture: job.architecture_handles.clone(),
            implementation: job.implementation_handles.clone(),
            conformance: job.conformance_handles.clone(),
        },
        synthesized_interpretations: packet
            .synthesized_interpretations
            .iter()
            .map(|interpretation| Interpretation {
                statement: interpretation.statement.clone(),
                support_handles: interpretation.source_handles.clone(),
                epistemic_status: "candidate_only".to_owned(),
            })
            .collect(),
        rival_models_and_dissent,
        unknowns_and_gaps: packet
            .unknowns_and_gaps
            .iter()
            .map(|residue| residue.text.clone())
            .collect(),
        recommended_probes_or_next_actions: packet
            .recommended_probes_or_next_actions
            .iter()
            .map(|probe| probe.text.clone())
            .collect(),
        invalidation_conditions: packet.invalidation_conditions.clone(),
        provenance,
    }
}

/// Maps a native orientation refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the owner
/// inputs were not. Dynamic payloads are dropped in favor of the bounded
/// static field names the owner variants already carry; nothing secret flows.
/// Exhaustive with no wildcard arm: extending the owner error taxonomy breaks
/// compilation here until the new refusal is assigned a mapping.
fn orientation_denied(error: &OrientationError) -> DreamerError {
    match error {
        OrientationError::Invalid(field)
        | OrientationError::Unsupported(field)
        | OrientationError::Binding(field)
        | OrientationError::Encoding(field)
        | OrientationError::Bounded(field) => DreamerError::InvalidAdmission(field),
        OrientationError::WrongJobClass => DreamerError::InvalidAdmission("job class binding"),
        OrientationError::Bound => DreamerError::InvalidAdmission("orientation bound"),
        OrientationError::RevalidationRequired => {
            DreamerError::InvalidAdmission("observation time")
        }
        OrientationError::Cancelled => DreamerError::InvalidAdmission("cancelled"),
        OrientationError::Internal => DreamerError::InvalidAdmission("internal projector failure"),
    }
}

/// Builds the bounded all-or-nothing routing policy for one A-31 call.
///
/// Shared by dispatch and the test harness: the sealed input digest covers
/// the policy, so both sides must use the identical value or the owner
/// digest check fails closed on drift.
fn curation_routing_policy() -> RoutingPolicy {
    let max_items = u32::try_from(MAX_BATCH_ITEMS).unwrap_or(u32::MAX);
    RoutingPolicy {
        policy_id: CURATION_POLICY_ID.to_owned(),
        policy_revision: 1,
        allow_partial: false,
        max_items,
    }
}

/// Dispatches one admitted Curation job through the A-31 sole fan-in.
///
/// Takes the A-20 screen binding from the screen stage, the owner protection
/// assessment derived from that same binding, and the
/// Governor-injected execution carrier (all already checked present by
/// [`dispatch_admitted`]). Then, genuinely and in order: resolves the
/// owner-published closed registry, validates its closure and stable digest,
/// validates the bounded all-or-nothing routing policy, validates the screen
/// binding through the real owner check, requires the carrier to bring live
/// ports (an empty port set refuses at the genuine owner port boundary), and
/// routes the injected batch through the real
/// [`route_validated_curation`](eliot_dreamer_curation::route_validated_curation),
/// then composes the narrow Curation Product Pulse from the owner screen
/// binding, the protection assessment, the admitted batch, and the routed set,
/// and maps the candidate set plus that pulse onto [`DreamResult::Curation`].
/// Never returns `UnsupportedJobClass`.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the composition moves owned Governor inputs in; borrowing would break the pinned lib.rs call shape"
)]
pub(crate) fn dispatch_curation(
    screen: ScreenBinding,
    protection: CurationProtectionSet,
    carrier: CurationExecutionCarrier<'_>,
) -> Result<DreamResult, DreamerError> {
    let registry = canonical_registry().map_err(|error| dispatch_denied(&error))?;
    registry
        .validate_closure()
        .map_err(|error| dispatch_denied(&error))?;
    let _registry_digest = registry.digest().map_err(|error| dispatch_denied(&error))?;
    let policy = curation_routing_policy();
    policy.validate().map_err(|error| curation_denied(&error))?;
    screen.validate().map_err(|error| dispatch_denied(&error))?;
    if screen.state != ScreenState::Eligible {
        return Err(DreamerError::InvalidAdmission("screen ineligible"));
    }
    // The assessment must cover exactly the members this binding admitted, so a
    // parallel or stale protection record can never narrate a different
    // operation than the one being routed.
    if protection.screened_targets != screen.screened_targets
        || protection.members.len() != protection.screened_targets.len()
    {
        return Err(DreamerError::InvalidAdmission(CURATION_PROTECTION_REFUSAL));
    }
    if carrier.ports.ports.is_empty() {
        return Err(curation_port_boundary_refusal(
            &registry,
            &carrier.batch.owner_pins,
            &carrier.ports,
        ));
    }
    let set = route_validated_curation(&carrier.batch, &screen, &registry, &policy, &carrier.ports)
        .map_err(|error| curation_denied(&error))?;
    let pulse = compose_curation_pulse(&screen, &protection, &carrier.batch, &set)?;
    map_curation_set(&set, pulse)
}

/// Renders one owner protection assessment as the receipt phrase that names
/// what the admission actually declared.
///
/// `Protected` cites the admitted declaration verbatim; `Unknown` says plainly
/// that no evidence was admitted, because a missing finding must never be
/// spelled as clearance.
fn protection_phrase(assessment: &CurationProtection) -> String {
    match assessment.class {
        Some(class) => format!(
            "owner declared {class} protection on {member} (declared reference: {reference})",
            class = protection_class_name(class),
            member = assessment.member_id,
            reference = assessment.owner_reference.as_deref().unwrap_or("absent"),
        ),
        None => format!(
            "no owner protection evidence was admitted for {member}; its protection state is unknown, not cleared",
            member = assessment.member_id,
        ),
    }
}

/// Closed wire name of one derived protection class.
fn protection_class_name(class: ProtectionClass) -> &'static str {
    match class {
        ProtectionClass::UnresolvedConflict => "UNRESOLVED_CONFLICT",
    }
}

/// Renders the member's protection findings, or states that none apply.
fn protection_summary(protection: &[CurationProtection]) -> String {
    if protection.is_empty() {
        return "this member transforms no screened target, so no owner protection finding applies"
            .to_owned();
    }
    protection
        .iter()
        .map(protection_phrase)
        .collect::<Vec<_>>()
        .join("; ")
}

/// I9.6 `support`: the evidence this routing record actually rests on.
///
/// Every value is a record the run produced — the two A-20 screen digests, the
/// dispatched request and sealed result digests, and the A-31 item's own
/// evidence references. It is deliberately NOT a usage count or a popularity
/// measure: A14.4 forbids frequent retrieval from strengthening a record, so
/// nothing popularity-shaped may enter this field.
fn candidate_support(
    pulse: &crate::CurationProductPulse,
    member: &CurationMemberOutcome,
    result_digest: &str,
) -> String {
    let evidence_refs = if member.evidence_refs.is_empty() {
        "none supplied by the routed item".to_owned()
    } else {
        member.evidence_refs.join(", ")
    };
    format!(
        "A-20 screen result {screen_result} and screen item {screen_item} admitted this member; \
         A-31 dispatched request digest {request} to handler {handler} after {calls} call(s) and \
         received result digest {result}; routed item evidence references: {evidence_refs}",
        screen_result = pulse.screen_result_digest,
        screen_item = pulse.screen_item_digest,
        request = member.request_digest.as_deref().unwrap_or("absent"),
        handler = member.handler_id,
        calls = member.calls,
        result = result_digest,
        evidence_refs = evidence_refs,
    )
}

/// I9.6 `counterevidence`: what counts against this candidate, stated from the
/// owner record rather than softened away.
///
/// A protected target and an unassessed one both appear here, which is what
/// keeps a protected exact-negative record distinguishable from an ordinary
/// one in the emitted receipt.
fn candidate_counterevidence(
    finding: &crate::CurationMemberFinding,
    protection: &[CurationProtection],
) -> String {
    use std::fmt::Write as _;

    let mut text = protection_summary(protection);
    if let Some(hint) = &finding.rejection_hint {
        // `write!` on a String is infallible, so the result is deliberately
        // discarded rather than surfaced as a fallible branch.
        let _ = write!(
            text,
            "; A-31 routing rejection hint for this member: {hint}"
        );
    }
    if finding.calls != 1 {
        let _ = write!(
            text,
            "; this member recorded {} handler call(s), so it carries no live handler result",
            finding.calls
        );
    }
    text
}

/// I9.6 `scope_and_applicability`: the exact operation the candidate is
/// proposed under, plus the handles it would touch.
///
/// Applicability is bound to the receipt's `state_fence` by reference rather
/// than restated, so the candidate can never claim a fence the pulse did not
/// run under.
fn candidate_scope(pulse: &crate::CurationProductPulse, member: &CurationMemberOutcome) -> String {
    let targets = if member.targets.is_empty() {
        "no mutable target".to_owned()
    } else {
        member.targets.join(", ")
    };
    let evidence_refs = if member.evidence_refs.is_empty() {
        "none".to_owned()
    } else {
        member.evidence_refs.join(", ")
    };
    format!(
        "applies to task {task} in scope {scope} under request {request} at dispatch attempt {attempt}, \
         bounded by the receipt state_fence; proposed mutable targets: {targets}; immutable evidence references: {evidence_refs}",
        task = pulse.task_id,
        scope = pulse.scope_id,
        request = pulse.request_id,
        attempt = pulse.attempt,
        targets = targets,
        evidence_refs = evidence_refs,
    )
}

/// I9.6 `preservation_report`: what this record preserved and what it did not
/// touch.
///
/// Candidate-only and honest: no source mutation was performed, and the owner
/// protection assessment for every target this member would transform is
/// restated here so a consumer reading only the candidate list still sees it.
/// A14.4 holds because a contested member is preserved and reported — never
/// dropped, and never silently merged away.
fn candidate_preservation(
    member: &CurationMemberOutcome,
    protection: &[CurationProtection],
) -> String {
    format!(
        "no source mutation was performed: candidate {member_id} ({kind}) is a routing record sealed by handler {handler} \
         under routing disposition {disposition}; owner protection findings: {protection_summary}",
        member_id = member.member_id,
        kind = member.kind.as_str(),
        handler = member.handler_id,
        disposition = member.disposition.as_str(),
        protection_summary = protection_summary(protection),
    )
}

/// Maps one routed A-31 candidate set onto the crate curation result.
///
/// One [`CurationCandidate`] per member with a live candidate disposition and
/// exactly one handler call: rejected (duplicate/conflict/abstention/
/// unsupported), blocked (blocked/partial/internal-defect), and unprocessed
/// members carry no sealed content and never surface as candidates. Under the
/// all-or-nothing policy the router already fails closed on any such member,
/// so the filter is defense-in-depth, never a silent drop.
///
/// Honest routing-record mapping: handler content stays Governor-sealed, so
/// the transformation and rollback texts name the sealing handler, the sealed
/// result digest, and the owner routing note instead of inventing content.
/// Provenance carries the omitted targets plus the denominator members
/// (G4-like lineage: what the set covered and what it left uncovered). A set
/// with zero accepted members refuses fail-closed instead of returning an
/// empty success. The composed Curation Product Pulse travels alongside the
/// candidate list, so the receipt always names the route, identities,
/// disposition, omissions, and proof ceiling the candidates came from.
///
/// The I9.6 candidate fields `support`, `counterevidence`,
/// `scope_and_applicability`, and `preservation_report` are filled from the
/// records this run produced, never from a fixed sentence: the pulse's own
/// finding for the member supplies the A-20 protection assessment, the A-31
/// member supplies its digests, evidence references, disposition, and routing
/// note, and the pulse supplies the screen digests and the operation identity
/// the candidate is applicable under. A member whose target carried an owner
/// protection declaration therefore states that declaration in
/// `counterevidence` and `preservation_report` instead of reading as an
/// ordinary candidate.
fn map_curation_set(
    set: &CurationCandidateSet,
    pulse: crate::CurationProductPulse,
) -> Result<DreamResult, DreamerError> {
    let mut candidates = Vec::with_capacity(set.members.len());
    for member in &set.members {
        if member.disposition != RoutingDisposition::Candidate || member.calls != 1 {
            continue;
        }
        let result_digest = member.result_digest.as_deref().unwrap_or("absent");
        // The member's protection findings come from the pulse finding for
        // that exact member, so the candidate and the receipt state one
        // assessment rather than two derivations of it.
        let finding = pulse
            .findings
            .iter()
            .find(|finding| finding.member_id == member.member_id)
            .ok_or(DreamerError::InvalidAdmission(
                crate::curation_pulse::PROTECTION_FINDING_REFUSAL,
            ))?;
        let protection = finding.protection.as_slice();
        candidates.push(CurationCandidate {
            candidate_id: member.member_id.clone(),
            kind: member.kind.as_str().to_owned(),
            source_handles: member.targets.clone(),
            support: candidate_support(&pulse, member, result_digest),
            counterevidence: candidate_counterevidence(finding, protection),
            scope_and_applicability: candidate_scope(&pulse, member),
            preservation_report: candidate_preservation(member, protection),
            proposed_transformation: format!(
                "routing record: handler {handler_id} sealed a live candidate under result digest {result_digest}; owner note: {note}; content stays Governor-sealed, this record maps the routing outcome only",
                handler_id = member.handler_id, note = member.note,
            ),
            uncertainty: "candidate_only; content sealed under result digest".to_owned(),
            rollback: format!(
                "routing record: discard candidate {member_id} ({kind}) sealed by handler {handler_id}; no source mutation was performed",
                member_id = member.member_id, kind = member.kind.as_str(), handler_id = member.handler_id,
            ),
        });
    }
    if candidates.is_empty() {
        return Err(DreamerError::InvalidAdmission(CURATION_EMPTY_REFUSAL));
    }
    let mut provenance = Vec::new();
    for handle in set
        .omitted_targets
        .iter()
        .chain(set.denominator.members.iter())
    {
        if !provenance.contains(handle) {
            provenance.push(handle.clone());
        }
    }
    Ok(DreamResult::Curation {
        job_id: set.job_id.clone(),
        candidates,
        provenance,
        pulse,
    })
}

/// Runs the genuine owner port-boundary check and maps its terminal refusal.
///
/// Validates the carrier port set against the closed registry and the batch
/// pins through the real owner
/// [`NativeCurationPortSet::validate`](eliot_dreamer_curation::NativeCurationPortSet::validate).
/// An empty carrier set always fails the exact-ten requirement, and the owner
/// error maps to the precise live-ports refusal. The `Ok` arm is
/// defensive-unreachable (an empty set can never satisfy the owner) and
/// refuses identically: there are still no live ports to dispatch through.
/// No handler is constructed, counted, or invoked on any path.
fn curation_port_boundary_refusal(
    registry: &CurationHandlerRegistry,
    pins: &[OwnerRevisionPin],
    ports: &NativeCurationPortSet<'_>,
) -> DreamerError {
    match ports.validate(registry, pins) {
        Err(error) => curation_denied(&error),
        Ok(()) => DreamerError::InvalidAdmission(CURATION_PORTS_REFUSAL),
    }
}

/// Maps a native curation routing refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code and never `UnsupportedJobClass`: the
/// admission was valid and A-31 owns the class, the routing inputs were not.
/// Dynamic payloads (digests, handler identities, reasons) are dropped in
/// favor of bounded static field names, except the port boundary, which maps
/// to the precise live-ports refusal naming the missing Governor injection.
/// Exhaustive with no wildcard arm: extending the owner error taxonomy breaks
/// compilation here until the new refusal is assigned a mapping.
fn curation_denied(error: &CurationRoutingError) -> DreamerError {
    match error {
        CurationRoutingError::Batch { field, .. } | CurationRoutingError::Binding { field, .. } => {
            DreamerError::InvalidAdmission(field)
        }
        CurationRoutingError::Receipt { .. } => {
            DreamerError::InvalidAdmission("validation receipt")
        }
        CurationRoutingError::Screen { .. } => DreamerError::InvalidAdmission("curation screen"),
        CurationRoutingError::Registry { .. } => {
            DreamerError::InvalidAdmission("handler registry conflict")
        }
        CurationRoutingError::Port { .. } => DreamerError::InvalidAdmission(CURATION_PORTS_REFUSAL),
        CurationRoutingError::Policy { .. } => DreamerError::InvalidAdmission("curation policy"),
        CurationRoutingError::Denominator { .. } => {
            DreamerError::InvalidAdmission("curation denominator")
        }
        CurationRoutingError::Handler { .. } | CurationRoutingError::HandlerPanicked { .. } => {
            DreamerError::InvalidAdmission("curation handler")
        }
        CurationRoutingError::Envelope { .. } => {
            DreamerError::InvalidAdmission("curation envelope")
        }
        CurationRoutingError::Atomicity { .. } => {
            DreamerError::InvalidAdmission("curation atomicity")
        }
        CurationRoutingError::Digest { .. } => DreamerError::InvalidAdmission("curation digest"),
    }
}

/// Test-only Curation execution support: the fixture handler, the valid
/// batch bound to one screen, and the ten-port carrier assembled around it.
///
/// Production never builds these (live ports are Governor-injected); the
/// dispatch-level and pipeline e2e tests use this harness to prove the wired
/// A-31 path with real owner crates and no new dependencies.
#[cfg(test)]
pub(crate) mod curation_test_support {
    use super::*;
    use eliot_contracts::sha256_hex;
    use eliot_dreamer_contracts::candidate::{
        DimensionVerdict, PRESERVATION_DIMENSIONS, PreservationDimension, PreservationReport,
    };
    use eliot_dreamer_contracts::curation::{ClassificationPayload, TargetEvidence, kind_family};
    use eliot_dreamer_contracts::registry::{
        CURATION_FAMILIES, CurationFamily, CurationHandlerPort,
    };
    use eliot_dreamer_contracts::{
        AtomicityMode, BoundCurationCall, CandidateDisposition, CurationKind, CurationPayload,
        NativeCurationHandler, ProducedCurationContent, TargetDenominator, ValidatedCurationItem,
        ValidationReceipt, parse_family,
    };
    use eliot_dreamer_curation::{
        NativeCurationPort, compute_input_digest, expected_owner_package,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fail-closed reason when the test harness cannot bind its fixture batch
    /// to the given screen, admission, and job.
    const HARNESS_BINDING_REFUSAL: &str = "curation test harness binding invalid";

    /// Revision pinned per owner family and matched by every injected port.
    const HARNESS_REVISION: &str = "test-rev-1";

    /// Test-only routing handler: echoes the dispatched payload as a live
    /// candidate with passing preservation, so the payload kind always equals
    /// the item kind, targets travel reverbatim, and counterevidence stays
    /// disjoint from mutable targets by construction (empty).
    pub(crate) struct TestRoutingHandler;

    impl NativeCurationHandler for TestRoutingHandler {
        fn handle(
            &self,
            call: &BoundCurationCall,
        ) -> Result<ProducedCurationContent, ContractViolation> {
            let mut verdicts = Vec::with_capacity(PRESERVATION_DIMENSIONS.len());
            for spelling in PRESERVATION_DIMENSIONS {
                verdicts.push(DimensionVerdict {
                    dimension: PreservationDimension::parse(spelling)?,
                    passed: true,
                    known: true,
                    note: "test routing handler preserves the dispatched payload verbatim"
                        .to_owned(),
                });
            }
            Ok(ProducedCurationContent {
                payload: call.request.payload.clone(),
                disposition: CandidateDisposition::Candidate,
                preservation: PreservationReport { verdicts },
                support_note: "test routing handler echoes the dispatched payload".to_owned(),
                rollback_note: "discard the routed candidate; no source mutation ran".to_owned(),
                counterevidence_refs: Vec::new(),
            })
        }
    }

    /// Owned port binding halves: the registry descriptor plus the owner
    /// package and revision the live port must carry. Stored owned because
    /// the live [`NativeCurationPort`] borrows the harness handler and
    /// cannot live inside the harness itself.
    struct HarnessPortBinding {
        port: CurationHandlerPort,
        owner_package: String,
        owner_revision: String,
    }

    /// Test harness owning one routing handler plus the valid batch bound to
    /// one screen binding.
    pub(crate) struct CurationTestHarness {
        handler: TestRoutingHandler,
        batch: ValidatedCurationBatch,
        port_bindings: Vec<HarnessPortBinding>,
    }

    /// Deterministic 64-hex fixture digest over one label.
    fn harness_hex(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    /// Builds the shape-valid A-05 receipt backing the fixture batch: every
    /// digest is well-formed hex, and the bundle/manifest digests plus the
    /// task/scope/fence triple equal the batch envelope so the owner
    /// uniformity check binds.
    fn harness_receipt(
        job_id: &str,
        bundle_digest: &str,
        manifest_digest: &str,
        binding: &ScreenBinding,
    ) -> Result<ValidationReceipt, DreamerError> {
        let receipt = ValidationReceipt {
            schema_version: 1,
            validator_contract: "curation-test-harness".to_owned(),
            validator_policy: "curation-test-policy".to_owned(),
            job_id: job_id.to_owned(),
            draft_digest: harness_hex(&format!("{job_id}:draft")),
            bundle_digest: bundle_digest.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            task_id: binding.task_id.clone(),
            scope_id: binding.scope_id.clone(),
            input_digest: harness_hex(&format!("{job_id}:validator-input")),
            output_digest: harness_hex(&format!("{job_id}:validator-output")),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            state_fence: binding.state_fence.clone(),
            preservation_digest: harness_hex(&format!("{job_id}:preservation")),
            budget_digest: harness_hex(&format!("{job_id}:budget")),
        };
        receipt
            .validate()
            .map_err(|_| DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL))?;
        Ok(receipt)
    }

    /// Builds one fixture item per screened target using the simplest payload
    /// kind (Classification): one mutable target, one disjoint evidence
    /// handle, and a per-item all-or-nothing denominator covering exactly
    /// that target, so the batch union covers the screen denominator exactly.
    fn harness_item(
        target: &str,
        index: usize,
        receipt: &ValidationReceipt,
        binding: &ScreenBinding,
        job_id: &str,
        requester: &eliot_dreamer_contracts::Requester,
    ) -> Result<ValidatedCurationItem, DreamerError> {
        let evidence = format!("evidence-{index}");
        if binding.screened_targets.contains(&evidence) {
            return Err(DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL));
        }
        let payload = CurationPayload::Classification(ClassificationPayload {
            label: "test-routing-fixture".to_owned(),
            confidence_bps: 9_000,
            target_evidence: TargetEvidence {
                targets: vec![target.to_owned()],
                evidence_refs: vec![evidence],
            },
        });
        let item = ValidatedCurationItem {
            receipt: receipt.clone(),
            kind_spelling: CurationKind::Classification.as_str().to_owned(),
            family_spelling: kind_family(CurationKind::Classification).to_owned(),
            payload,
            denominator: TargetDenominator {
                mode: AtomicityMode::AllOrNothing,
                members: vec![target.to_owned()],
                expected_total: 1,
            },
            source_digest: harness_hex(&format!("{job_id}:source:{target}")),
            task_id: binding.task_id.clone(),
            scope_id: binding.scope_id.clone(),
            state_fence: binding.state_fence.clone(),
            job_digest: harness_hex(&format!("{job_id}:job")),
            requester: requester.clone(),
            budget_note: "test harness batch; within admitted ceilings".to_owned(),
        };
        item.validate()
            .map_err(|_| DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL))?;
        Ok(item)
    }

    /// Builds the batch bound to one screen: request/task/scope/fence
    /// identities from that screen, denominator members equal to the screened
    /// targets, registry digest from the real closed registry, one revision
    /// pin per family in canonical order, budgets and usage from the
    /// admitted ceilings, and the input digest from the real owner seal over
    /// batch, screen, registry digest, and the shared routing policy.
    fn harness_batch(
        binding: &ScreenBinding,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<ValidatedCurationBatch, DreamerError> {
        let invalid = || DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL);
        binding.validate().map_err(|_| invalid())?;
        if binding.state != ScreenState::Eligible {
            return Err(invalid());
        }
        let admitted = admission_of(admission, job)?;
        let job_id = admitted.canonical_id();
        let registry = canonical_registry().map_err(|_| invalid())?;
        let registry_digest = registry.digest().map_err(|_| invalid())?;
        let bundle_digest = harness_hex(&format!("{job_id}:bundle"));
        let manifest_digest = harness_hex(&format!("{job_id}:manifest"));
        let receipt = harness_receipt(&job_id, &bundle_digest, &manifest_digest, binding)?;
        let mut items = Vec::with_capacity(binding.screened_targets.len());
        for (index, target) in binding.screened_targets.iter().enumerate() {
            items.push(harness_item(
                target,
                index,
                &receipt,
                binding,
                &job_id,
                &admitted.requester,
            )?);
        }
        let expected_total =
            u32::try_from(binding.screened_targets.len()).map_err(|_| invalid())?;
        let owner_pins = CURATION_FAMILIES
            .iter()
            .map(|spelling| {
                parse_family(spelling).map(|family| OwnerRevisionPin {
                    family,
                    revision: HARNESS_REVISION.to_owned(),
                })
            })
            .collect::<Result<Vec<OwnerRevisionPin>, ContractViolation>>()
            .map_err(|_| invalid())?;
        let budgets = admitted.budget;
        let usage = usage_of(&budgets);
        let policy = curation_routing_policy();
        let mut batch = ValidatedCurationBatch {
            job_id,
            request_id: binding.request_id.as_str().to_owned(),
            operation_id: admission.request_id.clone(),
            idempotency_key: admission.idempotency_key.clone(),
            requester: admitted.requester.clone(),
            task_id: binding.task_id.clone(),
            attempt: 1,
            scope_id: binding.scope_id.clone(),
            state_fence: binding.state_fence.clone(),
            bundle_digest,
            manifest_digest,
            grounding_digest: harness_hex("curation-test-harness:grounding"),
            receipt,
            items,
            denominator: TargetDenominator {
                mode: AtomicityMode::AllOrNothing,
                members: binding.screened_targets.clone(),
                expected_total,
            },
            privacy_profile: admitted.privacy_profile.clone(),
            authority_ref: "test-harness: no authority exercised".to_owned(),
            effect_note: "test-harness routing only; no effect exercised".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            atomicity: AtomicityMode::AllOrNothing,
            budgets,
            usage,
            deadline_ms: None,
            observation_time_ms: None,
            cancelled: false,
            predecessor_digests: Vec::new(),
            invalidation_note: "test-harness batch; no invalidation".to_owned(),
            registry_digest: registry_digest.clone(),
            owner_pins,
            input_digest: "0".repeat(64),
        };
        batch.input_digest = compute_input_digest(&batch, binding, &registry_digest, &policy)
            .map_err(|_| invalid())?;
        batch
            .validate()
            .map_err(|_| DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL))?;
        Ok(batch)
    }

    /// Builds the ten owned port halves from the real registry descriptors:
    /// byte-equal descriptors, the real expected owner package per family,
    /// and pin-matching revisions.
    fn harness_port_bindings(
        registry: &CurationHandlerRegistry,
    ) -> Result<Vec<HarnessPortBinding>, DreamerError> {
        let invalid = || DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL);
        let mut bindings = Vec::with_capacity(CURATION_FAMILIES.len());
        for spelling in CURATION_FAMILIES {
            let family = parse_family(spelling).map_err(|_| invalid())?;
            let declared = registry
                .handlers
                .iter()
                .find(|item| item.family == family)
                .ok_or_else(invalid)?;
            bindings.push(HarnessPortBinding {
                port: CurationHandlerPort {
                    port_id: format!("test-port-{}", family.as_str()),
                    descriptor: declared.clone(),
                },
                owner_package: expected_owner_package(family).to_owned(),
                owner_revision: HARNESS_REVISION.to_owned(),
            });
        }
        Ok(bindings)
    }

    impl CurationTestHarness {
        /// Builds the harness for one screen binding: the batch bound to
        /// that screen (request/task/scope/fence identities, denominator
        /// members, registry digest, owner pins, admitted budgets, sealed
        /// input digest) plus the ten owned port halves.
        pub(crate) fn for_screen(
            binding: &ScreenBinding,
            admission: &KernelJobAdmission,
            job: &DreamJobInput,
        ) -> Result<Self, DreamerError> {
            let invalid = || DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL);
            let registry = canonical_registry().map_err(|_| invalid())?;
            registry.validate_closure().map_err(|_| invalid())?;
            Ok(Self {
                handler: TestRoutingHandler,
                batch: harness_batch(binding, admission, job)?,
                port_bindings: harness_port_bindings(&registry)?,
            })
        }

        /// Builds the Governor-injected execution carrier around the
        /// harness handler: the ten-port set from the real registry
        /// descriptors with expected owner packages and pin-matching
        /// revisions, borrowing the owned test handler for every port (only
        /// the dispatched family is ever called).
        pub(crate) fn carrier(&self) -> CurationExecutionCarrier<'_> {
            let ports = self
                .port_bindings
                .iter()
                .map(|binding| NativeCurationPort {
                    port: binding.port.clone(),
                    owner_package: binding.owner_package.clone(),
                    owner_revision: binding.owner_revision.clone(),
                    handler: &self.handler,
                })
                .collect();
            CurationExecutionCarrier {
                batch: self.batch.clone(),
                ports: NativeCurationPortSet { ports },
            }
        }

        /// Returns the fixture batch bound to the screen, for boundary
        /// probes (e.g. pairing it with an empty port set) and assertions.
        pub(crate) fn batch(&self) -> &ValidatedCurationBatch {
            &self.batch
        }
    }

    /// Test-only counting routing handler for submit-path proofs: delegates
    /// the echo to [`TestRoutingHandler`] while counting invocations, so the
    /// public `submit` tests prove A-31 ran exactly once. Owns only the
    /// counter, so carrier sources built around it stay borrow-free.
    pub(crate) struct CountingRoutingHandler {
        calls: AtomicU64,
    }

    impl CountingRoutingHandler {
        /// Builds an uncalled counting handler.
        pub(crate) fn new() -> Self {
            Self {
                calls: AtomicU64::new(0),
            }
        }

        /// Returns the number of routed handler invocations so far.
        pub(crate) fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Default for CountingRoutingHandler {
        fn default() -> Self {
            Self::new()
        }
    }

    impl NativeCurationHandler for CountingRoutingHandler {
        fn handle(
            &self,
            call: &BoundCurationCall,
        ) -> Result<ProducedCurationContent, ContractViolation> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            TestRoutingHandler.handle(call)
        }
    }

    /// Owned port binding halves for test carrier sources: the registry
    /// descriptor plus the owner package and revision the live port must
    /// carry. Stored owned because the live [`NativeCurationPort`] borrows
    /// the source handler and cannot live inside the source itself.
    pub(crate) struct TestPortBinding {
        /// Registry descriptor, byte-equal to the closed registry entry.
        pub(crate) port: CurationHandlerPort,
        /// Real expected owner package for the descriptor family.
        pub(crate) owner_package: String,
        /// Pin-matching revision for the batch owner pins.
        pub(crate) owner_revision: String,
    }

    /// Builds the ten owned port halves from the real registry descriptors:
    /// delegates to the private harness builder so the descriptor/package/
    /// revision logic lives in exactly one place.
    pub(crate) fn test_port_bindings() -> Result<Vec<TestPortBinding>, DreamerError> {
        let invalid = || DreamerError::InvalidAdmission(HARNESS_BINDING_REFUSAL);
        let registry = canonical_registry().map_err(|_| invalid())?;
        registry.validate_closure().map_err(|_| invalid())?;
        Ok(harness_port_bindings(&registry)?
            .into_iter()
            .map(|binding| TestPortBinding {
                port: binding.port,
                owner_package: binding.owner_package,
                owner_revision: binding.owner_revision,
            })
            .collect())
    }

    /// Builds the fixture batch bound to one screen without assembling ports:
    /// delegates to the private harness builder so the digest/pin/seal logic
    /// lives in exactly one place and is never duplicated by hand. Test
    /// carrier sources reuse this for the presented screen, admission, and
    /// job, then wrap it in ports around their own handler.
    pub(crate) fn test_batch_for(
        screen: &ScreenBinding,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<ValidatedCurationBatch, DreamerError> {
        harness_batch(screen, admission, job)
    }

    /// Builds one bound fixture call over a single target, mirroring the
    /// handler-content proof below, so the counting-handler proof reuses the
    /// same valid call shape instead of rebuilding it by hand.
    fn harness_bound_call(target: &str) -> BoundCurationCall {
        use eliot_dreamer_contracts::registry::CurationHandlerDescriptor;

        let screen = harness_screen(&[target]);
        let receipt = harness_receipt(
            "job-harness",
            &harness_hex("job-harness:bundle"),
            &harness_hex("job-harness:manifest"),
            &screen,
        )
        .expect("harness receipt must validate");
        let requester = eliot_dreamer_contracts::Requester {
            origin: eliot_dreamer_contracts::RequesterOrigin::Human,
            principal: "harness".to_owned(),
            session: None,
        };
        let item = harness_item(
            "target-harness",
            0,
            &receipt,
            &screen,
            "job-harness",
            &requester,
        )
        .expect("harness item must validate");
        let payload = item.payload.clone();
        BoundCurationCall {
            port: CurationHandlerPort {
                port_id: "harness-port".to_owned(),
                descriptor: CurationHandlerDescriptor {
                    family: CurationFamily::Classification,
                    handler_id: "harness-check".to_owned(),
                    accepted_kinds: vec![CurationKind::Classification],
                },
            },
            item,
            request: eliot_dreamer_contracts::TypedCurationHandlerRequest {
                request_id: screen.request_id.as_str().to_owned(),
                receipt_id: screen.receipt_id.as_str().to_owned(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                profile: screen.profile.clone(),
                kind: CurationKind::Classification,
                family: CurationFamily::Classification,
                job_id: "job-harness".to_owned(),
                scope_id: screen.scope_id.clone(),
                task_id: screen.task_id.clone(),
                state_fence: screen.state_fence.clone(),
                payload,
                denominator: TargetDenominator {
                    mode: AtomicityMode::AllOrNothing,
                    members: vec!["target-harness".to_owned()],
                    expected_total: 1,
                },
                screen_binding: Some(screen),
            },
            registry_digest: "c".repeat(64),
        }
    }

    /// The counting handler echoes like the fixture handler, counts exactly
    /// one call per invocation, and the owned port halves cover every
    /// canonical family with pin-matching revisions.
    #[test]
    fn counting_handler_echoes_and_counts_with_full_port_coverage() {
        let handler = CountingRoutingHandler::new();
        assert_eq!(handler.calls(), 0);
        let call = harness_bound_call("target-harness");
        for _ in 0..2 {
            let content = handler
                .handle(&call)
                .expect("echo handler must produce content");
            assert_eq!(content.payload, call.request.payload);
            assert_eq!(content.disposition, CandidateDisposition::Candidate);
            assert!(content.preservation.overall().is_ok());
            assert!(content.counterevidence_refs.is_empty());
            assert!(
                content.validate_for(&call).is_ok(),
                "echoed content must satisfy the bound call"
            );
        }
        assert_eq!(handler.calls(), 2);
        let bindings = test_port_bindings().expect("port halves must build");
        assert_eq!(bindings.len(), CURATION_FAMILIES.len());
        for binding in &bindings {
            assert_eq!(binding.owner_revision, HARNESS_REVISION);
            assert!(
                !binding.owner_package.trim().is_empty(),
                "every port half must name its owner package"
            );
            assert!(
                !binding.port.port_id.trim().is_empty(),
                "every port half must carry a port identity"
            );
        }
    }
    /// The fixture handler echoes the dispatched payload with passing
    /// preservation and disjoint counterevidence, satisfying every
    /// `ProducedCurationContent` rule the owner enforces.
    #[test]
    fn test_routing_handler_produces_valid_content() {
        use eliot_dreamer_contracts::registry::CurationHandlerDescriptor;

        let screen = harness_screen(&["target-harness"]);
        let Ok(receipt) = harness_receipt(
            "job-harness",
            &harness_hex("job-harness:bundle"),
            &harness_hex("job-harness:manifest"),
            &screen,
        ) else {
            panic!("harness receipt must validate");
        };
        let requester = eliot_dreamer_contracts::Requester {
            origin: eliot_dreamer_contracts::RequesterOrigin::Human,
            principal: "harness".to_owned(),
            session: None,
        };
        let Ok(item) = harness_item(
            "target-harness",
            0,
            &receipt,
            &screen,
            "job-harness",
            &requester,
        ) else {
            panic!("harness item must validate");
        };
        let payload = item.payload.clone();
        let descriptor = CurationHandlerDescriptor {
            family: CurationFamily::Classification,
            handler_id: "harness-check".to_owned(),
            accepted_kinds: vec![CurationKind::Classification],
        };
        let handler = TestRoutingHandler;
        let call = BoundCurationCall {
            port: CurationHandlerPort {
                port_id: "harness-port".to_owned(),
                descriptor,
            },
            item,
            request: eliot_dreamer_contracts::TypedCurationHandlerRequest {
                request_id: screen.request_id.as_str().to_owned(),
                receipt_id: screen.receipt_id.as_str().to_owned(),
                source_snapshot: screen.source_snapshot.clone(),
                source_revision: screen.source_revision.clone(),
                profile: screen.profile.clone(),
                kind: CurationKind::Classification,
                family: CurationFamily::Classification,
                job_id: "job-harness".to_owned(),
                scope_id: screen.scope_id.clone(),
                task_id: screen.task_id.clone(),
                state_fence: screen.state_fence.clone(),
                payload: payload.clone(),
                denominator: TargetDenominator {
                    mode: AtomicityMode::AllOrNothing,
                    members: vec!["target-harness".to_owned()],
                    expected_total: 1,
                },
                screen_binding: Some(screen.clone()),
            },
            registry_digest: "c".repeat(64),
        };
        let content = handler.handle(&call);
        let Ok(content) = content else {
            panic!("echo handler must produce content");
        };
        assert_eq!(content.payload, payload);
        assert_eq!(content.disposition, CandidateDisposition::Candidate);
        assert!(content.preservation.overall().is_ok());
        assert!(!content.support_note.trim().is_empty());
        assert!(!content.rollback_note.trim().is_empty());
        assert!(content.counterevidence_refs.is_empty());
        assert!(
            content.validate_for(&call).is_ok(),
            "echoed content must satisfy the bound call"
        );
    }

    /// Builds one eligible fixture screen over the given targets.
    fn harness_screen(targets: &[&str]) -> ScreenBinding {
        ScreenBinding {
            request_id: binding_request_id(),
            receipt_id: binding_receipt_id(),
            screened_targets: targets.iter().map(|target| (*target).to_owned()).collect(),
            source_snapshot: "snapshot-harness".to_owned(),
            source_revision: "revision-harness".to_owned(),
            profile: "profile-harness".to_owned(),
            task_id: "task-harness".to_owned(),
            scope_id: "scope-harness".to_owned(),
            state_fence: binding_fence(),
            state: ScreenState::Eligible,
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
        }
    }

    fn binding_fence() -> eliot_contracts::StateFence {
        use std::num::NonZeroU64;

        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};

        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("harness lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("harness sequence must be nonzero");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("harness epoch must construct");
        };
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn binding_request_id() -> eliot_contracts::RequestId {
        let Ok(id) = eliot_contracts::RequestId::new("req-harness") else {
            panic!("harness request id must parse");
        };
        id
    }

    fn binding_receipt_id() -> eliot_contracts::ReceiptId {
        let Ok(id) = eliot_contracts::ReceiptId::new("rcpt-harness") else {
            panic!("harness receipt id must parse");
        };
        id
    }
}

#[cfg(test)]
mod slice_7_dispatch_tests {
    use super::*;

    /// Every native owner refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("governor.validated_draft"),
            ContractViolation::ImplicitDefault("schema_version"),
            ContractViolation::CrossStage("validated"),
            ContractViolation::UnknownVariant {
                field: "job_class",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "draft.revision",
                min: 1,
                max: 1,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "dispatch.draft",
                reason: "draft differs".to_owned(),
            },
            ContractViolation::Malformed {
                field: "draft.content",
                reason: "blank".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "model_calls",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = dispatch_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "owner refusal must not borrow the Kernel-admission code"
            );
        }
    }
}

#[cfg(test)]
mod slice_7_native_owner_tests {
    use super::*;
    use std::num::NonZeroU64;

    use crate::KERNEL_ADMISSION_REQUIRED;
    use curation_test_support::CurationTestHarness;
    use eliot_contracts::{
        EpochId, EpochLineageId, ReceiptId, RequestId, ResourceGeneration, StateFence,
    };
    use eliot_dreamer_contracts::{ScreenBinding, ScreenState};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SCOPE: &str = "scope-slice-7";
    const TASK: &str = "task-slice-7";
    const OPERATION: &str = "op-slice-7";
    const QUESTION: &str = "What does ELIOT know about this scope?";
    const CONFLICT: &str = "conflict-slice-7";

    fn fence() -> StateFence {
        let Ok(lineage) = EpochLineageId::new(TEST_LINEAGE) else {
            panic!("valid test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("nonzero test sequence must construct");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("valid test epoch must construct");
        };
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission() -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-slice-7".to_owned(),
            attempt_id: "attempt-slice-7".to_owned(),
            scope_id: SCOPE.to_owned(),
            request_id: OPERATION.to_owned(),
            idempotency_key: "job-slice-7:attempt-slice-7".to_owned(),
            cancellation_id: "cancel-slice-7".to_owned(),
            deadline_unix_ms: u64::MAX,
            state_fence: fence(),
        }
    }

    fn semantic_job(job_class: JobClass) -> DreamJobInput {
        DreamJobInput {
            job_id: "job-slice-7".to_owned(),
            job_class,
            exact_question: QUESTION.to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: SCOPE.to_owned(),
            task_id: Some(TASK.to_owned()),
            state_fence: fence(),
            evidence_handles: vec!["evidence-slice-7".to_owned()],
            memory_handles: vec!["memory-slice-7".to_owned()],
            architecture_handles: vec!["architecture-slice-7".to_owned()],
            implementation_handles: vec!["implementation-slice-7".to_owned()],
            conformance_handles: vec!["conformance-slice-7".to_owned()],
            conflicts_and_unknowns: vec![CONFLICT.to_owned()],
            privacy_profile: "local_only".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".to_owned(),
            forbidden_effects: Vec::new(),
        }
    }

    fn valid_screen() -> ScreenBinding {
        let Ok(request_id) = RequestId::new("req-slice-7") else {
            panic!("fixture request id must parse");
        };
        let Ok(receipt_id) = ReceiptId::new("rcpt-slice-7") else {
            panic!("fixture receipt id must parse");
        };
        ScreenBinding {
            request_id,
            receipt_id,
            screened_targets: vec!["target-slice-7".to_owned()],
            source_snapshot: "snapshot-slice-7".to_owned(),
            source_revision: "revision-slice-7".to_owned(),
            profile: "profile-slice-7".to_owned(),
            task_id: TASK.to_owned(),
            scope_id: SCOPE.to_owned(),
            state_fence: fence(),
            state: ScreenState::Eligible,
            result_digest: "a".repeat(64),
            item_digest: "b".repeat(64),
        }
    }

    fn harness_for_fixture() -> CurationTestHarness {
        let screen = valid_screen();
        match CurationTestHarness::for_screen(
            &screen,
            &admission(),
            &semantic_job(JobClass::Curation),
        ) {
            Ok(harness) => harness,
            Err(error) => panic!("fixture harness must build, got {error:?}"),
        }
    }

    /// Runs the genuine admitted chain up to the structured A-05 gate for one
    /// fixture job, returning the validated receipt dispatch requires **and**
    /// the grounding request the pipeline ran under.
    ///
    /// Both are returned because `dispatch_admitted` takes
    /// [`PipelineOrientationRecords`], which joins by reference the exact
    /// grounding request and validated candidate this chain produced. Handing
    /// it a rebuilt lookalike instead would let a later edit move the real
    /// grounding stage without the Orientation carrier noticing, which is
    /// precisely the "rebuild a lookalike" failure the owner's contract
    /// forbids. The grounding owner consumes its request by value, so this
    /// retains a clone exactly as production does.
    ///
    /// Every stage genuinely invokes its owner; any refusal fails the proof.
    fn validated_for(
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> (
        GroundingRequest,
        eliot_dreamer_contracts::validation::structured::ValidatedGroundingCandidate,
    ) {
        let model_inputs = match crate::model_stage::resolve_model_inputs(admission, job, &[]) {
            Ok(inputs) => inputs,
            Err(error) => panic!("fixture model inputs must resolve, got {error:?}"),
        };
        let draft = match crate::model_stage::run_admitted_model(model_inputs) {
            Ok(draft) => draft,
            Err(error) => panic!("fixture model must prove, got {error:?}"),
        };
        let request =
            match crate::grounding_stage::resolve_grounding_inputs(admission, job, draft, &[]) {
                Ok(request) => request,
                Err(error) => panic!("fixture grounding must resolve, got {error:?}"),
            };
        let grounded = match crate::grounding_stage::ground_admitted_draft(request.clone()) {
            Ok(grounded) => grounded,
            Err(error) => panic!("fixture grounding must prove, got {error:?}"),
        };
        let carrier =
            match crate::admitted_material::validation_input_for(admission, job, grounded, Some(0))
            {
                Ok(carrier) => carrier,
                Err(error) => panic!("fixture carrier must build, got {error:?}"),
            };
        match crate::validation_stage::validate_admitted_draft(&carrier) {
            Ok(validated) => (request, validated),
            Err(error) => panic!("fixture carrier must validate, got {error:?}"),
        }
    }

    /// The owner carriers these cases exercise.
    ///
    /// `screen` and `curation_protection` are members of
    /// [`OwnerCarriers`] rather than separate `dispatch_admitted` parameters:
    /// both are derived from one screened binding, so passing them separately
    /// let a caller supply a protection set with no binding behind it. Each case
    /// names which carriers it supplies so the refusal it asserts stays the
    /// refusal the arm under test produces.
    fn carriers(
        curation: Option<CurationExecutionCarrier<'_>>,
        screen: Option<ScreenBinding>,
        curation_protection: Option<CurationProtectionSet>,
    ) -> OwnerCarriers<'_> {
        OwnerCarriers {
            curation,
            screen,
            curation_protection,
            orientation: None,
        }
    }

    /// Orientation genuinely projects from the admitted pair: the structured
    /// A-05 receipt is proved at the dispatch gate, then the v1 hypothesis
    /// pair validates through the real v1 A-05 entry, the owner
    /// `build_projection` succeeds, packet identity bindings travel verbatim,
    /// and the G4 residues are preserved in `rival_models_and_dissent`.
    #[test]
    fn orientation_projects_packet_with_g4_preserved() {
        let admission = admission();
        let job = semantic_job(JobClass::Orientation);
        let (grounding, validated) = validated_for(&admission, &job);
        let result = dispatch_admitted(
            &admission,
            &job,
            carriers(None, None, None),
            JobClass::Orientation,
            Some(&validated),
            Some(PipelineOrientationRecords::new(&grounding, &validated)),
        );
        let Ok(DreamResult::Packet(packet)) = result else {
            panic!("orientation must project, got {result:?}");
        };
        assert_eq!(packet.packet_id.len(), 64);
        assert_eq!(packet.question, QUESTION);
        assert_eq!(packet.scope_id, SCOPE);
        assert_eq!(packet.state_fence, job.state_fence);
        assert_eq!(packet.source_coverage.evidence, job.evidence_handles);
        assert_eq!(packet.source_coverage.memory, job.memory_handles);
        assert_eq!(
            packet.source_coverage.architecture,
            job.architecture_handles
        );
        assert_eq!(
            packet.source_coverage.implementation,
            job.implementation_handles
        );
        assert_eq!(packet.source_coverage.conformance, job.conformance_handles);
        assert_eq!(packet.synthesized_interpretations.len(), 1);
        let interpretation = &packet.synthesized_interpretations[0];
        assert_eq!(interpretation.statement, QUESTION);
        assert_eq!(interpretation.support_handles, job.evidence_handles);
        assert_eq!(interpretation.epistemic_status, "candidate_only");
        // ABSOLUTE G4 RULE: the admitted model carries no counterevidence
        // text, so the rival list is exactly the two owner residue texts —
        // neither marker dropped nor thinned.
        assert_eq!(
            packet.rival_models_and_dissent.len(),
            2,
            "rival list must carry exactly both residue markers, got {:?}",
            packet.rival_models_and_dissent
        );
        // The four screening-side families are accounted as omissions and
        // surface as unknowns, never silently dropped.
        assert_eq!(
            packet.unknowns_and_gaps.len(),
            4,
            "unknowns must account the four omitted families, got {:?}",
            packet.unknowns_and_gaps
        );
        assert_eq!(
            packet.recommended_probes_or_next_actions,
            Vec::<String>::new()
        );
        assert_eq!(packet.invalidation_conditions, vec![CONFLICT.to_owned()]);
        assert!(
            packet.provenance.contains(&OPERATION.to_owned()),
            "provenance must carry the projection-input proof, got {:?}",
            packet.provenance
        );
    }

    /// Orientation without evidence handles refuses at the frame source: the
    /// frame binds admitted bundle material and none is invented here. The
    /// structured gate passes first (it carries handles, not frame text), so
    /// this refusal proves the handler-specific gate fires after validation.
    #[test]
    fn orientation_without_evidence_refuses_frame_source() {
        let admission = admission();
        let mut job = semantic_job(JobClass::Orientation);
        job.evidence_handles.clear();
        let (grounding, validated) = validated_for(&admission, &job);
        let refused = dispatch_admitted(
            &admission,
            &job,
            carriers(None, None, None),
            JobClass::Orientation,
            Some(&validated),
            Some(PipelineOrientationRecords::new(&grounding, &validated)),
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(FRAME_SOURCE_REFUSAL))
            ),
            "evidenceless orientation must name the frame source, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// Orientation without the structured validated candidate refuses at the
    /// receipt gate before any v1 derivation or handler work: raw
    /// unvalidated input alone cannot dispatch, making bypass
    /// architecturally impossible through this seam.
    #[test]
    fn orientation_without_validated_refuses_receipt_gate() {
        let admission = admission();
        let job = semantic_job(JobClass::Orientation);
        // The pipeline record is built and supplied while the `validated`
        // receipt is deliberately withheld. That is what makes this case prove
        // the gate ORDER: an available pipeline record does not substitute for
        // the structured A-05 receipt, so the refusal is the receipt gate and
        // not the arm quietly proceeding on the record alone.
        let (grounding, validated) = validated_for(&admission, &job);
        let refused = dispatch_admitted(
            &admission,
            &job,
            carriers(None, None, None),
            JobClass::Orientation,
            None,
            Some(PipelineOrientationRecords::new(&grounding, &validated)),
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(VALIDATION_RECEIPT_REFUSAL))
            ),
            "orientation without a validated receipt must name it, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// A caller-switched job identity refuses with the Kernel-admission code
    /// before any owner work (and before the receipt gate: the binding check
    /// runs first, so no validated input is needed to prove it).
    #[test]
    fn switched_identity_refuses_before_owner() {
        let admission = admission();
        let mut job = semantic_job(JobClass::Orientation);
        job.job_id = "caller-switched-job".to_owned();
        let refused = dispatch_admitted(
            &admission,
            &job,
            carriers(None, None, None),
            JobClass::Orientation,
            None,
            // No pipeline record, and none can exist: the caller switched the
            // job identity, so `resolve_model_inputs` fails its
            // `verify_admitted_binding` check before any stage runs. That
            // refusal IS this case's subject, so building a record here would
            // mean asserting a pipeline that never executed.
            None,
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A class parameter that disagrees with the semantic job refuses at the
    /// class binding before any owner work (and before the receipt gate).
    #[test]
    fn class_parameter_mismatch_refuses_at_binding() {
        let admission = admission();
        let job = semantic_job(JobClass::Orientation);
        // The job is a real Orientation job, so the pipeline genuinely runs and
        // the record is genuine. The `job_class` argument is what disagrees; the
        // refusal must come from the binding check before that argument routes
        // anything, which is only observable when a valid record is present.
        let (grounding, validated) = validated_for(&admission, &job);
        let refused = dispatch_admitted(
            &admission,
            &job,
            carriers(None, None, None),
            JobClass::Curation,
            None,
            Some(PipelineOrientationRecords::new(&grounding, &validated)),
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("job class binding"))
            ),
            "class mismatch must refuse at the binding, got {refused:?}"
        );
    }

    /// Curation without the Governor-injected carrier refuses at the carrier
    /// check with the precise reason — never `UnsupportedJobClass`, never
    /// the Kernel-admission code — before any screen or registry work burns.
    #[test]
    fn curation_without_carrier_refuses_at_carrier_check() {
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            carriers(None, Some(valid_screen()), None),
            JobClass::Curation,
            None,
            // Unconstructible for Curation, not merely omitted: the A-05 gate
            // rejects `JobClass::Curation` unconditionally
            // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
            // `validate_family` → `UnsupportedJobShape`), so no Curation job ever
            // yields a `ValidatedGroundingCandidate` and this record cannot be
            // built. Supplying one would mean fabricating a receipt the owner
            // refuses to issue.
            None,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_CARRIER_REFUSAL))
            ),
            "curation without a carrier must name it, got {refused:?}"
        );
        assert_eq!(
            refused.as_ref().map_err(DreamerError::code),
            Err("DREAMER_REQUEST_REJECTED")
        );
        assert!(
            !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
            "curation must never refuse with UnsupportedJobClass"
        );
        assert!(
            !matches!(refused, Err(DreamerError::KernelAdmissionRequired(_))),
            "curation must never borrow the Kernel-admission code"
        );
    }

    /// Curation with neither screen nor carrier refuses with the carrier
    /// reason: without the Governor-injected batch and ports there is
    /// nothing to route, so the carrier check names the missing governed
    /// input even when the screen is absent too.
    #[test]
    fn curation_without_carrier_or_screen_names_carrier() {
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            carriers(None, None, None),
            JobClass::Curation,
            None,
            // Unconstructible for Curation, not merely omitted: the A-05 gate
            // rejects `JobClass::Curation` unconditionally
            // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
            // `validate_family` → `UnsupportedJobShape`), so no Curation job ever
            // yields a `ValidatedGroundingCandidate` and this record cannot be
            // built. Supplying one would mean fabricating a receipt the owner
            // refuses to issue.
            None,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_CARRIER_REFUSAL))
            ),
            "curation without carrier or screen must name the carrier, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// Curation with a carrier but without the screen-stage binding refuses
    /// naming the missing governed screen before any registry work.
    #[test]
    fn curation_without_screen_names_missing_binding() {
        let harness = harness_for_fixture();
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            carriers(Some(harness.carrier()), None, None),
            JobClass::Curation,
            None,
            // Unconstructible for Curation, not merely omitted: the A-05 gate
            // rejects `JobClass::Curation` unconditionally
            // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
            // `validate_family` → `UnsupportedJobShape`), so no Curation job ever
            // yields a `ValidatedGroundingCandidate` and this record cannot be
            // built. Supplying one would mean fabricating a receipt the owner
            // refuses to issue.
            None,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_SCREEN_REFUSAL))
            ),
            "curation without a screen must name it, got {refused:?}"
        );
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err("DREAMER_REQUEST_REJECTED")
        );
    }

    /// Curation with a valid batch but an empty port set reaches the genuine
    /// A-31 port boundary: descriptors resolve from the real closed registry,
    /// registry/policy/screen validate for real, and the terminal refusal
    /// names the missing Governor-injected live ports with the precise
    /// reason — never `UnsupportedJobClass`.
    #[test]
    fn curation_empty_ports_carrier_reaches_port_boundary() {
        let harness = harness_for_fixture();
        let carrier = CurationExecutionCarrier {
            batch: harness.batch().clone(),
            ports: NativeCurationPortSet { ports: Vec::new() },
        };
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            carriers(Some(carrier), Some(valid_screen()), None),
            JobClass::Curation,
            None,
            // Unconstructible for Curation, not merely omitted: the A-05 gate
            // rejects `JobClass::Curation` unconditionally
            // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
            // `validate_family` → `UnsupportedJobShape`), so no Curation job ever
            // yields a `ValidatedGroundingCandidate` and this record cannot be
            // built. Supplying one would mean fabricating a receipt the owner
            // refuses to issue.
            None,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_PORTS_REFUSAL))
            ),
            "curation must refuse at the live-port boundary, got {refused:?}"
        );
        assert_eq!(
            refused.as_ref().map_err(DreamerError::code),
            Err("DREAMER_REQUEST_REJECTED")
        );
        assert!(
            !matches!(refused, Err(DreamerError::UnsupportedJobClass(_))),
            "curation must never refuse with UnsupportedJobClass"
        );
    }

    /// Curation with the injected carrier routes through the real A-31
    /// fan-in: the accepted candidate carries the kind wire spelling, the
    /// screened targets reverbatim, routing-record texts naming the sealing
    /// handler and result digest, the candidate-only ceiling, and denominator
    /// provenance; the result then renders through the Slice-8 edge to one
    /// JSONL line that round-trips to the identical view.
    #[test]
    fn curation_success_routes_accepted_candidate_with_provenance() {
        use crate::result_stage::{project_result_view, render_jsonl};
        use crate::{JobState, JobView};

        let harness = harness_for_fixture();
        let result = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            carriers(Some(harness.carrier()), Some(valid_screen()), None),
            JobClass::Curation,
            None,
            // Unconstructible for Curation, not merely omitted: the A-05 gate
            // rejects `JobClass::Curation` unconditionally
            // (`eliot-dreamer-candidate-validation/src/structured/validate.rs`,
            // `validate_family` → `UnsupportedJobShape`), so no Curation job ever
            // yields a `ValidatedGroundingCandidate` and this record cannot be
            // built. Supplying one would mean fabricating a receipt the owner
            // refuses to issue.
            None,
        );
        let Ok(DreamResult::Curation {
            job_id,
            candidates,
            provenance,
            pulse,
        }) = result
        else {
            panic!("injected-carrier curation must route, got {result:?}");
        };
        assert_eq!(candidates.len(), 1);
        let candidate = &candidates[0];
        assert_eq!(candidate.candidate_id.len(), 64);
        assert_eq!(candidate.kind, "classification");
        assert_eq!(
            candidate.source_handles,
            vec!["target-slice-7".to_owned()],
            "targets must travel reverbatim, got {:?}",
            candidate.source_handles
        );
        assert!(
            candidate
                .proposed_transformation
                .contains("eliot-dreamer-classification"),
            "transformation must name the sealing handler, got {:?}",
            candidate.proposed_transformation
        );
        assert!(
            candidate.proposed_transformation.contains("result digest"),
            "transformation must name the sealed result digest, got {:?}",
            candidate.proposed_transformation
        );
        assert_eq!(
            candidate.uncertainty,
            "candidate_only; content sealed under result digest"
        );
        assert!(
            !candidate.rollback.trim().is_empty(),
            "rollback must carry a routing record"
        );
        assert_eq!(
            provenance,
            vec!["target-slice-7".to_owned()],
            "provenance must carry the denominator members, got {provenance:?}"
        );
        assert_eq!(
            pulse.schema_version,
            crate::CURATION_PULSE_SCHEMA_VERSION,
            "the receipt must carry the curation product pulse"
        );
        assert_eq!(
            pulse.disposition,
            crate::CurationPulseDisposition::Complete,
            "an all-or-nothing run with no omission must read complete"
        );
        assert_eq!(
            pulse.candidate_ids,
            vec![candidate.candidate_id.clone()],
            "the pulse must name the routed candidate identities"
        );
        let view = project_result_view(
            &job_id,
            JobState::Completed,
            Some(DreamResult::Curation {
                job_id: job_id.clone(),
                candidates: candidates.clone(),
                provenance: provenance.clone(),
                pulse: pulse.clone(),
            }),
        );
        let Ok(line) = render_jsonl(&view) else {
            panic!("curation receipt must render");
        };
        assert!(!line.contains('\n'), "receipt must be exactly one line");
        let roundtrip: JobView = match serde_json::from_str(&line) {
            Ok(view) => view,
            Err(error) => panic!("receipt must round-trip, got {error:?}"),
        };
        assert_eq!(roundtrip, view);
    }

    /// `ResearchSynthesis` and `Maintenance` prove the structured receipt
    /// binding first and then fail closed naming their missing
    /// Governor-resolved inputs with the class named; the research and
    /// maintenance owners stay unwired (no dependency added for them).
    #[test]
    fn research_and_maintenance_name_missing_governed_inputs() {
        for (class, reason) in [
            (JobClass::ResearchSynthesis, RESEARCH_PACK_REFUSAL),
            (JobClass::Maintenance, MAINTENANCE_INPUTS_REFUSAL),
        ] {
            let admission = admission();
            let job = semantic_job(class);
            let (grounding, validated) = validated_for(&admission, &job);
            let refused = dispatch_admitted(
                &admission,
                &job,
                carriers(None, None, None),
                class,
                Some(&validated),
                Some(PipelineOrientationRecords::new(&grounding, &validated)),
            );
            assert!(
                matches!(refused, Err(DreamerError::InvalidAdmission(got)) if got == reason),
                "class {class:?} must name its governed input, got {refused:?}"
            );
            assert_eq!(
                refused.map_err(|error| error.code()),
                Err("DREAMER_REQUEST_REJECTED")
            );
        }
    }

    /// The five classes `submit` never admits refuse direct dispatch calls
    /// with their exact class payload and the request-rejected code, before
    /// any Kernel contact: `dispatch_admitted` takes only the admitted pair
    /// plus the class, so there is no port, transport, or admission channel
    /// it could call.
    #[test]
    fn refused_classes_reject_direct_dispatch() {
        for class in [
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let admission = admission();
            let job = semantic_job(class);
            // These five classes are NOT rejected by the A-05 gate: `job_class`
            // appears exactly once in the whole structured validation module and
            // rejects only `Curation`. The pipeline therefore genuinely runs for
            // each of them and the record is real, so it is built and supplied
            // rather than passed as `None`. Supplying it is what makes the case
            // prove the ORDER: an available, valid pipeline record still cannot
            // route a class that `submit` never admits.
            let (grounding, validated) = validated_for(&admission, &job);
            let refused = dispatch_admitted(
                &admission,
                &job,
                carriers(None, None, None),
                class,
                None,
                Some(PipelineOrientationRecords::new(&grounding, &validated)),
            );
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?}), got {refused:?}"
            );
            assert_eq!(
                refused.as_ref().map_err(DreamerError::code),
                Err("DREAMER_REQUEST_REJECTED")
            );
            let message = match refused {
                Err(error) => format!("{error}"),
                Ok(_) => panic!("refused class must fail"),
            };
            assert_eq!(message, format!("unsupported Dreamer job class: {class:?}"));
        }
    }

    /// Every native orientation refusal shape maps to the request-rejected
    /// code, never to the Kernel-admission code.
    #[test]
    fn every_orientation_refusal_maps_fail_closed() {
        let cases = [
            OrientationError::WrongJobClass,
            OrientationError::Invalid("frame source"),
            OrientationError::Unsupported("orientation frame schema"),
            OrientationError::Binding("frame task/scope/fence"),
            OrientationError::Bound,
            OrientationError::Bounded("packet item count"),
            OrientationError::RevalidationRequired,
            OrientationError::Cancelled,
            OrientationError::Encoding("frame body"),
            OrientationError::Internal,
        ];
        assert_eq!(cases.len(), 10);
        for error in &cases {
            let refused = orientation_denied(error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "orientation refusal must not borrow the Kernel-admission code"
            );
        }
        assert!(matches!(
            orientation_denied(&cases[1]),
            DreamerError::InvalidAdmission("frame source")
        ));
        assert!(matches!(
            orientation_denied(&OrientationError::WrongJobClass),
            DreamerError::InvalidAdmission("job class binding")
        ));
    }

    /// Every native curation routing refusal shape maps to the
    /// request-rejected code with its bounded static field; the port boundary
    /// always maps to the precise live-ports refusal, never to
    /// `UnsupportedJobClass` or the Kernel-admission code.
    #[test]
    fn every_curation_refusal_maps_fail_closed() {
        let cases = [
            CurationRoutingError::Batch {
                field: "items",
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Binding {
                field: "atomicity",
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Receipt {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Screen {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Registry {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Port {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Policy {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Denominator {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Handler {
                handler_id: "handler-slice-7".to_owned(),
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::HandlerPanicked {
                handler_id: "handler-slice-7".to_owned(),
            },
            CurationRoutingError::Envelope {
                handler_id: "handler-slice-7".to_owned(),
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Atomicity {
                detail: "redacted".to_owned(),
            },
            CurationRoutingError::Digest {
                detail: "redacted".to_owned(),
            },
        ];
        assert_eq!(cases.len(), 13);
        for error in &cases {
            let refused = curation_denied(error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "curation refusal must not borrow the Kernel-admission code"
            );
            assert!(
                !matches!(refused, DreamerError::UnsupportedJobClass(_)),
                "curation must never refuse with UnsupportedJobClass"
            );
        }
        assert!(matches!(
            curation_denied(&cases[0]),
            DreamerError::InvalidAdmission("items")
        ));
        assert!(matches!(
            curation_denied(&cases[5]),
            DreamerError::InvalidAdmission(CURATION_PORTS_REFUSAL)
        ));
    }
}

/// Coverage for [`map_orientation_packet`], the packet-to-result mapping.
///
/// # Why this module exists, and what it deliberately does NOT do
///
/// A prior session recorded that this mapping "has no direct test coverage on
/// this tree" and that the gap "cannot" be closed without fabricating an
/// [`OrientationSupply`](crate::OrientationSupply). That premise is false, and
/// this module is the proof.
///
/// [`map_orientation_packet`] takes
/// `(&OrientationPacketCandidate, &DreamJobInput)`. It does **not** take a
/// supply, does not read a carrier, and performs no stage work. The
/// [`OrientationSupply`] is an input to
/// [`compose_production_result`](crate::production_orientation::compose_production_result),
/// a different function in a different module, which runs the nine mandatory
/// stages *before* it ever reaches `build_projection` and this mapping.
///
/// Every input this mapping actually consumes is derived in-binary by this
/// crate's own stages, with no owner channel involved:
///
/// - the admitted job, frame, bundle and validation receipt come from
///   [`admission_of`], [`bundle_of`], [`orientation_frame_of`],
///   [`v1_model_of`], [`v1_grounded_of`] and the real v1 A-05 entry
///   [`validate_grounded_dream_draft_at`], exactly as
///   [`dispatch_orientation`] derives them;
/// - the packet itself comes from the owner's own
///   `eliot_dreamer_orientation::projection::build_projection`, invoked over
///   those five admitted values;
/// - the CEP handle slice is **empty**, which is the owner's own documented
///   lawful state here, not a shortcut: `build_projection`'s
///   `validate_coverage_denominator` returns `Ok(())` immediately when the
///   admitted job pins no coverage denominator (the crate's own
///   `orientation_admitted_job` sets `coverage_denominator: None` and
///   `admitted_evidence: Vec::new()` on exactly this reasoning), and every
///   handle check in `validate_position_inputs` is vacuous over an empty slice.
///
/// So the packet below is a **genuine owner-produced packet**, not a
/// fabricated one: it is built by the owner's producer from the crate's own
/// admitted material and then re-proved against that same material with the
/// owner's own [`OrientationPacketCandidate::validate_against`]. The mapping
/// then runs on it.
///
/// What this module does NOT do, and must not: it does not construct an
/// [`OrientationSupply`], does not assert that the supply channel is reachable,
/// and does not weaken the carrier to make a packet appear. The supply channel
/// remains unbuilt; that is a separate, real gap recorded in
/// `production_orientation`'s module contract. These cases cover the MAPPING,
/// which was never blocked by the missing supply in the first place.
#[cfg(test)]
mod orientation_packet_mapping_tests {
    use super::*;
    use crate::admitted_material::{
        admission_of, bundle_of, orientation_frame_of, preservation_of, usage_of, v1_grounded_of,
        v1_model_of, validation_policy_of,
    };
    use eliot_dreamer_orientation::projection::build_projection;
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SCOPE: &str = "scope-packet-map";
    const TASK: &str = "task-packet-map";
    const OPERATION: &str = "op-packet-map";
    const QUESTION: &str = "What does ELIOT know about this scope?";
    const CONFLICT: &str = "conflict-packet-map";

    fn fence() -> StateFence {
        let Ok(lineage) = EpochLineageId::new(TEST_LINEAGE) else {
            panic!("valid test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("nonzero test sequence must construct");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("valid test epoch must construct");
        };
        StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn admission() -> KernelJobAdmission {
        KernelJobAdmission {
            job_id: "job-packet-map".to_owned(),
            attempt_id: "attempt-packet-map".to_owned(),
            scope_id: SCOPE.to_owned(),
            request_id: OPERATION.to_owned(),
            idempotency_key: "job-packet-map:attempt-packet-map".to_owned(),
            cancellation_id: "cancel-packet-map".to_owned(),
            deadline_unix_ms: u64::MAX,
            state_fence: fence(),
        }
    }

    fn job() -> DreamJobInput {
        DreamJobInput {
            job_id: "job-packet-map".to_owned(),
            job_class: JobClass::Orientation,
            exact_question: QUESTION.to_owned(),
            requester: "test-harness".to_owned(),
            scope_id: SCOPE.to_owned(),
            task_id: Some(TASK.to_owned()),
            state_fence: fence(),
            evidence_handles: vec!["evidence-packet-map".to_owned()],
            memory_handles: vec!["memory-packet-map".to_owned()],
            architecture_handles: vec!["architecture-packet-map".to_owned()],
            implementation_handles: vec!["implementation-packet-map".to_owned()],
            conformance_handles: vec!["conformance-packet-map".to_owned()],
            conflicts_and_unknowns: vec![CONFLICT.to_owned()],
            privacy_profile: "local_only".to_owned(),
            allowed_tools: Vec::new(),
            allowed_model_routes: vec!["route-test".to_owned()],
            budget_units: 1,
            deadline_ms: 1,
            output_schema: "eliot.dreamer.v1".to_owned(),
            forbidden_effects: Vec::new(),
        }
    }

    /// The four inputs the owner's packet producer consumes: the admitted
    /// Orientation job, the v1 validated candidate, the bounded bundle, and the
    /// sealed policy.
    type PacketMaterial = (
        AdmittedOrientationJob,
        eliot_dreamer_contracts::ValidatedCandidate,
        DreamInputBundle,
        OrientationPolicy,
    );

    fn admitted_packet_material() -> PacketMaterial {
        let admission = admission();
        let job = job();
        let admitted = admission_of(&admission, &job).expect("admitted job must derive");
        let bundle = bundle_of(&admission, &job, &[]).expect("admitted bundle must derive");
        let frame_source = orientation_frame_source(&bundle).expect("frame source must resolve");
        let model = v1_model_of(&admission, &job).expect("admitted model must derive");
        let grounded = v1_grounded_of(&model).expect("admitted grounding must derive");
        let usage = usage_of(&admitted.budget);
        let validation_policy =
            validation_policy_of(admitted.policy_ref.as_str()).expect("validation policy seals");
        let preservation = preservation_of().expect("preservation report must build");
        let candidate = match validate_grounded_dream_draft_at(
            &admitted,
            &bundle,
            &model,
            &grounded,
            &validation_policy,
            &usage,
            &preservation,
            Some(0),
            false,
        ) {
            Ok(CandidateValidationOutcome::Accepted(candidate)) => *candidate,
            Ok(CandidateValidationOutcome::Rejected(report)) => {
                panic!("fixture candidate must be accepted, got {report:?}")
            }
            Err(error) => panic!("fixture candidate must validate, got {error:?}"),
        };
        let frame = orientation_frame_of(&admission, &admitted, &job, frame_source.as_str())
            .expect("orientation frame must build");
        let admitted_job = orientation_admitted_job(admitted, frame);
        let policy = orientation_dispatch_policy().expect("dispatch policy must seal");
        (admitted_job, candidate, bundle, policy)
    }

    /// Positive case: the mapping is exercised on a GENUINE owner-produced
    /// packet, with no [`OrientationSupply`] anywhere in this module.
    ///
    /// The packet is built by the owner's own `build_projection` over the
    /// crate's own admitted material, then re-proved with the owner's own
    /// `validate_against` against that same material. Every mapping guarantee
    /// the doc comment states is then asserted on the real result: identity
    /// bindings travel verbatim, the five handle families travel verbatim,
    /// interpreted statements stay at the candidate-only ceiling, and the
    /// ABSOLUTE G4 rule holds — both owner residues are appended after the
    /// rival texts, so neither marker is dropped or thinned.
    #[test]
    fn owner_packet_maps_with_g4_residues_and_verbatim_bindings() {
        let job = job();
        let (admitted_job, candidate, bundle, policy) = admitted_packet_material();
        // No owner channel: the crate's own `orientation_admitted_job` pins no
        // coverage denominator and no admitted evidence, so the owner's
        // denominator validator returns Ok over this admitted set by design.
        let packet = build_projection(&admitted_job, &candidate, &bundle, &[], &policy)
            .expect("owner projection must build over the admitted five-input set");
        // The packet is the owner's, re-proved against the very same admitted
        // material. A fabricated or drifted packet cannot pass this.
        packet
            .validate_against(&admitted_job, &bundle, &candidate, &[], &policy)
            .expect("owner packet must revalidate against its own admitted inputs");

        let mapped = map_orientation_packet(&packet, &job);

        // Identity bindings travel verbatim from the owner packet; the state
        // fence is the admitted semantic input's, proved equal to the
        // Kernel-admitted fence by the binding check these values came through.
        assert_eq!(mapped.packet_id, packet.packet_id);
        assert_eq!(mapped.job_id, packet.job_id);
        assert_eq!(mapped.question, QUESTION);
        assert_eq!(mapped.scope_id, SCOPE);
        assert_eq!(mapped.state_fence, job.state_fence);
        // The five admitted handle families travel verbatim.
        assert_eq!(mapped.source_coverage.evidence, job.evidence_handles);
        assert_eq!(mapped.source_coverage.memory, job.memory_handles);
        assert_eq!(
            mapped.source_coverage.architecture,
            job.architecture_handles
        );
        assert_eq!(
            mapped.source_coverage.implementation,
            job.implementation_handles
        );
        assert_eq!(mapped.source_coverage.conformance, job.conformance_handles);
        // Interpreted statements travel with their source handles, promoted to
        // nothing. Asserted as a correspondence with the owner's own
        // interpretation set plus the fixed candidate-only ceiling, so the
        // guarantee is that nothing is promoted and nothing is dropped, not a
        // count this fixture happens to produce.
        assert_eq!(
            mapped.synthesized_interpretations.len(),
            packet.synthesized_interpretations.len()
        );
        for (index, interpretation) in mapped.synthesized_interpretations.iter().enumerate() {
            let owner = &packet.synthesized_interpretations[index];
            assert_eq!(interpretation.statement, owner.statement);
            assert_eq!(interpretation.support_handles, owner.source_handles);
            assert_eq!(interpretation.epistemic_status, "candidate_only");
        }
        // ABSOLUTE G4 RULE: BOTH owner residues are appended to the rival list
        // after the rival texts, so neither marker can be dropped or thinned by
        // this mapping. Asserted against the owner's own residue texts, not a
        // count, so the guarantee is the one the contract states.
        let rivals = &mapped.rival_models_and_dissent;
        assert_eq!(rivals.len(), packet.rival_models_and_dissent.len() + 2);
        assert_eq!(
            rivals[rivals.len() - 2],
            packet.architecture_implications.text,
            "architecture implications must be appended as a rival marker"
        );
        assert_eq!(
            rivals[rivals.len() - 1],
            packet.model_routes_and_cost.text,
            "model routes and cost must be appended as a rival marker"
        );
        // The four screening-side families are accounted as omissions and
        // surface as unknowns, never silently dropped. Asserted as a
        // correspondence with the owner's own unknown residue set rather than a
        // hardcoded count, so the guarantee is that no unknown is thinned or
        // dropped by this mapping.
        assert_eq!(
            mapped.unknowns_and_gaps.len(),
            packet.unknowns_and_gaps.len()
        );
        for (index, gap) in mapped.unknowns_and_gaps.iter().enumerate() {
            assert_eq!(gap, &packet.unknowns_and_gaps[index].text);
        }
        // Inert probes travel as text only; probes never execute. Asserted as
        // a correspondence with the owner's own probe set.
        assert_eq!(
            mapped.recommended_probes_or_next_actions.len(),
            packet.recommended_probes_or_next_actions.len()
        );
        for (index, probe) in mapped.recommended_probes_or_next_actions.iter().enumerate() {
            assert_eq!(
                probe,
                &packet.recommended_probes_or_next_actions[index].text
            );
        }
        // Invalidation conditions travel verbatim.
        assert_eq!(
            mapped.invalidation_conditions,
            packet.invalidation_conditions
        );
        assert!(
            mapped.provenance.contains(&OPERATION.to_owned()),
            "provenance must carry the projection-input proof, got {:?}",
            mapped.provenance
        );
    }

    /// Refusal case: the mapping's own input gate refuses a packet that is not
    /// the owner's output for the admitted material it is presented with.
    ///
    /// [`map_orientation_packet`] performs no validation itself — the owner's
    /// producer does — so the proof that a packet is genuine lives in the owner's
    /// `validate_against`. This case shows that gate is real: a packet whose
    /// body was altered after production (its `question`, a field the owner
    /// binds the frame lineage against) is REFUSED, so nothing downstream can be
    /// built on an unowned packet. Without this, "the packet is genuine" would
    /// rest on the positive case alone.
    #[test]
    fn altered_owner_packet_is_refused_by_its_own_revalidation() {
        let job = job();
        let (admitted_job, candidate, bundle, policy) = admitted_packet_material();
        let packet = build_projection(&admitted_job, &candidate, &bundle, &[], &policy)
            .expect("owner projection must build over the admitted five-input set");

        let mut altered = packet.clone();
        altered.question = "a question the admitted frame never carried".to_owned();

        // The owner's own revalidation refuses the altered packet against the
        // admitted material it does not belong to.
        let refused = altered.validate_against(&admitted_job, &bundle, &candidate, &[], &policy);
        assert!(
            refused.is_err(),
            "an altered packet must not revalidate against its own admitted inputs"
        );
        // And the untouched original still does, so the refusal above is caused
        // by the alteration and not by a fixture that never validated at all.
        assert!(
            packet
                .validate_against(&admitted_job, &bundle, &candidate, &[], &policy)
                .is_ok(),
            "the unaltered owner packet must still revalidate"
        );
        // The mapping itself is total over a packet and never re-derives one:
        // it maps whatever packet it is handed, which is exactly why the
        // owner's revalidation is the gate that must hold.
        let mapped = map_orientation_packet(&altered, &job);
        assert_eq!(mapped.question, altered.question);
    }
}
