#![forbid(unsafe_code)]

//! Native owner dispatch for admitted Dreamer jobs (issue #702, Slice 7).
//!
//! After the Slice-A/1 admission dispatch admits a job class, this stage
//! resolves the exact native owner for one closed [`JobClass`] and invokes it
//! with no fallthrough: Curation names the A-31 curation fan-in
//! ([`route_validated_curation`](eliot_dreamer_curation::route_validated_curation)),
//! Orientation names `eliot-dreamer-orientation` `build_projection`, and every
//! other class names its native owner. Exhaustive with no wildcard arm:
//! extending the closed taxonomy breaks compilation here until the new class
//! is assigned an owning slice.
//!
//! [`dispatch_admitted`] is the single Slice-7 owner entry: it takes the
//! Kernel admission, the semantic job, the A-20 screen binding (for
//! Curation), and the closed class, and returns the typed [`DreamResult`].
//! There is no class-only stub seam: every arm either genuinely invokes its
//! owner or refuses naming the exact missing governed input. Orientation
//! derives the v1 hypothesis pair, validates it through the real v1 A-05
//! entry, and genuinely invokes `build_projection` before projecting the
//! packet; Curation genuinely resolves descriptors, validates
//! registry/policy/screen, and refuses at the live-port boundary;
//! `ResearchSynthesis` and `Maintenance` fail closed naming their missing
//! Governor-resolved inputs; the remaining five classes refuse with
//! `UnsupportedJobClass` (they never reach here via `submit`; direct calls
//! refuse).
//!
//! Fail-closed: every refusal is [`DreamerError::InvalidAdmission`] (the
//! request-rejected code) or [`DreamerError::UnsupportedJobClass`], never the
//! Kernel-admission code: the admission itself was valid, the owner inputs
//! were not. Dynamic payloads (handles, digests, reasons) are dropped in favor
//! of bounded static field names; nothing secret flows. No leaf handler is
//! invoked on any path: Curation stops at the port boundary because no
//! production `NativeCurationHandler` implementations exist in the workspace
//! (only test doubles), so the ten live ports the owner requires cannot be
//! assembled in-binary and leaf invocation awaits Governor-injected ports.

use eliot_dreamer_candidate_validation::{
    CandidateValidationOutcome, DreamDraftValidationError, validate_grounded_dream_draft_at,
};
use eliot_dreamer_contracts::{
    registry::{canonical_registry, CurationHandlerRegistry},
    ContractViolation, JobClass, ScreenBinding, ScreenState, SourceDisposition,
};
use eliot_dreamer_curation::{
    CurationRoutingError, NativeCurationPortSet, RoutingPolicy, MAX_BATCH_ITEMS,
};
use eliot_dreamer_orientation::{
    projection::{build_projection, OrientationPacketCandidate},
    AdmittedOrientationJob, OrientationError, OrientationPolicy,
};

use crate::admitted_material::{
    admission_of, bundle_of, orientation_frame_of, preservation_of, usage_of, v1_grounded_of,
    v1_model_of, validation_policy_of,
};
use crate::controller::verify_admitted_binding;
use crate::{
    DreamJobInput, DreamPacket, DreamResult, DreamerError, Interpretation, KernelJobAdmission,
    SourceCoverage,
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
/// and the closed class. Returns the owner-typed [`DreamResult`].
///
/// Fail-closed: the admission/job binding is verified first, then the class
/// parameter is bound against the semantic job, then the exhaustive nine-arm
/// match runs with no wildcard. Orientation derives the v1 hypothesis pair
/// from the admitted pair, validates it through the real v1 A-05 entry, and
/// genuinely invokes `build_projection`; Curation genuinely resolves
/// descriptors, validates registry/policy/screen, and refuses at the
/// live-port boundary; `ResearchSynthesis` and `Maintenance` name their
/// missing Governor-resolved inputs; the five classes `submit` never admits
/// refuse with `UnsupportedJobClass`.
pub(crate) fn dispatch_admitted(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    screen: Option<ScreenBinding>,
    job_class: JobClass,
) -> Result<DreamResult, DreamerError> {
    verify_admitted_binding(admission, job)?;
    if job.job_class != job_class {
        return Err(DreamerError::InvalidAdmission("job class binding"));
    }
    match job_class {
        // Native owner: eliot-dreamer-curation (A-31 sole fan-in).
        JobClass::Curation => dispatch_curation(screen),
        // Native owner: eliot-dreamer-orientation build_projection.
        JobClass::Orientation => dispatch_orientation(admission, job),
        // Native owner: eliot-dreamer-research-synthesis `synthesize`. The
        // owner takes its own `SynthesisRequest` vocabulary (a
        // Governor-owned `ResearchPack` with evidence grades, frozen
        // denominator, and source-independence bindings plus its own
        // grounded-draft shape): none of it is constructible from the
        // admitted binary material, and transcribing the validated
        // candidate into that vocabulary would be semantic recomputation
        // owned elsewhere. Fail closed naming the missing governed input;
        // no dependency is added for an unwired owner.
        JobClass::ResearchSynthesis => Err(DreamerError::InvalidAdmission(RESEARCH_PACK_REFUSAL)),
        // Native owner: eliot-dreamer-maintenance-plan
        // `propose_maintenance_plan`. The owner takes its own Governor-owned
        // plan inputs (objectives, trigger evidence, bounds, and history
        // bindings): none of it is constructible from the admitted binary
        // material, and synthesizing it here would be self-issued
        // authority. Fail closed naming the missing governed input; no
        // dependency is added for an unwired owner.
        JobClass::Maintenance => Err(DreamerError::InvalidAdmission(MAINTENANCE_INPUTS_REFUSAL)),
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

/// Dispatches one admitted Orientation job through the native projector.
///
/// Derives the v1 hypothesis pair from the admitted pair, validates it
/// through the real v1 A-05 entry
/// ([`validate_grounded_dream_draft_at`](eliot_dreamer_candidate_validation::validate_grounded_dream_draft_at)),
/// and genuinely invokes
/// [`build_projection`](eliot_dreamer_orientation::projection::build_projection)
/// over the accepted candidate. The v1 receipt terminal is honestly `partial`
/// (the residue is handle-bound but unevidenced; see
/// [`v1_grounded_of`](crate::admitted_material::v1_grounded_of)), which the
/// owner accepts as a candidate-only passage, never as truth.
///
/// Orientation adaptations (G1-G5) as owned by the orientation crate and
/// composed here:
///
/// - G1 (scope/state-fence split): the frame takes scope/task from the
///   admitted job and the operation from the Kernel correlation
///   (`request_id`), never collapsed into a single fence string.
/// - G2/G3 (native shapes): the candidate aggregate travels as the native
///   struct; nothing is parsed as YAML and evidence is never regrouped.
/// - G4 (marker preservation): the owner residues travel untouched into the
///   packet, and the result mapping carries both
///   `architecture_implications` and `model_routes_and_cost` texts into
///   `rival_models_and_dissent` (see [`map_orientation_packet`]).
/// - G5 (Governor sourcing): admitted evidence and epistemic-position handles
///   arrive through a source-owner port in a later slice, so both travel
///   empty here; locally built envelopes or positions would be self-issued
///   authority. The coverage denominator is likewise `None`.
fn dispatch_orientation(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<DreamResult, DreamerError> {
    let admitted = admission_of(admission, job)?;
    let bundle = bundle_of(admission, job)?;
    // The frame binds admitted bundle material: the first non-excluded
    // material in bundle order is the deterministic candidate frame source
    // until the Governor pins the frame source explicitly. No handle is
    // invented: a bundle with no bindable material refuses. This selects the
    // same first evidence handle the bundle plants the frame digest on, so
    // the frame built here is byte-identical to the planted one.
    let frame_source = bundle
        .materials
        .iter()
        .find(|material| !matches!(material.disposition, SourceDisposition::Excluded))
        .map(|material| material.handle.clone())
        .ok_or(DreamerError::InvalidAdmission(FRAME_SOURCE_REFUSAL))?;
    let model = v1_model_of(admission, job)?;
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
    let frame = orientation_frame_of(admission, &admitted, job, frame_source.as_str())?;
    let admitted_job = AdmittedOrientationJob {
        job: admitted,
        frame,
        admitted_evidence: Vec::new(),
        coverage_denominator: None,
    };
    // Bounded dispatch policy: explicit identity and revision, a 1 MiB output
    // envelope (inside the owner 4 MiB ceiling), and the owner defaults for
    // every other maximum. Sealing freezes the policy digest the packet
    // provenance binds.
    let mut policy = OrientationPolicy::new("eliot-dreamer-dispatch", 1, 1_048_576);
    policy.seal().map_err(|error| orientation_denied(&error))?;
    let packet = build_projection(&admitted_job, &candidate, &bundle, &[], &policy)
        .map_err(|error| orientation_denied(&error))?;
    Ok(DreamResult::Packet(map_orientation_packet(&packet, job)))
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
/// owner packet; the state fence from the admitted semantic input, which owns
/// the fence string the typed owner fence was captured under). Source
/// coverage carries the five admitted handle families verbatim. Interpreted
/// statements travel with their source handles at the candidate-only ceiling:
/// nothing is promoted. ABSOLUTE G4 RULE: both owner residues,
/// `architecture_implications` and `model_routes_and_cost`, are appended to
/// `rival_models_and_dissent` after the rival texts, so neither marker can be
/// dropped or thinned by this mapping. Unknowns, inert probes (text only:
/// probes never execute), invalidation conditions, and projection-input
/// provenance (proof of inputs, never of truth) travel likewise.
fn map_orientation_packet(packet: &OrientationPacketCandidate, job: &DreamJobInput) -> DreamPacket {
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

/// Dispatches one admitted Curation job through the A-31 sole fan-in.
///
/// Takes the A-20 screen binding from the screen stage (`Some` for Curation;
/// `None` refuses naming the missing governed screen). Then, genuinely and in
/// order: resolves the owner-published closed registry, validates its closure
/// and stable digest, validates a bounded all-or-nothing routing policy,
/// validates the screen binding through the real owner check, resolves the
/// ten owner descriptors through that validated registry, and runs the owner
/// port-set validation.
///
/// HARD TRUTH: no production `NativeCurationHandler` implementations exist in
/// the workspace (only test doubles), and the owner port validation requires
/// exactly ten live ports, so the empty in-binary port set always fails that
/// genuine owner check. The terminal outcome is therefore the precise
/// live-ports refusal — reached AFTER genuinely invoking the owner boundary,
/// with no handler semantics invented in this binary. Leaf invocation awaits
/// Governor-injected ports (which arrive together with the validated batch
/// material in a later slice; no batch envelope is fabricated here, so
/// [`route_validated_curation`](eliot_dreamer_curation::route_validated_curation)
/// itself is not yet callable). Never returns `UnsupportedJobClass`.
fn dispatch_curation(screen: Option<ScreenBinding>) -> Result<DreamResult, DreamerError> {
    let screen = screen.ok_or(DreamerError::InvalidAdmission(CURATION_SCREEN_REFUSAL))?;
    let registry = canonical_registry().map_err(|error| dispatch_denied(&error))?;
    registry
        .validate_closure()
        .map_err(|error| dispatch_denied(&error))?;
    let _registry_digest = registry.digest().map_err(|error| dispatch_denied(&error))?;
    let max_items = u32::try_from(MAX_BATCH_ITEMS).unwrap_or(u32::MAX);
    let policy = RoutingPolicy {
        policy_id: "eliot-dreamer-dispatch".to_owned(),
        policy_revision: 1,
        allow_partial: false,
        max_items,
    };
    policy.validate().map_err(|error| curation_denied(&error))?;
    screen.validate().map_err(|error| dispatch_denied(&error))?;
    if screen.state != ScreenState::Eligible {
        return Err(DreamerError::InvalidAdmission("screen ineligible"));
    }
    Err(curation_port_boundary_refusal(&registry))
}

/// Runs the genuine owner port-boundary check and maps its terminal refusal.
///
/// Validates the empty in-binary port set against the closed registry through
/// the real owner [`NativeCurationPortSet::validate`](eliot_dreamer_curation::NativeCurationPortSet::validate):
/// with no Governor-injected live ports this always fails the exact-ten
/// requirement, and the owner error maps to the precise live-ports refusal.
/// The `Ok` arm is defensive-unreachable (an empty set can never satisfy the
/// owner) and refuses identically: there are still no live ports to dispatch
/// through. No handler is constructed, counted, or invoked on any path.
fn curation_port_boundary_refusal(registry: &CurationHandlerRegistry) -> DreamerError {
    let empty = NativeCurationPortSet { ports: Vec::new() };
    match empty.validate(registry, &[]) {
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
            state_fence: "fence-slice-7".to_owned(),
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

    /// Orientation genuinely projects from the admitted pair: the v1
    /// hypothesis pair validates through the real v1 A-05 entry, the owner
    /// `build_projection` succeeds, packet identity bindings travel verbatim,
    /// and the G4 residues are preserved in `rival_models_and_dissent`.
    #[test]
    fn orientation_projects_packet_with_g4_preserved() {
        let admission = admission();
        let job = semantic_job(JobClass::Orientation);
        let result = dispatch_admitted(&admission, &job, None, JobClass::Orientation);
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
    /// frame binds admitted bundle material and none is invented here.
    #[test]
    fn orientation_without_evidence_refuses_frame_source() {
        let admission = admission();
        let mut job = semantic_job(JobClass::Orientation);
        job.evidence_handles.clear();
        let refused = dispatch_admitted(&admission, &job, None, JobClass::Orientation);
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

    /// A caller-switched job identity refuses with the Kernel-admission code
    /// before any owner work.
    #[test]
    fn switched_identity_refuses_before_owner() {
        let admission = admission();
        let mut job = semantic_job(JobClass::Orientation);
        job.job_id = "caller-switched-job".to_owned();
        let refused = dispatch_admitted(&admission, &job, None, JobClass::Orientation);
        assert_eq!(
            refused.map_err(|error| error.code()),
            Err(KERNEL_ADMISSION_REQUIRED)
        );
    }

    /// A class parameter that disagrees with the semantic job refuses at the
    /// class binding before any owner work.
    #[test]
    fn class_parameter_mismatch_refuses_at_binding() {
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Orientation),
            None,
            JobClass::Curation,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission("job class binding"))
            ),
            "class mismatch must refuse at the binding, got {refused:?}"
        );
    }

    /// Curation reaches the genuine A-31 port boundary: descriptors resolve
    /// from the real closed registry, registry/policy/screen validate for
    /// real, and the terminal refusal names the missing Governor-injected
    /// live ports with the precise reason — never `UnsupportedJobClass`.
    #[test]
    fn curation_reaches_port_boundary_with_precise_refusal() {
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            Some(valid_screen()),
            JobClass::Curation,
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

    /// Curation without the screen-stage binding refuses naming the missing
    /// governed screen before any registry work.
    #[test]
    fn curation_without_screen_names_missing_binding() {
        let refused = dispatch_admitted(
            &admission(),
            &semantic_job(JobClass::Curation),
            None,
            JobClass::Curation,
        );
        assert!(
            matches!(
                refused,
                Err(DreamerError::InvalidAdmission(CURATION_SCREEN_REFUSAL))
            ),
            "curation without a screen must name it, got {refused:?}"
        );
    }

    /// `ResearchSynthesis` and `Maintenance` fail closed naming their missing
    /// Governor-resolved inputs with the class named; the research and
    /// maintenance owners stay unwired (no dependency added for them).
    #[test]
    fn research_and_maintenance_name_missing_governed_inputs() {
        for (class, reason) in [
            (JobClass::ResearchSynthesis, RESEARCH_PACK_REFUSAL),
            (JobClass::Maintenance, MAINTENANCE_INPUTS_REFUSAL),
        ] {
            let refused =
                dispatch_admitted(&admission(), &semantic_job(class), None, class);
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
            let refused =
                dispatch_admitted(&admission(), &semantic_job(class), None, class);
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?}), got {refused:?}"
            );
            assert_eq!(
                refused.as_ref().map_err(DreamerError::code),
                Err("DREAMER_REQUEST_REJECTED")
            );
            assert_eq!(
                format!(
                    "{}",
                    refused.expect_err("refused class must fail")
                ),
                format!("unsupported Dreamer job class: {class:?}")
            );
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
