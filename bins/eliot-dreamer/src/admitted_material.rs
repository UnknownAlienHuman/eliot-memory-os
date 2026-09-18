//! Governed admitted material for the Dreamer pipeline (issue #702, Slices 4-7).
//!
//! Pure derivation of every owner input the pipeline stages need —
//! [`DreamJobAdmission`](eliot_dreamer_contracts::DreamJobAdmission),
//! [`DreamInputBundle`](eliot_dreamer_contracts::DreamInputBundle),
//! [`AllowedReferenceManifest`](eliot_dreamer_contracts::grounding::AllowedReferenceManifest),
//! the v2 validation carrier, and the v1 hypothesis pair — from the admitted
//! pair only. No retrieval, ranking, model work, or truth promotion happens
//! here: every digest below is owner-computed and every value passes the real
//! owner validation before it leaves.
//!
//! Binary-derived bindings, documented once here:
//!
//! * Task: the admitted `task_id` when present and non-blank, else
//!   `<job_id>:task` (mirrors `curation_screen_stage::screen_binding_for`).
//! * Refs: `contract_ref` is `<output_schema>:contract` and `policy_ref` is
//!   `<output_schema>:policy`. The standing grounding policy is issued for
//!   [`PROTOCOL_VERSION`](crate::PROTOCOL_VERSION), so only the canonical
//!   schema grounds successfully; any other schema refuses fail-closed at the
//!   owner (`policy_ref` binding mismatch), never silently.
//! * Budget: `model_calls`/`attempts`/`candidates` derive from `budget_units`
//!   clamped to the owner class ceilings, `wall_ms` from `deadline_ms` clamped
//!   likewise; the remaining dimensions carry the class ceilings. `None`
//!   (unknown) is allowed at rest by [`BudgetLimits::validate`](eliot_dreamer_contracts::BudgetLimits::validate)
//!   but the A-14b owner requires explicit caps and refuses
//!   unknown-as-unlimited, so ceilings — not `None` — are carried. The model
//!   stage reads `budget.attempts` back from the admitted job for
//!   `attempt.maximum_attempts`; the binding is proved by the owner at
//!   grounding time.
//! * Frozen digest: the digest of the frozen (empty) manifest shell itself,
//!   built deterministically from task/scope/fence only, so admission, bundle,
//!   and manifest agree by construction. The shell carries no references:
//!   Dreamer never synthesizes a frozen universe locally; references arrive
//!   Governor-resolved through a source-owner port in a later slice.
//! * Bundle materials: evidence handles only. Memory, architecture,
//!   implementation, and conformance handles are accounted as [`OmissionHandle`](eliot_dreamer_contracts::OmissionHandle)
//!   entries (never silently dropped), so the bundle claims
//!   [`PartialForScope`](eliot_dreamer_contracts::BundleCompleteness::PartialForScope)
//!   — the v1 lineage owner refuses `Unknown` for a validated draft. Each
//!   carried material keeps the handle verbatim with a `Required` disposition;
//!   the frame-source material (first evidence handle, Orientation only)
//!   carries the owner-computed orientation frame digest and byte size so the
//!   projector binds the same frame the bundle plants, while the rest carry
//!   zero bytes (this binary holds handles, not content) and a [`sha_hex`]
//!   content digest. `bundle.job_id` is the admitted canonical identity because
//!   [`StructuredModelDraft::validate`](eliot_dreamer_contracts::grounding::StructuredModelDraft::validate)
//!   requires it.
//! * v1 hypothesis pair: the A-03 text track (`draft::ModelDraft` hypothesis
//!   text plus `draft::GroundedDreamDraft` residues) carries the admitted
//!   question verbatim as its single hypothesis with the admitted evidence
//!   handles as its source set. The residue state is `Partial`: the handle is
//!   bound to bundle material but confirming evidence is not admitted, so the
//!   v1 receipt terminal is honestly `partial`, never success dressed as
//!   truth. The binary packet mapping keeps the `candidate_only` ceiling.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, TaskId, sha256_hex};
use eliot_dreamer_contracts::budget::{
    ATTEMPTS_CEILING, CANDIDATES_CEILING, INPUT_BYTES_CEILING, MODEL_CALLS_CEILING,
    OUTPUT_BYTES_CEILING, REFERENCE_WIDTH_CEILING, REPORT_BYTES_CEILING, SOURCE_WIDTH_CEILING,
    STU_CEILING, WALL_MS_CEILING, WORK_FAN_OUT_CEILING,
};
use eliot_dreamer_contracts::candidate::{
    DimensionVerdict, PRESERVATION_DIMENSIONS, PreservationDimension,
};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, ClaimKind, GROUNDING_SCHEMA_VERSION, GroundedDreamDraft,
    GroundingPolicy,
};
use eliot_dreamer_contracts::job::DREAM_JOB_SCHEMA_VERSION;
use eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES;
use eliot_dreamer_contracts::validation::model_digest;
use eliot_dreamer_contracts::validation::structured::GroundingValidationInput;
use eliot_dreamer_contracts::{
    BudgetLimits, BudgetUsage, BundleCompleteness, BundleMaterial, ClaimResidue, DreamInputBundle,
    DreamJobAdmission, GroundedDreamDraft as TextGroundedDraft, JobClass,
    ModelDraft as TextModelDraft, OmissionHandle, PreservationReport, Requester, RequesterOrigin,
    SourceDisposition, SupportState, ValidationPolicy,
};
use eliot_dreamer_orientation::LocalOrientationFrame;

use crate::PROTOCOL_VERSION;
use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// SHA-256 hex over parts joined with `"\n"`.
///
/// The newline join keeps multi-part preimages unambiguous: no two distinct
/// part sequences join to the same preimage unless a part itself contains a
/// newline, and admitted handles never do (the owner text check rejects
/// control characters).
pub(crate) fn sha_hex(parts: &[&str]) -> String {
    sha256_hex(parts.join("\n").as_bytes())
}

/// Derives the admitted task binding: the input task when present and
/// non-blank, else `<job_id>:task` as the owner requires a non-blank binding.
fn admitted_task_id(job: &DreamJobInput) -> String {
    job.task_id
        .clone()
        .filter(|task| !task.trim().is_empty())
        .unwrap_or_else(|| format!("{}:task", job.job_id))
}

/// Builds the frozen allow-list shell shared by admission, bundle, and manifest.
///
/// Deterministic in task/scope/fence only: the same triple always yields the
/// same shell, so [`admission_of`], [`bundle_of`], and [`manifest_of`] agree
/// by construction. The digest is the owner-computed preimage digest, then
/// proved with the real manifest validation; an empty reference set is valid
/// (no local universe is synthesized here).
fn frozen_manifest_shell(
    task_id: &str,
    scope_id: &str,
    fence: &StateFence,
) -> Result<AllowedReferenceManifest, DreamerError> {
    let task = TaskId::new(task_id).map_err(|_| DreamerError::InvalidAdmission("task_id"))?;
    let mut manifest = AllowedReferenceManifest {
        schema_version: GROUNDING_SCHEMA_VERSION,
        manifest_id: format!("{scope_id}:manifest"),
        run_id: format!("{scope_id}:run"),
        task_id: task,
        scope_id: scope_id.to_owned(),
        state_fence: fence.clone(),
        source_snapshot: sha_hex(&["source-snapshot", scope_id]),
        source_revision: sha_hex(&["source-revision", scope_id]),
        references: BTreeMap::new(),
        coverage_denominators: BTreeMap::new(),
        coverage_receipts: BTreeMap::new(),
        dependence_groups: BTreeSet::new(),
        digest: String::new(),
    };
    let digest = manifest
        .computed_digest()
        .map_err(|_| DreamerError::InvalidAdmission("manifest preimage digest"))?;
    manifest.digest = digest;
    manifest
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("admitted manifest binding invalid"))?;
    Ok(manifest)
}

/// Derives the single frozen manifest digest every stage must bind.
///
/// Defined as the digest of the frozen shell itself (see
/// [`frozen_manifest_shell`]), so admission, bundle, and manifest cannot
/// drift: all three derive it from the same task/scope/fence triple. The job
/// side of the triple is used because [`verify_admitted_binding`] guarantees
/// `job.state_fence == admission.state_fence` before any derivation runs.
fn frozen_digest(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<String, DreamerError> {
    let shell = frozen_manifest_shell(
        admitted_task_id(job).as_str(),
        admission.scope_id.as_str(),
        &job.state_fence,
    )?;
    Ok(shell.digest)
}

/// Derives the validated owner job admission from the admitted pair.
///
/// Fails closed: the binding check runs first, then every field is derived
/// from admitted material only, then the real [`DreamJobAdmission::validate`](eliot_dreamer_contracts::DreamJobAdmission::validate)
/// proves the result. Any owner refusal maps to the request-rejected code via
/// the `"admitted job binding invalid"` static, never to the Kernel-admission
/// code: the admission itself was valid, the derived binding was not.
pub(crate) fn admission_of(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<DreamJobAdmission, DreamerError> {
    verify_admitted_binding(admission, job)?;
    // Post-verify invariant: `job.validate` proved `deadline_ms > 0`, so the
    // `u64` conversion cannot fail; the static mapping keeps it fail-closed
    // regardless.
    let deadline_ms = u64::try_from(job.deadline_ms)
        .map_err(|_| DreamerError::InvalidAdmission("admitted job binding invalid"))?;
    // Post-verify invariant: `job.validate` proved `budget_units != 0`, so
    // each clamped count is at least 1 and the owner `Some(0)` rejection for
    // `model_calls`/`attempts`/`candidates` cannot trigger.
    let budget = BudgetLimits {
        input_bytes: Some(INPUT_BYTES_CEILING),
        output_bytes: Some(OUTPUT_BYTES_CEILING),
        source_width: Some(SOURCE_WIDTH_CEILING),
        reference_width: Some(REFERENCE_WIDTH_CEILING),
        model_calls: Some(job.budget_units.min(MODEL_CALLS_CEILING)),
        attempts: Some(job.budget_units.min(ATTEMPTS_CEILING)),
        candidates: Some(job.budget_units.min(CANDIDATES_CEILING)),
        wall_ms: Some(deadline_ms.min(WALL_MS_CEILING)),
        work_fan_out: Some(WORK_FAN_OUT_CEILING),
        report_bytes: Some(REPORT_BYTES_CEILING),
        max_stu: Some(STU_CEILING),
    };
    let admitted = DreamJobAdmission {
        schema_version: DREAM_JOB_SCHEMA_VERSION,
        job_class: job.job_class,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: job.requester.clone(),
            session: None,
        },
        operation_id: admission.request_id.clone(),
        idempotency_key: admission.idempotency_key.clone(),
        task_id: admitted_task_id(job),
        scope_id: admission.scope_id.clone(),
        // The job side carries the fence: `verify_admitted_binding` proved it
        // equals the admitted fence before this derivation ran.
        state_fence: job.state_fence.clone(),
        privacy_profile: job.privacy_profile.clone(),
        contract_ref: format!("{}:contract", job.output_schema),
        policy_ref: format!("{}:policy", job.output_schema),
        budget,
        deadline_ms: Some(deadline_ms),
        frozen_manifest_digest: frozen_digest(admission, job)?,
    };
    admitted
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("admitted job binding invalid"))?;
    Ok(admitted)
}

/// Derives the validated owner input bundle from the admitted pair.
///
/// Evidence handles are carried as materials; memory, architecture,
/// implementation, and conformance handles are accounted as omissions (never
/// silently dropped), so the bundle honestly claims `PartialForScope` — the
/// v1 lineage owner refuses `Unknown` for a validated draft. For Orientation
/// the frame-source material (first evidence handle) carries the
/// owner-computed orientation frame digest and byte size, so the projector
/// binds exactly the frame the bundle plants. The bundle is proved with the
/// real [`DreamInputBundle::validate`](eliot_dreamer_contracts::DreamInputBundle::validate).
pub(crate) fn bundle_of(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<DreamInputBundle, DreamerError> {
    verify_admitted_binding(admission, job)?;
    // Built through `admission_of` (not reassembled) so the canonical
    // identity, task binding, and frozen digest cannot drift from the job.
    let admitted = admission_of(admission, job)?;
    let carried: BTreeSet<&str> = job.evidence_handles.iter().map(String::as_str).collect();
    let plant_frame = job.job_class == JobClass::Orientation && !job.evidence_handles.is_empty();
    let mut materials = Vec::with_capacity(job.evidence_handles.len());
    for (index, handle) in job.evidence_handles.iter().enumerate() {
        // The frame source is the first non-excluded material in bundle
        // order; every carried material is `Required`, so it is the first
        // evidence handle on both the planting and the projection sides.
        let (bytes, digest) = if plant_frame && index == 0 {
            let frame = orientation_frame_of(admission, &admitted, job, handle)?;
            (frame.body_bytes, frame.body_digest.clone())
        } else {
            (0, sha_hex(&[handle.as_str()]))
        };
        materials.push(BundleMaterial {
            handle: handle.clone(),
            disposition: SourceDisposition::Required,
            bytes,
            digest,
        });
    }
    let mut omissions = Vec::new();
    for (family, handles) in [
        ("memory", &job.memory_handles),
        ("architecture", &job.architecture_handles),
        ("implementation", &job.implementation_handles),
        ("conformance", &job.conformance_handles),
    ] {
        for handle in handles {
            // A handle carried as evidence material is never also omitted:
            // the owner refuses duplicate bundle handles.
            if carried.contains(handle.as_str()) {
                continue;
            }
            omissions.push(OmissionHandle {
                handle: handle.clone(),
                reason: format!(
                    "{family} handle held screening-side; not carried as bundle material"
                ),
                scope_id: admission.scope_id.clone(),
                task_id: admitted.task_id.clone(),
                digest: sha_hex(&["omission", handle.as_str()]),
                nonrecoverable_reason: None,
                reversible: true,
            });
        }
    }
    let bundle = DreamInputBundle {
        // `BUNDLE_SCHEMA_VERSION` is private to the owner `bundle` module and
        // is exactly 1; the owner validation proves it.
        schema_version: 1,
        job_id: admitted.canonical_id(),
        scope_id: admission.scope_id.clone(),
        task_id: admitted.task_id.clone(),
        // Same fence agreement as `admission_of`: the verify gate proved the
        // job fence equals the admitted fence.
        state_fence: job.state_fence.clone(),
        manifest_digest: admitted.frozen_manifest_digest.clone(),
        materials,
        omissions,
        completeness: BundleCompleteness::PartialForScope,
        authoritative_denominator: None,
    };
    bundle
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("admitted bundle binding invalid"))?;
    Ok(bundle)
}

/// Rebuilds the frozen manifest the bundle binds.
///
/// Deterministic in the bundle's task/scope/fence only, so the digest equals
/// the bundle's manifest digest exactly when the bundle came from
/// [`bundle_of`]; a foreign bundle yields a shell whose digest the caller-side
/// drift check refuses. The real manifest validation and digest run inside
/// [`frozen_manifest_shell`].
pub(crate) fn manifest_of(
    bundle: &DreamInputBundle,
) -> Result<AllowedReferenceManifest, DreamerError> {
    frozen_manifest_shell(
        bundle.task_id.as_str(),
        bundle.scope_id.as_str(),
        &bundle.state_fence,
    )
}

/// Returns the standing binary grounding policy.
///
/// Fixed composition constants, not per-job derivation: the policy admits the
/// full closed claim vocabulary with bounded ceilings under every owner
/// class ceiling, and no non-material residue class (retained residue refuses
/// fail-closed at the owner). The digest is owner-computed; on the impossible
/// encoding failure a well-formed hex fallback is carried instead, which the
/// owner digest check then refuses fail-closed rather than grounding under a
/// forged binding.
pub(crate) fn grounding_policy() -> GroundingPolicy {
    let mut policy = GroundingPolicy {
        schema_version: GROUNDING_SCHEMA_VERSION,
        policy_id: format!("{PROTOCOL_VERSION}:policy"),
        revision: "r1".to_owned(),
        permitted_kinds: BTreeSet::from([
            ClaimKind::NumericQuantified,
            ClaimKind::TemporalVersioned,
            ClaimKind::Causal,
            ClaimKind::AbsenceExhaustiveNegative,
            ClaimKind::ComparativeSuperlative,
            ClaimKind::QuoteAttribution,
            ClaimKind::RecommendationNormativeInference,
            ClaimKind::IdentityEntity,
        ]),
        permitted_nonmaterial_classes: BTreeSet::new(),
        max_claims: 64,
        max_subclaims_per_claim: 8,
        max_support_handles_per_claim: 8,
        max_output_bytes: 131_072,
        digest: String::new(),
    };
    policy.digest = policy
        .computed_digest()
        .unwrap_or_else(|_| sha_hex(&[policy.policy_id.as_str(), policy.revision.as_str()]));
    policy
}

/// Derives the independent A-05 usage from admitted budget limits.
///
/// Carries each ceiling verbatim with floor 1 on the counted dimensions the
/// owners require positive (`model_calls`, `attempts`, `candidates`); the
/// admitted derivation already guarantees positivity, so the floor only
/// defends foreign budgets. Usage never exceeds its limits, so the owner
/// `fits` check passes by construction; byte dimensions carry the ceilings so
/// canonical preimages always fit inside usage.
pub(crate) fn usage_of(budget: &BudgetLimits) -> BudgetUsage {
    let take = |value: Option<u64>| value.unwrap_or(0);
    BudgetUsage {
        input_bytes: take(budget.input_bytes),
        output_bytes: take(budget.output_bytes),
        source_width: take(budget.source_width),
        reference_width: take(budget.reference_width),
        model_calls: take(budget.model_calls).max(1),
        attempts: take(budget.attempts).max(1),
        candidates: take(budget.candidates).max(1),
        wall_ms: take(budget.wall_ms),
        work_fan_out: take(budget.work_fan_out),
        report_bytes: take(budget.report_bytes),
        stu_used: 0,
    }
}

/// Seals the caller validation policy bound to one admitted `policy_ref`.
///
/// The v1 and v2 owners both bind `policy.policy_id` against
/// `job.policy_ref`, so the policy identity is the admitted ref verbatim with
/// frozen revision 1 under the owner canonical-byte ceiling. Sealing is the
/// real owner digest over the receipt-excluded preimage.
pub(crate) fn validation_policy_of(policy_ref: &str) -> Result<ValidationPolicy, DreamerError> {
    let ceiling = u64::try_from(MAX_CANONICAL_BYTES)
        .map_err(|_| DreamerError::InvalidAdmission("validation policy binding invalid"))?;
    let mut policy = ValidationPolicy::new(policy_ref, 1, ceiling);
    policy
        .seal()
        .map_err(|_| DreamerError::InvalidAdmission("validation policy binding invalid"))?;
    Ok(policy)
}

/// Builds the seven-dimension preservation report for a candidate-only bundle.
///
/// Every dimension passes known with an honest candidate-only note: the
/// bundle carries handles, never promoted facts, so there is nothing to
/// preserve beyond verbatim retention. Proved with the real owner shape
/// check; `overall` is left to the validating owner.
pub(crate) fn preservation_of() -> Result<PreservationReport, DreamerError> {
    let mut verdicts = Vec::with_capacity(PRESERVATION_DIMENSIONS.len());
    for spelling in PRESERVATION_DIMENSIONS {
        verdicts.push(DimensionVerdict {
            dimension: PreservationDimension::parse(spelling)
                .map_err(|_| DreamerError::InvalidAdmission("preservation binding invalid"))?,
            passed: true,
            known: true,
            note: "candidate-only bounded bundle; verbatim retention, no fact promoted".to_owned(),
        });
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("preservation binding invalid"))?;
    Ok(report)
}

/// Builds the v2 A-05 input carrier for one grounded draft.
///
/// Derives usage, policy (bound to the admitted `policy_ref`), and
/// preservation from admitted material only, with no rival declarations and
/// no cancellation. The caller supplies the explicit observation time:
/// pass `Some(0)` (start of attempt) for jobs with a positive deadline.
/// Proved with the real [`GroundingValidationInput::new`](eliot_dreamer_contracts::validation::structured::GroundingValidationInput::new).
pub(crate) fn validation_input_for(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    grounded: GroundedDreamDraft,
    observation_time_ms: Option<u64>,
) -> Result<GroundingValidationInput, DreamerError> {
    let admitted = admission_of(admission, job)?;
    let usage = usage_of(&admitted.budget);
    let policy = validation_policy_of(admitted.policy_ref.as_str())?;
    let preservation = preservation_of()?;
    GroundingValidationInput::new(
        grounded,
        policy,
        usage,
        preservation,
        observation_time_ms,
        false,
        None,
    )
    .map_err(|_| DreamerError::InvalidAdmission("validation input binding invalid"))
}

/// Derives the v1 hypothesis text from the admitted pair.
///
/// Carries the admitted question verbatim as the single hypothesis with the
/// admitted evidence handles as its source set: no text is invented and no
/// evidence is declared confirmed (the owner forbids confirmed carry in model
/// text). Requires at least one evidence handle; a handle-only bundle with
/// no evidence refuses naming the missing source set. Proved with the real
/// v1 [`ModelDraft::validate`](eliot_dreamer_contracts::ModelDraft::validate).
pub(crate) fn v1_model_of(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
) -> Result<TextModelDraft, DreamerError> {
    let admitted = admission_of(admission, job)?;
    if job.evidence_handles.is_empty() {
        return Err(DreamerError::InvalidAdmission("no admitted source handles"));
    }
    let model = TextModelDraft {
        // `DRAFT_SCHEMA_VERSION` is private to the owner `draft` module and
        // is exactly 1; the owner validation proves it.
        schema_version: 1,
        job_id: admitted.canonical_id(),
        statement: job.exact_question.clone(),
        source_handles: job.evidence_handles.clone(),
        counterevidence: Vec::new(),
        uncertainty: "candidate-only bounded bundle; single admitted bundle".to_owned(),
        expected_benefit: "bounds the next Governor-admitted probe".to_owned(),
        recommended_probes: Vec::new(),
        invalidation_conditions: job.conflicts_and_unknowns.clone(),
        declared_confirmed_handles: Vec::new(),
    };
    model
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("admitted hypothesis binding invalid"))?;
    Ok(model)
}

/// Grounds the v1 hypothesis against the admitted (empty) manifest.
///
/// Binds the owner-computed model digest with exactly one residue carrying
/// the hypothesis verbatim. The residue state is honestly `Partial`: the
/// source handle is bound to bundle material but confirming evidence is not
/// admitted, so the v1 receipt terminal is `partial`, never success dressed
/// as truth. Proved with the real v1
/// [`GroundedDreamDraft::validate`](eliot_dreamer_contracts::GroundedDreamDraft::validate).
pub(crate) fn v1_grounded_of(model: &TextModelDraft) -> Result<TextGroundedDraft, DreamerError> {
    let draft_digest = model_digest(model)
        .map_err(|_| DreamerError::InvalidAdmission("admitted hypothesis binding invalid"))?;
    let grounded = TextGroundedDraft {
        schema_version: 1,
        job_id: model.job_id.clone(),
        draft_digest,
        residues: vec![ClaimResidue {
            claim: model.statement.clone(),
            state: SupportState::Partial,
            detail: "handle-bound hypothesis; confirming evidence not admitted".to_owned(),
        }],
        coverage_note: "one hypothesis residue; confirmation awaits governed evidence".to_owned(),
    };
    grounded
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("admitted hypothesis binding invalid"))?;
    Ok(grounded)
}

/// Derives the native orientation frame for one bindable source handle.
///
/// The question travels as both question and goal (the admitted input carries
/// no separate goal text and inventing one would be model authority) with the
/// caller conflicts verbatim, the attempt and output contract from the
/// admission and semantic input, and the frame source as given. The bundle
/// plants this exact frame on the frame-source material, so both sides bind
/// the identical owner value. Proved by construction inside the owner.
pub(crate) fn orientation_frame_of(
    admission: &KernelJobAdmission,
    admitted: &DreamJobAdmission,
    job: &DreamJobInput,
    frame_source: &str,
) -> Result<LocalOrientationFrame, DreamerError> {
    LocalOrientationFrame::new(
        job.exact_question.clone(),
        job.exact_question.clone(),
        job.conflicts_and_unknowns.clone(),
        admission.attempt_id.clone(),
        job.output_schema.clone(),
        frame_source.to_owned(),
        admitted,
    )
    .map_err(|_| DreamerError::InvalidAdmission("orientation frame binding invalid"))
}
