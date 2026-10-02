//! Governed admitted material for the Dreamer pipeline (issue #702, Slices 4-7).
//!
//! Pure derivation of every owner input the pipeline stages need —
//! [`DreamJobAdmission`](eliot_dreamer_contracts::DreamJobAdmission),
//! [`DreamInputBundle`](eliot_dreamer_contracts::DreamInputBundle),
//! [`AllowedReferenceManifest`](eliot_dreamer_contracts::grounding::AllowedReferenceManifest),
//! the A-05 validation attachment, and the v1 hypothesis pair — from the
//! admitted pair only. No retrieval, ranking, model work, or truth promotion
//! happens here: every digest below is owner-computed and every value passes
//! the real owner validation before it leaves.
//!
//! The A-14b -> A-05 handoff has exactly one production construction site, and
//! it is not here. `eliot-dreamer-claim-grounding` owns it
//! (`validation_bridge::ground_for_validation` -> `bind_validation_input`,
//! which calls the frozen `GroundingValidationInput::new`): `ARCH-MOD-03`
//! ("one causal responsibility, one owner") and the crate's own
//! `module.toml` put the carrier construction in the cell that owns the
//! `GroundedDreamDraft` it carries. This module therefore supplies only the
//! A-05 half that the owner cannot know: the policy, the usage, the seven
//! preservation verdicts each computed from the admitted fact it corresponds
//! to (admitted job, derived bundle, rebuilt frozen manifest), plus the
//! observation time the caller measures for this attempt
//! ([`observed_attempt_wall_ms`]). One preservation verdict is not derived
//! from admitted material at all: [`identity_and_closure_findings`] names the
//! one conjunct that reads the standing policy this root issues instead. A
//! member this root does not hold is either reported as the absence it is, or
//! — where the frozen contract admits no absent state at all, as with
//! `cancellation_requested` — named in the comment that carries it, never
//! turned into a fabricated default.
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
use std::time::Instant;

use eliot_contracts::{StateFence, TaskId, sha256_hex};
use eliot_dreamer_claim_grounding::ValidationAttachment;
use eliot_dreamer_contracts::budget::{
    ATTEMPTS_CEILING, CANDIDATES_CEILING, INPUT_BYTES_CEILING, MODEL_CALLS_CEILING,
    OUTPUT_BYTES_CEILING, REFERENCE_WIDTH_CEILING, REPORT_BYTES_CEILING, SOURCE_WIDTH_CEILING,
    STU_CEILING, WALL_MS_CEILING, WORK_FAN_OUT_CEILING,
};
use eliot_dreamer_contracts::candidate::{
    DimensionVerdict, PRESERVATION_DIMENSIONS, PreservationDimension,
};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, ClaimKind, GROUNDING_SCHEMA_VERSION, GroundingPolicy,
};
use eliot_dreamer_contracts::job::DREAM_JOB_SCHEMA_VERSION;
use eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES;
use eliot_dreamer_contracts::validation::model_digest;
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
/// fail-closed at the owner). The digest is owner-computed.
///
/// This is the single place in this module where a typed owner failure becomes
/// a value rather than a refusal. Everywhere else an owner `Err` becomes the
/// matching `DreamerError::InvalidAdmission` static; here
/// [`GroundingPolicy::computed_digest`](eliot_dreamer_contracts::grounding::GroundingPolicy::computed_digest)
/// returning `ContractViolation` substitutes a freshly hashed well-formed hex
/// digest instead of propagating an `Err`, so the caller receives a policy
/// rather than a refusal. The substitution is deliberate and fail-closed one
/// stage later rather than at this site: the substituted digest is a valid hex
/// encoding but not the policy's real preimage digest, so the owner's own
/// digest check — `GroundingPolicy::validate`'s
/// `computed_digest()? != self.digest`
/// (`eliot-dreamer-contracts/src/grounding/policy.rs:88-93`), which the
/// grounding owner calls on this policy — is where the refusal actually
/// happens. Nothing grounds under a forged binding.
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

/// Observes the A-05 observation time for one admitted attempt.
///
/// The A-05 owner compares this value against the admitted job's own
/// `deadline_ms` in the same unit — its `validate_budget_deadline` refuses only
/// when `observed >= deadline`, and it refuses a *missing* observation as a
/// deadline failure of its own — so the value this seam supplies must be that
/// job's elapsed wall time, measured from the moment the admitted chain for
/// this attempt began. It is a measurement, never a literal: the origin
/// belongs to the caller that owns the attempt, this function only reads the
/// clock. A monotonic reading that does not fit the wire range is fail-closed
/// rather than clamped to a value the deadline gate would read as unexpired.
pub(crate) fn observed_attempt_wall_ms(started: Instant) -> Result<u64, DreamerError> {
    u64::try_from(started.elapsed().as_millis())
        .map_err(|_| DreamerError::InvalidAdmission("admitted attempt wall clock is out of range"))
}

/// Every handle family the admitted job carries, in bundle-accounting order.
fn admitted_handle_families(job: &DreamJobInput) -> [(&'static str, &[String]); 5] {
    [
        ("evidence", job.evidence_handles.as_slice()),
        ("memory", job.memory_handles.as_slice()),
        ("architecture", job.architecture_handles.as_slice()),
        ("implementation", job.implementation_handles.as_slice()),
        ("conformance", job.conformance_handles.as_slice()),
    ]
}

/// Builds one preservation verdict from an already-computed finding.
///
/// Its two refusals are distinct owner failures and keep distinct statics: an
/// unrecognised dimension spelling is not the same fault as the report shape
/// the caller later proves with
/// [`PreservationReport::validate`](eliot_dreamer_contracts::PreservationReport::validate).
fn preservation_verdict(
    spelling: &str,
    passed: bool,
    note: String,
) -> Result<DimensionVerdict, DreamerError> {
    Ok(DimensionVerdict {
        dimension: PreservationDimension::parse(spelling).map_err(|_| {
            DreamerError::InvalidAdmission("preservation dimension spelling is not a dimension")
        })?,
        passed,
        known: true,
        note,
    })
}

/// The two accountings the derived bundle makes of the admitted handles: the
/// handles it carries as material, and the handles it accounts as omissions.
fn bundle_handle_sets(bundle: &DreamInputBundle) -> (BTreeSet<&str>, BTreeSet<&str>) {
    let carried: BTreeSet<&str> = bundle.materials.iter().map(|m| m.handle.as_str()).collect();
    let omitted: BTreeSet<&str> = bundle.omissions.iter().map(|o| o.handle.as_str()).collect();
    (carried, omitted)
}

/// Computes the preservation verdicts that read the bundle's own accounting.
///
/// `coverage`, `faithfulness`, `reversibility`, and `provenance_retention` are
/// all properties of what the derived bundle does and does not carry, so each
/// is decided here by comparing the bundle's entries with the admitted job's
/// handle families. Keys are the owner's canonical dimension spellings.
fn bundle_accounting_findings(
    bundle: &DreamInputBundle,
    job: &DreamJobInput,
) -> BTreeMap<&'static str, (bool, String)> {
    let (carried, omitted) = bundle_handle_sets(bundle);
    let admitted_evidence: BTreeSet<&str> =
        job.evidence_handles.iter().map(String::as_str).collect();
    let is_retained_digest = |value: &str| {
        value.len() == 64
            && value
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    };
    let denominator_declared_honestly = bundle.materials.len() == carried.len()
        && bundle.omissions.len() == omitted.len()
        && bundle.completeness == BundleCompleteness::PartialForScope
        && bundle.authoritative_denominator.is_none();
    let handles_kept_verbatim = bundle
        .materials
        .iter()
        .all(|m| admitted_evidence.contains(m.handle.as_str()))
        && bundle
            .materials
            .iter()
            .all(|m| m.disposition == SourceDisposition::Required)
        && bundle.completeness != BundleCompleteness::CompleteForScope;
    let omissions_recoverable = bundle
        .omissions
        .iter()
        .all(|o| o.reversible && o.nonrecoverable_reason.is_none());
    let digests_retained = bundle
        .materials
        .iter()
        .all(|m| is_retained_digest(m.digest.as_str()))
        && bundle
            .omissions
            .iter()
            .all(|o| is_retained_digest(o.digest.as_str()) && !o.reason.trim().is_empty());
    BTreeMap::from([
        (
            "coverage",
            (
                denominator_declared_honestly,
                format!(
                    "{} carried and {} omitted handles declared {:?} with no authoritative \
                     denominator",
                    carried.len(),
                    omitted.len(),
                    bundle.completeness
                ),
            ),
        ),
        (
            "faithfulness",
            (
                handles_kept_verbatim,
                format!(
                    "every one of the {} carried handles keeps its admitted handle verbatim at \
                     the Required disposition; completeness never claims a whole scope",
                    carried.len()
                ),
            ),
        ),
        (
            "reversibility",
            (
                omissions_recoverable,
                format!(
                    "all {} omitted handles are reversible with no nonrecoverable reason, and \
                     this composition performs no external effect before the handoff",
                    omitted.len()
                ),
            ),
        ),
        (
            "provenance_retention",
            (
                digests_retained,
                format!(
                    "every one of the {} carried entries retains a 64-hex owner-computed content \
                     digest, and all {} omitted entries retain their reason and record digest",
                    carried.len(),
                    omitted.len()
                ),
            ),
        ),
    ])
}

/// Computes the preservation verdicts that read identity and closure.
///
/// `lineage`, `authority_ceiling`, and `dependency_closure` are decided against
/// the admitted job: `lineage` and `dependency_closure` compare the derived
/// bundle and the rebuilt frozen manifest with the admitted job, so each of
/// those comparisons is over admitted material only. `authority_ceiling` is
/// the one exception — its third conjunct reads [`grounding_policy`], the
/// standing composition constant this root issues, not admitted material,
/// because the ceiling this root admits is a property of the root's own
/// policy. Keys are the owner's canonical dimension spellings.
fn identity_and_closure_findings(
    admitted: &DreamJobAdmission,
    bundle: &DreamInputBundle,
    manifest: &AllowedReferenceManifest,
    job: &DreamJobInput,
) -> BTreeMap<&'static str, (bool, String)> {
    let (carried, omitted) = bundle_handle_sets(bundle);
    // Bound once: the standing policy is the same value in the
    // `authority_ceiling` conjunct and in its note, and each call recomputes
    // the owner SHA-256 digest.
    let policy = grounding_policy();

    // Every admitted handle must be named exactly once across the bundle's two
    // accountings, and no handle may be both carried and omitted.
    let admitted_count: usize = admitted_handle_families(job)
        .iter()
        .map(|(_, handles)| handles.len())
        .sum();
    let mut handles_accounted = true;
    for (_, handles) in admitted_handle_families(job) {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for handle in handles {
            if !seen.insert(handle.as_str()) {
                handles_accounted = false;
            }
            if !carried.contains(handle.as_str()) && !omitted.contains(handle.as_str()) {
                handles_accounted = false;
            }
        }
    }
    let every_handle_named_once = handles_accounted
        && carried.is_disjoint(&omitted)
        && bundle.materials.iter().all(|m| !m.handle.trim().is_empty())
        && bundle.omissions.iter().all(|o| !o.handle.trim().is_empty());

    let identity_chain_intact = bundle.job_id == admitted.canonical_id()
        && bundle.scope_id == admitted.scope_id
        && bundle.task_id == admitted.task_id
        && bundle.state_fence == job.state_fence
        && bundle.manifest_digest == admitted.frozen_manifest_digest
        && manifest.digest == admitted.frozen_manifest_digest
        && bundle
            .omissions
            .iter()
            .all(|o| o.scope_id == admitted.scope_id && o.task_id == admitted.task_id);

    // The third conjunct is the one comparison here that does not read the
    // admitted job: the standing policy is this root's own composition
    // constant (see this function's doc and [`grounding_policy`]).
    let ceiling_respected = manifest.references.is_empty()
        && bundle.authoritative_denominator.is_none()
        && policy.permitted_nonmaterial_classes.is_empty();

    BTreeMap::from([
        (
            "lineage",
            (
                identity_chain_intact,
                format!(
                    "bundle job, scope, task, fence, and frozen manifest digest agree with the \
                     admitted job and the rebuilt manifest; all {} omissions carry the same \
                     scope and task",
                    omitted.len()
                ),
            ),
        ),
        (
            "authority_ceiling",
            (
                ceiling_respected,
                format!(
                    "the rebuilt frozen manifest admits {} references, the bundle claims no \
                     authoritative denominator, and the standing grounding policy this root \
                     issues admits {} non-material residue classes; the owner caps every \
                     retained record itself",
                    manifest.references.len(),
                    policy.permitted_nonmaterial_classes.len()
                ),
            ),
        ),
        (
            "dependency_closure",
            (
                every_handle_named_once,
                format!(
                    "all {admitted_count} admitted handles are named exactly once across {} \
                     carried and {} omitted entries; none is dropped, duplicated, or both",
                    carried.len(),
                    omitted.len()
                ),
            ),
        ),
    ])
}

/// Builds the seven-dimension preservation report from the admitted material.
///
/// Each verdict is a comparison over admitted material this root actually
/// holds — the derived bundle, the rebuilt frozen manifest, and the admitted
/// job — with the single exception named in
/// [`identity_and_closure_findings`]. Each note states the counts that
/// comparison read, and those counts are the whole of the report's
/// discriminating content: what separates one admitted job's report from
/// another's is the admitted handle counts the comparisons read (`carried`,
/// `omitted`, the admitted handle total, the rebuilt manifest's reference
/// count, the standing policy's non-material class count), plus the
/// construction-fixed completeness the `coverage` note renders. No note
/// carries `job_id`, `scope_id`, `task_id`, `exact_question`, `budget_units`,
/// `deadline_ms`, `privacy_profile`, or `allowed_model_routes`, so two distinct
/// admitted jobs whose handle families have equal counts produce
/// byte-identical reports. A report for an admitted job with different handle
/// counts is therefore distinguishable from this one, and that weaker statement
/// is the one the composition-root proof asserts.
///
/// The comparisons are real derivations, not literals, and they stay: they are
/// what would decide the verdict if their inputs disagreed, and removing them
/// would delete the derivation rather than strengthen the claim. What the
/// measured truth is that on today's tree no admitted job can make any of them
/// fail. Duplicate handles are already refused by the real `bundle.validate()`
/// (bundle.rs:217-228) before [`bundle_of`] returns, so the `dependency_closure`
/// arm cannot fail;
/// `manifest.references` is empty by construction; the standing grounding
/// policy's permitted non-material classes are an empty set; `reversible: true`
/// and `nonrecoverable_reason: None` are fixed at construction; the disposition,
/// completeness, and denominator values are fixed at construction; and the
/// lineage comparisons compare fields [`bundle_of`] itself copied from the
/// admitted job. So on the current tree all seven verdicts pass by
/// construction. A structural re-derivation that could actually fail belongs
/// to the A-05 owner
/// (`candidate-validation/src/structured/validate.rs`), which re-checks these
/// properties against the grounded value it holds.
///
/// Every dimension is derived here, so none of them is reported as unmeasured:
/// a dimension this root could not derive is refused, not passed on a guess.
/// That refusal is the `Err` at the bottom of this function —
/// `DreamerError::InvalidAdmission("preservation dimension is not derived")` —
/// so no dimension is ever emitted with `known: false`;
/// [`preservation_verdict`] sets that field to `true` on every verdict it
/// builds, and a dimension that never reaches it never reaches a report.
///
/// The A-05 owner re-derives the same properties structurally against the
/// grounded value it holds
/// (`eliot_dreamer_candidate_validation::validate_preservation_evidence`),
/// so this report is the caller's half of that check — the admitted-input half
/// — and not a replacement for it. Proved with the real owner shape check;
/// `overall` is left to the validating owner.
pub(crate) fn preservation_of(
    admitted: &DreamJobAdmission,
    bundle: &DreamInputBundle,
    manifest: &AllowedReferenceManifest,
    job: &DreamJobInput,
) -> Result<PreservationReport, DreamerError> {
    let mut computed = identity_and_closure_findings(admitted, bundle, manifest, job);
    computed.extend(bundle_accounting_findings(bundle, job));
    let mut verdicts = Vec::with_capacity(PRESERVATION_DIMENSIONS.len());
    for spelling in PRESERVATION_DIMENSIONS {
        let Some((passed, note)) = computed.remove(*spelling) else {
            return Err(DreamerError::InvalidAdmission(
                "preservation dimension is not derived",
            ));
        };
        verdicts.push(preservation_verdict(spelling, passed, note)?);
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|_| DreamerError::InvalidAdmission("preservation binding invalid"))?;
    Ok(report)
}

/// Supplies the A-05 half of the A-14b -> A-05 handoff for one admission.
///
/// This is **not** a carrier: it is the explicitly supplied
/// [`ValidationAttachment`] the owning crate binds to the grounded draft. Every
/// member is derived from admitted material or measured by the caller — usage
/// from the admitted budget, policy sealed against the admitted `policy_ref`,
/// the seven preservation verdicts each computed from the derived bundle and
/// the rebuilt frozen manifest - with the single `authority_ceiling` exception
/// named in [`identity_and_closure_findings`] - and `observation_time_ms` as
/// the caller
/// measured it for this attempt ([`observed_attempt_wall_ms`]). The observation
/// is the admitted job's own elapsed wall time because that is the unit the
/// owner compares it against; it is never a literal, and the owner refuses a
/// deadline without an explicit observation, so an honest absence would be a
/// refusal rather than a pass.
///
/// Two members this root does not hold are reported differently, because the
/// frozen contract treats them differently.
///
/// `rival_declarations` is `None`: rival declarations are not admitted
/// material on this path, absence is recorded as absence, and it is never
/// filled from the grounded value, the ledger, or model text.
///
/// `cancellation_requested` is a frozen `bool`, not an `Option<bool>`
/// (`eliot_dreamer_contracts::validation::structured::GroundingValidationInput`),
/// so the field has no absent state: a `false` supplied here is read
/// downstream as an authoritative "not cancelled" and is consumed as such
/// (A-05's `validate_budget_deadline` rejects on `true` alone). The value
/// below is therefore not a recorded absence of observation — it is the
/// negative this path asserts, and it is asserted without consulting the
/// cancellation identity the root does hold:
/// [`KernelJobAdmission::cancellation_id`]. That identity is a Kernel-owned
/// handle with no local cancellation signal behind it on this path, so
/// nothing here checks, and the honest reading of this member is "this
/// composition did not observe a cancellation", not "cancellation was
/// checked and is absent". The missing tri-state belongs to the frozen
/// contract, which this root does not restate; it is recorded as a Contract
/// Challenge rather than papered over here.
///
/// The carrier itself is constructed in exactly one production place, inside
/// the crate whose `module.toml` claims that ownership
/// (`eliot_dreamer_claim_grounding::validation_bridge`).
pub(crate) fn validation_attachment_for(
    admission: &KernelJobAdmission,
    job: &DreamJobInput,
    observation_time_ms: Option<u64>,
) -> Result<ValidationAttachment, DreamerError> {
    let admitted = admission_of(admission, job)?;
    let bundle = bundle_of(admission, job)?;
    let manifest = manifest_of(&bundle)?;
    Ok(ValidationAttachment {
        policy: validation_policy_of(admitted.policy_ref.as_str())?,
        usage: usage_of(&admitted.budget),
        preservation: preservation_of(&admitted, &bundle, &manifest, job)?,
        observation_time_ms,
        // See the module-level note above: the frozen field admits no
        // unobserved state, so this `false` is an asserted negative and the
        // `cancellation_id` this root holds is not consulted to reach it.
        cancellation_requested: false,
        // No rival declarations are admitted material on this path.
        rival_declarations: None,
    })
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
