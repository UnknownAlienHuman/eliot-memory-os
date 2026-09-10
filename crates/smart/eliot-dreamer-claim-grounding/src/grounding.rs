//! Public operation and deterministic claim-denominator construction.

use std::collections::{BTreeMap, BTreeSet};

use eliot_dreamer_contracts::grounding::canonical::{GradeAssignment, SupportResult};
use eliot_dreamer_contracts::grounding::{
    AllowedReferenceManifest, ClaimGroundingLedger, GROUNDING_SCHEMA_VERSION, GroundedDreamDraft,
    GroundingPolicy, ModelDraft,
};
use eliot_dreamer_contracts::{
    ContractViolation, DreamInputBundle, DreamJobInput, canonical_bytes,
};

use crate::evidence;
use crate::precision;

const OUTPUT_FRONTIER_RESERVATION_REASON: &str = "grounding output byte cap exhausted";

/// An injected cancellation/deadline observation. It is never read from a
/// clock, runtime, environment, or ambient global.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cancellation {
    /// The operation may continue.
    NotCancelled,
    /// Stop before the next atomic claim, retaining the supplied reason.
    Cancelled(String),
}

/// Non-serialized execution controls for one pure grounding invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundingControls {
    /// Maximum number of whole claims to consume. The operation requires an
    /// explicit finite value; no ambient quota is consulted.
    pub whole_claim_quota: Option<usize>,
    /// Explicit cancellation observation.
    pub cancellation: Cancellation,
    /// Explicit deadline observation supplied by the caller.
    pub deadline_exceeded: bool,
}

impl Default for GroundingControls {
    fn default() -> Self {
        Self {
            whole_claim_quota: Some(4_096),
            cancellation: Cancellation::NotCancelled,
            deadline_exceeded: false,
        }
    }
}

/// Complete owned input to the pure grounding operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroundingRequest {
    pub job: DreamJobInput,
    pub bundle: DreamInputBundle,
    pub manifest: AllowedReferenceManifest,
    pub draft: ModelDraft,
    pub policy: GroundingPolicy,
    pub controls: GroundingControls,
}

impl GroundingRequest {
    /// Creates a request with the bounded default quota and no injected stop
    /// signal.
    #[must_use]
    pub fn new(
        job: DreamJobInput,
        bundle: DreamInputBundle,
        manifest: AllowedReferenceManifest,
        draft: ModelDraft,
        policy: GroundingPolicy,
    ) -> Self {
        Self {
            job,
            bundle,
            manifest,
            draft,
            policy,
            controls: GroundingControls::default(),
        }
    }

    /// Adds explicit execution controls without changing any serialized input.
    #[must_use]
    pub fn with_controls(mut self, controls: GroundingControls) -> Self {
        self.controls = controls;
        self
    }
}

/// Grounds one complete A03 v2 context. Only explicit proposed handles are
/// inspected; no manifest-wide search is performed.
pub fn ground_draft(
    job: DreamJobInput,
    bundle: DreamInputBundle,
    manifest: AllowedReferenceManifest,
    draft: ModelDraft,
    policy: GroundingPolicy,
) -> Result<GroundedDreamDraft, ContractViolation> {
    ground_draft_with_controls(GroundingRequest::new(job, bundle, manifest, draft, policy))
}

/// Executes grounding with explicit finite quota and injected stop signals.
#[allow(clippy::too_many_lines)]
pub fn ground_draft_with_controls(
    request: GroundingRequest,
) -> Result<GroundedDreamDraft, ContractViolation> {
    validate_inputs(&request)?;
    validate_controls(&request.controls)?;
    let Some(job_output_cap) = request.job.budget.output_bytes else {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "grounding requires an explicit output byte cap".into(),
        });
    };
    let output_cap = job_output_cap.min(request.policy.max_output_bytes);
    let GroundingRequest {
        job: _,
        bundle: _,
        manifest,
        draft,
        policy,
        controls,
    } = request;

    let order: Vec<String> = {
        let claims_by_id: BTreeMap<_, _> = draft
            .claims
            .iter()
            .map(|claim| (claim.claim_id.as_str(), claim))
            .collect();
        postorder(&claims_by_id)
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    };
    let has_claims = !order.is_empty();
    let expected_claim_ids: BTreeSet<_> = draft.claims.iter().map(|c| c.claim_id.clone()).collect();
    let expected_subclaim_ids: BTreeMap<_, _> = draft
        .claims
        .iter()
        .map(|claim| (claim.claim_id.clone(), claim.subclaim_ids.clone()))
        .collect();
    let nonmaterial_claim_ids: BTreeSet<_> = draft
        .non_material_claims
        .iter()
        .map(|claim| claim.claim_id.clone())
        .collect();
    let mut quota = controls.whole_claim_quota;
    let mut stop_reason = stop_reason(&controls);
    if quota == Some(0) && stop_reason.is_none() {
        stop_reason = Some("whole-claim quota exhausted".to_owned());
    }
    let mut grounded = initial_grounded(
        draft,
        manifest,
        policy,
        expected_claim_ids,
        expected_subclaim_ids,
        nonmaterial_claim_ids,
        stop_reason
            .clone()
            .or_else(|| has_claims.then_some(OUTPUT_FRONTIER_RESERVATION_REASON.to_owned())),
        output_cap,
    )?;

    for claim_id in order {
        let Some(claim) = grounded
            .input
            .claims
            .iter()
            .find(|claim| claim.claim_id == claim_id)
            .cloned()
        else {
            continue;
        };
        if stop_reason.is_some() || quota == Some(0) {
            if stop_reason.is_none() {
                stop_reason = Some("whole-claim quota exhausted".to_owned());
            }
            continue;
        }
        let mut record = evidence::evaluate_claim(&claim, &grounded.manifest, &grounded.policy)?;
        if grounded.input.job.job_class == eliot_dreamer_contracts::JobClass::Curation
            && !claim_screen_matches(&grounded.input, &claim)
        {
            if matches!(
                record.disposition,
                SupportResult::Supported | SupportResult::Partial
            ) {
                record.disposition = SupportResult::Unknown;
            }
            record.unknowns.insert(
                "curation screen binding is absent or differs from the input screen".into(),
            );
            evidence::recompute_record_assertability(&mut record);
            evidence::cap_record_assertability(
                &mut record,
                eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate,
            );
        }
        aggregate_parent_record(
            &grounded.input,
            grounded.input.job.job_class,
            &claim,
            &mut record,
            &grounded.ledger.records,
        )?;
        if let Err(error) = finalize_record(&mut record, output_cap) {
            if is_output_budget_error(&error) {
                grounded.ledger.unprocessed_reason =
                    Some(OUTPUT_FRONTIER_RESERVATION_REASON.to_owned());
                stop_reason.clone_from(&grounded.ledger.unprocessed_reason);
                break;
            }
            return Err(error);
        }
        grounded
            .ledger
            .records
            .insert(claim.claim_id.clone(), record);
        grounded
            .ledger
            .unprocessed_claim_ids
            .remove(&claim.claim_id);
        grounded.ledger.unprocessed_reason = (!grounded.ledger.unprocessed_claim_ids.is_empty())
            .then_some(OUTPUT_FRONTIER_RESERVATION_REASON.to_owned());
        if let Err(error) = check_grounded_output_budget(&grounded, output_cap)
            .and_then(|()| refresh_grounded(&mut grounded))
        {
            if is_output_budget_error(&error) {
                grounded.ledger.records.remove(&claim.claim_id);
                grounded
                    .ledger
                    .unprocessed_claim_ids
                    .insert(claim.claim_id.clone());
                let reason = OUTPUT_FRONTIER_RESERVATION_REASON.to_owned();
                grounded.ledger.unprocessed_reason = Some(reason.clone());
                stop_reason = Some(reason);
                refresh_grounded(&mut grounded)?;
                break;
            }
            return Err(error);
        }
        if let Some(left) = quota.as_mut() {
            *left = left.saturating_sub(1);
        }
    }

    if grounded.ledger.unprocessed_claim_ids.is_empty() {
        stop_reason = None;
    }
    grounded.ledger.unprocessed_reason = stop_reason;
    refresh_grounded(&mut grounded)?;
    Ok(grounded)
}

#[allow(clippy::too_many_arguments)]
fn initial_grounded(
    draft: ModelDraft,
    manifest: AllowedReferenceManifest,
    policy: GroundingPolicy,
    expected_claim_ids: BTreeSet<String>,
    expected_subclaim_ids: BTreeMap<String, BTreeSet<String>>,
    nonmaterial_claim_ids: BTreeSet<String>,
    unprocessed_reason: Option<String>,
    output_cap: u64,
) -> Result<GroundedDreamDraft, ContractViolation> {
    let unprocessed_claim_ids = expected_claim_ids.clone();
    let ledger = ClaimGroundingLedger {
        schema_version: GROUNDING_SCHEMA_VERSION,
        operation_id: draft.job.operation_id.clone(),
        run_id: manifest.run_id.clone(),
        job_id: draft.job_id.clone(),
        task_id: draft.task_id.clone(),
        scope_id: draft.scope_id.clone(),
        state_fence: draft.state_fence.clone(),
        draft_digest: draft.draft_digest.clone(),
        manifest_digest: manifest.digest.clone(),
        policy_digest: policy.digest.clone(),
        expected_claim_ids,
        expected_subclaim_ids,
        records: BTreeMap::new(),
        nonmaterial_claim_ids,
        unprocessed_claim_ids,
        unprocessed_reason,
        ledger_digest: String::new(),
    };
    let mut grounded = GroundedDreamDraft {
        schema_version: GROUNDING_SCHEMA_VERSION,
        job_id: draft.job_id.clone(),
        task_id: draft.task_id.clone(),
        scope_id: draft.scope_id.clone(),
        state_fence: draft.state_fence.clone(),
        draft_digest: draft.draft_digest.clone(),
        manifest_digest: manifest.digest.clone(),
        policy_digest: policy.digest.clone(),
        screen: draft.screen.clone(),
        input: draft,
        manifest,
        policy,
        ledger,
        output_digest: String::new(),
    };
    check_grounded_output_budget(&grounded, output_cap)?;
    refresh_grounded(&mut grounded)?;
    Ok(grounded)
}

fn refresh_grounded(grounded: &mut GroundedDreamDraft) -> Result<(), ContractViolation> {
    grounded.ledger.ledger_digest = grounded.ledger.computed_digest()?;
    grounded.output_digest = grounded.computed_digest()?;
    grounded.validate()
}

fn is_output_budget_error(error: &ContractViolation) -> bool {
    matches!(
        error,
        ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            ..
        }
    )
}

fn finalize_record(
    record: &mut eliot_dreamer_contracts::grounding::ClaimGroundingRecord,
    output_cap: u64,
) -> Result<(), ContractViolation> {
    let mut probe = record.clone();
    probe.record_digest = "0".repeat(64);
    let size = canonical_bytes(&probe)?.len();
    if u64::try_from(size).unwrap_or(u64::MAX) > output_cap {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "claim grounding record exceeds the retained output byte cap".into(),
        });
    }
    record.record_digest = record.computed_digest()?;
    Ok(())
}

fn check_grounded_output_budget(
    grounded: &GroundedDreamDraft,
    output_cap: u64,
) -> Result<(), ContractViolation> {
    let mut probe = grounded.clone();
    probe.ledger.ledger_digest = "0".repeat(64);
    probe.output_digest = "0".repeat(64);
    let size = canonical_bytes(&probe)?.len();
    if u64::try_from(size).unwrap_or(u64::MAX) > output_cap {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "grounded draft exceeds the retained output byte cap".into(),
        });
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_inputs(request: &GroundingRequest) -> Result<(), ContractViolation> {
    request.job.validate()?;
    request.bundle.validate()?;
    request.draft.validate()?;
    request.manifest.validate()?;
    request.policy.validate()?;
    let Some(input_bytes) = request.job.budget.input_bytes else {
        return Err(ContractViolation::Budget {
            dimension: "grounding_input_bytes",
            reason: "grounding requires an explicit input byte cap".into(),
        });
    };
    let Some(output_bytes) = request.job.budget.output_bytes else {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "grounding requires an explicit output byte cap".into(),
        });
    };
    if request.policy.max_output_bytes > output_bytes {
        return Err(ContractViolation::Budget {
            dimension: "grounding_output_bytes",
            reason: "policy output ceiling exceeds the retained job budget".into(),
        });
    }
    // A03's typed digest/validation path performs the bounded streaming
    // preflight for every retained input component before any claim work.
    // Keep the caller's explicit input cap in the request contract as well.
    if input_bytes == 0 {
        return Err(ContractViolation::Budget {
            dimension: "grounding_input_bytes",
            reason: "input byte cap must be non-zero".into(),
        });
    }
    let admitted_material_bytes =
        request
            .bundle
            .materials
            .iter()
            .try_fold(0_u64, |total, material| {
                total
                    .checked_add(material.bytes)
                    .ok_or(ContractViolation::Budget {
                        dimension: "grounding_input_bytes",
                        reason: "admitted material byte count overflow".into(),
                    })
            })?;
    if admitted_material_bytes > input_bytes {
        return Err(ContractViolation::Budget {
            dimension: "grounding_input_bytes",
            reason: "admitted material bytes exceed the retained job budget".into(),
        });
    }
    let canonical_input_bytes = canonical_bytes(&(
        &request.job,
        &request.bundle,
        &request.manifest,
        &request.draft,
        &request.policy,
    ))?;
    if u64::try_from(canonical_input_bytes.len()).unwrap_or(u64::MAX) > input_bytes {
        return Err(ContractViolation::Budget {
            dimension: "grounding_input_bytes",
            reason: "canonical retained input exceeds the job byte budget".into(),
        });
    }
    if request.job.policy_ref != request.policy.policy_id {
        return Err(ContractViolation::BindingMismatch {
            field: "policy_ref",
            reason: "job policy reference differs from the retained grounding policy".into(),
        });
    }
    let Some(reference_width) = request.job.budget.reference_width else {
        return Err(ContractViolation::Budget {
            dimension: "reference_width",
            reason: "grounding requires an explicit reference width cap".into(),
        });
    };
    let reference_count = u64::try_from(request.manifest.references.len()).map_err(|_| {
        ContractViolation::Budget {
            dimension: "reference_width",
            reason: "retained reference count cannot be represented".into(),
        }
    })?;
    if reference_count > reference_width {
        return Err(ContractViolation::Budget {
            dimension: "reference_width",
            reason: "retained references exceed the job width budget".into(),
        });
    }
    let Some(source_width) = request.job.budget.source_width else {
        return Err(ContractViolation::Budget {
            dimension: "source_width",
            reason: "grounding requires an explicit source width cap".into(),
        });
    };
    let mut source_owners = BTreeSet::new();
    for reference in request.manifest.references.values() {
        if let Some(lineage) = &reference.source_lineage {
            source_owners.insert(lineage.owner.clone());
        }
        if let Some(provenance) = &reference.provenance {
            for lineage in &provenance.lineage {
                source_owners.insert(lineage.owner.clone());
            }
        }
    }
    let source_count =
        u64::try_from(source_owners.len()).map_err(|_| ContractViolation::Budget {
            dimension: "source_width",
            reason: "retained source count cannot be represented".into(),
        })?;
    if source_count > source_width {
        return Err(ContractViolation::Budget {
            dimension: "source_width",
            reason: "retained sources exceed the job width budget".into(),
        });
    }
    for (handle, reference) in &request.manifest.references {
        for assertion in &reference.assertions {
            assertion.validate_for(
                handle,
                &request.manifest.task_id,
                &request.manifest.scope_id,
                &request.manifest.state_fence,
            )?;
        }
    }
    if request.draft.claims.len() > request.policy.max_claims as usize
        || request.draft.claims.iter().any(|claim| {
            claim.subclaim_ids.len() > request.policy.max_subclaims_per_claim as usize
                || claim.proposed_support.len()
                    > request.policy.max_support_handles_per_claim as usize
                || claim.proposed_counterevidence.len()
                    > request.policy.max_support_handles_per_claim as usize
        })
        || request.draft.non_material_claims.iter().any(|claim| {
            !request
                .policy
                .permitted_nonmaterial_classes
                .contains(&claim.category)
        })
    {
        return Err(ContractViolation::Budget {
            dimension: "grounding_policy",
            reason: "retained input exceeds the policy ceilings".into(),
        });
    }
    if request.draft.job != request.job || request.draft.bundle != request.bundle {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_input",
            reason: "job or bundle differs from the retained model draft".into(),
        });
    }
    if request.manifest.digest != request.draft.input_manifest_digest
        || request.job.frozen_manifest_digest != request.manifest.digest
        || request.manifest.task_id != request.draft.task_id
        || request.manifest.scope_id != request.draft.scope_id
        || request.manifest.state_fence != request.draft.state_fence
    {
        return Err(ContractViolation::BindingMismatch {
            field: "grounding_input",
            reason: "manifest does not match the draft's frozen context".into(),
        });
    }
    Ok(())
}

fn validate_controls(controls: &GroundingControls) -> Result<(), ContractViolation> {
    if controls.whole_claim_quota.is_none() {
        return Err(ContractViolation::Budget {
            dimension: "whole_claim_work",
            reason: "grounding requires a finite whole-claim quota".into(),
        });
    }
    if let Cancellation::Cancelled(reason) = &controls.cancellation {
        if reason.trim().is_empty() {
            return Ok(());
        }
        if reason.len() > 256 {
            return Err(ContractViolation::OutOfBounds {
                field: "cancellation.reason",
                min: 1,
                max: 256,
                got: i64::try_from(reason.len()).unwrap_or(i64::MAX),
            });
        }
        if reason.chars().any(char::is_control) {
            return Err(ContractViolation::Malformed {
                field: "cancellation.reason",
                reason: "reason contains control characters".into(),
            });
        }
    }
    Ok(())
}

fn stop_reason(controls: &GroundingControls) -> Option<String> {
    match &controls.cancellation {
        Cancellation::Cancelled(reason) => Some(if reason.trim().is_empty() {
            "operation cancelled".to_owned()
        } else {
            reason.clone()
        }),
        Cancellation::NotCancelled if controls.deadline_exceeded => {
            Some("injected deadline observation".to_owned())
        }
        Cancellation::NotCancelled => None,
    }
}

fn claim_screen_matches(
    draft: &ModelDraft,
    claim: &eliot_dreamer_contracts::grounding::MaterialClaim,
) -> bool {
    claim
        .screen_target
        .as_ref()
        .is_some_and(|target| Some(&target.screen) == draft.screen.as_ref())
}

#[allow(clippy::too_many_lines)]
fn aggregate_parent_record(
    draft: &ModelDraft,
    job_class: eliot_dreamer_contracts::JobClass,
    claim: &eliot_dreamer_contracts::grounding::MaterialClaim,
    record: &mut eliot_dreamer_contracts::grounding::ClaimGroundingRecord,
    existing: &BTreeMap<String, eliot_dreamer_contracts::grounding::ClaimGroundingRecord>,
) -> Result<(), ContractViolation> {
    if claim.subclaim_ids.is_empty() {
        return Ok(());
    }
    let mut child_result = None;
    let mut child_grade_ceiling: Option<
        eliot_dreamer_contracts::grounding::canonical::EvidenceGrade,
    > = None;
    let mut child_assertability = None;
    let mut child_coverage = BTreeSet::new();
    let mut child_dependence = BTreeSet::new();
    let mut child_assignments = Vec::new();
    let mut complete = true;
    let mut child_unknowns = BTreeSet::new();
    let mut child_precision_findings = BTreeSet::new();
    for child_id in &claim.subclaim_ids {
        let Some(child) = existing.get(child_id) else {
            complete = false;
            continue;
        };
        child_result = Some(match child_result {
            Some(current) => evidence::aggregate_pair(current, child.disposition),
            None => child.disposition,
        });
        child_grade_ceiling = Some(match child_grade_ceiling {
            Some(current) => current.min(child.grade_ceiling),
            None => child.grade_ceiling,
        });
        if let Some(grade) = &child.grade {
            child_assignments.push(grade.clone());
        }
        child_assertability = Some(match child_assertability {
            Some(current) => weaker_assertability(current, child.assertability_ceiling),
            None => child.assertability_ceiling,
        });
        child_coverage.extend(child.coverage_denominator_ids.iter().cloned());
        child_dependence.extend(child.dependence_groups.iter().cloned());
        child_unknowns.extend(child.unknowns.iter().cloned());
        child_precision_findings.extend(child.precision_findings.iter().cloned());
    }
    let Some(child_result) = child_result else {
        return Ok(());
    };
    if !complete {
        record.disposition = SupportResult::Unknown;
        record
            .unknowns
            .insert("subclaim closure is incomplete".into());
    } else if record.component_outcomes.is_empty() {
        record.disposition = child_result;
    } else {
        record.disposition = evidence::aggregate_pair(record.disposition, child_result);
    }
    if let Some(child_grade_ceiling) = child_grade_ceiling {
        if record.component_outcomes.is_empty() {
            record.grade_ceiling = child_grade_ceiling;
        } else {
            record.grade_ceiling = record.grade_ceiling.min(child_grade_ceiling);
        }
    }
    if !child_assignments.is_empty() {
        if let Some(own_grade) = &record.grade {
            child_assignments.push(own_grade.clone());
        }
        record.grade = Some(
            GradeAssignment::weakest(&child_assignments).map_err(|error| {
                ContractViolation::BindingMismatch {
                    field: "child.grade",
                    reason: error.to_string(),
                }
            })?,
        );
        record.grade_ceiling = record
            .grade
            .as_ref()
            .and_then(GradeAssignment::known_grade)
            .unwrap_or(record.grade_ceiling);
    }
    if let Some(child_assertability) = child_assertability {
        evidence::cap_record_assertability(record, child_assertability);
    }
    if !matches!(
        claim.payload,
        eliot_dreamer_contracts::grounding::PrecisionPayload::AbsenceExhaustiveNegative { .. }
    ) {
        record.coverage_denominator_ids.extend(child_coverage);
    }
    record.dependence_groups.extend(child_dependence);
    record.unknowns.extend(child_unknowns);
    record.precision_findings.extend(child_precision_findings);
    if job_class == eliot_dreamer_contracts::JobClass::Curation
        && !claim_screen_matches(draft, claim)
        && matches!(
            record.disposition,
            SupportResult::Supported | SupportResult::Partial
        )
    {
        record.disposition = SupportResult::Unknown;
        record
            .unknowns
            .insert("curation screen binding is absent or differs from the input screen".into());
    }
    if !precision::class_is_groundable(claim, !record.coverage_denominator_ids.is_empty())
        && record.disposition == SupportResult::Supported
    {
        record.disposition = SupportResult::Unknown;
        record
            .precision_findings
            .insert("typed precision payload is incomplete for grounding".into());
    }
    evidence::recompute_record_assertability(record);
    evidence::cap_record_assertability(
        record,
        eliot_dreamer_contracts::grounding::canonical::PositionAssertability::HypothesisCandidate,
    );
    Ok(())
}

fn weaker_assertability(
    left: eliot_dreamer_contracts::grounding::canonical::PositionAssertability,
    right: eliot_dreamer_contracts::grounding::canonical::PositionAssertability,
) -> eliot_dreamer_contracts::grounding::canonical::PositionAssertability {
    use eliot_dreamer_contracts::grounding::canonical::PositionAssertability;
    let rank = |value| match value {
        PositionAssertability::UnknownWithheldQuarantined => 0,
        PositionAssertability::PlanningOnly => 1,
        PositionAssertability::HypothesisCandidate => 2,
        PositionAssertability::ConflictQualificationRequired => 3,
        PositionAssertability::QualifiedInference => 4,
        PositionAssertability::ObservedFact => 5,
        PositionAssertability::MaterialEffect => 6,
    };
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}

fn postorder<'a>(
    claims: &BTreeMap<&'a str, &'a eliot_dreamer_contracts::grounding::MaterialClaim>,
) -> Vec<&'a str> {
    let children: BTreeSet<&str> = claims
        .values()
        .flat_map(|claim| claim.subclaim_ids.iter().map(String::as_str))
        .collect();
    let mut roots: Vec<_> = claims
        .keys()
        .copied()
        .filter(|id| !children.contains(id))
        .collect();
    roots.sort_unstable();
    let mut output = Vec::with_capacity(claims.len());
    let mut visited = BTreeSet::new();
    for root in roots {
        let mut stack = vec![(root, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                output.push(id);
                continue;
            }
            if !visited.insert(id) {
                continue;
            }
            stack.push((id, true));
            if let Some(claim) = claims.get(id) {
                let mut ids: Vec<_> = claim.subclaim_ids.iter().map(String::as_str).collect();
                ids.sort_unstable_by(|left, right| right.cmp(left));
                for child in ids {
                    if !visited.contains(child) {
                        stack.push((child, false));
                    }
                }
            }
        }
    }
    let mut rest: Vec<_> = claims
        .keys()
        .copied()
        .filter(|id| !visited.contains(id))
        .collect();
    rest.sort_unstable();
    for id in rest {
        let mut stack = vec![(id, false)];
        while let Some((current, expanded)) = stack.pop() {
            if expanded {
                output.push(current);
                continue;
            }
            if !visited.insert(current) {
                continue;
            }
            stack.push((current, true));
            if let Some(claim) = claims.get(current) {
                let mut ids: Vec<_> = claim.subclaim_ids.iter().map(String::as_str).collect();
                ids.sort_unstable_by(|left, right| right.cmp(left));
                for child in ids {
                    if !visited.contains(child) {
                        stack.push((child, false));
                    }
                }
            }
        }
    }
    output
}
