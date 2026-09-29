//! Bounded A14 activation over an immutable A10 build candidate.
use crate::derived_stage::{DerivedStage, RelationCoverage};
use crate::profile::RelationDirection;
use crate::publication::PublicationGrant;
use crate::{ActivationError, ActivationProfile};
use eliot_cue_contracts::{
    ActivationRequest, ActivationResult, ActivationResultSpec, ActivationStrength, ActivationTrace,
    AdmittedCueBindingProjection, BoundKind, Completeness, CueContractError,
    CueSnapshotBuildCandidate, DerivedActivation, DirectActivation, LifecycleState, MatchMode,
    NormalizedCue, RelationEdge, RelationEdgeId, TargetHandle, TraceStep, WorkScopeId,
};
use eliot_evidence::{EpistemicStatus, EvidenceFreshness};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;

/// A result bound to the exact candidate, request and numerical policy used.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueActivationEvaluation {
    pub policy_id: String,
    pub policy_revision: u32,
    pub policy_digest: eliot_cue_contracts::Digest,
    pub candidate_build_digest: eliot_cue_contracts::Digest,
    pub input_digest: eliot_cue_contracts::Digest,
    /// Disposition of the optional relation-derived stage.
    ///
    /// The direct domain and the optional relation domain are reported apart, so
    /// absent, stale, unqualified, or bounded relation coverage can never be
    /// read as a direct-match absence.
    pub derived_stage: DerivedStage,
    pub result: ActivationResult,
}

#[derive(Clone, Debug)]
struct SearchState {
    target: TargetHandle,
    direct_seed: TargetHandle,
    score: ActivationStrength,
    path: Vec<RelationEdgeId>,
}

#[derive(Serialize)]
struct CanonicalInput<'a> {
    domain: &'static str,
    candidate_payload: &'a [u8],
    request: &'a ActivationRequest,
    profile: &'a ActivationProfile,
}

#[derive(Default)]
struct Budget {
    work: u64,
    nodes: u32,
    edges: u32,
}

/// Evaluates direct and forward relation activation with fixed supplied policy.
///
/// The operation performs no normalization, indexing, graph discovery, I/O or
/// authority decision. The candidate's active/current labels are checked as
/// supplied assertions, and the returned result remains a retrieval signal.
pub fn evaluate_activation(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
) -> Result<CueActivationEvaluation, ActivationError> {
    preflight(candidate, request, profile)?;
    if request.cancelled {
        return Err(ActivationError::Cancelled);
    }
    if let Some(deadline) = request.deadline_ms {
        let observed = request
            .observed_at
            .valid_time_ms
            .ok_or(ActivationError::Deadline)?;
        if observed > deadline {
            return Err(ActivationError::Deadline);
        }
    }
    let input_digest = input_digest(candidate, request, profile)?;
    let mut budget = Budget::default();
    let direct = direct_phase(candidate, request, profile, &mut budget)?;
    let outcome = derived_stage(candidate, request, profile, &direct, &mut budget)?;
    let result = assemble_result(
        request,
        direct,
        outcome.derived,
        outcome.trace,
        outcome.completeness,
    )?;
    let evaluation = CueActivationEvaluation {
        policy_id: profile.profile_id.clone(),
        policy_revision: profile.profile_revision,
        policy_digest: profile.digest.clone(),
        candidate_build_digest: candidate.build_digest.clone(),
        input_digest,
        derived_stage: outcome.stage,
        result,
    };
    validate_output(&evaluation, request)?;
    Ok(evaluation)
}

/// Evaluates a request against a live publication grant.
///
/// This is the entry point the runtime composition uses. It resolves the exact
/// publication, disclosure and influence state through the caller's grant
/// before any evaluation runs, so a build candidate or a self-consistent
/// receipt is never evaluated as if it were a live publication, and a direct
/// read that is limited stays an explicit limitation.
///
/// The direct domain is unaffected by the optional relation domain in both
/// directions: a limited direct read is refused here rather than answered from
/// relation coverage, and a grant is not withdrawn because relation evidence
/// is absent.
///
/// # Errors
/// Refuses a grant that does not authorize exactly this request, and a request
/// whose direct domain cannot be answered under the grant. Every refusal is a
/// typed [`ActivationError`]; none of them is a successful evaluation.
pub fn evaluate_published_activation(
    grant: &PublicationGrant,
    request: &ActivationRequest,
    profile: &ActivationProfile,
    scope_id: &WorkScopeId,
) -> Result<CueActivationEvaluation, ActivationError> {
    grant.validate_for(request, scope_id)?;
    if !grant.is_direct_granted() {
        return Err(ActivationError::StaleInput);
    }
    evaluate_activation(&grant.candidate, request, profile)
}

/// The optional stage's contribution and its typed disposition.
struct DerivedOutcome {
    derived: Vec<DerivedActivation>,
    trace: ActivationTrace,
    completeness: Completeness,
    stage: DerivedStage,
}

/// Resolves direct-only versus spread-enabled policy, then runs the optional stage.
///
/// The direct-only branch is decided from the request bounds before any relation
/// material is validated, so a direct-only request never requires, contacts,
/// starts, or rebuilds a relation service. A spread-enabled request already
/// carries the optional relation material the caller acquired; this resolves
/// whether that material is usable and preserves a valid completed direct result
/// whenever only the optional stage is unavailable or reaches an admitted limit.
fn derived_stage(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
    direct: &[DirectActivation],
    budget: &mut Budget,
) -> Result<DerivedOutcome, ActivationError> {
    if request.is_direct_only() {
        return direct_result_without_derived(direct, request, DerivedStage::Disabled);
    }
    match relation_gap(candidate, request, profile) {
        Some(gap) => direct_result_without_derived(
            direct,
            request,
            DerivedStage::Unavailable {
                reason: gap.reason,
                unusable: gap.unusable,
            },
        ),
        None => spread_phase(candidate, request, profile, direct, budget),
    }
}

/// The result of a completed direct evaluation with no derived contribution.
///
/// The trace still records every direct hit, so an absent, unusable, or disabled
/// optional stage never removes the evidence for an exact cue. The direct
/// completeness is derived from the un-followed relation edges: with a resumable
/// remainder the search was partial, and with none it was complete. Neither
/// declares the direct snapshot absent.
fn direct_result_without_derived(
    direct: &[DirectActivation],
    request: &ActivationRequest,
    stage: DerivedStage,
) -> Result<DerivedOutcome, ActivationError> {
    let completeness = match &stage {
        DerivedStage::Unavailable { unusable, .. } if unusable.is_empty() => Completeness::Complete,
        DerivedStage::Unavailable { unusable, .. } => Completeness::Partial {
            frontier: unusable.clone(),
        },
        _ => Completeness::Complete,
    };
    Ok(DerivedOutcome {
        derived: Vec::new(),
        trace: direct_trace(direct, trace_limit(request))?,
        completeness,
        stage,
    })
}

/// Why the optional relation domain could not contribute, and where it stopped.
struct RelationGap {
    reason: RelationCoverage,
    unusable: Vec<RelationEdgeId>,
}

/// Supplied relation edges this profile and fence do not admit.
///
/// Only coverage and currency are resolved here. Identity, scope, and fence
/// binding of the supplied edges remain hard refusals in `preflight`, because a
/// forged or mismatched edge set is corrupted shared input rather than absent
/// optional material. Reasons are reported in declaration order so the same
/// evidence always yields the same typed outcome.
fn relation_gap(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
) -> Option<RelationGap> {
    if candidate.relation_edges.is_empty() {
        return Some(RelationGap {
            reason: RelationCoverage::Absent,
            unusable: Vec::new(),
        });
    }
    let mut unusable: BTreeSet<RelationEdgeId> = BTreeSet::new();
    let mut not_current = false;
    let mut registry_changed = false;
    let mut kind_not_admitted = false;
    for edge in &candidate.relation_edges {
        // Allowed edge direction and kind are explicit profile semantics. An
        // unweighted kind is not traversed and never fails the direct domain.
        if !is_current_evidence(edge.evidence.freshness, edge.evidence.status)
            || edge.evidence.state_fence != request.state_fence
        {
            not_current = true;
        } else if profile.registry_revision.as_deref() != Some(edge.registry_revision.as_str()) {
            registry_changed = true;
        } else if profile.relation_weight(edge.kind).is_none() {
            kind_not_admitted = true;
        } else {
            continue;
        }
        unusable.insert(edge.relation_edge_id.clone());
    }
    let reason = if not_current {
        RelationCoverage::NotCurrent
    } else if registry_changed {
        RelationCoverage::RegistryRevisionChanged
    } else if kind_not_admitted {
        RelationCoverage::KindNotAdmitted
    } else {
        return None;
    };
    Some(RelationGap {
        reason,
        unusable: unusable.into_iter().collect(),
    })
}

impl CueActivationEvaluation {
    /// Validates retained identity, structural bindings, and the A10 result shape.
    ///
    /// This is a structural/binding check; it does not replay traversal, prove
    /// maximum-path selection, or authenticate admission evidence.
    pub fn validate_against(
        &self,
        candidate: &CueSnapshotBuildCandidate,
        request: &ActivationRequest,
        profile: &ActivationProfile,
    ) -> Result<(), ActivationError> {
        preflight(candidate, request, profile)?;
        if self.policy_id != profile.profile_id
            || self.policy_revision != profile.profile_revision
            || self.policy_digest != profile.digest
            || self.candidate_build_digest != candidate.build_digest
            || self.input_digest != input_digest(candidate, request, profile)?
        {
            return Err(ActivationError::ProfileBinding);
        }
        self.result.validate_against(request)?;
        if self.result.direct.iter().any(|hit| {
            !candidate
                .snapshot
                .members
                .iter()
                .any(|member| member.target == hit.target)
        }) {
            return Err(ActivationError::ProfileBinding);
        }
        self.validate_derived_stage(candidate, request, profile)?;
        validate_output(self, request)?;
        Ok(())
    }

    /// Checks that the recorded optional-stage disposition is the one these
    /// exact inputs produce.
    ///
    /// A structurally valid arbitrary result is not proof the local evaluator
    /// ran, so the optional stage is re-resolved here. Only the coverage and
    /// policy decision is re-derived; the traversal itself is not replayed.
    fn validate_derived_stage(
        &self,
        candidate: &CueSnapshotBuildCandidate,
        request: &ActivationRequest,
        profile: &ActivationProfile,
    ) -> Result<(), ActivationError> {
        let expected = if request.is_direct_only() {
            Some(DerivedStage::Disabled)
        } else {
            relation_gap(candidate, request, profile).map(|gap| DerivedStage::Unavailable {
                reason: gap.reason,
                unusable: gap.unusable,
            })
        };
        match (&self.derived_stage, expected) {
            (DerivedStage::Disabled, Some(DerivedStage::Disabled)) => Ok(()),
            (
                DerivedStage::Unavailable { reason, unusable },
                Some(DerivedStage::Unavailable {
                    reason: expected_reason,
                    unusable: expected_unusable,
                }),
            ) => {
                if *reason == expected_reason && *unusable == expected_unusable {
                    Ok(())
                } else {
                    Err(ActivationError::ProfileBinding)
                }
            }
            // A spread-enabled run with usable relation evidence is the only
            // stage that may report a traversal outcome, and a direct-only
            // request is the only one that may report `Disabled`.
            (DerivedStage::Evaluated | DerivedStage::BoundReached { .. }, None)
                if !request.is_direct_only() =>
            {
                Ok(())
            }
            _ => Err(ActivationError::ProfileBinding),
        }
    }
}

fn preflight(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
) -> Result<(), ActivationError> {
    cheap_bounds(candidate, request, profile)?;
    candidate.validate()?;
    request.validate()?;
    profile.validate()?;
    validate_request_identity(request)?;
    if profile.bounds != request.bounds
        || candidate.snapshot.snapshot_id != request.snapshot_id
        || candidate.snapshot.state_fence != request.state_fence
        || candidate.snapshot.rebuild.normalization_profile != request.normalization_profile
        || candidate.scope_id != request_scope(request)?
        || candidate.proof_ceiling != eliot_cue_contracts::ProofCeiling::CandidateArtifact
    {
        return Err(ActivationError::ProfileBinding);
    }
    // Relation identity is only bound when the optional stage may run. A
    // direct-only request carries no relation edges, so the published snapshot's
    // optional relation set is neither required nor validated here.
    if !request.is_direct_only() {
        let candidate_edges: BTreeMap<_, _> = candidate
            .relation_edges
            .iter()
            .map(|edge| (&edge.relation_edge_id, edge))
            .collect();
        let request_edges: BTreeMap<_, _> = request
            .relation_edges
            .iter()
            .map(|edge| (&edge.relation_edge_id, edge))
            .collect();
        if candidate_edges != request_edges {
            return Err(ActivationError::ProfileBinding);
        }
    }
    for projection in &candidate.admitted_bindings {
        validate_current_projection(projection, request)?;
    }
    for seed in &request.seeds {
        validate_current_observation(seed, request)?;
        for key in &seed.comparison_keys {
            if profile.rule(seed.observed.kind, key.match_mode).is_none() {
                return Err(ActivationError::Unsupported);
            }
        }
    }
    Ok(())
}

fn validate_request_identity(request: &ActivationRequest) -> Result<(), ActivationError> {
    let mut observed_ids = BTreeSet::new();
    let mut key_records = BTreeMap::new();
    for seed in &request.seeds {
        if !observed_ids.insert(seed.observed.observed_cue_id.clone()) {
            return Err(ActivationError::Contract(
                CueContractError::DuplicateIdentity {
                    field: "activation.seeds",
                },
            ));
        }
        for key in &seed.comparison_keys {
            if let Some((kind, existing)) = key_records.get(&key.comparison_key_id)
                && (*kind != seed.observed.kind || *existing != key)
            {
                return Err(ActivationError::ProfileBinding);
            }
            key_records.insert(key.comparison_key_id.clone(), (seed.observed.kind, key));
        }
    }
    Ok(())
}

fn cheap_bounds(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
) -> Result<(), ActivationError> {
    if candidate.admitted_bindings.len() > eliot_cue_contracts::MAX_SNAPSHOT_MEMBERS
        || candidate.snapshot.members.len() > eliot_cue_contracts::MAX_SNAPSHOT_MEMBERS
        || candidate.snapshot.rebuild.source_denominator.len()
            > eliot_cue_contracts::MAX_SNAPSHOT_MEMBERS
        || candidate.relation_edges.len() > eliot_cue_contracts::MAX_RELATION_EDGES
        || request.seeds.len() > eliot_cue_contracts::MAX_SEEDS
        || request.relation_edges.len() > eliot_cue_contracts::MAX_RELATION_EDGES
    {
        return Err(ActivationError::Limit {
            field: "activation.input_count",
        });
    }
    let mut total = 0usize;
    charge(&mut total, candidate.schema_revision.len())?;
    charge(&mut total, candidate.scope_id.as_str().len())?;
    charge(&mut total, candidate.snapshot.snapshot_id.as_str().len())?;
    charge(&mut total, candidate.build_digest.as_str().len())?;
    charge_profile(
        &mut total,
        &candidate.snapshot.rebuild.normalization_profile,
    )?;
    charge(&mut total, request.schema_revision.len())?;
    charge(&mut total, request.request_id.as_str().len())?;
    charge(&mut total, request.snapshot_id.as_str().len())?;
    charge(&mut total, profile.revision.len())?;
    charge(&mut total, profile.profile_id.len())?;
    if let Some(registry) = profile.registry_revision.as_deref() {
        charge(&mut total, registry.len())?;
    }
    for member in &candidate.snapshot.members {
        charge(&mut total, member.target.as_str().len())?;
        charge(&mut total, member.canonical.canonical_cue_id.as_str().len())?;
        charge(&mut total, member.canonical.canonical_value.len())?;
        charge(&mut total, member.canonical.digest.as_str().len())?;
    }
    for source in &candidate.snapshot.rebuild.source_denominator {
        charge(&mut total, source.target.as_str().len())?;
        charge(&mut total, source.digest.as_str().len())?;
        charge_provenance(&mut total, &source.provenance)?;
    }
    for projection in &candidate.admitted_bindings {
        charge_projection(&mut total, projection)?;
    }
    for edge in &candidate.relation_edges {
        charge_edge(&mut total, edge)?;
    }
    for edge in &request.relation_edges {
        charge_edge(&mut total, edge)?;
    }
    for seed in &request.seeds {
        charge_normalized(&mut total, seed)?;
    }
    if total > MAX_INPUT_BYTES {
        return Err(ActivationError::Limit {
            field: "activation.input_bytes",
        });
    }
    Ok(())
}

fn charge_projection(
    total: &mut usize,
    projection: &AdmittedCueBindingProjection,
) -> Result<(), ActivationError> {
    charge(
        total,
        projection.candidate.binding_candidate_id.as_str().len(),
    )?;
    charge(total, projection.candidate.target.as_str().len())?;
    charge(total, projection.candidate.digest.as_str().len())?;
    charge_normalized(total, &projection.normalized)?;
    charge(total, projection.admission.candidate_id.as_str().len())?;
    charge(total, projection.admission.candidate_digest.as_str().len())?;
    charge(total, projection.admission.task_id.as_str().len())?;
    charge(total, projection.admission.scope_id.as_str().len())?;
    charge(
        total,
        projection.admission.receipt.receipt_id.as_str().len(),
    )?;
    charge(total, projection.admission.receipt.canonical_sha256.len())
}

fn charge_normalized(total: &mut usize, cue: &NormalizedCue) -> Result<(), ActivationError> {
    charge(total, cue.schema_revision.len())?;
    charge(total, cue.observed.schema_revision.len())?;
    charge(total, cue.observed.observed_cue_id.as_str().len())?;
    charge(total, cue.observed.original_value.len())?;
    charge(total, cue.observed.source.target.as_str().len())?;
    charge(total, cue.observed.source.digest.as_str().len())?;
    charge_provenance(total, &cue.observed.source.provenance)?;
    charge(total, cue.observed.context.task_id.as_str().len())?;
    charge(total, cue.observed.context.scope_id.as_str().len())?;
    charge_profile(total, &cue.profile)?;
    charge_evidence(total, &cue.observed.context.evidence)?;
    if let Some(canonical) = cue.canonical.as_ref() {
        charge(total, canonical.canonical_cue_id.as_str().len())?;
        charge(total, canonical.canonical_value.len())?;
        charge(total, canonical.digest.as_str().len())?;
    }
    match &cue.outcome {
        eliot_cue_contracts::NormalizationOutcome::AuthorizedLoss { policy_ref } => {
            charge(total, policy_ref.len())?;
        }
        eliot_cue_contracts::NormalizationOutcome::Ambiguous { rivals } => {
            if rivals.len() > eliot_cue_contracts::MAX_COMPARISON_KEYS {
                return Err(ActivationError::Limit {
                    field: "activation.input_count",
                });
            }
            for rival in rivals {
                charge(total, rival.canonical_cue_id.as_str().len())?;
                charge(total, rival.canonical_value.len())?;
                charge(total, rival.digest.as_str().len())?;
            }
        }
        eliot_cue_contracts::NormalizationOutcome::Unsupported { reason } => {
            charge(total, reason.len())?;
        }
        _ => {}
    }
    if cue.comparison_keys.len() > eliot_cue_contracts::MAX_COMPARISON_KEYS
        || cue.transformation_evidence.len() > eliot_cue_contracts::MAX_TRANSFORMATION_STEPS
    {
        return Err(ActivationError::Limit {
            field: "activation.input_count",
        });
    }
    for key in &cue.comparison_keys {
        charge(total, key.comparison_key_id.as_str().len())?;
        charge(total, key.key_value.len())?;
        charge_profile(total, &key.profile)?;
    }
    for step in &cue.transformation_evidence {
        charge(total, step.step.len())?;
        charge(total, step.result.len())?;
    }
    Ok(())
}

fn charge_edge(total: &mut usize, edge: &RelationEdge) -> Result<(), ActivationError> {
    charge(total, edge.relation_edge_id.as_str().len())?;
    charge(total, edge.from.as_str().len())?;
    charge(total, edge.to.as_str().len())?;
    charge(total, edge.registry_revision.len())?;
    charge(total, edge.edge_digest.as_str().len())?;
    charge_evidence(total, &edge.evidence)
}

fn charge_profile(
    total: &mut usize,
    profile: &eliot_cue_contracts::NormalizationProfile,
) -> Result<(), ActivationError> {
    charge(total, profile.profile_id.len())?;
    charge(total, profile.digest.as_str().len())
}

fn charge_evidence(
    total: &mut usize,
    evidence: &eliot_cue_contracts::EvidenceEnvelope,
) -> Result<(), ActivationError> {
    charge_provenance(total, &evidence.provenance)?;
    if let Some(binding) = evidence.verification.as_ref() {
        charge(total, binding.contract_id.as_str().len())?;
        charge(total, binding.run_id.as_str().len())?;
        charge(total, binding.revision.len())?;
    }
    Ok(())
}

fn charge_provenance(
    total: &mut usize,
    provenance: &eliot_evidence::Provenance,
) -> Result<(), ActivationError> {
    charge(total, provenance.source_id.as_str().len())?;
    charge(total, provenance.capture_route.len())?;
    charge(total, provenance.scope.len())?;
    if let Some(raw) = provenance.raw_handle.as_deref() {
        charge(total, raw.len())?;
    }
    if let Some(revision) = provenance.revision.as_deref() {
        charge(total, revision.len())?;
    }
    Ok(())
}

fn charge(total: &mut usize, bytes: usize) -> Result<(), ActivationError> {
    *total = total.checked_add(bytes).ok_or(ActivationError::Limit {
        field: "activation.input_bytes",
    })?;
    if *total > MAX_INPUT_BYTES {
        return Err(ActivationError::Limit {
            field: "activation.input_bytes",
        });
    }
    Ok(())
}

fn validate_current_projection(
    projection: &AdmittedCueBindingProjection,
    request: &ActivationRequest,
) -> Result<(), ActivationError> {
    validate_current_observation(&projection.normalized, request)?;
    if !matches!(
        projection.candidate.freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    ) {
        return Err(ActivationError::StaleInput);
    }
    if projection.candidate.disposition == eliot_cue_contracts::BindingDisposition::Rejected {
        return Err(ActivationError::Unsupported);
    }
    Ok(())
}

fn validate_current_observation(
    cue: &NormalizedCue,
    request: &ActivationRequest,
) -> Result<(), ActivationError> {
    if cue.observed.context.lifecycle != LifecycleState::Active
        || cue.observed.context.state_fence != request.state_fence
        || cue.observed.context.scope_id != request_scope(request)?
        || cue.observed.context.task_id != request_task(request)?
        || cue.observed.context.evidence.provenance.scope != cue.observed.context.scope_id.as_str()
        || !is_current_evidence(
            cue.observed.context.evidence.freshness,
            cue.observed.context.evidence.status,
        )
    {
        return Err(ActivationError::StaleInput);
    }
    if cue.profile != request.normalization_profile {
        return Err(ActivationError::ProfileBinding);
    }
    Ok(())
}

fn request_scope(
    request: &ActivationRequest,
) -> Result<eliot_cue_contracts::WorkScopeId, ActivationError> {
    request
        .seeds
        .first()
        .map(|seed| seed.observed.context.scope_id.clone())
        .ok_or(ActivationError::Unsupported)
}

fn request_task(request: &ActivationRequest) -> Result<eliot_contracts::TaskId, ActivationError> {
    request
        .seeds
        .first()
        .map(|seed| seed.observed.context.task_id.clone())
        .ok_or(ActivationError::Unsupported)
}

fn is_current_evidence(freshness: EvidenceFreshness, status: EpistemicStatus) -> bool {
    matches!(
        freshness,
        EvidenceFreshness::ExactCandidate
            | EvidenceFreshness::ExactCommit
            | EvidenceFreshness::ExactQuiescedWorktree
    ) && matches!(
        status,
        EpistemicStatus::Observed | EpistemicStatus::Supported | EpistemicStatus::Verified
    )
}

fn direct_phase(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
    budget: &mut Budget,
) -> Result<Vec<DirectActivation>, ActivationError> {
    let mut hits = Vec::new();
    let mut hit_keys = BTreeSet::new();
    let max_intermediate_hits = usize::from(request.bounds.max_direct)
        .checked_mul(2)
        .ok_or(ActivationError::Limit {
            field: "activation.max_direct",
        })?;
    for seed in &request.seeds {
        for projection in &candidate.admitted_bindings {
            budget.nodes = budget.nodes.checked_add(1).ok_or(ActivationError::Limit {
                field: "activation.max_nodes",
            })?;
            if budget.nodes > request.bounds.max_nodes {
                return Err(ActivationError::Limit {
                    field: "activation.max_nodes",
                });
            }
            if projection.normalized.observed.kind != seed.observed.kind {
                continue;
            }
            for seed_key in &seed.comparison_keys {
                budget.work = budget.work.checked_add(1).ok_or(ActivationError::Limit {
                    field: "activation.max_work",
                })?;
                if budget.work > request.bounds.max_work {
                    return Err(ActivationError::Limit {
                        field: "activation.max_work",
                    });
                }
                let Some(rule) = profile.rule(seed.observed.kind, seed_key.match_mode) else {
                    continue;
                };
                if rule.direct_strength < request.bounds.activation_threshold {
                    continue;
                }
                let mut matched = false;
                for record_key in &projection.normalized.comparison_keys {
                    budget.work = budget.work.checked_add(1).ok_or(ActivationError::Limit {
                        field: "activation.max_work",
                    })?;
                    if budget.work > request.bounds.max_work {
                        return Err(ActivationError::Limit {
                            field: "activation.max_work",
                        });
                    }
                    if key_matches(seed_key, record_key) {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    let target = projection.candidate.target.clone();
                    if hit_keys.insert((target.clone(), seed_key.comparison_key_id.clone())) {
                        if hits.len() >= max_intermediate_hits {
                            return Err(ActivationError::Limit {
                                field: "activation.max_direct",
                            });
                        }
                        hits.push((
                            mode_rank(seed_key.match_mode),
                            target,
                            seed_key.clone(),
                            rule.direct_strength,
                        ));
                    }
                }
            }
        }
    }
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(b.3.cmp(&a.3))
            .then(a.1.cmp(&b.1))
            .then(a.2.comparison_key_id.cmp(&b.2.comparison_key_id))
    });
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for (_, target, key, strength) in hits {
        if strength < request.bounds.activation_threshold
            || !seen.insert((target.clone(), key.comparison_key_id.clone()))
        {
            continue;
        }
        result.push(DirectActivation::new(target, key, strength));
        if result.len() > usize::from(request.bounds.max_direct) {
            return Err(ActivationError::Limit {
                field: "activation.max_direct",
            });
        }
    }
    Ok(result)
}

fn key_matches(
    query: &eliot_cue_contracts::ComparisonKey,
    record: &eliot_cue_contracts::ComparisonKey,
) -> bool {
    if query.profile != record.profile
        || query.form != record.form
        || query.match_mode != record.match_mode
    {
        return false;
    }
    match query.match_mode {
        MatchMode::Exact | MatchMode::Signature => query.key_value == record.key_value,
        MatchMode::Prefix => query.key_value.starts_with(&record.key_value),
        _ => false,
    }
}

const fn mode_rank(mode: MatchMode) -> u8 {
    match mode {
        MatchMode::Exact => 0,
        MatchMode::Prefix => 1,
        MatchMode::Signature => 2,
        _ => 255,
    }
}

type BestStates =
    BTreeMap<(TargetHandle, u8, TargetHandle), (ActivationStrength, Vec<RelationEdgeId>)>;

struct SpreadWork<'a> {
    candidate: &'a CueSnapshotBuildCandidate,
    request: &'a ActivationRequest,
    profile: &'a ActivationProfile,
    budget: &'a mut Budget,
    frontier: Vec<SearchState>,
    best: BestStates,
    stopped_frontier: Vec<RelationEdgeId>,
    stopped_by_fanout: bool,
    /// The admitted bound that stopped this optional stage, when one did.
    stopped_by_bound: Option<&'static str>,
    derived_states: Vec<SearchState>,
}

struct SpreadRun {
    stopped_frontier: Vec<RelationEdgeId>,
    stopped_by_fanout: bool,
    stopped_by_bound: Option<&'static str>,
    derived_states: Vec<SearchState>,
}

fn spread_phase(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
    direct: &[DirectActivation],
    budget: &mut Budget,
) -> Result<DerivedOutcome, ActivationError> {
    let mut direct_best = BTreeMap::new();
    for hit in direct {
        let replace = direct_best
            .get(&hit.target)
            .is_none_or(|old: &DirectActivation| hit.strength > old.strength);
        if replace {
            direct_best.insert(hit.target.clone(), hit.clone());
        }
    }
    let frontier = direct_best
        .values()
        .map(|hit| SearchState {
            target: hit.target.clone(),
            direct_seed: hit.target.clone(),
            score: hit.strength,
            path: Vec::new(),
        })
        .collect();
    let run = SpreadWork {
        candidate,
        request,
        profile,
        budget,
        frontier,
        best: BTreeMap::new(),
        stopped_frontier: Vec::new(),
        stopped_by_fanout: false,
        stopped_by_bound: None,
        derived_states: Vec::new(),
    }
    .run()?;
    let (derived, unreported) = final_derived(&run.derived_states, direct, request)?;
    let trace = trace_for(
        direct,
        &run.derived_states,
        &candidate.relation_edges,
        profile,
        trace_limit(request),
    )?;
    // An admitted bound that stopped this optional stage never retracts the
    // completed direct result. Every derived hit it did reach is kept, the
    // un-followed remainder becomes the frontier, and the exact bound is named,
    // so a cap can neither become `Complete` nor fail the whole evaluation.
    let bounded = run.stopped_by_bound.map(|field| {
        (
            field,
            unfollowed_edges(candidate, &run.derived_states, &run.stopped_frontier),
        )
    });
    let stage = match bounded {
        Some((field, frontier)) if frontier.is_empty() => {
            return Err(ActivationError::Limit { field });
        }
        Some((field, _)) => DerivedStage::BoundReached {
            field: field.to_owned(),
        },
        None if !unreported.is_empty() => DerivedStage::BoundReached {
            field: "activation.max_derived".to_owned(),
        },
        None => DerivedStage::Evaluated,
    };
    let completeness = spread_completeness(bounded, &unreported, &run);
    Ok(DerivedOutcome {
        derived,
        trace,
        completeness,
        stage,
    })
}

/// The completeness the optional stage's own run actually reached.
///
/// An admitted bound always reports `Partial` with the un-followed remainder, a
/// depth or fan-out stop reports `Truncated` with its own stopped frontier, and
/// only a run that followed every supplied edge and stopped for no reason
/// reports `Complete`. No cap can collapse into `Complete`.
fn spread_completeness(
    bounded: Option<(&'static str, Vec<RelationEdgeId>)>,
    unreported: &[RelationEdgeId],
    run: &SpreadRun,
) -> Completeness {
    match bounded {
        Some((_, frontier)) => Completeness::Partial { frontier },
        None if !unreported.is_empty() => Completeness::Partial {
            frontier: unreported.to_vec(),
        },
        None if run.stopped_frontier.is_empty() => Completeness::Complete,
        None => Completeness::Truncated {
            bound_hit: if run.stopped_by_fanout {
                BoundKind::Fanout
            } else {
                BoundKind::Depth
            },
            frontier: run.stopped_frontier.clone(),
        },
    }
}

/// Every supplied relation edge the traversal did not follow.
///
/// A state records each edge it consumed, so the remainder is the work a resumed
/// search still owes. It is non-empty whenever an admitted bound stopped the
/// optional stage, which is what keeps a cap from collapsing into a `Complete`
/// result. Depth and fan-out stops contribute their own stopped frontier too,
/// because those edges were admitted but never followed.
fn unfollowed_edges(
    candidate: &CueSnapshotBuildCandidate,
    states: &[SearchState],
    stopped_frontier: &[RelationEdgeId],
) -> Vec<RelationEdgeId> {
    let mut followed: BTreeSet<&RelationEdgeId> = BTreeSet::new();
    for state in states {
        followed.extend(state.path.iter());
    }
    let mut frontier: Vec<RelationEdgeId> = candidate
        .relation_edges
        .iter()
        .map(|edge| &edge.relation_edge_id)
        .filter(|id| !followed.contains(id))
        .cloned()
        .collect();
    for id in stopped_frontier {
        if !followed.contains(id) {
            frontier.push(id.clone());
        }
    }
    frontier.sort();
    frontier.dedup();
    frontier
}

/// The trace bound this request admits, capped by the contract ceiling.
fn trace_limit(request: &ActivationRequest) -> usize {
    usize::from(request.bounds.max_trace_steps).min(eliot_cue_contracts::MAX_TRACE_STEPS)
}

impl SpreadWork<'_> {
    fn run(mut self) -> Result<SpreadRun, ActivationError> {
        while !self.frontier.is_empty() {
            self.frontier.sort_by(|a, b| {
                b.score
                    .cmp(&a.score)
                    .then(a.path.len().cmp(&b.path.len()))
                    .then(a.path.cmp(&b.path))
                    .then(a.target.cmp(&b.target))
            });
            let state = self.frontier.remove(0);
            if self.is_obsolete(&state)? {
                continue;
            }
            self.process_state(&state)?;
        }
        self.stopped_frontier.sort();
        self.stopped_frontier.dedup();
        Ok(SpreadRun {
            stopped_frontier: self.stopped_frontier,
            stopped_by_fanout: self.stopped_by_fanout,
            stopped_by_bound: self.stopped_by_bound,
            derived_states: self.derived_states,
        })
    }

    fn is_obsolete(&self, state: &SearchState) -> Result<bool, ActivationError> {
        let depth = u8::try_from(state.path.len()).map_err(|_| ActivationError::Limit {
            field: "activation.max_depth",
        })?;
        Ok(self
            .best
            .get(&(state.target.clone(), depth, state.direct_seed.clone()))
            .is_some_and(|(best_score, best_path)| {
                state.score < *best_score || (state.score == *best_score && state.path > *best_path)
            }))
    }

    fn process_state(&mut self, state: &SearchState) -> Result<(), ActivationError> {
        if let Some(field) = self.charge_node() {
            self.stop_optional(field);
            return Ok(());
        }
        let mut outgoing = Vec::new();
        for index in 0..self.candidate.relation_edges.len() {
            if let Some(field) = self.charge_edge() {
                self.stop_optional(field);
                return Ok(());
            }
            let edge = &self.candidate.relation_edges[index];
            if self.departs(&state.target, edge) {
                outgoing.push(index);
            }
        }
        outgoing.sort_by(|left, right| {
            self.candidate.relation_edges[*left]
                .relation_edge_id
                .cmp(&self.candidate.relation_edges[*right].relation_edge_id)
        });
        if outgoing.is_empty() {
            return Ok(());
        }
        if state.path.len() >= usize::from(self.request.bounds.max_depth) {
            self.stopped_frontier.extend(outgoing.iter().map(|index| {
                self.candidate.relation_edges[*index]
                    .relation_edge_id
                    .clone()
            }));
            return Ok(());
        }
        let allowed = usize::from(self.request.bounds.max_fanout);
        if outgoing.len() > allowed {
            self.stopped_frontier
                .extend(outgoing[allowed..].iter().map(|index| {
                    self.candidate.relation_edges[*index]
                        .relation_edge_id
                        .clone()
                }));
            self.stopped_by_fanout = true;
            outgoing.truncate(allowed);
        }
        for index in outgoing {
            let edge = self.candidate.relation_edges[index].clone();
            if self.expand_edge(state, &edge)? {
                self.stop_optional("activation.max_path_len");
                return Ok(());
            }
        }
        Ok(())
    }

    /// Stops the optional stage at an admitted bound.
    ///
    /// Only the relation-derived traversal stops here. The completed direct
    /// result, the derived hits already reached, and the un-followed remainder
    /// are all preserved, and the exact bound is named in the stage outcome.
    fn stop_optional(&mut self, field: &'static str) {
        self.stopped_by_bound = Some(field);
        self.frontier.clear();
    }

    /// Whether this edge departs `from` in a direction the profile admits.
    ///
    /// Direction is read from the profile rule for the edge's own kind, so an
    /// unadmitted kind is never traversed and a reverse or bidirectional rule
    /// is traversed the way the profile names rather than by assumption.
    fn departs(&self, from: &TargetHandle, edge: &RelationEdge) -> bool {
        arrival_of(self.profile, edge, from).is_some()
    }

    /// Returns `true` when this edge may not extend the path under the
    /// admitted path-length bound.
    fn expand_edge(
        &mut self,
        state: &SearchState,
        edge: &RelationEdge,
    ) -> Result<bool, ActivationError> {
        let Some(arrival) = arrival_of(self.profile, edge, &state.target) else {
            return Ok(false);
        };
        if state.path.iter().any(|id| id == &edge.relation_edge_id)
            || path_revisits(state, &arrival, &self.candidate.relation_edges, self.profile)
        {
            return Ok(false);
        }
        let weight = self
            .profile
            .relation_weight(edge.kind)
            .ok_or(ActivationError::ProfileBinding)?;
        let score_u32 = (u32::from(state.score.0) * u32::from(weight)) / 1000;
        let score =
            ActivationStrength(
                u16::try_from(score_u32).map_err(|_| ActivationError::Limit {
                    field: "activation.score",
                })?,
            );
        let mut path = state.path.clone();
        path.push(edge.relation_edge_id.clone());
        if path.len() > usize::from(self.request.bounds.max_path_len) {
            return Ok(true);
        }
        if score < self.request.bounds.activation_threshold {
            return Ok(false);
        }
        let depth = u8::try_from(path.len()).map_err(|_| ActivationError::Limit {
            field: "activation.max_depth",
        })?;
        let key = (arrival.clone(), depth, state.direct_seed.clone());
        let improve = self.best.get(&key).is_none_or(|(old_score, old_path)| {
            score > *old_score || (score == *old_score && path < *old_path)
        });
        if improve {
            self.best.insert(key, (score, path.clone()));
            let next = SearchState {
                target: arrival,
                direct_seed: state.direct_seed.clone(),
                score,
                path,
            };
            self.derived_states.push(next.clone());
            self.frontier.push(next);
        }
        Ok(false)
    }

    /// Charges one node visit, returning the admitted bound that stopped the
    /// optional stage instead of refusing the whole evaluation.
    fn charge_node(&mut self) -> Option<&'static str> {
        let nodes = self.budget.nodes.checked_add(1)?;
        if nodes > self.request.bounds.max_nodes {
            self.budget.nodes = nodes;
            return Some("activation.max_nodes");
        }
        let work = self.budget.work.checked_add(1)?;
        if work > self.request.bounds.max_work {
            self.budget.nodes = nodes;
            self.budget.work = work;
            return Some("activation.max_work");
        }
        self.budget.nodes = nodes;
        self.budget.work = work;
        None
    }

    /// Charges one edge inspection, returning the admitted bound that stopped
    /// the optional stage instead of refusing the whole evaluation.
    fn charge_edge(&mut self) -> Option<&'static str> {
        let edges = self.budget.edges.checked_add(1)?;
        if edges > self.request.bounds.max_edges {
            self.budget.edges = edges;
            return Some("activation.max_edges");
        }
        let work = self.budget.work.checked_add(1)?;
        if work > self.request.bounds.max_work {
            self.budget.edges = edges;
            self.budget.work = work;
            return Some("activation.max_work");
        }
        self.budget.edges = edges;
        self.budget.work = work;
        None
    }
}

/// The strongest observed path per non-direct target, within the derived bound.
///
/// Selection keeps the maximum admissible path contribution per target, so a
/// duplicate relation or a second route to the same target never adds to its
/// score. The second return value names the resumable edges of the paths the
/// admitted derived bound did not admit, so that cap stays visible as a frontier
/// instead of becoming a silently smaller answer.
fn final_derived(
    states: &[SearchState],
    direct: &[DirectActivation],
    request: &ActivationRequest,
) -> Result<(Vec<DerivedActivation>, Vec<RelationEdgeId>), ActivationError> {
    let direct_targets: BTreeSet<_> = direct.iter().map(|hit| hit.target.clone()).collect();
    let mut selected: BTreeMap<TargetHandle, &SearchState> = BTreeMap::new();
    for state in states {
        if direct_targets.contains(&state.target) {
            continue;
        }
        let replace = selected.get(&state.target).is_none_or(|old| {
            state.score > old.score
                || (state.score == old.score
                    && (state.path.len() < old.path.len()
                        || (state.path.len() == old.path.len() && state.path < old.path)))
        });
        if replace {
            selected.insert(state.target.clone(), state);
        }
    }
    let limit = usize::from(request.bounds.max_derived);
    let mut result = Vec::new();
    let mut unreported: Vec<RelationEdgeId> = Vec::new();
    for state in selected.values() {
        if result.len() >= limit {
            if let Some(last) = state.path.last() {
                unreported.push(last.clone());
            }
            continue;
        }
        result.push(DerivedActivation::try_new(
            state.target.clone(),
            state.direct_seed.clone(),
            state.path.clone(),
            state.score,
        )?);
    }
    unreported.sort();
    unreported.dedup();
    Ok((result, unreported))
}

fn direct_trace(
    direct: &[DirectActivation],
    trace_limit: usize,
) -> Result<ActivationTrace, ActivationError> {
    let mut steps = Vec::new();
    for hit in direct {
        if steps.len() >= trace_limit {
            return Err(ActivationError::Limit {
                field: "activation.trace",
            });
        }
        steps.push(TraceStep::new(None, 0, hit.target.clone()));
    }
    Ok(ActivationTrace::new(steps))
}

fn trace_for(
    direct: &[DirectActivation],
    states: &[SearchState],
    edges: &[RelationEdge],
    profile: &ActivationProfile,
    trace_limit: usize,
) -> Result<ActivationTrace, ActivationError> {
    let mut steps = Vec::new();
    for hit in direct {
        if steps.len() >= trace_limit {
            return Err(ActivationError::Limit {
                field: "activation.trace",
            });
        }
        steps.push(TraceStep::new(None, 0, hit.target.clone()));
    }
    for state in states {
        trace_state(state, edges, profile, trace_limit, &mut steps)?;
    }
    Ok(ActivationTrace::new(steps))
}

/// Records the trace steps one search state actually walked.
///
/// Each step names the node that step reached, resolved through the profile's
/// direction for that edge's kind, so the trace of a reverse or bidirectional
/// profile reports the real arrival rather than the edge's stored destination.
fn trace_state(
    state: &SearchState,
    edges: &[RelationEdge],
    profile: &ActivationProfile,
    trace_limit: usize,
    steps: &mut Vec<TraceStep>,
) -> Result<(), ActivationError> {
    let mut current = state.direct_seed.clone();
    for (index, edge_id) in state.path.iter().enumerate() {
        if steps.len() >= trace_limit {
            return Err(ActivationError::Limit {
                field: "activation.trace",
            });
        }
        let depth = u8::try_from(index + 1).map_err(|_| ActivationError::Limit {
            field: "activation.trace",
        })?;
        let edge = edges
            .iter()
            .find(|candidate| &candidate.relation_edge_id == edge_id)
            .ok_or(ActivationError::Contract(
                CueContractError::BrokenActivationPath,
            ))?;
        let reached = arrival_of(profile, edge, &current).ok_or(ActivationError::Contract(
            CueContractError::BrokenActivationPath,
        ))?;
        steps.push(TraceStep::new(Some(edge_id.clone()), depth, reached.clone()));
        current = reached;
    }
    Ok(())
}

fn assemble_result(
    request: &ActivationRequest,
    direct: Vec<DirectActivation>,
    derived: Vec<DerivedActivation>,
    trace: ActivationTrace,
    completeness: Completeness,
) -> Result<ActivationResult, ActivationError> {
    let result_count = direct
        .len()
        .checked_add(derived.len())
        .ok_or(ActivationError::Limit {
            field: "activation.max_results",
        })?;
    if result_count > usize::from(request.bounds.max_results) {
        return Err(ActivationError::Limit {
            field: "activation.max_results",
        });
    }
    let result = ActivationResult::new(ActivationResultSpec {
        schema_revision: eliot_cue_contracts::CONTRACT_REVISION.to_owned(),
        request_id: request.request_id.clone(),
        snapshot_id: request.snapshot_id.clone(),
        normalization_profile: request.normalization_profile.clone(),
        state_fence: request.state_fence.clone(),
        observed_at: request.observed_at,
        deadline_ms: request.deadline_ms,
        cancelled: request.cancelled,
        direct,
        derived,
        completeness,
        trace,
    });
    result.validate_against(request)?;
    Ok(result)
}

fn input_digest(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
) -> Result<eliot_cue_contracts::Digest, ActivationError> {
    let candidate_payload = candidate.canonical_payload_bytes()?;
    let mut canonical_request = request.clone();
    canonical_request
        .seeds
        .sort_by(|a, b| a.observed.observed_cue_id.cmp(&b.observed.observed_cue_id));
    for seed in &mut canonical_request.seeds {
        seed.comparison_keys
            .sort_by(|a, b| a.comparison_key_id.cmp(&b.comparison_key_id));
    }
    canonical_request
        .relation_edges
        .sort_by(|a, b| a.relation_edge_id.cmp(&b.relation_edge_id));
    let bytes = eliot_contracts::canonical_json_bytes(&CanonicalInput {
        domain: "eliot.cue.activation.input.v1",
        candidate_payload: &candidate_payload,
        request: &canonical_request,
        profile,
    })
    .map_err(|_| CueContractError::Foundation {
        field: "activation.input_digest",
    })?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(ActivationError::Limit {
            field: "activation.input_bytes",
        });
    }
    Ok(eliot_cue_contracts::Digest::new(
        eliot_contracts::sha256_hex(&bytes),
    )?)
}

fn validate_output(
    evaluation: &CueActivationEvaluation,
    request: &ActivationRequest,
) -> Result<(), ActivationError> {
    let bytes = eliot_contracts::canonical_json_bytes(evaluation).map_err(|_| {
        CueContractError::Foundation {
            field: "activation.output",
        }
    })?;
    let maximum =
        usize::try_from(request.bounds.max_output_bytes).map_err(|_| ActivationError::Limit {
            field: "activation.max_output_bytes",
        })?;
    if bytes.len() > maximum || bytes.len() > 4 * 1024 * 1024 {
        return Err(ActivationError::Limit {
            field: "activation.max_output_bytes",
        });
    }
    Ok(())
}

/// Whether reaching `arrival` would revisit a node already on this path.
///
/// The nodes already visited are the direct seed, the current target, and the
/// node reached at each earlier step. Those earlier arrivals are recomputed by
/// walking the path in order from the seed, because a bidirectional edge's
/// arrival depends on the node it departed from. Recomputing the walk is what
/// keeps the check honest for a non-forward profile: a reverse or bidirectional
/// step is compared against the node it actually reached.
fn path_revisits(
    state: &SearchState,
    arrival: &TargetHandle,
    edges: &[RelationEdge],
    profile: &ActivationProfile,
) -> bool {
    if *arrival == state.target || *arrival == state.direct_seed {
        return true;
    }
    let mut visited = BTreeSet::new();
    visited.insert(state.direct_seed.clone());
    let mut current = state.direct_seed.clone();
    for id in &state.path {
        let Some(edge) = edges.iter().find(|edge| &edge.relation_edge_id == id) else {
            // A path naming an edge the publication does not carry cannot be
            // described by this profile, so it is not one this call extends.
            return true;
        };
        let Some(reached) = arrival_of(profile, edge, &current) else {
            return true;
        };
        visited.insert(reached.clone());
        current = reached;
    }
    visited.contains(arrival)
}

/// The endpoint `edge` reaches when it departs `from` in its admitted
/// direction.
///
/// Returns `None` when the edge does not depart `from` in any direction the
/// profile admits for its kind.
fn arrival_of(
    profile: &ActivationProfile,
    edge: &RelationEdge,
    from: &TargetHandle,
) -> Option<TargetHandle> {
    match profile.relation_direction(edge.kind)? {
        RelationDirection::Forward if edge.from == *from => Some(edge.to.clone()),
        RelationDirection::Reverse if edge.to == *from => Some(edge.from.clone()),
        RelationDirection::Bidirectional if edge.from == *from => Some(edge.to.clone()),
        RelationDirection::Bidirectional if edge.to == *from => Some(edge.from.clone()),
        RelationDirection::Forward
        | RelationDirection::Reverse
        | RelationDirection::Bidirectional => None,
    }
}
