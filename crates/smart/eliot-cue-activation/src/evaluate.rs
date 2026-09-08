//! Bounded A14 activation over an immutable A10 build candidate.
use crate::{ActivationError, ActivationProfile};
use eliot_cue_contracts::{
    ActivationRequest, ActivationResult, ActivationResultSpec, ActivationStrength, ActivationTrace,
    AdmittedCueBindingProjection, BoundKind, Completeness, CueContractError,
    CueSnapshotBuildCandidate, DerivedActivation, DirectActivation, LifecycleState, MatchMode,
    NormalizedCue, RelationEdge, RelationEdgeId, TargetHandle, TraceStep,
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
    let (derived, trace, completeness) =
        spread_phase(candidate, request, profile, &direct, &mut budget)?;
    let result = assemble_result(request, direct, derived, trace, completeness)?;
    let evaluation = CueActivationEvaluation {
        policy_id: profile.profile_id.clone(),
        policy_revision: profile.profile_revision,
        policy_digest: profile.digest.clone(),
        candidate_build_digest: candidate.build_digest.clone(),
        input_digest,
        result,
    };
    validate_output(&evaluation, request)?;
    Ok(evaluation)
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
        validate_output(self, request)?;
        Ok(())
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
    if candidate.relation_edges.len() != request.relation_edges.len() {
        return Err(ActivationError::ProfileBinding);
    }
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
    for edge in &candidate.relation_edges {
        if edge.evidence.state_fence != request.state_fence
            || !is_current_evidence(edge.evidence.freshness, edge.evidence.status)
        {
            return Err(ActivationError::StaleInput);
        }
        if profile.registry_revision.as_deref() != Some(edge.registry_revision.as_str()) {
            return Err(ActivationError::ProfileBinding);
        }
        if profile.relation_weight(edge.kind).is_none() {
            return Err(ActivationError::Unsupported);
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
    derived_states: Vec<SearchState>,
}

struct SpreadRun {
    stopped_frontier: Vec<RelationEdgeId>,
    stopped_by_fanout: bool,
    derived_states: Vec<SearchState>,
}

fn spread_phase(
    candidate: &CueSnapshotBuildCandidate,
    request: &ActivationRequest,
    profile: &ActivationProfile,
    direct: &[DirectActivation],
    budget: &mut Budget,
) -> Result<(Vec<DerivedActivation>, ActivationTrace, Completeness), ActivationError> {
    if request.bounds.max_depth == 0 {
        return Ok((
            Vec::new(),
            direct_trace(
                direct,
                usize::from(request.bounds.max_trace_steps)
                    .min(eliot_cue_contracts::MAX_TRACE_STEPS),
            )?,
            Completeness::Complete,
        ));
    }
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
        derived_states: Vec::new(),
    }
    .run()?;
    let derived = final_derived(&run.derived_states, direct, request)?;
    let trace = trace_for(
        direct,
        &run.derived_states,
        &candidate.relation_edges,
        usize::from(request.bounds.max_trace_steps).min(eliot_cue_contracts::MAX_TRACE_STEPS),
    )?;
    if run.stopped_frontier.is_empty() {
        return Ok((derived, trace, Completeness::Complete));
    }
    let bound_hit = if run.stopped_by_fanout {
        BoundKind::Fanout
    } else {
        BoundKind::Depth
    };
    Ok((
        derived,
        trace,
        Completeness::Truncated {
            frontier: run.stopped_frontier,
            bound_hit,
        },
    ))
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
        self.charge_node()?;
        let mut outgoing = Vec::new();
        for index in 0..self.candidate.relation_edges.len() {
            self.charge_edge()?;
            let edge = &self.candidate.relation_edges[index];
            if edge.from == state.target && self.profile.relation_weight(edge.kind).is_some() {
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
            self.expand_edge(state, &edge)?;
        }
        Ok(())
    }

    fn expand_edge(
        &mut self,
        state: &SearchState,
        edge: &RelationEdge,
    ) -> Result<(), ActivationError> {
        if state.path.iter().any(|id| id == &edge.relation_edge_id)
            || edge_in_path_target(state, edge, &self.candidate.relation_edges)
        {
            return Ok(());
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
            return Err(ActivationError::Limit {
                field: "activation.max_path_len",
            });
        }
        if score < self.request.bounds.activation_threshold {
            return Ok(());
        }
        let depth = u8::try_from(path.len()).map_err(|_| ActivationError::Limit {
            field: "activation.max_depth",
        })?;
        let key = (edge.to.clone(), depth, state.direct_seed.clone());
        let improve = self.best.get(&key).is_none_or(|(old_score, old_path)| {
            score > *old_score || (score == *old_score && path < *old_path)
        });
        if improve {
            self.best.insert(key, (score, path.clone()));
            let next = SearchState {
                target: edge.to.clone(),
                direct_seed: state.direct_seed.clone(),
                score,
                path,
            };
            self.derived_states.push(next.clone());
            self.frontier.push(next);
        }
        Ok(())
    }

    fn charge_node(&mut self) -> Result<(), ActivationError> {
        self.budget.nodes = self
            .budget
            .nodes
            .checked_add(1)
            .ok_or(ActivationError::Limit {
                field: "activation.max_nodes",
            })?;
        if self.budget.nodes > self.request.bounds.max_nodes {
            return Err(ActivationError::Limit {
                field: "activation.max_nodes",
            });
        }
        self.budget.work = self
            .budget
            .work
            .checked_add(1)
            .ok_or(ActivationError::Limit {
                field: "activation.max_work",
            })?;
        if self.budget.work > self.request.bounds.max_work {
            return Err(ActivationError::Limit {
                field: "activation.max_work",
            });
        }
        Ok(())
    }

    fn charge_edge(&mut self) -> Result<(), ActivationError> {
        self.budget.edges = self
            .budget
            .edges
            .checked_add(1)
            .ok_or(ActivationError::Limit {
                field: "activation.max_edges",
            })?;
        if self.budget.edges > self.request.bounds.max_edges {
            return Err(ActivationError::Limit {
                field: "activation.max_edges",
            });
        }
        self.budget.work = self
            .budget
            .work
            .checked_add(1)
            .ok_or(ActivationError::Limit {
                field: "activation.max_work",
            })?;
        if self.budget.work > self.request.bounds.max_work {
            return Err(ActivationError::Limit {
                field: "activation.max_work",
            });
        }
        Ok(())
    }
}

fn final_derived(
    states: &[SearchState],
    direct: &[DirectActivation],
    request: &ActivationRequest,
) -> Result<Vec<DerivedActivation>, ActivationError> {
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
    let mut result = Vec::new();
    for state in selected.values() {
        result.push(DerivedActivation::try_new(
            state.target.clone(),
            state.direct_seed.clone(),
            state.path.clone(),
            state.score,
        )?);
        if result.len() > usize::from(request.bounds.max_derived) {
            return Err(ActivationError::Limit {
                field: "activation.max_derived",
            });
        }
    }
    Ok(result)
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
    trace_limit: usize,
) -> Result<ActivationTrace, ActivationError> {
    let edge_targets: BTreeMap<_, _> = edges
        .iter()
        .map(|edge| (&edge.relation_edge_id, &edge.to))
        .collect();
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
        for (index, edge_id) in state.path.iter().enumerate() {
            if steps.len() >= trace_limit {
                return Err(ActivationError::Limit {
                    field: "activation.trace",
                });
            }
            let depth = u8::try_from(index + 1).map_err(|_| ActivationError::Limit {
                field: "activation.trace",
            })?;
            let target = edge_targets.get(edge_id).ok_or(ActivationError::Contract(
                CueContractError::BrokenActivationPath,
            ))?;
            steps.push(TraceStep::new(
                Some(edge_id.clone()),
                depth,
                (*target).clone(),
            ));
        }
    }
    Ok(ActivationTrace::new(steps))
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

fn edge_in_path_target(state: &SearchState, edge: &RelationEdge, edges: &[RelationEdge]) -> bool {
    if edge.to == state.target || edge.to == state.direct_seed {
        return true;
    }
    state
        .path
        .iter()
        .filter_map(|id| {
            edges
                .iter()
                .find(|candidate| &candidate.relation_edge_id == id)
        })
        .any(|previous| previous.from == edge.to)
}
