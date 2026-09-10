//! Bounded, deterministic Architecture source projection.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use eliot_contracts::{ArtifactId, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{
    ArchitectureApplicabilityState, ArchitectureBriefCandidate, ArchitectureBriefDisposition,
    ArchitectureBriefGap, ArchitectureBriefGapClass, ArchitectureBriefGapState,
    ArchitectureBriefOmission, ArchitectureBriefSection, ArchitectureBriefSectionKind,
    ArchitectureBriefStatement, ArchitectureDependencyKind, ArchitectureSourceStatus,
    SelfQueryContractError, SelfQueryInput, SelfQueryOutputProfile,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::to_writer;

use crate::synthesis::{
    DataAvailability, ModelSynthesis, MonetaryCostAvailability, RivalModels, RouteAvailability,
    RouteCostEnvelope,
};

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_CANONICAL_WRAPPER_BYTES: u64 = 16 * 1024 * 1024;

struct WorkMeter {
    used: u64,
    maximum: u64,
}

impl WorkMeter {
    fn new(maximum: u64) -> Self {
        Self { used: 0, maximum }
    }

    fn charge(&mut self, field: &'static str) -> Result<(), SelfQueryContractError> {
        let next = self.used.saturating_add(1);
        if next > self.maximum {
            return Err(SelfQueryContractError::Bound {
                field,
                maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
                actual: usize::try_from(next).unwrap_or(usize::MAX),
            });
        }
        self.used = next;
        Ok(())
    }
}

struct Selection {
    selected: BTreeSet<ArtifactId>,
    unresolved: BTreeSet<ArtifactId>,
    required_unresolved: bool,
    frontier: Vec<String>,
}

struct CountingWriter {
    written: usize,
    maximum: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.written.saturating_add(bytes.len()) > self.maximum {
            self.written = self.maximum.saturating_add(1);
            return Err(io::Error::other("canonical output bound"));
        }
        self.written += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_canonical_size<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<usize, SelfQueryContractError> {
    let mut writer = CountingWriter {
        written: 0,
        maximum,
    };
    to_writer(&mut writer, value).map_err(|_| SelfQueryContractError::Bound {
        field,
        maximum,
        actual: writer.written,
    })?;
    Ok(writer.written)
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureBriefProjection {
    /// Exact A9.5 question retained from the A-03 input closure.
    pub question: String,
    pub candidate: ArchitectureBriefCandidate,
    pub model_synthesis: ModelSynthesis,
    pub rival_models: RivalModels,
    pub routes_and_cost: RouteCostEnvelope,
    /// Canonical byte size of this complete wrapper, including this field.
    pub total_output_bytes: u64,
    pub projection_digest: String,
}

#[derive(Serialize)]
struct ProjectionDigestPreimage<'a> {
    question: &'a str,
    candidate: &'a ArchitectureBriefCandidate,
    model_synthesis: &'a ModelSynthesis,
    rival_models: &'a RivalModels,
    routes_and_cost: &'a RouteCostEnvelope,
    total_output_bytes: u64,
}

impl ArchitectureBriefProjection {
    fn digest_preimage(&self) -> ProjectionDigestPreimage<'_> {
        ProjectionDigestPreimage {
            question: &self.question,
            candidate: &self.candidate,
            model_synthesis: &self.model_synthesis,
            rival_models: &self.rival_models,
            routes_and_cost: &self.routes_and_cost,
            total_output_bytes: self.total_output_bytes,
        }
    }

    fn compute_projection_digest(&self) -> Result<String, SelfQueryContractError> {
        canonical_json_bytes(&self.digest_preimage())
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| SelfQueryContractError::Encoding {
                field: "projection.projection_digest",
            })
    }

    /// Validates wrapper lineage, resource bounds and the projection digest.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        if self.question.len() > 64 * 1024 {
            return Err(SelfQueryContractError::Bound {
                field: "projection.question",
                maximum: 64 * 1024,
                actual: self.question.len(),
            });
        }
        self.candidate.policy.validate()?;
        self.model_synthesis.validate()?;
        let maximum = usize::try_from(
            self.candidate
                .policy
                .max_output_bytes
                .min(MAX_CANONICAL_WRAPPER_BYTES),
        )
        .unwrap_or(usize::MAX);
        let measured = bounded_canonical_size(self, maximum, "projection.output_wire")?;
        if measured != usize::try_from(self.total_output_bytes).unwrap_or(usize::MAX) {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.total_output_bytes",
            });
        }
        if self.question.trim().is_empty() || self.question.chars().any(char::is_control) {
            return Err(SelfQueryContractError::Missing {
                field: "projection.question",
            });
        }
        if self
            .candidate
            .source
            .as_ref()
            .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
            && !self.candidate.sections.is_empty()
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.nonaccepted_source_sections",
            });
        }
        if self.rival_models.availability != DataAvailability::NotRetainedByV1
            || self.routes_and_cost.routes != RouteAvailability::NotRetainedByV1
            || self.routes_and_cost.monetary_cost != MonetaryCostAvailability::NotRetainedByV1
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.v1_unavailable_fields",
            });
        }
        if self.routes_and_cost.projection_usage != self.candidate.usage {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.projection_usage",
            });
        }
        self.routes_and_cost.budget_limits.validate().map_err(|_| {
            SelfQueryContractError::BindingMismatch {
                field: "projection.budget_limits",
            }
        })?;
        self.candidate.validate()?;
        if self.total_output_bytes > self.candidate.policy.max_output_bytes {
            return Err(SelfQueryContractError::Bound {
                field: "projection.total_output_bytes",
                maximum: usize::try_from(self.candidate.policy.max_output_bytes)
                    .unwrap_or(usize::MAX),
                actual: usize::try_from(self.total_output_bytes).unwrap_or(usize::MAX),
            });
        }
        bounded_canonical_size(
            &self.digest_preimage(),
            maximum,
            "projection.digest_preimage",
        )?;
        if self.projection_digest != self.compute_projection_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "projection.projection_digest",
            });
        }
        Ok(())
    }

    /// Revalidates the projection against the exact A-03 closure.
    pub fn validate_against(&self, input: &SelfQueryInput) -> Result<(), SelfQueryContractError> {
        input.validate()?;
        self.validate()?;
        if self.question != input.question
            || self.model_synthesis.model != input.validated_candidate.model
            || self.model_synthesis.grounded != input.validated_candidate.grounded
            || self.routes_and_cost.budget_limits != input.validated_candidate.job.budget
            || self.routes_and_cost.upstream_usage != input.usage
        {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.input_synthesis",
            });
        }
        self.candidate.validate_against(input)
    }
}

/// Builds the pure `ArchitectureSelfQuery` → `ArchitectureBrief` projection.
#[expect(
    clippy::too_many_lines,
    reason = "explicit bounded projection orchestration keeps wire construction auditable"
)]
pub fn project_architecture_brief(
    input: &SelfQueryInput,
) -> Result<ArchitectureBriefProjection, SelfQueryContractError> {
    input.validate()?;
    if input.profile.output_profile != SelfQueryOutputProfile::ArchitectureBrief {
        return Err(SelfQueryContractError::BindingMismatch {
            field: "input.profile.output_profile",
        });
    }
    let mut meter = WorkMeter::new(input.policy.max_work);
    meter.charge("projection.work_units")?;
    let input_digest = input.input_digest()?;
    let Selection {
        selected,
        unresolved,
        required_unresolved,
        mut frontier,
    } = select_governing_closure(input, &mut meter)?;
    let mut sections = sections_for(input, &selected, &mut meter)?;
    sections.sort_by_key(|section| section.kind);
    let gaps = gaps_for(input, &unresolved, &mut meter)?;
    let mut omissions = omissions_for(input, &mut meter)?;
    omissions.sort_by(|left, right| left.handle.cmp(&right.handle));

    for member in &input.denominator.members {
        if !input
            .anchors
            .iter()
            .any(|anchor| anchor.anchor_id == member.anchor_id)
        {
            frontier.push(format!("missing denominator anchor:{}", member.anchor_id));
        }
    }
    frontier.sort();
    frontier.dedup();
    let expansion_handles = frontier
        .iter()
        .filter_map(|value| {
            value
                .strip_prefix("missing dependency:")
                .or_else(|| value.strip_prefix("missing denominator anchor:"))
        })
        .filter_map(|value| ArtifactId::new(value.trim()).ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let source_status = input.source.as_ref().map(|source| source.status);
    let mut disposition = match source_status {
        None | Some(ArchitectureSourceStatus::Unavailable) => {
            ArchitectureBriefDisposition::NoSource
        }
        Some(
            ArchitectureSourceStatus::Draft
            | ArchitectureSourceStatus::Rejected
            | ArchitectureSourceStatus::Superseded
            | ArchitectureSourceStatus::Stale,
        ) => ArchitectureBriefDisposition::Unsupported,
        Some(ArchitectureSourceStatus::Accepted) if input.policy.cancellation_requested => {
            ArchitectureBriefDisposition::Cancelled
        }
        Some(ArchitectureSourceStatus::Accepted)
            if input
                .policy
                .now_ms
                .zip(input.policy.deadline_ms)
                .is_some_and(|(now, deadline)| now >= deadline) =>
        {
            ArchitectureBriefDisposition::Bound
        }
        Some(ArchitectureSourceStatus::Accepted)
            if required_unresolved || !unresolved.is_empty() || !input.denominator.complete =>
        {
            if required_unresolved {
                ArchitectureBriefDisposition::Blocked
            } else {
                ArchitectureBriefDisposition::Partial
            }
        }
        Some(ArchitectureSourceStatus::Accepted) => ArchitectureBriefDisposition::Complete,
    };
    if input.policy.cancellation_requested {
        disposition = ArchitectureBriefDisposition::Cancelled;
    }
    if disposition == ArchitectureBriefDisposition::Complete
        && input.preservation.overall().is_err()
    {
        disposition = ArchitectureBriefDisposition::Partial;
    }

    let input_bytes = u64::try_from(
        canonical_json_bytes(input)
            .map_err(|_| SelfQueryContractError::Encoding {
                field: "projection.input_wire",
            })?
            .len(),
    )
    .unwrap_or(u64::MAX);
    let reference_width =
        retained_reference_width(input, &gaps, &omissions, &expansion_handles, &mut meter)?;
    let usage = eliot_dreamer_contracts::BudgetUsage {
        input_bytes,
        output_bytes: 0,
        source_width: u64::from(input.source.is_some()),
        reference_width,
        model_calls: 0,
        attempts: 0,
        candidates: 1,
        wall_ms: 0,
        work_fan_out: 0,
        report_bytes: 0,
        stu_used: 0,
    };

    let candidate_id =
        ArtifactId::new(format!("architecture-brief:{input_digest}")).map_err(|_| {
            SelfQueryContractError::Encoding {
                field: "candidate.candidate_id",
            }
        })?;
    let mut candidate = ArchitectureBriefCandidate {
        schema_version: 1,
        candidate_id,
        job_id: input.validated_candidate.bundle.job_id.clone(),
        operation_id: input.validated_candidate.job.operation_id.clone(),
        idempotency_key: input.validated_candidate.job.idempotency_key.clone(),
        task_id: input.validated_candidate.job.task_id.clone(),
        scope_id: input.validated_candidate.job.scope_id.clone(),
        requester_origin: input.validated_candidate.job.requester.origin,
        profile: input.profile.clone(),
        source_bundle_handle: input.source_bundle_handle.clone(),
        pair: input.source.as_ref().map(|source| source.pair.clone()),
        source: input.source.clone(),
        anchors: input.anchors.clone(),
        denominator: input.denominator.clone(),
        sections,
        gaps,
        omissions,
        frontier,
        expansion_handles,
        attempt: input.attempt.clone(),
        state_fence: input.validated_candidate.job.state_fence.clone(),
        policy: input.policy.clone(),
        usage,
        work_units: meter.used,
        preservation: input.preservation.clone(),
        authority_ceiling: input.policy.authority_ceiling,
        privacy: input.policy.privacy,
        disclosure: input.policy.disclosure,
        effect_ceiling: input.policy.effect_ceiling,
        proof_ceiling: input.policy.proof_ceiling,
        invalidation_conditions: input.invalidation_conditions.clone(),
        disposition,
        input_digest,
        output_digest: ZERO_DIGEST.to_owned(),
    };
    meter.charge("projection.candidate_digest")?;
    candidate.work_units = meter.used;
    for _ in 0..3 {
        candidate.output_digest = candidate.compute_output_digest()?;
        let candidate_size = bounded_canonical_size(
            &candidate,
            usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
            "candidate.output_wire",
        )?;
        let measured = u64::try_from(candidate_size).unwrap_or(u64::MAX);
        if candidate.usage.output_bytes == measured {
            break;
        }
        candidate.usage.output_bytes = measured;
    }
    candidate.output_digest = candidate.compute_output_digest()?;
    let candidate_size = bounded_canonical_size(
        &candidate,
        usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
        "candidate.output_wire",
    )?;
    if candidate.usage.output_bytes != u64::try_from(candidate_size).unwrap_or(u64::MAX) {
        return Err(SelfQueryContractError::BindingMismatch {
            field: "candidate.usage.output_bytes",
        });
    }
    candidate.validate_against(input)?;

    let model_synthesis = ModelSynthesis {
        model: input.validated_candidate.model.clone(),
        grounded: input.validated_candidate.grounded.clone(),
    };
    let rival_models = RivalModels {
        availability: DataAvailability::NotRetainedByV1,
    };
    let routes_and_cost = RouteCostEnvelope {
        routes: RouteAvailability::NotRetainedByV1,
        monetary_cost: MonetaryCostAvailability::NotRetainedByV1,
        budget_limits: input.validated_candidate.job.budget,
        upstream_usage: input.usage,
        projection_usage: candidate.usage,
    };
    let mut projection = ArchitectureBriefProjection {
        question: input.question.clone(),
        candidate,
        model_synthesis,
        rival_models,
        routes_and_cost,
        total_output_bytes: 0,
        projection_digest: ZERO_DIGEST.to_owned(),
    };
    meter.charge("projection.wrapper_digest")?;
    for _ in 0..3 {
        bounded_canonical_size(
            &projection.digest_preimage(),
            usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
            "projection.digest_preimage",
        )?;
        projection.projection_digest = projection.compute_projection_digest()?;
        let measured = bounded_canonical_size(
            &projection,
            usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
            "projection.output_wire",
        )?;
        let measured = u64::try_from(measured).unwrap_or(u64::MAX);
        if projection.total_output_bytes == measured {
            break;
        }
        projection.total_output_bytes = measured;
    }
    bounded_canonical_size(
        &projection.digest_preimage(),
        usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
        "projection.digest_preimage",
    )?;
    projection.projection_digest = projection.compute_projection_digest()?;
    let final_size = bounded_canonical_size(
        &projection,
        usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
        "projection.output_wire",
    )?;
    if final_size != usize::try_from(projection.total_output_bytes).unwrap_or(usize::MAX) {
        return Err(SelfQueryContractError::BindingMismatch {
            field: "projection.total_output_bytes",
        });
    }
    if projection.total_output_bytes > input.policy.max_output_bytes {
        return Err(SelfQueryContractError::Bound {
            field: "projection.total_output_bytes",
            maximum: usize::try_from(input.policy.max_output_bytes).unwrap_or(usize::MAX),
            actual: usize::try_from(projection.total_output_bytes).unwrap_or(usize::MAX),
        });
    }
    projection.validate_against(input)?;
    Ok(projection)
}

#[expect(
    clippy::too_many_lines,
    reason = "explicit bounded governing-closure traversal keeps authority checks auditable"
)]
fn select_governing_closure(
    input: &SelfQueryInput,
    meter: &mut WorkMeter,
) -> Result<Selection, SelfQueryContractError> {
    if input
        .source
        .as_ref()
        .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
        || input.policy.cancellation_requested
        || input
            .policy
            .now_ms
            .zip(input.policy.deadline_ms)
            .is_some_and(|(now, deadline)| now >= deadline)
    {
        let unresolved = input
            .anchors
            .iter()
            .map(|anchor| anchor.anchor_id.clone())
            .collect::<BTreeSet<_>>();
        let mut frontier = Vec::new();
        if input
            .source
            .as_ref()
            .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
        {
            frontier.push("source is not accepted".to_owned());
        }
        if input.policy.cancellation_requested {
            frontier.push("projection cancelled".to_owned());
        }
        if input
            .policy
            .now_ms
            .zip(input.policy.deadline_ms)
            .is_some_and(|(now, deadline)| now >= deadline)
        {
            frontier.push("projection deadline elapsed".to_owned());
        }
        let required_unresolved = input.denominator.members.iter().any(|member| {
            member.required
                && matches!(
                    member.kind,
                    ArchitectureDependencyKind::HardBoundary
                        | ArchitectureDependencyKind::GlobalBoundary
                )
        });
        return Ok(Selection {
            selected: BTreeSet::new(),
            unresolved,
            required_unresolved,
            frontier,
        });
    }
    let by_id = input
        .anchors
        .iter()
        .map(|anchor| (anchor.anchor_id.clone(), anchor))
        .collect::<BTreeMap<_, _>>();
    let mut selected = BTreeSet::new();
    let mut unresolved = BTreeSet::new();
    let mut frontier = Vec::new();
    let mut required_unresolved = false;
    for root in &input.anchors {
        meter.charge("projection.work_units")?;
        if !matches!(
            root.applicability.state,
            ArchitectureApplicabilityState::Applicable
                | ArchitectureApplicabilityState::Conditional
        ) {
            if root.applicability.state == ArchitectureApplicabilityState::Unknown {
                unresolved.insert(root.anchor_id.clone());
                frontier.push(format!("unknown applicability:{}", root.anchor_id));
            }
            continue;
        }
        let mut stack = vec![(root.anchor_id.clone(), false)];
        let mut seen = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        let mut local = BTreeSet::new();
        let mut ok = true;
        while let Some((id, leaving)) = stack.pop() {
            meter.charge("projection.work_units")?;
            if leaving {
                visiting.remove(&id);
                continue;
            }
            if !seen.insert(id.clone()) {
                if visiting.contains(&id) {
                    ok = false;
                    frontier.push(format!("cyclic dependency:{id}"));
                }
                continue;
            }
            let Some(anchor) = by_id.get(&id) else {
                ok = false;
                frontier.push(format!("missing dependency:{id}"));
                continue;
            };
            if matches!(
                anchor.applicability.state,
                ArchitectureApplicabilityState::Unknown
                    | ArchitectureApplicabilityState::NotApplicable
            ) {
                ok = false;
                unresolved.insert(anchor.anchor_id.clone());
                frontier.push(format!("governing applicability:{}", anchor.anchor_id));
            } else {
                local.insert(anchor.anchor_id.clone());
            }
            visiting.insert(id.clone());
            stack.push((id, true));
            for dependency in anchor.dependency_refs.iter().rev() {
                meter.charge("projection.work_units")?;
                stack.push((dependency.clone(), false));
            }
        }
        if ok {
            selected.extend(local);
        } else {
            unresolved.insert(root.anchor_id.clone());
            if input
                .denominator
                .members
                .iter()
                .any(|member| member.required && member.anchor_id == root.anchor_id)
            {
                required_unresolved = true;
            }
        }
    }
    for member in &input.denominator.members {
        if member.required && member.kind == ArchitectureDependencyKind::HardBoundary
            || member.kind == ArchitectureDependencyKind::GlobalBoundary
        {
            let state = by_id
                .get(&member.anchor_id)
                .map(|anchor| anchor.applicability.state);
            if !matches!(
                state,
                Some(
                    ArchitectureApplicabilityState::Applicable
                        | ArchitectureApplicabilityState::Conditional
                )
            ) {
                required_unresolved = true;
                frontier.push(format!("required boundary:{}", member.anchor_id));
                if let Some(anchor) = by_id.get(&member.anchor_id) {
                    unresolved.insert(anchor.anchor_id.clone());
                }
            }
        }
    }
    Ok(Selection {
        selected,
        unresolved,
        required_unresolved,
        frontier,
    })
}

fn sections_for(
    input: &SelfQueryInput,
    selected: &BTreeSet<ArtifactId>,
    meter: &mut WorkMeter,
) -> Result<Vec<ArchitectureBriefSection>, SelfQueryContractError> {
    let mut grouped: BTreeMap<ArchitectureBriefSectionKind, Vec<ArchitectureBriefStatement>> =
        BTreeMap::new();
    let by_id = input
        .anchors
        .iter()
        .map(|anchor| (anchor.anchor_id.clone(), anchor))
        .collect::<BTreeMap<_, _>>();
    for anchor_id in ordered_selected_ids(input, selected, meter)? {
        meter.charge("projection.work_units")?;
        let anchor = by_id
            .get(&anchor_id)
            .ok_or(SelfQueryContractError::BindingMismatch {
                field: "projection.selected_anchor",
            })?;
        let statement_id =
            ArtifactId::new(format!("statement:{}", anchor.anchor_id)).map_err(|_| {
                SelfQueryContractError::Encoding {
                    field: "statement.statement_id",
                }
            })?;
        grouped
            .entry(section_kind(anchor.class))
            .or_default()
            .push(ArchitectureBriefStatement {
                statement_id,
                class: anchor.class,
                anchor_id: anchor.anchor_id.clone(),
                source_handle: anchor.source_handle.clone(),
                source_revision: anchor.revision.clone(),
                source_digest: anchor.source_digest.clone(),
                byte_start: anchor.byte_start,
                byte_end: anchor.byte_end,
                modality: anchor.modality,
                text: anchor.text.clone(),
            });
    }
    grouped
        .into_iter()
        .map(|(kind, statements)| {
            let mut section = ArchitectureBriefSection {
                kind,
                statements,
                digest: ZERO_DIGEST.to_owned(),
            };
            section.digest = section.compute_digest()?;
            Ok(section)
        })
        .collect()
}

/// Orders derived statements by explicit dependency edges, with stable ID
/// ordering for unrelated anchors. The source anchor vector itself is never
/// rewritten.
fn ordered_selected_ids(
    input: &SelfQueryInput,
    selected: &BTreeSet<ArtifactId>,
    meter: &mut WorkMeter,
) -> Result<Vec<ArtifactId>, SelfQueryContractError> {
    let by_id = input
        .anchors
        .iter()
        .map(|anchor| (anchor.anchor_id.clone(), anchor))
        .collect::<BTreeMap<_, _>>();
    let mut indegree = selected
        .iter()
        .map(|id| (id.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut outgoing: BTreeMap<ArtifactId, Vec<ArtifactId>> = BTreeMap::new();
    for id in selected {
        meter.charge("projection.work_units")?;
        let anchor = by_id
            .get(id)
            .ok_or(SelfQueryContractError::BindingMismatch {
                field: "projection.selected_anchor",
            })?;
        for dependency in &anchor.dependency_refs {
            meter.charge("projection.work_units")?;
            if selected.contains(dependency) {
                *indegree
                    .get_mut(id)
                    .ok_or(SelfQueryContractError::BindingMismatch {
                        field: "projection.selected_anchor",
                    })? += 1;
                outgoing
                    .entry(dependency.clone())
                    .or_default()
                    .push(id.clone());
            }
        }
    }
    for children in outgoing.values_mut() {
        children.sort();
    }
    let mut ready = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(id, _)| id.clone())
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(selected.len());
    while let Some(id) = ready.pop_first() {
        meter.charge("projection.work_units")?;
        order.push(id.clone());
        if let Some(children) = outgoing.get(&id) {
            for child in children {
                meter.charge("projection.work_units")?;
                let degree =
                    indegree
                        .get_mut(child)
                        .ok_or(SelfQueryContractError::BindingMismatch {
                            field: "projection.selected_anchor",
                        })?;
                *degree -= 1;
                if *degree == 0 {
                    ready.insert(child.clone());
                }
            }
        }
    }
    if order.len() != selected.len() {
        let emitted = order.iter().cloned().collect::<BTreeSet<_>>();
        order.extend(selected.iter().filter(|id| !emitted.contains(*id)).cloned());
    }
    Ok(order)
}

fn section_kind(
    class: eliot_dreamer_contracts::ArchitectureAnchorClass,
) -> ArchitectureBriefSectionKind {
    match class {
        eliot_dreamer_contracts::ArchitectureAnchorClass::Intent
        | eliot_dreamer_contracts::ArchitectureAnchorClass::Rationale => {
            ArchitectureBriefSectionKind::IntentAndRationale
        }
        eliot_dreamer_contracts::ArchitectureAnchorClass::Guarantee
        | eliot_dreamer_contracts::ArchitectureAnchorClass::HardBoundary
        | eliot_dreamer_contracts::ArchitectureAnchorClass::Invariant => {
            ArchitectureBriefSectionKind::InvariantsAndHardBoundaries
        }
        eliot_dreamer_contracts::ArchitectureAnchorClass::Owner => {
            ArchitectureBriefSectionKind::OwnersAndForbiddenTransfers
        }
        eliot_dreamer_contracts::ArchitectureAnchorClass::NonGoal
        | eliot_dreamer_contracts::ArchitectureAnchorClass::OpenQuestion => {
            ArchitectureBriefSectionKind::NonGoalsAndOpenQuestions
        }
        eliot_dreamer_contracts::ArchitectureAnchorClass::Precedence => {
            ArchitectureBriefSectionKind::PrecedenceAndSupersession
        }
        eliot_dreamer_contracts::ArchitectureAnchorClass::FailureBehavior => {
            ArchitectureBriefSectionKind::BehaviorAndFailureConditions
        }
    }
}

fn gaps_for(
    input: &SelfQueryInput,
    unresolved: &BTreeSet<ArtifactId>,
    meter: &mut WorkMeter,
) -> Result<Vec<ArchitectureBriefGap>, SelfQueryContractError> {
    unresolved
        .iter()
        .map(|id| {
            meter.charge("projection.work_units")?;
            let anchor = input.anchors.iter().find(|anchor| anchor.anchor_id == *id);
            let detail = anchor.map_or_else(
                || "governing anchor is missing from the supplied closure".to_owned(),
                |anchor| anchor.applicability.reason.clone(),
            );
            Ok(ArchitectureBriefGap {
                gap_id: ArtifactId::new(format!("gap:{id}")).map_err(|_| {
                    SelfQueryContractError::Encoding {
                        field: "gap.gap_id",
                    }
                })?,
                class: ArchitectureBriefGapClass::Architecture,
                state: if anchor.is_some_and(|anchor| {
                    anchor.applicability.state == ArchitectureApplicabilityState::Unknown
                }) {
                    ArchitectureBriefGapState::Unknown
                } else {
                    ArchitectureBriefGapState::Partial
                },
                owner: "architecture-source-closure".to_owned(),
                detail,
                evidence_refs: anchor
                    .map(|anchor| anchor.applicability.evidence_refs.clone())
                    .unwrap_or_default(),
            })
        })
        .collect()
}

fn omissions_for(
    input: &SelfQueryInput,
    meter: &mut WorkMeter,
) -> Result<Vec<ArchitectureBriefOmission>, SelfQueryContractError> {
    input
        .validated_candidate
        .bundle
        .omissions
        .iter()
        .map(|omission| {
            meter.charge("projection.work_units")?;
            Ok(ArchitectureBriefOmission {
                handle: ArtifactId::new(omission.handle.clone()).map_err(|_| {
                    SelfQueryContractError::Encoding {
                        field: "omission.handle",
                    }
                })?,
                reason: omission.nonrecoverable_reason.as_ref().map_or_else(
                    || omission.reason.clone(),
                    |extra| format!("{}; nonrecoverable: {extra}", omission.reason),
                ),
                reversible: omission.reversible,
            })
        })
        .collect()
}

fn retained_reference_width(
    input: &SelfQueryInput,
    gaps: &[ArchitectureBriefGap],
    omissions: &[ArchitectureBriefOmission],
    expansion_handles: &[ArtifactId],
    meter: &mut WorkMeter,
) -> Result<u64, SelfQueryContractError> {
    let mut refs = BTreeSet::new();
    for anchor in &input.anchors {
        refs.extend(anchor.dependency_refs.iter());
        refs.extend(anchor.applicability.evidence_refs.iter());
        meter.charge("projection.work_units")?;
    }
    for member in &input.denominator.members {
        refs.insert(&member.member_id);
        refs.insert(&member.anchor_id);
        meter.charge("projection.work_units")?;
    }
    for gap in gaps {
        refs.extend(gap.evidence_refs.iter());
        meter.charge("projection.work_units")?;
    }
    for omission in omissions {
        refs.insert(&omission.handle);
        meter.charge("projection.work_units")?;
    }
    refs.extend(expansion_handles.iter());
    for _ in expansion_handles {
        meter.charge("projection.work_units")?;
    }
    Ok(u64::try_from(refs.len()).unwrap_or(u64::MAX))
}
