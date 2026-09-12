use std::collections::{BTreeMap, BTreeSet};

use eliot_conformance_contracts::{
    CapabilitySupportRow, EvidenceExecutionStatus, ImplementationSupport, SupportObservationState,
};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{ArchitectureSourceStatus, SelfQueryOutputProfile};

use crate::{
    ArchitectureAlignment, EvidenceAxisSnapshot, EvidenceVerdict, ImplementationBriefDisposition,
    ImplementationBriefError, ImplementationBriefInput, ImplementationBriefProjection,
    ImplementationEvidence, ImplementationGap, ImplementationGapClass, ImplementationMechanism,
    ImplementationObligation, ImplementationOmission, ImplementationSourceStatus,
    MechanismAssessment, MechanismDisposition, ObligationAssessment, ProofStage, StageAssessment,
    StageDisposition, IMPLEMENTATION_BRIEF_PROOF_CEILING, IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
    validation::{MAX_WIRE_BYTES, bounded_canonical_size},
};

struct WorkMeter {
    used: u64,
    maximum: u64,
}

impl WorkMeter {
    const fn new(maximum: u64) -> Self {
        Self { used: 0, maximum }
    }

    fn charge(&mut self) -> Result<(), ImplementationBriefError> {
        let next = self.used.saturating_add(1);
        if next > self.maximum {
            return Err(ImplementationBriefError::Bound {
                field: "projection.work_units",
                maximum: usize::try_from(self.maximum).unwrap_or(usize::MAX),
                actual: usize::try_from(next).unwrap_or(usize::MAX),
            });
        }
        self.used = next;
        Ok(())
    }
}

/// Produces the pure candidate-only Implementation self-query projection.
#[expect(
    clippy::too_many_lines,
    reason = "all denominator, source, evidence, and gap joins stay explicit"
)]
pub fn project_implementation_brief(
    input: &ImplementationBriefInput,
) -> Result<ImplementationBriefProjection, ImplementationBriefError> {
    input.validate()?;
    if input.self_query.profile.output_profile != SelfQueryOutputProfile::ImplementationBrief {
        return Err(ImplementationBriefError::BindingMismatch {
            field: "input.self_query.profile.output_profile",
        });
    }

    let mut meter = WorkMeter::new(input.self_query.policy.max_work);
    meter.charge()?;
    let support_rows = input
        .conformance
        .support_rows
        .iter()
        .map(|row| (row.support_claim_ref.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let mechanisms = input
        .mechanisms
        .iter()
        .map(|value| (value.mechanism_id.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let obligations = input
        .obligations
        .iter()
        .map(|value| (value.obligation_id.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let statements = input
        .implementation_source
        .as_ref()
        .map(|source| {
            source
                .statements
                .iter()
                .map(|value| (value.statement_id.as_str(), value))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let architecture_ids = input
        .self_query
        .anchors
        .iter()
        .map(|anchor| anchor.anchor_id.as_str())
        .collect::<BTreeSet<_>>();

    let mut gaps = BTreeMap::new();
    let mut assessments = Vec::with_capacity(input.denominator.mechanism_ids.len());
    for mechanism_id in &input.denominator.mechanism_ids {
        meter.charge()?;
        assessments.push(assess_mechanism(
            input,
            mechanism_id,
            mechanisms.get(mechanism_id.as_str()).copied(),
            &obligations,
            &support_rows,
            &statements,
            &architecture_ids,
            &mut gaps,
            &mut meter,
        )?);
    }

    account_missing_denominator_members(input, &mut gaps, &mut meter)?;
    assessments.sort_by(|left, right| left.mechanism_id.cmp(&right.mechanism_id));
    let mut gaps = gaps.into_values().collect::<Vec<_>>();
    gaps.sort_by(|left, right| left.gap_id.cmp(&right.gap_id));

    let mut omissions = input
        .self_query
        .validated_candidate
        .bundle
        .omissions
        .iter()
        .map(|omission| ImplementationOmission {
            omission_id: format!("bundle-omission:{}", omission.handle),
            owner: "dream-input-bundle".to_owned(),
            detail: omission.nonrecoverable_reason.as_ref().map_or_else(
                || omission.reason.clone(),
                |reason| format!("{}; nonrecoverable: {reason}", omission.reason),
            ),
            reversible: omission.reversible,
        })
        .collect::<Vec<_>>();
    if input.implementation_source.is_none() {
        omissions.push(ImplementationOmission {
            omission_id: "implementation-source-unavailable".to_owned(),
            owner: "implementation-source-owner".to_owned(),
            detail: "no Implementation source projection was supplied".to_owned(),
            reversible: true,
        });
    }
    omissions.sort_by(|left, right| left.omission_id.cmp(&right.omission_id));

    let job = &input.self_query.validated_candidate.job;
    let state_fence_digest = canonical_json_bytes(&job.state_fence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ImplementationBriefError::Encoding {
            field: "projection.state_fence_digest",
        })?;
    let disposition = projection_disposition(input, &assessments, &gaps);
    meter.charge()?;
    let mut projection = ImplementationBriefProjection {
        schema_version: IMPLEMENTATION_BRIEF_SCHEMA_VERSION,
        candidate_id: format!("implementation-brief:{}", input.input_digest),
        job_id: job.canonical_id(),
        operation_id: job.operation_id.clone(),
        idempotency_key: job.idempotency_key.clone(),
        task_id: job.task_id.clone(),
        scope_id: job.scope_id.clone(),
        profile: input.self_query.profile.clone(),
        attempt: input.self_query.attempt.clone(),
        state_fence_digest,
        question: input.self_query.question.clone(),
        architecture_source_handle: input
            .self_query
            .source
            .as_ref()
            .map(|source| source.source_handle.as_str().to_owned()),
        architecture_source_digest: input
            .self_query
            .source
            .as_ref()
            .map(|source| source.digest.clone()),
        implementation_source_handle: input
            .implementation_source
            .as_ref()
            .map(|source| source.source_handle.clone()),
        implementation_source_digest: input
            .implementation_source
            .as_ref()
            .map(|source| source.source_digest.clone()),
        implementation_source_status: input
            .implementation_source
            .as_ref()
            .map(|source| source.status),
        mechanisms: assessments,
        gaps,
        omissions,
        denominator: input.denominator.clone(),
        invalidation_conditions: input.invalidation_conditions.clone(),
        disposition,
        proof_ceiling: IMPLEMENTATION_BRIEF_PROOF_CEILING.to_owned(),
        work_units: meter.used,
        total_output_bytes: 0,
        input_digest: input.input_digest.clone(),
        output_digest: "0".repeat(64),
    };
    seal_output_size(input, &mut projection)?;
    projection.validate()?;
    Ok(projection)
}

impl ImplementationBriefProjection {
    /// Reprojects the exact closure and rejects every changed same-identity field.
    pub fn validate_against(
        &self,
        input: &ImplementationBriefInput,
    ) -> Result<(), ImplementationBriefError> {
        self.validate()?;
        if project_implementation_brief(input)? != *self {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "projection.input_binding",
            });
        }
        Ok(())
    }
}

fn seal_output_size(
    input: &ImplementationBriefInput,
    projection: &mut ImplementationBriefProjection,
) -> Result<(), ImplementationBriefError> {
    let maximum = usize::try_from(
        input
            .self_query
            .policy
            .max_output_bytes
            .min(MAX_WIRE_BYTES as u64),
    )
    .unwrap_or(MAX_WIRE_BYTES);
    for _ in 0..16 {
        projection.output_digest = projection.compute_output_digest()?;
        let measured = u64::try_from(bounded_canonical_size(
            projection,
            maximum,
            "projection.output_wire",
        )?)
        .unwrap_or(u64::MAX);
        if projection.total_output_bytes == measured {
            projection.output_digest = projection.compute_output_digest()?;
            return Ok(());
        }
        projection.total_output_bytes = measured;
    }
    Err(ImplementationBriefError::BindingMismatch {
        field: "projection.total_output_bytes",
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "authority-separated source and evidence indexes remain explicit"
)]
fn assess_mechanism(
    input: &ImplementationBriefInput,
    mechanism_id: &str,
    mechanism: Option<&ImplementationMechanism>,
    obligations: &BTreeMap<&str, &ImplementationObligation>,
    support_rows: &BTreeMap<&str, &CapabilitySupportRow>,
    statements: &BTreeMap<&str, &crate::ImplementationStatement>,
    architecture_ids: &BTreeSet<&str>,
    gaps: &mut BTreeMap<String, ImplementationGap>,
    meter: &mut WorkMeter,
) -> Result<MechanismAssessment, ImplementationBriefError> {
    let Some(mechanism) = mechanism else {
        insert_gap(
            gaps,
            ImplementationGap {
                gap_id: format!("gap:mechanism:{mechanism_id}"),
                class: ImplementationGapClass::Coverage,
                owner: "implementation-denominator".to_owned(),
                mechanism_id: Some(mechanism_id.to_owned()),
                obligation_id: None,
                stage: None,
                detail: "expected mechanism is unspecified in the supplied Implementation source"
                    .to_owned(),
                evidence_refs: Vec::new(),
            },
        );
        return Ok(MechanismAssessment {
            mechanism_id: mechanism_id.to_owned(),
            owner: None,
            architecture_refs: Vec::new(),
            statement_refs: Vec::new(),
            obligation_ids: Vec::new(),
            dependency_refs: Vec::new(),
            obligations: Vec::new(),
            disposition: MechanismDisposition::Unknown,
        });
    };

    let gap_count = gaps.len();
    let mut architecture_conflict = false;
    for reference in &mechanism.architecture_refs {
        meter.charge()?;
        if !architecture_ids.contains(reference.as_str()) {
            insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!("gap:{}:architecture:{reference}", mechanism.mechanism_id),
                    class: ImplementationGapClass::Source,
                    owner: "architecture-source-owner".to_owned(),
                    mechanism_id: Some(mechanism.mechanism_id.clone()),
                    obligation_id: None,
                    stage: None,
                    detail: "referenced governing Architecture anchor is absent".to_owned(),
                    evidence_refs: Vec::new(),
                },
            );
        }
    }
    for reference in &mechanism.statement_refs {
        meter.charge()?;
        match statements.get(reference.as_str()) {
            None => insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!("gap:{}:statement:{reference}", mechanism.mechanism_id),
                    class: ImplementationGapClass::Source,
                    owner: "implementation-source-owner".to_owned(),
                    mechanism_id: Some(mechanism.mechanism_id.clone()),
                    obligation_id: None,
                    stage: None,
                    detail: "referenced Implementation statement is absent".to_owned(),
                    evidence_refs: Vec::new(),
                },
            ),
            Some(statement) if statement.alignment == ArchitectureAlignment::Conflict => {
                architecture_conflict = true;
                insert_gap(
                    gaps,
                    ImplementationGap {
                        gap_id: format!(
                            "gap:{}:architecture-conflict:{reference}",
                            mechanism.mechanism_id
                        ),
                        class: ImplementationGapClass::ArchitectureConflict,
                        owner: "architecture-precedence-owner".to_owned(),
                        mechanism_id: Some(mechanism.mechanism_id.clone()),
                        obligation_id: None,
                        stage: None,
                        detail: "Implementation conflicts with governing Architecture".to_owned(),
                        evidence_refs: Vec::new(),
                    },
                );
            }
            Some(statement) if statement.alignment == ArchitectureAlignment::Unknown => {
                insert_gap(
                    gaps,
                    ImplementationGap {
                        gap_id: format!(
                            "gap:{}:architecture-unknown:{reference}",
                            mechanism.mechanism_id
                        ),
                        class: ImplementationGapClass::Unknown,
                        owner: "architecture-precedence-owner".to_owned(),
                        mechanism_id: Some(mechanism.mechanism_id.clone()),
                        obligation_id: None,
                        stage: None,
                        detail: "Architecture alignment remains unknown".to_owned(),
                        evidence_refs: Vec::new(),
                    },
                );
            }
            Some(_) => {}
        }
    }

    let mut obligation_assessments = Vec::with_capacity(mechanism.obligation_refs.len());
    for obligation_id in &mechanism.obligation_refs {
        meter.charge()?;
        obligation_assessments.push(assess_obligation(
            input,
            mechanism,
            obligation_id,
            obligations.get(obligation_id.as_str()).copied(),
            support_rows,
            gaps,
            meter,
        )?);
    }
    obligation_assessments.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
    let disposition = mechanism_disposition(
        architecture_conflict,
        gaps.len() > gap_count,
        &obligation_assessments,
    );
    Ok(MechanismAssessment {
        mechanism_id: mechanism.mechanism_id.clone(),
        owner: Some(mechanism.owner.clone()),
        architecture_refs: mechanism.architecture_refs.clone(),
        statement_refs: mechanism.statement_refs.clone(),
        obligation_ids: mechanism.obligation_refs.clone(),
        dependency_refs: mechanism.dependency_refs.clone(),
        obligations: obligation_assessments,
        disposition,
    })
}

fn assess_obligation(
    input: &ImplementationBriefInput,
    mechanism: &ImplementationMechanism,
    obligation_id: &str,
    obligation: Option<&ImplementationObligation>,
    support_rows: &BTreeMap<&str, &CapabilitySupportRow>,
    gaps: &mut BTreeMap<String, ImplementationGap>,
    meter: &mut WorkMeter,
) -> Result<ObligationAssessment, ImplementationBriefError> {
    let Some(obligation) = obligation else {
        let gap_id = format!("gap:{}:obligation:{obligation_id}", mechanism.mechanism_id);
        insert_gap(
            gaps,
            ImplementationGap {
                gap_id: gap_id.clone(),
                class: ImplementationGapClass::Coverage,
                owner: mechanism.owner.clone(),
                mechanism_id: Some(mechanism.mechanism_id.clone()),
                obligation_id: Some(obligation_id.to_owned()),
                stage: None,
                detail: "declared mechanism obligation is absent".to_owned(),
                evidence_refs: Vec::new(),
            },
        );
        return Ok(ObligationAssessment {
            obligation_id: obligation_id.to_owned(),
            mechanism_id: mechanism.mechanism_id.clone(),
            owner: mechanism.owner.clone(),
            required_domains: Vec::new(),
            stages: Vec::new(),
            gap_ids: vec![gap_id],
            complete: false,
        });
    };

    let mut stages = Vec::with_capacity(obligation.required_stages.len());
    let mut gap_ids = Vec::new();
    for stage in &obligation.required_stages {
        meter.charge()?;
        let mut matching = input
            .evidence
            .iter()
            .filter(|item| {
                item.obligation_id == obligation.obligation_id && item.stage == *stage
            })
            .collect::<Vec<_>>();
        matching.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        let mut snapshots = Vec::with_capacity(matching.len());
        let mut dispositions = Vec::with_capacity(matching.len().max(1));
        if matching.is_empty() {
            dispositions.push(StageDisposition::Missing);
        }
        for evidence in matching {
            meter.charge()?;
            if let Some(row) = support_rows.get(evidence.support_claim_ref.as_str()).copied() {
                snapshots.push(EvidenceAxisSnapshot::from_parts(evidence, row));
                dispositions.push(evidence_disposition(evidence, row));
            } else {
                dispositions.push(StageDisposition::Missing);
            }
        }
        snapshots.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        let disposition = dispositions
            .into_iter()
            .max_by_key(|value| disposition_severity(*value))
            .unwrap_or(StageDisposition::Missing);
        if !stage_is_complete(disposition) {
            let gap_id = format!(
                "gap:{}:{}:{stage:?}",
                mechanism.mechanism_id, obligation.obligation_id
            )
            .to_ascii_lowercase();
            gap_ids.push(gap_id.clone());
            insert_gap(
                gaps,
                ImplementationGap {
                    gap_id,
                    class: gap_class_for_stage(*stage, disposition),
                    owner: obligation.owner.clone(),
                    mechanism_id: Some(mechanism.mechanism_id.clone()),
                    obligation_id: Some(obligation.obligation_id.clone()),
                    stage: Some(*stage),
                    detail: format!("required {stage:?} evidence is {disposition:?}"),
                    evidence_refs: snapshots
                        .iter()
                        .map(|snapshot| snapshot.evidence_id.clone())
                        .collect(),
                },
            );
        }
        stages.push(StageAssessment {
            stage: *stage,
            disposition,
            evidence: snapshots,
        });
    }
    gap_ids.sort();
    gap_ids.dedup();
    let complete = stages
        .iter()
        .all(|stage| stage_is_complete(stage.disposition))
        && gap_ids.is_empty();
    Ok(ObligationAssessment {
        obligation_id: obligation.obligation_id.clone(),
        mechanism_id: obligation.mechanism_id.clone(),
        owner: obligation.owner.clone(),
        required_domains: obligation.required_domains.clone(),
        stages,
        gap_ids,
        complete,
    })
}

fn account_missing_denominator_members(
    input: &ImplementationBriefInput,
    gaps: &mut BTreeMap<String, ImplementationGap>,
    meter: &mut WorkMeter,
) -> Result<(), ImplementationBriefError> {
    let actual_obligations = input
        .obligations
        .iter()
        .map(|value| value.obligation_id.as_str())
        .collect::<BTreeSet<_>>();
    for id in &input.denominator.obligation_ids {
        meter.charge()?;
        if !actual_obligations.contains(id.as_str()) {
            insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!("gap:obligation:{id}"),
                    class: ImplementationGapClass::Coverage,
                    owner: "implementation-denominator".to_owned(),
                    mechanism_id: None,
                    obligation_id: Some(id.clone()),
                    stage: None,
                    detail: "expected obligation is absent".to_owned(),
                    evidence_refs: Vec::new(),
                },
            );
        }
    }
    let actual_evidence = input
        .evidence
        .iter()
        .map(|value| value.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    for id in &input.denominator.evidence_ids {
        meter.charge()?;
        if !actual_evidence.contains(id.as_str()) {
            insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!("gap:evidence:{id}"),
                    class: ImplementationGapClass::Coverage,
                    owner: "implementation-denominator".to_owned(),
                    mechanism_id: None,
                    obligation_id: None,
                    stage: None,
                    detail: "expected evidence is absent".to_owned(),
                    evidence_refs: Vec::new(),
                },
            );
        }
    }
    Ok(())
}

fn evidence_disposition(
    evidence: &ImplementationEvidence,
    row: &CapabilitySupportRow,
) -> StageDisposition {
    if evidence.verdict == EvidenceVerdict::Conflicted
        || row.support_observation_state == SupportObservationState::Conflicted
    {
        return StageDisposition::Conflicted;
    }
    if row.support_observation_state == SupportObservationState::Stale
        || row.implementation_support == ImplementationSupport::Stale
    {
        return StageDisposition::Stale;
    }
    match evidence.verdict {
        EvidenceVerdict::Failed => return StageDisposition::Failed,
        EvidenceVerdict::Partial => return StageDisposition::Partial,
        EvidenceVerdict::Skipped => return StageDisposition::Skipped,
        EvidenceVerdict::Simulated => return StageDisposition::Simulated,
        EvidenceVerdict::Missing => return StageDisposition::Missing,
        EvidenceVerdict::Unavailable => return StageDisposition::Unavailable,
        EvidenceVerdict::Unknown => return StageDisposition::Unknown,
        EvidenceVerdict::NotApplicable => return StageDisposition::NotApplicable,
        EvidenceVerdict::Passed | EvidenceVerdict::Conflicted => {}
    }
    match row.support_observation_state {
        SupportObservationState::NotRunning | SupportObservationState::Unavailable => {
            return StageDisposition::Unavailable;
        }
        SupportObservationState::Unknown => return StageDisposition::Unknown,
        SupportObservationState::Stale => return StageDisposition::Stale,
        SupportObservationState::Conflicted => return StageDisposition::Conflicted,
        SupportObservationState::Observed => {}
    }
    match row.evidence_execution_status {
        EvidenceExecutionStatus::NotExecuted => return StageDisposition::CurrentUnverified,
        EvidenceExecutionStatus::Simulated => return StageDisposition::Simulated,
        EvidenceExecutionStatus::UnknownOutcome => return StageDisposition::Unknown,
        EvidenceExecutionStatus::Executed => {}
    }
    match row.implementation_support {
        ImplementationSupport::CurrentVerified => StageDisposition::CurrentVerified,
        ImplementationSupport::CurrentUnverified
        | ImplementationSupport::Target
        | ImplementationSupport::Experimental => StageDisposition::CurrentUnverified,
        ImplementationSupport::Partial | ImplementationSupport::Degraded => {
            StageDisposition::Partial
        }
        ImplementationSupport::Blocked | ImplementationSupport::Deferred => {
            StageDisposition::Missing
        }
        ImplementationSupport::Stale => StageDisposition::Stale,
        ImplementationSupport::NotApplicable => StageDisposition::NotApplicable,
    }
}

const fn stage_is_complete(disposition: StageDisposition) -> bool {
    matches!(
        disposition,
        StageDisposition::CurrentVerified | StageDisposition::NotApplicable
    )
}

const fn disposition_severity(disposition: StageDisposition) -> u8 {
    match disposition {
        StageDisposition::CurrentVerified => 0,
        StageDisposition::NotApplicable => 1,
        StageDisposition::CurrentUnverified => 2,
        StageDisposition::Partial => 3,
        StageDisposition::Simulated => 4,
        StageDisposition::Skipped => 5,
        StageDisposition::Missing => 6,
        StageDisposition::Unavailable => 7,
        StageDisposition::Unknown => 8,
        StageDisposition::Stale => 9,
        StageDisposition::Conflicted => 10,
        StageDisposition::Failed => 11,
    }
}

fn mechanism_disposition(
    architecture_conflict: bool,
    has_gap: bool,
    obligations: &[ObligationAssessment],
) -> MechanismDisposition {
    if architecture_conflict {
        return MechanismDisposition::Deviated;
    }
    let dispositions = obligations
        .iter()
        .flat_map(|obligation| obligation.stages.iter().map(|stage| stage.disposition))
        .collect::<Vec<_>>();
    if dispositions.contains(&StageDisposition::Failed) {
        return MechanismDisposition::Blocked;
    }
    if dispositions.contains(&StageDisposition::Conflicted) {
        return MechanismDisposition::Conflicted;
    }
    if dispositions.contains(&StageDisposition::Stale) {
        return MechanismDisposition::Stale;
    }
    if dispositions.iter().any(|value| {
        matches!(
            value,
            StageDisposition::Unknown | StageDisposition::Unavailable
        )
    }) {
        return MechanismDisposition::Unknown;
    }
    if !obligations.is_empty()
        && obligations.iter().all(|obligation| {
            obligation
                .stages
                .iter()
                .all(|stage| stage.disposition == StageDisposition::NotApplicable)
        })
    {
        return MechanismDisposition::NotApplicable;
    }
    if !has_gap && obligations.iter().all(|obligation| obligation.complete) {
        MechanismDisposition::Supported
    } else {
        MechanismDisposition::Partial
    }
}

fn projection_disposition(
    input: &ImplementationBriefInput,
    mechanisms: &[MechanismAssessment],
    gaps: &[ImplementationGap],
) -> ImplementationBriefDisposition {
    if input.self_query.policy.cancellation_requested {
        return ImplementationBriefDisposition::Cancelled;
    }
    if input
        .self_query
        .policy
        .now_ms
        .zip(input.self_query.policy.deadline_ms)
        .is_some_and(|(now, deadline)| now >= deadline)
    {
        return ImplementationBriefDisposition::Bound;
    }
    if input.implementation_source.is_none() {
        return ImplementationBriefDisposition::NoSource;
    }
    if input
        .implementation_source
        .as_ref()
        .is_some_and(|source| source.status != ImplementationSourceStatus::Accepted)
        || input
            .self_query
            .source
            .as_ref()
            .is_none_or(|source| source.status != ArchitectureSourceStatus::Accepted)
    {
        return ImplementationBriefDisposition::Unsupported;
    }
    if gaps
        .iter()
        .any(|gap| gap.class == ImplementationGapClass::ArchitectureConflict)
        || mechanisms.iter().any(|mechanism| {
            matches!(
                mechanism.disposition,
                MechanismDisposition::Blocked
                    | MechanismDisposition::Deviated
                    | MechanismDisposition::Conflicted
            )
        })
    {
        return ImplementationBriefDisposition::Blocked;
    }
    if input.denominator.complete
        && gaps.is_empty()
        && mechanisms.iter().all(|mechanism| {
            matches!(
                mechanism.disposition,
                MechanismDisposition::Supported | MechanismDisposition::NotApplicable
            )
        })
        && input.self_query.preservation.overall().is_ok()
    {
        ImplementationBriefDisposition::Complete
    } else {
        ImplementationBriefDisposition::Partial
    }
}

const fn gap_class_for_stage(
    stage: ProofStage,
    disposition: StageDisposition,
) -> ImplementationGapClass {
    if matches!(disposition, StageDisposition::Conflicted) {
        return ImplementationGapClass::Conflict;
    }
    if matches!(disposition, StageDisposition::Stale) {
        return ImplementationGapClass::Stale;
    }
    if matches!(disposition, StageDisposition::Unknown) {
        return ImplementationGapClass::Unknown;
    }
    match stage {
        ProofStage::Source => ImplementationGapClass::Source,
        ProofStage::Compile => ImplementationGapClass::Compile,
        ProofStage::Unit | ProofStage::Property | ProofStage::Package => {
            ImplementationGapClass::Package
        }
        ProofStage::Integration => ImplementationGapClass::Integration,
        ProofStage::Edge => ImplementationGapClass::Edge,
        ProofStage::Runtime => ImplementationGapClass::Runtime,
        ProofStage::Product => ImplementationGapClass::Product,
        ProofStage::Release => ImplementationGapClass::Release,
    }
}

fn insert_gap(gaps: &mut BTreeMap<String, ImplementationGap>, gap: ImplementationGap) {
    gaps.entry(gap.gap_id.clone()).or_insert(gap);
}
