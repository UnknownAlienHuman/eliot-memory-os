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
    fn new(maximum: u64) -> Self {
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

/// Produces the pure, candidate-only Implementation self-query projection.
#[expect(
    clippy::too_many_lines,
    reason = "explicit accounting keeps source, denominator, evidence, gaps, and proof stages auditable"
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
        .map(|mechanism| (mechanism.mechanism_id.as_str(), mechanism))
        .collect::<BTreeMap<_, _>>();
    let obligations = input
        .obligations
        .iter()
        .map(|obligation| (obligation.obligation_id.as_str(), obligation))
        .collect::<BTreeMap<_, _>>();
    let statement_map = input
        .implementation_source
        .as_ref()
        .map(|source| {
            source
                .statements
                .iter()
                .map(|statement| (statement.statement_id.as_str(), statement))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let architecture_ids = input
        .self_query
        .anchors
        .iter()
        .map(|anchor| anchor.anchor_id.as_str())
        .collect::<BTreeSet<_>>();

    let mut gaps = BTreeMap::<String, ImplementationGap>::new();
    let mut assessments = Vec::with_capacity(input.denominator.mechanism_ids.len());
    for mechanism_id in &input.denominator.mechanism_ids {
        meter.charge()?;
        assessments.push(assess_mechanism(
            input,
            mechanism_id,
            mechanisms.get(mechanism_id.as_str()).copied(),
            &obligations,
            &support_rows,
            &statement_map,
            &architecture_ids,
            &mut gaps,
            &mut meter,
        )?);
    }

    let actual_obligations = input
        .obligations
        .iter()
        .map(|value| value.obligation_id.as_str())
        .collect::<BTreeSet<_>>();
    for obligation_id in &input.denominator.obligation_ids {
        meter.charge()?;
        if !actual_obligations.contains(obligation_id.as_str()) {
            insert_gap(
                &mut gaps,
                ImplementationGap {
                    gap_id: format!("gap:obligation:{obligation_id}"),
                    class: ImplementationGapClass::Coverage,
                    owner: "implementation-denominator".to_owned(),
                    mechanism_id: None,
                    obligation_id: Some(obligation_id.clone()),
                    stage: None,
                    detail: "expected obligation is absent from the supplied closure".to_owned(),
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
    for evidence_id in &input.denominator.evidence_ids {
        meter.charge()?;
        if !actual_evidence.contains(evidence_id.as_str()) {
            insert_gap(
                &mut gaps,
                ImplementationGap {
                    gap_id: format!("gap:evidence:{evidence_id}"),
                    class: ImplementationGapClass::Coverage,
                    owner: "implementation-denominator".to_owned(),
                    mechanism_id: None,
                    obligation_id: None,
                    stage: None,
                    detail: "expected evidence is absent from the supplied closure".to_owned(),
                    evidence_refs: Vec::new(),
                },
            );
        }
    }

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

    let mut gaps = gaps.into_values().collect::<Vec<_>>();
    gaps.sort_by(|left, right| left.gap_id.cmp(&right.gap_id));
    assessments.sort_by(|left, right| left.mechanism_id.cmp(&right.mechanism_id));

    let disposition = projection_disposition(input, &assessments, &gaps);
    let job = &input.self_query.validated_candidate.job;
    let state_fence_digest = canonical_json_bytes(&job.state_fence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ImplementationBriefError::Encoding {
            field: "projection.state_fence_digest",
        })?;
    let architecture_source_handle = input
        .self_query
        .source
        .as_ref()
        .map(|source| source.source_handle.as_str().to_owned());
    let architecture_source_digest = input
        .self_query
        .source
        .as_ref()
        .map(|source| source.digest.clone());
    let implementation_source_handle = input
        .implementation_source
        .as_ref()
        .map(|source| source.source_handle.clone());
    let implementation_source_digest = input
        .implementation_source
        .as_ref()
        .map(|source| source.source_digest.clone());
    let implementation_source_status = input
        .implementation_source
        .as_ref()
        .map(|source| source.status);

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
        architecture_source_handle,
        architecture_source_digest,
        implementation_source_handle,
        implementation_source_digest,
        implementation_source_status,
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

    let maximum = usize::try_from(
        input
            .self_query
            .policy
            .max_output_bytes
            .min(MAX_WIRE_BYTES as u64),
    )
    .unwrap_or(MAX_WIRE_BYTES);
    let mut stable = false;
    for _ in 0..16 {
        projection.output_digest = projection.compute_output_digest()?;
        let measured = bounded_canonical_size(&projection, maximum, "projection.output_wire")?;
        let measured = u64::try_from(measured).unwrap_or(u64::MAX);
        if projection.total_output_bytes == measured {
            stable = true;
            break;
        }
        projection.total_output_bytes = measured;
    }
    if !stable {
        return Err(ImplementationBriefError::BindingMismatch {
            field: "projection.total_output_bytes",
        });
    }
    projection.output_digest = projection.compute_output_digest()?;
    let final_size = bounded_canonical_size(&projection, maximum, "projection.output_wire")?;
    if u64::try_from(final_size).unwrap_or(u64::MAX) != projection.total_output_bytes {
        return Err(ImplementationBriefError::BindingMismatch {
            field: "projection.total_output_bytes",
        });
    }
    projection.validate()?;
    Ok(projection)
}

impl ImplementationBriefProjection {
    /// Reprojects the exact input and rejects every changed same-identity field.
    pub fn validate_against(
        &self,
        input: &ImplementationBriefInput,
    ) -> Result<(), ImplementationBriefError> {
        self.validate()?;
        let expected = project_implementation_brief(input)?;
        if &expected != self {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "projection.input_binding",
            });
        }
        Ok(())
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "all authority-separated indexes are explicit projection inputs"
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
                detail: "expected mechanism is absent from the supplied closure".to_owned(),
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
            disposition: MechanismDisposition::Absent,
        });
    };

    let initial_gap_count = gaps.len();
    let mut architecture_conflict = false;
    for architecture_ref in &mechanism.architecture_refs {
        meter.charge()?;
        if !architecture_ids.contains(architecture_ref.as_str()) {
            insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!(
                        "gap:{}:architecture:{}",
                        mechanism.mechanism_id, architecture_ref
                    ),
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
    for statement_ref in &mechanism.statement_refs {
        meter.charge()?;
        match statements.get(statement_ref.as_str()) {
            None => insert_gap(
                gaps,
                ImplementationGap {
                    gap_id: format!(
                        "gap:{}:statement:{}",
                        mechanism.mechanism_id, statement_ref
                    ),
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
                            "gap:{}:architecture-conflict:{}",
                            mechanism.mechanism_id, statement_ref
                        ),
                        class: ImplementationGapClass::ArchitectureConflict,
                        owner: "architecture-precedence-owner".to_owned(),
                        mechanism_id: Some(mechanism.mechanism_id.clone()),
                        obligation_id: None,
                        stage: None,
                        detail: "Implementation statement conflicts with governing Architecture"
                            .to_owned(),
                        evidence_refs: Vec::new(),
                    },
                );
            }
            Some(statement) if statement.alignment == ArchitectureAlignment::Unknown => {
                insert_gap(
                    gaps,
                    ImplementationGap {
                        gap_id: format!(
                            "gap:{}:architecture-unknown:{}",
                            mechanism.mechanism_id, statement_ref
                        ),
                        class: ImplementationGapClass::Unknown,
                        owner: "architecture-precedence-owner".to_owned(),
                        mechanism_id: Some(mechanism.mechanism_id.clone()),
                        obligation_id: None,
                        stage: None,
                        detail: "Architecture alignment is unknown".to_owned(),
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

    let new_gaps = gaps.len() > initial_gap_count;
    let disposition = mechanism_disposition(
        architecture_conflict,
        new_gaps,
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

#[expect(
    clippy::too_many_arguments,
    reason = "the obligation assessment keeps all evidence and owner joins explicit"
)]
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
        let gap_id = format!(
            "gap:{}:obligation:{}",
            mechanism.mechanism_id, obligation_id
        );
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

    let mut stage_assessments = Vec::with_capacity(obligation.required_stages.len());
    let mut obligation_gap_ids = Vec::new();
    for stage in &obligation.required_stages {
        meter.charge()?;
        let mut matching = input
            .evidence
            .iter()
            .filter(|evidence| {
                evidence.obligation_id == obligation.obligation_id && evidence.stage == *stage
            })
            .collect::<Vec<_>>();
        matching.sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
        let mut snapshots = Vec::new();
        let mut dispositions = Vec::new();
        if matching.is_empty() {
            dispositions.push(StageDisposition::Missing);
        }
        for evidence in matching {
            meter.charge()?;
            let Some(row) = support_rows.get(evidence.support_claim_ref.as_str()).copied() else {
                let gap_id = format!(
                    "gap:{}:{}:{stage:?}:support-row",
                    mechanism.mechanism_id, obligation.obligation_id
                )
                .to_ascii_lowercase();
                obligation_gap_ids.push(gap_id.clone());
                insert_gap(
                    gaps,
                    ImplementationGap {
                        gap_id,
                        class: ImplementationGapClass::Contract,
                        owner: obligation.owner.clone(),
                        mechanism_id: Some(mechanism.mechanism_id.clone()),
                        obligation_id: Some(obligation.obligation_id.clone()),
                        stage: Some(*stage),
                        detail: "evidence references a missing support claim".to_owned(),
                        evidence_refs: vec![evidence.evidence_id.clone()],
                    },
                );
                dispositions.push(StageDisposition::Missing);
                continue;
            };
            snapshots.push(EvidenceAxisSnapshot::from_parts(evidence, row));
            dispositions.push(evidence_disposition(evidence, row));
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
            obligation_gap_ids.push(gap_id.clone());
            let evidence_refs = snapshots
                .iter()
                .map(|snapshot| snapshot.evidence_id.clone())
                .collect();
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
                    evidence_refs,
                },
            );
        }
        stage_assessments.push(StageAssessment {
            stage: *stage,
            disposition,
            evidence: snapshots,
        });
    }
    obligation_gap_ids.sort();
    obligation_gap_ids.dedup();
    let complete = stage_assessments
        .iter()
        .all(|stage| stage_is_complete(stage.disposition))
        && obligation_gap_ids.is_empty();
    Ok(ObligationAssessment {
        obligation_id: obligation.obligation_id.clone(),
        mechanism_id: obligation.mechanism_id.clone(),
        owner: obligation.owner.clone(),
        required_domains: obligation.required_domains.clone(),
        stages: stage_assessments,
        gap_ids: obligation_gap_ids,
        complete,
    })
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
        EvidenceVerdict::Conflicted | EvidenceVerdict::Passed => {}
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
            obligation.stages.iter().all(|stage| {
                stage.disposition == StageDisposition::NotApplicable
            })
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
        ProofStage::Package => ImplementationGapClass::Package,
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
