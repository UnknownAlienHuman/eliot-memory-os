#![allow(clippy::expect_used, clippy::unwrap_used)]

use super::{NegativeMemoryActionError, require_effect_ready};
use eliot_agent_contracts::AgentAttemptId;
use eliot_context_contracts::{
    ContextBinding, QUALITY_APPLICABILITY_INPUTS, QUALITY_DIMENSIONS,
    QUALITY_RESULT_SCHEMA_VERSION, QUALITY_SCORECARD_SCHEMA_VERSION, QualityApplicability,
    QualityDimension, QualityDimensionResult, QualityDimensionState, QualityOperation,
    QualityOutputBinding, QualityRefusalKind, QualityScorecard,
};
use eliot_contracts::{
    ArtifactId, DecisionId, EpochId, EpochLineageId, ResourceGeneration, StateFence, TaskId,
};
use eliot_receipts::{ProofCeiling, WorkScopeId};

#[test]
fn missing_scorecard_refuses_dependent_action() {
    assert_eq!(
        require_effect_ready(None),
        Err(NegativeMemoryActionError::QualityNotReady {
            operation: QualityOperation::DependentAction,
            kind: QualityRefusalKind::InvalidScorecard,
            blocking: Vec::new(),
            unresolved_applicability: Vec::new(),
        })
    );
}

#[test]
fn current_passing_scorecard_remains_ready() {
    let card = scorecard(None);
    card.validate()
        .expect("fixture is a structurally valid card");

    assert_eq!(require_effect_ready(Some(&card)), Ok(()));
}

#[test]
fn unknown_required_anchor_is_returned_as_the_blocker() {
    let card = scorecard(Some(QualityDimension::ExactAnchorProvenanceCoverage));
    card.validate()
        .expect("unknown grade is structurally valid");

    let refusal = require_effect_ready(Some(&card)).expect_err("unknown anchor blocks effect");
    let NegativeMemoryActionError::QualityNotReady {
        operation,
        kind,
        blocking,
        unresolved_applicability,
    } = refusal
    else {
        panic!("expected typed scorecard refusal");
    };

    assert_eq!(operation, QualityOperation::DependentAction);
    assert_eq!(kind, QualityRefusalKind::OperationBlocked);
    assert!(unresolved_applicability.is_empty());
    assert_eq!(blocking.len(), 1);
    assert_eq!(
        blocking[0].dimension,
        QualityDimension::ExactAnchorProvenanceCoverage
    );
    assert_eq!(blocking[0].state, QualityDimensionState::Unknown);
    assert_eq!(
        blocking[0].unknown_evidence,
        vec![artifact("missing-anchor")]
    );
}

fn scorecard(unknown_dimension: Option<QualityDimension>) -> QualityScorecard {
    let binding = binding();
    let results = QUALITY_DIMENSIONS
        .into_iter()
        .map(|dimension| {
            let is_unknown = Some(dimension) == unknown_dimension;
            let evidence = artifact("quality-evidence");
            QualityDimensionResult {
                schema_version: QUALITY_RESULT_SCHEMA_VERSION,
                dimension,
                state: if is_unknown {
                    QualityDimensionState::Unknown
                } else {
                    QualityDimensionState::Passed
                },
                rule_revision: artifact("rule-revision"),
                required_evidence: vec![if is_unknown {
                    artifact("missing-anchor")
                } else {
                    evidence.clone()
                }],
                evidence: if is_unknown {
                    Vec::new()
                } else {
                    vec![evidence]
                },
                measurements: Vec::new(),
                failed_invariant: None,
                unknown_evidence: if is_unknown {
                    vec![artifact("missing-anchor")]
                } else {
                    Vec::new()
                },
                proof_ceiling: ProofCeiling::Observation,
                invalidation: None,
                binding: binding.clone(),
            }
        })
        .collect();

    QualityScorecard {
        schema_version: QUALITY_SCORECARD_SCHEMA_VERSION,
        binding,
        output: QualityOutputBinding {
            recipe_digest: digest(),
            fence_digest: digest(),
            admitted_digest: digest(),
            rendered_digest: digest(),
            serializer_id: "serde-json".to_owned(),
            serializer_version: "1".to_owned(),
            serializer_options_digest: digest(),
            route_id: "route".to_owned(),
            evidence_revisions: Vec::new(),
            omission_handles: Vec::new(),
        },
        applicability: QualityApplicability {
            resolved: QUALITY_APPLICABILITY_INPUTS.to_vec(),
            unknown: Vec::new(),
        },
        results,
    }
}

fn binding() -> ContextBinding {
    ContextBinding {
        task_id: TaskId::new("task").expect("fixture task"),
        attempt_id: AgentAttemptId::new("attempt").expect("fixture attempt"),
        scope_id: WorkScopeId::new("scope").expect("fixture scope"),
        state_fence: StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture lineage"),
                std::num::NonZeroU64::new(1).expect("nonzero epoch"),
            )
            .expect("fixture epoch"),
            ResourceGeneration::new(1).expect("fixture generation"),
        ),
        decision_id: DecisionId::new("decision").expect("fixture decision"),
        operation_id: None,
    }
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture artifact handle")
}

fn digest() -> String {
    "a".repeat(64)
}
