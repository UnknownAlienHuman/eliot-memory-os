use eliot_contracts::canonical_json_bytes;

use super::*;

#[test]
fn routing_owner_mismatch_is_rejected_after_resealing() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let mut decision = decide(&policy, &admitted, &draft, &boundary);
    {
        let candidate = match decision.candidate.as_mut() {
            Some(value) => value,
            None => panic!("candidate expected"),
        };
        candidate.routing = RoutingRecommendation::Human {
            principal: "human-1".to_owned(),
            decision_kind: HumanDecisionKind::Approval,
            authority_ref: "human-authority-1".to_owned(),
        };
        must(candidate.seal(&policy));
    }
    must(decision.seal(&policy));

    assert!(matches!(
        validate_clarification_decision(&decision, &policy),
        Err(ClarificationError::BindingMismatch { .. })
    ));
}

#[test]
fn candidate_id_must_bind_the_decision_input_digest() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let mut decision = decide(&policy, &admitted, &draft, &boundary);
    {
        let candidate = match decision.candidate.as_mut() {
            Some(value) => value,
            None => panic!("candidate expected"),
        };
        candidate.candidate_id = digest('9');
        must(candidate.seal(&policy));
    }
    must(decision.seal(&policy));

    assert_eq!(
        validate_clarification_decision(&decision, &policy),
        Err(ClarificationError::IdentityConflict)
    );
}

#[test]
fn each_finite_option_must_name_the_atomic_variable() {
    let (policy, admitted, draft, boundary) = valid_inputs();
    let mut decision = decide(&policy, &admitted, &draft, &boundary);
    {
        let candidate = match decision.candidate.as_mut() {
            Some(value) => value,
            None => panic!("candidate expected"),
        };
        let options = match &mut candidate.variable.answer_schema {
            AnswerSchema::Choice { options } => options,
            _ => panic!("choice schema expected"),
        };
        options[0].referenced_variables.clear();
        must(candidate.seal(&policy));
    }
    must(decision.seal(&policy));

    assert!(matches!(
        validate_clarification_decision(&decision, &policy),
        Err(ClarificationError::InvalidField { .. })
    ));
}

#[test]
fn materiality_evidence_must_be_retained_in_candidate_sources() {
    let policy = policy();
    let mut item = ambiguity(DecisionOwner::TaskLocalAgent);
    if let Some(materiality) = &mut item.materiality {
        materiality.evidence_refs = vec!["source-2".to_owned()];
    }
    let mut source_denominator = denominator();
    source_denominator
        .material_handles
        .push("source-2".to_owned());
    source_denominator.denominator_digest = must(source_denominator.identity_digest());
    let mut admitted = AdmittedClarificationJob {
        schema_version: CLARIFICATION_SCHEMA_VERSION,
        job: job(),
        ambiguities: vec![item],
        source_denominator,
        admission_digest: String::new(),
    };
    must(admitted.seal(&policy));

    assert!(matches!(
        propose_clarification(
            &admitted,
            &validated_draft(&admitted.job),
            &boundary(),
            &policy,
        ),
        Err(ClarificationError::BindingMismatch { .. })
    ));
}

#[test]
fn serialized_wire_size_is_bounded_not_only_semantic_preimage() {
    let (base_policy, admitted, draft, boundary) = valid_inputs();
    let decision = decide(&base_policy, &admitted, &draft, &boundary);
    let semantic_bytes = match usize::try_from(decision.output_bytes) {
        Ok(value) => value,
        Err(error) => panic!("semantic byte count does not fit usize: {error}"),
    };
    let wire_bytes = must(canonical_json_bytes(&decision)).len();
    assert!(wire_bytes > semantic_bytes);

    let mut tight_policy = base_policy;
    tight_policy.max_output_bytes = semantic_bytes.saturating_add(1);
    must(tight_policy.seal());

    assert!(matches!(
        propose_clarification(&admitted, &draft, &boundary, &tight_policy),
        Err(ClarificationError::LimitExceeded {
            field: "decision.serialized_output_bytes",
            ..
        })
    ));
}
