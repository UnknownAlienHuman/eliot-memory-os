use eliot_contracts::{
    EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence, canonical_json_bytes,
    sha256_hex,
};
use eliot_protocol::{
    AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION,
    AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationOwnerEvidence,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResolvedBinding, AgentActivationResultSubmit,
    AgentActivationRetryDirective, AgentActivationSelectionDirective,
    MAX_AGENT_ACTIVATION_CANDIDATES, ProtocolError, decode_agent_activation_result_submit,
};
use serde_json::Value;

const RESOLVED_AT_UNIX_MS: u64 = 9_000;

fn test_epoch(sequence: u64) -> EpochId {
    {
        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("lineage");
        };
        let Some(sequence) = std::num::NonZeroU64::new(sequence) else {
            panic!("sequence");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("epoch");
        };
        epoch
    }
}

fn ticket() -> Result<AgentActivationResolutionTicket, ProtocolError> {
    AgentActivationResolutionTicket {
        wire_id: AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "activation-ticket-v2-1".to_owned(),
        activation_request_id: RequestId::new("activation-request-v2-1")?,
        demand_id: "activation-demand-v2-1".to_owned(),
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-connection-v2-1".to_owned(),
        cancellation_id: "activation-cancellation-v2-1".to_owned(),
        state_fence: StateFence::new(test_epoch(7), ResourceGeneration::new(11)?),
        kernel_deadline_unix_ms: 10_000,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
}

fn binding() -> AgentActivationResolvedBinding {
    AgentActivationResolvedBinding {
        principal_id: "principal-1".to_owned(),
        session_id: "session-1".to_owned(),
        task_id: "task-1".to_owned(),
        work_unit_id: "work-unit-1".to_owned(),
        work_scope_id: "work-scope-1".to_owned(),
        task_revision: "task-revision-1".to_owned(),
        plan_id: "plan-1".to_owned(),
        plan_revision: "plan-revision-1".to_owned(),
    }
}

fn task_selection() -> AgentActivationSelectionDirective {
    AgentActivationSelectionDirective {
        candidate_handles: vec!["eliot://task/task-1".to_owned()],
        candidate_coverage: AgentActivationCandidateCoverage::Complete,
        recovery_handle: "eliot://recovery/select-task-1".to_owned(),
    }
}

fn dispositions(
    ticket: &AgentActivationResolutionTicket,
) -> Result<Vec<AgentActivationResolutionDisposition>, ProtocolError> {
    Ok(vec![
        AgentActivationResolutionDisposition::Resolved {
            binding: Box::new(binding()),
        },
        AgentActivationResolutionDisposition::TaskSelectionRequired {
            selection: task_selection(),
        },
        AgentActivationResolutionDisposition::ScopeSelectionRequired {
            selection: task_selection(),
        },
        AgentActivationResolutionDisposition::ScopeAmbiguous {
            selection: AgentActivationSelectionDirective {
                candidate_handles: vec![
                    "eliot://scope/scope-1".to_owned(),
                    "eliot://scope/scope-2".to_owned(),
                ],
                candidate_coverage: AgentActivationCandidateCoverage::Complete,
                recovery_handle: "eliot://recovery/select-scope-1".to_owned(),
            },
        },
        AgentActivationResolutionDisposition::NotReady {
            recovery_handle: "eliot://recovery/governor-not-ready-1".to_owned(),
            retry: AgentActivationRetryDirective {
                dependency_ref: "governor-owner-set".to_owned(),
                observed_dependency_revision: "revision-7".to_owned(),
                not_before_unix_ms: ticket.kernel_deadline_unix_ms - 1,
            },
        },
        AgentActivationResolutionDisposition::StaleFence {
            recovery_handle: "eliot://recovery/stale-fence-1".to_owned(),
            observed_state_fence: Some(StateFence::new(
                test_epoch(8),
                ResourceGeneration::new(11)?,
            )),
        },
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/activation-resolution-1".to_owned(),
        },
    ])
}

fn result(
    ticket: &AgentActivationResolutionTicket,
    disposition: AgentActivationResolutionDisposition,
) -> Result<AgentActivationResolutionResult, ProtocolError> {
    AgentActivationResolutionResult::new(ticket, RESOLVED_AT_UNIX_MS, disposition)
}

#[test]
fn every_disposition_round_trips_and_binds_exact_ticket() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    for disposition in dispositions(&ticket)? {
        let result = result(&ticket, disposition)?;
        result.validate_against(&ticket)?;
        let encoded =
            serde_json::to_vec(&result).map_err(|error| ProtocolError::Json(error.to_string()))?;
        let decoded: AgentActivationResolutionResult = serde_json::from_slice(&encoded)
            .map_err(|error| ProtocolError::Json(error.to_string()))?;
        assert_eq!(decoded, result);
        decoded.validate_against(&ticket)?;
    }
    Ok(())
}

#[test]
fn complete_empty_task_candidate_set_represents_no_active_binding() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    result(
        &ticket,
        AgentActivationResolutionDisposition::TaskSelectionRequired {
            selection: AgentActivationSelectionDirective {
                candidate_handles: Vec::new(),
                candidate_coverage: AgentActivationCandidateCoverage::Complete,
                recovery_handle: "eliot://recovery/task-intake".to_owned(),
            },
        },
    )?;
    Ok(())
}

#[test]
fn candidate_coverage_and_scope_ambiguity_are_fail_closed() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    for selection in [
        AgentActivationSelectionDirective {
            candidate_handles: vec!["eliot://task/one".to_owned()],
            candidate_coverage: AgentActivationCandidateCoverage::Unknown,
            recovery_handle: "eliot://recovery/select-task".to_owned(),
        },
        AgentActivationSelectionDirective {
            candidate_handles: Vec::new(),
            candidate_coverage: AgentActivationCandidateCoverage::Partial,
            recovery_handle: "eliot://recovery/select-task".to_owned(),
        },
    ] {
        assert!(
            result(
                &ticket,
                AgentActivationResolutionDisposition::TaskSelectionRequired { selection },
            )
            .is_err()
        );
    }

    for selection in [
        AgentActivationSelectionDirective {
            candidate_handles: Vec::new(),
            candidate_coverage: AgentActivationCandidateCoverage::Complete,
            recovery_handle: "eliot://recovery/select-scope".to_owned(),
        },
        AgentActivationSelectionDirective {
            candidate_handles: vec!["eliot://scope/one".to_owned()],
            candidate_coverage: AgentActivationCandidateCoverage::Complete,
            recovery_handle: "eliot://recovery/select-scope".to_owned(),
        },
        AgentActivationSelectionDirective {
            candidate_handles: Vec::new(),
            candidate_coverage: AgentActivationCandidateCoverage::Unknown,
            recovery_handle: "eliot://recovery/select-scope".to_owned(),
        },
    ] {
        assert!(
            result(
                &ticket,
                AgentActivationResolutionDisposition::ScopeAmbiguous { selection },
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn wire_identity_is_exact() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let result = result(
        &ticket,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/activation-resolution".to_owned(),
        },
    )?;
    assert_eq!(result.wire_id, AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_ID);
    assert_eq!(
        result.wire_version,
        AGENT_ACTIVATION_RESOLUTION_RESULT_WIRE_VERSION
    );
    Ok(())
}

#[test]
fn not_ready_retry_must_be_future_and_before_ticket_expiry() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let valid = AgentActivationRetryDirective {
        dependency_ref: "governor-owner-set".to_owned(),
        observed_dependency_revision: "revision-7".to_owned(),
        not_before_unix_ms: RESOLVED_AT_UNIX_MS + 1,
    };
    result(
        &ticket,
        AgentActivationResolutionDisposition::NotReady {
            recovery_handle: "eliot://recovery/not-ready".to_owned(),
            retry: valid.clone(),
        },
    )?;

    for retry in [
        AgentActivationRetryDirective {
            dependency_ref: String::new(),
            ..valid.clone()
        },
        AgentActivationRetryDirective {
            observed_dependency_revision: String::new(),
            ..valid.clone()
        },
        AgentActivationRetryDirective {
            not_before_unix_ms: 0,
            ..valid.clone()
        },
        AgentActivationRetryDirective {
            not_before_unix_ms: RESOLVED_AT_UNIX_MS,
            ..valid.clone()
        },
        AgentActivationRetryDirective {
            not_before_unix_ms: ticket.kernel_deadline_unix_ms,
            ..valid.clone()
        },
        AgentActivationRetryDirective {
            not_before_unix_ms: ticket.kernel_deadline_unix_ms + 1,
            ..valid
        },
    ] {
        assert!(
            result(
                &ticket,
                AgentActivationResolutionDisposition::NotReady {
                    recovery_handle: "eliot://recovery/not-ready".to_owned(),
                    retry,
                },
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn result_observation_must_precede_ticket_expiry() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    for observed_at in [
        0,
        ticket.kernel_deadline_unix_ms,
        ticket.kernel_deadline_unix_ms + 1,
    ] {
        let result = AgentActivationResolutionResult::new(
            &ticket,
            observed_at,
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "eliot://failure/activation-resolution".to_owned(),
            },
        );
        assert!(result.is_err());
    }
    Ok(())
}

#[test]
fn ticket_identity_digest_fence_and_result_digest_substitution_fail() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let result = result(
        &ticket,
        AgentActivationResolutionDisposition::TaskSelectionRequired {
            selection: task_selection(),
        },
    )?;

    let mut other_id = result.clone();
    other_id.ticket_id = "activation-ticket-other".to_owned();
    other_id = other_id.with_computed_digest()?;
    assert!(other_id.validate_against(&ticket).is_err());

    let mut other_digest = result.clone();
    other_digest.ticket_sha256 = "f".repeat(64);
    other_digest = other_digest.with_computed_digest()?;
    assert!(other_digest.validate_against(&ticket).is_err());

    let mut other_fence = result.clone();
    other_fence.ticket_state_fence = StateFence::new(test_epoch(8), ResourceGeneration::new(11)?);
    other_fence = other_fence.with_computed_digest()?;
    assert!(other_fence.validate_against(&ticket).is_err());

    let mut tampered = result;
    tampered.result_sha256 = "e".repeat(64);
    assert!(tampered.validate().is_err());
    Ok(())
}

#[test]
fn candidate_sets_reject_duplicate_oversized_and_excessive_handles() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    for candidate_handles in [
        vec!["eliot://task/one".to_owned(), "eliot://task/one".to_owned()],
        vec!["x".repeat(513)],
        (0..=MAX_AGENT_ACTIVATION_CANDIDATES)
            .map(|index| format!("eliot://task/{index}"))
            .collect(),
    ] {
        assert!(
            result(
                &ticket,
                AgentActivationResolutionDisposition::TaskSelectionRequired {
                    selection: AgentActivationSelectionDirective {
                        candidate_handles,
                        candidate_coverage: AgentActivationCandidateCoverage::Complete,
                        recovery_handle: "eliot://recovery/select-task".to_owned(),
                    },
                },
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn stale_fence_cannot_repeat_ticket_fence() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    assert!(
        result(
            &ticket,
            AgentActivationResolutionDisposition::StaleFence {
                recovery_handle: "eliot://recovery/stale-fence".to_owned(),
                observed_state_fence: Some(ticket.state_fence.clone()),
            },
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn unknown_fields_are_rejected() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let result = result(
        &ticket,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/activation-resolution".to_owned(),
        },
    )?;
    let mut unknown =
        serde_json::to_value(&result).map_err(|error| ProtocolError::Json(error.to_string()))?;
    unknown["unexpected"] = Value::Bool(true);
    assert!(serde_json::from_value::<AgentActivationResolutionResult>(unknown).is_err());

    let mut unknown_disposition =
        serde_json::to_value(&result).map_err(|error| ProtocolError::Json(error.to_string()))?;
    unknown_disposition["disposition"]["unexpected"] = Value::Bool(true);
    assert!(
        serde_json::from_value::<AgentActivationResolutionResult>(unknown_disposition).is_err()
    );
    Ok(())
}

#[test]
fn resolved_projection_contains_no_kernel_activation_authority_fields() -> Result<(), ProtocolError>
{
    let value =
        serde_json::to_value(binding()).map_err(|error| ProtocolError::Json(error.to_string()))?;
    let object = value.as_object().ok_or(ProtocolError::InvalidField {
        field: "agent_activation_resolution_result.binding",
        reason: "test binding must serialize as an object",
    })?;
    for forbidden in [
        "activation_generation",
        "activation_fence",
        "authority_epoch",
        "capability",
        "effect",
        "nonce",
    ] {
        assert!(!object.contains_key(forbidden));
    }
    Ok(())
}

#[test]
fn resolved_owner_evidence_binds_exact_binding_and_ticket_fence() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let exact_binding = binding();
    let result = AgentActivationResolutionResult::new_with_owner_evidence(
        &ticket,
        RESOLVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::Resolved {
            binding: Box::new(exact_binding.clone()),
        },
        17,
    )?;
    let evidence = result
        .owner_evidence
        .as_ref()
        .ok_or(ProtocolError::InvalidField {
            field: "test.owner_evidence",
            reason: "Resolved must carry owner evidence",
        })?;
    evidence.validate_against_binding(&exact_binding, &ticket.state_fence)?;
    assert_eq!(evidence.binding.as_ref(), &exact_binding);
    assert_eq!(evidence.owner_revision, 17);

    let mut changed_binding = exact_binding;
    changed_binding.task_revision = "task-revision-2".to_owned();
    let mut rebound = result.clone();
    if let AgentActivationResolutionDisposition::Resolved { binding } = &mut rebound.disposition {
        *binding = Box::new(changed_binding);
    }
    let rebound = rebound.with_computed_digest()?;
    assert!(rebound.validate_against(&ticket).is_err());

    let mut missing = result;
    missing.owner_evidence = None;
    let missing = missing.with_computed_digest()?;
    assert!(missing.validate_against(&ticket).is_err());
    Ok(())
}

#[test]
fn negative_dispositions_reject_owner_evidence() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let mut result = result(
        &ticket,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/activation-resolution".to_owned(),
        },
    )?;
    result.owner_evidence = Some(AgentActivationOwnerEvidence::for_binding(
        &binding(),
        1,
        ticket.state_fence.clone(),
    )?);
    let result = result.with_computed_digest()?;
    assert!(result.validate_against(&ticket).is_err());
    Ok(())
}

#[test]
fn strict_v2_decoder_rejects_bare_unknown_and_legacy_shapes() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let result = result(
        &ticket,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/activation-resolution".to_owned(),
        },
    )?;
    let submit = AgentActivationResultSubmit::new(result)?;
    let encoded =
        serde_json::to_value(&submit).map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert_eq!(decode_agent_activation_result_submit(&encoded)?, submit);

    let mut unknown_outer = encoded.clone();
    unknown_outer["unexpected"] = Value::Bool(true);
    assert!(decode_agent_activation_result_submit(&unknown_outer).is_err());

    let mut unknown_inner = encoded;
    unknown_inner["result"]["unexpected"] = Value::Bool(true);
    assert!(decode_agent_activation_result_submit(&unknown_inner).is_err());

    let bare_result = serde_json::to_value(&submit.result)
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    assert!(decode_agent_activation_result_submit(&bare_result).is_err());
    assert!(
        decode_agent_activation_result_submit(&serde_json::json!({
            "operation": "agent_activation_submit",
            "decision": Value::Null,
        }))
        .is_err()
    );
    Ok(())
}

#[test]
fn historical_v1_is_explicitly_importable_but_not_v2_compatible() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    let mut historical = serde_json::json!({
        "wire_id": "eliot.protocol.agent-activation-resolution-decision",
        "wire_version": 1,
        "ticket_id": ticket.ticket_id.clone(),
        "ticket_sha256": ticket.ticket_sha256.clone(),
        "state_fence": ticket.state_fence.clone(),
        "principal_id": "principal-1",
        "session_id": "session-1",
        "task_id": "task-1",
        "work_unit_id": "work-unit-1",
        "work_scope_id": "work-scope-1",
        "task_revision": "task-revision-1",
        "plan_id": "plan-1",
        "plan_revision": "plan-revision-1",
        "decision_sha256": "",
    });
    let unsigned = canonical_json_bytes(&historical)
        .map_err(|error| ProtocolError::Json(error.to_string()))?;
    historical["decision_sha256"] = Value::String(sha256_hex(&unsigned));
    let bytes =
        serde_json::to_vec(&historical).map_err(|error| ProtocolError::Json(error.to_string()))?;
    let imported =
        eliot_protocol::activation_resolution_v1::decode_activation_resolution_v1_import(&bytes)?;
    imported.validate_against(&ticket)?;
    assert!(decode_agent_activation_result_submit(&historical).is_err());
    Ok(())
}

#[test]
fn successor_ticket_requires_due_time_and_changed_named_dependency() -> Result<(), ProtocolError> {
    let predecessor = ticket()?;
    let predecessor_result = result(
        &predecessor,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/predecessor".to_owned(),
        },
    )?;
    let mut successor = ticket()?;
    successor.ticket_id = "activation-ticket-successor".to_owned();
    successor.successor_of = Some(eliot_protocol::AgentActivationTicketPredecessor {
        predecessor_ticket_id: predecessor.ticket_id.clone(),
        predecessor_ticket_sha256: predecessor.ticket_sha256.clone(),
        predecessor_result_sha256: predecessor_result.result_sha256.clone(),
        dependency_ref: "governor.readiness".to_owned(),
        observed_dependency_revision: "1:Starting".to_owned(),
        not_before_unix_ms: 5_000,
    });
    successor = successor.with_computed_digest()?;

    let fresh = AgentActivationResolutionResult::new_for_successor(
        &successor,
        RESOLVED_AT_UNIX_MS + 1,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "eliot://failure/successor".to_owned(),
        },
        7,
        "1:Ready",
    )?;
    fresh.validate_against(&successor)?;
    assert_eq!(
        fresh
            .dependency_observation
            .as_ref()
            .map(|observation| observation.observed_dependency_revision.as_str()),
        Some("1:Ready")
    );
    assert!(
        AgentActivationResolutionResult::new_for_successor(
            &successor,
            RESOLVED_AT_UNIX_MS + 1,
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "eliot://failure/unchanged".to_owned(),
            },
            7,
            "1:Starting",
        )
        .is_err()
    );
    assert!(
        AgentActivationResolutionResult::new_for_successor(
            &successor,
            4_999,
            AgentActivationResolutionDisposition::FailedInternal {
                failure_handle: "eliot://failure/early".to_owned(),
            },
            7,
            "1:Ready",
        )
        .is_err()
    );
    Ok(())
}
