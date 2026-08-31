use eliot_contracts::{AuthorityEpoch, RequestId, ResourceGeneration, StateFence};
use eliot_protocol::{
    AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID, AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket,
    AgentActivationSelectionDirective, ProtocolError,
};

const RESOLVED_AT_UNIX_MS: u64 = 9_000;

fn ticket() -> Result<AgentActivationResolutionTicket, ProtocolError> {
    AgentActivationResolutionTicket {
        wire_id: AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "activation-scope-ticket-v2-1".to_owned(),
        activation_request_id: RequestId::new("activation-scope-request-v2-1")?,
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: "activation-scope-connection-v2-1".to_owned(),
        state_fence: StateFence::new(AuthorityEpoch::new(7)?, ResourceGeneration::new(11)?),
        kernel_deadline_unix_ms: 10_000,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
}

#[test]
fn complete_empty_scope_set_is_selection_required_not_ambiguity() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    AgentActivationResolutionResult::new(
        &ticket,
        RESOLVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::ScopeSelectionRequired {
            selection: AgentActivationSelectionDirective {
                candidate_handles: Vec::new(),
                candidate_coverage: AgentActivationCandidateCoverage::Complete,
                recovery_handle: "eliot://recovery/scope-intake".to_owned(),
            },
        },
    )?;

    let ambiguous = AgentActivationResolutionResult::new(
        &ticket,
        RESOLVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::ScopeAmbiguous {
            selection: AgentActivationSelectionDirective {
                candidate_handles: Vec::new(),
                candidate_coverage: AgentActivationCandidateCoverage::Complete,
                recovery_handle: "eliot://recovery/select-scope".to_owned(),
            },
        },
    );
    assert!(ambiguous.is_err());
    Ok(())
}

#[test]
fn scope_ambiguity_requires_two_exact_candidates() -> Result<(), ProtocolError> {
    let ticket = ticket()?;
    for candidate_handles in [Vec::new(), vec!["eliot://scope/one".to_owned()]] {
        let result = AgentActivationResolutionResult::new(
            &ticket,
            RESOLVED_AT_UNIX_MS,
            AgentActivationResolutionDisposition::ScopeAmbiguous {
                selection: AgentActivationSelectionDirective {
                    candidate_handles,
                    candidate_coverage: AgentActivationCandidateCoverage::Complete,
                    recovery_handle: "eliot://recovery/select-scope".to_owned(),
                },
            },
        );
        assert!(result.is_err());
    }

    AgentActivationResolutionResult::new(
        &ticket,
        RESOLVED_AT_UNIX_MS,
        AgentActivationResolutionDisposition::ScopeAmbiguous {
            selection: AgentActivationSelectionDirective {
                candidate_handles: vec![
                    "eliot://scope/one".to_owned(),
                    "eliot://scope/two".to_owned(),
                ],
                candidate_coverage: AgentActivationCandidateCoverage::Complete,
                recovery_handle: "eliot://recovery/select-scope".to_owned(),
            },
        },
    )?;
    Ok(())
}
