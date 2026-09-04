//! Read-only activation resolution projection.
//!
//! The v2 chain below is complete and covered by this module's tests, but
//! `map_resolved_snapshot_to_protocol` has no caller in the daemon path yet,
//! so the whole chain reads as dead code. It is production code awaiting its
//! caller, not test scaffolding, so it is not `#[cfg(test)]`.
//!
//! # Architecture
//! - **A2.3 Modular architecture** — bounded pure projection cell; no new runtime/process/failure boundary.
//! - **A13.2 Kernel and failure domains** — Kernel remains sole authority/fencing owner; this projection only reads the admitted Governor snapshot.
//! - **A13.10 Observability and Diagnostic Brief** — decision is a derived projection/receipt; it does not prove a transition.
//! - **ARCH-MOD-02 Depth is additive and micro-modular** — extracted as independently understandable/testable/replaceable capability cell; size and physical form remain empirical.
//!
//! # Implementation
//! - **I1.11 Startup algorithm** — resolution is available only after Governor/Kernel admission; no startup authority issuance here.
//! - **I2.1 Crate-rich extraction of a capability behind an owned contract** — pure contract/test seam justifies isolated module; no placeholder proliferation.
//! - **I2.23 Capability-family topology and crate extraction decisions** — Governor task/authority/canonical-transition family; validated via `CrateExtractionDecision`.
//! - **Semantic-grant handle: `eliot_governor::GovernorActivationSnapshot` / `eliot_protocol::AgentActivationResolutionTicket` -> `eliot_protocol::AgentActivationResolutionDecision` via `GovernorComposition::read_unique_agent_activation`** — Kernel-issued ticket resolved against the current Governor owner set.
//! - **Wave 2 Governor-internal outcome -> protocol v2**: `eliot_governor::GovernorActivationOutcome` -> `eliot_protocol::AgentActivationResolutionResult` is a lossless, exhaustive mapping; no resolver error is coerced to success or dropped.
//!
//! This is a read-only activation resolution projection and owns no authority issuance, write/effect, fence, default, retry, Kernel, Store, or lifecycle semantics.

#![allow(dead_code)]

use eliot_governor::{
    GovernorActivationOutcome, GovernorCandidateCoverage, GovernorRetryDirective,
    GovernorSelectionDirective,
};
use eliot_protocol::{
    AgentActivationCandidateCoverage, AgentActivationResolutionDecision,
    AgentActivationResolutionDisposition, AgentActivationResolutionResult,
    AgentActivationResolutionTicket, AgentActivationResolvedBinding, AgentActivationRetryDirective,
    AgentActivationSelectionDirective,
};

use crate::DaemonError;

/// Read-only semantic-resolution boundary owned by eliotd.
///
/// The boundary accepts only a Kernel-issued correlation ticket. It does not
/// accept caller-selected semantic IDs and does not issue transport sessions,
/// fences, capabilities, or effects.
pub trait AgentActivationResolver {
    /// Resolves one exact ticket against the current Governor owner set.
    fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError>;

    /// Resolves one exact ticket to the canonical v2 typed result. This is the
    /// lossless projection for wave 2; every `GovernorActivationOutcome`
    /// variant maps to exactly one `AgentActivationResolutionDisposition`
    /// without silent coercion.
    fn resolve_agent_activation_v2(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionResult, DaemonError> {
        // Default implementation falls back to mapping the legacy decision as
        // Resolved. Implementations that own a typed Governor outcome should
        // override this to provide the exhaustive variant coverage.
        let decision = self.resolve_agent_activation(ticket, now)?;
        // This path is only used when a concrete resolver has not yet moved to
        // the typed Governor outcome; it synthesizes a Resolved binding from
        // the legacy decision to preserve lossless mapping for that single path.
        let binding = AgentActivationResolvedBinding {
            principal_id: decision.principal_id,
            session_id: decision.session_id,
            task_id: decision.task_id,
            work_unit_id: decision.work_unit_id,
            work_scope_id: decision.work_scope_id,
            task_revision: decision.task_revision,
            plan_id: decision.plan_id,
            plan_revision: decision.plan_revision,
        };
        AgentActivationResolutionResult::new(
            ticket,
            now.max(1),
            AgentActivationResolutionDisposition::Resolved {
                binding: Box::new(binding),
            },
        )
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))
    }
}

pub(super) fn map_activation_snapshot(
    ticket: &AgentActivationResolutionTicket,
    snapshot: eliot_governor::GovernorActivationSnapshot,
) -> Result<AgentActivationResolutionDecision, DaemonError> {
    AgentActivationResolutionDecision {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_DECISION_WIRE_ID.to_owned(),
        wire_version: AgentActivationResolutionDecision::CONTRACT_VERSION,
        ticket_id: ticket.ticket_id.clone(),
        ticket_sha256: ticket.ticket_sha256.clone(),
        state_fence: snapshot.state_fence,
        principal_id: snapshot.principal_id,
        session_id: snapshot.session_id,
        task_id: snapshot.task_id.to_string(),
        work_unit_id: snapshot.work_unit_id,
        work_scope_id: snapshot.work_scope_id,
        task_revision: snapshot.task_revision.to_string(),
        plan_id: snapshot.plan_id,
        plan_revision: snapshot.plan_revision,
        decision_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

// ---------------------------------------------------------------------------
// Wave 2: lossless Governor -> protocol v2 mapping
// ---------------------------------------------------------------------------

fn map_coverage(coverage: GovernorCandidateCoverage) -> AgentActivationCandidateCoverage {
    match coverage {
        GovernorCandidateCoverage::Complete => AgentActivationCandidateCoverage::Complete,
        GovernorCandidateCoverage::Partial => AgentActivationCandidateCoverage::Partial,
        GovernorCandidateCoverage::Unknown => AgentActivationCandidateCoverage::Unknown,
    }
}

fn map_selection(selection: GovernorSelectionDirective) -> AgentActivationSelectionDirective {
    AgentActivationSelectionDirective {
        candidate_handles: selection.candidate_handles,
        candidate_coverage: map_coverage(selection.candidate_coverage),
        recovery_handle: selection.recovery_handle,
    }
}

fn map_retry(retry: GovernorRetryDirective) -> AgentActivationRetryDirective {
    AgentActivationRetryDirective {
        dependency_ref: retry.dependency_ref,
        observed_dependency_revision: retry.observed_dependency_revision,
        not_before_unix_ms: retry.not_before_unix_ms,
    }
}

/// Lossless mapping from the Governor-internal typed outcome to the wire v2
/// protocol result. Every variant is preserved 1:1; no error is coerced to
/// `Resolved` and no error is dropped.
pub fn map_governor_outcome_to_protocol(
    ticket: &AgentActivationResolutionTicket,
    outcome: GovernorActivationOutcome,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = match outcome {
        GovernorActivationOutcome::Resolved(snapshot) => {
            let binding = AgentActivationResolvedBinding {
                principal_id: snapshot.principal_id,
                session_id: snapshot.session_id,
                task_id: snapshot.task_id.to_string(),
                work_unit_id: snapshot.work_unit_id,
                work_scope_id: snapshot.work_scope_id,
                task_revision: snapshot.task_revision.to_string(),
                plan_id: snapshot.plan_id,
                plan_revision: snapshot.plan_revision,
            };
            AgentActivationResolutionDisposition::Resolved {
                binding: Box::new(binding),
            }
        }
        GovernorActivationOutcome::TaskSelectionRequired { selection } => {
            AgentActivationResolutionDisposition::TaskSelectionRequired {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::ScopeSelectionRequired { selection } => {
            AgentActivationResolutionDisposition::ScopeSelectionRequired {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::ScopeAmbiguous { selection } => {
            AgentActivationResolutionDisposition::ScopeAmbiguous {
                selection: map_selection(selection),
            }
        }
        GovernorActivationOutcome::NotReady {
            recovery_handle,
            retry,
        } => AgentActivationResolutionDisposition::NotReady {
            recovery_handle,
            retry: map_retry(retry),
        },
        GovernorActivationOutcome::StaleFence {
            recovery_handle,
            observed_state_fence,
        } => AgentActivationResolutionDisposition::StaleFence {
            recovery_handle,
            observed_state_fence,
        },
        GovernorActivationOutcome::FailedInternal { failure_handle } => {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle }
        }
    };

    AgentActivationResolutionResult::new(ticket, resolved_at_unix_ms, disposition)
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

/// Pure snapshot/fence fixture helper: builds a deterministic ticket-bound
/// v2 result directly from a Governor snapshot for the `Resolved` case.
pub fn map_resolved_snapshot_to_protocol(
    ticket: &AgentActivationResolutionTicket,
    snapshot: eliot_governor::GovernorActivationSnapshot,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    map_governor_outcome_to_protocol(
        ticket,
        GovernorActivationOutcome::Resolved(snapshot),
        resolved_at_unix_ms,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod projection_tests {
    use super::*;
    use eliot_contracts::RequestId;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
    use eliot_governor::{
        GovernorActivationSnapshot, fixture_failed_internal, fixture_not_ready,
        fixture_scope_ambiguous, fixture_scope_selection_required, fixture_stale_fence,
        fixture_task_selection_required,
    };
    use eliot_protocol::AgentActivationResolutionTicket;

    fn test_ticket(deadline: u64) -> AgentActivationResolutionTicket {
        let mut ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-test".to_owned(),
            activation_request_id: RequestId::new("activation-request-1").expect("request id"),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-1".to_owned(),
            state_fence: StateFence::new(
                AuthorityEpoch::new(1).expect("epoch"),
                ResourceGeneration::new(1).expect("gen"),
            ),
            kernel_deadline_unix_ms: deadline,
            ticket_sha256: String::new(),
        };
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        ticket
    }

    fn test_snapshot() -> GovernorActivationSnapshot {
        GovernorActivationSnapshot {
            state_fence: StateFence::new(
                AuthorityEpoch::new(1).expect("epoch"),
                ResourceGeneration::new(1).expect("gen"),
            ),
            principal_id: "principal-1".to_owned(),
            session_id: "session-1".to_owned(),
            task_id: eliot_contracts::TaskId::new("task-1").expect("task id"),
            work_unit_id: "work-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            task_revision: 7,
            plan_id: "plan-1".to_owned(),
            plan_revision: "plan-revision-1".to_owned(),
        }
    }

    #[test]
    fn lossless_resolved_maps_to_protocol_resolved() {
        let ticket = test_ticket(100);
        let snapshot = test_snapshot();
        let result = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(snapshot),
            50,
        )
        .expect("resolved mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::Resolved { .. }
        ));
        assert_eq!(result.ticket_id, ticket.ticket_id);
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn task_selection_required_is_not_coerced_to_resolved() {
        let ticket = test_ticket(100);
        let outcome = fixture_task_selection_required();
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
        ));
        // Must not be Resolved.
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid");
    }

    #[test]
    fn scope_ambiguous_requires_two_candidates_and_is_preserved() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match result.disposition {
            AgentActivationResolutionDisposition::ScopeAmbiguous { selection } => {
                assert_eq!(selection.candidate_handles.len(), 2);
            }
            _ => panic!("expected ScopeAmbiguous"),
        }
    }

    #[test]
    fn scope_selection_required_is_distinct_from_ambiguous() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_selection_required(Vec::new());
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::ScopeSelectionRequired { .. }
        ));
        // Ambiguous would require >=2 candidates; this has 0 with Unknown -> distinct.
    }

    #[test]
    fn not_ready_carries_dependency_and_is_transient() {
        let ticket = test_ticket(100);
        let outcome = fixture_not_ready("governor.session", "rev-1", 60);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(result.is_transient_retry());
        match result.disposition {
            AgentActivationResolutionDisposition::NotReady { retry, .. } => {
                assert_eq!(retry.dependency_ref, "governor.session");
                assert!(retry.not_before_unix_ms > 50);
                assert!(retry.not_before_unix_ms < 100);
            }
            _ => panic!("expected NotReady"),
        }
    }

    #[test]
    fn stale_fence_is_not_success_and_does_not_create_session() {
        let ticket = test_ticket(100);
        let outcome = fixture_stale_fence(None);
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::StaleFence { .. }
        ));
        assert!(result.resolved_binding().is_none());
    }

    #[test]
    fn stale_fence_with_observed_fence_preserves_difference() {
        let ticket = test_ticket(100);
        let observed = StateFence::new(
            AuthorityEpoch::new(1).expect("epoch"),
            ResourceGeneration::new(2).expect("gen"),
        );
        let outcome = fixture_stale_fence(Some(observed.clone()));
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        match result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                observed_state_fence: Some(fence),
                ..
            } => assert_ne!(fence, ticket.state_fence),
            _ => panic!("expected StaleFence with fence"),
        }
    }

    #[test]
    fn failed_internal_is_not_task_ambiguity() {
        let ticket = test_ticket(100);
        let outcome = fixture_failed_internal("malformed-snapshot");
        let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::FailedInternal { .. }
        ));
        // Must not be coerced to TaskSelectionRequired.
        assert!(!matches!(
            result.disposition,
            AgentActivationResolutionDisposition::TaskSelectionRequired { .. }
        ));
    }

    #[test]
    fn every_governor_outcome_maps_to_distinct_protocol_kind() {
        let ticket = test_ticket(100);
        let snapshot = test_snapshot();
        let outcomes = vec![
            (GovernorActivationOutcome::Resolved(snapshot), "RESOLVED"),
            (fixture_task_selection_required(), "TASK_SELECTION_REQUIRED"),
            (
                fixture_scope_selection_required(vec!["scope:x".to_owned()]),
                "SCOPE_SELECTION_REQUIRED",
            ),
            (
                fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]),
                "SCOPE_AMBIGUOUS",
            ),
            (fixture_not_ready("dep", "rev", 60), "NOT_READY"),
            (fixture_stale_fence(None), "STALE_FENCE"),
            (fixture_failed_internal("internal"), "FAILED_INTERNAL"),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for (outcome, expected_kind) in outcomes {
            let expected = expected_kind;
            let result = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect("mapping");
            let kind = match result.disposition {
                AgentActivationResolutionDisposition::Resolved { .. } => "RESOLVED",
                AgentActivationResolutionDisposition::TaskSelectionRequired { .. } => {
                    "TASK_SELECTION_REQUIRED"
                }
                AgentActivationResolutionDisposition::ScopeSelectionRequired { .. } => {
                    "SCOPE_SELECTION_REQUIRED"
                }
                AgentActivationResolutionDisposition::ScopeAmbiguous { .. } => "SCOPE_AMBIGUOUS",
                AgentActivationResolutionDisposition::NotReady { .. } => "NOT_READY",
                AgentActivationResolutionDisposition::StaleFence { .. } => "STALE_FENCE",
                AgentActivationResolutionDisposition::FailedInternal { .. } => "FAILED_INTERNAL",
            };
            assert_eq!(kind, expected);
            assert!(kinds.insert(kind.to_owned()), "duplicate kind {kind}");
        }
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn no_resolver_error_is_silently_dropped_or_coerced_to_success() {
        let ticket = test_ticket(100);
        // Each non-resolved outcome must not produce an Ok(Resolved) result.
        let non_resolved = vec![
            fixture_task_selection_required(),
            fixture_scope_selection_required(Vec::new()),
            fixture_scope_ambiguous(vec!["scope:a".to_owned(), "scope:b".to_owned()]),
            fixture_not_ready("dep", "rev", 60),
            fixture_stale_fence(None),
            fixture_failed_internal("failure"),
        ];
        for outcome in non_resolved {
            let result = map_governor_outcome_to_protocol(&ticket, outcome.clone(), 50)
                .expect("non-resolved must map to Ok with correct disposition, not Err");
            assert!(
                result.resolved_binding().is_none(),
                "resolver error was coerced to success: {:?}",
                result.disposition
            );
        }
        // Resolved must be the only path that yields a binding.
        let resolved = map_governor_outcome_to_protocol(
            &ticket,
            GovernorActivationOutcome::Resolved(test_snapshot()),
            50,
        )
        .expect("resolved");
        assert!(resolved.resolved_binding().is_some());
    }

    #[test]
    fn protocol_validation_rejects_coerced_observed_fence_equal_to_ticket() {
        let ticket = test_ticket(100);
        // Governor StaleFence with observed == ticket fence must be rejected by
        // protocol validation, proving the mapping does not hide fence mismatches.
        let outcome = fixture_stale_fence(Some(ticket.state_fence.clone()));
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        // The error is surfaced as DaemonError::Lifecycle wrapping ProtocolError,
        // not dropped or mapped to Resolved.
        assert!(err.to_string().contains("observed_state_fence"));
    }

    #[test]
    fn not_ready_window_must_be_before_deadline() {
        let ticket = test_ticket(100);
        // not_before == deadline must fail, not be silently accepted.
        let outcome = fixture_not_ready("dep", "rev", 100);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("not_before_unix_ms"));
    }

    #[test]
    fn scope_ambiguous_with_one_candidate_is_rejected_not_coerced() {
        let ticket = test_ticket(100);
        let outcome = fixture_scope_ambiguous(vec!["only-one".to_owned()]);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("SCOPE_AMBIGUOUS"));
    }
}
