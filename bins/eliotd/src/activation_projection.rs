//! Read-only activation resolution projection.
//!
//! # Architecture
//! - **A2.3 Modular architecture** — bounded pure projection cell; no new runtime/process/failure boundary.
//! - **A13.2 Kernel and failure domains** — Kernel remains sole authority/fencing owner; this projection only reads the admitted Governor snapshot.
//! - **A13.10 Observability and Diagnostic Brief** — decision is a derived projection/receipt; it does not prove a transition.
//! - **ARCH-MOD-02 Depth is additive and micro-modular** — extracted as independently understandable/testable/replaceable capability cell; size and physical form remain empirical.
//!
//! # Implementation
//! - **I1.11 Startup algorithm** — resolution is available only after Governor/Kernel admission; no startup authority issuance here.
//! - **I2.2 When a capability becomes a separate crate** — pure contract/test seam justifies isolated module; no placeholder proliferation.
//! - **I2.23 Capability-family topology and crate extraction decisions** — Governor task/authority/canonical-transition family; validated via `CrateExtractionDecision`.
//! - **Semantic-grant handle: `eliot_governor::GovernorActivationOutcome` / `eliot_protocol::AgentActivationResolutionTicket` -> `eliot_protocol::AgentActivationResolutionDecision` via `GovernorComposition::resolve_activation_outcome`** — Kernel-issued ticket resolved against the current Governor owner set.
//! - **Wave 2 Governor-internal outcome -> protocol v2**: `eliot_governor::GovernorActivationOutcome` -> `eliot_protocol::AgentActivationResolutionResult` is a lossless, exhaustive mapping; no resolver error is coerced to success or dropped.
//!
//! This is a read-only activation resolution projection and owns no authority issuance, write/effect, fence, default, retry, Kernel, Store, or lifecycle semantics.

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
    /// v1 compatibility projection: resolves one exact ticket to the legacy
    /// `AgentActivationResolutionDecision` shape.
    ///
    /// v1-compat only. This method must not consume v2 typed-result data
    /// (`AgentActivationResolutionResult` / `AgentActivationResolutionDisposition`);
    /// v2 (`resolve_agent_activation_v2`) is the single production resolver
    /// spine. Callers on the typed-outcome path must call v2.
    ///
    /// Removal: no production caller remains on this method (the runtime claim
    /// arm resolves through v2). Final v1 retirement is tracked by #66;
    /// this method is not removed as opportunistic cleanup.
    fn resolve_agent_activation(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionDecision, DaemonError>;

    /// Canonical v2 production spine: resolves one exact ticket to the typed
    /// v2 result. This is the lossless projection for wave 2; every
    /// `GovernorActivationOutcome` variant maps to exactly one
    /// `AgentActivationResolutionDisposition` without silent coercion.
    ///
    /// No default body is provided on purpose: every concrete resolver must
    /// supply the exhaustive typed-outcome projection, so a resolver that has
    /// not moved to the typed outcome fails closed at build time instead of
    /// silently inheriting a synthesized `Resolved` binding.
    fn resolve_agent_activation_v2(
        &self,
        ticket: &AgentActivationResolutionTicket,
        now: u64,
    ) -> Result<AgentActivationResolutionResult, DaemonError>;
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
    // #740: request/result span over the typed projection boundary. The
    // Governor outcome stays the sole discriminator; the span only names the
    // resulting disposition plus the available ticket/result identities.
    let _span = tracing::info_span!(
        "eliotd.activation_projection",
        ticket = %crate::diagnostics::sanitize_identity(&ticket.ticket_id)
    )
    .entered();
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
        .inspect(|result| {
            // #740: result span carries disposition + digest identities only.
            let _ = crate::diagnostics::AdmissionRecord::of(
                crate::diagnostics::disposition_of_resolution(&result.disposition),
                &ticket.ticket_id,
                &result.result_sha256,
            )
            .emit();
        })
}

/// Typed fail-closed result for a `Resolved` snapshot whose fence no longer
/// matches the Kernel-issued ticket fence (#66).
///
/// The Governor owner resolved against current state, but the ticket was
/// issued under a different fence (e.g. generation advanced between daemon
/// admission and claim). Submitting the stale binding would create a Session
/// under the wrong fence; dropping it as a hard daemon error would kill the
/// loop instead of answering the ticket. Return a `StaleFence` terminal
/// result carrying the observed fence, so the Kernel fails closed without
/// creating a Session and the daemon stays alive for the next claim. Never
/// produces a binding.
pub fn stale_fence_for_resolved_mismatch(
    ticket: &AgentActivationResolutionTicket,
    observed_state_fence: eliot_contracts::StateFence,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::StaleFence {
        recovery_handle: "daemon.fence-mismatch:recovery".to_owned(),
        observed_state_fence: Some(observed_state_fence),
    };
    AgentActivationResolutionResult::new(ticket, resolved_at_unix_ms, disposition)
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

/// Typed fail-closed result when the Governor is not ready to classify the
/// exact ticket (#204).
///
/// The ticket is already validated at this point, but no Governor outcome
/// exists to map: returning a hard error would kill the daemon loop and leave
/// the claimed ticket unanswered, so the bridge waiter would observe a
/// result-less expiry (a timeout-like outcome) instead of the distinct
/// internal failure. Answer with a `FailedInternal` terminal result instead,
/// so the Kernel records a typed disposition that stays distinct from every
/// other negative and from the deadline outcome, and the daemon stays alive
/// for the next claim. Never produces a binding and never retries the ticket.
/// If the fallback itself cannot bind (e.g. the deadline passed under the
/// resolver), the caller keeps the original readiness error unchanged.
pub fn failed_internal_for_unready_governor(
    ticket: &AgentActivationResolutionTicket,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::FailedInternal {
        failure_handle: "daemon.governor-not-ready:recovery".to_owned(),
    };
    AgentActivationResolutionResult::new(ticket, resolved_at_unix_ms, disposition)
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

/// Typed fail-closed result when the Governor→protocol mapping rejects a
/// classified outcome for the exact ticket (#202).
///
/// The Governor classified the ticket, but the classified data cannot bind it
/// (e.g. a `NotReady` retry window at or past the Kernel deadline, an
/// ambiguity finding with fewer than two candidates, or a stale-fence
/// observation equal to the ticket fence). Returning the mapping error would
/// kill the daemon loop and leave the ticket unanswered; a `FailedInternal`
/// terminal result answers the ticket instead, so the Kernel records a typed
/// disposition and the daemon stays alive for the next claim. The failed
/// outcome kind is carried in the bounded failure handle; the full mapping
/// error stays in daemon diagnostics. Never produces a binding and never
/// retries the same ticket.
pub fn failed_internal_for_mapping_failure(
    ticket: &AgentActivationResolutionTicket,
    outcome_kind: &str,
    resolved_at_unix_ms: u64,
) -> Result<AgentActivationResolutionResult, DaemonError> {
    let disposition = AgentActivationResolutionDisposition::FailedInternal {
        failure_handle: format!("daemon.mapping-failure:{outcome_kind}:recovery"),
    };
    AgentActivationResolutionResult::new(ticket, resolved_at_unix_ms, disposition)
        .map_err(|error| DaemonError::Lifecycle(error.to_string()))
}

#[cfg(test)]
mod projection_tests {
    #![allow(clippy::expect_used)] // test-only panic-acceptable (#838).
    use super::*;
    use eliot_contracts::RequestId;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{
        GovernorActivationSnapshot, fixture_failed_internal, fixture_not_ready,
        fixture_scope_ambiguous, fixture_scope_selection_required, fixture_stale_fence,
        fixture_task_selection_required,
    };
    use eliot_protocol::AgentActivationResolutionTicket;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_ticket(deadline: u64) -> AgentActivationResolutionTicket {
        let mut ticket = AgentActivationResolutionTicket {
            wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
            ticket_id: "ticket-test".to_owned(),
            activation_request_id: RequestId::new("activation-request-1").expect("request id"),
            activation_request_sha256: "a".repeat(64),
            peer_admission_receipt_sha256: "b".repeat(64),
            connection_id: "connection-1".to_owned(),
            state_fence: StateFence::new(test_epoch(1), ResourceGeneration::new(1).expect("gen")),
            kernel_deadline_unix_ms: deadline,
            ticket_sha256: String::new(),
        };
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        ticket
    }

    fn test_snapshot() -> GovernorActivationSnapshot {
        GovernorActivationSnapshot {
            state_fence: StateFence::new(test_epoch(1), ResourceGeneration::new(1).expect("gen")),
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
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
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

    #[test]
    fn resolved_fence_mismatch_yields_typed_stale_fence_without_binding() {
        // #66: a Resolved snapshot under a stale fence must surface as a
        // typed StaleFence terminal result, never as a Session binding and
        // never as a silent drop.
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert_ne!(observed, ticket.state_fence);
        let result = stale_fence_for_resolved_mismatch(&ticket, observed.clone(), 50)
            .expect("stale fence result");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::StaleFence { .. }
        ));
        assert!(result.resolved_binding().is_none());
        match &result.disposition {
            AgentActivationResolutionDisposition::StaleFence {
                observed_state_fence: Some(fence),
                ..
            } => assert_eq!(fence, &observed),
            _ => panic!("expected StaleFence with observed fence"),
        }
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn resolved_fence_mismatch_with_equal_fence_is_rejected() {
        // The helper must not hide a fence match as StaleFence: an observed
        // fence equal to the ticket fence is rejected by protocol validation.
        let ticket = test_ticket(100);
        let err = stale_fence_for_resolved_mismatch(&ticket, ticket.state_fence.clone(), 50)
            .expect_err("equal fence must reject");
        assert!(err.to_string().contains("observed_state_fence"));
    }

    #[test]
    fn not_ready_past_deadline_falls_back_to_failed_internal() {
        // #202: a Governor NotReady whose retry window reaches the Kernel
        // deadline cannot bind the ticket, so the mapping rejects it. The
        // fallback answers the same ticket with a typed FailedInternal
        // terminal result instead of leaving it unanswered.
        let ticket = test_ticket(100);
        let outcome = fixture_not_ready("dep", "rev", 100);
        let err = map_governor_outcome_to_protocol(&ticket, outcome, 50).expect_err("must reject");
        assert!(err.to_string().contains("not_before_unix_ms"));
        let result =
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).expect("fallback result");
        assert!(matches!(
            result.disposition,
            AgentActivationResolutionDisposition::FailedInternal { .. }
        ));
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn failed_internal_fallback_carries_kind_and_no_binding() {
        // #202: the fallback carries the failed outcome kind in its bounded
        // failure handle and never produces a binding.
        let ticket = test_ticket(100);
        let result = failed_internal_for_mapping_failure(&ticket, "SCOPE_AMBIGUOUS", 50)
            .expect("fallback result");
        match &result.disposition {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
                assert!(failure_handle.contains("SCOPE_AMBIGUOUS"));
            }
            _ => panic!("expected FailedInternal"),
        }
        assert!(result.resolved_binding().is_none());
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn unready_governor_yields_typed_failed_internal_without_binding() {
        // #204: an unready Governor answers the exact valid ticket with a
        // typed FailedInternal terminal result instead of a hard loop-fatal
        // error: distinct from every other negative, never transient, and
        // never a binding.
        let ticket = test_ticket(100);
        let result =
            failed_internal_for_unready_governor(&ticket, 50).expect("unready fallback result");
        match &result.disposition {
            AgentActivationResolutionDisposition::FailedInternal { failure_handle } => {
                assert!(failure_handle.contains("governor-not-ready"));
            }
            _ => panic!("expected FailedInternal"),
        }
        assert!(result.resolved_binding().is_none());
        assert!(!result.is_transient_retry());
        assert_eq!(result.ticket_id, ticket.ticket_id);
        result.validate_against(&ticket).expect("valid binding");
    }

    #[test]
    fn unready_governor_fallback_at_deadline_fails_closed() {
        // #204: the fallback never fabricates a result past the Kernel
        // deadline; a ticket that expired under the resolver stays an error.
        let ticket = test_ticket(100);
        assert!(
            failed_internal_for_unready_governor(&ticket, 100).is_err(),
            "resolved_at at the deadline must not bind"
        );
    }

    // WORK_UNIT_CASE: 839/5
    #[test]
    fn tampered_ticket_is_rejected_by_every_fail_closed_constructor() {
        // #204 scenario 10: a tampered/wrong ticket (digest mismatch) binds
        // nothing. Every fail-closed constructor validates the ticket first
        // via `AgentActivationResolutionResult::new`, so each stays Err with
        // no binding and no new mapping.
        let mut ticket = test_ticket(100);
        ticket.ticket_id = "ticket-tampered".to_owned();
        // Digest still covers the original id: tampered by construction.
        assert!(ticket.validate().is_err());
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                50,
            )
            .is_err(),
            "tampered ticket must not map"
        );
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 50).is_err(),
            "tampered ticket must not yield StaleFence"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).is_err(),
            "tampered ticket must not yield mapping-failure FailedInternal"
        );
        assert!(
            failed_internal_for_unready_governor(&ticket, 50).is_err(),
            "tampered ticket must not yield unready FailedInternal"
        );
    }

    // WORK_UNIT_CASE: 839/4
    #[test]
    fn malformed_wire_rejected_before_semantic_resolution() {
        // Malformed wire identity with a fresh digest: the shape defect is
        // reported, never a digest mismatch. The production resolver
        // (`DaemonComposition::resolve_agent_activation_v2`) invokes
        // `ticket.validate()` before readiness/deadline/Governor access, so
        // this rejection provably precedes any Governor read.
        let mut ticket = test_ticket(100);
        ticket.wire_id = "eliot.agent.activation.resolution.ticket.malformed".to_owned();
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        let error = match ticket.validate() {
            Ok(()) => panic!("malformed wire id validated"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("agent_activation_resolution_ticket.wire"),
            "malformed wire reported the wrong field: {error}"
        );
        // Zero wire version is equally malformed.
        let mut zeroed = test_ticket(100);
        zeroed.wire_version = 0;
        zeroed.ticket_sha256 = zeroed.compute_digest().expect("digest");
        assert!(zeroed.validate().is_err(), "zero wire version validated");
        // No fail-closed constructor may consume either malformed ticket.
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        for bad in [&ticket, &zeroed] {
            assert!(
                map_governor_outcome_to_protocol(
                    bad,
                    GovernorActivationOutcome::Resolved(test_snapshot()),
                    50,
                )
                .is_err(),
                "typed mapping consumed a malformed-wire ticket"
            );
            assert!(
                stale_fence_for_resolved_mismatch(bad, observed.clone(), 50).is_err(),
                "stale-fence fallback consumed a malformed-wire ticket"
            );
            assert!(
                failed_internal_for_unready_governor(bad, 50).is_err(),
                "unready-Governor fallback consumed a malformed-wire ticket"
            );
            assert!(
                failed_internal_for_mapping_failure(bad, "NOT_READY", 50).is_err(),
                "mapping-failure fallback consumed a malformed-wire ticket"
            );
        }
    }

    // WORK_UNIT_CASE: 839/21
    #[test]
    fn unknown_wire_version_rejected_before_semantic_resolution() {
        // Well-formed ticket on a future version with a matching digest: an
        // unknown version, not a malformed shape and not a digest mismatch.
        // Rejected by the same `ticket.validate()` the production resolver
        // runs before any Governor read, so no v2 data is ever decoded.
        let mut ticket = test_ticket(100);
        ticket.wire_version = AgentActivationResolutionTicket::CONTRACT_VERSION + 1;
        ticket.ticket_sha256 = ticket.compute_digest().expect("digest");
        let error = match ticket.validate() {
            Ok(()) => panic!("unknown wire version validated"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("agent_activation_resolution_ticket.wire"),
            "unknown version reported the wrong field: {error}"
        );
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                50,
            )
            .is_err(),
            "typed mapping consumed an unknown-version ticket"
        );
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 50).is_err(),
            "stale-fence fallback consumed an unknown-version ticket"
        );
        assert!(
            failed_internal_for_unready_governor(&ticket, 50).is_err(),
            "unready-Governor fallback consumed an unknown-version ticket"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 50).is_err(),
            "mapping-failure fallback consumed an unknown-version ticket"
        );
    }

    // WORK_UNIT_CASE: 839/9
    #[test]
    fn post_deadline_resolved_at_is_rejected_by_every_fail_closed_constructor() {
        // #204 scenario 11: no valid terminal result at or past the Kernel
        // deadline. `Result::new` requires resolved_at strictly earlier than
        // the deadline, so each constructor stays Err and never fabricates a
        // typed negative past expiry. (Unready past-deadline covered above.)
        let ticket = test_ticket(100);
        let observed = StateFence::new(test_epoch(1), ResourceGeneration::new(2).expect("gen"));
        assert!(
            map_governor_outcome_to_protocol(
                &ticket,
                GovernorActivationOutcome::Resolved(test_snapshot()),
                100,
            )
            .is_err(),
            "resolved_at at the deadline must not bind"
        );
        assert!(
            stale_fence_for_resolved_mismatch(&ticket, observed, 100).is_err(),
            "stale-fence fallback at the deadline must not bind"
        );
        assert!(
            failed_internal_for_mapping_failure(&ticket, "NOT_READY", 100).is_err(),
            "mapping-failure fallback at the deadline must not bind"
        );
    }

    #[test]
    fn wrong_ticket_result_binding_is_rejected() {
        // #204 scenario 10 (wrong-ticket half): a result bound to one ticket
        // never validates against another ticket identity.
        let ticket = test_ticket(100);
        let result = failed_internal_for_unready_governor(&ticket, 50).expect("fallback result");
        result.validate_against(&ticket).expect("valid binding");
        let mut other = test_ticket(100);
        other.ticket_id = "ticket-other".to_owned();
        other.ticket_sha256 = other.compute_digest().expect("digest");
        assert!(other.validate().is_ok());
        assert!(
            result.validate_against(&other).is_err(),
            "result bound to one ticket must not validate against another"
        );
    }
}
