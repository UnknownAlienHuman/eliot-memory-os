//! Governor-internal typed semantic outcome for activation resolution.
//!
//! This module is the single typed discriminator for activation semantics.
//! It classifies every resolver path into one exact outcome without falling
//! back to stringly-typed [`crate::composition::CompositionError`] parsing and
//! without coercing any error into a success binding. The downstream
//! `eliotd::activation_projection` layer maps this outcome losslessly to the
//! protocol v2 `AgentActivationResolutionResult`.

use crate::composition::GovernorActivationSnapshot;
use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

/// Coverage denominator for bounded candidate handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GovernorCandidateCoverage {
    Complete,
    Partial,
    Unknown,
}

/// Bounded selection directive carried by task/scope outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorSelectionDirective {
    pub candidate_handles: Vec<String>,
    pub candidate_coverage: GovernorCandidateCoverage,
    pub recovery_handle: String,
}

impl GovernorSelectionDirective {
    pub fn new(
        candidate_handles: Vec<String>,
        candidate_coverage: GovernorCandidateCoverage,
        recovery_handle: impl Into<String>,
    ) -> Self {
        Self {
            candidate_handles,
            candidate_coverage,
            recovery_handle: recovery_handle.into(),
        }
    }
}

/// Retry directive for transient `NotReady` outcomes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernorRetryDirective {
    pub dependency_ref: String,
    pub observed_dependency_revision: String,
    pub not_before_unix_ms: u64,
}

impl GovernorRetryDirective {
    pub fn new(
        dependency_ref: impl Into<String>,
        observed_dependency_revision: impl Into<String>,
        not_before_unix_ms: u64,
    ) -> Self {
        Self {
            dependency_ref: dependency_ref.into(),
            observed_dependency_revision: observed_dependency_revision.into(),
            not_before_unix_ms,
        }
    }
}

/// Governor-internal typed semantic outcome for activation resolution.
///
/// Every variant corresponds 1:1 to a protocol v2 disposition and is produced
/// without string inspection. Domain mapping is exhaustive; there is no
/// catch-all that silently becomes `Resolved`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum GovernorActivationOutcome {
    Resolved(GovernorActivationSnapshot),
    TaskSelectionRequired {
        selection: GovernorSelectionDirective,
    },
    ScopeSelectionRequired {
        selection: GovernorSelectionDirective,
    },
    ScopeAmbiguous {
        selection: GovernorSelectionDirective,
    },
    NotReady {
        recovery_handle: String,
        retry: GovernorRetryDirective,
    },
    StaleFence {
        recovery_handle: String,
        observed_state_fence: Option<StateFence>,
    },
    FailedInternal {
        failure_handle: String,
    },
}

impl GovernorActivationOutcome {
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }

    #[must_use]
    pub fn is_transient_retry(&self) -> bool {
        matches!(self, Self::NotReady { .. })
    }

    #[must_use]
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Resolved(_) => "RESOLVED",
            Self::TaskSelectionRequired { .. } => "TASK_SELECTION_REQUIRED",
            Self::ScopeSelectionRequired { .. } => "SCOPE_SELECTION_REQUIRED",
            Self::ScopeAmbiguous { .. } => "SCOPE_AMBIGUOUS",
            Self::NotReady { .. } => "NOT_READY",
            Self::StaleFence { .. } => "STALE_FENCE",
            Self::FailedInternal { .. } => "FAILED_INTERNAL",
        }
    }
}

// ---------------------------------------------------------------------------
// Pure snapshot/fence fixtures — deterministic, no I/O, no generation loss
// ---------------------------------------------------------------------------

/// Fixture: exactly one current compatible activation snapshot maps to `Resolved`.
pub fn fixture_resolved(snapshot: GovernorActivationSnapshot) -> GovernorActivationOutcome {
    GovernorActivationOutcome::Resolved(snapshot)
}

/// Fixture: no current task / missing TaskContract -> TaskSelectionRequired.
/// Uses UNKNOWN coverage with empty handles to avoid claiming exhaustive absence.
pub fn fixture_task_selection_required() -> GovernorActivationOutcome {
    GovernorActivationOutcome::TaskSelectionRequired {
        selection: GovernorSelectionDirective::new(
            Vec::new(),
            GovernorCandidateCoverage::Unknown,
            "governor.task-selection:recovery",
        ),
    }
}

/// Fixture: bounded partial task selection with at least one known candidate.
pub fn fixture_task_selection_partial(candidates: Vec<String>) -> GovernorActivationOutcome {
    GovernorActivationOutcome::TaskSelectionRequired {
        selection: GovernorSelectionDirective::new(
            candidates,
            GovernorCandidateCoverage::Partial,
            "governor.task-selection:recovery",
        ),
    }
}

/// Fixture: scope not authenticated/resolved but not multi-candidate ambiguity.
pub fn fixture_scope_selection_required(candidates: Vec<String>) -> GovernorActivationOutcome {
    let coverage = if candidates.is_empty() {
        GovernorCandidateCoverage::Unknown
    } else {
        GovernorCandidateCoverage::Partial
    };
    GovernorActivationOutcome::ScopeSelectionRequired {
        selection: GovernorSelectionDirective::new(
            candidates,
            coverage,
            "governor.scope-selection:recovery",
        ),
    }
}

/// Fixture: at least two exact candidate scope handles remain.
pub fn fixture_scope_ambiguous(candidates: Vec<String>) -> GovernorActivationOutcome {
    GovernorActivationOutcome::ScopeAmbiguous {
        selection: GovernorSelectionDirective::new(
            candidates,
            GovernorCandidateCoverage::Complete,
            "governor.scope-ambiguous:recovery",
        ),
    }
}

/// Fixture: transient named owner dependency -> NotReady.
pub fn fixture_not_ready(
    dependency_ref: &str,
    observed_revision: &str,
    not_before_unix_ms: u64,
) -> GovernorActivationOutcome {
    GovernorActivationOutcome::NotReady {
        recovery_handle: "governor.not-ready:recovery".to_owned(),
        retry: GovernorRetryDirective::new(dependency_ref, observed_revision, not_before_unix_ms),
    }
}

/// Fixture: ticket / snapshot fence mismatch -> StaleFence.
pub fn fixture_stale_fence(observed: Option<StateFence>) -> GovernorActivationOutcome {
    GovernorActivationOutcome::StaleFence {
        recovery_handle: "governor.stale-fence:recovery".to_owned(),
        observed_state_fence: observed,
    }
}

/// Fixture: malformed/impossible snapshot -> FailedInternal.
pub fn fixture_failed_internal(reason: &str) -> GovernorActivationOutcome {
    GovernorActivationOutcome::FailedInternal {
        failure_handle: format!("governor.internal:{reason}"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence, TaskId};

    fn test_snapshot() -> crate::composition::GovernorActivationSnapshot {
        crate::composition::GovernorActivationSnapshot {
            state_fence: StateFence::new(
                AuthorityEpoch::new(1).unwrap(),
                ResourceGeneration::new(1).unwrap(),
            ),
            principal_id: "principal-1".to_owned(),
            session_id: "session-1".to_owned(),
            task_id: TaskId::new("task-1").unwrap(),
            work_unit_id: "work-1".to_owned(),
            work_scope_id: "scope-1".to_owned(),
            task_revision: 7,
            plan_id: "plan-1".to_owned(),
            plan_revision: "plan-revision-1".to_owned(),
        }
    }

    #[test]
    fn all_fixtures_produce_distinct_kinds() {
        let snapshot = test_snapshot();
        let outcomes = [
            fixture_resolved(snapshot),
            fixture_task_selection_required(),
            fixture_scope_selection_required(Vec::new()),
            fixture_scope_ambiguous(vec!["a".to_owned(), "b".to_owned()]),
            fixture_not_ready("dep", "rev", 60),
            fixture_stale_fence(None),
            fixture_failed_internal("internal"),
        ];
        let kinds: std::collections::BTreeSet<_> = outcomes
            .iter()
            .map(GovernorActivationOutcome::kind_str)
            .collect();
        assert_eq!(kinds.len(), 7);
    }

    #[test]
    fn pure_snapshot_fixture_is_resolved_and_bound_to_fence() {
        let snapshot = test_snapshot();
        let fence = snapshot.state_fence.clone();
        let outcome = fixture_resolved(snapshot.clone());
        assert!(outcome.is_resolved());
        assert!(!outcome.is_transient_retry());
        match outcome {
            GovernorActivationOutcome::Resolved(s) => assert_eq!(s.state_fence, fence),
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn not_ready_is_only_transient_and_carries_dependency() {
        let outcomes = vec![
            fixture_resolved(test_snapshot()),
            fixture_task_selection_required(),
            fixture_not_ready("governor.task", "rev-1", 60),
            fixture_stale_fence(None),
            fixture_failed_internal("x"),
        ];
        for outcome in outcomes {
            if outcome.kind_str() == "NOT_READY" {
                assert!(outcome.is_transient_retry());
            } else {
                assert!(!outcome.is_transient_retry());
            }
        }
        let not_ready = fixture_not_ready("governor.session", "rev-2", 80);
        match not_ready {
            GovernorActivationOutcome::NotReady { retry, .. } => {
                assert_eq!(retry.dependency_ref, "governor.session");
                assert_eq!(retry.not_before_unix_ms, 80);
            }
            _ => panic!("expected NotReady"),
        }
    }

    #[test]
    fn stale_fence_never_coerced_to_resolved() {
        let stale = fixture_stale_fence(None);
        assert!(!stale.is_resolved());
        assert_eq!(stale.kind_str(), "STALE_FENCE");
        let with_fence = fixture_stale_fence(Some(StateFence::new(
            AuthorityEpoch::new(1).unwrap(),
            ResourceGeneration::new(2).unwrap(),
        )));
        assert!(!with_fence.is_resolved());
    }

    #[test]
    fn failed_internal_never_becomes_task_selection() {
        let failed = fixture_failed_internal("malformed");
        assert_eq!(failed.kind_str(), "FAILED_INTERNAL");
        assert!(!matches!(
            failed,
            GovernorActivationOutcome::TaskSelectionRequired { .. }
        ));
    }

    #[test]
    fn no_resolver_error_is_silently_dropped() {
        // Every non-resolved fixture must not be Resolved.
        let fixtures = vec![
            fixture_task_selection_required(),
            fixture_scope_selection_required(Vec::new()),
            fixture_scope_ambiguous(vec!["a".to_owned(), "b".to_owned()]),
            fixture_not_ready("dep", "rev", 60),
            fixture_stale_fence(None),
            fixture_failed_internal("internal"),
        ];
        for outcome in fixtures {
            assert!(
                !outcome.is_resolved(),
                "fixture {:?} was coerced to Resolved",
                outcome.kind_str()
            );
        }
    }
}
