//! Governor-owned, fence-keyed suppliers for the six reactive planning inputs.
//!
//! The typed values are produced by their semantic owners and published through
//! the type-specific `GovernorComposition::publish_reactive_*` seams. Governor
//! binds every publication to the authenticated task/session/scope/fence and
//! to accepted observation evidence from its one `ObservationJournal`. The
//! owner is a rebuildable read projection: it owns no queue, delivery receipt,
//! canonical write path, or fallback value.

#![forbid(unsafe_code)]

use std::sync::{RwLock, RwLockReadGuard};

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection,
    IntegrationCoverageProfile as ReactiveIntegrationCoverageProfile, SessionDeliverySnapshot,
};
use eliot_contracts::{StateFence, TaskId, canonical_json_bytes, sha256_hex};
use eliot_observation::{ObservationAdmissionResult, ObservationJournal};
use eliot_reactive_context_plan::{ReactiveCueActivation, ReactiveDeliveryPolicy};
use eliot_receipts::WorkScopeId;
use thiserror::Error;

use crate::composition::GovernorActivationSnapshot;
use crate::reactive_owner_projection::{
    MAX_REACTIVE_OWNER_RECORDS, ReactiveOwnerProjectionError, ReactiveOwnerSource,
    project_reactive_owner_from_sources,
};

/// The six immutable owner outputs consumed by the A4 planner, plus the
/// already-retained cue/index rows used to bind them to admitted observations.
///
/// This is the complete read result from the Governor owner, not a caller-shaped
/// plan. Every field was validated against the exact activation before it was
/// retained, and no field is synthesized from an ID or a default.
#[derive(Clone, Debug)]
pub struct GovernorReactiveProjectionSet {
    /// A15 context view assembled from the retained context owner.
    pub context_view: ContextPlanningView,
    /// A10 evaluated cue request/result pair from the cue owner.
    pub cue_activation: ReactiveCueActivation,
    /// Session-owned delivery history for this exact session.
    pub session_delivery: SessionDeliverySnapshot,
    /// Governor attention/conflict projection.
    pub critical_attention: CriticalAttentionProjection,
    /// Host/runtime/interface coverage and watchdog/trace evidence profile.
    pub integration_coverage: ReactiveIntegrationCoverageProfile,
    /// Owner-issued policy and bounded delivery limits.
    pub delivery_policy: ReactiveDeliveryPolicy,
    /// Exact A12 cue results and context-owner target-to-atom joins.
    pub owner_sources: Vec<ReactiveOwnerSource>,
}

impl GovernorReactiveProjectionSet {
    fn validate_against(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<(), ReactiveProjectionError> {
        validate_context_view(&self.context_view, activation)?;
        validate_cue_activation(&self.cue_activation, &self.context_view, activation)?;
        validate_session_delivery(&self.session_delivery, activation)?;
        validate_critical_attention(&self.critical_attention, activation)?;
        validate_integration_coverage(&self.integration_coverage, activation)?;
        validate_delivery_policy(&self.delivery_policy, activation)?;
        if self.owner_sources.len() > MAX_REACTIVE_OWNER_RECORDS {
            return Err(ReactiveProjectionError::OwnerSource(
                ReactiveOwnerProjectionError::Bound("projection.owner_sources"),
            ));
        }
        Ok(())
    }
}

fn invalid_projection(
    projection: &'static str,
    error: impl std::fmt::Display,
) -> ReactiveProjectionError {
    ReactiveProjectionError::InvalidProjection {
        projection,
        reason: error.to_string(),
    }
}

fn stale_projection(projection: &'static str, field: &'static str) -> ReactiveProjectionError {
    ReactiveProjectionError::StaleProjection { projection, field }
}

fn validate_context_view(
    view: &ContextPlanningView,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    view.validate()
        .map_err(|error| invalid_projection("context_view", error))?;
    let binding = &view.view.binding;
    if binding.task_id != activation.task_id {
        return Err(stale_projection("context_view", "view.binding.task_id"));
    }
    if binding.scope_id.as_str() != activation.work_scope_id {
        return Err(stale_projection("context_view", "view.binding.scope_id"));
    }
    if binding.state_fence != activation.state_fence {
        return Err(stale_projection("context_view", "view.binding.state_fence"));
    }
    Ok(())
}

fn validate_cue_activation(
    cue: &ReactiveCueActivation,
    view: &ContextPlanningView,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    cue.validate_against(view)
        .map_err(|error| invalid_projection("cue_activation", error))?;
    if cue.request.state_fence != activation.state_fence {
        return Err(stale_projection("cue_activation", "request.state_fence"));
    }
    Ok(())
}

fn validate_session_delivery(
    session: &SessionDeliverySnapshot,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    session
        .validate()
        .map_err(|error| invalid_projection("session_delivery", error))?;
    if session.session_id.as_str() != activation.session_id {
        return Err(stale_projection("session_delivery", "session_id"));
    }
    if session.principal_id != activation.principal_id {
        return Err(stale_projection("session_delivery", "principal_id"));
    }
    if session.task_id != activation.task_id {
        return Err(stale_projection("session_delivery", "task_id"));
    }
    if session.scope_id.as_str() != activation.work_scope_id {
        return Err(stale_projection("session_delivery", "scope_id"));
    }
    if session.state_fence != activation.state_fence {
        return Err(stale_projection("session_delivery", "state_fence"));
    }
    Ok(())
}

fn validate_critical_attention(
    attention: &CriticalAttentionProjection,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    attention
        .validate()
        .map_err(|error| invalid_projection("critical_attention", error))?;
    if attention.task_id != activation.task_id {
        return Err(stale_projection("critical_attention", "task_id"));
    }
    if attention.scope_id.as_str() != activation.work_scope_id {
        return Err(stale_projection("critical_attention", "scope_id"));
    }
    if attention.state_fence != activation.state_fence {
        return Err(stale_projection("critical_attention", "state_fence"));
    }
    Ok(())
}

fn validate_integration_coverage(
    coverage: &ReactiveIntegrationCoverageProfile,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    coverage
        .validate()
        .map_err(|error| invalid_projection("integration_coverage", error))?;
    if coverage.state_fence != activation.state_fence {
        return Err(stale_projection("integration_coverage", "state_fence"));
    }
    Ok(())
}

fn validate_delivery_policy(
    policy: &ReactiveDeliveryPolicy,
    activation: &GovernorActivationSnapshot,
) -> Result<(), ReactiveProjectionError> {
    policy
        .validate()
        .map_err(|error| invalid_projection("delivery_policy", error))?;
    if policy.plan_id.as_str() != activation.plan_id {
        return Err(stale_projection("delivery_policy", "plan_id"));
    }
    Ok(())
}

/// Typed evidence binding captured from the Governor's admitted journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReactiveAcceptedEvidence {
    task_id: TaskId,
    scope_id: String,
    state_fence: StateFence,
    record_count: usize,
    digest: String,
}

impl ReactiveAcceptedEvidence {
    fn validate_against(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<(), ReactiveProjectionError> {
        if self.task_id != activation.task_id {
            return Err(ReactiveProjectionError::EvidenceBindingMismatch {
                field: "accepted_evidence.task_id",
            });
        }
        if self.scope_id != activation.work_scope_id {
            return Err(ReactiveProjectionError::EvidenceBindingMismatch {
                field: "accepted_evidence.scope_id",
            });
        }
        if self.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::EvidenceBindingMismatch {
                field: "accepted_evidence.state_fence",
            });
        }
        if self.record_count == 0 || self.digest.len() != 64 {
            return Err(ReactiveProjectionError::EvidenceUnavailable);
        }
        Ok(())
    }
}

/// Errors raised by the concrete Governor reactive projection owner.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ReactiveProjectionError {
    /// No six-projection set has been published for the live activation.
    #[error("reactive projections are withheld: {projection} has no owner publication")]
    NotPublished { projection: &'static str },
    /// A typed value failed its own contract validation.
    #[error("reactive projection {projection} is invalid: {reason}")]
    InvalidProjection {
        projection: &'static str,
        reason: String,
    },
    /// A typed value belongs to another activation.
    #[error("reactive projection {projection} is stale at {field}")]
    StaleProjection {
        projection: &'static str,
        field: &'static str,
    },
    /// Accepted evidence was not bound to the same live activation.
    #[error("reactive accepted evidence binding mismatch at {field}")]
    EvidenceBindingMismatch { field: &'static str },
    /// There is no accepted evidence from which to publish a reactive set.
    #[error("reactive projections are withheld: no accepted evidence for the live activation")]
    EvidenceUnavailable,
    /// The bounded owner source list disagrees with the admitted journal.
    #[error("reactive owner source validation failed: {0}")]
    OwnerSource(#[from] ReactiveOwnerProjectionError),
    /// The owner lock was poisoned after an interrupted writer.
    #[error("reactive projection owner lock is poisoned")]
    Poisoned,
    /// Canonical evidence digesting failed at the owner boundary.
    #[error("reactive accepted evidence could not be canonicalized: {0}")]
    EvidenceCanonicalization(String),
}

struct PublishedReactiveProjection {
    revision: u64,
    activation: GovernorActivationSnapshot,
    evidence: ReactiveAcceptedEvidence,
    context_view: Option<ContextPlanningView>,
    cue_activation: Option<ReactiveCueActivation>,
    session_delivery: Option<SessionDeliverySnapshot>,
    critical_attention: Option<CriticalAttentionProjection>,
    integration_coverage: Option<ReactiveIntegrationCoverageProfile>,
    delivery_policy: Option<ReactiveDeliveryPolicy>,
    owner_sources: Option<Vec<ReactiveOwnerSource>>,
}

impl PublishedReactiveProjection {
    fn empty(
        revision: u64,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
    ) -> Self {
        Self {
            revision,
            activation,
            evidence,
            context_view: None,
            cue_activation: None,
            session_delivery: None,
            critical_attention: None,
            integration_coverage: None,
            delivery_policy: None,
            owner_sources: None,
        }
    }

    fn missing_projection(&self) -> Option<&'static str> {
        if self.context_view.is_none() {
            return Some("context_view");
        }
        if self.cue_activation.is_none() {
            return Some("cue_activation");
        }
        if self.session_delivery.is_none() {
            return Some("session_delivery");
        }
        if self.critical_attention.is_none() {
            return Some("critical_attention");
        }
        if self.integration_coverage.is_none() {
            return Some("integration_coverage");
        }
        if self.delivery_policy.is_none() {
            return Some("delivery_policy");
        }
        if self.owner_sources.is_none() {
            return Some("owner_sources");
        }
        None
    }

    fn into_set(&self) -> Result<GovernorReactiveProjectionSet, ReactiveProjectionError> {
        if let Some(projection) = self.missing_projection() {
            return Err(ReactiveProjectionError::NotPublished { projection });
        }
        Ok(GovernorReactiveProjectionSet {
            context_view: self.context_view.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "context_view",
                },
            )?,
            cue_activation: self.cue_activation.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "cue_activation",
                },
            )?,
            session_delivery: self.session_delivery.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "session_delivery",
                },
            )?,
            critical_attention: self.critical_attention.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "critical_attention",
                },
            )?,
            integration_coverage: self.integration_coverage.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "integration_coverage",
                },
            )?,
            delivery_policy: self.delivery_policy.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "delivery_policy",
                },
            )?,
            owner_sources: self.owner_sources.clone().ok_or(
                ReactiveProjectionError::NotPublished {
                    projection: "owner_sources",
                },
            )?,
        })
    }
}

struct ReactiveProjectionState {
    state_fence: StateFence,
    published: Option<PublishedReactiveProjection>,
}

/// One rebuildable Governor owner for the six typed reactive projections.
///
/// The owner retains only the latest type-specific owner publications and their
/// evidence binding. Refreshing the authenticated Kernel generation clears the
/// partial set, so an old projection can never survive a State Fence change.
pub struct GovernorReactiveProjectionOwner {
    state: RwLock<ReactiveProjectionState>,
}

impl std::fmt::Debug for GovernorReactiveProjectionOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernorReactiveProjectionOwner")
            .finish_non_exhaustive()
    }
}

impl GovernorReactiveProjectionOwner {
    /// Creates an empty owner at one authenticated State Fence.
    pub(crate) fn new(state_fence: StateFence) -> Result<Self, ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner.state_fence",
            })?;
        Ok(Self {
            state: RwLock::new(ReactiveProjectionState {
                state_fence,
                published: None,
            }),
        })
    }

    /// Returns the latest set only when it belongs to the exact activation.
    pub fn read(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<GovernorReactiveProjectionSet, ReactiveProjectionError> {
        let state = self.read_state()?;
        if state.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "reactive_owner",
                field: "state_fence",
            });
        }
        let published = state
            .published
            .as_ref()
            .ok_or(ReactiveProjectionError::NotPublished {
                projection: "six_owner_projections",
            })?;
        if published.activation != *activation {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "reactive_owner",
                field: "activation",
            });
        }
        published.evidence.validate_against(activation)?;
        let projections = published.into_set()?;
        projections.validate_against(activation)?;
        Ok(projections)
    }

    /// Supplies the current A15 context view for one authenticated tick.
    pub fn read_context_view(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ContextPlanningView, ReactiveProjectionError> {
        Ok(self.read(activation)?.context_view)
    }

    /// Supplies the current A10 cue request/result pair for one tick.
    pub fn read_cue_activation(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveCueActivation, ReactiveProjectionError> {
        Ok(self.read(activation)?.cue_activation)
    }

    /// Supplies the session-owned delivery history for one tick.
    pub fn read_session_delivery(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<SessionDeliverySnapshot, ReactiveProjectionError> {
        Ok(self.read(activation)?.session_delivery)
    }

    /// Supplies the Governor attention projection for one tick.
    pub fn read_critical_attention(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<CriticalAttentionProjection, ReactiveProjectionError> {
        Ok(self.read(activation)?.critical_attention)
    }

    /// Supplies the verified host/runtime/interface coverage profile.
    pub fn read_integration_coverage(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveIntegrationCoverageProfile, ReactiveProjectionError> {
        Ok(self.read(activation)?.integration_coverage)
    }

    /// Supplies the owner-issued delivery policy for one exact plan.
    pub fn read_delivery_policy(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveDeliveryPolicy, ReactiveProjectionError> {
        Ok(self.read(activation)?.delivery_policy)
    }

    /// Supplies the retained cue/index rows used for admitted-record joins.
    pub fn read_owner_sources(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<Vec<ReactiveOwnerSource>, ReactiveProjectionError> {
        Ok(self.read(activation)?.owner_sources)
    }

    /// Returns whether a source is missing for this activation. Stale or
    /// malformed published state deliberately remains a hard read failure.
    pub fn is_published_for(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<bool, ReactiveProjectionError> {
        let state = self.read_state()?;
        match state.published.as_ref() {
            None => Ok(false),
            Some(published) if published.activation == *activation => {
                Ok(published.missing_projection().is_none())
            }
            Some(_) => Err(ReactiveProjectionError::StaleProjection {
                projection: "reactive_owner",
                field: "activation",
            }),
        }
    }

    pub(crate) fn publish_context_view(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        view: ContextPlanningView,
    ) -> Result<(), ReactiveProjectionError> {
        validate_context_view(&view, &activation)?;
        self.with_publication(activation, evidence, |published| {
            published.context_view = Some(view);
        })
    }

    pub(crate) fn publish_cue_activation(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        cue: ReactiveCueActivation,
    ) -> Result<(), ReactiveProjectionError> {
        cue.check_pair()
            .map_err(|error| invalid_projection("cue_activation", error))?;
        if cue.request.state_fence != activation.state_fence {
            return Err(stale_projection("cue_activation", "request.state_fence"));
        }
        self.with_publication(activation, evidence, |published| {
            published.cue_activation = Some(cue);
        })
    }

    pub(crate) fn publish_session_delivery(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        session: SessionDeliverySnapshot,
    ) -> Result<(), ReactiveProjectionError> {
        validate_session_delivery(&session, &activation)?;
        self.with_publication(activation, evidence, |published| {
            published.session_delivery = Some(session);
        })
    }

    pub(crate) fn publish_critical_attention(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        attention: CriticalAttentionProjection,
    ) -> Result<(), ReactiveProjectionError> {
        validate_critical_attention(&attention, &activation)?;
        self.with_publication(activation, evidence, |published| {
            published.critical_attention = Some(attention);
        })
    }

    pub(crate) fn publish_integration_coverage(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        coverage: ReactiveIntegrationCoverageProfile,
    ) -> Result<(), ReactiveProjectionError> {
        validate_integration_coverage(&coverage, &activation)?;
        self.with_publication(activation, evidence, |published| {
            published.integration_coverage = Some(coverage);
        })
    }

    pub(crate) fn publish_delivery_policy(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        policy: ReactiveDeliveryPolicy,
    ) -> Result<(), ReactiveProjectionError> {
        validate_delivery_policy(&policy, &activation)?;
        self.with_publication(activation, evidence, |published| {
            published.delivery_policy = Some(policy);
        })
    }

    pub(crate) fn publish_owner_sources(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        sources: Vec<ReactiveOwnerSource>,
    ) -> Result<(), ReactiveProjectionError> {
        if sources.len() > MAX_REACTIVE_OWNER_RECORDS {
            return Err(ReactiveProjectionError::OwnerSource(
                ReactiveOwnerProjectionError::Bound("projection.owner_sources"),
            ));
        }
        self.with_publication(activation, evidence, |published| {
            published.owner_sources = Some(sources);
        })
    }

    fn with_publication<F>(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        update: F,
    ) -> Result<(), ReactiveProjectionError>
    where
        F: FnOnce(&mut PublishedReactiveProjection),
    {
        evidence.validate_against(&activation)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        if state.state_fence != activation.state_fence {
            return Err(stale_projection("reactive_owner", "state_fence"));
        }
        let replace = state.published.as_ref().is_none_or(|published| {
            published.activation != activation || published.evidence != evidence
        });
        if replace {
            let revision = state
                .published
                .as_ref()
                .map_or(1, |published| published.revision.saturating_add(1));
            state.published = Some(PublishedReactiveProjection::empty(
                revision, activation, evidence,
            ));
        }
        let published = state
            .published
            .as_mut()
            .ok_or(ReactiveProjectionError::NotPublished {
                projection: "six_owner_projections",
            })?;
        update(published);
        Ok(())
    }

    pub(crate) fn reset(&self, state_fence: StateFence) -> Result<(), ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner.state_fence",
            })?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        state.state_fence = state_fence;
        state.published = None;
        Ok(())
    }

    fn read_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, ReactiveProjectionState>, ReactiveProjectionError> {
        self.state
            .read()
            .map_err(|_| ReactiveProjectionError::Poisoned)
    }
}

/// Build the accepted-evidence binding from the one retained Governor journal.
pub(crate) fn accepted_evidence_for(
    journal: &ObservationJournal,
    activation: &GovernorActivationSnapshot,
) -> Result<ReactiveAcceptedEvidence, ReactiveProjectionError> {
    let mut accepted = Vec::new();
    for entry in journal.snapshot() {
        let ObservationAdmissionResult::Accepted { receipt } = entry.result else {
            continue;
        };
        if receipt.state_fence != activation.state_fence {
            continue;
        }
        receipt.validate().map_err(|error| {
            ReactiveProjectionError::EvidenceCanonicalization(error.to_string())
        })?;
        let Some(event) = receipt.record.event.as_ref() else {
            continue;
        };
        if event.affected_scope.work_scope.as_str() != activation.work_scope_id
            || event.affected_scope.task_ref.as_deref() != Some(activation.task_id.as_str())
        {
            continue;
        }
        accepted.push(serde_json::to_value(receipt).map_err(|error| {
            ReactiveProjectionError::EvidenceCanonicalization(error.to_string())
        })?);
    }
    if accepted.is_empty() {
        return Err(ReactiveProjectionError::EvidenceUnavailable);
    }
    let bytes = canonical_json_bytes(&accepted)
        .map_err(|error| ReactiveProjectionError::EvidenceCanonicalization(error.to_string()))?;
    Ok(ReactiveAcceptedEvidence {
        task_id: activation.task_id.clone(),
        scope_id: activation.work_scope_id.clone(),
        state_fence: activation.state_fence.clone(),
        record_count: accepted.len(),
        digest: sha256_hex(&bytes),
    })
}

/// Validate the cue/index rows against the same accepted journal before the
/// six-projection set is published.
pub(crate) fn validate_owner_sources(
    journal: &ObservationJournal,
    activation: &GovernorActivationSnapshot,
    sources: &[ReactiveOwnerSource],
) -> Result<(), ReactiveProjectionError> {
    if sources.len() > MAX_REACTIVE_OWNER_RECORDS {
        return Err(ReactiveProjectionError::OwnerSource(
            ReactiveOwnerProjectionError::Bound("projection.owner_sources"),
        ));
    }
    let scope_id = WorkScopeId::new(activation.work_scope_id.clone()).map_err(|_| {
        ReactiveProjectionError::EvidenceBindingMismatch {
            field: "activation.work_scope_id",
        }
    })?;
    project_reactive_owner_from_sources(journal, &scope_id, &activation.state_fence, sources)
        .map(|_| ())
        .map_err(ReactiveProjectionError::OwnerSource)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    fn activation() -> GovernorActivationSnapshot {
        let state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::genesis(),
        );
        GovernorActivationSnapshot {
            state_fence,
            principal_id: "principal".to_owned(),
            session_id: "session".to_owned(),
            task_id: TaskId::new("task").expect("task"),
            work_unit_id: "work-unit".to_owned(),
            work_scope_id: "scope".to_owned(),
            task_revision: 1,
            plan_id: "plan".to_owned(),
            plan_revision: "1".to_owned(),
        }
    }

    #[test]
    fn unpublished_owner_withholds_without_an_empty_projection() {
        let live = activation();
        let owner =
            GovernorReactiveProjectionOwner::new(live.state_fence.clone()).expect("owner fence");
        assert!(!owner.is_published_for(&live).expect("status read"));
        assert!(matches!(
            owner.read(&live),
            Err(ReactiveProjectionError::NotPublished {
                projection: "six_owner_projections"
            })
        ));
    }

    #[test]
    fn partial_owner_publication_withholds_until_every_projection_exists() {
        let live = activation();
        let owner =
            GovernorReactiveProjectionOwner::new(live.state_fence.clone()).expect("owner fence");
        let evidence = ReactiveAcceptedEvidence {
            task_id: live.task_id.clone(),
            scope_id: live.work_scope_id.clone(),
            state_fence: live.state_fence.clone(),
            record_count: 1,
            digest: "0".repeat(64),
        };
        owner
            .publish_owner_sources(live.clone(), evidence, Vec::new())
            .expect("owner rows can be retained as an intermediate stage");
        assert!(!owner.is_published_for(&live).expect("status read"));
        assert!(matches!(
            owner.read(&live),
            Err(ReactiveProjectionError::NotPublished {
                projection: "context_view"
            })
        ));
    }

    #[test]
    fn refresh_reset_withholds_the_previous_activation() {
        let live = activation();
        let mut rotated = live.state_fence.clone();
        rotated.resource_generation = ResourceGeneration::new(2).expect("generation");
        let owner =
            GovernorReactiveProjectionOwner::new(live.state_fence.clone()).expect("owner fence");
        owner.reset(rotated.clone()).expect("reset");
        assert!(matches!(
            owner.read(&live),
            Err(ReactiveProjectionError::StaleProjection {
                projection: "reactive_owner",
                field: "state_fence"
            })
        ));
    }
}
