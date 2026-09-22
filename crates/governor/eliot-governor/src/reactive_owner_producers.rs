//! Governor-owned producers for the six reactive planning projections.
//!
//! The six values are produced by their semantic owners and retained here as
//! one fence/evidence-bound owner material set until the existing daemon
//! cadence consumes it.  This module does not derive a view, cue result,
//! delivery record, attention member, coverage event, policy, or atom join.
//! A missing owner output therefore remains a withheld feed.  The retained
//! values are rebuildable projections, not a queue or a second authority.

#![forbid(unsafe_code)]

use std::sync::{RwLock, RwLockReadGuard};

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection,
    IntegrationCoverageProfile as ReactiveIntegrationCoverageProfile, SessionDeliverySnapshot,
};
use eliot_contracts::StateFence;
use eliot_reactive_context_plan::{ReactiveCueActivation, ReactiveDeliveryPolicy};

use crate::composition::GovernorActivationSnapshot;
use crate::reactive_owner_projection::{MAX_REACTIVE_OWNER_RECORDS, ReactiveOwnerSource};
use crate::reactive_projections::{
    GovernorReactiveProjectionSet, ReactiveAcceptedEvidence, ReactiveProjectionError,
    validate_context_view, validate_critical_attention, validate_delivery_policy,
    validate_integration_coverage, validate_session_delivery,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProducerBinding {
    activation: GovernorActivationSnapshot,
    evidence: ReactiveAcceptedEvidence,
}

struct ReactiveOwnerProducerState {
    state_fence: StateFence,
    binding: Option<ProducerBinding>,
    context_view: Option<ContextPlanningView>,
    cue_activation: Option<ReactiveCueActivation>,
    session_delivery: Option<SessionDeliverySnapshot>,
    critical_attention: Option<CriticalAttentionProjection>,
    integration_coverage: Option<ReactiveIntegrationCoverageProfile>,
    delivery_policy: Option<ReactiveDeliveryPolicy>,
    owner_sources: Option<Vec<ReactiveOwnerSource>>,
}

impl ReactiveOwnerProducerState {
    fn empty(state_fence: StateFence) -> Self {
        Self {
            state_fence,
            binding: None,
            context_view: None,
            cue_activation: None,
            session_delivery: None,
            critical_attention: None,
            integration_coverage: None,
            delivery_policy: None,
            owner_sources: None,
        }
    }

    fn clear_values(&mut self) {
        self.binding = None;
        self.context_view = None;
        self.cue_activation = None;
        self.session_delivery = None;
        self.critical_attention = None;
        self.integration_coverage = None;
        self.delivery_policy = None;
        self.owner_sources = None;
    }

    fn ensure_binding(&mut self, binding: &ProducerBinding) {
        if self.binding.as_ref() != Some(binding) {
            self.clear_values();
            self.binding = Some(binding.clone());
        }
    }
}

/// Retains owner-issued reactive values until one cadence tick can consume all
/// six values atomically.
pub(crate) struct GovernorReactiveOwnerProducers {
    state: RwLock<ReactiveOwnerProducerState>,
}

impl std::fmt::Debug for GovernorReactiveOwnerProducers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernorReactiveOwnerProducers")
            .finish_non_exhaustive()
    }
}

impl GovernorReactiveOwnerProducers {
    pub(crate) fn new(state_fence: StateFence) -> Result<Self, ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner_producers.state_fence",
            })?;
        Ok(Self {
            state: RwLock::new(ReactiveOwnerProducerState::empty(state_fence)),
        })
    }

    /// Retain the actual A15/context-owner view for this activation.
    pub(crate) fn retain_context_view(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        view: ContextPlanningView,
    ) -> Result<(), ReactiveProjectionError> {
        validate_context_view(&view, &activation)?;
        self.install(activation, evidence, |state| {
            state.context_view = Some(view)
        })
    }

    /// Retain the actual A10 cue-owner request/result pair for this activation.
    pub(crate) fn retain_cue_activation(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        cue: ReactiveCueActivation,
    ) -> Result<(), ReactiveProjectionError> {
        cue.check_pair()
            .map_err(|error| ReactiveProjectionError::InvalidProjection {
                projection: "cue_activation",
                reason: error.to_string(),
            })?;
        if cue.request.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "cue_activation",
                field: "request.state_fence",
            });
        }
        self.install(activation, evidence, |state| {
            state.cue_activation = Some(cue)
        })
    }

    /// Retain the session owner's actual delivery history for this session.
    pub(crate) fn retain_session_delivery(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        session: SessionDeliverySnapshot,
    ) -> Result<(), ReactiveProjectionError> {
        validate_session_delivery(&session, &activation)?;
        self.install(activation, evidence, |state| {
            state.session_delivery = Some(session)
        })
    }

    /// Retain the actual attention-owner projection, including unresolved
    /// members and explicit missing-coverage evidence.
    pub(crate) fn retain_critical_attention(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        attention: CriticalAttentionProjection,
    ) -> Result<(), ReactiveProjectionError> {
        validate_critical_attention(&attention, &activation)?;
        self.install(activation, evidence, |state| {
            state.critical_attention = Some(attention)
        })
    }

    /// Retain actual host/runtime/interface coverage.  A coverage label or
    /// the separate Governor derivation is not accepted as this projection.
    pub(crate) fn retain_integration_coverage(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        coverage: ReactiveIntegrationCoverageProfile,
    ) -> Result<(), ReactiveProjectionError> {
        validate_integration_coverage(&coverage, &activation)?;
        self.install(activation, evidence, |state| {
            state.integration_coverage = Some(coverage)
        })
    }

    /// Retain the exact policy assembled by the policy owner for this plan.
    pub(crate) fn retain_delivery_policy(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        policy: ReactiveDeliveryPolicy,
    ) -> Result<(), ReactiveProjectionError> {
        validate_delivery_policy(&policy, &activation)?;
        self.install(activation, evidence, |state| {
            state.delivery_policy = Some(policy)
        })
    }

    /// Retain the cue/context owner's explicit admitted-record rows and
    /// target-to-atom joins.  Journal correlation is performed by the
    /// composition before the complete set reaches the consumer.
    pub(crate) fn retain_owner_sources(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        sources: Vec<ReactiveOwnerSource>,
    ) -> Result<(), ReactiveProjectionError> {
        if sources.len() > MAX_REACTIVE_OWNER_RECORDS {
            return Err(ReactiveProjectionError::OwnerSource(
                crate::reactive_owner_projection::ReactiveOwnerProjectionError::Bound(
                    "projection.owner_sources",
                ),
            ));
        }
        self.install(activation, evidence, |state| {
            state.owner_sources = Some(sources)
        })
    }

    /// Stage a complete owner-produced set in one call.  This is used when an
    /// owner lane already has all six values and preserves the same atomic
    /// production semantics as the per-owner methods.
    pub(crate) fn retain_projection_set(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        projections: GovernorReactiveProjectionSet,
    ) -> Result<(), ReactiveProjectionError> {
        projections.validate_against(&activation)?;
        self.install(activation, evidence, |state| {
            state.context_view = Some(projections.context_view);
            state.cue_activation = Some(projections.cue_activation);
            state.session_delivery = Some(projections.session_delivery);
            state.critical_attention = Some(projections.critical_attention);
            state.integration_coverage = Some(projections.integration_coverage);
            state.delivery_policy = Some(projections.delivery_policy);
            state.owner_sources = Some(projections.owner_sources);
        })
    }

    /// Return a complete set only when every retained output has the exact
    /// current activation and accepted-evidence binding.
    pub(crate) fn ready_for(
        &self,
        activation: &GovernorActivationSnapshot,
        evidence: &ReactiveAcceptedEvidence,
    ) -> Result<Option<GovernorReactiveProjectionSet>, ReactiveProjectionError> {
        let state = self.read_state()?;
        if state.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_producers",
                field: "state_fence",
            });
        }
        let Some(binding) = state.binding.as_ref() else {
            return Ok(None);
        };
        let expected = ProducerBinding {
            activation: activation.clone(),
            evidence: evidence.clone(),
        };
        if binding != &expected {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_producers",
                field: "owner_binding",
            });
        }
        let (
            Some(context_view),
            Some(cue_activation),
            Some(session_delivery),
            Some(critical_attention),
            Some(integration_coverage),
            Some(delivery_policy),
            Some(owner_sources),
        ) = (
            state.context_view.clone(),
            state.cue_activation.clone(),
            state.session_delivery.clone(),
            state.critical_attention.clone(),
            state.integration_coverage.clone(),
            state.delivery_policy.clone(),
            state.owner_sources.clone(),
        )
        else {
            return Ok(None);
        };
        let projections = GovernorReactiveProjectionSet {
            context_view,
            cue_activation,
            session_delivery,
            critical_attention,
            integration_coverage,
            delivery_policy,
            owner_sources,
        };
        projections.validate_against(activation)?;
        Ok(Some(projections))
    }

    pub(crate) fn reset(&self, state_fence: StateFence) -> Result<(), ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner_producers.state_fence",
            })?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        *state = ReactiveOwnerProducerState::empty(state_fence);
        Ok(())
    }

    fn install<F>(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        update: F,
    ) -> Result<(), ReactiveProjectionError>
    where
        F: FnOnce(&mut ReactiveOwnerProducerState),
    {
        evidence.validate_against(&activation)?;
        let binding = ProducerBinding {
            activation,
            evidence,
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        if state.state_fence != binding.activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_producers",
                field: "state_fence",
            });
        }
        state.ensure_binding(&binding);
        update(&mut state);
        Ok(())
    }

    fn read_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, ReactiveOwnerProducerState>, ReactiveProjectionError> {
        self.state
            .read()
            .map_err(|_| ReactiveProjectionError::Poisoned)
    }
}
