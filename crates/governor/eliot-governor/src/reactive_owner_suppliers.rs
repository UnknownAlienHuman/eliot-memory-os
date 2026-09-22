//! Governor-owned suppliers for the six reactive planning projections.
//!
//! This module is the owner-facing ingress and read boundary for the daemon's
//! reactive source.  It is deliberately separate from the older publication
//! compatibility owner: the scheduler prepares an exact activation/evidence
//! tick, then reads the values retained by the named semantic owners.  A
//! missing owner value remains missing; this module never constructs a
//! default, acceptance, identity, or ready state.

#![forbid(unsafe_code)]

use std::sync::{RwLock, RwLockReadGuard};

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection,
    IntegrationCoverageProfile as ReactiveIntegrationCoverageProfile, SessionDeliverySnapshot,
};
use eliot_contracts::StateFence;
use eliot_reactive_context_plan::{ReactiveCueActivation, ReactiveDeliveryPolicy};

use crate::composition::GovernorActivationSnapshot;
use crate::reactive_owner_projection::ReactiveOwnerSource;
use crate::reactive_projections::{
    GovernorReactiveProjectionSet, ReactiveAcceptedEvidence, ReactiveProjectionError,
    validate_context_view, validate_critical_attention, validate_delivery_policy,
    validate_integration_coverage, validate_session_delivery,
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnerBinding {
    activation: GovernorActivationSnapshot,
    evidence: ReactiveAcceptedEvidence,
}

#[derive(Clone, Debug)]
struct BoundOwnerValue<T> {
    binding: OwnerBinding,
    value: T,
}

struct ReactiveOwnerSupplierState {
    state_fence: StateFence,
    binding: Option<OwnerBinding>,
    prepared_tick: Option<OwnerBinding>,
    context_view: Option<BoundOwnerValue<ContextPlanningView>>,
    cue_activation: Option<BoundOwnerValue<ReactiveCueActivation>>,
    session_delivery: Option<BoundOwnerValue<SessionDeliverySnapshot>>,
    critical_attention: Option<BoundOwnerValue<CriticalAttentionProjection>>,
    integration_coverage: Option<BoundOwnerValue<ReactiveIntegrationCoverageProfile>>,
    delivery_policy: Option<BoundOwnerValue<ReactiveDeliveryPolicy>>,
    owner_sources: Option<BoundOwnerValue<Vec<ReactiveOwnerSource>>>,
}

impl ReactiveOwnerSupplierState {
    fn empty(state_fence: StateFence) -> Self {
        Self {
            state_fence,
            binding: None,
            prepared_tick: None,
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
        self.prepared_tick = None;
        self.context_view = None;
        self.cue_activation = None;
        self.session_delivery = None;
        self.critical_attention = None;
        self.integration_coverage = None;
        self.delivery_policy = None;
        self.owner_sources = None;
    }

    fn ensure_binding(&mut self, binding: &OwnerBinding) {
        if self.binding.as_ref() != Some(binding) {
            self.clear_values();
            self.binding = Some(binding.clone());
        }
    }
}

/// One read-only Governor supplier set for the six A4 inputs.
///
/// The values are owner outputs, not planner inputs manufactured by the
/// daemon.  An owner records a typed value only after Governor has bound it to
/// the current task/session/scope/fence and accepted-evidence digest.  The
/// daemon then prepares the same binding immediately before its scheduling
/// read.  This makes a changed evidence set or activation stale without
/// keeping a second journal or scheduler.
pub struct GovernorReactiveOwnerSuppliers {
    state: RwLock<ReactiveOwnerSupplierState>,
}

impl std::fmt::Debug for GovernorReactiveOwnerSuppliers {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GovernorReactiveOwnerSuppliers")
            .finish_non_exhaustive()
    }
}

impl GovernorReactiveOwnerSuppliers {
    /// Creates an empty supplier set at one authenticated State Fence.
    pub(crate) fn new(state_fence: StateFence) -> Result<Self, ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner_suppliers.state_fence",
            })?;
        Ok(Self {
            state: RwLock::new(ReactiveOwnerSupplierState::empty(state_fence)),
        })
    }

    /// Binds the scheduler's current tick to the exact accepted evidence.
    ///
    /// This must run immediately before the daemon reads the six suppliers.
    /// It does not make any projection available by itself.
    pub(crate) fn prepare_tick(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
    ) -> Result<(), ReactiveProjectionError> {
        evidence.validate_against(&activation)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        if state.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_suppliers",
                field: "state_fence",
            });
        }
        state.prepared_tick = Some(OwnerBinding {
            activation,
            evidence,
        });
        Ok(())
    }

    /// Read all six owner projections and the retained cue/index rows for the
    /// prepared tick.  Every slot is checked against the same binding.
    pub fn read(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<GovernorReactiveProjectionSet, ReactiveProjectionError> {
        let state = self.read_state()?;
        if state.state_fence != activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_suppliers",
                field: "state_fence",
            });
        }
        let prepared =
            state
                .prepared_tick
                .as_ref()
                .ok_or(ReactiveProjectionError::NotPublished {
                    projection: "reactive_tick",
                })?;
        if prepared.activation != *activation {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_suppliers",
                field: "activation",
            });
        }
        prepared.evidence.validate_against(activation)?;
        let binding = OwnerBinding {
            activation: activation.clone(),
            evidence: prepared.evidence.clone(),
        };
        let projections = GovernorReactiveProjectionSet {
            context_view: value_for(&state.context_view, &binding, "context_view")?,
            cue_activation: value_for(&state.cue_activation, &binding, "cue_activation")?,
            session_delivery: value_for(&state.session_delivery, &binding, "session_delivery")?,
            critical_attention: value_for(
                &state.critical_attention,
                &binding,
                "critical_attention",
            )?,
            integration_coverage: value_for(
                &state.integration_coverage,
                &binding,
                "integration_coverage",
            )?,
            delivery_policy: value_for(&state.delivery_policy, &binding, "delivery_policy")?,
            owner_sources: value_for(&state.owner_sources, &binding, "owner_sources")?,
        };
        projections.validate_against(activation)?;
        Ok(projections)
    }

    /// Reports whether all six owner values and owner rows are available for
    /// the prepared activation.  A missing value is a normal withholding
    /// state; stale state remains a hard error.
    pub fn is_ready_for(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<bool, ReactiveProjectionError> {
        match self.read(activation) {
            Ok(_) => Ok(true),
            Err(ReactiveProjectionError::NotPublished { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn read_context_view(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ContextPlanningView, ReactiveProjectionError> {
        Ok(self.read(activation)?.context_view)
    }

    pub fn read_cue_activation(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveCueActivation, ReactiveProjectionError> {
        Ok(self.read(activation)?.cue_activation)
    }

    pub fn read_session_delivery(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<SessionDeliverySnapshot, ReactiveProjectionError> {
        Ok(self.read(activation)?.session_delivery)
    }

    pub fn read_critical_attention(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<CriticalAttentionProjection, ReactiveProjectionError> {
        Ok(self.read(activation)?.critical_attention)
    }

    pub fn read_integration_coverage(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveIntegrationCoverageProfile, ReactiveProjectionError> {
        Ok(self.read(activation)?.integration_coverage)
    }

    pub fn read_delivery_policy(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ReactiveDeliveryPolicy, ReactiveProjectionError> {
        Ok(self.read(activation)?.delivery_policy)
    }

    pub fn read_owner_sources(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<Vec<ReactiveOwnerSource>, ReactiveProjectionError> {
        Ok(self.read(activation)?.owner_sources)
    }

    pub(crate) fn install_context_view(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        view: ContextPlanningView,
    ) -> Result<(), ReactiveProjectionError> {
        validate_context_view(&view, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.context_view = Some(BoundOwnerValue {
                binding,
                value: view,
            });
        })
    }

    pub(crate) fn install_cue_activation(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        cue: ReactiveCueActivation,
    ) -> Result<(), ReactiveProjectionError> {
        validate_cue_activation_without_view(&cue, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.cue_activation = Some(BoundOwnerValue {
                binding,
                value: cue,
            });
        })
    }

    pub(crate) fn install_session_delivery(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        session: SessionDeliverySnapshot,
    ) -> Result<(), ReactiveProjectionError> {
        validate_session_delivery(&session, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.session_delivery = Some(BoundOwnerValue {
                binding,
                value: session,
            });
        })
    }

    pub(crate) fn install_critical_attention(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        attention: CriticalAttentionProjection,
    ) -> Result<(), ReactiveProjectionError> {
        validate_critical_attention(&attention, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.critical_attention = Some(BoundOwnerValue {
                binding,
                value: attention,
            });
        })
    }

    pub(crate) fn install_integration_coverage(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        coverage: ReactiveIntegrationCoverageProfile,
    ) -> Result<(), ReactiveProjectionError> {
        validate_integration_coverage(&coverage, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.integration_coverage = Some(BoundOwnerValue {
                binding,
                value: coverage,
            });
        })
    }

    pub(crate) fn install_delivery_policy(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        policy: ReactiveDeliveryPolicy,
    ) -> Result<(), ReactiveProjectionError> {
        validate_delivery_policy(&policy, &activation)?;
        self.install(activation, evidence, |state, binding| {
            state.delivery_policy = Some(BoundOwnerValue {
                binding,
                value: policy,
            });
        })
    }

    pub(crate) fn install_owner_sources(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        sources: Vec<ReactiveOwnerSource>,
    ) -> Result<(), ReactiveProjectionError> {
        if sources.len() > crate::reactive_owner_projection::MAX_REACTIVE_OWNER_RECORDS {
            return Err(ReactiveProjectionError::OwnerSource(
                crate::reactive_owner_projection::ReactiveOwnerProjectionError::Bound(
                    "projection.owner_sources",
                ),
            ));
        }
        self.install(activation, evidence, |state, binding| {
            state.owner_sources = Some(BoundOwnerValue {
                binding,
                value: sources,
            });
        })
    }

    pub(crate) fn reset(&self, state_fence: StateFence) -> Result<(), ReactiveProjectionError> {
        state_fence
            .validate()
            .map_err(|_| ReactiveProjectionError::EvidenceBindingMismatch {
                field: "owner_suppliers.state_fence",
            })?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        *state = ReactiveOwnerSupplierState::empty(state_fence);
        Ok(())
    }

    fn install<F>(
        &self,
        activation: GovernorActivationSnapshot,
        evidence: ReactiveAcceptedEvidence,
        update: F,
    ) -> Result<(), ReactiveProjectionError>
    where
        F: FnOnce(&mut ReactiveOwnerSupplierState, OwnerBinding),
    {
        evidence.validate_against(&activation)?;
        let binding = OwnerBinding {
            activation,
            evidence,
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| ReactiveProjectionError::Poisoned)?;
        if state.state_fence != binding.activation.state_fence {
            return Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_suppliers",
                field: "state_fence",
            });
        }
        state.ensure_binding(&binding);
        update(&mut state, binding);
        Ok(())
    }

    fn read_state(
        &self,
    ) -> Result<RwLockReadGuard<'_, ReactiveOwnerSupplierState>, ReactiveProjectionError> {
        self.state
            .read()
            .map_err(|_| ReactiveProjectionError::Poisoned)
    }
}

fn value_for<T: Clone>(
    value: &Option<BoundOwnerValue<T>>,
    binding: &OwnerBinding,
    projection: &'static str,
) -> Result<T, ReactiveProjectionError> {
    let value = value
        .as_ref()
        .ok_or(ReactiveProjectionError::NotPublished { projection })?;
    if value.binding != *binding {
        return Err(ReactiveProjectionError::StaleProjection {
            projection,
            field: "owner_binding",
        });
    }
    Ok(value.value.clone())
}

fn validate_cue_activation_without_view(
    cue: &ReactiveCueActivation,
    activation: &GovernorActivationSnapshot,
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, TaskId};
    use std::num::NonZeroU64;

    fn activation(generation: u64) -> GovernorActivationSnapshot {
        let state_fence = StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(generation).expect("generation"),
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
    fn absent_owner_withholds_and_refresh_reset_invalidates_old_binding() {
        let live = activation(1);
        let supplier =
            GovernorReactiveOwnerSuppliers::new(live.state_fence.clone()).expect("supplier fence");
        supplier
            .prepare_tick(
                live.clone(),
                crate::reactive_projections::test_accepted_evidence(&live),
            )
            .expect("prepare authenticated tick");

        assert!(!supplier.is_ready_for(&live).expect("read readiness"));
        assert!(matches!(
            supplier.read(&live),
            Err(ReactiveProjectionError::NotPublished {
                projection: "context_view"
            })
        ));

        let rotated = activation(2).state_fence;
        supplier.reset(rotated).expect("refresh reset");
        assert!(matches!(
            supplier.read(&live),
            Err(ReactiveProjectionError::StaleProjection {
                projection: "owner_suppliers",
                field: "state_fence"
            })
        ));
    }
}
