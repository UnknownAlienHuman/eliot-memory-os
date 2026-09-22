//! Daemon-side reactive feed supplier (composition wiring).
//!
//! Projects the plan lane's [`LiveActivationBindings`] port from the
//! Governor's authenticated activation snapshot and drives sealed owner
//! projections through [`drive_live_feed`]. The settled outcome feeds A1's
//! `admit_producer_feed` transport call (bridge lane) with the live
//! Governor derivation; that admit call, the derivation retention, and the
//! transport replay window stay with the bridge lane.
//!
//! Authority boundaries (this module invents nothing):
//!
//! ```text
//! governor owns:  activation snapshot truth (coordination/session/task/
//!                 scope/canonical owners under the live fence), risk
//!                 derivation, attention/conflict/problem semantics,
//!                 context/evidence admission decisions.
//! cue lane owns:  observation minting, normalization, index sealing,
//!                 activation evaluation.
//! context assembly owns: admitted-set retention, recipe/quality/measurement,
//!                 active-view assembly.
//! bridge owns (A1): session ledger, delivery history, receipts, admission.
//! this module owns: snapshot-to-bindings projection, liveness-gated drive
//!                 composition. No retained state, no ledger, no minted
//!                 identities, no planning semantics.
//! ```
//!
//! The runtime source is deliberately owner-shaped: each six-input method is
//! called for the fresh authenticated activation, and the returned values are
//! validated before the planner runs. Current main has no registered source
//! for those typed projections yet; the scheduler therefore reports an
//! explicit unconfigured state and never fills the gap with an empty view,
//! policy, receipt, or queue. A3's Kernel/resource expansion and the A4
//! owning lanes can register their concrete source through the public seam.

#![allow(clippy::result_large_err)]

use std::sync::Arc;

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection, IntegrationCoverageProfile,
    SessionDeliverySnapshot,
};
use eliot_contracts::{ArtifactId, SessionId};
use eliot_governor::{
    GovernorActivationSnapshot, GovernorReactiveProjectionOwner, ReactiveObservationCueProjection,
    ReactiveOwnerProjection, ReactiveOwnerProjectionError, ReactiveOwnerSource,
    project_reactive_owner_from_sources,
};
use eliot_observation::ObservationJournal;
use eliot_reactive_context_plan::{
    LiveActivationBindings, SettledPlanFeedError, SettledPlanFeedInputs, SettledPlanFeedOutcome,
    drive_live_feed,
};
use eliot_receipts::WorkScopeId;

/// Fail-closed supplier errors. Projection defects abort the drive; feed
/// errors pass through untouched so the planner/producer vocabulary stays
/// exact across the composition boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveFeedSupplyError {
    /// A snapshot string was rejected by its validated identity
    /// constructor: the snapshot never becomes bindings, the planner never
    /// runs. `field` names the rejected snapshot field.
    InvalidSnapshotBinding { field: &'static str, reason: String },
    /// The Governor journal or an owner-issued cue/atom row failed its
    /// fail-closed projection checks.
    OwnerProjection(ReactiveOwnerProjectionError),
    /// The A4 feed contained a cue or atom binding that was not present in the
    /// same current owner projection.
    OwnerFeedBindingMismatch { field: &'static str },
    /// A named owner could not supply one of the six typed feed projections.
    OwnerRead {
        projection: &'static str,
        reason: String,
    },
    /// The one registered Governor owner has not received all six real
    /// projections for this activation. The scheduler withholds the tick;
    /// it does not manufacture an empty plan or treat the source as absent.
    OwnerWithheld {
        projection: &'static str,
        reason: String,
    },
    /// A supplied owner projection failed its own contract validation.
    OwnerInputInvalid {
        projection: &'static str,
        reason: String,
    },
    /// A supplied owner projection is valid in isolation but belongs to a
    /// different authenticated activation.
    OwnerInputStale {
        projection: &'static str,
        field: &'static str,
    },
    /// The liveness gate, planner, or producer reported; carried verbatim.
    Feed(SettledPlanFeedError),
}

impl std::fmt::Display for ReactiveFeedSupplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSnapshotBinding { field, reason } => write!(
                formatter,
                "reactive feed snapshot binding {field} rejected: {reason}"
            ),
            Self::OwnerProjection(error) => write!(formatter, "reactive owner projection: {error}"),
            Self::OwnerFeedBindingMismatch { field } => {
                write!(formatter, "reactive feed owner binding mismatch: {field}")
            }
            Self::OwnerRead { projection, reason } => {
                write!(
                    formatter,
                    "reactive feed owner read {projection} failed: {reason}"
                )
            }
            Self::OwnerWithheld { projection, reason } => write!(
                formatter,
                "reactive feed owner {projection} is withheld: {reason}"
            ),
            Self::OwnerInputInvalid { projection, reason } => write!(
                formatter,
                "reactive feed owner projection {projection} is invalid: {reason}"
            ),
            Self::OwnerInputStale { projection, field } => write!(
                formatter,
                "reactive feed owner projection {projection} is stale at {field}"
            ),
            Self::Feed(error) => write!(formatter, "reactive feed: {error}"),
        }
    }
}

impl std::error::Error for ReactiveFeedSupplyError {}

/// Read-only owner source for the six typed inputs required by the A4
/// planner. Each method must read the retained projection from its owning
/// lane; this boundary does not construct a projection, seal a digest, or
/// substitute an empty value.
pub trait ReactiveFeedOwnerSource: Send + Sync {
    /// Reports a truthful absence before individual projection reads. Existing
    /// external sources default to `Ready`; the Governor adapter uses this to
    /// distinguish an unpublished owner set from malformed/stale state.
    fn availability(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> ReactiveFeedOwnerAvailability {
        ReactiveFeedOwnerAvailability::Ready
    }
    /// Read the assembled A15 context view for the exact activation.
    fn read_context_view(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ContextPlanningView, String>;
    /// Read the retained A10 request/result pair for the exact activation.
    fn read_cue_activation(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveCueActivation, String>;
    /// Read the immutable A1/session delivery history for the exact activation.
    fn read_session_snapshot(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<SessionDeliverySnapshot, String>;
    /// Read the current Critical Attention projection for the exact activation.
    fn read_critical_attention(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<CriticalAttentionProjection, String>;
    /// Read the current verified coverage/watchdog/trace profile for the exact activation.
    fn read_integration_coverage(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<IntegrationCoverageProfile, String>;
    /// Read the owner-issued delivery policy for the exact activation.
    fn read_policy(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveDeliveryPolicy, String>;
    /// Read the admitted observation/cue/index rows used by the Governor
    /// journal projection. Rows remain owner output; this method does not
    /// turn cue targets into atom identities.
    fn read_owner_sources(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<Vec<ReactiveOwnerSource>, String>;
}

/// Read status of the one registered owner source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReactiveFeedOwnerAvailability {
    /// A read may proceed. A later read can still fail closed for stale data.
    Ready,
    /// The owner has no current six-projection publication yet.
    Withheld {
        projection: &'static str,
        reason: String,
    },
}

/// Concrete daemon adapter over the Governor's retained six-projection owner.
///
/// It reads one clone of the owner publication for each typed method; the
/// owner validates the same activation on every read. This adapter retains no
/// queue, source history, planner state, or receipt authority.
pub struct GovernorReactiveFeedSource {
    owner: Arc<GovernorReactiveProjectionOwner>,
}

impl GovernorReactiveFeedSource {
    /// Installs the read-only adapter over the Governor owner.
    #[must_use]
    pub fn new(owner: Arc<GovernorReactiveProjectionOwner>) -> Self {
        Self { owner }
    }
}

impl ReactiveFeedOwnerSource for GovernorReactiveFeedSource {
    fn availability(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> ReactiveFeedOwnerAvailability {
        match self.owner.is_published_for(activation) {
            Ok(true) => ReactiveFeedOwnerAvailability::Ready,
            Ok(false) => ReactiveFeedOwnerAvailability::Withheld {
                projection: "six_owner_projections",
                reason: "no current owner publication".to_owned(),
            },
            Err(_error) => ReactiveFeedOwnerAvailability::Ready,
        }
    }

    fn read_context_view(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<ContextPlanningView, String> {
        self.owner
            .read_context_view(activation)
            .map_err(|error| error.to_string())
    }

    fn read_cue_activation(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveCueActivation, String> {
        self.owner
            .read_cue_activation(activation)
            .map_err(|error| error.to_string())
    }

    fn read_session_snapshot(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<SessionDeliverySnapshot, String> {
        self.owner
            .read_session_delivery(activation)
            .map_err(|error| error.to_string())
    }

    fn read_critical_attention(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<CriticalAttentionProjection, String> {
        self.owner
            .read_critical_attention(activation)
            .map_err(|error| error.to_string())
    }

    fn read_integration_coverage(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<IntegrationCoverageProfile, String> {
        self.owner
            .read_integration_coverage(activation)
            .map_err(|error| error.to_string())
    }

    fn read_policy(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveDeliveryPolicy, String> {
        self.owner
            .read_delivery_policy(activation)
            .map_err(|error| error.to_string())
    }

    fn read_owner_sources(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<Vec<ReactiveOwnerSource>, String> {
        self.owner
            .read_owner_sources(activation)
            .map_err(|error| error.to_string())
    }
}

/// One immutable set of owner outputs captured for one authenticated tick.
///
/// The snapshot is a transport-free composition value. It is not retained by
/// the daemon and it owns no queue or receipt. `validate` binds every typed
/// projection to the Governor activation before `drive_live_feed` is called.
#[derive(Clone, Debug)]
pub struct ReactiveFeedOwnerSnapshot {
    /// Owner-issued admitted observation/cue/index rows.
    pub owner_sources: Vec<ReactiveOwnerSource>,
    /// Owner-issued A15 context view.
    pub view: ContextPlanningView,
    /// Owner-issued A10 cue activation.
    pub cue_activation: eliot_reactive_context_plan::ReactiveCueActivation,
    /// Owner-issued session delivery history.
    pub session_snapshot: SessionDeliverySnapshot,
    /// Owner-issued Critical Attention projection.
    pub critical_attention: CriticalAttentionProjection,
    /// Owner-issued integration coverage profile.
    pub integration_coverage: IntegrationCoverageProfile,
    /// Owner-issued delivery policy.
    pub policy: eliot_reactive_context_plan::ReactiveDeliveryPolicy,
}

impl ReactiveFeedOwnerSnapshot {
    /// Read all six projections and the admitted owner rows from one source,
    /// then validate their exact joins against the authenticated activation.
    pub fn read_from(
        activation: &GovernorActivationSnapshot,
        source: &dyn ReactiveFeedOwnerSource,
    ) -> Result<Self, ReactiveFeedSupplyError> {
        if let ReactiveFeedOwnerAvailability::Withheld { projection, reason } =
            source.availability(activation)
        {
            return Err(ReactiveFeedSupplyError::OwnerWithheld { projection, reason });
        }
        let snapshot = Self {
            owner_sources: source.read_owner_sources(activation).map_err(|reason| {
                ReactiveFeedSupplyError::OwnerRead {
                    projection: "admitted_owner_sources",
                    reason,
                }
            })?,
            view: source.read_context_view(activation).map_err(|reason| {
                ReactiveFeedSupplyError::OwnerRead {
                    projection: "context_view",
                    reason,
                }
            })?,
            cue_activation: source.read_cue_activation(activation).map_err(|reason| {
                ReactiveFeedSupplyError::OwnerRead {
                    projection: "cue_activation",
                    reason,
                }
            })?,
            session_snapshot: source.read_session_snapshot(activation).map_err(|reason| {
                ReactiveFeedSupplyError::OwnerRead {
                    projection: "session_snapshot",
                    reason,
                }
            })?,
            critical_attention: source
                .read_critical_attention(activation)
                .map_err(|reason| ReactiveFeedSupplyError::OwnerRead {
                    projection: "critical_attention",
                    reason,
                })?,
            integration_coverage: source.read_integration_coverage(activation).map_err(
                |reason| ReactiveFeedSupplyError::OwnerRead {
                    projection: "integration_coverage",
                    reason,
                },
            )?,
            policy: source.read_policy(activation).map_err(|reason| {
                ReactiveFeedSupplyError::OwnerRead {
                    projection: "policy",
                    reason,
                }
            })?,
        };
        snapshot.validate(activation)?;
        Ok(snapshot)
    }

    /// Validate every owner contract and its activation binding.
    pub fn validate(
        &self,
        activation: &GovernorActivationSnapshot,
    ) -> Result<(), ReactiveFeedSupplyError> {
        self.view
            .validate()
            .map_err(|error| owner_input_invalid("context_view", error))?;
        self.cue_activation
            .validate_against(&self.view)
            .map_err(|error| owner_input_invalid("cue_activation", error))?;
        self.session_snapshot
            .validate()
            .map_err(|error| owner_input_invalid("session_snapshot", error))?;
        self.critical_attention
            .validate()
            .map_err(|error| owner_input_invalid("critical_attention", error))?;
        self.integration_coverage
            .validate()
            .map_err(|error| owner_input_invalid("integration_coverage", error))?;
        self.policy
            .validate()
            .map_err(|error| owner_input_invalid("policy", error))?;

        let binding = &self.view.view.binding;
        if binding.task_id != activation.task_id {
            return Err(owner_input_stale("context_view", "view.binding.task_id"));
        }
        if binding.scope_id.as_str() != activation.work_scope_id {
            return Err(owner_input_stale("context_view", "view.binding.scope_id"));
        }
        if binding.state_fence != activation.state_fence {
            return Err(owner_input_stale(
                "context_view",
                "view.binding.state_fence",
            ));
        }
        if self.cue_activation.request.state_fence != activation.state_fence {
            return Err(owner_input_stale("cue_activation", "request.state_fence"));
        }
        if self.session_snapshot.session_id.as_str() != activation.session_id {
            return Err(owner_input_stale("session_snapshot", "session_id"));
        }
        if self.session_snapshot.task_id != activation.task_id {
            return Err(owner_input_stale("session_snapshot", "task_id"));
        }
        if self.session_snapshot.scope_id.as_str() != activation.work_scope_id {
            return Err(owner_input_stale("session_snapshot", "scope_id"));
        }
        if self.session_snapshot.state_fence != activation.state_fence {
            return Err(owner_input_stale("session_snapshot", "state_fence"));
        }
        if self.critical_attention.task_id != activation.task_id {
            return Err(owner_input_stale("critical_attention", "task_id"));
        }
        if self.critical_attention.scope_id.as_str() != activation.work_scope_id {
            return Err(owner_input_stale("critical_attention", "scope_id"));
        }
        if self.critical_attention.state_fence != activation.state_fence {
            return Err(owner_input_stale("critical_attention", "state_fence"));
        }
        if self.integration_coverage.state_fence != activation.state_fence {
            return Err(owner_input_stale("integration_coverage", "state_fence"));
        }
        if self.policy.plan_id.as_str() != activation.plan_id {
            return Err(owner_input_stale("policy", "plan_id"));
        }
        Ok(())
    }

    /// Borrow the six projections in the exact input shape consumed by A4.
    #[must_use]
    pub fn inputs(&self) -> SettledPlanFeedInputs<'_> {
        SettledPlanFeedInputs {
            view: &self.view,
            cue_activation: &self.cue_activation,
            session_snapshot: &self.session_snapshot,
            critical_attention: &self.critical_attention,
            integration_coverage: &self.integration_coverage,
            policy: &self.policy,
        }
    }
}

/// Concrete adapter over already-retained owner projections.
///
/// This is useful at a composition seam where the owning lanes already hold
/// the six values. It only clones those exact values for one tick; it never
/// constructs a default, recomputes a digest, or records a receipt.
pub struct BorrowedReactiveFeedOwner<'a> {
    /// Retained A15 view owner output.
    pub view: &'a ContextPlanningView,
    /// Retained A10 cue owner output.
    pub cue_activation: &'a eliot_reactive_context_plan::ReactiveCueActivation,
    /// Retained session owner output.
    pub session_snapshot: &'a SessionDeliverySnapshot,
    /// Retained Attention owner output.
    pub critical_attention: &'a CriticalAttentionProjection,
    /// Retained coverage owner output.
    pub integration_coverage: &'a IntegrationCoverageProfile,
    /// Retained policy owner output.
    pub policy: &'a eliot_reactive_context_plan::ReactiveDeliveryPolicy,
    /// Retained admitted observation/cue/index rows.
    pub owner_sources: &'a [ReactiveOwnerSource],
}

impl ReactiveFeedOwnerSource for BorrowedReactiveFeedOwner<'_> {
    fn read_context_view(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<ContextPlanningView, String> {
        Ok(self.view.clone())
    }

    fn read_cue_activation(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveCueActivation, String> {
        Ok(self.cue_activation.clone())
    }

    fn read_session_snapshot(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<SessionDeliverySnapshot, String> {
        Ok(self.session_snapshot.clone())
    }

    fn read_critical_attention(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<CriticalAttentionProjection, String> {
        Ok(self.critical_attention.clone())
    }

    fn read_integration_coverage(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<IntegrationCoverageProfile, String> {
        Ok(self.integration_coverage.clone())
    }

    fn read_policy(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<eliot_reactive_context_plan::ReactiveDeliveryPolicy, String> {
        Ok(self.policy.clone())
    }

    fn read_owner_sources(
        &self,
        _activation: &GovernorActivationSnapshot,
    ) -> Result<Vec<ReactiveOwnerSource>, String> {
        Ok(self.owner_sources.to_vec())
    }
}

fn owner_input_invalid(
    projection: &'static str,
    error: impl std::fmt::Display,
) -> ReactiveFeedSupplyError {
    ReactiveFeedSupplyError::OwnerInputInvalid {
        projection,
        reason: error.to_string(),
    }
}

fn owner_input_stale(projection: &'static str, field: &'static str) -> ReactiveFeedSupplyError {
    ReactiveFeedSupplyError::OwnerInputStale { projection, field }
}

fn invalid_binding(field: &'static str, error: impl std::fmt::Display) -> ReactiveFeedSupplyError {
    ReactiveFeedSupplyError::InvalidSnapshotBinding {
        field,
        reason: error.to_string(),
    }
}

/// Project the plan lane's live-activation port from the authenticated
/// snapshot, field for field through validated constructors.
///
/// The snapshot itself is authenticated by `read_unique_agent_activation`
/// (task/session/scope/fence cross-checked against the coordination,
/// session, task, scope, and canonical owners). This projection copies
/// those bindings into the plan lane's typed port: strings are validated,
/// never trusted as authority.
pub fn project_live_bindings(
    snapshot: &GovernorActivationSnapshot,
) -> Result<LiveActivationBindings, ReactiveFeedSupplyError> {
    Ok(LiveActivationBindings {
        task_id: snapshot.task_id.clone(),
        scope_id: WorkScopeId::new(snapshot.work_scope_id.clone())
            .map_err(|error| invalid_binding("snapshot.work_scope_id", error))?,
        session_id: SessionId::new(snapshot.session_id.clone())
            .map_err(|error| invalid_binding("snapshot.session_id", error))?,
        plan_id: ArtifactId::new(snapshot.plan_id.clone())
            .map_err(|error| invalid_binding("snapshot.plan_id", error))?,
        state_fence: snapshot.state_fence.clone(),
    })
}

/// Drive sealed owner projections under one live activation snapshot.
///
/// Projects the bindings, then runs the liveness-gated feed: rotated or
/// foreign projections fail closed as `StaleActivation` before planning;
/// current projections settle through the real planner and producer. Holds
/// no state across calls; retention lives with the derivation and transport
/// owners.
pub fn drive_daemon_feed(
    snapshot: &GovernorActivationSnapshot,
    inputs: SettledPlanFeedInputs<'_>,
) -> Result<SettledPlanFeedOutcome, ReactiveFeedSupplyError> {
    let bindings = project_live_bindings(snapshot)?;
    drive_live_feed(&bindings, inputs).map_err(ReactiveFeedSupplyError::Feed)
}

/// Read the six owner projections from the named owners and drive one
/// authenticated feed evaluation.
///
/// The activation snapshot is the only authority supplied by the daemon
/// composition. The source must return the exact current owner values for
/// that snapshot; a missing source, stale projection, malformed digest, or
/// journal/cue mismatch fails before the planner runs.
pub fn drive_daemon_feed_from_source(
    snapshot: &GovernorActivationSnapshot,
    journal: &ObservationJournal,
    source: &dyn ReactiveFeedOwnerSource,
) -> Result<SettledPlanFeedOutcome, ReactiveFeedSupplyError> {
    let owner_snapshot = ReactiveFeedOwnerSnapshot::read_from(snapshot, source)?;
    drive_daemon_feed_from_owners(
        snapshot,
        journal,
        &owner_snapshot.owner_sources,
        owner_snapshot.inputs(),
    )
}

fn owner_projection_matches_feed(
    projection: &ReactiveOwnerProjection,
    inputs: &SettledPlanFeedInputs<'_>,
) -> Result<(), ReactiveFeedSupplyError> {
    for seed in &inputs.cue_activation.request.seeds {
        let mut matches = projection
            .observations
            .iter()
            .flat_map(ReactiveObservationCueProjection::observed_cues)
            .filter(|observed| *observed == seed);
        if matches.next().is_none() || matches.next().is_some() {
            return Err(ReactiveFeedSupplyError::OwnerFeedBindingMismatch {
                field: "cue_activation.request.seeds",
            });
        }
    }
    for binding in &inputs.cue_activation.target_bindings {
        let mut matches = projection
            .observations
            .iter()
            .flat_map(|observation| observation.target_atom_bindings.iter())
            .filter(|atom| {
                atom.target == binding.target
                    && atom.atom_id == binding.item_id
                    && binding
                        .source_revision
                        .as_deref()
                        .is_none_or(|revision| revision == atom.source_revision)
                    && binding
                        .source_digest
                        .as_deref()
                        .is_none_or(|digest| digest == atom.source_digest)
            });
        if matches.next().is_none() || matches.next().is_some() {
            return Err(ReactiveFeedSupplyError::OwnerFeedBindingMismatch {
                field: "cue_activation.target_bindings",
            });
        }
    }
    Ok(())
}

/// Drive the A4 feed from the retained Governor journal plus concrete
/// owner-issued cue/index rows.
///
/// The journal remains the sole admitted observation source; the supplied rows
/// are immutable outputs of the real cue/context owners. They are projected
/// and then cross-checked against every A4 seed and target-to-atom binding
/// before the liveness gate or planner runs. A caller cannot supply a detached
/// activation over an unrelated cue.
pub fn drive_daemon_feed_from_owners(
    snapshot: &GovernorActivationSnapshot,
    journal: &ObservationJournal,
    owner_sources: &[ReactiveOwnerSource],
    inputs: SettledPlanFeedInputs<'_>,
) -> Result<SettledPlanFeedOutcome, ReactiveFeedSupplyError> {
    let bindings = project_live_bindings(snapshot)?;
    let owner_projection = project_reactive_owner_from_sources(
        journal,
        &bindings.scope_id,
        &bindings.state_fence,
        owner_sources,
    )
    .map_err(ReactiveFeedSupplyError::OwnerProjection)?;
    owner_projection_matches_feed(&owner_projection, &inputs)?;
    drive_live_feed(&bindings, inputs).map_err(ReactiveFeedSupplyError::Feed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use eliot_contracts::TaskId;

    struct UnavailableOwnerSource;

    impl ReactiveFeedOwnerSource for UnavailableOwnerSource {
        fn read_context_view(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<ContextPlanningView, String> {
            Err("A15 owner is not registered".to_owned())
        }

        fn read_cue_activation(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<eliot_reactive_context_plan::ReactiveCueActivation, String> {
            Err("A10 owner is not registered".to_owned())
        }

        fn read_session_snapshot(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<SessionDeliverySnapshot, String> {
            Err("session owner is not registered".to_owned())
        }

        fn read_critical_attention(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<CriticalAttentionProjection, String> {
            Err("Attention owner is not registered".to_owned())
        }

        fn read_integration_coverage(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<IntegrationCoverageProfile, String> {
            Err("coverage owner is not registered".to_owned())
        }

        fn read_policy(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<eliot_reactive_context_plan::ReactiveDeliveryPolicy, String> {
            Err("policy owner is not registered".to_owned())
        }

        fn read_owner_sources(
            &self,
            _activation: &GovernorActivationSnapshot,
        ) -> Result<Vec<ReactiveOwnerSource>, String> {
            Err("admitted owner is not registered".to_owned())
        }
    }

    fn snapshot() -> GovernorActivationSnapshot {
        GovernorActivationSnapshot {
            state_fence: eliot_contracts::StateFence::new(
                eliot_contracts::EpochId::new(
                    eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                        .expect("fixture lineage"),
                    std::num::NonZeroU64::new(1).expect("fixture sequence"),
                )
                .expect("fixture epoch"),
                eliot_contracts::ResourceGeneration::new(1).expect("fixture generation"),
            ),
            principal_id: "principal".to_owned(),
            session_id: "session".to_owned(),
            task_id: TaskId::new("task").expect("fixture task"),
            work_unit_id: "work-unit".to_owned(),
            work_scope_id: "scope".to_owned(),
            task_revision: 1,
            plan_id: "plan".to_owned(),
            plan_revision: "1".to_owned(),
        }
    }

    #[test]
    fn project_live_bindings_maps_snapshot_exactly() {
        let bindings = project_live_bindings(&snapshot()).expect("fixture snapshot projects");
        assert_eq!(bindings.task_id, TaskId::new("task").expect("fixture task"));
        assert_eq!(bindings.scope_id.as_str(), "scope");
        assert_eq!(bindings.session_id.as_str(), "session");
        assert_eq!(bindings.plan_id.as_str(), "plan");
        assert_eq!(bindings.state_fence, snapshot().state_fence);
    }

    #[test]
    fn project_live_bindings_rejects_control_characters() {
        let mut foreign = snapshot();
        foreign.session_id = "session\0".to_owned();
        match project_live_bindings(&foreign) {
            Err(ReactiveFeedSupplyError::InvalidSnapshotBinding { field, .. }) => {
                assert_eq!(field, "snapshot.session_id");
            }
            other => panic!("control characters must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn project_live_bindings_rejects_blank_scope() {
        let mut foreign = snapshot();
        foreign.work_scope_id = "   ".to_owned();
        match project_live_bindings(&foreign) {
            Err(ReactiveFeedSupplyError::InvalidSnapshotBinding { field, .. }) => {
                assert_eq!(field, "snapshot.work_scope_id");
            }
            other => panic!("blank scope must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn missing_owner_source_fails_closed_without_empty_projection() {
        match ReactiveFeedOwnerSnapshot::read_from(&snapshot(), &UnavailableOwnerSource) {
            Err(ReactiveFeedSupplyError::OwnerRead { projection, reason }) => {
                assert_eq!(projection, "admitted_owner_sources");
                assert_eq!(reason, "admitted owner is not registered");
            }
            other => panic!("missing owner state must not become an empty feed: {other:?}"),
        }
    }
}
