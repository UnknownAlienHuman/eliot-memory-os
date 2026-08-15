//! P-07 generation routing and cutover decision core.
//!
//! The Kernel owns the runtime generation route table. A route is the exact
//! decision path a capability follows, and it always points to one active
//! generation at one authority epoch. Switching a route is a *cutover*: it
//! never mutates the old generation, it raises the authority epoch, and it
//! frees only the previous epoch's fences through a forward transition.

use std::collections::BTreeMap;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
use eliot_runtime_contracts::GenerationCutoverState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};
use crate::{RouteFence, RouteScope};

/// One route bound to one active generation at one authority epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationRoute {
    route_scope: RouteScope,
    active_generation: ResourceGeneration,
    authority_epoch: AuthorityEpoch,
}

impl GenerationRoute {
    /// Creates a route binding.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation or epoch is zero.
    pub fn new(
        route_scope: RouteScope,
        active_generation: ResourceGeneration,
        authority_epoch: AuthorityEpoch,
    ) -> Result<Self, KernelError> {
        if active_generation.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "active_generation",
                reason: "must be greater than zero",
            });
        }
        if authority_epoch.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "authority_epoch",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            route_scope,
            active_generation,
            authority_epoch,
        })
    }

    /// Returns the route scope.
    #[must_use]
    pub fn route_scope(&self) -> &RouteScope {
        &self.route_scope
    }

    /// Returns the active generation.
    #[must_use]
    pub const fn active_generation(&self) -> ResourceGeneration {
        self.active_generation
    }

    /// Returns the bound authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }
}

/// A prepared generation cutover decision.
///
/// The decision is immutable and is only *applied* by [`GenerationRouter`]
/// when its state has reached [`GenerationCutoverState::Committed`]. Rollback
/// is never a backward transition: it is a new cutover at a newer epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverDecision {
    cutover_id: String,
    route_scope: RouteScope,
    old_generation: Option<ResourceGeneration>,
    new_generation: ResourceGeneration,
    old_epoch: AuthorityEpoch,
    new_epoch: AuthorityEpoch,
    state: GenerationCutoverState,
}

impl CutoverDecision {
    /// Creates and validates a cutover decision.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is blank, the generations are not
    /// distinct, or the epoch does not strictly rise.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cutover_id: impl Into<String>,
        route_scope: RouteScope,
        old_generation: Option<ResourceGeneration>,
        new_generation: ResourceGeneration,
        old_epoch: AuthorityEpoch,
        new_epoch: AuthorityEpoch,
        state: GenerationCutoverState,
    ) -> Result<Self, KernelError> {
        let cutover_id = cutover_id.into();
        validate_id(&cutover_id, "cutover_id")?;
        if old_generation == Some(new_generation) {
            return Err(KernelError::InvalidField {
                field: "new_generation",
                reason: "cutover must select a distinct generation",
            });
        }
        if new_epoch.value() <= old_epoch.value() {
            return Err(KernelError::InvalidField {
                field: "new_epoch",
                reason: "cutover must raise the authority epoch",
            });
        }
        Ok(Self {
            cutover_id,
            route_scope,
            old_generation,
            new_generation,
            old_epoch,
            new_epoch,
            state,
        })
    }

    /// Returns the cutover identity.
    #[must_use]
    pub fn cutover_id(&self) -> &str {
        &self.cutover_id
    }

    /// Returns the route being switched.
    #[must_use]
    pub fn route_scope(&self) -> &RouteScope {
        &self.route_scope
    }

    /// Returns the previously active generation, if any.
    #[must_use]
    pub const fn old_generation(&self) -> Option<ResourceGeneration> {
        self.old_generation
    }

    /// Returns the candidate generation.
    #[must_use]
    pub const fn new_generation(&self) -> ResourceGeneration {
        self.new_generation
    }

    /// Returns the epoch before the switch.
    #[must_use]
    pub const fn old_epoch(&self) -> AuthorityEpoch {
        self.old_epoch
    }

    /// Returns the epoch reserved for the switch.
    #[must_use]
    pub const fn new_epoch(&self) -> AuthorityEpoch {
        self.new_epoch
    }

    /// Returns the current cutover state.
    #[must_use]
    pub const fn state(&self) -> GenerationCutoverState {
        self.state
    }
}

/// The Kernel-owned runtime generation route table.
///
/// The router enforces exact route fencing and applies only committed,
/// epoch-raising cutovers. It never mutates a prior generation record; a
/// cutover replaces the active route while the old generation drains through
/// the separate [`GenerationCutoverState`] machine.
#[derive(Clone, Debug, Default)]
pub struct GenerationRouter {
    routes: BTreeMap<RouteScope, GenerationRoute>,
    epoch: AuthorityEpoch,
}

impl GenerationRouter {
    /// Creates an empty router at the genesis epoch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
            epoch: AuthorityEpoch::genesis(),
        }
    }

    /// Creates a router seeded with an explicit epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the epoch is zero.
    pub fn at_epoch(epoch: AuthorityEpoch) -> Result<Self, KernelError> {
        if epoch.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "epoch",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            routes: BTreeMap::new(),
            epoch,
        })
    }

    /// Returns the router's current authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> AuthorityEpoch {
        self.epoch
    }

    /// Registers or replaces a route at the current epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the route's epoch does not match the router.
    pub fn register(&mut self, route: GenerationRoute) -> Result<(), KernelError> {
        if route.authority_epoch() != self.epoch {
            return Err(KernelError::StaleEpoch {
                observed: route.authority_epoch().value(),
                active: self.epoch.value(),
            });
        }
        self.routes.insert(route.route_scope().clone(), route);
        Ok(())
    }

    /// Resolves the active route for an exact, current fence.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RouteMismatch`] for an unknown route,
    /// [`KernelError::StaleEpoch`] for a fenced fence, or
    /// [`KernelError::FenceMismatch`] when the fence disagrees with the route.
    pub fn route_for_fence(&self, fence: &RouteFence) -> Result<&GenerationRoute, KernelError> {
        let route = self
            .routes
            .get(fence.route_scope())
            .ok_or(KernelError::RouteMismatch)?;
        fence.enforce(fence.route_scope(), self.epoch)?;
        if route.authority_epoch() != fence.authority_epoch()
            || route.active_generation() != fence.resource_generation()
        {
            return Err(KernelError::FenceMismatch);
        }
        Ok(route)
    }

    /// Resolves the active route for a scope without a fence.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RouteMismatch`] when the route is unknown.
    pub fn route(&self, scope: &RouteScope) -> Result<&GenerationRoute, KernelError> {
        self.routes.get(scope).ok_or(KernelError::RouteMismatch)
    }

    /// Applies a committed cutover, raising the epoch and switching the route.
    ///
    /// # Errors
    ///
    /// Returns an error when the decision is not [`GenerationCutoverState::Committed`],
    /// the route is unknown, or the decision's old generation/epoch do not
    /// match the router's current state.
    pub fn cutover(&mut self, decision: &CutoverDecision) -> Result<(), KernelError> {
        if decision.state() != GenerationCutoverState::Committed {
            return Err(KernelError::IllegalTransition {
                machine: "generation-cutover",
                from: decision.state().to_string(),
                to: GenerationCutoverState::Committed.to_string(),
            });
        }
        let route = self
            .routes
            .get(decision.route_scope())
            .ok_or(KernelError::RouteMismatch)?;
        let Some(old_generation) = decision.old_generation() else {
            return Err(KernelError::InvalidField {
                field: "old_generation",
                reason: "cutover requires a prior active generation",
            });
        };
        if route.active_generation() != old_generation {
            return Err(KernelError::FenceMismatch);
        }
        if decision.old_epoch() != self.epoch {
            return Err(KernelError::StaleEpoch {
                observed: decision.old_epoch().value(),
                active: self.epoch.value(),
            });
        }
        if decision.old_epoch() != self.epoch || decision.new_epoch().value() <= self.epoch.value()
        {
            return Err(KernelError::StaleEpoch {
                observed: decision.old_epoch().value(),
                active: self.epoch.value(),
            });
        }
        let new_epoch = decision.new_epoch();
        self.epoch = decision.new_epoch();
        // The authority epoch is global.  A cutover for one scope therefore
        // re-fences every still-active scope at the same new epoch; keeping an
        // unaffected route at the old epoch would make recovery and the live
        // router disagree about the current authority fence.
        let prior_routes = self.routes.clone();
        let mut rebound_routes = BTreeMap::new();
        for (scope, prior) in prior_routes {
            let route = GenerationRoute::new(scope.clone(), prior.active_generation(), new_epoch)?;
            rebound_routes.insert(scope, route);
        }
        let replaced = GenerationRoute::new(
            decision.route_scope().clone(),
            decision.new_generation(),
            new_epoch,
        )?;
        rebound_routes.insert(decision.route_scope().clone(), replaced);
        self.routes = rebound_routes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router_with_daemon(epoch: u64, generation: u64) -> Result<GenerationRouter, KernelError> {
        let mut router = GenerationRouter::at_epoch(AuthorityEpoch::new(epoch)?)?;
        router.register(GenerationRoute::new(
            RouteScope::new("daemon")?,
            ResourceGeneration::new(generation)?,
            AuthorityEpoch::new(epoch)?,
        )?)?;
        Ok(router)
    }

    #[test]
    fn fence_must_match_route_generation_and_epoch() -> Result<(), KernelError> {
        let router = router_with_daemon(2, 5)?;
        let good_fence = RouteFence::new(
            RouteScope::new("daemon")?,
            AuthorityEpoch::new(2)?,
            ResourceGeneration::new(5)?,
            eliot_process::Generation::new(1)?,
            "nonce",
        )?;
        assert!(router.route_for_fence(&good_fence).is_ok());

        let wrong_generation = RouteFence::new(
            RouteScope::new("daemon")?,
            AuthorityEpoch::new(2)?,
            ResourceGeneration::new(6)?,
            eliot_process::Generation::new(1)?,
            "nonce",
        )?;
        assert!(matches!(
            router.route_for_fence(&wrong_generation),
            Err(KernelError::FenceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn cutover_requires_distinct_generation_and_rising_epoch() -> Result<(), KernelError> {
        assert!(
            CutoverDecision::new(
                "c-1",
                RouteScope::new("daemon")?,
                Some(ResourceGeneration::new(5)?),
                ResourceGeneration::new(5)?,
                AuthorityEpoch::new(2)?,
                AuthorityEpoch::new(3)?,
                GenerationCutoverState::Preparing,
            )
            .is_err()
        );
        assert!(
            CutoverDecision::new(
                "c-1",
                RouteScope::new("daemon")?,
                Some(ResourceGeneration::new(5)?),
                ResourceGeneration::new(6)?,
                AuthorityEpoch::new(2)?,
                AuthorityEpoch::new(2)?,
                GenerationCutoverState::Preparing,
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn cutover_rebinds_unaffected_scopes_to_global_epoch() -> Result<(), KernelError> {
        let mut router = router_with_daemon(2, 5)?;
        router.register(GenerationRoute::new(
            RouteScope::new("worker")?,
            ResourceGeneration::new(8)?,
            AuthorityEpoch::new(2)?,
        )?)?;
        let decision = CutoverDecision::new(
            "cutover-global-epoch",
            RouteScope::new("daemon")?,
            Some(ResourceGeneration::new(5)?),
            ResourceGeneration::new(6)?,
            AuthorityEpoch::new(2)?,
            AuthorityEpoch::new(3)?,
            GenerationCutoverState::Committed,
        )?;
        router.cutover(&decision)?;
        assert_eq!(router.epoch(), AuthorityEpoch::new(3)?);
        assert_eq!(
            router
                .route(&RouteScope::new("daemon")?)?
                .active_generation()
                .value(),
            6
        );
        assert_eq!(
            router
                .route(&RouteScope::new("worker")?)?
                .active_generation()
                .value(),
            8
        );
        assert_eq!(
            router.route(&RouteScope::new("worker")?)?.authority_epoch(),
            AuthorityEpoch::new(3)?
        );
        Ok(())
    }

    #[test]
    fn committed_cutover_switches_route_and_raises_epoch() -> Result<(), KernelError> {
        let mut router = router_with_daemon(2, 5)?;
        let decision = CutoverDecision::new(
            "c-1",
            RouteScope::new("daemon")?,
            Some(ResourceGeneration::new(5)?),
            ResourceGeneration::new(6)?,
            AuthorityEpoch::new(2)?,
            AuthorityEpoch::new(3)?,
            GenerationCutoverState::Committed,
        )?;
        router.cutover(&decision)?;
        assert_eq!(router.epoch().value(), 3);
        let route = router.route(&RouteScope::new("daemon")?)?;
        assert_eq!(route.active_generation().value(), 6);
        assert_eq!(route.authority_epoch().value(), 3);
        Ok(())
    }

    #[test]
    fn non_committed_cutover_is_rejected() -> Result<(), KernelError> {
        let mut router = router_with_daemon(2, 5)?;
        let decision = CutoverDecision::new(
            "c-1",
            RouteScope::new("daemon")?,
            Some(ResourceGeneration::new(5)?),
            ResourceGeneration::new(6)?,
            AuthorityEpoch::new(2)?,
            AuthorityEpoch::new(3)?,
            GenerationCutoverState::Preparing,
        )?;
        assert!(matches!(
            router.cutover(&decision),
            Err(KernelError::IllegalTransition { .. })
        ));
        Ok(())
    }

    #[test]
    fn model_based_cutover_sequence_preserves_epoch_monotonicity() -> Result<(), KernelError> {
        // A deterministic model that mirrors the router: every successful
        // cutover must raise the epoch and leave the route at the new
        // generation. A stale or non-committed cutover must change nothing.
        let mut router = GenerationRouter::at_epoch(AuthorityEpoch::genesis())?;
        let mut model_epoch = 1u64;
        let mut model_generation = 1u64;

        for step in 0..40 {
            let next_epoch = model_epoch + 1;
            let next_generation = model_generation + 1;
            let decision = CutoverDecision::new(
                format!("c-{step}"),
                RouteScope::new("daemon")?,
                Some(ResourceGeneration::new(model_generation)?),
                ResourceGeneration::new(next_generation)?,
                AuthorityEpoch::new(model_epoch)?,
                AuthorityEpoch::new(next_epoch)?,
                if step % 5 == 4 {
                    GenerationCutoverState::Preparing
                } else {
                    GenerationCutoverState::Committed
                },
            )?;

            if step == 0 {
                router.register(GenerationRoute::new(
                    RouteScope::new("daemon")?,
                    ResourceGeneration::new(model_generation)?,
                    AuthorityEpoch::new(model_epoch)?,
                )?)?;
            }

            let committed = step % 5 != 4;
            assert_eq!(router.cutover(&decision).is_ok(), committed);
            if committed {
                model_epoch = next_epoch;
                model_generation = next_generation;
            }
            assert_eq!(router.epoch().value(), model_epoch);
            let route = router.route(&RouteScope::new("daemon")?)?;
            assert_eq!(route.active_generation().value(), model_generation);
            assert_eq!(route.authority_epoch().value(), model_epoch);
        }
        Ok(())
    }
}
