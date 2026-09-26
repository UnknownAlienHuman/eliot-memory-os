//! P-07 generation routing and cutover decision core.
//!
//! The Kernel owns the runtime generation route table. A route is the exact
//! decision path a capability follows, and it always points to one active
//! generation at one lineage-aware authority epoch. Switching a route is a
//! *cutover*: it never mutates the old generation, it raises the sequence
//! inside the same lineage, and it frees only the previous epoch's fences
//! through a forward transition.
//!
//! Implemented by issue #64: the route, the cutover decision, and the router's
//! own active epoch all carry the canonical [`EpochId`] tuple. There is no
//! scalar epoch field left for a caller to coerce, and no numeric comparison
//! can decide authority across two lineages.

use std::collections::BTreeMap;

use eliot_contracts::{EpochId, EpochRelation, ResourceGeneration};
use eliot_runtime_contracts::GenerationCutoverState;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};
use crate::{RouteFence, RouteScope};

/// One route bound to one active generation at one lineage-aware authority epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationRoute {
    route_scope: RouteScope,
    active_generation: ResourceGeneration,
    authority_epoch: EpochId,
}

impl GenerationRoute {
    /// Creates a route binding.
    ///
    /// The epoch is the canonical tuple: a non-zero sequence inside a named
    /// lineage, both already validated by [`EpochId`] construction, so this
    /// constructor has no scalar epoch to reject.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation is zero.
    pub fn new(
        route_scope: RouteScope,
        active_generation: ResourceGeneration,
        authority_epoch: EpochId,
    ) -> Result<Self, KernelError> {
        if active_generation.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "active_generation",
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

    /// Returns the bound lineage-aware authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }
}

/// A prepared generation cutover decision.
///
/// The decision is immutable and is only *applied* by [`GenerationRouter`]
/// when its state has reached [`GenerationCutoverState::Committed`]. Rollback
/// is never a backward transition: it is a new cutover at a newer sequence
/// inside the same epoch lineage. A cutover never mints a lineage; restore,
/// break-glass, and corruption recovery do that separately.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverDecision {
    cutover_id: String,
    route_scope: RouteScope,
    old_generation: Option<ResourceGeneration>,
    new_generation: ResourceGeneration,
    old_epoch: EpochId,
    new_epoch: EpochId,
    state: GenerationCutoverState,
}

impl CutoverDecision {
    /// Creates and validates a cutover decision.
    ///
    /// The epoch pair is compared on the exact tuple first. Two lineages are
    /// unrelated, never ordered, so a cross-lineage pair is refused before any
    /// sequence is read. Only inside one lineage is the strictly-rising
    /// sequence rule evaluated.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity is blank, the generations are not
    /// distinct, the epochs belong to different lineages, or the sequence does
    /// not strictly rise inside that one lineage.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cutover_id: impl Into<String>,
        route_scope: RouteScope,
        old_generation: Option<ResourceGeneration>,
        new_generation: ResourceGeneration,
        old_epoch: EpochId,
        new_epoch: EpochId,
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
        if old_epoch.lineage_id != new_epoch.lineage_id {
            return Err(KernelError::InvalidField {
                field: "new_epoch",
                reason: "cutover must stay inside one epoch lineage",
            });
        }
        if new_epoch.sequence.get() <= old_epoch.sequence.get() {
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

    /// Returns the lineage-aware epoch before the switch.
    #[must_use]
    pub const fn old_epoch(&self) -> &EpochId {
        &self.old_epoch
    }

    /// Returns the lineage-aware epoch reserved for the switch.
    #[must_use]
    pub const fn new_epoch(&self) -> &EpochId {
        &self.new_epoch
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
///
/// The router has no lineage-less genesis constructor: an unbound scalar epoch
/// cannot seed a route table, so every router starts from one explicit
/// [`EpochId`] tuple minted by the Kernel service.
#[derive(Clone, Debug)]
pub struct GenerationRouter {
    routes: BTreeMap<RouteScope, GenerationRoute>,
    epoch: EpochId,
}

impl GenerationRouter {
    /// Creates an empty router at the exact lineage-aware epoch.
    #[must_use]
    pub fn at_epoch(epoch: EpochId) -> Self {
        Self {
            routes: BTreeMap::new(),
            epoch,
        }
    }

    /// Returns the router's current lineage-aware authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> &EpochId {
        &self.epoch
    }

    /// Registers or replaces a route at the current epoch.
    ///
    /// The route epoch must be the exact same tuple as the router's active
    /// epoch. A route minted under a different lineage at the same sequence is
    /// unrelated and is refused as [`KernelError::StaleEpochTuple`].
    ///
    /// # Errors
    ///
    /// Returns an error when the route's epoch tuple is not the router's.
    pub fn register(&mut self, route: GenerationRoute) -> Result<(), KernelError> {
        if !route.authority_epoch().is_same_authority(&self.epoch) {
            return Err(KernelError::StaleEpochTuple {
                observed: route.authority_epoch().clone(),
                active: self.epoch.clone(),
            });
        }
        self.routes.insert(route.route_scope().clone(), route);
        Ok(())
    }

    /// Authorizes one presented lineage-aware epoch against the active tuple.
    ///
    /// This is the router's single #59 exact-epoch-rejection guard, shared by
    /// every admission entry point so the rule cannot be reimplemented per
    /// caller. Only the exact active [`EpochId`] tuple is authority: a sequence
    /// inside the router's own lineage that is not the active one stays a plain
    /// [`KernelError::FenceMismatch`], so a lower fenced epoch and an
    /// unactivated future epoch remain typed exactly as issue #59 fixed them. An
    /// epoch from another lineage is unrelated rather than ordered, and reports
    /// both complete tuples as [`KernelError::StaleEpochTuple`]. The presented
    /// scalar sequence is never read, so no caller can coerce a lineaged epoch
    /// back to a counter.
    fn authorize_presented_epoch(&self, presented: &EpochId) -> Result<(), KernelError> {
        if presented.is_same_authority(&self.epoch) {
            return Ok(());
        }
        Err(if presented.lineage_id == self.epoch.lineage_id {
            KernelError::FenceMismatch
        } else {
            KernelError::StaleEpochTuple {
                observed: presented.clone(),
                active: self.epoch.clone(),
            }
        })
    }

    /// Resolves the active route for an exact, current fence.
    ///
    /// The presented epoch is the canonical [`EpochId`] tuple. Exact tuple
    /// equality is the only authorization rule: the fence's own scalar epoch
    /// is never read here, so a cross-lineage same-sequence fence cannot be
    /// admitted and no caller can coerce a lineaged epoch back to a counter.
    /// The epoch decision is the router's one shared #59 exact-epoch guard,
    /// which also decides [`Self::route_for_supervised_generation`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RouteMismatch`] for an unknown route,
    /// [`KernelError::StaleEpochTuple`] when the presented tuple is not the
    /// router's active tuple, or [`KernelError::FenceMismatch`] when the
    /// generation disagrees with the route or the fence covers another scope.
    pub fn route_for_fence(
        &self,
        fence: &RouteFence,
        fence_epoch: &EpochId,
    ) -> Result<&GenerationRoute, KernelError> {
        let route = self
            .routes
            .get(fence.route_scope())
            .ok_or(KernelError::RouteMismatch)?;
        self.authorize_presented_epoch(fence_epoch)?;
        if fence.route_scope() != route.route_scope() {
            return Err(KernelError::FenceMismatch);
        }
        if !route.authority_epoch().is_same_authority(fence_epoch)
            || route.active_generation() != fence.resource_generation()
        {
            return Err(KernelError::FenceMismatch);
        }
        Ok(route)
    }

    /// Resolves the active route for a presented supervised-generation tuple.
    ///
    /// This is a *sibling* of [`Self::route_for_fence`], not an overload of it.
    /// A [`RouteFence`] additionally carries one physical process generation
    /// ([`RouteFence::generation`]) and one correlation nonce
    /// ([`RouteFence::nonce`]), and a supervised child launch descriptor holds
    /// neither: it presents a route scope, a [`ResourceGeneration`], a
    /// lineage-aware [`EpochId`], and a launch nonce that is a public argv
    /// correlation value rather than a fence nonce. Reusing
    /// [`Self::route_for_fence`] for such a caller would require inventing the
    /// missing fence identity, and a fabricated fence is precisely the
    /// authority expansion an exact fence must never grant.
    ///
    /// The rule is therefore shared, not reimplemented: the presented epoch is
    /// decided by the router's one shared #59 exact-epoch guard that also
    /// decides [`Self::route_for_fence`], and the presented generation is
    /// compared for exact equality against the active route's generation
    /// exactly as a fence's resource generation is.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RouteMismatch`] for an unknown route,
    /// [`KernelError::StaleEpochTuple`] when the presented tuple is not the
    /// router's active tuple, or [`KernelError::FenceMismatch`] when the
    /// presented generation disagrees with the active route's generation.
    pub fn route_for_supervised_generation(
        &self,
        route_scope: &RouteScope,
        resource_generation: ResourceGeneration,
        presented_epoch: &EpochId,
    ) -> Result<&GenerationRoute, KernelError> {
        let route = self
            .routes
            .get(route_scope)
            .ok_or(KernelError::RouteMismatch)?;
        self.authorize_presented_epoch(presented_epoch)?;
        if !route.authority_epoch().is_same_authority(presented_epoch)
            || route.active_generation() != resource_generation
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
        // The cutover must name the router's exact active tuple. A decision
        // minted against a different lineage, or against an already-superseded
        // sequence, cannot advance the live fence.
        if !decision.old_epoch().is_same_authority(&self.epoch) {
            return Err(KernelError::StaleEpochTuple {
                observed: decision.old_epoch().clone(),
                active: self.epoch.clone(),
            });
        }
        // The new epoch must be strictly newer *inside the router's own
        // lineage*. A different lineage is unrelated and can never advance the
        // live fence, and an equal or older sequence is not a forward
        // transition.
        if decision.new_epoch().relation_to(&self.epoch) != EpochRelation::SameLineageNewer {
            return Err(KernelError::StaleEpochTuple {
                observed: decision.new_epoch().clone(),
                active: self.epoch.clone(),
            });
        }
        let new_epoch = decision.new_epoch().clone();
        self.epoch = new_epoch.clone();
        // The authority epoch is global.  A cutover for one scope therefore
        // re-fences every still-active scope at the same new epoch; keeping an
        // unaffected route at the old epoch would make recovery and the live
        // router disagree about the current authority fence.
        let prior_routes = self.routes.clone();
        let mut rebound_routes = BTreeMap::new();
        for (scope, prior) in prior_routes {
            let route =
                GenerationRoute::new(scope.clone(), prior.active_generation(), new_epoch.clone())?;
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
    use eliot_contracts::{AuthorityEpoch, EpochLineageId};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const FOREIGN_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    fn canonical_epoch(lineage: &str, sequence: u64) -> Result<EpochId, KernelError> {
        let lineage_id = EpochLineageId::new(lineage).map_err(|_| KernelError::InvalidField {
            field: "lineage_id",
            reason: "must be a canonical UUID lineage",
        })?;
        let sequence = NonZeroU64::new(sequence).ok_or(KernelError::InvalidField {
            field: "sequence",
            reason: "must be greater than zero",
        })?;
        EpochId::new(lineage_id, sequence).map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "invalid canonical epoch",
        })
    }

    fn router_with_daemon(epoch: u64, generation: u64) -> Result<GenerationRouter, KernelError> {
        let epoch = canonical_epoch(TEST_LINEAGE, epoch)?;
        let mut router = GenerationRouter::at_epoch(epoch.clone());
        router.register(GenerationRoute::new(
            RouteScope::new("daemon")?,
            ResourceGeneration::new(generation)?,
            epoch,
        )?)?;
        Ok(router)
    }

    #[test]
    fn fence_must_match_route_generation_and_epoch() -> Result<(), KernelError> {
        let router = router_with_daemon(2, 5)?;
        let epoch = canonical_epoch(TEST_LINEAGE, 2)?;
        let good_fence = RouteFence::new(
            RouteScope::new("daemon")?,
            AuthorityEpoch::new(2)?,
            ResourceGeneration::new(5)?,
            eliot_process::Generation::new(1)?,
            "nonce",
        )?;
        assert!(router.route_for_fence(&good_fence, &epoch).is_ok());

        let wrong_generation = RouteFence::new(
            RouteScope::new("daemon")?,
            AuthorityEpoch::new(2)?,
            ResourceGeneration::new(6)?,
            eliot_process::Generation::new(1)?,
            "nonce",
        )?;
        assert!(matches!(
            router.route_for_fence(&wrong_generation, &epoch),
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
                canonical_epoch(TEST_LINEAGE, 2)?,
                canonical_epoch(TEST_LINEAGE, 3)?,
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
                canonical_epoch(TEST_LINEAGE, 2)?,
                canonical_epoch(TEST_LINEAGE, 2)?,
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
                canonical_epoch(TEST_LINEAGE, 2)?,
                canonical_epoch(FOREIGN_LINEAGE, 9)?,
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
            canonical_epoch(TEST_LINEAGE, 2)?,
        )?)?;
        let decision = CutoverDecision::new(
            "cutover-global-epoch",
            RouteScope::new("daemon")?,
            Some(ResourceGeneration::new(5)?),
            ResourceGeneration::new(6)?,
            canonical_epoch(TEST_LINEAGE, 2)?,
            canonical_epoch(TEST_LINEAGE, 3)?,
            GenerationCutoverState::Committed,
        )?;
        router.cutover(&decision)?;
        assert_eq!(router.epoch(), &canonical_epoch(TEST_LINEAGE, 3)?);
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
            &canonical_epoch(TEST_LINEAGE, 3)?
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
            canonical_epoch(TEST_LINEAGE, 2)?,
            canonical_epoch(TEST_LINEAGE, 3)?,
            GenerationCutoverState::Committed,
        )?;
        router.cutover(&decision)?;
        let active = canonical_epoch(TEST_LINEAGE, 3)?;
        assert!(router.epoch().is_same_authority(&active));
        let route = router.route(&RouteScope::new("daemon")?)?;
        assert_eq!(route.active_generation().value(), 6);
        assert!(route.authority_epoch().is_same_authority(&active));
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
            canonical_epoch(TEST_LINEAGE, 2)?,
            canonical_epoch(TEST_LINEAGE, 3)?,
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
        let mut router = GenerationRouter::at_epoch(canonical_epoch(TEST_LINEAGE, 1)?);
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
                canonical_epoch(TEST_LINEAGE, model_epoch)?,
                canonical_epoch(TEST_LINEAGE, next_epoch)?,
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
                    canonical_epoch(TEST_LINEAGE, model_epoch)?,
                )?)?;
            }

            let committed = step % 5 != 4;
            assert_eq!(router.cutover(&decision).is_ok(), committed);
            if committed {
                model_epoch = next_epoch;
                model_generation = next_generation;
            }
            assert!(
                router
                    .epoch()
                    .is_same_authority(&canonical_epoch(TEST_LINEAGE, model_epoch)?)
            );
            let route = router.route(&RouteScope::new("daemon")?)?;
            assert_eq!(route.active_generation().value(), model_generation);
            assert!(
                route
                    .authority_epoch()
                    .is_same_authority(&canonical_epoch(TEST_LINEAGE, model_epoch)?)
            );
        }
        Ok(())
    }

    #[test]
    fn canonical_fence_gates_route_before_scalar_match() -> Result<(), KernelError> {
        let router = router_with_daemon(2, 5)?;
        let fence = RouteFence::new(
            RouteScope::new("daemon")?,
            AuthorityEpoch::new(2)?,
            ResourceGeneration::new(5)?,
            eliot_process::Generation::new(1)?,
            "nonce",
        )?;
        let active = canonical_epoch(TEST_LINEAGE, 2)?;
        let same = canonical_epoch(TEST_LINEAGE, 2)?;
        let cross_lineage_same_sequence = canonical_epoch(FOREIGN_LINEAGE, 2)?;
        assert!(router.route_for_fence(&fence, &same).is_ok());
        assert!(matches!(
            router.route_for_fence(&fence, &cross_lineage_same_sequence),
            Err(KernelError::StaleEpochTuple { .. })
        ));
        Ok(())
    }
}
