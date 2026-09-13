//! P-07 authority epoch activation and exact route fencing.
//!
//! The Kernel owns the only authority to raise an [`AuthorityEpoch`] and to
//! issue an exact [`RouteFence`] binding a route to that epoch. A fence is
//! *exact*: it carries every identity that must agree before an effect or
//! transition may proceed, and any mismatch fails closed as
//! [`KernelError::FenceMismatch`] or [`KernelError::StaleEpoch`].

use std::fmt;
use std::str::FromStr;

use eliot_contracts::{
    AuthorityEpoch, EpochId, EpochRelation, ResourceGeneration, epoch_identity_digest,
};
use eliot_process::Generation;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{KernelError, validate_id};

/// An opaque route identity owned by the Kernel decision core.
///
/// A route is the exact decision path a capability follows (for example
/// `daemon`, `store_bridge`, `user_broker`, `doctor`, or a `native_worker`
/// class). The prefix is preserved without interpretation and carries no
/// authority on its own.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct RouteScope(String);

impl RouteScope {
    /// Creates a validated route identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is blank, contains control characters,
    /// or exceeds the identity byte ceiling.
    pub fn new(value: impl Into<String>) -> Result<Self, KernelError> {
        let value = value.into();
        validate_id(&value, "route_scope")?;
        Ok(Self(value))
    }

    /// Returns the wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RouteScope {
    type Err = KernelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// An exact, epoch-bound route fence issued by the Kernel.
///
/// The fence binds one route to one authority epoch, one resource generation
/// and one physical [`Generation`]. It is deliberately not approximate: the
/// [`Self::matches`] check requires field-for-field equality, an epoch older
/// than the Kernel's current epoch is stale, and an unactivated future epoch
/// is rejected as a fence mismatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFence {
    route_scope: RouteScope,
    authority_epoch: AuthorityEpoch,
    resource_generation: ResourceGeneration,
    generation: Generation,
    nonce: String,
}

impl RouteFence {
    /// Creates and validates an exact route fence.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce is blank, contains control characters,
    /// or when the authority epoch or resource generation is zero.
    pub fn new(
        route_scope: RouteScope,
        authority_epoch: AuthorityEpoch,
        resource_generation: ResourceGeneration,
        generation: Generation,
        nonce: impl Into<String>,
    ) -> Result<Self, KernelError> {
        let nonce = nonce.into();
        validate_id(&nonce, "route_fence.nonce")?;
        if authority_epoch.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "authority_epoch",
                reason: "must be greater than zero",
            });
        }
        if resource_generation.value() == 0 {
            return Err(KernelError::InvalidField {
                field: "resource_generation",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            route_scope,
            authority_epoch,
            resource_generation,
            generation,
            nonce,
        })
    }

    /// Returns the exact route this fence covers.
    #[must_use]
    pub fn route_scope(&self) -> &RouteScope {
        &self.route_scope
    }

    /// Returns the bound authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.authority_epoch
    }

    /// Returns the bound resource generation.
    #[must_use]
    pub const fn resource_generation(&self) -> ResourceGeneration {
        self.resource_generation
    }

    /// Returns the bound physical process generation.
    #[must_use]
    pub const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the opaque correlation nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Returns `true` only for exact field-for-field equality.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }

    /// Returns `true` when the fence belongs to a fenced (stale) epoch.
    #[must_use]
    pub fn is_stale(&self, current_epoch: AuthorityEpoch) -> bool {
        self.authority_epoch.value() < current_epoch.value()
    }

    /// Validates that the fence covers `route` at the exact active epoch.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::RouteMismatch`] for a different route,
    /// [`KernelError::StaleEpoch`] for a fenced epoch, and
    /// [`KernelError::FenceMismatch`] for an unactivated future epoch.
    pub fn enforce(
        &self,
        route: &RouteScope,
        current_epoch: AuthorityEpoch,
    ) -> Result<(), KernelError> {
        if &self.route_scope != route {
            return Err(KernelError::RouteMismatch);
        }
        if self.is_stale(current_epoch) {
            return Err(KernelError::StaleEpoch {
                observed: self.authority_epoch.value(),
                active: current_epoch.value(),
            });
        }
        if self.authority_epoch != current_epoch {
            return Err(KernelError::FenceMismatch);
        }
        Ok(())
    }
}

/// The durable projection of an epoch activation and the fence it raises.
///
/// Raising an epoch never mutates the previous epoch; it records a new,
/// strictly greater epoch and fences every route that still carries the old
/// one. Consumers bound to the old epoch become stale and must re-acquire.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochActivation {
    activation_id: String,
    prior_epoch: AuthorityEpoch,
    active_epoch: AuthorityEpoch,
    fenced_routes: Vec<RouteScope>,
}

impl EpochActivation {
    /// Creates an epoch activation with a strictly increasing epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the activation identity is blank, the new epoch
    /// does not strictly exceed the prior epoch, or the fenced-route list
    /// contains duplicates.
    pub fn new(
        activation_id: impl Into<String>,
        prior_epoch: AuthorityEpoch,
        active_epoch: AuthorityEpoch,
        fenced_routes: Vec<RouteScope>,
    ) -> Result<Self, KernelError> {
        let activation_id = activation_id.into();
        validate_id(&activation_id, "epoch_activation.activation_id")?;
        if active_epoch.value() <= prior_epoch.value() {
            return Err(KernelError::InvalidField {
                field: "active_epoch",
                reason: "activation must strictly raise the epoch",
            });
        }
        let mut seen = std::collections::BTreeSet::new();
        for route in &fenced_routes {
            if !seen.insert(route.clone()) {
                return Err(KernelError::InvalidField {
                    field: "fenced_routes",
                    reason: "must not contain duplicates",
                });
            }
        }
        Ok(Self {
            activation_id,
            prior_epoch,
            active_epoch,
            fenced_routes,
        })
    }

    /// Returns the activation identity.
    #[must_use]
    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    /// Returns the epoch this activation fences.
    #[must_use]
    pub const fn prior_epoch(&self) -> AuthorityEpoch {
        self.prior_epoch
    }

    /// Returns the epoch this activation makes current.
    #[must_use]
    pub const fn active_epoch(&self) -> AuthorityEpoch {
        self.active_epoch
    }

    /// Returns the routes fenced by this activation.
    #[must_use]
    pub fn fenced_routes(&self) -> &[RouteScope] {
        &self.fenced_routes
    }
}

/// Returns `true` only for exact canonical tuple equality.
///
/// This is the lineage-aware counterpart to the scalar epoch equality check:
/// equal sequences from different lineages are unrelated and return `false`.
#[must_use]
pub fn authorizes_canonical(fence_epoch: &EpochId, active: &EpochId) -> bool {
    fence_epoch.is_same_authority(active)
}

/// Returns `true` when a canonical fence is fenced relative to the active epoch.
///
/// Same-lineage older fences are stale; cross-lineage fences are unrelated and
/// therefore also fenced (fail-closed). Same-tuple and same-lineage newer
/// fences are not stale — a newer fence is a future mismatch, not a stale one.
#[must_use]
pub fn is_stale_canonical(fence_epoch: &EpochId, active: &EpochId) -> bool {
    match fence_epoch.relation_to(active) {
        EpochRelation::Same
        | EpochRelation::DirectParent
        | EpochRelation::SameLineageNewer => false,
        EpochRelation::DirectChild
        | EpochRelation::SameLineageOlder
        | EpochRelation::UnrelatedLineage => true,
    }
}

/// Returns `true` only for an exact one-step child in one lineage.
///
/// Cross-lineage inputs and skipped sequences return `false` without ordering
/// epochs across lineages.
#[must_use]
pub fn is_direct_child_canonical(child: &EpochId, parent: &EpochId) -> bool {
    child.is_direct_child_of(parent)
}

/// Computes the canonical digest binding both lineage and sequence.
///
/// The digest input includes the contract domain separator, the lineage UUID,
/// and the sequence, so a lineage change with the same sequence yields a
/// different digest.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when canonical digest serialization
/// fails.
pub fn canonical_epoch_digest(epoch: &EpochId) -> Result<String, KernelError> {
    epoch_identity_digest(epoch)
        .map(|digest| digest.as_str().to_owned())
        .map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "canonical digest serialization failed",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, EpochLineageId};
    use std::num::NonZeroU64;

    fn fence(epoch: u64, route: &str) -> Result<RouteFence, KernelError> {
        RouteFence::new(
            RouteScope::new(route)?,
            AuthorityEpoch::new(epoch)?,
            ResourceGeneration::genesis(),
            Generation::new(1)?,
            "nonce-1",
        )
    }

    #[test]
    fn exact_fence_requires_field_for_field_equality() -> Result<(), KernelError> {
        let a = fence(1, "daemon")?;
        let mut b = a.clone();
        assert!(a.matches(&b));
        b.nonce = "different".to_owned();
        assert!(!a.matches(&b));
        Ok(())
    }

    #[test]
    fn stale_fence_is_rejected_for_the_exact_route() -> Result<(), KernelError> {
        let fence = fence(2, "store_bridge")?;
        let route = RouteScope::new("store_bridge")?;
        assert!(matches!(
            fence.enforce(&route, AuthorityEpoch::new(3)?),
            Err(KernelError::StaleEpoch {
                observed: 2,
                active: 3
            })
        ));
        assert!(fence.enforce(&route, AuthorityEpoch::new(2)?).is_ok());
        Ok(())
    }

    #[test]
    fn future_fence_is_rejected_for_the_exact_route() -> Result<(), KernelError> {
        let fence = fence(3, "store_bridge")?;
        let route = RouteScope::new("store_bridge")?;
        assert!(matches!(
            fence.enforce(&route, AuthorityEpoch::new(2)?),
            Err(KernelError::FenceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn wrong_route_fails_closed() -> Result<(), KernelError> {
        let fence = fence(2, "doctor")?;
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            fence.enforce(&route, AuthorityEpoch::new(2)?),
            Err(KernelError::RouteMismatch)
        ));
        Ok(())
    }

    #[test]
    fn epoch_activation_must_strictly_raise_epoch() -> Result<(), KernelError> {
        assert!(
            EpochActivation::new(
                "activation-1",
                AuthorityEpoch::new(3)?,
                AuthorityEpoch::new(3)?,
                Vec::new(),
            )
            .is_err()
        );
        let activation = EpochActivation::new(
            "activation-1",
            AuthorityEpoch::new(3)?,
            AuthorityEpoch::new(4)?,
            vec![RouteScope::new("daemon")?],
        )?;
        assert_eq!(activation.prior_epoch().value(), 3);
        assert_eq!(activation.active_epoch().value(), 4);
        assert_eq!(activation.fenced_routes().len(), 1);
        Ok(())
    }

    #[test]
    fn epoch_activation_rejects_duplicate_routes() -> Result<(), KernelError> {
        let route = RouteScope::new("daemon")?;
        assert!(
            EpochActivation::new(
                "activation-1",
                AuthorityEpoch::genesis(),
                AuthorityEpoch::new(2)?,
                vec![route.clone(), route],
            )
            .is_err()
        );
        Ok(())
    }

    fn canonical_epoch(lineage: &str, sequence: u64) -> Result<EpochId, KernelError> {
        let lineage_id =
            EpochLineageId::new(lineage).map_err(|_| KernelError::InvalidField {
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

    #[test]
    fn canonical_tuple_authorizes_only_exact_match() -> Result<(), KernelError> {
        let active = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 4)?;
        let same = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 4)?;
        let cross_lineage_same_sequence =
            canonical_epoch("6ba7b810-9dad-11d1-80b4-00c04fd430c8", 4)?;
        let same_lineage_older = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 3)?;
        assert!(authorizes_canonical(&same, &active));
        assert!(!authorizes_canonical(&cross_lineage_same_sequence, &active));
        assert!(!authorizes_canonical(&same_lineage_older, &active));
        // Cross-lineage and older fences are fenced; the exact tuple is not.
        assert!(!is_stale_canonical(&same, &active));
        assert!(is_stale_canonical(&cross_lineage_same_sequence, &active));
        assert!(is_stale_canonical(&same_lineage_older, &active));
        Ok(())
    }

    #[test]
    fn canonical_direct_child_requires_same_lineage_single_step() -> Result<(), KernelError> {
        let parent = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 4)?;
        let child = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 5)?;
        let skipped = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 6)?;
        let cross_lineage = canonical_epoch("6ba7b810-9dad-11d1-80b4-00c04fd430c8", 5)?;
        assert!(is_direct_child_canonical(&child, &parent));
        assert!(!is_direct_child_canonical(&skipped, &parent));
        assert!(!is_direct_child_canonical(&cross_lineage, &parent));
        Ok(())
    }

    #[test]
    fn canonical_digest_binds_lineage() -> Result<(), KernelError> {
        let left = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 4)?;
        let cross_lineage = canonical_epoch("6ba7b810-9dad-11d1-80b4-00c04fd430c8", 4)?;
        let next_sequence = canonical_epoch("550e8400-e29b-41d4-a716-446655440000", 5)?;
        let left_digest = canonical_epoch_digest(&left)?;
        assert_eq!(left_digest, canonical_epoch_digest(&left)?);
        assert_ne!(left_digest, canonical_epoch_digest(&cross_lineage)?);
        assert_ne!(left_digest, canonical_epoch_digest(&next_sequence)?);
        Ok(())
    }
}
