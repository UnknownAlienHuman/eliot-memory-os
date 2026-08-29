//! P-07 authority epoch activation and exact route fencing.
//!
//! The Kernel owns the only authority to raise an [`AuthorityEpoch`] and to
//! issue an exact [`RouteFence`] binding a route to that epoch. A fence is
//! *exact*: it carries every identity that must agree before an effect or
//! transition may proceed, and any mismatch fails closed as
//! [`KernelError::FenceMismatch`] or [`KernelError::StaleEpoch`].

use std::fmt;
use std::str::FromStr;

use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::AuthorityEpoch;

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
}
