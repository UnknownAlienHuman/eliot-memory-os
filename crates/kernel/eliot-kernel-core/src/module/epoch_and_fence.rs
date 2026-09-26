//! P-07 authority epoch activation and exact route fencing.
//!
//! The Kernel owns the only authority to raise an [`EpochId`] and to issue an
//! exact [`RouteFence`] binding a route to that epoch. A fence is *exact*: it
//! carries every identity that must agree before an effect or transition may
//! proceed, and any mismatch fails closed as [`KernelError::FenceMismatch`],
//! [`KernelError::StaleEpoch`] or [`KernelError::StaleEpochTuple`].
//!
//! There is no scalar epoch in this module. An authority-bearing value is
//! always the complete `(lineage_id, sequence)` tuple of
//! `epoch-id.contract.toml` `[types.EpochId]`, so the three rules the contract
//! fixes are structural rather than documentary:
//!
//! - **Exact tuple equality is the authorization rule.** Two equal sequences
//!   from different lineages are unrelated, not equal.
//! - **A direct child is one lineage and one step.** A skipped sequence, a
//!   repeat, or a different lineage is not a forward transition.
//! - **A lineage change mints a new lineage at genesis and fences the old
//!   one.** Restore, migration, corruption recovery and break-glass therefore
//!   cannot be projected as a larger number, and no epoch of a previous
//!   lineage can become active again.
//!
//! No field, accessor, or error in this module narrows an epoch to `u64`.

use std::fmt;
use std::str::FromStr;

use eliot_contracts::{
    EpochId, EpochLineageId, EpochRelation, EpochTransition, LowercaseSha256, ResourceGeneration,
    epoch_identity_digest,
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
/// The fence binds one route to one complete authority epoch tuple, one
/// resource generation and one physical [`Generation`]. It is deliberately
/// not approximate: [`Self::matches`] requires field-for-field equality —
/// which includes both `lineage_id` and `sequence` — [`Self::enforce`]
/// admits only the exact active tuple, an older epoch *of the same lineage*
/// is stale, an epoch of a different lineage is unrelated and is fenced,
/// and an unactivated future epoch of the same lineage is a fence
/// mismatch.
///
/// The epoch field is the contract's closed [`EpochId`], so a fence can
/// neither be built from nor narrowed to a bare counter, and two unrelated
/// lineages holding the same sequence produce two unequal fences.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFence {
    route_scope: RouteScope,
    authority_epoch: EpochId,
    resource_generation: ResourceGeneration,
    generation: Generation,
    nonce: String,
}

impl RouteFence {
    /// Creates and validates an exact route fence.
    ///
    /// The authority epoch arrives as a validated [`EpochId`] tuple, so there
    /// is no scalar epoch left to reject: a non-zero sequence inside a
    /// canonical lineage is the only representable form, and no conversion
    /// from a counter exists on this type.
    ///
    /// # Errors
    ///
    /// Returns an error when the nonce is blank, contains control characters,
    /// or when the resource generation is zero.
    pub fn new(
        route_scope: RouteScope,
        authority_epoch: EpochId,
        resource_generation: ResourceGeneration,
        generation: Generation,
        nonce: impl Into<String>,
    ) -> Result<Self, KernelError> {
        let nonce = nonce.into();
        validate_id(&nonce, "route_fence.nonce")?;
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

    /// Returns the bound lineage-aware authority epoch.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
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
    ///
    /// Because [`EpochId`] equality is tuple equality, two fences minted under
    /// different lineages are unequal even when their sequences match.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self == other
    }

    /// Computes the canonical digest of the fence's bound epoch.
    ///
    /// The digest input is the contract domain separator, the lineage UUID and
    /// the sequence (`epoch-id.contract.toml` `[types.EpochId]`), so a fence
    /// from a different lineage at the same sequence has a different digest.
    /// This is the only epoch representation that leaves this module, and it is
    /// a digest: no numeric epoch is recoverable from it.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidField`] when canonical digest
    /// serialization fails.
    pub fn epoch_digest(&self) -> Result<LowercaseSha256, KernelError> {
        epoch_identity_digest(&self.authority_epoch).map_err(|_| KernelError::InvalidField {
            field: "epoch_id",
            reason: "canonical digest serialization failed",
        })
    }

    /// Returns `true` when the fence belongs to a fenced epoch.
    ///
    /// A fence is fenced when it is neither the active tuple nor an
    /// unactivated same-lineage future tuple. An epoch of a different lineage
    /// is *unrelated*, never merely older, so it is fenced (fail-closed)
    /// instead of being ordered against `active_epoch`.
    #[must_use]
    pub fn is_stale(&self, active_epoch: &EpochId) -> bool {
        match self.authority_epoch.relation_to(active_epoch) {
            EpochRelation::Same | EpochRelation::DirectChild | EpochRelation::SameLineageNewer => {
                false
            }
            EpochRelation::DirectParent
            | EpochRelation::SameLineageOlder
            | EpochRelation::UnrelatedLineage => true,
        }
    }

    /// Validates that the fence covers `route` at the exact active epoch.
    ///
    /// Exact tuple equality is the whole admission rule. The refusal is typed
    /// so that a cross-lineage epoch can never be reported, or re-read, as a
    /// numeric comparison:
    ///
    /// - a different route is [`KernelError::RouteMismatch`];
    /// - an epoch of a different lineage is [`KernelError::StaleEpochTuple`]
    ///   carrying both complete tuples, whether its sequence is smaller, equal,
    ///   or larger;
    /// - an older epoch *of the active lineage* is [`KernelError::StaleEpoch`];
    /// - a future epoch *of the active lineage* is
    ///   [`KernelError::FenceMismatch`].
    ///
    /// # Errors
    ///
    /// Returns the first applicable rejection described above.
    pub fn enforce(&self, route: &RouteScope, active_epoch: &EpochId) -> Result<(), KernelError> {
        if &self.route_scope != route {
            return Err(KernelError::RouteMismatch);
        }
        if self.authority_epoch.is_same_authority(active_epoch) {
            return Ok(());
        }
        if self.authority_epoch.lineage_id != active_epoch.lineage_id {
            return Err(KernelError::StaleEpochTuple {
                observed: self.authority_epoch.clone(),
                active: active_epoch.clone(),
            });
        }
        if self.is_stale(active_epoch) {
            return Err(KernelError::StaleEpoch {
                observed: self.authority_epoch.sequence.get(),
                active: active_epoch.sequence.get(),
            });
        }
        Err(KernelError::FenceMismatch)
    }
}

/// The closed cause of an authority-epoch lineage change.
///
/// `epoch-id.contract.toml` `[migration].restore_rule` and I6.10 name exactly
/// these four transitions as the ones that mint a fresh lineage, and
/// `[types.EpochTransition]` fixes their result: genesis in a new lineage, with
/// no parent. An ordinary in-lineage advance is not one of them, so it cannot
/// be spelled here.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageChange {
    /// Restore from a backup, manifest, or installation snapshot.
    Restore,
    /// A governed canonical migration.
    Migration,
    /// Recovery from detected corruption or unknown ownership.
    CorruptionRecovery,
    /// Break-glass reconstitution after the ordinary recovery path is lost.
    BreakGlass,
}

/// The durable projection of an epoch activation and the fence it raises.
///
/// Raising an epoch never mutates the previous epoch and never reorders it.
/// There are exactly two admitted shapes, and the constructor is the only way
/// to obtain one:
///
/// - [`Self::advance`] — one admitted direct-child step inside the same
///   lineage. A repeat, a skipped sequence, a sequence overflow, or any
///   different lineage is refused here, so a restart inside one lineage can
///   only move forward by exactly one.
/// - [`Self::new_lineage`] — restore, migration, corruption recovery, or
///   break-glass mints a globally distinct lineage at genesis and must name
///   the routes it fences. A lineage change cannot be projected as a larger
///   number, and the previous lineage is never reactivated.
///
/// Every epoch outside `active_epoch` is fenced by this record, so an old
/// token, session, route, or receipt bound to a previous lineage fails the
/// exact-tuple rule of [`RouteFence::enforce`] and cannot become active again.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochActivation {
    activation_id: String,
    prior_epoch: EpochId,
    active_epoch: EpochId,
    transition: EpochTransition,
    lineage_change: Option<LineageChange>,
    fenced_routes: Vec<RouteScope>,
}

impl EpochActivation {
    /// Records one admitted in-lineage direct-child advance.
    ///
    /// `active_epoch` must be the exact direct child of `prior_epoch`: one
    /// lineage, one step. A different lineage is refused rather than
    /// compared, so a larger sequence from another lineage can neither
    /// supersede nor finalize this activation.
    ///
    /// # Errors
    ///
    /// Returns an error when the activation identity is blank, the prior
    /// sequence cannot advance without overflow, `active_epoch` is not the
    /// exact direct child, or the fenced-route list contains duplicates.
    pub fn advance(
        activation_id: impl Into<String>,
        prior_epoch: EpochId,
        active_epoch: EpochId,
        fenced_routes: Vec<RouteScope>,
    ) -> Result<Self, KernelError> {
        let activation_id = activation_id.into();
        validate_id(&activation_id, "epoch_activation.activation_id")?;
        let transition =
            EpochTransition::direct_child(&prior_epoch).map_err(|_| KernelError::InvalidField {
                field: "active_epoch",
                reason: "an in-lineage advance must be the exact direct child of the prior epoch",
            })?;
        if !transition.current.is_same_authority(&active_epoch) {
            return Err(KernelError::InvalidField {
                field: "active_epoch",
                reason: "an in-lineage advance must be the exact direct child of the prior epoch",
            });
        }
        Ok(Self {
            activation_id,
            prior_epoch,
            active_epoch,
            transition,
            lineage_change: None,
            fenced_routes: distinct_routes(fenced_routes)?,
        })
    }

    /// Mints a globally distinct lineage for restore, migration, corruption
    /// recovery, or break-glass.
    ///
    /// A13.7 requires the new lineage to be globally distinct when a shared
    /// maximum cannot be demonstrated, and requires old epochs not to revive.
    /// That is enforced here rather than documented: the new lineage must
    /// differ from the lineage being fenced, it starts at genesis with no
    /// parent (so no old tuple is ever reactivated), and the caller must name
    /// the routes it fences — a lineage change with an empty fence set is
    /// refused instead of being admitted with an unfenced predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error when the activation identity is blank, the new lineage
    /// is not globally distinct from the fenced one, no route is fenced, or the
    /// fenced-route list contains duplicates.
    #[allow(clippy::too_many_arguments)]
    pub fn new_lineage(
        activation_id: impl Into<String>,
        prior_epoch: EpochId,
        new_lineage: EpochLineageId,
        cause: LineageChange,
        fenced_routes: Vec<RouteScope>,
    ) -> Result<Self, KernelError> {
        let activation_id = activation_id.into();
        validate_id(&activation_id, "epoch_activation.activation_id")?;
        if new_lineage == prior_epoch.lineage_id {
            return Err(KernelError::InvalidField {
                field: "lineage_id",
                reason: "a lineage change must mint a globally distinct lineage",
            });
        }
        if fenced_routes.is_empty() {
            return Err(KernelError::InvalidField {
                field: "fenced_routes",
                reason: "a lineage change must fence the previous lineage's routes before admission",
            });
        }
        let transition = EpochTransition::genesis(new_lineage);
        let active_epoch = transition.current.clone();
        Ok(Self {
            activation_id,
            prior_epoch,
            active_epoch,
            transition,
            lineage_change: Some(cause),
            fenced_routes: distinct_routes(fenced_routes)?,
        })
    }

    /// Returns the activation identity.
    #[must_use]
    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    /// Returns the complete epoch this activation fences.
    #[must_use]
    pub const fn prior_epoch(&self) -> &EpochId {
        &self.prior_epoch
    }

    /// Returns the complete epoch this activation makes current.
    #[must_use]
    pub const fn active_epoch(&self) -> &EpochId {
        &self.active_epoch
    }

    /// Returns the explicit current/parent transition this activation records.
    ///
    /// The parent is explicit and cannot be inferred from a counter
    /// (`[types.EpochTransition]`). For a lineage change the parent is absent
    /// by construction, because the previous lineage is fenced rather than
    /// continued.
    #[must_use]
    pub const fn transition(&self) -> &EpochTransition {
        &self.transition
    }

    /// Returns the cause of the lineage change, or `None` for an in-lineage
    /// advance.
    #[must_use]
    pub const fn lineage_change(&self) -> Option<LineageChange> {
        self.lineage_change
    }

    /// Returns the routes fenced by this activation.
    #[must_use]
    pub fn fenced_routes(&self) -> &[RouteScope] {
        &self.fenced_routes
    }

    /// Returns `true` when this activation admits `epoch` as the active one.
    #[must_use]
    pub fn admits(&self, epoch: &EpochId) -> bool {
        epoch.is_same_authority(&self.active_epoch)
    }

    /// Returns `true` when `epoch` is fenced by this activation.
    ///
    /// Only the activation's own active tuple survives it. Every epoch of the
    /// lineage it replaced, and every epoch of any older lineage, is therefore
    /// fenced and cannot become active again through this record.
    #[must_use]
    pub fn fences(&self, epoch: &EpochId) -> bool {
        !epoch.is_same_authority(&self.active_epoch)
    }
}

/// Rejects a fenced-route list that names the same route twice.
fn distinct_routes(fenced_routes: Vec<RouteScope>) -> Result<Vec<RouteScope>, KernelError> {
    let mut seen = std::collections::BTreeSet::new();
    for route in &fenced_routes {
        if !seen.insert(route.clone()) {
            return Err(KernelError::InvalidField {
                field: "fenced_routes",
                reason: "must not contain duplicates",
            });
        }
    }
    Ok(fenced_routes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::EpochLineageId;
    use std::num::NonZeroU64;

    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
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

    fn fence(epoch: EpochId, route: &str) -> Result<RouteFence, KernelError> {
        RouteFence::new(
            RouteScope::new(route)?,
            epoch,
            ResourceGeneration::genesis(),
            Generation::new(1)?,
            "nonce-1",
        )
    }

    #[test]
    fn exact_fence_requires_field_for_field_equality() -> Result<(), KernelError> {
        let a = fence(canonical_epoch(LINEAGE, 1)?, "daemon")?;
        let mut b = a.clone();
        assert!(a.matches(&b));
        b.nonce = "different".to_owned();
        assert!(!a.matches(&b));
        Ok(())
    }

    #[test]
    fn stale_fence_is_rejected_for_the_exact_route() -> Result<(), KernelError> {
        let fence = fence(canonical_epoch(LINEAGE, 2)?, "store_bridge")?;
        let route = RouteScope::new("store_bridge")?;
        assert!(matches!(
            fence.enforce(&route, &canonical_epoch(LINEAGE, 3)?),
            Err(KernelError::StaleEpoch {
                observed: 2,
                active: 3
            })
        ));
        assert!(fence.enforce(&route, &canonical_epoch(LINEAGE, 2)?).is_ok());
        Ok(())
    }

    #[test]
    fn future_fence_is_rejected_for_the_exact_route() -> Result<(), KernelError> {
        let fence = fence(canonical_epoch(LINEAGE, 3)?, "store_bridge")?;
        let route = RouteScope::new("store_bridge")?;
        assert!(matches!(
            fence.enforce(&route, &canonical_epoch(LINEAGE, 2)?),
            Err(KernelError::FenceMismatch)
        ));
        Ok(())
    }

    #[test]
    fn wrong_route_fails_closed() -> Result<(), KernelError> {
        let fence = fence(canonical_epoch(LINEAGE, 2)?, "doctor")?;
        let route = RouteScope::new("daemon")?;
        assert!(matches!(
            fence.enforce(&route, &canonical_epoch(LINEAGE, 2)?),
            Err(KernelError::RouteMismatch)
        ));
        Ok(())
    }

    #[test]
    fn epoch_activation_must_strictly_raise_epoch() -> Result<(), KernelError> {
        assert!(
            EpochActivation::advance(
                "activation-1",
                canonical_epoch(LINEAGE, 3)?,
                canonical_epoch(LINEAGE, 3)?,
                Vec::new(),
            )
            .is_err()
        );
        let activation = EpochActivation::advance(
            "activation-1",
            canonical_epoch(LINEAGE, 3)?,
            canonical_epoch(LINEAGE, 4)?,
            vec![RouteScope::new("daemon")?],
        )?;
        assert_eq!(activation.prior_epoch().sequence.get(), 3);
        assert_eq!(activation.active_epoch().sequence.get(), 4);
        assert_eq!(activation.fenced_routes().len(), 1);
        assert_eq!(activation.lineage_change(), None);
        Ok(())
    }

    #[test]
    fn epoch_activation_rejects_duplicate_routes() -> Result<(), KernelError> {
        let route = RouteScope::new("daemon")?;
        assert!(
            EpochActivation::advance(
                "activation-1",
                canonical_epoch(LINEAGE, 1)?,
                canonical_epoch(LINEAGE, 2)?,
                vec![route.clone(), route],
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn canonical_tuple_authorizes_only_exact_match() -> Result<(), KernelError> {
        let active = canonical_epoch(LINEAGE, 4)?;
        let same = canonical_epoch(LINEAGE, 4)?;
        let cross_lineage_same_sequence = canonical_epoch(FOREIGN_LINEAGE, 4)?;
        let larger_cross_lineage = canonical_epoch(FOREIGN_LINEAGE, 9)?;
        let same_lineage_older = canonical_epoch(LINEAGE, 3)?;
        let route = RouteScope::new("daemon")?;
        let exact = fence(same.clone(), "daemon")?;
        let unrelated = fence(cross_lineage_same_sequence.clone(), "daemon")?;
        let foreign_newer = fence(larger_cross_lineage.clone(), "daemon")?;
        let older = fence(same_lineage_older.clone(), "daemon")?;

        assert!(exact.enforce(&route, &active).is_ok());
        // Equal sequences from different lineages are unrelated, not equal.
        assert!(matches!(
            unrelated.enforce(&route, &active),
            Err(KernelError::StaleEpochTuple { .. })
        ));
        // A numerically larger sequence from another lineage is not newer.
        assert!(matches!(
            foreign_newer.enforce(&route, &active),
            Err(KernelError::StaleEpochTuple { .. })
        ));
        assert!(matches!(
            older.enforce(&route, &active),
            Err(KernelError::StaleEpoch { .. })
        ));
        // Cross-lineage and same-lineage older fences are fenced; the exact
        // tuple and a same-lineage future tuple are not.
        assert!(!exact.is_stale(&active));
        assert!(unrelated.is_stale(&active));
        assert!(foreign_newer.is_stale(&active));
        assert!(older.is_stale(&active));
        assert!(
            !fence(same_lineage_older.clone(), "daemon")?.is_stale(&canonical_epoch(LINEAGE, 3)?)
        );
        Ok(())
    }

    #[test]
    fn canonical_direct_child_requires_same_lineage_single_step() -> Result<(), KernelError> {
        let parent = canonical_epoch(LINEAGE, 4)?;
        let child = canonical_epoch(LINEAGE, 5)?;
        let skipped = canonical_epoch(LINEAGE, 6)?;
        let cross_lineage = canonical_epoch(FOREIGN_LINEAGE, 5)?;
        let routes = vec![RouteScope::new("daemon")?];
        assert!(
            EpochActivation::advance(
                "activation-1",
                parent.clone(),
                child.clone(),
                routes.clone()
            )
            .is_ok()
        );
        assert!(
            EpochActivation::advance("activation-1", parent.clone(), skipped, routes.clone())
                .is_err()
        );
        assert!(
            EpochActivation::advance("activation-1", parent.clone(), cross_lineage, routes)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn canonical_digest_binds_lineage() -> Result<(), KernelError> {
        let left = fence(canonical_epoch(LINEAGE, 4)?, "daemon")?;
        let cross_lineage = fence(canonical_epoch(FOREIGN_LINEAGE, 4)?, "daemon")?;
        let next_sequence = fence(canonical_epoch(LINEAGE, 5)?, "daemon")?;
        let left_digest = left.epoch_digest()?;
        assert_eq!(left_digest, left.epoch_digest()?);
        assert_ne!(left_digest, cross_lineage.epoch_digest()?);
        assert_ne!(left_digest, next_sequence.epoch_digest()?);
        Ok(())
    }
}
