//! Durable irreversible storage-effect declaration for a committed route
//! cutover (issue #1872; I5.11, I14.14).
//!
//! `I5.11` closes with one sentence that is a decision procedure and not a
//! stage: "Rollback switches generation back only if no irreversible
//! migration/effect occurred; otherwise uses forward repair." The decision needs
//! a record of *whether an irreversible effect occurred*, and the only durable
//! record the existing cutover family carries is the committed
//! [`crate::GenerationCutoverOwnership`] row's `migration` decision — which is
//! fixed at the linearization point, by construction, because that is what a
//! linearization point means. An effect issued *after* that point is therefore
//! in no committed row of that family, and this row is where it goes.
//!
//! It is deliberately NOT a second route owner, a second cutover machine, or a
//! second store. It has no epoch transition, no route, no artifact identity and
//! no in-flight set, because none of those happened: no switch occurred to
//! record. It answers exactly one question — did an irreversible effect occur
//! on this route scope under this committed cutover — and the rollback decision
//! reads it through the same [`crate::RedbRecoveryStore`] that already owns
//! every other durable fact about this route.
//!
//! Every field is either owner-issued or a coordinate the committed cutover row
//! already carries, and the writer re-derives the two that matter rather than
//! accepting them:
//!
//! - `cutover_linearization_record_id` is read out of the committed
//!   [`crate::GenerationCutoverOwnership`] row inside the same write
//!   transaction that writes this declaration, and a presented value that
//!   differs from it is refused. A declaration can therefore not name a
//!   cutover identity, an epoch or a generation the committed cutover does not
//!   itself carry.
//! - `linearization_record_id` is minted by the writer from the store's own
//!   operational order. A caller cannot supply it, so a row cannot claim a
//!   durable position it was not written at.
//!
//! The row is write-once by content under its own key, exactly like
//! [`crate::CanonicalStoreRouteOwnership`]: an identical declaration is
//! idempotent and a different one under the same key is refused, because an
//! irreversible effect that occurred can never be re-described as a different
//! one.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::{OrsError, validate_digest, validate_text};

/// The two irreversible storage effects `I5.11` names.
///
/// This is the durable owner's copy of the class, owned here beside the
/// [`crate::StateMigrationDecision`] that the same rule reads at the cutover.
/// `eliot-kernel-service` re-exports this exact type rather than declaring a
/// second one, so the coordinator's ledger and this durable row cannot drift
/// into two vocabularies: there is one class, one spelling and one wire name.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IrreversibleStorageEffect {
    /// The candidate's imported state cannot be reconciled back into the
    /// incumbent store, so a generation switch back would lose canonical data.
    IrreversibleMigration,
    /// A canonical or external effect was already issued through the candidate
    /// route, so the effect must be reconciled forward rather than undone.
    ExternalEffectIssued,
}

impl std::fmt::Display for IrreversibleStorageEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::IrreversibleMigration => "irreversible_migration",
            Self::ExternalEffectIssued => "external_effect_issued",
        })
    }
}

/// One durable declaration that an irreversible migration or external effect
/// occurred on a `canonical_store` route scope under a committed cutover.
///
/// The whole content is compared with the operation that reads it: the reader
/// loads the committed [`crate::GenerationCutoverOwnership`] row this names and
/// requires the scope, the committed state and the linearization identity to be
/// the ones that row itself carries. Existence of a row proves nothing on its
/// own, which is why [`Self::validate`] checks shape and the store's reader
/// checks the binding.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrreversibleStorageEffectRecord {
    /// Stable [`crate::CapabilityRouteScope`] hash the effect occurred on.
    pub route_scope_hash: String,
    /// Identity of the committed cutover the effect occurred under.
    pub cutover_id: String,
    /// That committed cutover row's own ORS linearization identity.
    ///
    /// Written by the store from the committed row, never accepted from a
    /// caller, so a declaration is bound to the exact durable switch it
    /// describes.
    pub cutover_linearization_record_id: String,
    /// Which irreversible effect occurred.
    pub effect: IrreversibleStorageEffect,
    /// ORS linearization identity of this declaration; `None` while presented,
    /// assigned by the writer inside the transaction that makes the row
    /// durable.
    pub linearization_record_id: Option<String>,
}

impl IrreversibleStorageEffectRecord {
    /// Validates the row's own shape.
    ///
    /// The cutover binding is NOT checked here: it needs the committed cutover
    /// row, so it is proved by the store's writer against the original recorded
    /// value rather than re-derived against a value the caller presented.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(
            self.route_scope_hash.as_str(),
            "irreversible_storage_effect_route_scope_hash",
        )?;
        validate_text(&self.cutover_id, "irreversible_storage_effect_cutover_id")?;
        validate_text(
            &self.cutover_linearization_record_id,
            "irreversible_storage_effect_cutover_linearization",
        )?;
        if let Some(linearization) = &self.linearization_record_id {
            validate_text(
                linearization,
                "irreversible_storage_effect_linearization",
            )?;
        }
        Ok(())
    }

    /// Returns the exact durable key this row is filed under.
    ///
    /// The key is derived from the whole owner-bound content rather than from an
    /// identity the caller chose, so a retry of the same declaration lands on
    /// the same row and two different declarations can never share one.
    pub fn key(&self) -> Result<String, OrsError> {
        self.validate()?;
        Ok(format!(
            "{}:{}:{}",
            self.route_scope_hash, self.cutover_id, self.effect
        ))
    }

    /// Returns whether a stored row describes the same declaration as this one.
    ///
    /// The writer's own [`Self::linearization_record_id`] is excluded: it is
    /// owner-allocated progression, not part of what was declared, so an exact
    /// replay is one declaration and must not be read as a different one.
    #[must_use]
    pub fn same_declaration(&self, other: &Self) -> bool {
        self.route_scope_hash == other.route_scope_hash
            && self.cutover_id == other.cutover_id
            && self.cutover_linearization_record_id == other.cutover_linearization_record_id
            && self.effect == other.effect
    }
}
