//! Durable initial owner of one capability route scope (issue #1872).
//!
//! `I14.14` makes the active generation of a route registry state, and `I5.11`
//! stage 8 the only transition that may change it: "commit the
//! `canonical_store` `CapabilityRouteScope` cutover through Kernel Generation
//! Registry". A route that has never been cut over therefore has no
//! `GenerationCutoverOwnership` row to read, and "no committed cutover for this
//! scope" is on its own indistinguishable from "any generation may own this
//! route". That is the state every installation starts in, so a configuration
//! change or a restart could install an approved but uncommitted candidate
//! bridge on the canonical route with no stage evidence at all.
//!
//! This row is the missing owner record. It states which generation a route
//! scope *started* at, it is written once per scope, and the only thing that may
//! replace it is a committed [`crate::GenerationCutoverOwnership`] cutover for
//! the same scope. It is deliberately NOT a cutover record and never claims to
//! be one: it carries no epoch transition, no in-flight disposition set and no
//! linearization identity, because no switch happened to record.
//!
//! The row is named by its scope hash, which is the same stable
//! [`crate::CapabilityRouteScope::declare`] hash every committed cutover row is
//! filtered on, so the two families cannot disagree about which scope they are
//! talking about.

use eliot_contracts::ResourceGeneration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::model::{OrsError, validate_digest};

/// The durable record of the generation a capability route scope started at.
///
/// It answers exactly one question — which generation owns this scope before any
/// cutover has been committed — and its whole content is compared against the
/// generation a caller presents, so its existence proves nothing on its own:
/// only the equality of [`Self::initial_generation`] with the presented
/// generation admits anything.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalStoreRouteOwnership {
    /// Stable [`crate::CapabilityRouteScope`] hash this row is the owner of.
    pub route_scope_hash: String,
    /// The generation that owned the scope before any committed cutover.
    pub initial_generation: ResourceGeneration,
}

impl CanonicalStoreRouteOwnership {
    /// Validates the row's own shape.
    ///
    /// The scope hash is checked for digest shape here and against the scope it
    /// was loaded under by the reader, so a stored row can never be read back as
    /// the owner record of a scope it does not name.
    pub fn validate(&self) -> Result<(), OrsError> {
        validate_digest(
            self.route_scope_hash.as_str(),
            "canonical_store_route_scope_hash",
        )?;
        if self.initial_generation.value() == 0 {
            return Err(OrsError::InvalidField {
                field: "canonical_store_route_initial_generation",
                reason: "the recorded initial generation must be greater than zero",
            });
        }
        Ok(())
    }
}
