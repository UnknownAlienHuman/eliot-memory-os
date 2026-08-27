//! Typed authority-owner recovery for the Governor semantic boundary.
//!
//! Architecture traceability: `ARCH-AUTH-01` and `ARCH-SEC-02` require the
//! Governor to restore authority-owned state without minting authority;
//! `ARCH-RES-01`, `A13.6`, and `I1.8` bind recovery to one exact state fence;
//! `A13.6` keeps Kernel recovery opaque while this owner performs semantic
//! decoding. Implementation anchors are `P.3`, `I2.2`, and `I2.23`: the
//! payload is versioned and deny-unknown, and ordinary-module extraction does
//! not create a new provider or failure domain.
//!
//! Forbidden boundary: this module never issues leases, mints tokens,
//! activates effects, invents an empty replacement for non-empty durable
//! state, or lets Kernel decode these semantic records.

use super::CompositionError;
use eliot_authority::{
    EffectAuthorizer, EffectAuthorizerRecoverySnapshot, GrantGraph, GrantGraphRecoverySnapshot,
};
use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Versioned semantic owner payload retained by Governor recovery.
pub const AUTHORITY_OWNER_SNAPSHOT_SCHEMA: &str = "eliot.governor.authority-owner.v1";
pub const AUTHORITY_OWNER_SNAPSHOT_VERSION: u16 = 1;

/// Complete typed authority state bound to one outer Governor fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOwnerSnapshot {
    /// Closed owner-payload schema identity.
    pub schema: String,
    /// Closed owner-payload schema version.
    pub version: u16,
    /// Exact Governor recovery fence.
    pub state_fence: StateFence,
    /// Full deterministic grant-lineage snapshot.
    pub grant_graph: GrantGraphRecoverySnapshot,
    /// Full deterministic effect-idempotency snapshot.
    pub effect_authorizer: EffectAuthorizerRecoverySnapshot,
}

impl AuthorityOwnerSnapshot {
    /// Constructs a typed payload after validating both authority snapshots.
    pub fn new(
        state_fence: StateFence,
        grant_graph: GrantGraphRecoverySnapshot,
        effect_authorizer: EffectAuthorizerRecoverySnapshot,
    ) -> Result<Self, CompositionError> {
        let snapshot = Self {
            schema: AUTHORITY_OWNER_SNAPSHOT_SCHEMA.to_owned(),
            version: AUTHORITY_OWNER_SNAPSHOT_VERSION,
            state_fence,
            grant_graph,
            effect_authorizer,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Validates schema, semantic authority state, and exact nested fences.
    pub fn validate(&self) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self.schema != AUTHORITY_OWNER_SNAPSHOT_SCHEMA
            || self.version != AUTHORITY_OWNER_SNAPSHOT_VERSION
        {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has an invalid schema or version".to_owned(),
            ));
        }
        self.grant_graph
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        self.effect_authorizer
            .validate()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        if self
            .grant_graph
            .grants
            .iter()
            .any(|grant| grant.binding.state_fence != self.state_fence)
        {
            return Err(CompositionError::Recovery(
                "authority grant snapshot contains a stale nested fence".to_owned(),
            ));
        }
        if self
            .effect_authorizer
            .records
            .iter()
            .any(|record| record.operation.state_fence != self.state_fence)
        {
            return Err(CompositionError::Recovery(
                "authority effect snapshot contains a stale nested fence".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_against(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        self.validate()?;
        if self.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "authority owner snapshot has a stale outer fence".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authority owner retaining only restored, pure authority state.
#[derive(Clone, Debug)]
pub struct AuthorityOwner {
    /// Exact Governor recovery fence retained with the restored authority state.
    state_fence: StateFence,
    /// Effect-level authorizer restored from its complete typed snapshot.
    pub effects: EffectAuthorizer,
    /// Grant graph lineage restored from its complete typed snapshot.
    pub grants: GrantGraph,
}

impl AuthorityOwner {
    pub(super) fn from_snapshot(
        snapshot: &AuthorityOwnerSnapshot,
        expected_fence: &StateFence,
    ) -> Result<Self, CompositionError> {
        snapshot.validate_against(expected_fence)?;
        let grants = GrantGraph::from_recovery_snapshot(snapshot.grant_graph.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effects = EffectAuthorizer::from_snapshot(snapshot.effect_authorizer.clone())
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        Ok(Self {
            state_fence: snapshot.state_fence.clone(),
            effects,
            grants,
        })
    }

    /// Returns the exact fence retained by this authority owner.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Emits the complete deterministic typed authority recovery payload.
    pub fn snapshot(&self) -> Result<AuthorityOwnerSnapshot, CompositionError> {
        let grant_graph = self
            .grants
            .recovery_snapshot()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        let effect_authorizer = self
            .effects
            .snapshot()
            .map_err(|error| CompositionError::Recovery(error.to_string()))?;
        AuthorityOwnerSnapshot::new(self.state_fence.clone(), grant_graph, effect_authorizer)
    }
}
