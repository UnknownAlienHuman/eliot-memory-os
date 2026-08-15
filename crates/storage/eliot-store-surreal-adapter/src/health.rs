//! Bounded provider and adapter health observations.
//!
//! These types report liveness and schema-generation position. They are
//! observations, never semantic readiness or authority verdicts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_protocol::ProtocolVersion;

/// Liveness observation of the SurrealDB provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealth {
    Unknown,
    Unavailable,
    Reachable,
}

/// Typed availability of the store bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdapterAvailability {
    Unavailable,
    MigrationUnavailable,
    ProviderUnavailable,
    Available,
}

/// Health observation from the bridge, never a semantic readiness verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdapterHealth {
    /// Exact C0-07 EBP revision exposed by the S-03 bridge surface.
    pub protocol_version: ProtocolVersion,
    pub availability: AdapterAvailability,
    pub provider: ProviderHealth,
    pub schema_generation: Option<String>,
}

impl AdapterHealth {
    /// Reports that the bridge has not been probed yet.
    pub const fn unprobed() -> Self {
        Self {
            protocol_version: ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Unavailable,
            provider: ProviderHealth::Unknown,
            schema_generation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_round_trips_serde() {
        let health = AdapterHealth {
            protocol_version: ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Available,
            provider: ProviderHealth::Reachable,
            schema_generation: Some("1.0.0".to_owned()),
        };
        let encoded = serde_json::to_value(&health).expect("serialize");
        let decoded: AdapterHealth = serde_json::from_value(encoded).expect("deserialize");
        assert_eq!(decoded, health);
    }

    #[test]
    fn unprobed_is_unknown() {
        let health = AdapterHealth::unprobed();
        assert_eq!(health.availability, AdapterAvailability::Unavailable);
        assert_eq!(health.provider, ProviderHealth::Unknown);
        assert!(health.schema_generation.is_none());
    }
}
