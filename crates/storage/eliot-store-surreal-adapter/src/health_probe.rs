//! Passive health projection for the `SurrealDB` store bridge.
//!
//! Architecture: A4.5 (anchored observations), A5.1 (observations are not
//! reality), A12.3 (one governed canonical write path).
//! Implementation: I5.1-I5.3 (storage bridge and store-neutral API), I5.20
//! (bounded read model).
//! Ownership: map existing bridge observations only; no provider/process,
//! migration/schema, credential, filesystem, recovery, write/effect, or
//! authority ownership.

use super::probe_readiness;
use crate::SurrealStoreAdapter;
use crate::health::{AdapterAvailability, AdapterHealth, ProviderHealth};
use crate::readiness::SemanticReadiness;
use eliot_store_api::{CONTRACT_VERSION, StoreError, StoreHealth, StoreHealthStatus};

/// Bounded bridge health observation.
///
/// `Available` is deliberately withheld until the semantic readiness probe
/// confirms both the expected schema generation and the canonical fence. A
/// reachable provider with missing/mismatched schema remains unavailable to
/// Store callers.
pub(crate) async fn adapter_health(adapter: &SurrealStoreAdapter) -> AdapterHealth {
    match probe_readiness(adapter).await {
        Ok(SemanticReadiness::Ready { generation }) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Available,
            provider: ProviderHealth::Reachable,
            schema_generation: Some(generation.to_string()),
        },
        Ok(SemanticReadiness::MigrationRequired { observed, .. }) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::MigrationUnavailable,
            provider: ProviderHealth::Reachable,
            schema_generation: observed,
        },
        Ok(SemanticReadiness::Unavailable) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::Unavailable,
            provider: ProviderHealth::Unknown,
            schema_generation: None,
        },
        Err(_) => AdapterHealth {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            availability: AdapterAvailability::ProviderUnavailable,
            provider: ProviderHealth::Unavailable,
            schema_generation: None,
        },
    }
}

/// Maps the bridge availability to the bounded store health status.
pub(crate) async fn health(adapter: &SurrealStoreAdapter) -> Result<StoreHealth, StoreError> {
    let health = adapter_health(adapter).await;
    let status = match health.availability {
        AdapterAvailability::Available => StoreHealthStatus::Ready,
        AdapterAvailability::MigrationUnavailable | AdapterAvailability::ProviderUnavailable => {
            StoreHealthStatus::Unavailable
        }
        AdapterAvailability::Unavailable => StoreHealthStatus::Degraded,
    };
    let digest = adapter.operation_manifest.digest.clone();
    Ok(StoreHealth {
        status,
        contract_version: CONTRACT_VERSION,
        manifest_digest: digest,
    })
}
