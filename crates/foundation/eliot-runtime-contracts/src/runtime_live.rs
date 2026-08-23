//! Canonical identity of the minimal runtime-live `SurrealDB` store.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The loopback bind reserved by the runtime-live store.
pub const RUNTIME_LIVE_STORE_BIND: &str = "127.0.0.1:8000";
/// The WebSocket RPC endpoint reserved by the runtime-live store.
pub const RUNTIME_LIVE_STORE_ENDPOINT: &str = "ws://127.0.0.1:8000/rpc";
/// The `SurrealDB` namespace reserved by the runtime-live store.
pub const RUNTIME_LIVE_STORE_NAMESPACE: &str = "eliot";

/// Failure while extracting the minimal store identity from `generation.json`.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RuntimeLiveStoreIdentityError {
    #[error("store configuration JSON is malformed: {0}")]
    Malformed(String),
}

#[derive(Deserialize)]
struct RuntimeLiveStoreConfigProjection {
    provider_bind_address: String,
    endpoint: String,
    namespace: String,
}

/// A typed, provider-neutral identity for a runtime-live store.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLiveStoreIdentity {
    /// Exact loopback bind address.
    pub bind: String,
    /// Exact WebSocket RPC endpoint.
    pub endpoint: String,
    /// Exact `SurrealDB` namespace.
    pub namespace: String,
}

impl RuntimeLiveStoreIdentity {
    /// Constructs the canonical runtime-live identity.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            bind: RUNTIME_LIVE_STORE_BIND.to_owned(),
            endpoint: RUNTIME_LIVE_STORE_ENDPOINT.to_owned(),
            namespace: RUNTIME_LIVE_STORE_NAMESPACE.to_owned(),
        }
    }

    /// Returns true only for an exact bind, endpoint and namespace match.
    #[must_use]
    pub fn is_exact_match(&self, bind: &str, endpoint: &str, namespace: &str) -> bool {
        self.bind == bind && self.endpoint == endpoint && self.namespace == namespace
    }

    /// Extracts only the provider bind, endpoint and namespace from a store
    /// launch JSON document. Unknown fields remain the consumer's concern.
    pub fn from_store_config_json(bytes: &[u8]) -> Result<Self, RuntimeLiveStoreIdentityError> {
        let projection: RuntimeLiveStoreConfigProjection = serde_json::from_slice(bytes)
            .map_err(|error| RuntimeLiveStoreIdentityError::Malformed(error.to_string()))?;
        Ok(Self {
            bind: projection.provider_bind_address,
            endpoint: projection.endpoint,
            namespace: projection.namespace,
        })
    }

    /// Returns whether this parsed store document is the canonical identity.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        Self::canonical() == *self
    }
}

impl Default for RuntimeLiveStoreIdentity {
    fn default() -> Self {
        Self::canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_identity_is_stable() {
        let identity = RuntimeLiveStoreIdentity::canonical();
        assert_eq!(identity.bind, RUNTIME_LIVE_STORE_BIND);
        assert_eq!(identity.endpoint, RUNTIME_LIVE_STORE_ENDPOINT);
        assert_eq!(identity.namespace, RUNTIME_LIVE_STORE_NAMESPACE);
        assert!(identity.is_exact_match(
            RUNTIME_LIVE_STORE_BIND,
            RUNTIME_LIVE_STORE_ENDPOINT,
            RUNTIME_LIVE_STORE_NAMESPACE,
        ));
    }

    #[test]
    fn identity_match_requires_every_component() {
        let identity = RuntimeLiveStoreIdentity::canonical();
        assert!(!identity.is_exact_match("127.0.0.1:8001", RUNTIME_LIVE_STORE_ENDPOINT, "eliot"));
        assert!(!identity.is_exact_match(
            RUNTIME_LIVE_STORE_BIND,
            "ws://127.0.0.1:8001/rpc",
            "eliot"
        ));
        assert!(!identity.is_exact_match(
            RUNTIME_LIVE_STORE_BIND,
            RUNTIME_LIVE_STORE_ENDPOINT,
            "other"
        ));
    }

    #[test]
    fn store_config_projection_ignores_unrelated_fields()
    -> Result<(), RuntimeLiveStoreIdentityError> {
        let identity = RuntimeLiveStoreIdentity::from_store_config_json(
            br#"{"provider_bind_address":"127.0.0.1:8000","endpoint":"ws://127.0.0.1:8000/rpc","namespace":"eliot","provider_arguments":["--bind"]}"#,
        )?;
        assert!(identity.is_canonical());
        Ok(())
    }
}
