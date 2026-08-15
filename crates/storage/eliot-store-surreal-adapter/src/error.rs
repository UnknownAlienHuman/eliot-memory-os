//! Adapter error model retaining recovery-relevant provider outcomes.
//!
//! `UnknownOutcome` is deliberately richer than `StoreError::Unavailable`: the
//! bridge surfaces it through its own methods so a caller can reconcile by
//! exact operation identity. The [`CanonicalStoreClient`](eliot_store_api::CanonicalStoreClient)
//! trait collapses it to `StoreError::Unavailable`, which is the signal that a
//! caller must resolve the durable receipt before retrying.

use eliot_store_api::StoreError;
use thiserror::Error;

/// Failure of the SurrealDB store bridge.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AdapterError {
    #[error("provider is unavailable")]
    ProviderUnavailable,
    #[error("schema migration is required before canonical access")]
    MigrationRequired,
    #[error("provider outcome is unknown; reconcile by operation identity {operation_id}")]
    UnknownOutcome { operation_id: String },
    #[error("migration outcome is unknown; reconcile migration {migration_id}")]
    UnknownMigrationOutcome { migration_id: String },
    #[error("provider reported a partial outcome")]
    PartialOutcome,
    #[error("provider-side compare-and-set conflict")]
    ProviderConflict,
    #[error("named operation is unavailable: {operation}")]
    NamedOperationUnavailable { operation: String },
    #[error("configuration error: {0}")]
    Config(String),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

impl AdapterError {
    /// Collapses an adapter error to the store boundary. Unknown or provider
    /// failures become `StoreError::Unavailable` so the caller resolves the
    /// durable receipt before retrying; deterministic validation failures keep
    /// their typed store error.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error,
            Self::ProviderUnavailable
            | Self::MigrationRequired
            | Self::UnknownOutcome { .. }
            | Self::UnknownMigrationOutcome { .. }
            | Self::PartialOutcome
            | Self::ProviderConflict
            | Self::NamedOperationUnavailable { .. }
            | Self::Config(_)
            | Self::Serialization(_) => StoreError::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_round_trip_unchanged() {
        let error = AdapterError::Store(StoreError::RevisionConflict);
        assert_eq!(error.into_store_error(), StoreError::RevisionConflict);
    }

    #[test]
    fn unknown_outcome_collapses_to_unavailable() {
        let error = AdapterError::UnknownOutcome {
            operation_id: "op-1".to_owned(),
        };
        assert_eq!(error.into_store_error(), StoreError::Unavailable);
    }
}
