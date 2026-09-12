//! Adapter error model retaining recovery-relevant provider outcomes.
//!
//! `UnknownOutcome` is deliberately richer than `StoreError::Unavailable`: the
//! bridge surfaces it through its own methods so a caller can reconcile by
//! exact operation identity. Where only a `StoreError` can cross (the
//! [`CanonicalStoreClient`](eliot_store_api::CanonicalStoreClient) trait), it
//! maps to `StoreError::MissingReceiptEnvelope`, which preserves the unknown
//! outcome and exact-operation reconciliation once the dispatch boundary
//! supplies the admitted operation identity.

use eliot_store_api::StoreError;
use thiserror::Error;

/// Failure of the `SurrealDB` store bridge.
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
    /// Maps an adapter error to the store boundary without wildcard collapse.
    /// Each provider observation keeps a distinct typed `StoreError` so
    /// `StoreFailure::from_store_error` preserves its disposition:
    /// transport loss stays retryable `Unavailable`; provider
    /// compare-and-set conflict stays `RevisionConflict`; unknown or partial
    /// provider outcomes stay reconciling `MissingReceiptEnvelope` (the
    /// admitted operation identity at the dispatch boundary is the
    /// reconciliation key; this variant itself carries no identity);
    /// unavailable named operations stay unsupported `UnknownOperation`;
    /// configuration defects stay deterministic `InvalidField` and
    /// serialization defects stay `Serialization`, both with provider prose
    /// dropped in favour of bounded static text.
    /// Contract ceiling (honest stop; extending it needs a Contract Challenge
    /// owned outside Wave A): `StoreError` has no Backpressure, Deadline,
    /// `MigrationRequired` or `Partial` variants, so `MigrationRequired` and
    /// `UnknownMigrationOutcome` remain `Unavailable` here and can never
    /// produce the `MigrationRequired`, `Backpressured` or `DeadlineExceeded`
    /// dispositions. Live migration paths keep their exact outcome via
    /// `map_schema_bootstrap_error`, not this function.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error,
            Self::ProviderUnavailable => StoreError::Unavailable,
            Self::ProviderConflict => StoreError::RevisionConflict,
            Self::UnknownOutcome { .. } | Self::PartialOutcome => {
                StoreError::MissingReceiptEnvelope
            }
            Self::NamedOperationUnavailable { .. } => StoreError::UnknownOperation,
            Self::Config(_) => StoreError::InvalidField {
                field: "store.configuration",
                reason: "invalid store configuration",
            },
            Self::Serialization(_) => StoreError::Serialization(
                "canonical provider response serialization failed".to_owned(),
            ),
            Self::MigrationRequired | Self::UnknownMigrationOutcome { .. } => {
                StoreError::Unavailable
            }
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
