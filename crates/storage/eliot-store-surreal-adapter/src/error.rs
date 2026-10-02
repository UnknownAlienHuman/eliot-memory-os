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

/// Bounded ceiling on the provider `kind` word retained by
/// [`AdapterError::ProviderRefused`] (#937, #938, #940).
///
/// The pinned `v3.1.4` provider states `kind` as a closed failure-family tag
/// (`ErrorDetails::kind_str`, documented on `client::rpc_parse::RpcErrorBody`),
/// but nothing in this crate bounds the length of a string a frame may carry,
/// so the retained word is truncated to this ceiling on a `char` boundary. The
/// vendor `details` object is never retained at all and has no ceiling here:
/// it is unbounded vendor prose and no public error member may retain it.
const PROVIDER_KIND_MAX_CHARS: usize = 64;

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
    /// Canonical allocation contention (S-CONC-TX, issue #989).
    ///
    /// The canonical transaction aborted on the shared fence/sequence
    /// compare-and-set while carrying no semantic revision/ordering/owner-row
    /// conflict marker. Classification is a closed typed protocol (exact
    /// fence-CAS sentinel tokens plus a clean statement-error denominator in
    /// `apply/atomic_write`, never prose inference), and the fence CAS
    /// precedes the receipt create in statement order, so this outcome is
    /// proved-not-committed for this operation identity: the bounded
    /// allocation retry may re-read the fence and recompute only
    /// allocation-dependent values under the unchanged semantic contract. It
    /// is never a semantic stale-head conflict and never an unknown outcome.
    #[error(
        "canonical allocation contention; re-read allocation by operation identity {operation_id}"
    )]
    AllocationContention { operation_id: String },
    /// A provider error frame refused the request (#937, #938, #940).
    ///
    /// Distinct from [`Self::ProviderUnavailable`], which every local
    /// transport, pool and health condition in this crate also produces and for
    /// which no provider frame exists that could state a cause. Here the
    /// provider answered, so the bounded, non-content-bearing facts it stated
    /// are retained: `kind`, its own failure family, and `code`, its JSON-RPC
    /// numeric code.
    ///
    /// `kind` is the provider's word, never an ELIOT verdict, and stays `None`
    /// when the frame named none: an absent family is recorded as no family
    /// stated and is never promoted to an authentication, validation, query or
    /// internal cause. `crate::error::AdapterError::provider_refused` is the only
    /// construction path: it bounds the retained word and deliberately accepts
    /// no `message` or `details` argument, so no caller can retain unbounded
    /// vendor prose in it.
    #[error("provider refused the request; provider kind = {kind:?}, provider code = {code}")]
    ProviderRefused { kind: Option<String>, code: i64 },
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
    /// Builds the bounded refusal record for one provider error frame
    /// (#937, #938, #940).
    ///
    /// `kind` is retained exactly as the provider stated it, or `None` when the
    /// frame stated none; a word longer than [`PROVIDER_KIND_MAX_CHARS`] is
    /// truncated on a `char` boundary and marked with an ellipsis, so the
    /// payload stays bounded whatever a frame carries. `code` is the provider's
    /// numeric JSON-RPC code and is bounded by construction.
    ///
    /// The provider's `message` and `details` are not accepted as arguments at
    /// all: they are unbounded vendor prose, and this signature is the reason
    /// neither can reach this payload, `Display` or `Debug`.
    pub(crate) fn provider_refused(code: i64, kind: Option<&str>) -> Self {
        Self::ProviderRefused {
            kind: kind.map(|kind| {
                if kind.chars().count() > PROVIDER_KIND_MAX_CHARS {
                    let retained: String = kind.chars().take(PROVIDER_KIND_MAX_CHARS).collect();
                    format!("{retained}...")
                } else {
                    kind.to_owned()
                }
            }),
            code,
        }
    }

    /// Maps an adapter error to the store boundary without wildcard collapse.
    /// Each provider observation keeps a distinct typed `StoreError` so
    /// `StoreFailure::from_store_error` preserves its disposition:
    /// transport loss stays retryable `Unavailable`; provider
    /// compare-and-set conflict stays `RevisionConflict`; transient canonical
    /// allocation contention (S-CONC-TX, issue #989) stays retryable
    /// `Unavailable` and never a false semantic `RevisionConflict`; unknown
    /// or partial provider outcomes stay reconciling
    /// `MissingReceiptEnvelope` (the admitted operation identity at the
    /// dispatch boundary is the reconciliation key; this variant itself
    /// carries no identity); unavailable named operations stay unsupported
    /// `UnknownOperation`; configuration defects stay deterministic
    /// `InvalidField` and serialization defects stay `Serialization`, both
    /// with provider prose dropped in favour of bounded static text.
    ///
    /// Contract ceiling (honest stop; extending it needs a Contract Challenge
    /// owned outside Wave A): `StoreError` has no Backpressure, Deadline,
    /// `MigrationRequired` or `Partial` variants, so `MigrationRequired` and
    /// `UnknownMigrationOutcome` remain `Unavailable` here and can never
    /// produce the `MigrationRequired`, `Backpressured` or `DeadlineExceeded`
    /// dispositions. Live migration paths keep their exact outcome via
    /// `map_schema_bootstrap_error`, not this function.
    ///
    /// Second contract ceiling, for [`Self::ProviderRefused`]: `StoreError` has
    /// no payload-bearing member that can carry a bounded provider cause
    /// without asserting a cause the provider did not state. Its only
    /// payload-bearing members are `InvalidField` (two `&'static str`, so a
    /// dynamic family cannot cross, plus a deterministic field verdict),
    /// `TransitionDigestMismatch` (a digest verdict), `Serialization` and
    /// `Security` (an authentication verdict). Mapping a `Query`,
    /// `Validation`, `Internal` or absent `kind` onto any of them would invent
    /// exactly the verdict this variant exists to stop, so the typed
    /// disposition stays the transport-loss `Unavailable` and the provider's
    /// `kind` and `code` stay readable above the `StoreError` seam, on the
    /// adapter's own error. This is a stated ceiling, not a claim that
    /// `Unavailable` is the right retry class for every provider refusal: it is
    /// the disposition [`Self::ProviderUnavailable`] already produced for these
    /// frames, so this arm neither improves nor worsens it.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error,
            Self::ProviderUnavailable | Self::AllocationContention { .. } => {
                StoreError::Unavailable
            }
            Self::ProviderRefused { .. } => StoreError::Unavailable,
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
    fn unknown_outcome_maps_to_missing_receipt_envelope() {
        let error = AdapterError::UnknownOutcome {
            operation_id: "op-1".to_owned(),
        };
        assert_eq!(error.into_store_error(), StoreError::MissingReceiptEnvelope);
    }

    #[test]
    fn allocation_contention_is_transient_never_a_semantic_conflict() {
        let error = AdapterError::AllocationContention {
            operation_id: "op-alloc-1".to_owned(),
        };
        assert_eq!(error.clone().into_store_error(), StoreError::Unavailable);
        assert_ne!(
            error.clone().into_store_error(),
            StoreError::RevisionConflict
        );
        assert_ne!(error.into_store_error(), StoreError::MissingReceiptEnvelope);
    }

    #[test]
    fn deterministic_conflict_mapping_is_preserved() {
        assert_eq!(
            AdapterError::ProviderConflict.into_store_error(),
            StoreError::RevisionConflict
        );
        assert_eq!(
            AdapterError::ProviderUnavailable.into_store_error(),
            StoreError::Unavailable
        );
        assert_eq!(
            AdapterError::PartialOutcome.into_store_error(),
            StoreError::MissingReceiptEnvelope
        );
    }
}
