//! Sole SurrealDB credential and client owner for the ELIOT canonical store.
//!
//! This crate is the only place that holds SurrealDB credentials and drives the
//! versioned named-operation WebSocket/RPC bridge. It implements the
//! store-neutral [`CanonicalStoreClient`] contract so that no provider client
//! type, credential, physical table name or raw query string crosses this
//! boundary.
//!
//! The adapter is the single writer to the canonical control tables. It
//! preserves the complete transition, projection, and outbox surface,
//! commits receipts atomically, and supports reconciliation of unknown write
//! outcomes by exact operation identity. Canonical access is gated on schema
//! generation (`semantic readiness`); migrations are applied only through an
//! explicit, checksummed [`CompiledMigration`].

#![forbid(unsafe_code)]

mod apply;
mod client;
mod config;
mod error;
mod health;
mod plan;
mod readiness;
mod schema;

use std::fmt;

pub use config::{
    ADAPTER_NAME, ConfigError, PINNED_SURREALDB_MAJOR, SchemaGeneration, SchemaGenerationError,
    SurrealAdapterConfig,
};
use eliot_platform::ClockObservation;
use eliot_store_api::{
    CONTRACT_VERSION, CanonicalStoreClient, EffectClass, NamedOperationManifest, NamedReadRequest,
    NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, RevisionHead, RevisionHeadExpectation, RevisionKey, ScopeId,
    ScopeRevisionView, StoreError, StoreHealth, TransitionClass, WriteReceipt,
};
pub use error::AdapterError;
pub use health::{AdapterAvailability, AdapterHealth, ProviderHealth};
pub use readiness::{CompiledMigration, MigrationReceipt, SemanticReadiness};

/// The sole SurrealDB credential and client owner for the ELIOT canonical
/// store.
pub struct SurrealStoreAdapter {
    pub(crate) config: SurrealAdapterConfig,
    pub(crate) client: tokio::sync::OnceCell<client::RpcTransport>,
    pub(crate) write_lock: tokio::sync::Mutex<()>,
    /// Immutable closed operation manifest admitted by this adapter instance.
    pub(crate) operation_manifest: NamedOperationManifest,
}

impl fmt::Debug for SurrealStoreAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealStoreAdapter")
            .field("config", &self.config)
            .field("connected", &self.client.get().is_some())
            .finish()
    }
}

impl SurrealStoreAdapter {
    /// Builds an adapter with the given connection and generation settings.
    pub fn new(config: SurrealAdapterConfig) -> Self {
        Self {
            config,
            client: tokio::sync::OnceCell::new(),
            write_lock: tokio::sync::Mutex::new(()),
            operation_manifest: default_manifest(),
        }
    }

    /// Builds an adapter with an explicit immutable manifest supplied by the
    /// composition owner. The manifest is validated once and cannot be
    /// replaced while the adapter is live.
    pub fn new_with_manifest(
        config: SurrealAdapterConfig,
        manifest: NamedOperationManifest,
    ) -> Result<Self, StoreError> {
        manifest.validate()?;
        Ok(Self {
            config,
            client: tokio::sync::OnceCell::new(),
            write_lock: tokio::sync::Mutex::new(()),
            operation_manifest: manifest,
        })
    }

    /// Returns the (redacted) configuration.
    pub fn config(&self) -> &SurrealAdapterConfig {
        &self.config
    }

    /// Returns the immutable manifest bound to this adapter.
    pub fn operation_manifest(&self) -> &NamedOperationManifest {
        &self.operation_manifest
    }

    /// Establishes and authenticates the client connection eagerly.
    pub async fn connect(&self) -> Result<(), AdapterError> {
        let _ = apply::client(self).await?;
        Ok(())
    }

    /// Observes the database's semantic readiness against the configured
    /// schema generation.
    pub async fn probe_readiness(&self) -> Result<SemanticReadiness, AdapterError> {
        apply::probe_readiness(self).await
    }

    /// Reports bounded bridge health without asserting semantic readiness.
    pub async fn adapter_health(&self) -> AdapterHealth {
        apply::adapter_health(self).await
    }

    /// Applies one explicit, checksummed migration under composition-owner
    /// authority. The adapter never migrates implicitly.
    pub async fn apply_migration(
        &self,
        migration: &CompiledMigration,
        observed_clock: &ClockObservation,
    ) -> Result<MigrationReceipt, AdapterError> {
        apply::apply_migration(self, migration, observed_clock).await
    }

    /// Applies one prepared S-01 transition and its optimistic head
    /// expectations in the same provider transaction.
    pub async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, AdapterError> {
        apply::apply_prepared(
            self,
            ctx,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
    }

    /// Reconciles an ambiguous write by reading only its durable receipt.
    pub async fn reconcile(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, AdapterError> {
        apply::read_receipt(self, operation_id).await
    }

    /// Builds the first-generation schema migration for the given target
    /// generation. The composition owner applies it through
    /// [`SurrealStoreAdapter::apply_migration`] under migration authority.
    pub fn initial_schema_migration(generation: SchemaGeneration) -> CompiledMigration {
        CompiledMigration::new(
            "eliot.store.surreal.schema.v1",
            schema::SCHEMA_DDL,
            generation,
        )
    }
}

impl CanonicalStoreClient for SurrealStoreAdapter {
    async fn apply_prepared(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreError> {
        apply::apply_prepared(
            self,
            ctx,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
        )
        .await
        .map_err(AdapterError::into_store_error)
    }

    async fn receipt(&self, operation_id: OperationId) -> Result<Option<WriteReceipt>, StoreError> {
        apply::read_receipt(self, operation_id)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        apply::read_revision_heads(self, keys)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn scope_revision_view(
        &self,
        scope_id: ScopeId,
    ) -> Result<ScopeRevisionView, StoreError> {
        apply::read_scope_view(self, scope_id)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        apply::read_ordering_heads(self, scopes)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        apply::execute_named(self, query)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn health(&self) -> Result<StoreHealth, StoreError> {
        apply::health(self).await
    }
}

fn default_manifest() -> NamedOperationManifest {
    NamedOperationManifest::new(
        ADAPTER_NAME,
        CONTRACT_VERSION,
        vec![
            TransitionClass::CaptureCandidate,
            TransitionClass::Epistemic,
            TransitionClass::TaskControl,
            TransitionClass::LifecyclePolicy,
            TransitionClass::RecoverySchema,
        ],
        EffectClass::ReversibleMutation,
        1024 * 1024,
        1024 * 1024,
        30_000,
    )
    .expect("built-in adapter manifest is valid")
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn config() -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "root".to_owned(),
            password: SecretString::new("test-secret".into()),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::new("1.0.0").expect("valid generation"),
        }
    }

    #[test]
    fn adapter_debug_redacts_credentials() {
        let adapter = SurrealStoreAdapter::new(config());
        let rendered = format!("{adapter:?}");
        assert!(!rendered.contains("test-secret"));
        assert!(rendered.contains("connected"));
    }
}
