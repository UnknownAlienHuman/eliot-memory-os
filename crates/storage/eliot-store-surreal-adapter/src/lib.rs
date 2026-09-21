//! Sole `SurrealDB` credential and client owner for the ELIOT canonical store.
//!
//! This crate is the only place that holds `SurrealDB` credentials and drives the
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
mod dreamer_job;
mod error;
mod health;
mod plan;
mod readiness;
mod schema;
mod write_execution;
mod write_scheduler;

use std::fmt;
use std::num::NonZeroUsize;

pub use config::{
    ADAPTER_NAME, ClientSetLimits, ConfigError, MAX_CLIENT_SET_SESSIONS_PER_ROLE,
    PINNED_SURREALDB_MAJOR, SchemaGeneration, SchemaGenerationError, SurrealAdapterConfig,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::RetainedProcessPathLease;
use eliot_store_api::{
    CAPABILITY_RESERVED_WRITE, CanonicalStoreClient, CanonicalValidationSnapshot, ExactJsonBytes,
    GENESIS_MANIFEST_NAME, NamedOperationManifest, NamedReadRequest, NamedReadResponse,
    OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId, PreparedTransition,
    RequestMeta, ReservedWriteRequest, RevisionHead, RevisionHeadExpectation, RevisionKey, ScopeId,
    ScopeRevisionView, StateFence, StoreError, StoreGenesisRequest, StoreHealth,
    StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt, generated_operation_manifests,
    operation_manifest_set_digest,
};
pub use error::AdapterError;
pub use health::{AdapterAvailability, AdapterHealth, ProviderHealth};
pub use readiness::{CompiledMigration, MigrationReceipt, SemanticReadiness};
pub use write_execution::{
    AttemptOutcome, CleanupError, ConcurrentEvidence, DrainReport, DurableOpOutcome,
    DurableRecoverySet, ExclusiveOpKind, ExecutableAttempt, ExecutionCapacity, ExecutionMetrics,
    ExecutionProfile, OpExecution, ProtectedPermit, ProviderGate, ReconcileOutcome,
    ReservedAttemptTransport, SubmitDisposition, UnreservedAdmission, WriteExecution,
    join_cleanup_result,
};
pub use write_scheduler::{
    CompletionOutcome, ReservationProjection, ReservedScopeProjection, ScheduleReject,
    SchedulerAdmission, SchedulerOccupancy, WriteScheduler,
};

/// The sole `SurrealDB` credential and client owner for the ELIOT canonical
/// store.
pub struct SurrealStoreAdapter {
    pub(crate) config: SurrealAdapterConfig,
    pub(crate) provider_process_lease: std::sync::Arc<RetainedProcessPathLease>,
    pub(crate) client: tokio::sync::OnceCell<Result<client::RpcTransport, AdapterError>>,
    pub(crate) write_lock: tokio::sync::Mutex<()>,
    /// Immutable closed operation manifest admitted by this adapter instance.
    pub(crate) operation_manifest: NamedOperationManifest,
    /// Fixed bounded RPC session-set limits (S-CONC-CLIENTS, issue #987).
    /// The compatibility profile preserves the pre-pool facade; an explicit
    /// profile enables separate read/write/admin lanes under the same single
    /// provider generation.
    pub(crate) client_limits: ClientSetLimits,
    /// Armed production-path transaction-attempt rendezvous (S-CONC-TX #989
    /// proof hook). `None` unless the rendezvous integration test arms it;
    /// no production caller arms it, so production always observes the
    /// disarmed (inert) state documented on [`Self::arm_tx_rendezvous`].
    pub(crate) tx_rendezvous: std::sync::Mutex<Option<std::sync::Arc<tokio::sync::Barrier>>>,
    /// Installed write-execution generation (S-CONC-EXECUTE, issue #993).
    /// `None` preserves the pre-#993 direct path; one installed generation
    /// owns the bounded scheduler and permit bounds, gates unreserved
    /// `Apply` under the concurrent profile, and routes reserved writes
    /// and exclusive drains.
    pub(crate) execution: std::sync::Mutex<Option<std::sync::Arc<WriteExecution>>>,
}

impl fmt::Debug for SurrealStoreAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SurrealStoreAdapter")
            .field("config", &"private")
            .field("provider_process_lease", &"retained")
            .field("connected", &self.client.get().is_some_and(Result::is_ok))
            .field("write_lock", &"private")
            .field("execution", &"private")
            .field("operation_manifest", &self.operation_manifest)
            .field("client_limits", &self.client_limits)
            .field("tx_rendezvous", &"private")
            .finish()
    }
}

impl SurrealStoreAdapter {
    /// Builds an adapter with the given connection and generation settings.
    ///
    /// Construction binds the instance to the active generated operation
    /// catalogue: the catalogue set is generated and its set digest is
    /// computed here, so a malformed catalogue fails closed at composition
    /// time instead of at first write. The single-manifest slot keeps the
    /// generated bootstrap (genesis) entry for health/handshake display; the
    /// authoritative pre-stage gate always validates against the whole active
    /// set (see `apply::validate_transition`). There is no aggregate
    /// broad-manifest fallback.
    pub fn new(
        config: SurrealAdapterConfig,
        provider_process_lease: RetainedProcessPathLease,
    ) -> Result<Self, AdapterError> {
        config
            .validate()
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        provider_process_lease
            .validate(
                std::path::Path::new(&config.provider_executable_path),
                std::path::Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .map_err(|_| {
                AdapterError::Config(
                    "canonical provider process lease failed identity validation".to_owned(),
                )
            })?;
        let entries = generated_operation_manifests().map_err(AdapterError::Store)?;
        operation_manifest_set_digest(&entries).map_err(AdapterError::Store)?;
        let operation_manifest = entries
            .into_iter()
            .find(|entry| entry.name == GENESIS_MANIFEST_NAME)
            .ok_or(AdapterError::Store(StoreError::UnknownOperation))?;
        Ok(Self {
            config,
            provider_process_lease: std::sync::Arc::new(provider_process_lease),
            client: tokio::sync::OnceCell::new(),
            write_lock: tokio::sync::Mutex::new(()),
            tx_rendezvous: std::sync::Mutex::new(None),
            execution: std::sync::Mutex::new(None),
            operation_manifest,
            client_limits: ClientSetLimits::compatibility(),
        })
    }

    /// Builds an adapter with an explicit bounded RPC session-set profile.
    ///
    /// The limits are validated closed values (1..=8 sessions per role) that
    /// select how many read, normal-write and health/admin lanes share this
    /// adapter's single provider generation. [`SurrealAdapterConfig`] itself
    /// is untouched, so every existing struct literal keeps compiling: this
    /// constructor, not a new required config field, carries the profile.
    pub fn new_with_client_set(
        config: SurrealAdapterConfig,
        provider_process_lease: RetainedProcessPathLease,
        manifest: NamedOperationManifest,
        limits: ClientSetLimits,
    ) -> Result<Self, StoreError> {
        config.validate().map_err(|_| StoreError::Unavailable)?;
        provider_process_lease
            .validate(
                std::path::Path::new(&config.provider_executable_path),
                std::path::Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .map_err(|_| StoreError::Unavailable)?;
        manifest.validate()?;
        Ok(Self {
            config,
            provider_process_lease: std::sync::Arc::new(provider_process_lease),
            client: tokio::sync::OnceCell::new(),
            write_lock: tokio::sync::Mutex::new(()),
            tx_rendezvous: std::sync::Mutex::new(None),
            execution: std::sync::Mutex::new(None),
            operation_manifest: manifest,
            client_limits: limits,
        })
    }

    /// Builds an adapter with an explicit immutable manifest supplied by the
    /// composition owner. The manifest is validated once and cannot be
    /// replaced while the adapter is live.
    pub fn new_with_manifest(
        config: SurrealAdapterConfig,
        provider_process_lease: RetainedProcessPathLease,
        manifest: NamedOperationManifest,
    ) -> Result<Self, StoreError> {
        config.validate().map_err(|_| StoreError::Unavailable)?;
        provider_process_lease
            .validate(
                std::path::Path::new(&config.provider_executable_path),
                std::path::Path::new(&config.store_work_root),
                &config.provider_artifact_digest,
            )
            .map_err(|_| StoreError::Unavailable)?;
        manifest.validate()?;
        Ok(Self {
            config,
            provider_process_lease: std::sync::Arc::new(provider_process_lease),
            client: tokio::sync::OnceCell::new(),
            write_lock: tokio::sync::Mutex::new(()),
            tx_rendezvous: std::sync::Mutex::new(None),
            execution: std::sync::Mutex::new(None),
            operation_manifest: manifest,
            client_limits: ClientSetLimits::compatibility(),
        })
    }

    /// Returns the (redacted) configuration.
    pub fn config(&self) -> &SurrealAdapterConfig {
        &self.config
    }

    /// Returns the fixed bounded session-set limits bound at construction.
    pub fn client_set_limits(&self) -> ClientSetLimits {
        self.client_limits
    }

    /// Installs the concurrent reserved-write execution generation
    /// (S-CONC-EXECUTE, issue #993).
    ///
    /// The evidence binds actuals: the expected schema generation comes
    /// from this adapter's validated configuration, while the observed
    /// generation, Kernel generation identity, and current fence come from
    /// the composition owner after readiness and authentication. Install
    /// fails when a generation is already present: profile change is a
    /// drained generation transition, never a live overwrite.
    pub fn install_concurrent_execution(
        &self,
        lanes: NonZeroUsize,
        max_pending: NonZeroUsize,
        observed_generation: SchemaGeneration,
        kernel_generation: String,
        state_fence: StateFence,
    ) -> Result<(), AdapterError> {
        let evidence = ConcurrentEvidence {
            capability: CAPABILITY_RESERVED_WRITE,
            observed_generation,
            expected_generation: self.config.expected_schema_generation.clone(),
            state_fence,
            kernel_generation,
        };
        let execution = WriteExecution::install_concurrent(
            self.client_limits,
            lanes,
            max_pending,
            &evidence,
            write_execution::current_time_ms(),
        )?;
        self.install_execution(execution)
    }

    /// Installs the serial compatibility execution generation: one lane,
    /// legacy unreserved path admitted, reserved writes refused.
    pub fn install_serial_execution(&self, max_pending: NonZeroUsize) -> Result<(), AdapterError> {
        let execution = WriteExecution::install_serial(self.client_limits, max_pending)?;
        self.install_execution(execution)
    }

    /// Uninstalls the execution generation for a profile change. Fails
    /// closed unless the installed generation is quiescent, open, and
    /// never recovery-blocked.
    pub fn uninstall_drained_execution(&self) -> Result<(), AdapterError> {
        let mut slot = self
            .execution
            .lock()
            .map_err(|_| AdapterError::Store(StoreError::Unavailable))?;
        let Some(execution) = slot.as_ref() else {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.generation",
                reason: "no execution generation is installed",
            }));
        };
        execution.uninstall_readiness()?;
        *slot = None;
        Ok(())
    }

    /// Advertises the reserved-write capability exactly when a concurrent
    /// execution generation owns this adapter. No backend without an
    /// accepted scheduler advertises it.
    #[must_use]
    pub fn reserved_write_capability(&self) -> Option<&'static str> {
        let slot = self.execution.lock().ok()?;
        if slot.as_ref().is_some_and(|execution| execution.is_concurrent()) {
            Some(CAPABILITY_RESERVED_WRITE)
        } else {
            None
        }
    }

    /// Returns the installed execution generation, if any.
    pub(crate) fn execution_handle(&self) -> Option<std::sync::Arc<WriteExecution>> {
        self.execution.lock().ok().and_then(|slot| slot.clone())
    }

    /// Installs one execution generation; refuses when one is present.
    fn install_execution(&self, execution: WriteExecution) -> Result<(), AdapterError> {
        let mut slot = self
            .execution
            .lock()
            .map_err(|_| AdapterError::Store(StoreError::Unavailable))?;
        if slot.is_some() {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "execution.generation",
                reason: "an execution generation is already installed",
            }));
        }
        *slot = Some(std::sync::Arc::new(execution));
        Ok(())
    }

    /// Arms the S-CONC-TX production-path transaction-attempt rendezvous
    /// (issue #989 proof hook).
    ///
    /// Test observability only: the sole armer is the
    /// `production_path_disjoint_writers_overlap_and_conflicts_fail_closed`
    /// integration test, which passes a three-party barrier so its two public
    /// production writers plus the test-side observer future prove concurrent
    /// progress past admission. No
    /// production caller arms this hook.
    ///
    /// Inert-by-default guarantee: while disarmed, the attempt loop performs
    /// one uncontended `std` mutex lock plus an `is_none` check and returns
    /// without awaiting, allocating, logging, touching the provider, or
    /// altering the error taxonomy — the canonical transaction path is
    /// byte-identical to the unhooked flow. The mutex is never held across an
    /// await and never contended in production, so disarmed writers neither
    /// block nor serialize on it.
    pub fn arm_tx_rendezvous(&self, barrier: std::sync::Arc<tokio::sync::Barrier>) {
        if let Ok(mut guard) = self.tx_rendezvous.lock() {
            *guard = Some(barrier);
        }
    }

    /// Disarms the S-CONC-TX production-path rendezvous, restoring the inert
    /// production state. See [`Self::arm_tx_rendezvous`].
    pub fn disarm_tx_rendezvous(&self) {
        if let Ok(mut guard) = self.tx_rendezvous.lock() {
            *guard = None;
        }
    }

    /// Returns the currently armed rendezvous barrier, if any. The attempt
    /// loop clones the `Arc` under the mutex and waits outside it, so the
    /// mutex is never held across an await.
    pub(crate) fn tx_rendezvous_barrier(&self) -> Option<std::sync::Arc<tokio::sync::Barrier>> {
        self.tx_rendezvous
            .lock()
            .ok()
            .and_then(|guard| (*guard).clone())
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
        state_fence: &eliot_store_api::StateFence,
    ) -> Result<MigrationReceipt, AdapterError> {
        apply::apply_migration(self, migration, observed_clock, state_fence).await
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

    /// Applies one prepared S-01 transition with per-operation payload
    /// authorities bound in (slice C2, issue #19).
    ///
    /// `authorities` aligns 1:1 with the transition's named operations and
    /// carries the original authority values. Entries with at least one
    /// claimed authority plan through the authority-carrying path; all-`None`
    /// entries keep the legacy path. The admitted-operation gate runs before
    /// any provider I/O in both cases.
    pub async fn apply_prepared_with_authority(
        &self,
        ctx: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
        authorities: &[Option<ExactJsonBytes>],
    ) -> Result<WriteReceipt, AdapterError> {
        apply::apply_prepared_with_authority(
            self,
            ctx,
            transition,
            expected_revision_heads,
            expected_ordering_heads,
            authorities,
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
        if generation.as_str() == schema::GENERATION_V2 {
            CompiledMigration::new(schema::MIGRATION_ID_V2, schema::SCHEMA_DDL_V2, generation)
        } else {
            CompiledMigration::new(schema::MIGRATION_ID_V1, schema::SCHEMA_DDL, generation)
        }
    }

    /// Builds the additive v1-to-v2 forward migration. The delta DDL creates
    /// only the new `recovery_owner` and `recovery_job` tables.
    pub fn v1_to_v2_migration() -> CompiledMigration {
        CompiledMigration::new(
            schema::MIGRATION_ID_V1_TO_V2,
            schema::SCHEMA_MIGRATION_V1_TO_V2_DDL,
            SchemaGeneration::v2(),
        )
    }

    /// Builds the v2 baseline migration (full schema). Empty databases admit
    /// exactly this plan.
    pub fn v2_baseline_migration() -> CompiledMigration {
        CompiledMigration::new(
            schema::MIGRATION_ID_V2,
            schema::SCHEMA_DDL_V2,
            SchemaGeneration::v2(),
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

    async fn recovery(
        &self,
        request: StoreRecoveryRequest,
    ) -> Result<StoreRecoverySnapshot, StoreError> {
        apply::recovery(self, request)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn apply_reserved_write(
        &self,
        request: ReservedWriteRequest,
    ) -> Result<WriteReceipt, StoreError> {
        apply::apply_reserved_write(self, request)
            .await
            .map_err(AdapterError::into_store_error)
    }

    async fn initialize_genesis(
        &self,
        context: &RequestMeta,
        request: StoreGenesisRequest,
    ) -> Result<WriteReceipt, StoreError> {
        apply::initialize_genesis(self, context, request)
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

    async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        apply::read_validation_snapshot(self)
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

    async fn dreamer_job(
        &self,
        ctx: &RequestMeta,
        request: eliot_protocol::dreamer_job::DurableJobRequest,
    ) -> Result<eliot_protocol::dreamer_job::DurableJobResponse, StoreError> {
        // Boxed: the ledger future holds multi-kilobyte canonical payloads
        // across provider awaits, exceeding the default future-size lint.
        Box::pin(dreamer_job::dreamer_job(self, ctx, request))
            .await
            .map_err(AdapterError::into_store_error)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use secrecy::SecretString;

    use super::*;
    use crate::schema;

    fn config() -> SurrealAdapterConfig {
        SurrealAdapterConfig {
            endpoint: "ws://127.0.0.1:18000/rpc".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "provider-user".to_owned(),
            password: SecretString::new("test-secret".into()),
            provider_bind_address: "127.0.0.1:18000".to_owned(),
            installation_id: "installation-test".to_owned(),
            installation_profile: "portable_dev".to_owned(),
            runtime_state_roots_digest: "a".repeat(64),
            provider_executable_path: r"C:\eliot\surreal.exe".to_owned(),
            provider_artifact_digest: "b".repeat(64),
            provider_arguments: vec![
                "start".to_owned(),
                "--no-banner".to_owned(),
                "--bind".to_owned(),
                "127.0.0.1:18000".to_owned(),
                "--temporary-directory".to_owned(),
                r"C:\eliot\store\tmp".to_owned(),
                "--log-file-enabled".to_owned(),
                "--log-file-path".to_owned(),
                r"C:\eliot\store\work".to_owned(),
                "--log-file-name".to_owned(),
                "surrealdb.log".to_owned(),
                "surrealkv://C:/eliot/store/data".to_owned(),
            ],
            store_data_root: r"C:\eliot\store\data".to_owned(),
            store_work_root: r"C:\eliot\store\work".to_owned(),
            store_temp_root: r"C:\eliot\store\tmp".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            expected_provider_major: PINNED_SURREALDB_MAJOR,
            expected_schema_generation: SchemaGeneration::v2(),
        }
    }

    #[test]
    fn adapter_debug_redacts_credentials() {
        let rendered = format!("{:?}", config());
        assert!(!rendered.contains("test-secret"));
        assert!(!rendered.contains("provider-user"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn v1_migration_is_immutable() {
        let generation = SchemaGeneration::new(schema::GENERATION_V1).expect("valid");
        let m = SurrealStoreAdapter::initial_schema_migration(generation);
        assert_eq!(m.migration_id(), schema::MIGRATION_ID_V1);
        assert_eq!(m.generation_after().as_str(), schema::GENERATION_V1);
        assert_eq!(
            m.checksum_sha256(),
            eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes())
        );
        assert!(!m.checksum_sha256().is_empty());
    }

    #[test]
    fn v2_baseline_is_full_and_contains_recovery() {
        let m = SurrealStoreAdapter::v2_baseline_migration();
        assert_eq!(m.migration_id(), schema::MIGRATION_ID_V2);
        assert_eq!(m.generation_after().as_str(), schema::GENERATION_V2);
        assert_ne!(
            m.checksum_sha256(),
            eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes())
        );
        assert!(schema::SCHEMA_DDL_V2.contains(schema::table::RECOVERY_OWNER));
        assert!(schema::SCHEMA_DDL_V2.contains(schema::table::RECOVERY_JOB));
        assert!(schema::SCHEMA_DDL_V2.contains(schema::SCHEMA_DDL.trim()));
    }

    #[test]
    fn v1_to_v2_is_additive_delta() {
        let m = SurrealStoreAdapter::v1_to_v2_migration();
        assert_eq!(m.migration_id(), schema::MIGRATION_ID_V1_TO_V2);
        assert_eq!(m.generation_after().as_str(), schema::GENERATION_V2);
        assert_ne!(
            m.checksum_sha256(),
            eliot_store_api::sha256_hex(schema::SCHEMA_DDL.as_bytes())
        );
        assert!(!schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains("DEFINE TABLE schema_meta"));
        assert!(schema::SCHEMA_MIGRATION_V1_TO_V2_DDL.contains(schema::table::RECOVERY_OWNER));
    }

    #[test]
    fn v2_migrations_have_no_destructive_statements() {
        for ddl in [schema::SCHEMA_DDL_V2, schema::SCHEMA_MIGRATION_V1_TO_V2_DDL] {
            let lower = ddl.to_ascii_lowercase();
            assert!(!lower.contains("drop "));
            assert!(!lower.contains("delete "));
            assert!(!lower.contains("remove "));
        }
    }
}
