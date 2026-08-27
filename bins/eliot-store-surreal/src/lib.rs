#![forbid(unsafe_code)]

//! Composition owner for the S-03 canonical store bridge.
//!
//! This process exposes only the store-neutral EBP contract.  `SurrealDB`
//! credentials, provider transport and query text stay inside
//! `eliot-store-surreal-adapter`; this root only assembles the adapter and
//! serializes bounded contract receipts. Blob contributes one process/root
//! claim identity; it is not a second store or semantic write path.

use std::collections::BTreeSet;
use std::path::Path;

use eliot_blob::BlobRootOwner;
use eliot_contracts::StateFence;
use eliot_installation::{
    InstallationProfile, ValidatedRuntimeRootLeases, WindowsRuntimeRootLease,
    WindowsRuntimeRootLeaseProvider,
};
#[cfg(test)]
use eliot_installation::{PHASE_B_PENDING_SCM_DIGEST, RuntimeLaunchDescriptor};
use eliot_ipc::{BoundIdentity, ReplayDisposition, ReplayLedger, TransportError, TransportLimits};
use eliot_kernel_service::{
    HostStoreBootstrapRequirement, STORE_MODULE_IDENTITY, STORE_ROUTE_IDENTITY,
};
use eliot_platform::{ClockObservation, PlatformHandle};
use eliot_platform_windows::WindowsPlatform;
use eliot_protocol::{
    ClientHello, EncodingProfile, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange,
    ProtocolVersion, ServerHello,
};
#[cfg(test)]
use eliot_store_api::StoreGenesisRequest;
use eliot_store_api::{
    CAPABILITIES, CanonicalStoreClient, CanonicalValidationSnapshot, EFFECTS, NamedReadRequest,
    NamedReadResponse, OperationId, OrderingHead, OrderingHeadExpectation, OrderingScopeId,
    PreparedTransition, RequestMeta, RevisionHead, RevisionHeadExpectation, RevisionKey,
    StoreError, StoreHealth, WriteReceipt, decode_request_frame,
};
pub use eliot_store_api::{
    ReadinessReceipt, ReadinessStatus, StoreRequest as Request, StoreResponse as Response,
};
use eliot_store_surreal_adapter::{
    AdapterError, CompiledMigration, MigrationReceipt, PINNED_SURREALDB_MAJOR, SchemaGeneration,
    SemanticReadiness, SurrealAdapterConfig, SurrealStoreAdapter,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;

mod launch_config;
#[cfg(test)]
pub(crate) use launch_config::{LEGACY_PHASE_B_ZERO_DIGEST, parse_config_bytes};
pub use launch_config::{
    StoreLaunchConfig, launch_config_digest, load_config, load_portable_dev_config,
};
pub(crate) use launch_config::{validate_digest, validate_launch_text};
mod request_dispatch;
pub use request_dispatch::StoreDispatchBackend;
#[cfg(test)]
use request_dispatch::UNKNOWN_GENESIS_REASON;
pub use request_dispatch::dispatch;
#[cfg(test)]
use request_dispatch::map_genesis_dispatch_result;
#[cfg(test)]
use request_dispatch::map_recovery_dispatch_result;

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "eliot.s03.ebp.v1";

/// Error returned by the neutral Store root while preserving an ambiguous
/// provider write identity for the EBP response boundary.
#[derive(Debug, Error)]
pub enum StoreCompositionError {
    /// A deterministic store/API failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The provider crossed a write boundary without proving its outcome.
    #[error("provider outcome is unknown for operation {operation_id}: {reason}")]
    UnknownOutcome {
        /// Exact operation identity used for receipt reconciliation.
        operation_id: OperationId,
        /// Bounded provider reason, not a success claim.
        reason: String,
    },
}

/// A bounded, non-wire command for the future transaction-owned
/// `MigrateStoreSchema` operation.
///
/// The command deliberately carries only binding material. It contains no
/// credential and no provider query text; the Store process resolves its
/// configured credential and the adapter owns the sole `SurrealDB` writer.
/// Host/installer IPC is intentionally not part of this seam yet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSchemaBootstrapCommand {
    /// Installation lineage that owns the Store launch descriptor.
    pub installation_id: String,
    /// Exact candidate-generation handle from the Host launch descriptor.
    pub generation: String,
    /// Authority generation from the Host launch descriptor.
    pub authority_generation: u64,
    /// Digest of the complete approved Store launch configuration.
    pub approved_config_hash: String,
    /// Authority/state fence copied from the approved launch descriptor.
    pub state_fence: StateFence,
    /// Compiler-approved migration identity.
    pub migration_id: String,
    /// Compiler-derived migration checksum.
    pub migration_checksum_sha256: String,
    /// Explicit P-01 clock observation supplied by the future authority owner.
    pub observed_clock: ClockObservation,
}

/// Authoritative Store-side result of one schema bootstrap attempt.
///
/// The receipt is a complete binding projection, not a generic "success"
/// boolean. An exact replay after a process restart returns the same values
/// after the adapter reads and verifies durable `schema_meta` and fence state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSchemaBootstrapReceipt {
    pub installation_id: String,
    pub generation: String,
    pub authority_generation: u64,
    pub approved_config_hash: String,
    pub state_fence: StateFence,
    pub migration_id: String,
    pub migration_checksum_sha256: String,
    pub generation_after: String,
}

impl StoreSchemaBootstrapReceipt {
    /// Validates the receipt before it is returned across a future control
    /// boundary or retained for an in-process exact replay.
    pub fn validate(&self) -> Result<(), String> {
        validate_launch_text(&self.installation_id, "installation_id")?;
        validate_launch_text(&self.generation, "generation")?;
        validate_launch_text(&self.migration_id, "migration_id")?;
        validate_launch_text(&self.generation_after, "generation_after")?;
        validate_digest(&self.approved_config_hash, "approved_config_hash")?;
        validate_digest(&self.migration_checksum_sha256, "migration_checksum_sha256")?;
        if self.authority_generation == 0 {
            return Err("authority_generation must be non-zero".to_owned());
        }
        self.state_fence
            .validate()
            .map_err(|error| format!("invalid receipt state_fence: {error}"))
    }
}

/// Error surface for the Store-only schema bootstrap seam.
#[derive(Debug, Error)]
pub enum StoreSchemaBootstrapError {
    /// The command did not match the immutable Store launch binding.
    #[error("schema bootstrap command rejected: {0}")]
    Rejected(String),
    /// The provider crossed the migration effect boundary without a durable
    /// identity that can prove the result.
    #[error("schema bootstrap outcome is unknown for migration {migration_id}")]
    UnknownOutcome { migration_id: String },
    /// The provider returned a partial result that is not safe to interpret
    /// as either committed or absent.
    #[error("schema bootstrap provider outcome is partial; reconcile migration by exact identity")]
    PartialOutcome,
    /// A deterministic Store/API failure.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

/// Immutable Store-side binding captured at composition time. It is private
/// so callers cannot mint a binding detached from the validated launch config.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreSchemaBootstrapBinding {
    profile: InstallationProfile,
    installation_id: String,
    generation: String,
    authority_generation: u64,
    approved_config_hash: String,
    state_fence: StateFence,
    schema_generation: String,
}

impl StoreSchemaBootstrapBinding {
    fn from_config(config: &StoreLaunchConfig) -> Self {
        Self {
            profile: config.runtime_launch.profile,
            installation_id: config
                .runtime_launch
                .installation_epoch
                .installation
                .as_str()
                .to_owned(),
            generation: config.runtime_launch.generation.as_str().to_owned(),
            authority_generation: config.runtime_launch.authority_generation.value(),
            approved_config_hash: config.approved_config_hash.clone(),
            state_fence: config.runtime_launch.authority_state_fence.clone(),
            schema_generation: config.schema_generation.clone(),
        }
    }

    fn validate_command(
        &self,
        command: &StoreSchemaBootstrapCommand,
        migration: &CompiledMigration,
    ) -> Result<(), StoreSchemaBootstrapError> {
        if self.profile != InstallationProfile::SystemService {
            return Err(StoreSchemaBootstrapError::Rejected(
                "schema bootstrap is reserved for the SystemService profile".to_owned(),
            ));
        }
        validate_launch_text(&command.installation_id, "installation_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.generation, "generation")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_launch_text(&command.migration_id, "migration_id")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(&command.approved_config_hash, "approved_config_hash")
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        validate_digest(
            &command.migration_checksum_sha256,
            "migration_checksum_sha256",
        )
        .map_err(StoreSchemaBootstrapError::Rejected)?;
        if command.authority_generation == 0 {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation must be non-zero".to_owned(),
            ));
        }
        command
            .state_fence
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        command
            .observed_clock
            .validate()
            .map_err(|error| StoreSchemaBootstrapError::Rejected(error.to_string()))?;
        if command.observed_clock.valid_time_ms.is_none()
            && command.observed_clock.known_time_ms.is_none()
        {
            return Err(StoreSchemaBootstrapError::Rejected(
                "observed_clock must contain valid_time_ms or known_time_ms".to_owned(),
            ));
        }
        let checks = [
            (
                command.installation_id.as_str(),
                self.installation_id.as_str(),
                "installation_id",
            ),
            (
                command.generation.as_str(),
                self.generation.as_str(),
                "generation",
            ),
            (
                command.approved_config_hash.as_str(),
                self.approved_config_hash.as_str(),
                "approved_config_hash",
            ),
            (
                command.migration_id.as_str(),
                migration.migration_id(),
                "migration_id",
            ),
            (
                command.migration_checksum_sha256.as_str(),
                migration.checksum_sha256(),
                "migration_checksum_sha256",
            ),
        ];
        if let Some((_, _, field)) = checks
            .iter()
            .find(|(provided, expected, _)| provided != expected)
        {
            return Err(StoreSchemaBootstrapError::Rejected(format!(
                "{field} does not match the immutable Store launch/migration binding"
            )));
        }
        if command.authority_generation != self.authority_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "authority_generation does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if command.state_fence != self.state_fence {
            return Err(StoreSchemaBootstrapError::Rejected(
                "state_fence does not match the immutable Store launch binding".to_owned(),
            ));
        }
        if migration.generation_after().as_str() != self.schema_generation {
            return Err(StoreSchemaBootstrapError::Rejected(
                "migration generation does not match the configured Store schema generation"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn receipt(
        &self,
        migration: &MigrationReceipt,
    ) -> Result<StoreSchemaBootstrapReceipt, StoreSchemaBootstrapError> {
        let receipt = StoreSchemaBootstrapReceipt {
            installation_id: self.installation_id.clone(),
            generation: self.generation.clone(),
            authority_generation: self.authority_generation,
            approved_config_hash: self.approved_config_hash.clone(),
            state_fence: self.state_fence.clone(),
            migration_id: migration.migration_id.clone(),
            migration_checksum_sha256: migration.checksum_sha256.clone(),
            generation_after: migration.generation_after.as_str().to_owned(),
        };
        receipt
            .validate()
            .map_err(StoreSchemaBootstrapError::Rejected)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoreSchemaBootstrapCache {
    command: StoreSchemaBootstrapCommand,
    receipt: StoreSchemaBootstrapReceipt,
}

fn map_schema_bootstrap_error(error: AdapterError) -> StoreSchemaBootstrapError {
    match error {
        AdapterError::UnknownMigrationOutcome { migration_id } => {
            StoreSchemaBootstrapError::UnknownOutcome { migration_id }
        }
        AdapterError::PartialOutcome => StoreSchemaBootstrapError::PartialOutcome,
        AdapterError::Config(reason) => StoreSchemaBootstrapError::Rejected(format!(
            "provider rejected the admitted schema bootstrap: {reason}"
        )),
        AdapterError::Store(error) => StoreSchemaBootstrapError::Store(error),
        other => StoreSchemaBootstrapError::Store(other.into_store_error()),
    }
}

fn map_adapter_error(error: AdapterError) -> StoreCompositionError {
    match error {
        AdapterError::UnknownOutcome { operation_id } => match OperationId::new(operation_id) {
            Ok(operation_id) => StoreCompositionError::UnknownOutcome {
                operation_id,
                reason: "provider outcome is unknown; reconcile by exact receipt".to_owned(),
            },
            Err(error) => StoreCompositionError::Store(StoreError::Foundation(error)),
        },
        AdapterError::Store(error) => StoreCompositionError::Store(error),
        other => StoreCompositionError::Store(other.into_store_error()),
    }
}

/// Constructs the exact store-neutral bootstrap descriptor consumed by
/// Kernel from this boundary's already-validated concrete launch config.
///
/// Concrete endpoint, namespace, database, credential and Blob fields never
/// cross this seam. The descriptor binds only the route/fence, authenticated
/// pipe peer, approved digests, launch identity and bounded timeout.
pub fn store_bootstrap_descriptor(
    config: &StoreLaunchConfig,
) -> Result<HostStoreBootstrapRequirement, String> {
    config.validate()?;
    let store_generation = config.runtime_launch.authority_generation;
    let handle = |value: &str, field: &str| {
        PlatformHandle::new(value).map_err(|error| format!("invalid {field}: {error}"))
    };
    let connection_id = format!(
        "kernel-store:{}:{}",
        config.instance_id, config.launch_nonce
    );
    Ok(HostStoreBootstrapRequirement {
        route_identity: handle(STORE_ROUTE_IDENTITY, "route identity")?,
        canonical_pipe_identity: handle(&config.store_pipe, "canonical pipe identity")?,
        store_generation,
        state_fence: config.runtime_launch.authority_state_fence.clone(),
        launch_nonce: handle(&config.launch_nonce, "launch nonce")?,
        connection_id: handle(&connection_id, "connection identity")?,
        expected_peer_sid: handle(&config.expected_client_sid, "Store peer SID")?,
        expected_peer_session_id: config.expected_client_session_id,
        approved_artifact_hash: handle(&config.approved_artifact_hash, "Store artifact digest")?,
        approved_config_hash: handle(&config.approved_config_hash, "Store config digest")?,
        timeout_ms: config.connect_timeout_ms,
    })
}

/// Canonical store composition. All provider authority is held by the one
/// adapter and one process/root Blob claim; Blob does not become a semantic
/// store or alternate transition path.
pub struct StoreComposition {
    store: SurrealStoreAdapter,
    blob: BlobRootOwner,
    state_fence: StateFence,
    schema_bootstrap_binding: StoreSchemaBootstrapBinding,
    schema_bootstrap_cache: tokio::sync::Mutex<Option<StoreSchemaBootstrapCache>>,
    _runtime_root_leases: ValidatedRuntimeRootLeases<WindowsRuntimeRootLease>,
}

impl std::fmt::Debug for StoreComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreComposition")
            .field("store", &self.store)
            .field("blob_owner", &self.blob)
            .field("state_fence", &self.state_fence)
            .finish_non_exhaustive()
    }
}

impl StoreComposition {
    /// Builds the adapter from the explicit target launch configuration.
    /// Credential bytes are read only inside this process from the configured
    /// Windows Credential Manager reference and are retained only by the
    /// adapter's redacted `SecretString` configuration.
    pub fn new(config: &StoreLaunchConfig) -> Result<Self, String> {
        config.validate()?;
        let schema_bootstrap_binding = StoreSchemaBootstrapBinding::from_config(config);
        let blob = BlobRootOwner::claim(
            config.blob_root.clone(),
            format!("store-composition:{}", config.instance_id),
            std::process::id(),
        )
        .map_err(|error| format!("claim Blob root owner: {error}"))?;
        let platform = WindowsPlatform::new(config.blob_root.clone())
            .map_err(|error| format!("validate Blob root for credential access: {error}"))?;
        let password = resolve_credential(&platform, &config.credential_ref)?;
        let roots = &config.runtime_launch.runtime_state_roots;
        let mut root_lease_provider = WindowsRuntimeRootLeaseProvider::for_roots(roots)
            .map_err(|error| format!("validate runtime-root provider: {error}"))?;
        let runtime_root_leases = roots
            .retain_and_validate(&mut root_lease_provider)
            .map_err(|error| format!("retain canonical runtime roots: {error}"))?;
        let provider_platform = WindowsPlatform::new(roots.profile_anchor_root.as_str().to_owned())
            .map_err(|error| format!("validate provider launch contour: {error}"))?;
        let provider_process_lease = provider_platform
            .retain_process_path_lease(
                Path::new(
                    config
                        .runtime_launch
                        .canonical_store_executable_path
                        .as_str(),
                ),
                Path::new(roots.store_work_root.as_str()),
                config
                    .runtime_launch
                    .canonical_store_artifact_digest
                    .as_str(),
            )
            .map_err(|_| "retain canonical provider process identity failed".to_owned())?;
        let state_fence = config.runtime_launch.authority_state_fence.clone();
        state_fence
            .validate()
            .map_err(|error| format!("invalid Store state fence: {error}"))?;
        let store = SurrealStoreAdapter::new(
            materialize_adapter_config(config, password)?,
            provider_process_lease,
        )
        .map_err(|error| format!("compose canonical provider adapter: {error}"))?;
        Ok(Self {
            store,
            blob,
            state_fence,
            schema_bootstrap_binding,
            schema_bootstrap_cache: tokio::sync::Mutex::new(None),
            _runtime_root_leases: runtime_root_leases,
        })
    }

    /// Rejects attempts to add a second process/root owner after composition.
    pub fn with_blob_owner(self, _owner: BlobRootOwner) -> Result<Self, String> {
        Err("exactly one Blob root owner is composed by StoreComposition::new".to_owned())
    }

    /// Returns the sole process/root claim identity. It carries no semantic
    /// write authority and does not mint Blob receipts.
    #[must_use]
    pub fn blob_owner(&self) -> &BlobRootOwner {
        &self.blob
    }

    /// Bounded adapter/provider health observation.
    pub async fn health(&self) -> Result<StoreHealth, StoreError> {
        self.store.health().await
    }

    /// Starts the one retained canonical provider child and proves authenticated
    /// version readiness before the Store pipe accepts requests.
    pub async fn connect(&self) -> Result<(), String> {
        self.store
            .connect()
            .await
            .map_err(|error| format!("canonical provider startup failed: {error}"))
    }

    /// Semantic schema readiness observation.  This is not a write authority
    /// verdict and is returned as its own receipt/status surface.
    pub async fn readiness(&self) -> Result<ReadinessReceipt, StoreError> {
        let readiness = self
            .store
            .probe_readiness()
            .await
            .map_err(AdapterError::into_store_error)?;
        if matches!(readiness, SemanticReadiness::Ready { .. }) {
            let snapshot = self.store.validation_snapshot().await?;
            snapshot.validate()?;
            if snapshot.state_fence != self.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        Ok(match readiness {
            SemanticReadiness::Unavailable => ReadinessReceipt::unavailable(),
            SemanticReadiness::MigrationRequired { expected, observed } => {
                ReadinessReceipt::migration_required(expected.to_string(), observed)
            }
            SemanticReadiness::Ready { generation } => {
                ReadinessReceipt::ready(generation.to_string())
            }
        })
    }

    /// Applies exactly the adapter's explicit first-generation schema plan.
    /// Normal Store startup never calls this method; portable development must
    /// opt into the separate schema-initialization CLI mode.
    pub async fn apply_initial_schema_migration(
        &self,
        observed_clock: &ClockObservation,
    ) -> Result<MigrationReceipt, StoreCompositionError> {
        if self.schema_bootstrap_binding.profile != InstallationProfile::PortableDev {
            return Err(StoreCompositionError::Store(StoreError::Unavailable));
        }
        let generation = self.store.config().expected_schema_generation.clone();
        let migration = SurrealStoreAdapter::initial_schema_migration(generation);
        self.store
            .apply_migration(&migration, observed_clock, &self.state_fence)
            .await
            .map_err(map_adapter_error)
    }

    /// Executes one explicitly bound `SystemService` schema bootstrap command.
    ///
    /// This is intentionally a Store-local seam for the future transaction-
    /// owned `MigrateStoreSchema` operation. It is not on the normal EBP
    /// request catalogue and does not add Host or installer effects. The
    /// provider is authenticated by this composition before the adapter's
    /// single migration writer is entered. The in-process cache rejects a
    /// second non-identical command; an exact replay after process restart is
    /// resolved by the adapter's durable schema-meta readback.
    pub async fn bootstrap_schema(
        &self,
        command: StoreSchemaBootstrapCommand,
    ) -> Result<StoreSchemaBootstrapReceipt, StoreSchemaBootstrapError> {
        let generation = self.store.config().expected_schema_generation.clone();
        let migration = SurrealStoreAdapter::initial_schema_migration(generation);
        self.schema_bootstrap_binding
            .validate_command(&command, &migration)?;

        let mut cache = self.schema_bootstrap_cache.lock().await;
        if let Some(cached) = cache.as_ref() {
            if cached.command == command {
                return Ok(cached.receipt.clone());
            }
            return Err(StoreSchemaBootstrapError::Rejected(
                "one-shot schema bootstrap already consumed by a different command".to_owned(),
            ));
        }

        self.store
            .connect()
            .await
            .map_err(map_schema_bootstrap_error)?;
        let migration_receipt = self
            .store
            .apply_migration(&migration, &command.observed_clock, &command.state_fence)
            .await
            .map_err(map_schema_bootstrap_error)?;
        let receipt = self.schema_bootstrap_binding.receipt(&migration_receipt)?;
        *cache = Some(StoreSchemaBootstrapCache {
            command,
            receipt: receipt.clone(),
        });
        Ok(receipt)
    }

    /// Executes one closed named read from the store API catalogue.
    pub async fn named(
        &self,
        request: NamedReadRequest,
    ) -> Result<NamedReadResponse, eliot_store_api::StoreError> {
        self.store.execute_named(request).await
    }

    /// Applies one fully prepared transition through the sole canonical write
    /// path and returns the immutable transport receipt.
    pub async fn apply(
        &self,
        context: &RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    ) -> Result<WriteReceipt, StoreCompositionError> {
        context
            .validate()
            .map_err(StoreError::Foundation)
            .map_err(StoreCompositionError::Store)?;
        transition
            .validate()
            .map_err(StoreCompositionError::Store)?;
        if context.state_fence != transition.state_fence {
            return Err(StoreCompositionError::Store(StoreError::FenceMismatch));
        }
        self.store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
            .map_err(map_adapter_error)
    }

    /// Reconciles a possibly ambiguous write by exact operation identity.
    pub async fn receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        self.store
            .reconcile(operation_id)
            .await
            .map_err(AdapterError::into_store_error)
    }

    /// Reads revision heads through the neutral store boundary.
    pub async fn revision_heads(
        &self,
        keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        self.store.revision_heads(keys).await
    }

    /// Reads one coherent canonical validation snapshot.
    pub async fn validation_snapshot(&self) -> Result<CanonicalValidationSnapshot, StoreError> {
        self.store.validation_snapshot().await
    }

    /// Reads ordering heads through the neutral store boundary.
    pub async fn ordering_heads(
        &self,
        scopes: Vec<OrderingScopeId>,
    ) -> Result<Vec<OrderingHead>, StoreError> {
        self.store.ordering_heads(scopes).await
    }

    /// Returns the immutable closed operation manifest digest for the ready
    /// response; no provider-specific data is exposed.
    pub fn operation_manifest_digest(&self) -> &str {
        self.store.operation_manifest().digest.as_str()
    }
}

/// Requires the complete semantic-ready receipt for the exact configured
/// schema generation before a Store pipe may be created or advertised.
///
/// `StoreComposition::readiness` has already performed the canonical fence
/// snapshot proof. This final pure gate rejects unavailable, migration,
/// malformed, partial, or generation-mismatched receipts.
pub fn require_semantic_ready_for_pipe(
    receipt: &ReadinessReceipt,
    expected_generation: &str,
) -> Result<(), String> {
    receipt
        .validate()
        .map_err(|error| format!("invalid semantic readiness receipt: {error}"))?;
    if receipt.status != ReadinessStatus::Ready
        || receipt.expected_generation.as_deref() != Some(expected_generation)
        || receipt.observed_generation.as_deref() != Some(expected_generation)
    {
        return Err(
            "canonical Store schema/fence is not semantically ready; pipe admission denied"
                .to_owned(),
        );
    }
    Ok(())
}

/// Immutable identity projected into the S-03 `ServerHello`.  The transport
/// loop does not get to invent any provider or process authority; it receives
/// this projection from the one `StoreComposition`.
#[derive(Clone, Debug)]
pub struct StoreHandshakeIdentity {
    operation_manifest_digest: String,
    blob_root_owner: serde_json::Value,
}

impl StoreHandshakeIdentity {
    /// Creates the bounded identity projection for one admitted composition.
    #[must_use]
    pub fn new(
        operation_manifest_digest: impl Into<String>,
        blob_root_owner: serde_json::Value,
    ) -> Self {
        Self {
            operation_manifest_digest: operation_manifest_digest.into(),
            blob_root_owner,
        }
    }
}

/// Authenticated S-03 session state retained by the Store transport loop.
///
/// The fields are intentionally private. Callers can obtain only the
/// negotiated transport values needed to send a response; request admission
/// remains inside [`validate_request_frame`].
pub struct StoreEbpSession {
    connection_id: String,
    protocol_version: ProtocolVersion,
    state_fence: StateFence,
    module_generation: eliot_protocol::ProtocolModuleGeneration,
    max_frame_bytes: usize,
    capabilities: BTreeSet<String>,
    replay: ReplayLedger,
}

impl StoreEbpSession {
    #[must_use]
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }
}

/// Admits the only supported S-03 `ClientHello` and binds the complete
/// generation/fence/epoch lineage to the resulting session.
pub fn admit_handshake(
    frame: Frame,
    limits: TransportLimits,
    config: &StoreLaunchConfig,
    identity: &StoreHandshakeIdentity,
) -> Result<(StoreEbpSession, ServerHello), String> {
    config.validate()?;
    frame
        .validate()
        .map_err(|error| format!("validate EBP hello frame: {error}"))?;
    if frame.encoding_profile != EncodingProfile::JsonV1
        || frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Start
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return Err("first frame must be an uncorrelated json-v1 Control/Start hello".to_owned());
    }
    let ProtocolPayload::Json(payload) = frame.payload else {
        return Err("EBP hello payload must use json-v1".to_owned());
    };
    let hello: ClientHello =
        serde_json::from_value(payload).map_err(|error| format!("decode ClientHello: {error}"))?;
    hello
        .validate()
        .map_err(|error| format!("validate ClientHello: {error}"))?;
    if hello.module_bridge_identity != STORE_MODULE_IDENTITY {
        return Err(format!(
            "ClientHello module_bridge_identity must be {STORE_MODULE_IDENTITY}"
        ));
    }
    let state_fence = &hello.module_generation.state_fence;
    if hello.artifact_hash.as_str() != config.approved_artifact_hash
        || hello.launch_nonce != config.launch_nonce
        || hello.module_generation.generation.value() != config.store_generation()
        || state_fence.resource_generation != hello.module_generation.generation
        || state_fence.resource_generation.value() != config.store_generation()
        || state_fence.authority_epoch != hello.authority_epoch
        || state_fence.authority_epoch.value() != config.authority_epoch()
        || state_fence != &config.runtime_launch.authority_state_fence
    {
        return Err(
            "ClientHello is outside the Host-approved store generation/fence lineage".to_owned(),
        );
    }
    if identity.operation_manifest_digest.trim().is_empty() {
        return Err("store operation manifest digest is empty".to_owned());
    }
    let server_range = ProtocolRange {
        minimum: ProtocolVersion::CURRENT,
        maximum: ProtocolVersion::CURRENT,
    };
    let protocol_version = hello
        .protocol_range
        .select(server_range)
        .map_err(|error| format!("negotiate EBP version: {error}"))?;
    if usize::try_from(hello.max_frame).unwrap_or(usize::MAX) > limits.max_frame_bytes {
        return Err("ClientHello max_frame exceeds the bounded transport limit".to_owned());
    }
    let capabilities: Vec<String> = CAPABILITIES
        .iter()
        .filter(|capability| hello.capabilities.iter().any(|value| value == **capability))
        .map(|capability| (*capability).to_owned())
        .collect();
    let effects: Vec<String> = EFFECTS.iter().map(|effect| (*effect).to_owned()).collect();
    let server_hello = ServerHello {
        selected_protocol: protocol_version,
        session_principal_binding: format!("{SERVICE_NAME}:{}", std::process::id()),
        allowed_capabilities: capabilities.clone(),
        allowed_effects: effects,
        config_snapshot: serde_json::json!({
            "service": SERVICE_NAME,
            "protocol": PROTOCOL_VERSION,
            "artifact_hash": config.approved_artifact_hash,
            "config_hash": config.approved_config_hash,
            "operation_manifest_digest": identity.operation_manifest_digest,
            "blob_root_owner": identity.blob_root_owner,
        }),
        heartbeat_ms: 30_000,
        control_channel: "named_pipe".to_owned(),
        rejection_reason: None,
        authority_epoch: hello.authority_epoch,
    };
    server_hello
        .validate()
        .map_err(|error| format!("validate ServerHello: {error}"))?;
    Ok((
        StoreEbpSession {
            connection_id: frame.connection_id,
            protocol_version,
            state_fence: state_fence.clone(),
            module_generation: hello.module_generation.clone(),
            max_frame_bytes: usize::try_from(hello.max_frame)
                .map_err(|_| "ClientHello max_frame does not fit usize".to_owned())?,
            capabilities: capabilities.into_iter().collect(),
            replay: ReplayLedger::default(),
        },
        server_hello,
    ))
}

/// Validates one request against the admitted session and replay ledger.
pub fn validate_request_frame(
    session: &mut StoreEbpSession,
    frame: &Frame,
) -> Result<Request, String> {
    if frame.protocol_version != session.protocol_version
        || frame.connection_id != session.connection_id
    {
        return Err("request frame is outside the negotiated EBP session".to_owned());
    }
    let (request_id, identity, request) =
        decode_request_frame(frame).map_err(|error| error.to_string())?;
    if identity.request.state_fence != session.state_fence {
        return Err("request identity state fence does not match the handshake fence".to_owned());
    }
    let bound = BoundIdentity::new(
        session.connection_id.clone(),
        session.module_generation.clone(),
        request_id.to_string(),
    )
    .map_err(|error| format!("invalid request identity binding: {error}"))?;
    match session.replay.observe_bound(bound, frame) {
        Ok(ReplayDisposition::New | ReplayDisposition::Duplicate) => {}
        Ok(ReplayDisposition::Conflict) => {
            return Err("request identity conflicts with a prior frame".to_owned());
        }
        Err(TransportError::RegistryFull) => {
            return Err("bounded transport registry is full".to_owned());
        }
        Err(error) => return Err(error.to_string()),
    }
    let capability = request.capability();
    if !session.capabilities.contains(capability) {
        return Err(format!("capability is not admitted: {capability}"));
    }
    Ok(request)
}

/// Purely materializes the credential-bearing adapter configuration from an
/// already digest-bound Store launch projection. Provider argv is copied from
/// the validated runtime descriptor and then revalidated byte-for-byte against
/// the Store coordinates and roots; it is never reconstructed at spawn time.
pub fn materialize_adapter_config(
    config: &StoreLaunchConfig,
    password: SecretString,
) -> Result<SurrealAdapterConfig, String> {
    config.validate()?;
    let schema_generation = SchemaGeneration::new(config.schema_generation.as_str())
        .map_err(|error| error.to_string())?;
    let launch = &config.runtime_launch;
    let roots = &launch.runtime_state_roots;
    let adapter = SurrealAdapterConfig {
        endpoint: config.endpoint.clone(),
        provider_bind_address: config.provider_bind_address.clone(),
        namespace: config.namespace.clone(),
        database: config.database.clone(),
        username: config.username.clone(),
        password,
        installation_id: launch.installation_epoch.installation.as_str().to_owned(),
        installation_profile: match launch.profile {
            InstallationProfile::SystemService => "system_service",
            InstallationProfile::UserMode => "user_mode",
            InstallationProfile::PortableDev => "portable_dev",
        }
        .to_owned(),
        runtime_state_roots_digest: roots.roots_digest.as_str().to_owned(),
        provider_executable_path: launch.canonical_store_executable_path.as_str().to_owned(),
        provider_artifact_digest: launch.canonical_store_artifact_digest.as_str().to_owned(),
        provider_arguments: launch
            .canonical_store_arguments
            .iter()
            .map(|argument| argument.as_str().to_owned())
            .collect(),
        store_data_root: roots.store_data_root.as_str().to_owned(),
        store_work_root: roots.store_work_root.as_str().to_owned(),
        store_temp_root: roots.store_temp_root.as_str().to_owned(),
        connect_timeout_ms: config.connect_timeout_ms,
        query_timeout_ms: config.query_timeout_ms,
        expected_provider_major: PINNED_SURREALDB_MAJOR,
        expected_schema_generation: schema_generation,
    };
    adapter.validate().map_err(|error| error.to_string())?;
    Ok(adapter)
}

fn resolve_credential(
    platform: &WindowsPlatform,
    credential_ref: &str,
) -> Result<SecretString, String> {
    let credential = platform
        .read_credential(credential_ref)
        .map_err(|error| format!("read configured credential reference: {error}"))?;
    let password = String::from_utf8(credential.expose().to_vec())
        .map_err(|_| "configured credential is not UTF-8".to_owned())?;
    non_empty_secret(&password, "configured credential")
}

fn non_empty_secret(value: &str, source: &str) -> Result<SecretString, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{source} is empty"));
    }
    Ok(SecretString::new(value.into()))
}

#[cfg(test)]
// Test fixtures intentionally fail immediately when their static identities are invalid.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, ResourceGeneration,
    };
    use eliot_installation::{InstallationEpoch, RuntimeStateRoots};
    use eliot_runtime_contracts::{
        HealthVector, ModuleContract, ModuleGeneration, ModuleGenerationState,
    };

    fn handle(value: impl Into<String>) -> PlatformHandle {
        PlatformHandle::new(value).expect("valid test handle")
    }

    fn runtime_state_roots() -> RuntimeStateRoots {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            profile: InstallationProfile,
            profile_anchor_root: &'a PlatformHandle,
            installation_root: &'a PlatformHandle,
            host_state_root: &'a PlatformHandle,
            kernel_ors_root: &'a PlatformHandle,
            kernel_work_root: &'a PlatformHandle,
            store_data_root: &'a PlatformHandle,
            store_work_root: &'a PlatformHandle,
            store_temp_root: &'a PlatformHandle,
            watchdog_state_root: &'a PlatformHandle,
        }
        let installation_key = "1".repeat(64);
        let installation_root = format!(r"C:\ProgramData\Eliot\installations\{installation_key}");
        let mut roots = RuntimeStateRoots {
            profile: InstallationProfile::SystemService,
            profile_anchor_root: handle(r"C:\ProgramData"),
            installation_root: handle(&installation_root),
            host_state_root: handle(format!(r"{installation_root}\host")),
            kernel_ors_root: handle(format!(r"{installation_root}\kernel\state")),
            kernel_work_root: handle(format!(r"{installation_root}\kernel\work")),
            store_data_root: handle(format!(r"{installation_root}\store\data")),
            store_work_root: handle(format!(r"{installation_root}\store\work")),
            store_temp_root: handle(format!(r"{installation_root}\store\tmp")),
            watchdog_state_root: handle(format!(r"{installation_root}\watchdog")),
            roots_digest: handle("0".repeat(64)),
        };
        let bytes = serde_json::to_vec(&Unsigned {
            profile: roots.profile,
            profile_anchor_root: &roots.profile_anchor_root,
            installation_root: &roots.installation_root,
            host_state_root: &roots.host_state_root,
            kernel_ors_root: &roots.kernel_ors_root,
            kernel_work_root: &roots.kernel_work_root,
            store_data_root: &roots.store_data_root,
            store_work_root: &roots.store_work_root,
            store_temp_root: &roots.store_temp_root,
            watchdog_state_root: &roots.watchdog_state_root,
        })
        .expect("serialize roots digest fixture");
        roots.roots_digest = handle(format!("{:x}", Sha256::digest(bytes)));
        roots
    }

    fn reseal_runtime_launch(descriptor: &mut RuntimeLaunchDescriptor) {
        *descriptor = descriptor
            .clone()
            .with_computed_digest()
            .expect("serialize unsigned runtime launch");
    }

    fn runtime_launch() -> RuntimeLaunchDescriptor {
        let roots = runtime_state_roots();
        let config_path = handle(r"C:\ProgramData\Eliot\generation.json");
        let authority_generation = ResourceGeneration::genesis();
        let authority_state_fence =
            StateFence::new(AuthorityEpoch::genesis(), authority_generation);
        let mut descriptor = RuntimeLaunchDescriptor {
            profile: InstallationProfile::SystemService,
            portable_root: None,
            installation_epoch: InstallationEpoch {
                installation: handle("installation-test"),
                lineage_id: handle("lineage-test"),
                sequence: 1,
            },
            generation: handle("generation-test"),
            authority_generation,
            authority_state_fence,
            supervision_authority: eliot_installation::SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: handle("test-supervision-scope"),
            },
            authority_descriptor_path: handle(r"C:\ProgramData\Eliot\authority.json"),
            authority_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
            runtime_state_roots: roots.clone(),
            kernel_work_root: roots.kernel_work_root.clone(),
            kernel_artifact_digest: handle("1".repeat(64)),
            eliotd_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliotd.exe"),
            eliotd_artifact_digest: handle("c".repeat(64)),
            eliotd_config_path: handle(r"C:\ProgramData\Eliot\governor\eliotd.json"),
            eliotd_config_digest: handle("d".repeat(64)),
            protected_snapshot_digest: handle("e".repeat(64)),
            eliotd_descriptor_path: handle(r"C:\ProgramData\Eliot\eliotd.json"),
            eliotd_descriptor_digest: handle("e".repeat(64)),
            eliotd_launch_nonce: handle(format!("eliotd:{}", "1".repeat(32))),
            store_config_path: config_path.clone(),
            store_credential_target: handle("eliot/store/v1/0123456789abcdef0123456789abcdef"),
            store_bridge_executable_path: handle(
                r"C:\ProgramData\Eliot\bin\eliot-store-surreal.exe",
            ),
            store_bridge_artifact_digest: handle("a".repeat(64)),
            store_bootstrap_descriptor_path: handle(r"C:\ProgramData\Eliot\store-bootstrap.json"),
            store_bootstrap_descriptor_digest: handle(eliot_installation::PHASE_B_PENDING_MARKER),
            canonical_store_executable_path: handle(r"C:\ProgramData\Eliot\bin\surreal.exe"),
            canonical_store_artifact_digest: handle("b".repeat(64)),
            kernel_arguments: vec![
                handle("--work-root"),
                roots.kernel_work_root.clone(),
                handle("--store-bootstrap"),
                handle(r"C:\ProgramData\Eliot\store-bootstrap.json"),
                handle("--store-bootstrap-sha256"),
                handle(eliot_installation::PHASE_B_PENDING_MARKER),
                handle("--authority-descriptor"),
                handle(r"C:\ProgramData\Eliot\authority.json"),
                handle("--authority-descriptor-sha256"),
                handle(eliot_installation::PHASE_B_PENDING_MARKER),
                handle("--kernel-artifact-sha256"),
                handle("1".repeat(64)),
                handle("--eliotd-descriptor"),
                handle(r"C:\ProgramData\Eliot\eliotd.json"),
                handle("--eliotd-descriptor-sha256"),
                handle("e".repeat(64)),
            ],
            store_bridge_arguments: vec![handle("--config"), config_path],
            canonical_store_arguments: vec![
                handle("start"),
                handle("--no-banner"),
                handle("--bind"),
                handle("127.0.0.1:8000"),
                handle("--temporary-directory"),
                roots.store_temp_root.clone(),
                handle("--log-file-enabled"),
                handle("--log-file-path"),
                roots.store_work_root.clone(),
                handle("--log-file-name"),
                handle("surrealdb.log"),
                handle(format!(
                    "surrealkv://{}",
                    roots.store_data_root.as_str().replace('\\', "/")
                )),
            ],
            host_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-host.exe"),
            host_artifact_digest: handle("c".repeat(64)),
            watchdog_executable_path: handle(r"C:\ProgramData\Eliot\bin\eliot-watchdog.exe"),
            watchdog_artifact_digest: handle("4".repeat(64)),
            descriptor_digest: handle("0".repeat(64)),
        };
        reseal_runtime_launch(&mut descriptor);
        descriptor
    }

    fn config() -> StoreLaunchConfig {
        let mut config = StoreLaunchConfig {
            store_pipe: r"\\.\pipe\eliot\store-test".to_owned(),
            launch_nonce: "launch-test".to_owned(),
            expected_client_sid: "S-1-5-18".to_owned(),
            expected_client_session_id: 0,
            approved_artifact_hash: "a".repeat(64),
            approved_config_hash: String::new(),
            endpoint: "ws://127.0.0.1:8000/rpc".to_owned(),
            provider_bind_address: "127.0.0.1:8000".to_owned(),
            namespace: "eliot".to_owned(),
            database: "eliot".to_owned(),
            username: "store".to_owned(),
            connect_timeout_ms: 1_000,
            query_timeout_ms: 1_000,
            schema_generation: "1.0.0".to_owned(),
            blob_root: r"C:\ProgramData\Eliot\blob".to_owned(),
            instance_id: "store-test".to_owned(),
            credential_ref: "eliot/store/v1/0123456789abcdef0123456789abcdef".to_owned(),
            runtime_launch: runtime_launch(),
        };
        config.approved_config_hash = launch_config_digest(&config).expect("config digest");
        config
    }

    #[test]
    fn runtime_digest_domains_reject_scm_selector_and_legacy_zero() {
        for reserved in [PHASE_B_PENDING_SCM_DIGEST, LEGACY_PHASE_B_ZERO_DIGEST] {
            assert!(validate_digest(reserved, "test.runtime").is_err());

            let mut artifact = config();
            artifact.approved_artifact_hash = reserved.to_owned();
            assert!(artifact.validate().is_err());

            let mut approved_config = config();
            approved_config.approved_config_hash = reserved.to_owned();
            assert!(approved_config.validate().is_err());
        }
    }

    fn schema_bootstrap_command(config: &StoreLaunchConfig) -> StoreSchemaBootstrapCommand {
        let migration = SurrealStoreAdapter::initial_schema_migration(
            SchemaGeneration::new(config.schema_generation.clone()).expect("schema generation"),
        );
        StoreSchemaBootstrapCommand {
            installation_id: config
                .runtime_launch
                .installation_epoch
                .installation
                .as_str()
                .to_owned(),
            generation: config.runtime_launch.generation.as_str().to_owned(),
            authority_generation: config.runtime_launch.authority_generation.value(),
            approved_config_hash: config.approved_config_hash.clone(),
            state_fence: config.runtime_launch.authority_state_fence.clone(),
            migration_id: migration.migration_id().to_owned(),
            migration_checksum_sha256: migration.checksum_sha256().to_owned(),
            observed_clock: ClockReading {
                valid_time_ms: Some(1_000),
                known_time_ms: Some(1_001),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        }
    }

    #[test]
    fn system_service_schema_bootstrap_command_and_receipt_are_fully_bound() {
        let config = config();
        let binding = StoreSchemaBootstrapBinding::from_config(&config);
        let command = schema_bootstrap_command(&config);
        let migration = SurrealStoreAdapter::initial_schema_migration(
            SchemaGeneration::new(config.schema_generation.clone()).expect("schema generation"),
        );

        binding
            .validate_command(&command, &migration)
            .expect("exact SystemService command");
        let provider_receipt = MigrationReceipt {
            migration_id: migration.migration_id().to_owned(),
            checksum_sha256: migration.checksum_sha256().to_owned(),
            generation_after: migration.generation_after().clone(),
        };
        let receipt = binding
            .receipt(&provider_receipt)
            .expect("typed authoritative receipt");
        receipt.validate().expect("receipt validates");
        assert_eq!(receipt.installation_id, command.installation_id);
        assert_eq!(receipt.state_fence, command.state_fence);
        assert_eq!(
            receipt.migration_checksum_sha256,
            command.migration_checksum_sha256
        );
        let encoded = serde_json::to_string(&receipt).expect("receipt serialization");
        assert!(!encoded.contains("password"));
        assert!(!encoded.contains("credential"));
    }

    #[test]
    fn schema_bootstrap_rejects_profile_and_binding_drift_before_provider_effect() {
        let config = config();
        let command = schema_bootstrap_command(&config);
        let migration = SurrealStoreAdapter::initial_schema_migration(
            SchemaGeneration::new(config.schema_generation.clone()).expect("schema generation"),
        );
        let mut portable_binding = StoreSchemaBootstrapBinding::from_config(&config);
        portable_binding.profile = InstallationProfile::PortableDev;
        assert!(matches!(
            portable_binding.validate_command(&command, &migration),
            Err(StoreSchemaBootstrapError::Rejected(reason))
                if reason.contains("SystemService")
        ));

        let binding = StoreSchemaBootstrapBinding::from_config(&config);
        let mut drifted = command;
        drifted.state_fence = StateFence::new(
            AuthorityEpoch::new(2).expect("epoch"),
            ResourceGeneration::genesis(),
        );
        assert!(matches!(
            binding.validate_command(&drifted, &migration),
            Err(StoreSchemaBootstrapError::Rejected(reason))
                if reason.contains("state_fence")
        ));
    }

    #[test]
    fn schema_bootstrap_rejects_unobserved_clock_and_migration_identity_drift() {
        let config = config();
        let binding = StoreSchemaBootstrapBinding::from_config(&config);
        let migration = SurrealStoreAdapter::initial_schema_migration(
            SchemaGeneration::new(config.schema_generation.clone()).expect("schema generation"),
        );
        let mut no_clock = schema_bootstrap_command(&config);
        no_clock.observed_clock = ClockReading::default();
        assert!(matches!(
            binding.validate_command(&no_clock, &migration),
            Err(StoreSchemaBootstrapError::Rejected(reason))
                if reason.contains("observed_clock")
        ));

        let mut wrong_migration = schema_bootstrap_command(&config);
        wrong_migration.migration_checksum_sha256 = "b".repeat(64);
        assert!(matches!(
            binding.validate_command(&wrong_migration, &migration),
            Err(StoreSchemaBootstrapError::Rejected(reason))
                if reason.contains("migration_checksum_sha256")
        ));
    }

    #[test]
    fn launch_nonce_and_operational_fields_are_digest_bound() {
        let config = config();
        assert!(config.validate().is_ok());
        let mut altered = config.clone();
        altered.launch_nonce = "different-launch".to_owned();
        assert!(altered.validate().is_err());
        let mut endpoint_altered = config;
        endpoint_altered.endpoint = "ws://127.0.0.1:9000".to_owned();
        assert!(endpoint_altered.validate().is_err());
    }

    #[test]
    fn credential_ref_must_match_descriptor_bound_target() {
        let config = config();
        assert!(config.validate().is_ok());

        let mut mismatched = config;
        mismatched.credential_ref = "eliot/store/v1/fedcba9876543210fedcba9876543210".to_owned();
        mismatched.approved_config_hash =
            launch_config_digest(&mismatched).expect("mismatched config digest");
        let error = mismatched
            .validate()
            .expect_err("credential target mismatch");
        assert!(error.contains("credential_ref must exactly equal"));
    }

    #[test]
    fn canonical_runtime_identity_profile_and_digest_are_required() {
        let config = config();
        assert!(config.validate().is_ok());

        let mut profile_mismatch = config.clone();
        profile_mismatch.runtime_launch.profile = InstallationProfile::UserMode;
        profile_mismatch.approved_config_hash =
            launch_config_digest(&profile_mismatch).expect("mismatched config digest");
        assert!(profile_mismatch.validate().is_err());

        let mut digest_mismatch = config.clone();
        digest_mismatch
            .runtime_launch
            .runtime_state_roots
            .roots_digest = handle("c".repeat(64));
        digest_mismatch.approved_config_hash =
            launch_config_digest(&digest_mismatch).expect("mismatched config digest");
        assert!(digest_mismatch.validate().is_err());

        let mut invalid_installation = config;
        invalid_installation
            .runtime_launch
            .installation_epoch
            .sequence = 0;
        invalid_installation.approved_config_hash =
            launch_config_digest(&invalid_installation).expect("mismatched config digest");
        assert!(invalid_installation.validate().is_err());
    }

    #[test]
    fn recomputed_digest_cannot_authorize_an_altered_runtime_live_target() {
        let config = config();
        for (bind, endpoint, namespace) in [
            ("127.0.0.1:8001", "ws://127.0.0.1:8001/rpc", "eliot"),
            ("127.0.0.1:8000", "ws://127.0.0.1:8000/rpc", "other"),
        ] {
            let mut altered = config.clone();
            altered.provider_bind_address = bind.to_owned();
            altered.endpoint = endpoint.to_owned();
            altered.namespace = namespace.to_owned();
            altered.approved_config_hash =
                launch_config_digest(&altered).expect("recomputed altered digest");
            assert!(altered.validate().is_err());
        }
    }

    #[test]
    fn neutral_descriptor_excludes_concrete_provider_configuration() {
        let config = config();
        let descriptor = store_bootstrap_descriptor(&config).expect("neutral descriptor");
        descriptor.validate().expect("descriptor validates");
        assert_eq!(descriptor.route_identity.as_str(), STORE_ROUTE_IDENTITY);
        assert_eq!(
            descriptor.canonical_pipe_identity.as_str(),
            config.store_pipe
        );
        assert_eq!(descriptor.timeout_ms, config.connect_timeout_ms);
        let encoded = serde_json::to_value(&descriptor).expect("descriptor JSON");
        for forbidden in [
            "endpoint",
            "namespace",
            "database",
            "username",
            "credential_ref",
            "blob_root",
            "schema_generation",
        ] {
            assert!(encoded.get(forbidden).is_none(), "leaked {forbidden}");
        }
    }

    #[test]
    fn bounded_config_parser_supports_json_and_rejects_other_extensions() {
        let config = config();
        let json = serde_json::to_vec(&config).expect("JSON config");
        let exact_path = Path::new(config.runtime_launch.store_config_path.as_str());
        let parsed = parse_config_bytes(exact_path, &json).expect("JSON config parses");
        assert_eq!(parsed.store_pipe, config.store_pipe);
        assert_eq!(parsed.approved_config_hash, config.approved_config_hash);
        assert!(
            parse_config_bytes(Path::new(r"C:\ProgramData\Eliot\different.json"), &json).is_err()
        );
        assert!(
            parse_config_bytes(Path::new(r"C:\ProgramData\Eliot\generation.txt"), &json).is_err()
        );
    }

    #[test]
    fn materialized_config_binds_full_runtime_descriptor_and_outer_digest() {
        let config = config();
        let exact_path = Path::new(config.runtime_launch.store_config_path.as_str()).to_path_buf();
        assert!(config.validate_materialized_at(&exact_path).is_ok());

        let mut authority_tampered = config.clone();
        authority_tampered
            .runtime_launch
            .authority_descriptor_digest = handle("8".repeat(64));
        assert!(
            authority_tampered
                .validate_materialized_at(&exact_path)
                .is_err()
        );

        let mut resealed_inner = config.clone();
        resealed_inner.runtime_launch.generation = handle("generation-replaced");
        reseal_runtime_launch(&mut resealed_inner.runtime_launch);
        assert!(resealed_inner.runtime_launch.validate().is_ok());
        assert!(
            resealed_inner
                .validate_materialized_at(&exact_path)
                .is_err()
        );

        let mut bridge_mismatch = config;
        bridge_mismatch.approved_artifact_hash = "9".repeat(64);
        bridge_mismatch.approved_config_hash =
            launch_config_digest(&bridge_mismatch).expect("outer config digest");
        assert!(
            bridge_mismatch
                .validate_materialized_at(&exact_path)
                .is_err()
        );
    }

    #[test]
    fn descriptor_provider_argv_materializes_exactly_and_rejects_bind_substitution() {
        let mut config = config();
        config.schema_generation = SchemaGeneration::v2().as_str().to_owned();
        config.approved_config_hash = launch_config_digest(&config).expect("v2 config digest");
        let adapter =
            materialize_adapter_config(&config, SecretString::new("materialization-secret".into()))
                .expect("descriptor materializes adapter config");
        assert_eq!(
            adapter.provider_arguments,
            config
                .runtime_launch
                .canonical_store_arguments
                .iter()
                .map(|argument| argument.as_str().to_owned())
                .collect::<Vec<_>>()
        );

        let mut substituted = config;
        substituted.provider_bind_address = "127.0.0.1:9000".to_owned();
        substituted.endpoint = "ws://127.0.0.1:9000/rpc".to_owned();
        substituted.approved_config_hash =
            launch_config_digest(&substituted).expect("outer digest");
        assert!(
            materialize_adapter_config(
                &substituted,
                SecretString::new("materialization-secret".into()),
            )
            .is_err()
        );
    }

    #[test]
    fn pipe_gate_requires_exact_complete_semantic_ready_receipt() {
        assert!(
            require_semantic_ready_for_pipe(&ReadinessReceipt::ready("1.0.0".to_owned()), "1.0.0")
                .is_ok()
        );
        assert!(
            require_semantic_ready_for_pipe(&ReadinessReceipt::unavailable(), "1.0.0").is_err()
        );
        assert!(
            require_semantic_ready_for_pipe(
                &ReadinessReceipt::migration_required("1.0.0".to_owned(), None),
                "1.0.0",
            )
            .is_err()
        );
        let partial = ReadinessReceipt {
            status: ReadinessStatus::Ready,
            expected_generation: Some("1.0.0".to_owned()),
            observed_generation: Some("0.9.0".to_owned()),
        };
        assert!(require_semantic_ready_for_pipe(&partial, "1.0.0").is_err());
    }

    #[test]
    fn recovery_dispatch_default_unavailable_is_error() {
        assert_eq!(
            map_recovery_dispatch_result(Err(StoreError::Unavailable)),
            Response::Error {
                error: "store unavailable".to_owned(),
            }
        );
    }

    #[test]
    fn genesis_dispatch_default_unavailable_is_error() {
        let request = StoreGenesisRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            operation_id: OperationId::new("genesis-dispatch").expect("operation id"),
            idempotency_key: "genesis-retry".to_owned(),
            canonical_request_hash: String::new(),
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            owner_records: Vec::new(),
        };
        assert_eq!(
            map_genesis_dispatch_result(request, Err(StoreError::Unavailable)),
            Response::Error {
                error: "store unavailable".to_owned(),
            }
        );
    }

    #[test]
    fn recovery_and_genesis_capabilities_are_advertised_in_order() {
        assert_eq!(
            &CAPABILITIES[8..],
            &[
                eliot_store_api::CAPABILITY_RECOVERY,
                eliot_store_api::CAPABILITY_INITIALIZE_GENESIS,
            ]
        );
    }

    #[test]
    fn genesis_missing_receipt_envelope_is_unknown_with_exact_operation() {
        let operation_id = OperationId::new("genesis-unknown").expect("operation id");
        let request = StoreGenesisRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            idempotency_key: "genesis-retry".to_owned(),
            canonical_request_hash: String::new(),
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            owner_records: Vec::new(),
        };
        assert_eq!(
            map_genesis_dispatch_result(request, Err(StoreError::MissingReceiptEnvelope)),
            Response::Unknown {
                operation_id,
                reason: UNKNOWN_GENESIS_REASON.to_owned(),
            }
        );
        assert!(UNKNOWN_GENESIS_REASON.len() <= 256);
    }

    #[test]
    fn unknown_provider_outcome_keeps_exact_wire_operation() {
        let error = map_adapter_error(AdapterError::UnknownOutcome {
            operation_id: "operation-test".to_owned(),
        });
        assert!(matches!(
            error,
            StoreCompositionError::UnknownOutcome { operation_id, .. }
                if operation_id.as_str() == "operation-test"
        ));
    }

    #[test]
    fn schema_bootstrap_preserves_unknown_and_partial_provider_outcomes() {
        assert!(matches!(
            map_schema_bootstrap_error(AdapterError::UnknownMigrationOutcome {
                migration_id: "migration-test".to_owned(),
            }),
            StoreSchemaBootstrapError::UnknownOutcome { migration_id }
                if migration_id == "migration-test"
        ));
        assert!(matches!(
            map_schema_bootstrap_error(AdapterError::PartialOutcome),
            StoreSchemaBootstrapError::PartialOutcome
        ));
    }

    fn client_hello_frame(config: &StoreLaunchConfig) -> Frame {
        let module_id = ContractId::new(STORE_MODULE_IDENTITY).expect("module id");
        let artifact_id =
            ArtifactId::new(config.approved_artifact_hash.as_str()).expect("artifact");
        let authority_epoch = config.runtime_launch.authority_state_fence.authority_epoch;
        let generation = config.runtime_launch.authority_generation;
        let hello = ClientHello {
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_bridge_identity: STORE_MODULE_IDENTITY.to_owned(),
            artifact_hash: artifact_id.clone(),
            module_contract: ModuleContract {
                module_id: module_id.clone(),
                version: ContractVersion::new(1, 0, 0),
                artifact_id: artifact_id.clone(),
                protocols: vec![PROTOCOL_VERSION.to_owned()],
                required_capabilities: vec!["store.readiness".to_owned()],
                optional_capabilities: Vec::new(),
                advisory_capabilities: Vec::new(),
                state_owner: "eliot-kernel".to_owned(),
                failure_domain: SERVICE_NAME.to_owned(),
                hot_replace: false,
            },
            module_generation: ModuleGeneration {
                module_id,
                generation,
                artifact_id,
                state: ModuleGenerationState::Active,
                health: HealthVector::healthy(),
                state_fence: StateFence::new(authority_epoch, generation),
            },
            launch_nonce: config.launch_nonce.clone(),
            capabilities: CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
                .expect("protocol frame limit fits the wire field"),
            authority_epoch,
        };
        eliot_ipc::client_hello_frame("connection-test", &hello).expect("hello frame")
    }

    #[test]
    fn handshake_rejects_partial_generation_or_fence_lineage() {
        let config = config();
        let identity = StoreHandshakeIdentity::new("manifest-test", serde_json::json!({}));
        let frame = client_hello_frame(&config);
        assert!(
            admit_handshake(
                frame.clone(),
                TransportLimits::default(),
                &config,
                &identity,
            )
            .is_ok()
        );

        let ProtocolPayload::Json(payload) = frame.payload else {
            panic!("hello payload");
        };
        let mut hello: ClientHello = serde_json::from_value(payload).expect("client hello");
        hello.module_generation.state_fence = StateFence::new(
            config.runtime_launch.authority_state_fence.authority_epoch,
            ResourceGeneration::new(config.store_generation() + 1).expect("generation"),
        );
        let mismatched =
            eliot_ipc::client_hello_frame("connection-test", &hello).expect("mismatched hello");
        assert!(
            admit_handshake(mismatched, TransportLimits::default(), &config, &identity,).is_err()
        );

        let mismatched_authority =
            AuthorityEpoch::new(config.authority_epoch() + 1).expect("epoch");
        hello.authority_epoch = mismatched_authority;
        hello.module_generation.state_fence = StateFence::new(
            mismatched_authority,
            config.runtime_launch.authority_generation,
        );
        let mismatched_epoch = eliot_ipc::client_hello_frame("connection-test", &hello)
            .expect("mismatched epoch hello");
        assert!(
            admit_handshake(
                mismatched_epoch,
                TransportLimits::default(),
                &config,
                &identity,
            )
            .is_err()
        );
    }

    #[test]
    fn store_replay_bound_capacity_is_registry_full_distinct_from_conflict() {
        use eliot_ipc::{BoundIdentity, ReplayDisposition, TransportError};
        let generation: eliot_protocol::ProtocolModuleGeneration =
            serde_json::from_value(serde_json::json!({
                "module_id": "module.test",
                "generation": 1,
                "artifact_id": "artifact",
                "state": "ACTIVE",
                "health": {
                    "liveness": "HEALTHY",
                    "readiness": "HEALTHY",
                    "freshness": "HEALTHY",
                    "compatibility": "HEALTHY",
                    "integrity": "HEALTHY",
                    "capacity": "HEALTHY"
                },
                "state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1
                }
            }))
            .expect("generation");
        let frame = eliot_protocol::Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
            connection_id: "c".to_owned(),
            request_id: None,
            kind: eliot_protocol::FrameKind::Heartbeat,
            message_type: eliot_protocol::MessageType::Health,
            request_identity: None,
            payload: eliot_protocol::ProtocolPayload::Json(serde_json::Value::Null),
            trace_context: std::collections::BTreeMap::new(),
        };
        let mut ledger = eliot_ipc::ReplayLedger::with_capacity(1).expect("capacity");
        let bound = BoundIdentity::new("stream", generation.clone(), "request-1").expect("bound");
        assert_eq!(
            ledger.observe_bound(bound.clone(), &frame).expect("new"),
            ReplayDisposition::New
        );
        assert_eq!(
            ledger
                .observe_bound(bound.clone(), &frame)
                .expect("duplicate"),
            ReplayDisposition::Duplicate
        );
        let mut conflict = frame.clone();
        conflict.connection_id = "other".to_owned();
        assert_eq!(
            ledger
                .observe_bound(bound.clone(), &conflict)
                .expect("conflict"),
            ReplayDisposition::Conflict
        );
        let second = BoundIdentity::new("stream", generation, "request-2").expect("bound2");
        assert_eq!(
            ledger.observe_bound(second, &frame),
            Err(TransportError::RegistryFull)
        );
    }

    #[test]
    fn store_replay_1025th_new_identity_is_registry_full() {
        use eliot_ipc::{BoundIdentity, ReplayDisposition, TransportError};
        let generation: eliot_protocol::ProtocolModuleGeneration =
            serde_json::from_value(serde_json::json!({
                "module_id": "module.test",
                "generation": 1,
                "artifact_id": "artifact",
                "state": "ACTIVE",
                "health": {
                    "liveness": "HEALTHY",
                    "readiness": "HEALTHY",
                    "freshness": "HEALTHY",
                    "compatibility": "HEALTHY",
                    "integrity": "HEALTHY",
                    "capacity": "HEALTHY"
                },
                "state_fence": {
                    "authority_epoch": 1,
                    "resource_generation": 1
                }
            }))
            .expect("generation");
        let frame = eliot_protocol::Frame {
            protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
            encoding_profile: eliot_protocol::EncodingProfile::JsonV1,
            connection_id: "c".to_owned(),
            request_id: None,
            kind: eliot_protocol::FrameKind::Heartbeat,
            message_type: eliot_protocol::MessageType::Health,
            request_identity: None,
            payload: eliot_protocol::ProtocolPayload::Json(serde_json::Value::Null),
            trace_context: std::collections::BTreeMap::new(),
        };
        let mut ledger = eliot_ipc::ReplayLedger::default();
        for n in 1..=1024 {
            let id = format!("request-{n}");
            let bound = BoundIdentity::new("stream", generation.clone(), id).expect("bound");
            assert_eq!(
                ledger.observe_bound(bound, &frame).expect("new"),
                ReplayDisposition::New
            );
        }
        let overflow = BoundIdentity::new("stream", generation, "request-1025").expect("overflow");
        assert_eq!(
            ledger.observe_bound(overflow, &frame),
            Err(TransportError::RegistryFull)
        );
    }
}
