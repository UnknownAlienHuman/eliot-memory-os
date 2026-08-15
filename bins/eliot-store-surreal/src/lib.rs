#![forbid(unsafe_code)]

//! Composition owner for the S-03 canonical store bridge.
//!
//! This process exposes only the store-neutral EBP contract.  SurrealDB
//! credentials, provider transport and query text stay inside
//! `eliot-store-surreal-adapter`; this root only assembles the adapter and
//! serializes bounded contract receipts.  Blob is an injected capability and
//! has one public owner, so a co-located implementation cannot create a
//! second root owner or a semantic write path.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_blob_api::BlobStoreClient;
use eliot_platform::ClockObservation;
use eliot_store_api::{
    CanonicalStoreClient, NamedReadRequest, NamedReadResponse, OperationId,
    OrderingHeadExpectation, PreparedTransition, RequestMeta, RevisionHeadExpectation,
    WriteReceipt,
};
use eliot_store_surreal_adapter::{
    AdapterError, AdapterHealth, MigrationReceipt, SchemaGeneration, SemanticReadiness,
    SurrealAdapterConfig, SurrealStoreAdapter,
};
use eliot_types::GovernorConfig;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

pub const SERVICE_NAME: &str = "eliot-store-surreal";
pub const PROTOCOL_VERSION: &str = "eliot.s03.ebp.v1";
const SCHEMA_GENERATION: &str = "1.0.0";
const PASSWORD_ENV: &str = "ELIOT_SURREAL_PASSWORD";

/// The one process-level Blob owner.  The concrete service remains behind the
/// provider-neutral S-04 contract and is responsible for claiming its root.
#[derive(Clone)]
pub struct BlobOwner {
    client: Arc<dyn BlobStoreClient>,
}

impl BlobOwner {
    /// Injects the already-constructed owner.  Construction of a concrete
    /// `BlobStoreService` claims the root exactly once.
    pub fn new(client: Arc<dyn BlobStoreClient>) -> Self {
        Self { client }
    }

    /// Returns the sole provider-neutral Blob capability.
    pub fn client(&self) -> &dyn BlobStoreClient {
        self.client.as_ref()
    }
}

impl std::fmt::Debug for BlobOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BlobOwner(<provider-neutral capability>)")
    }
}

/// Canonical store composition.  All provider authority is held by the one
/// adapter; the optional Blob owner is only an injected capability and never a
/// semantic store or alternate transition path.
pub struct StoreComposition {
    store: SurrealStoreAdapter,
    blob: Option<BlobOwner>,
}

impl std::fmt::Debug for StoreComposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreComposition")
            .field("store", &self.store)
            .field("blob_owner_present", &self.blob.is_some())
            .finish()
    }
}

impl StoreComposition {
    /// Builds the adapter from the existing process configuration.  The
    /// password is resolved only in this process and passed directly to the
    /// adapter as a redacted secret value; it is never deserialized from the
    /// config file or exposed in this API.
    pub fn new(config: GovernorConfig) -> Result<Self, String> {
        config.validate().map_err(|error| error.to_string())?;
        Ok(Self {
            store: SurrealStoreAdapter::new(adapter_config(&config)?),
            blob: None,
        })
    }

    /// Adds the one co-located/process-backed Blob capability.  A second owner
    /// is rejected instead of silently replacing the active root owner.
    pub fn with_blob_owner(mut self, owner: BlobOwner) -> Result<Self, String> {
        if self.blob.is_some() {
            return Err("exactly one Blob root owner is permitted".to_owned());
        }
        self.blob = Some(owner);
        Ok(self)
    }

    /// Returns the configured provider-neutral Blob capability, if composed.
    pub fn blob(&self) -> Option<&dyn BlobStoreClient> {
        self.blob.as_ref().map(BlobOwner::client)
    }

    /// Bounded adapter/provider health observation.
    pub async fn health(&self) -> AdapterHealth {
        self.store.adapter_health().await
    }

    /// Semantic schema readiness observation.  This is not a write authority
    /// verdict and is returned as its own receipt/status surface.
    pub async fn readiness(&self) -> Result<SemanticReadiness, AdapterError> {
        self.store.probe_readiness().await
    }

    /// Applies the one admitted schema migration and returns its durable
    /// migration receipt.  Migration is explicit and never implicit at start.
    pub async fn migrate(&self) -> Result<MigrationReceipt, AdapterError> {
        let generation = SchemaGeneration::new(SCHEMA_GENERATION)
            .map_err(|error| AdapterError::Config(error.to_string()))?;
        let migration = SurrealStoreAdapter::initial_schema_migration(generation);
        self.store
            .apply_migration(&migration, &observed_clock())
            .await
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
    ) -> Result<WriteReceipt, AdapterError> {
        self.store
            .apply_prepared(
                context,
                transition,
                expected_revision_heads,
                expected_ordering_heads,
            )
            .await
    }

    /// Reconciles a possibly ambiguous write by exact operation identity.
    pub async fn receipt(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<WriteReceipt>, AdapterError> {
        self.store.reconcile(operation_id).await
    }

    /// Returns the immutable closed operation manifest digest for the ready
    /// response; no provider-specific data is exposed.
    pub fn operation_manifest_digest(&self) -> &str {
        self.store.operation_manifest().digest.as_str()
    }
}

fn adapter_config(config: &GovernorConfig) -> Result<SurrealAdapterConfig, String> {
    let schema_generation =
        SchemaGeneration::new(SCHEMA_GENERATION).map_err(|error| error.to_string())?;
    let password = std::env::var(PASSWORD_ENV).unwrap_or_default();
    Ok(SurrealAdapterConfig {
        endpoint: config.db.surreal.endpoint.clone(),
        namespace: config.db.surreal.ns.clone(),
        database: config.db.surreal.db.clone(),
        username: config.db.surreal.user.clone(),
        password: SecretString::new(password.into()),
        connect_timeout_ms: config.db.surreal.startup_timeout_ms,
        query_timeout_ms: config.db.surreal.query_timeout_ms,
        expected_schema_generation: schema_generation,
    })
}

fn observed_clock() -> ClockObservation {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0);
    ClockObservation {
        valid_time_ms: Some(now),
        known_time_ms: Some(now),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

/// Loads the process's non-secret configuration.  Secret material is resolved
/// from `ELIOT_SURREAL_PASSWORD` only inside [`StoreComposition::new`].
pub fn load_config(path: Option<&Path>) -> Result<GovernorConfig, String> {
    let Some(path) = path else {
        return Ok(GovernorConfig::default());
    };
    let bytes = std::fs::read(path).map_err(|error| format!("read config: {error}"))?;
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("json") => {
            serde_json::from_slice(&bytes).map_err(|error| format!("parse JSON config: {error}"))
        }
        _ => toml::from_slice(&bytes).map_err(|error| format!("parse TOML config: {error}")),
    }
}

#[derive(Debug, Serialize)]
pub struct MigrationResponse {
    pub migration_id: String,
    pub checksum_sha256: String,
    pub generation_after: String,
}

impl From<MigrationReceipt> for MigrationResponse {
    fn from(receipt: MigrationReceipt) -> Self {
        Self {
            migration_id: receipt.migration_id,
            checksum_sha256: receipt.checksum_sha256,
            generation_after: receipt.generation_after.to_string(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReadinessReceipt {
    pub status: &'static str,
    pub expected_generation: Option<String>,
    pub observed_generation: Option<String>,
}

impl From<SemanticReadiness> for ReadinessReceipt {
    fn from(readiness: SemanticReadiness) -> Self {
        match readiness {
            SemanticReadiness::Unavailable => Self {
                status: "unavailable",
                expected_generation: None,
                observed_generation: None,
            },
            SemanticReadiness::MigrationRequired { expected, observed } => Self {
                status: "migration_required",
                expected_generation: Some(expected.to_string()),
                observed_generation: observed,
            },
            SemanticReadiness::Ready { generation } => Self {
                status: "ready",
                expected_generation: Some(generation.to_string()),
                observed_generation: Some(generation.to_string()),
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ready {
        service: &'static str,
        protocol: &'static str,
        operation_manifest_digest: String,
    },
    Health {
        record: AdapterHealth,
    },
    Readiness {
        receipt: ReadinessReceipt,
    },
    Migrated {
        receipt: MigrationResponse,
    },
    Named {
        response: NamedReadResponse,
    },
    Transaction {
        receipt: WriteReceipt,
    },
    Receipt {
        receipt: Option<WriteReceipt>,
    },
    Stopped,
    Error {
        error: String,
    },
}

/// Closed process request catalogue.  No provider SDK, table, query string or
/// credential is representable on this wire surface.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Health,
    Readiness,
    Migrate,
    Named {
        request: NamedReadRequest,
    },
    Apply {
        context: RequestMeta,
        transition: PreparedTransition,
        expected_revision_heads: Vec<RevisionHeadExpectation>,
        expected_ordering_heads: Vec<OrderingHeadExpectation>,
    },
    Receipt {
        operation_id: OperationId,
    },
    Stop,
}
